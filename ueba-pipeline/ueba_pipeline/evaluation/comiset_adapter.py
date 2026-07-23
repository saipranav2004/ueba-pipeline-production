"""Adapter for the COMISET real-telemetry corpus (Zenodo 10.5281/zenodo.15375146).

WHAT THIS IS
------------
COMISET (Comillas Security Event dataSET, CC-BY-4.0, described in Data in Brief
2025, doi:10.1016/j.dib.2025.111723) is a public corpus of **real** Windows event
telemetry in two environments: a lab emulating a small company (with executed,
MITRE-ATT&CK-labelled attacks) and a **real** university network — the genuine
multi-day human benign background that OTRF cannot provide and that a
detection-performance measurement requires. Access is direct HTTP from Zenodo
with no data-use agreement, unlike LANL.

WHAT IT PROVES HERE, AND WHAT IT DOES NOT
-----------------------------------------
This adapter is scoped, like ``otrf_adapter``, to **ingestion correctness** — that
the production ``normalize_event`` path fires on genuine COMISET records once the
Elasticsearch/HELK envelope is unwrapped. It does **not** by itself establish
detection recall or false-positive rate: that needs the full multi-GB download,
its Security/Sysmon ``_index`` buckets, and the attack labelling (see FORMAT).

FORMAT (verified against the real archive, not assumed)
-------------------------------------------------------
Each archive is a single ``.zip`` (zip64, written with a leading split/spanning
marker ``PK\\x07\\x08``) holding one newline-delimited JSON file. Each line is an
**Elasticsearch export record** — ``_index``/``_type``/``_id``/``_source`` — whose
``_source`` is a **flat HELK/Winlogbeat document**:

  * ``event_id``   — the Windows Event ID (e.g. ``"4624"``), also mirrored at
                     ``_source.z_elastic_ecs.event.code``
  * ``log_name``   — the channel (e.g. ``"Security"``,
                     ``"Microsoft-Windows-Sysmon/Operational"``)
  * ``host_name``  — the computer
  * ``@timestamp`` — the event time (ISO-8601, ``Z``)
  * the Windows ``EventData`` fields **flattened to top level under their original
    names** (``TargetUserName``, ``LogonType``, ``IpAddress``, ``GrantedAccess``,
    …), because HELK's Winlogbeat pipeline applies ``field_nest_cleanup``.

The engine's flat-envelope parser keys on ``Channel``/``Hostname``/``EventID``/
``EventTime``; COMISET uses ``log_name``/``host_name``/``event_id``/``@timestamp``.
The only COMISET-specific transform, therefore, is to add those aliases — the
flattened event fields already sit exactly where ``_FIELD_MAPS`` looks for them.
Everything else is the identical production path, which is the point: no
COMISET-specific field parsing exists.

Records are grouped by HELK ``_index`` bucket (``…-winevent-additional-…``,
``…-security-…``, ``…-sysmon-…``, …). The Security and Sysmon buckets — the ones
the engine's views read — appear only deeper in the stream, so a small streamed
prefix is dominated by benign OS ``additional`` channels; a Security/Sysmon or
attack-labelled measurement requires the full archive.
"""
from __future__ import annotations

import io
import json
import struct
import urllib.request
import zipfile
import zlib
from pathlib import Path
from typing import Iterator, Union

from ueba_pipeline.parsing.normalize import NormalizedEvent, normalize_event

COMISET_RECORD = "https://zenodo.org/api/records/15375146"
COMISET_FILES = {
    "lab": "https://zenodo.org/api/records/15375146/files/"
           "Comiset23_Lab_Environment_Dataset.zip/content",
    "real": "https://zenodo.org/api/records/15375146/files/"
            "Comiset23_Real_Environment_Dataset.zip/content",
}

# HELK/Winlogbeat envelope field -> the alias the production flat-envelope parser
# (parsing.normalize._extract_envelope) already recognises. This is the whole of
# the COMISET-specific transform.
_ENVELOPE_ALIASES = (
    ("event_id", "EventID"),
    ("log_name", "Channel"),
    ("host_name", "Hostname"),
    ("@timestamp", "EventTime"),
)

_ZIP_SPAN_MARKER = b"PK\x07\x08"   # leading marker of a split/spanned zip
_ZIP_LOCAL_HEADER = b"PK\x03\x04"


def comiset_source_to_raw(record: dict) -> dict:
    """Unwrap one Elasticsearch export record into a dict the production parser
    ingests.

    Takes ``_source`` and adds the ``Channel``/``Hostname``/``EventID``/
    ``EventTime`` aliases for HELK's ``log_name``/``host_name``/``event_id``/
    ``@timestamp``. The original keys are left in place (harmless: they are not in
    any ``_FIELD_MAPS`` entry), so this is a pure widening — no field is dropped or
    renamed away, preserving the parser's "never silently drop a record" contract.

    A record with no ``_source`` is returned unchanged, so a malformed line still
    reaches ``normalize_event`` and is quarantined there rather than here.
    """
    source = record.get("_source")
    if not isinstance(source, dict):
        return record
    raw = dict(source)
    for helk_key, alias in _ENVELOPE_ALIASES:
        if alias not in raw and source.get(helk_key) is not None:
            raw[alias] = source[helk_key]
    return raw


def _read_ndjson_bytes(data: bytes) -> Iterator[dict]:
    for line in data.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if line:
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue                       # a truncated tail line, e.g. from a prefix


def read_comiset_records(source: Union[str, Path]) -> Iterator[dict]:
    """Yield raw Elasticsearch export records from a COMISET ``.zip`` or ``.json``.

    ``.zip`` is streamed member-by-member via the standard library (which handles
    the zip64 sizes and the leading spanning marker through the central directory
    at end-of-file), so the multi-GB single JSON member is never materialised. For
    a partial/streamed prefix of an archive, use :func:`stream_comiset_head`
    instead — a prefix has no central directory for ``zipfile`` to read.
    """
    path = Path(source)
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            for member in archive.namelist():
                if member.endswith(".json") or member.endswith(".ndjson"):
                    with archive.open(member) as handle:
                        yield from _read_ndjson_stream(handle)
    elif path.suffix in (".json", ".ndjson"):
        with open(path, "rb") as handle:
            yield from _read_ndjson_stream(handle)
    else:
        raise ValueError(f"unrecognised COMISET source extension: {path.name}")


def _read_ndjson_stream(handle) -> Iterator[dict]:
    """Yield JSON objects from a binary NDJSON stream without loading it whole."""
    buffer = io.TextIOWrapper(handle, encoding="utf-8", errors="replace")
    for line in buffer:
        line = line.strip()
        if line:
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def read_comiset_events(source: Union[str, Path],
                        keep_raw: bool = False) -> Iterator[NormalizedEvent]:
    """Yield NormalizedEvents from a COMISET archive, through the production parser.

    Each record is unwrapped by :func:`comiset_source_to_raw` and then flows
    through the identical ``normalize_event`` path the rest of the pipeline uses,
    so a pass here exercises the real parser, canonical field maps and feature
    contract — no COMISET-specific event parsing exists.
    """
    for record in read_comiset_records(source):
        event = normalize_event(comiset_source_to_raw(record), keep_raw=keep_raw)
        if event is not None:
            yield event


def stream_comiset_head(url: str, max_uncompressed_bytes: int = 64 * 1024 * 1024,
                        timeout: float = 180.0) -> Iterator[dict]:
    """Stream and inflate the *head* of a COMISET archive over an HTTP range
    request, yielding raw records without downloading the whole file.

    This is how the corpus is inspected without a multi-GB transfer: the single
    zip member is a continuous deflate stream, so its leading records can be
    recovered from a byte prefix. The complete-line boundary of the last record is
    unknown in a prefix, so a trailing partial line is dropped by the JSON guard in
    :func:`_read_ndjson_bytes`.

    Requires network access; raises the underlying URL error if the host is
    unreachable, which the opt-in test catches and skips.
    """
    # A byte prefix large enough to inflate to roughly the requested size. Deflate
    # on this newline-JSON corpus runs ~13-15x, so request a conservatively small
    # compressed window and stop once enough has inflated.
    compressed_window = max(1 << 20, max_uncompressed_bytes // 12)
    req = urllib.request.Request(url, headers={"Range": f"bytes=0-{compressed_window - 1}"})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        head = response.read()

    off = len(_ZIP_SPAN_MARKER) if head[:4] == _ZIP_SPAN_MARKER else 0
    if head[off:off + 4] != _ZIP_LOCAL_HEADER:
        raise ValueError("COMISET archive head is not a zip local file header")
    fn_len = struct.unpack("<H", head[off + 26:off + 28])[0]
    extra_len = struct.unpack("<H", head[off + 28:off + 30])[0]
    method = struct.unpack("<H", head[off + 8:off + 10])[0]
    data_start = off + 30 + fn_len + extra_len
    payload = head[data_start:]
    if method == 8:                            # deflate
        inflated = zlib.decompressobj(-15).decompress(payload, max_uncompressed_bytes)
    elif method == 0:                          # stored
        inflated = payload[:max_uncompressed_bytes]
    else:
        raise ValueError(f"unexpected zip compression method {method}")
    yield from _read_ndjson_bytes(inflated)


def download_comiset_archive(which: str, dest_dir: Union[str, Path],
                             timeout: float = 600.0) -> Path:
    """Download a full COMISET archive (``which`` in {"lab", "real"}) to ``dest_dir``.

    The lab archive is ~4.9 GB and the real archive ~31.7 GB, so this is for a
    deliberate offline run, not CI. Ingestion inspection in CI uses
    :func:`stream_comiset_head` instead.
    """
    if which not in COMISET_FILES:
        raise ValueError(f"unknown COMISET archive {which!r}; expected 'lab' or 'real'")
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    target = dest / Path(COMISET_FILES[which]).parent.name
    with urllib.request.urlopen(COMISET_FILES[which], timeout=timeout) as response:
        target.write_bytes(response.read())
    return target

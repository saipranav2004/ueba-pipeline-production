"""Adapter for the OTRF Security-Datasets (formerly Mordor) real-telemetry corpus.

WHAT THIS IS
------------
OTRF Security-Datasets (https://github.com/OTRF/Security-Datasets, MIT-licensed)
is a public library of **real** Windows Security and Sysmon logs captured while
ATT&CK-mapped attacks were executed on a live domain. It is the most accessible
real Windows/AD telemetry for this engine: every dataset is a small JSON archive
downloadable over plain HTTP with no data-use agreement, unlike LANL.

WHAT IT PROVES, AND WHAT IT DOES NOT
------------------------------------
OTRF captures clear the event logs immediately before each attack run, so a
dataset is essentially the attack's own telemetry with only incidental
background. That makes it the right tool for one job and the wrong tool for
another:

  * It **proves the engine's ingestion is correct against real Windows event
    schemas** — that the parser, the canonical field maps, the feature contract,
    and the graph edge projections fire on genuine logs rather than only on the
    simulator's output. Running the pipeline over these datasets is how the
    project validates that its understanding of real event structure is right.
  * It **cannot measure detection recall or false-positive rate**, because there
    is no realistic multi-day benign baseline to detect against or to raise false
    positives from. Those require a labelled corpus with real background traffic
    (LANL 2015), and this adapter does not pretend otherwise.

This distinction is the honest one the research survey draws: OTRF is a
detection-logic fixture library, not a validation corpus.

FORMAT
------
Each dataset is a ``.zip`` (occasionally ``.tar.gz``) containing one
newline-delimited JSON file. Records are flat NXLog/Mordor shape — top-level
``EventID``, ``Channel``, ``Hostname`` and the event fields — which
``parsing.normalize`` already ingests. The only real-world wrinkles, both fixed
in the parser after being found here, are that different capture runs carry the
event time under ``EventTime``, ``@timestamp`` or ``TimeCreated``, and that some
timestamps use a short fractional-second-plus-``Z`` form.
"""
from __future__ import annotations

import io
import json
import tarfile
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List, Optional, Union

from ueba_pipeline.parsing.normalize import NormalizedEvent, normalize_event

OTRF_RAW_BASE = (
    "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/"
    "datasets/atomic/windows"
)


@dataclass(frozen=True)
class OTRFDataset:
    """One curated OTRF capture and the behaviour the engine should show on it."""

    name: str
    rel_path: str            # path under datasets/atomic/windows/
    tactic: str
    technique: str           # MITRE ATT&CK id
    expected_views: tuple    # graph views the engine must project on this capture
    note: str

    @property
    def url(self) -> str:
        return f"{OTRF_RAW_BASE}/{self.rel_path}"


# A curated set spanning the techniques the engine targets, each verified to
# ingest and to project the expected behavioural graph view(s). Paths are stable
# locations in the OTRF repository. This is a starting set, not the whole corpus;
# add a row to extend coverage.
OTRF_DATASETS: List[OTRFDataset] = [
    OTRFDataset(
        "dcsync", "credential_access/host/"
        "covenant_dcsync_dcerpc_drsuapi_DsGetNCChanges.zip",
        "credential_access", "T1003.006", ("dir_op", "proc_access"),
        "DCSync via DRSUAPI; the 4662 carries the Replicating-Directory-Changes "
        "GUID and projects the dir_op edge (actor -> adobjaccess).",
    ),
    OTRFDataset(
        "ntds_ntdsutil", "credential_access/host/"
        "cmd_dumping_ntds_dit_file_ntdsutil.zip",
        "credential_access", "T1003.003", ("proc_access", "rare_proc"),
        "NTDS.dit extraction via ntdsutil; heavy real Sysmon-10 process-access "
        "telemetry.",
    ),
    OTRFDataset(
        "lsass_comsvcs", "credential_access/host/"
        "psh_lsass_memory_dump_comsvcs.zip",
        "credential_access", "T1003.001", ("proc_access",),
        "LSASS memory dump via comsvcs.dll MiniDump; the credential-store access "
        "shows as a proc_access edge.",
    ),
    OTRFDataset(
        "pth_lsass", "credential_access/host/empire_over_pth_patch_lsass.zip",
        "credential_access", "T1550.002", ("user_src", "src_dst", "proc_access"),
        "Over-Pass-the-Hash patching LSASS; remote-logon and process-access edges.",
    ),
    OTRFDataset(
        "rubeus_ptt", "credential_access/host/empire_shell_rubeus_asktgt_ptt.zip",
        "credential_access", "T1550.003", ("user_src", "src_dst", "proc_access"),
        "Rubeus asktgt Pass-the-Ticket; Kerberos ticket request plus auth edges.",
    ),
]


def _read_ndjson_bytes(data: bytes) -> Iterator[dict]:
    for line in data.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if line:
            yield json.loads(line)


def read_otrf_records(source: Union[str, Path]) -> Iterator[dict]:
    """Yield raw event dicts from an OTRF ``.zip``, ``.tar.gz`` or ``.json`` file.

    A single archive holds one newline-delimited JSON file; this reads it without
    extracting to disk.
    """
    path = Path(source)
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            for member in archive.namelist():
                if member.endswith(".json"):
                    yield from _read_ndjson_bytes(archive.read(member))
    elif path.suffixes[-2:] == [".tar", ".gz"] or path.suffix == ".tgz":
        with tarfile.open(path, "r:gz") as archive:
            for member in archive.getmembers():
                if member.name.endswith(".json"):
                    handle = archive.extractfile(member)
                    if handle is not None:
                        yield from _read_ndjson_bytes(handle.read())
    elif path.suffix == ".json":
        yield from _read_ndjson_bytes(path.read_bytes())
    else:
        raise ValueError(f"unrecognised OTRF source extension: {path.name}")


def read_otrf_events(source: Union[str, Path],
                     keep_raw: bool = False) -> Iterator[NormalizedEvent]:
    """Yield NormalizedEvents from an OTRF dataset, through the production parser.

    Records with no recognisable envelope are skipped (the same quarantine the
    file/Kafka sources apply); everything else flows through the identical
    ``normalize_event`` path the rest of the pipeline uses, which is the point —
    no OTRF-specific parsing exists, so a pass here exercises the real parser.
    """
    for raw in read_otrf_records(source):
        event = normalize_event(raw, keep_raw=keep_raw)
        if event is not None:
            yield event


def download_otrf_dataset(dataset: OTRFDataset, dest_dir: Union[str, Path],
                          timeout: float = 60.0) -> Path:
    """Download one dataset archive to ``dest_dir`` and return the local path.

    Uses only the standard library so the adapter adds no dependency. Raises the
    underlying URL error if the host is unreachable; callers that must tolerate an
    offline environment should catch it and skip.
    """
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    target = dest / Path(dataset.rel_path).name
    with urllib.request.urlopen(dataset.url, timeout=timeout) as response:
        target.write_bytes(response.read())
    return target


def dataset_by_name(name: str) -> Optional[OTRFDataset]:
    for dataset in OTRF_DATASETS:
        if dataset.name == name:
            return dataset
    return None

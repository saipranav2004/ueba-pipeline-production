"""
ingestion/source.py — Source-agnostic event ingestion.

`EventSource` is the seam that lets this pipeline run against the file-based
synthetic generator and a real-time Kafka topic through the same interface,
without touching parsing or feature code. `FileEventSource` reads the JSONL the
generator produces; `KafkaEventSource` consumes a live topic via the
librdkafka-backed `confluent-kafka` client with at-least-once semantics.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

from ueba_pipeline.parsing.normalize import NormalizedEvent, normalize_event


@dataclass
class IngestStats:
    """Ingest counters surfaced to monitoring/.

    A pipeline that silently drops unparseable records hides a data-quality
    problem until it has already skewed a baseline, so every record is either
    parsed or counted."""

    total_records: int = 0
    unrecognized_envelope: int = 0
    parsed_with_warnings: int = 0
    by_event_type: dict | None = None

    def __post_init__(self) -> None:
        if self.by_event_type is None:
            self.by_event_type = {}

    def record(self, ne: Optional[NormalizedEvent]) -> None:
        self.total_records += 1
        if ne is None:
            self.unrecognized_envelope += 1
            return
        if ne.parse_warnings:
            self.parsed_with_warnings += 1
        self.by_event_type[ne.event_type] = self.by_event_type.get(ne.event_type, 0) + 1


class EventSource(ABC):
    """Protocol every ingestion backend must satisfy. Kept deliberately
    narrow (one method) so a Kafka, S3, or database-backed implementation
    can be dropped in without a broader interface renegotiation."""

    @abstractmethod
    def read(self) -> Iterator[NormalizedEvent]:
        """Yields NormalizedEvent records in the order the backend can best
        provide them. Ordering guarantees (or lack thereof) are a property
        of the concrete backend and must be documented there — this
        pipeline's feature engineering assumes events within a user's
        window are order-independent (it aggregates, doesn't replay a
        state machine), so strict ordering is not required."""
        raise NotImplementedError


class FileEventSource(EventSource):
    """Reads newline-delimited JSON (JSONL) files, one record per line, as
    produced by enterprise_simulator. Handles multiple files/directories,
    quarantines (counts, does not raise on) malformed JSON lines and
    unrecognized envelopes, per the "never silently drop" rule in
    parsing/normalize.py.
    """

    # enterprise_simulator writes each event to BOTH a per-channel directory
    # (security_logs/, sysmon_logs/, dns_logs/, ...) AND a merged `kafka_json/`
    # directory that mirrors every event combined into one stream. `kafka_json/`
    # represents what a real deployment publishes to a Kafka topic -- it is an
    # ALTERNATE representation of the same data, not an additional source, so
    # reading it alongside the per-channel files would double-count every event.
    # The recursive glob (`**/*.jsonl`) cannot know that, so these directories
    # are excluded by name.
    _ALTERNATE_REPRESENTATION_DIRS = {"kafka_json", "csv_exports"}

    def __init__(self, paths: list[str | Path], stats: Optional[IngestStats] = None):
        self.paths = [Path(p) for p in paths]
        self.stats = stats if stats is not None else IngestStats()

    @classmethod
    def from_directory(cls, root: str | Path, pattern: str = "**/*.jsonl") -> "FileEventSource":
        root = Path(root)
        all_paths = sorted(root.glob(pattern))
        paths = [
            p for p in all_paths
            if not (cls._ALTERNATE_REPRESENTATION_DIRS & set(p.relative_to(root).parts))
        ]
        excluded = len(all_paths) - len(paths)
        if excluded:
            import sys
            print(
                f"[FileEventSource] excluded {excluded} file(s) under "
                f"{sorted(cls._ALTERNATE_REPRESENTATION_DIRS)} — these are "
                f"alternate/merged representations of the same events found "
                f"in the per-channel directories, not additional data. "
                f"Ingesting both would double-count every event.",
                file=sys.stderr,
            )
        return cls(paths)

    def read(self, keep_raw: bool = True) -> Iterator[NormalizedEvent]:
        """Yield NormalizedEvents from all files. keep_raw=False drops each
        event's raw_event_data (unused by feature extraction) to roughly halve
        per-event memory on the batch training/scoring path."""
        for path in self.paths:
            with open(path, "r") as f:
                for line_no, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        raw = json.loads(line)
                    except json.JSONDecodeError:
                        self.stats.total_records += 1
                        self.stats.unrecognized_envelope += 1
                        continue
                    ne = normalize_event(raw, keep_raw=keep_raw)
                    self.stats.record(ne)
                    if ne is not None:
                        yield ne


class KafkaEventSource(EventSource):
    """Real-time ingestion from a Kafka topic, using ``confluent-kafka``
    (librdkafka) -- the C-backed client Confluent maintains, which matches the
    Java client's throughput and is the production standard for Python (the pure
    Python ``kafka-python`` is unmaintained/deprecated).

    Design decisions, chosen for correctness with this pipeline's semantics:

    * **At-least-once delivery.** ``enable.auto.commit`` is disabled and offsets
      are committed only *after* an event has been handed downstream (the
      generator commits when it resumes past ``yield``). A crash mid-batch
      therefore re-delivers at most the in-flight event rather than dropping it.
      At-least-once (not exactly-once) is the right choice here because feature
      engineering aggregates events within a user's window and is idempotent to
      a re-delivered duplicate -- it does not replay a state machine -- so the
      transactional overhead of exactly-once buys nothing.
    * **Natural backpressure.** ``read()`` is a pull-based generator over
      ``poll()``; if feature computation falls behind, the consumer simply polls
      less often. There is no unbounded internal buffer to overflow, and
      librdkafka's fetch queue is bounded by ``queued.max.messages.kbytes``.
    * **Raw JSON on the wire.** Records are parsed with the same
      ``normalize_event`` path as files, so a Winlogbeat/NXLog JSON producer
      needs no schema registry. Avro/Protobuf + Schema Registry can be added
      behind this same seam by swapping the deserializer without touching
      parsing or feature code.

    Security (SASL_SSL/mTLS) and consumer tuning are passed through ``config``
    so a hardened broker (see docker/docker-compose.prod.yml) is a config change,
    not a code change.
    """

    def __init__(
        self,
        bootstrap_servers: list[str],
        topic: str,
        group_id: str,
        stats: Optional[IngestStats] = None,
        poll_timeout_seconds: float = 1.0,
        auto_offset_reset: str = "latest",
        extra_config: Optional[dict] = None,
        stop_on_eof: bool = False,
    ):
        self.bootstrap_servers = bootstrap_servers
        self.topic = topic
        self.group_id = group_id
        self.stats = stats if stats is not None else IngestStats()
        self.poll_timeout_seconds = poll_timeout_seconds
        self.auto_offset_reset = auto_offset_reset
        self.extra_config = extra_config or {}
        # stop_on_eof=True makes read() terminate when it reaches the end of every
        # partition, which is what batch/replay and tests want; the streaming
        # default (False) blocks waiting for new events forever.
        self.stop_on_eof = stop_on_eof

    def _build_config(self) -> dict:
        config = {
            "bootstrap.servers": ",".join(self.bootstrap_servers),
            "group.id": self.group_id,
            "enable.auto.commit": False,      # at-least-once: commit after processing
            "auto.offset.reset": self.auto_offset_reset,
            "enable.partition.eof": self.stop_on_eof,
        }
        # extra_config carries SASL_SSL/mTLS and tuning; caller-provided keys win.
        config.update(self.extra_config)
        return config

    def read(self) -> Iterator[NormalizedEvent]:
        """Consume the topic, yielding NormalizedEvent records. Offsets are
        committed after each record is consumed downstream (at-least-once).

        Ordering: Kafka guarantees per-partition order but not cross-partition
        order. This pipeline's feature engineering is order-independent within a
        user's window, so partition-level ordering is sufficient and no global
        reordering is performed.
        """
        # Imported lazily so the rest of the pipeline (and the file path) has no
        # hard dependency on confluent-kafka being installed.
        try:
            from confluent_kafka import Consumer, KafkaError
        except ImportError as exc:  # pragma: no cover - environment-dependent
            raise RuntimeError(
                "KafkaEventSource requires the 'confluent-kafka' package. "
                "Install it with: pip install confluent-kafka"
            ) from exc

        consumer = Consumer(self._build_config())
        consumer.subscribe([self.topic])
        eof_partitions: set = set()
        try:
            while True:
                msg = consumer.poll(self.poll_timeout_seconds)
                if msg is None:
                    if self.stop_on_eof and eof_partitions:
                        # Reached EOF on at least one partition and nothing new
                        # is arriving -- in replay mode, stop.
                        break
                    continue
                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        if self.stop_on_eof:
                            eof_partitions.add((msg.topic(), msg.partition()))
                        continue
                    # A real broker/consumer error: surface it rather than
                    # silently spinning.
                    raise RuntimeError(f"Kafka consume error: {msg.error()}")

                self.stats.total_records += 1
                try:
                    raw = json.loads(msg.value())
                except (json.JSONDecodeError, TypeError):
                    self.stats.unrecognized_envelope += 1
                    consumer.commit(msg, asynchronous=False)
                    continue

                ne = normalize_event(raw)
                # record() already increments total_records, so account for the
                # manual increment above.
                self.stats.total_records -= 1
                self.stats.record(ne)
                if ne is not None:
                    yield ne
                # Commit only after the consumer of this generator has processed
                # the event (execution resumes here past the yield) -- this is
                # what makes delivery at-least-once rather than at-most-once.
                consumer.commit(msg, asynchronous=False)
        finally:
            consumer.close()

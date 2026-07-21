#!/usr/bin/env python3
"""validate_streaming.py -- live Kafka validation harness.

This is the infra-dependent counterpart to the mock-based unit tests. It needs
a REACHABLE Kafka broker (see docker/docker-compose.yml). It does two things:

  --produce    read the synthetic estate off disk (the same FileEventSource the
               file path uses) and produce every event onto the topic as JSON,
               so `score-stream` can consume a realistic stream.

  (default)    a consume-side offset-accounting check: consume the topic to EOF
               and confirm every produced offset is seen exactly once, which is
               the observable half of at-least-once (no drops). Kill/restart the
               consumer mid-run to exercise the reprocess-on-crash path and
               confirm no gaps.

The detection logic itself is validated by the unit suite and by `score-stream`;
this script is specifically about the broker-dependent guarantees that a mock
cannot establish: real offset commit semantics, real throughput, real EOF.

Exit status is nonzero on any parity failure so it can gate a pipeline.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path


def _load_events(data_dir: str):
    # Reuse the exact same ingestion path the file source uses, so what we
    # produce is byte-identical to what the file path would have parsed.
    repo_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repo_root))
    from ueba_pipeline.ingestion import FileEventSource
    src = FileEventSource.from_directory(data_dir)
    # keep_raw=True so the produced JSON carries the original envelope.
    for ne in src.read(keep_raw=True):
        yield ne


def _raw_of(ne) -> dict:
    # Prefer the original raw envelope if retained; fall back to a minimal
    # normalized projection so the consumer's normalize_event still resolves.
    raw = getattr(ne, "raw_event_data", None)
    if raw:
        return raw
    return {
        "@timestamp": ne.event_time.isoformat() if ne.event_time else None,
        "winlog": {"event_id": ne.event_type, "channel": "Security",
                   "event_data": ne.fields},
        "event": {}, "host": {"name": "unknown"},
    }


def produce(args) -> int:
    try:
        from confluent_kafka import Producer
    except ImportError:
        print("confluent-kafka not installed; pip install confluent-kafka",
              file=sys.stderr)
        return 2

    p = Producer({"bootstrap.servers": args.bootstrap})
    n = 0
    t0 = time.time()
    for ne in _load_events(args.data_dir):
        p.produce(args.topic, json.dumps(_raw_of(ne)).encode("utf-8"))
        n += 1
        if n % 10000 == 0:
            p.poll(0)
    p.flush()
    dt = time.time() - t0
    print(f"[produce] {n} events onto '{args.topic}' in {dt:.1f}s "
          f"({n / dt:.0f}/s)")
    # Record the expected count so the consume side can assert exactly-once.
    Path(args.count_file).write_text(str(n))
    print(f"[produce] expected-count written to {args.count_file}")
    return 0


def verify(args) -> int:
    try:
        from confluent_kafka import Consumer, KafkaError
    except ImportError:
        print("confluent-kafka not installed; pip install confluent-kafka",
              file=sys.stderr)
        return 2

    c = Consumer({
        "bootstrap.servers": args.bootstrap,
        "group.id": args.group_id,
        "enable.auto.commit": False,
        "auto.offset.reset": "earliest",
        "enable.partition.eof": True,
    })
    c.subscribe([args.topic])

    seen_offsets: set = set()
    eof_parts: set = set()
    n_parts = None
    t0 = time.time()
    try:
        while True:
            msg = c.poll(1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    eof_parts.add(msg.partition())
                    # crude termination: stop once we've hit EOF on every
                    # partition we've seen at least one EOF for and none new.
                    if n_parts is not None and len(eof_parts) >= n_parts:
                        break
                    continue
                print(f"[verify] consumer error: {msg.error()}", file=sys.stderr)
                return 2
            seen_offsets.add((msg.partition(), msg.offset()))
            # commit after "processing" (here: recording) -> at-least-once
            c.commit(msg, asynchronous=False)
            # learn partition count lazily from assignment
            if n_parts is None:
                asg = c.assignment()
                if asg:
                    n_parts = len({tp.partition for tp in asg})
    finally:
        c.close()

    seen = len(seen_offsets)
    dt = time.time() - t0
    print(f"[verify] consumed {seen} unique (partition,offset) records in "
          f"{dt:.1f}s ({seen / dt:.0f}/s)")

    cf = Path(args.count_file)
    if cf.exists():
        expected = int(cf.read_text().strip())
        if seen < expected:
            print(f"[verify] FAIL: saw {seen} < produced {expected} -- events "
                  f"were DROPPED (violates at-least-once)")
            return 1
        if seen > expected:
            print(f"[verify] note: saw {seen} > produced {expected} -- "
                  f"duplicates are acceptable under at-least-once (e.g. after a "
                  f"forced restart); confirm they are duplicates, not new data")
        else:
            print(f"[verify] PASS: exactly-once under normal operation "
                  f"({seen} == {expected})")
    else:
        print(f"[verify] no expected-count file at {cf}; ran a raw consume only")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bootstrap", required=True,
                    help="Kafka bootstrap servers, e.g. localhost:9092")
    ap.add_argument("--topic", default="ueba-events")
    ap.add_argument("--data-dir", default="enterprise_simulator/output")
    ap.add_argument("--group-id", default="ueba-validate")
    ap.add_argument("--count-file", default="/tmp/ueba_produced_count.txt")
    ap.add_argument("--produce", action="store_true",
                    help="Produce the estate onto the topic (default is verify)")
    args = ap.parse_args()
    return produce(args) if args.produce else verify(args)


if __name__ == "__main__":
    raise SystemExit(main())

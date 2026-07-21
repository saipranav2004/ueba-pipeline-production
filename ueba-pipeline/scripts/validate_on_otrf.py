"""Download the curated OTRF Security-Datasets and validate the engine's ingestion
against real Windows/Sysmon telemetry.

This is the real-data counterpart to the simulator benchmark. It does NOT measure
detection recall — OTRF captures have no realistic benign baseline (see
ueba_pipeline/evaluation/otrf_adapter.py). It measures something the simulator
cannot: that the parser, canonical field maps, feature contract and graph edge
projections all fire correctly on genuine Windows event schemas.

Usage:
    python scripts/validate_on_otrf.py [--cache-dir artifacts/otrf]

Requires network access to raw.githubusercontent.com. Prints a per-dataset table
and exits non-zero if any curated dataset fails to project its expected views.
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ueba_pipeline.evaluation.otrf_adapter import (
    OTRF_DATASETS, download_otrf_dataset, read_otrf_events,
)
from ueba_pipeline.graph.auth_graph_anomaly import (
    AuthGraphAnomalyDetector, AuthGraphConfig,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", default="artifacts/otrf")
    args = parser.parse_args()

    print(f"{'dataset':16} {'technique':11} {'records':>8} {'parsed':>7} "
          f"{'mapped':>7}  views (expected -> projected)", flush=True)

    failures = 0
    for dataset in OTRF_DATASETS:
        try:
            local = download_otrf_dataset(dataset, args.cache_dir)
        except Exception as exc:
            print(f"{dataset.name:16} DOWNLOAD FAILED: {exc}", flush=True)
            failures += 1
            continue

        events = list(read_otrf_events(local))
        timed = [e for e in events if e.event_time]
        mapped = [e for e in timed if e.event_type != "unknown"]

        graph = AuthGraphAnomalyDetector(config=AuthGraphConfig())
        views = Counter(v for e in timed for v, _ in graph.edges_for(e))
        projected = set(views)
        missing = set(dataset.expected_views) - projected
        status = "OK" if not missing else f"MISSING {sorted(missing)}"
        if missing:
            failures += 1

        print(f"{dataset.name:16} {dataset.technique:11} {len(events):>8} "
              f"{len(timed):>7} {len(mapped):>7}  "
              f"{sorted(dataset.expected_views)} -> {dict(views)}  {status}",
              flush=True)

    if failures:
        print(f"\n{failures} dataset(s) failed validation", flush=True)
        sys.exit(1)
    print("\nall curated OTRF datasets ingest and project their expected views",
          flush=True)


if __name__ == "__main__":
    main()

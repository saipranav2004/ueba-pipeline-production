"""Measure throughput, latency, memory and how each scales with estate size.

Production claims about performance have to be measured rather than predicted.
This reports four things the deployment guide needs:

  fit / score throughput    events per second on the batch path
  streaming latency         per-event scoring cost, including tail percentiles,
                            because a stream is judged on its slow events
  resident state            the detector's in-memory footprint and the size of
                            the persisted bundle
  scaling                   how all of the above move as the estate grows, which
                            is the claim that actually needs testing: updates are
                            O(1) per edge, but the number of *distinct* edges
                            grows with the estate, and that is what bounds memory

Usage:
    python scripts/benchmark_performance.py [--bench-dir artifacts/bench]
"""
from __future__ import annotations

import argparse
import glob
import statistics
import sys
import time
import tracemalloc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ueba_pipeline.config.schema import load_config
from ueba_pipeline.engine import BehavioralEngine, EngineConfig, _time_sorted_graph_events
from ueba_pipeline.ingestion.source import FileEventSource


def _graph_state_size(graph) -> tuple:
    """Distinct edges held, and the detector's traced heap footprint."""
    edges = sum(len(view) for view in graph._edges.values())
    counters = sum(len(m) for store in (graph._dst_counts, graph._src_counts,
                                        graph._src_totals, graph._dst_totals)
                   for m in store.values())
    return edges, counters


def measure(data_dir: str, fraction: float):
    config = load_config()
    events = [e for e in FileEventSource.from_directory(data_dir).read() if e.event_time]
    events.sort(key=lambda e: e.event_time)
    if fraction < 1.0:
        events = events[: int(len(events) * fraction)]
    split = int(len(events) * 0.60)
    train, test = events[:split], events[split:]

    engine = BehavioralEngine(config=EngineConfig(
        window_hours=config.window.feature_window_hours))

    tracemalloc.start()
    t0 = time.perf_counter()
    engine.fit(train, config_capability=config.capability)
    fit_s = time.perf_counter() - t0
    _, fit_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    t0 = time.perf_counter()
    detections, risks = engine.score(test)
    score_s = time.perf_counter() - t0

    # Per-event streaming latency over the graph-bearing events, which are the
    # ones that do work; the rest are filtered before scoring.
    stream_events = _time_sorted_graph_events(test)[:4000]
    latencies = []
    sessions = None
    from ueba_pipeline.graph.sessions import SessionResolver
    sessions = SessionResolver().fit(test, lambda v: str(v or "").strip().lower())
    for e in stream_events:
        cell = {}
        t0 = time.perf_counter()
        engine._score_graph_event(e, cell, absorb=True, sessions=sessions)
        latencies.append((time.perf_counter() - t0) * 1e6)   # microseconds

    edges, counters = _graph_state_size(engine.graph)

    import io, json
    from ueba_pipeline.models.serialization import engine_to_bundle
    state, arrays = engine_to_bundle(engine)
    bundle_bytes = len(json.dumps(state).encode()) + sum(a.nbytes for a in arrays.values())

    latencies.sort()
    return {
        "events": len(events),
        "entities": len({r.entity for r in risks}),
        "fit_eps": len(train) / max(fit_s, 1e-9),
        "score_eps": len(test) / max(score_s, 1e-9),
        "fit_peak_mib": fit_peak / 1024 / 1024,
        "p50_us": statistics.median(latencies) if latencies else 0.0,
        "p99_us": latencies[int(len(latencies) * 0.99)] if latencies else 0.0,
        "edges": edges,
        "counters": counters,
        "bundle_kib": bundle_bytes / 1024,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bench-dir", default="artifacts/bench")
    args = parser.parse_args()

    estates = sorted(glob.glob(f"{args.bench_dir}/seed_*"))
    if not estates:
        sys.exit(f"no seeded estates under {args.bench_dir}/seed_*")
    estate = estates[0]

    print("Scaling with estate size (fraction of one estate's event stream)\n", flush=True)
    header = (f"{'events':>9}{'fit ev/s':>11}{'score ev/s':>12}{'fit MiB':>9}"
              f"{'p50 us':>9}{'p99 us':>9}{'edges':>9}{'counters':>10}{'bundle KiB':>12}")
    print(header, flush=True)
    for fraction in (0.125, 0.25, 0.5, 1.0):
        m = measure(estate, fraction)
        print(f"{m['events']:>9}{m['fit_eps']:>11,.0f}{m['score_eps']:>12,.0f}"
              f"{m['fit_peak_mib']:>9.1f}{m['p50_us']:>9.1f}{m['p99_us']:>9.1f}"
              f"{m['edges']:>9}{m['counters']:>10}{m['bundle_kib']:>12.1f}", flush=True)

    print("\nAcross all estates at full size\n", flush=True)
    print(header, flush=True)
    for estate in estates:
        m = measure(estate, 1.0)
        print(f"{m['events']:>9}{m['fit_eps']:>11,.0f}{m['score_eps']:>12,.0f}"
              f"{m['fit_peak_mib']:>9.1f}{m['p50_us']:>9.1f}{m['p99_us']:>9.1f}"
              f"{m['edges']:>9}{m['counters']:>10}{m['bundle_kib']:>12.1f}", flush=True)


if __name__ == "__main__":
    main()

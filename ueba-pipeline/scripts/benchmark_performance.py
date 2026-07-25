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
    """Distinct edges held, and the counter entries backing them."""
    edges = sum(len(view) for view in graph._edges.values())
    counters = sum(len(m) for store in (graph._dst_counts, graph._src_counts,
                                        graph._src_totals, graph._dst_totals)
                   for m in store.values())
    return edges, counters


def _track_state_size(engine) -> int:
    """Per-entity rows held by the deviation queues.

    These grow with the number of identities directly, not with their working
    set, so they are the part of resident state most exposed to estate size --
    which is exactly why they belong in a scaling measurement rather than being
    assumed cheap.
    """
    rows = 0
    for name in ("nhi_track", "insider_track"):
        track = getattr(engine, name, None)
        if track is None:
            continue
        rows += len(track._hour_counts) + len(track._counts._total)
        rows += len(track.covered)
    return rows


def _engine_state_size(engine) -> tuple:
    """Distinct edges and counters across EVERY queue, not just the relational one.

    The published scaling table measured `engine.graph` alone. That was accurate
    when the engine had one queue; it now has four, and the execution queue holds
    a second graph whose views are disjoint from the relational one. Reporting
    only the first understates resident state by however large the second is.
    """
    edges, counters = _graph_state_size(engine.graph)
    exec_edges = exec_counters = 0
    if getattr(engine, "execution_graph", None) is not None:
        exec_edges, exec_counters = _graph_state_size(engine.execution_graph)
    return edges, counters, exec_edges, exec_counters, _track_state_size(engine)


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
    _detections, risks = engine.score(test)
    score_s = time.perf_counter() - t0

    # The analyst-facing scoring path is score() PLUS score_queues(); an operator
    # waits for both. Measuring only the first understated the cost of a run by
    # however much the execution and deviation queues take, which is the number
    # this line exists to stop guessing at.
    t0 = time.perf_counter()
    queues = engine.score_queues(test)
    queues_s = time.perf_counter() - t0

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

    edges, counters, exec_edges, exec_counters, track_rows = _engine_state_size(engine)

    import json

    from ueba_pipeline.models.serialization import engine_to_bundle
    state, arrays = engine_to_bundle(engine)
    bundle_bytes = len(json.dumps(state).encode()) + sum(a.nbytes for a in arrays.values())

    latencies.sort()
    return {
        "events": len(events),
        "entities": len({r.entity for r in risks}),
        "fit_eps": len(train) / max(fit_s, 1e-9),
        "score_eps": len(test) / max(score_s, 1e-9),
        "queues_eps": len(test) / max(queues_s, 1e-9),
        # What an operator actually waits for: both scoring passes over one batch.
        "total_score_eps": len(test) / max(score_s + queues_s, 1e-9),
        "fit_peak_mib": fit_peak / 1024 / 1024,
        "p50_us": statistics.median(latencies) if latencies else 0.0,
        "p99_us": latencies[int(len(latencies) * 0.99)] if latencies else 0.0,
        "edges": edges,
        "counters": counters,
        "exec_edges": exec_edges,
        "exec_counters": exec_counters,
        "track_rows": track_rows,
        "total_edges": edges + exec_edges,
        "queue_alerts": {k: sum(1 for a in v if a.alerted) for k, v in queues.items()},
        "bundle_kib": bundle_bytes / 1024,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bench-dir", default="artifacts/bench")
    args = parser.parse_args()

    estates = sorted(glob.glob(f"{args.bench_dir}/seed_*"))
    if not estates:
        sys.exit(f"no seeded estates under {args.bench_dir}/seed_*")

    header = (f"{'estate':<14}{'ids':>7}{'events':>10}{'fit ev/s':>10}"
              f"{'rel ev/s':>10}{'queue ev/s':>11}{'both ev/s':>10}{'fit MiB':>9}"
              f"{'p50 us':>8}{'p99 us':>8}{'rel edg':>9}{'exec edg':>9}"
              f"{'trk rows':>9}{'bundle KiB':>11}")

    def row(label, m):
        print(f"{label:<14}{m['entities']:>7}{m['events']:>10}{m['fit_eps']:>10,.0f}"
              f"{m['score_eps']:>10,.0f}{m['queues_eps']:>11,.0f}"
              f"{m['total_score_eps']:>10,.0f}{m['fit_peak_mib']:>9.1f}"
              f"{m['p50_us']:>8.1f}{m['p99_us']:>8.1f}{m['edges']:>9}"
              f"{m['exec_edges']:>9}{m['track_rows']:>9}{m['bundle_kib']:>11.1f}",
              flush=True)

    print("Scaling with estate size (fraction of one estate's event stream)\n", flush=True)
    print(header, flush=True)
    estate = estates[0]
    for fraction in (0.125, 0.25, 0.5, 1.0):
        row(f"{fraction:g}x stream", measure(estate, fraction))

    print("\nAcross all estates at full size\n", flush=True)
    print(header, flush=True)
    for estate in estates:
        m = measure(estate, 1.0)
        row(Path(estate).name, m)
        print(f"{'':<14}alerts per queue: {m['queue_alerts']}", flush=True)


if __name__ == "__main__":
    main()

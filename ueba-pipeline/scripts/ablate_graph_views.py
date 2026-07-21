"""Measure what each relationship view contributes to detection.

A view earns its place only if removing it costs recall, or if keeping it costs
false positives it does not repay. This runs the shipped evaluation harness over
every seeded estate once per configuration:

  * ``all``            -- every view (the baseline)
  * ``drop:<view>``    -- every view except one (leave-one-out)
  * ``only:<view>``    -- that view alone (standalone contribution)

Leave-one-out and standalone answer different questions. A view can be redundant
(dropping it costs nothing because another view catches the same attacks) while
still being individually capable, and a view can be individually weak while
carrying attacks nothing else sees. Both are reported so the decision is not made
on one number.

Usage:
    python scripts/ablate_graph_views.py [--bench-dir artifacts/bench]
"""
from __future__ import annotations

import argparse
import glob
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ueba_pipeline.config.schema import load_config
from ueba_pipeline.engine import BehavioralEngine, EngineConfig
from ueba_pipeline.evaluation.honest_eval import _evaluate_detections, _load
from ueba_pipeline.features import observed_entity_windows
from ueba_pipeline.graph.auth_graph_anomaly import AuthGraphAnomalyDetector, AuthGraphConfig

ALL_VIEWS = ("user_src", "src_dst", "proc_access", "rare_proc",
             "kerb_ctx", "tgs_enc", "dir_op")


def run_estate(data_dir: str, views, train_fraction: float = 0.60):
    config = load_config()
    events, labels = _load(data_dir)
    t0, t1 = events[0].event_time, events[-1].event_time
    split = t0 + (t1 - t0) * train_fraction

    train = [e for e in events if e.event_time < split]
    test = [e for e in events if e.event_time >= split]
    test_days = (t1 - split).total_seconds() / 86400.0
    test_attacks = [a for a in labels if a["_e"] >= split]

    engine = BehavioralEngine(config=EngineConfig(
        window_hours=config.window.feature_window_hours))
    engine.graph = AuthGraphAnomalyDetector(
        config=AuthGraphConfig(enabled_views=frozenset(views)))
    engine.fit(train, config_capability=config.capability)
    detections, _ = engine.score(test)
    windows = observed_entity_windows(test, engine.config.window_hours)
    return _evaluate_detections(engine, detections, test_attacks, test_days,
                                len(windows), "none", windows)


def evaluate_config(estates, views):
    detected = total = 0
    fps = []
    caught = set()
    for estate in estates:
        r = run_estate(estate, views)
        detected += r.detected
        total += r.n_test_attacks
        fps.append(r.alerts_per_day)
        for key, hit in r.per_attack.items():
            if hit:
                caught.add(f"{estate}:{key}")
    return detected, total, sum(fps) / len(fps), caught


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bench-dir", default="artifacts/bench")
    args = parser.parse_args()

    estates = sorted(glob.glob(f"{args.bench_dir}/seed_*"))
    if not estates:
        sys.exit(f"no seeded estates under {args.bench_dir}/seed_*")

    print(f"{'configuration':24}{'recall':>12}{'FP/day':>9}{'delta':>8}", flush=True)

    base_det, base_tot, base_fp, base_caught = evaluate_config(estates, ALL_VIEWS)
    print(f"{'all views':24}{base_det:>5}/{base_tot:<6}{base_fp:>9.2f}{'--':>8}", flush=True)

    print("\n-- leave one out --", flush=True)
    for view in ALL_VIEWS:
        kept = [v for v in ALL_VIEWS if v != view]
        det, tot, fp, _ = evaluate_config(estates, kept)
        print(f"{'drop ' + view:24}{det:>5}/{tot:<6}{fp:>9.2f}{det - base_det:>+8}",
              flush=True)

    print("\n-- standalone --", flush=True)
    for view in ALL_VIEWS:
        det, tot, fp, caught = evaluate_config(estates, [view])
        unique = len(caught - (base_caught - caught))
        print(f"{'only ' + view:24}{det:>5}/{tot:<6}{fp:>9.2f}"
              f"{'':>8}  attacks: {det}", flush=True)


if __name__ == "__main__":
    main()

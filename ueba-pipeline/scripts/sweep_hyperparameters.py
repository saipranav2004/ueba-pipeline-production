"""Measure how sensitive detection is to each free parameter.

This reports sensitivity, not a tuned optimum. Picking the value that maximises
recall on the same estates the headline is quoted from would be selection on the
test set, and the resulting number would be a restatement of the search rather
than a measurement. What is useful is the *shape*: a parameter whose curve is
flat needs no justification beyond its default, while a peaked one is load
bearing and its default has to be defended.

Parameters swept:

  alpha                       Dirichlet concentration for the back-off to the
                              global marginal. Small values trust the per-source
                              history completely; large values ignore it.
  absorb_surprise             Surprise above which an edge is not folded into the
                              baseline, so repeated abuse cannot be laundered.
                              Governs the streaming path only; batch score() never
                              absorbs, so it cannot move the batch benchmark.
  null_calibration_fraction   Share of training held out to measure each view's
                              benign null against a frozen baseline.

Usage:
    python scripts/sweep_hyperparameters.py [--bench-dir artifacts/bench]
"""
from __future__ import annotations

import argparse
import glob
import statistics
import sys
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ueba_pipeline.config.schema import load_config
from ueba_pipeline.engine import BehavioralEngine, EngineConfig
from ueba_pipeline.evaluation.honest_eval import _evaluate_detections, _load
from ueba_pipeline.features import observed_entity_windows
from ueba_pipeline.graph.auth_graph_anomaly import AuthGraphAnomalyDetector, AuthGraphConfig


def run_estate(data_dir: str, graph_cfg: AuthGraphConfig, engine_cfg: EngineConfig,
               train_fraction: float = 0.60):
    config = load_config()
    events, labels = _load(data_dir)
    t0, t1 = events[0].event_time, events[-1].event_time
    split = t0 + (t1 - t0) * train_fraction

    train = [e for e in events if e.event_time < split]
    test = [e for e in events if e.event_time >= split]
    test_days = (t1 - split).total_seconds() / 86400.0
    test_attacks = [a for a in labels if a["_e"] >= split]

    engine = BehavioralEngine(config=engine_cfg)
    engine.graph = AuthGraphAnomalyDetector(config=graph_cfg)
    engine.fit(train, config_capability=config.capability)
    detections, _ = engine.score(test)
    windows = observed_entity_windows(test, engine.config.window_hours)
    return _evaluate_detections(engine, detections, test_attacks, test_days,
                                len(windows), "none", windows)


def evaluate(estates, graph_cfg, engine_cfg):
    det = tot = 0
    fps = []
    for estate in estates:
        r = run_estate(estate, graph_cfg, engine_cfg)
        det += r.detected
        tot += r.n_test_attacks
        fps.append(r.alerts_per_day)
    return det, tot, statistics.fmean(fps)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bench-dir", default="artifacts/bench")
    args = parser.parse_args()

    estates = sorted(glob.glob(f"{args.bench_dir}/seed_*"))
    if not estates:
        sys.exit(f"no seeded estates under {args.bench_dir}/seed_*")

    base_graph = AuthGraphConfig()
    base_engine = EngineConfig(window_hours=load_config().window.feature_window_hours)

    sweeps = {
        "alpha": [0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0],
        "absorb_surprise": [6.0, 8.0, 10.0, 12.0, 16.0, 24.0, 1e9],
        "null_calibration_fraction": [0.15, 0.20, 0.30, 0.40, 0.50],
    }

    print(f"{'parameter':28}{'value':>12}{'recall':>12}{'FP/day':>9}", flush=True)
    for name, values in sweeps.items():
        results = []
        for value in values:
            if name == "null_calibration_fraction":
                g, e = base_graph, replace(base_engine, null_calibration_fraction=value)
            else:
                g, e = replace(base_graph, **{name: value}), base_engine
            det, tot, fp = evaluate(estates, g, e)
            results.append(det)
            marker = "  <- default" if _is_default(name, value) else ""
            shown = "no cap" if value == 1e9 else value
            print(f"{name:28}{str(shown):>12}{det:>5}/{tot:<6}{fp:>9.2f}{marker}",
                  flush=True)
        span = max(results) - min(results)
        print(f"{'':28}{'spread':>12}{span:>5} detections across the range\n", flush=True)


def _is_default(name: str, value) -> bool:
    defaults = {"alpha": 1.0, "absorb_surprise": 12.0,
                "null_calibration_fraction": 0.30}
    return defaults.get(name) == value


if __name__ == "__main__":
    main()

"""Driver for the classical-model comparison (ueba_pipeline.evaluation.model_benchmark).

Runs every split protocol over every seeded estate under artifacts/bench/, writes
the aggregate report and the per-fold rows to disk, and prints progress as it goes
so a long run is observable and its partial results survive an interruption.

Usage:
    python scripts/run_model_benchmark.py [--window-hours 1.0] [--out artifacts/bench]
"""
from __future__ import annotations

import argparse
import csv
import glob
import json
import sys
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ueba_pipeline.evaluation.model_benchmark import (
    aggregate,
    build_window_dataset,
    evaluate_graph_reference,
    graph_reference_scores,
    render,
    run_protocol,
)

PROTOCOLS = ["temporal", "entity_disjoint", "entity_and_time_disjoint",
             "attack_family_disjoint"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--window-hours", type=float, default=1.0)
    parser.add_argument("--bench-dir", default="artifacts/bench")
    parser.add_argument("--out", default="artifacts/bench")
    args = parser.parse_args()

    dirs = sorted(glob.glob(f"{args.bench_dir}/seed_*"))
    if not dirs:
        sys.exit(f"no seeded estates under {args.bench_dir}/seed_*")
    print(f"datasets: {len(dirs)}", flush=True)

    datasets = []
    for d in dirs:
        data = build_window_dataset(d, args.window_hours)
        datasets.append(data)
        print(f"  built {d}: {len(data)} windows, {int(data.y.sum())} positives, "
              f"prevalence={data.prevalence:.5f}", flush=True)

    all_rows = []
    for protocol in PROTOCOLS:
        for data in datasets:
            rows = run_protocol(data, protocol)
            all_rows.extend(rows)
            print(f"  {protocol:<26} {data.source:<32} folds_scored={len(rows)}",
                  flush=True)

    # Graph-track reference column (temporal protocol only): the shipped
    # relational detector scored on its own substrate, mapped onto the same
    # windows so its per-window PR-AUC sits beside the classical models.
    for data in datasets:
        cell_scores = graph_reference_scores(data.source, data)
        if cell_scores is None:
            continue
        row = evaluate_graph_reference(data, cell_scores)
        if row is not None:
            all_rows.append(row)
            print(f"  graph_reference            {data.source:<32} scored", flush=True)

    report = render(aggregate(all_rows), datasets)
    print("\n" + report, flush=True)

    with open(f"{args.out}/model_comparison.txt", "w", encoding="utf-8") as handle:
        handle.write(report + "\n")
    with open(f"{args.out}/model_comparison_folds.csv", "w", newline="",
              encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(asdict(all_rows[0]).keys()))
        writer.writeheader()
        for row in all_rows:
            writer.writerow(asdict(row))
    with open(f"{args.out}/model_comparison_aggregate.json", "w",
              encoding="utf-8") as handle:
        json.dump([asdict(a) for a in aggregate(all_rows)], handle, indent=2)

    print(f"\nwrote report + {len(all_rows)} fold rows to {args.out}/", flush=True)


if __name__ == "__main__":
    main()

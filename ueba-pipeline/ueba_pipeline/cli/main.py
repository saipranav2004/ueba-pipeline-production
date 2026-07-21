"""cli/main.py -- ``python -m ueba_pipeline.cli.main <command>``.

Commands:
  train             ingest -> features -> fit the engine -> signed bundle
  score             load bundle -> ingest -> score -> ranked entity alerts
  score-stream      load bundle -> score online, adapting the baseline as it goes
  drift-check       compare a live window's capabilities against the trained bundle
  walk-forward-eval causal out-of-time evaluation of the engine
  model-benchmark   compare classical models on the feature matrix (leakage-resistant)
  lanl-eval         per-authentication ROC on LANL 2015 (or a LANL-format fixture)
  graph-viz         render the identity graph to standalone HTML

Thin orchestration only; detection logic lives in ueba_pipeline.engine and the
graph detector it composes.
"""
from __future__ import annotations

import argparse
import sys

from ueba_pipeline.config import load_config
from ueba_pipeline.ingestion import FileEventSource
from ueba_pipeline.engine import BehavioralEngine, EngineConfig, is_graph_event


def _read_events(data_dir: str):
    events = [e for e in FileEventSource.from_directory(data_dir).read() if e.event_time]
    events.sort(key=lambda e: e.event_time)
    return events


def cmd_train(args: argparse.Namespace) -> None:
    cfg = load_config()
    events = _read_events(args.data_dir)
    contaminated = None
    if args.exclude_attack_labels:
        from ueba_pipeline.engine import _event_key
        import json
        from datetime import datetime, timedelta

        labels = [json.loads(l) for l in open(args.exclude_attack_labels)]
        spans = []
        for a in labels:
            s = datetime.fromisoformat(a["start_time"].replace("Z", "+00:00"))
            e = datetime.fromisoformat(a["end_time"].replace("Z", "+00:00"))
            spans.append((s - timedelta(hours=1), e + timedelta(hours=1)))
        contaminated = {
            _event_key(ev) for ev in events
            if is_graph_event(ev.event_type) and any(s <= ev.event_time <= x for s, x in spans)
        }

    engine = BehavioralEngine(config=EngineConfig(window_hours=cfg.window.feature_window_hours))
    engine.fit(events, config_capability=cfg.capability, contaminated=contaminated)
    engine.save(args.model_dir)
    print(f"[train] fit on {len(events)} events -> signed bundle at {args.model_dir}", file=sys.stderr)
    # Per-view benign novelty rate: a view whose benign edges are routinely novel
    # cannot separate a first contact from an attack, however it is calibrated.
    print(f"  {'view':14s} {'edges':>8s} {'benign novelty':>15s}", file=sys.stderr)
    for view, st in engine.view_stats.items():
        print(f"  {view:14s} {st['edges']:>8d} {st['novel_rate']:>14.1%}", file=sys.stderr)


def cmd_score(args: argparse.Namespace) -> None:
    engine = BehavioralEngine.load(args.model_dir)
    if getattr(args, "alert_budget_per_day", None) is not None:
        engine.config.alert_budget_per_day = args.alert_budget_per_day
    events = _read_events(args.data_dir)
    detections, risks = engine.score(events)
    alerts = engine.alerts(risks)
    mode = engine.config.alert_mode
    budget = (f"budget {engine.config.alert_budget_per_day}/day" if mode == "budget"
              else f"FDR {engine.config.alert_fdr}")
    print(f"[score] {len(events)} events -> {len(detections)} window detections, "
          f"{len(alerts)} entity alert(s) ({mode}: {budget})", file=sys.stderr)
    print(f"  {'p-value':>10s}  {'entity':28s}  evidence            peak")
    for r in alerts:
        top = r.top_hour.isoformat() if r.top_hour else "-"
        print(f"  {r.p_value:10.3e}  {r.entity:28s}  "
              f"hits={r.graph_hits:<4d} windows={r.n_windows:<4d} {top}")


def cmd_score_stream(args: argparse.Namespace) -> None:
    """Score events in event-time order, adapting the graph baseline as it goes.

    This is the online path: the detector absorbs each event before the next
    arrives, so a live estate's baseline tracks drift. Detections are emitted per
    event. Batch ``score`` is the reproducible path; this one trades
    reproducibility for adaptation.
    """
    engine = BehavioralEngine.load(args.model_dir)
    events = _read_events(args.data_dir)
    n = 0
    print(f"  {'p-value':>10s}  {'entity':28s}  hour", file=sys.stderr)
    for d in engine.score_stream(iter(events)):
        n += 1
        print(f"  {d.p:10.3e}  {d.entity:28s}  {d.hour.isoformat()}")
    print(f"[score-stream] {len(events)} events -> {n} window detection(s)", file=sys.stderr)


def cmd_drift(args: argparse.Namespace) -> None:
    """Compare a trained bundle's capability manifest against a live window.

    A deployment's log-source availability changes after go-live (a GPO disables
    PowerShell logging, Sysmon rolls out fleet-wide). Either direction invalidates
    the frozen feature order and requires a retrain; this reports it explicitly
    rather than letting the engine score against a silently-changed schema.
    """
    from ueba_pipeline.config import load_config
    from ueba_pipeline.features import build_capability_manifest
    from ueba_pipeline.monitoring.drift import detect_capability_drift

    engine = BehavioralEngine.load(args.model_dir)
    cfg = load_config()
    live = build_capability_manifest(_read_events(args.data_dir), cfg.capability)
    report = detect_capability_drift(engine.manifest, live)
    print(f"[drift] trained groups: {sorted(engine.manifest.available_groups)}", file=sys.stderr)
    print(f"[drift] live groups:    {sorted(live.available_groups)}", file=sys.stderr)
    if report.groups_lost:
        print(f"  LOST (was trained on, now absent): {sorted(report.groups_lost)}")
    if report.groups_gained:
        print(f"  GAINED (now present, not trained on): {sorted(report.groups_gained)}")
    print(f"  requires_retrain: {report.requires_retrain}")
    if report.requires_retrain:
        sys.exit(2)


def cmd_lanl_eval(args: argparse.Namespace) -> None:
    """Per-authentication ROC on the LANL 2015 auth stream (or a synthetic
    LANL-format fixture). Validates the production graph detector against the
    canonical public lateral-movement benchmark."""
    from ueba_pipeline.evaluation.lanl_adapter import load_lanl
    from ueba_pipeline.evaluation.benchmark import lanl_roc_eval

    ds = load_lanl(args.auth, args.redteam, max_rows=args.max_rows)
    if not ds.malicious:
        print("[lanl-eval] WARNING: no red-team labels loaded", file=sys.stderr)
    print(f"[lanl-eval] {len(ds.events):,} auth events, "
          f"{len(ds.malicious):,} red-team labels", file=sys.stderr)
    for contamination in ("oracle", "none"):
        res = lanl_roc_eval(ds.events, ds.is_malicious,
                            train_fraction=args.train_fraction,
                            contamination=contamination, target_fpr=args.target_fpr)
        print(res.render())


def cmd_walk_forward(args: argparse.Namespace) -> None:
    from ueba_pipeline.evaluation.honest_eval import evaluate, render

    results = evaluate(args.data_dir, train_fraction=args.train_fraction,
                       contamination=args.contamination)
    print(render(results, args.data_dir))


def cmd_model_benchmark(args: argparse.Namespace) -> None:
    """Compare classical models on the behavioural feature matrix under the four
    leakage-resistant split protocols, with the shipped detector as a reference
    column. See evaluation/model_benchmark.py for the protocol design."""
    from ueba_pipeline.evaluation.model_benchmark import (
        aggregate, build_window_dataset, evaluate_graph_reference,
        graph_reference_scores, render, run_protocol,
    )

    protocols = args.protocols.split(",") if args.protocols else [
        "temporal", "entity_disjoint", "entity_and_time_disjoint",
        "attack_family_disjoint",
    ]
    datasets = [build_window_dataset(d, args.window_hours) for d in args.data_dirs]
    rows = []
    for data in datasets:
        for protocol in protocols:
            rows.extend(run_protocol(data, protocol))
        if not args.no_graph_reference and "temporal" in protocols:
            cells = graph_reference_scores(data.source, data)
            if cells is not None:
                ref = evaluate_graph_reference(data, cells)
                if ref is not None:
                    rows.append(ref)
    print(render(aggregate(rows), datasets))


def cmd_graph_viz(args: argparse.Namespace) -> None:
    import json as _json
    from ueba_pipeline.graph.identity_graph import build_identity_graph_from_roster
    from ueba_pipeline.graph.visualize import write_html

    directory = {}
    if args.directory:
        with open(args.directory) as f:
            directory = _json.load(f)
    graph = build_identity_graph_from_roster(
        args.roster,
        admin_accounts=directory.get("admin_accounts"),
        service_accounts=directory.get("service_accounts"),
        servers=directory.get("servers"),
        domain_controllers=directory.get("domain_controllers"),
    )
    out = write_html(graph, args.output, title=args.title, max_nodes=args.max_nodes)
    report = graph.compute_risk_scores()
    print(f"[graph-viz] {report.n_nodes} nodes, {report.n_edges} edges, "
          f"{report.n_tier0_assets} Tier-0 asset(s) -> {out}", file=sys.stderr)


def main() -> None:
    p = argparse.ArgumentParser(prog="ueba", description="Two-track behavioral ITDR engine")
    sub = p.add_subparsers(dest="command", required=True)

    p_train = sub.add_parser("train", help="Fit the two-track engine and write a signed bundle")
    p_train.add_argument("--data-dir", required=True)
    p_train.add_argument("--model-dir", default="artifacts/models/engine")
    p_train.add_argument("--exclude-attack-labels", default=None,
                         help="attack-labels JSONL; matching events are kept out of the baseline")
    p_train.set_defaults(func=cmd_train)

    p_score = sub.add_parser("score", help="Score new data and print ranked entity alerts")
    p_score.add_argument("--data-dir", required=True)
    p_score.add_argument("--model-dir", default="artifacts/models/engine")
    p_score.add_argument("--alert-budget-per-day", type=float, default=None,
                         help="analyst alert budget; the N most significant entities "
                              "per day are alerted (default: the engine's fitted value)")
    p_score.set_defaults(func=cmd_score)

    p_stream = sub.add_parser("score-stream", help="Score events online, adapting the baseline as it goes")
    p_stream.add_argument("--data-dir", required=True)
    p_stream.add_argument("--model-dir", default="artifacts/models/engine")
    p_stream.set_defaults(func=cmd_score_stream)

    p_drift = sub.add_parser("drift-check", help="Compare a live window's capabilities against the trained bundle")
    p_drift.add_argument("--data-dir", required=True)
    p_drift.add_argument("--model-dir", default="artifacts/models/engine")
    p_drift.set_defaults(func=cmd_drift)

    p_lanl = sub.add_parser("lanl-eval", help="Per-auth ROC on LANL 2015 (or a LANL-format fixture)")
    p_lanl.add_argument("--auth", required=True, help="path to auth.txt")
    p_lanl.add_argument("--redteam", required=True, help="path to redteam.txt")
    p_lanl.add_argument("--train-fraction", type=float, default=0.5)
    p_lanl.add_argument("--target-fpr", type=float, default=0.009,
                        help="FPR at which to report TPR (Bowman RAID 2020 operating point)")
    p_lanl.add_argument("--max-rows", type=int, default=None,
                        help="cap auth rows read (for a streamed prefix of the full file)")
    p_lanl.set_defaults(func=cmd_lanl_eval)

    p_wf = sub.add_parser("walk-forward-eval", help="Causal out-of-time evaluation")
    p_wf.add_argument("--data-dir", required=True)
    p_wf.add_argument("--train-fraction", type=float, default=0.60)
    p_wf.add_argument("--contamination", choices=["oracle", "none"], default="none",
                      help="'oracle' cleans the baseline with ground-truth labels "
                           "(upper bound, unavailable in production); 'none' is the "
                           "unlabelled cold start. Both bounds measure identically.")
    p_wf.set_defaults(func=cmd_walk_forward)

    p_mb = sub.add_parser("model-benchmark",
                          help="Compare classical models on the feature matrix under "
                               "leakage-resistant protocols")
    p_mb.add_argument("--data-dirs", nargs="+", required=True,
                      help="one or more estate directories (each an independent seed)")
    p_mb.add_argument("--window-hours", type=float, default=1.0)
    p_mb.add_argument("--protocols", default=None,
                      help="comma-separated subset of temporal,entity_disjoint,"
                           "entity_and_time_disjoint,attack_family_disjoint")
    p_mb.add_argument("--no-graph-reference", action="store_true",
                      help="skip the shipped graph-track reference column")
    p_mb.set_defaults(func=cmd_model_benchmark)

    p_viz = sub.add_parser("graph-viz", help="Render the identity graph to HTML")
    p_viz.add_argument("--roster", required=True)
    p_viz.add_argument("--directory", default=None)
    p_viz.add_argument("--output", default="artifacts/identity_graph.html")
    p_viz.add_argument("--title", default="Identity Graph")
    p_viz.add_argument("--max-nodes", type=int, default=500)
    p_viz.set_defaults(func=cmd_graph_viz)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

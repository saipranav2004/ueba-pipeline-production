"""First real-data evaluation of the engine on COMISET (Zenodo 15375146).

Two measurements, because they answer different questions and only one needs
labels:

  1. REAL per-view benign novelty rates. The engine's whole view-admission logic
     rests on how often a *benign* edge is novel (device-keyed `user_src` at ~9%
     on the simulator, `dir_op` at ~5%, …). The audit's deepest objection is that
     those rates are simulator artefacts. Fitting the production engine on COMISET's
     real benign telemetry re-measures them on real Windows event streams — no
     labels required — and is the single most direct test of the simulator
     circularity.

  2. Per-authentication ROC. COMISET labels malicious events inline with a
     `rule_technique_id` field (the dataset's own rule-based labelling — so this is
     recall against *that* labelling, not a hand-curated ground truth). Feeding the
     labelled graph events through the production per-view calibrated scoring
     (`lanl_roc_eval`) gives a real TPR-at-FPR / AUC, directly comparable to the
     Bowman (RAID 2020) LANL reference the engine cites.

Both are measured on a bounded prefix of the lab archive (the member inflates to
~155 GB and is a continuous deflate stream, so a prefix is streamed rather than the
whole file materialised). A prefix is ordered by HELK `_index`, not strictly by
time, so this is a first real-data signal to be read with its caveats, not a
product claim — exactly the honesty the rest of the evaluation docs insist on.
"""
from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field

from ueba_pipeline.config.schema import load_config
from ueba_pipeline.engine import BehavioralEngine, EngineConfig, is_graph_event
from ueba_pipeline.evaluation.benchmark import lanl_roc_eval
from ueba_pipeline.evaluation.comiset_adapter import comiset_source_to_raw, iter_comiset_archive
from ueba_pipeline.parsing.normalize import NormalizedEvent, normalize_event

# The COMISET malicious label, verified in the real archive to be lower-case
# (the Data-in-Brief paper writes it capitalised); accept both to be safe.
_LABEL_KEYS = ("rule_technique_id", "Rule_technique_id")
_LABEL_NAME_KEYS = ("rule_technique_name", "Rule_technique_name")


def _label(source: dict) -> str | None:
    for k in _LABEL_KEYS:
        v = source.get(k)
        if v not in (None, "", "-"):
            return str(v)
    return None


def load_comiset_graph_events(records: Iterable[dict],
                              max_events: int | None = None) -> Iterator[NormalizedEvent]:
    """Yield the graph-relevant NormalizedEvents from COMISET raw records.

    Only events the relational detector actually models are kept (auth, Kerberos,
    directory ops, Sysmon process-access) — the rest score p=1 by construction and
    would only dilute the population. The inline COMISET technique label is copied
    onto ``event.fields['rule_technique_id']`` so a downstream ``is_malicious`` can
    read it from the normalized event.
    """
    n = 0
    for record in records:
        source = record.get("_source")
        if not isinstance(source, dict):
            continue
        event = normalize_event(comiset_source_to_raw(record), keep_raw=False)
        if event is None or not is_graph_event(event.event_type):
            continue
        tech = _label(source)
        if tech is not None:
            event.fields["rule_technique_id"] = tech
        yield event
        n += 1
        if max_events is not None and n >= max_events:
            return


def is_malicious(event: NormalizedEvent) -> bool:
    return bool(event.fields.get("rule_technique_id"))


@dataclass
class ComisetReport:
    n_graph_events: int
    n_malicious: int
    n_malicious_visible: int                # labelled events that project >=1 graph edge
    channel_mix: dict[str, int]
    technique_mix: dict[str, int]
    view_novelty: dict[str, dict]           # view -> {edges, novel_rate} on benign fit
    roc: object = None                      # RocResult or None
    caveats: list[str] = field(default_factory=list)

    def render(self) -> str:
        vis = (f"  ({self.n_malicious_visible:,} project a modelled relation; the rest "
               f"are non-relational techniques the graph engine cannot see by design)"
               if self.n_malicious else "")
        out = [f"COMISET real-data evaluation  graph_events={self.n_graph_events:,}  "
               f"malicious(labelled)={self.n_malicious:,}" + vis]
        out.append("  channels: " + ", ".join(
            f"{c}={n}" for c, n in sorted(self.channel_mix.items(), key=lambda x: -x[1])[:8]))
        if self.technique_mix:
            out.append("  labelled techniques: " + ", ".join(
                f"{t}={n}"
                for t, n in sorted(self.technique_mix.items(), key=lambda x: -x[1])[:10]))
        out.append("")
        out.append("  REAL per-view benign novelty (production held-out calibration):")
        out.append(f"    {'view':14s} {'edges':>8s} {'benign novelty':>15s}")
        for view, st in sorted(self.view_novelty.items()):
            out.append(f"    {view:14s} {st['edges']:>8d} {st['novel_rate']:>14.1%}")
        if self.roc is not None:
            out.append("")
            out.append("  " + self.roc.render().replace("\n", "\n  "))
        if self.caveats:
            out.append("\n  caveats:")
            out.extend(f"    - {c}" for c in self.caveats)
        return "\n".join(out)


def evaluate_comiset(archive_path: str, max_events: int = 1_500_000,
                     max_uncompressed_bytes: int = 6 << 30,
                     train_fraction: float = 0.6) -> ComisetReport:
    """Run both real-data measurements over a bounded prefix of a COMISET archive.

    ``archive_path`` may be a partial/still-downloading ``.zip`` — it is read by
    chunked raw inflation, not ``zipfile``.
    """
    events: list[NormalizedEvent] = list(load_comiset_graph_events(
        iter_comiset_archive(archive_path, max_uncompressed_bytes=max_uncompressed_bytes),
        max_events=max_events))

    from ueba_pipeline.graph.auth_graph_anomaly import AuthGraphAnomalyDetector
    projector = AuthGraphAnomalyDetector()   # edges_for is stateless (pure projection)

    channel_mix: dict[str, int] = {}
    technique_mix: dict[str, int] = {}
    n_malicious_visible = 0
    for e in events:
        channel_mix[e.channel] = channel_mix.get(e.channel, 0) + 1
        t = e.fields.get("rule_technique_id")
        if t:
            technique_mix[t] = technique_mix.get(t, 0) + 1
            if projector.edges_for(e):
                n_malicious_visible += 1
    malicious = [e for e in events if is_malicious(e)]

    # (1) Real benign novelty: fit the production engine on the benign graph events
    # and read the per-view rates it reports at train time.
    benign = [e for e in events if not is_malicious(e)]
    cfg = load_config()
    engine = BehavioralEngine(config=EngineConfig(window_hours=cfg.window.feature_window_hours))
    view_novelty: dict[str, dict] = {}
    if benign:
        engine.fit(benign, config_capability=cfg.capability)
        view_novelty = engine.view_stats

    # (2) Per-event ROC on the labelled graph events (contamination='none': the
    # unlabelled cold start, since COMISET's own labels are rule-derived).
    roc = None
    caveats = [
        "labels are COMISET's own rule-based technique tags, not curated ground truth",
        "measured on a prefix ordered by HELK _index, not strictly time-contiguous",
        "graph-relevant events only; attacks leaving no modelled relation are unscored",
    ]
    timed = [e for e in events if e.event_time is not None]
    if malicious and len(timed) - len(malicious) > 100 and any(is_malicious(e) for e in timed):
        roc = lanl_roc_eval(timed, is_malicious, train_fraction=train_fraction,
                            contamination="none")
    else:
        caveats.append("too few labelled graph events in this prefix for a ROC; "
                       "stream a larger prefix")

    return ComisetReport(
        n_graph_events=len(events), n_malicious=len(malicious),
        n_malicious_visible=n_malicious_visible,
        channel_mix=channel_mix, technique_mix=technique_mix,
        view_novelty=view_novelty, roc=roc, caveats=caveats,
    )

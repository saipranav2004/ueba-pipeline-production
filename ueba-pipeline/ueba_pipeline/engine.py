"""Behavioral detection engine -- the production detection path.

ARCHITECTURE
------------
One detector (:class:`AuthGraphAnomalyDetector`) emitting a **calibrated
p-value** against a frozen benign null. It scores relational anomalies -- lateral
movement, credential-forgery reuse, credential-store access, ticket downgrade,
and directory-object change -- per event, as
Dirichlet-smoothed edge surprise across several independently calibrated
relationship views.

Measured on the honest all-technique benchmark: 54/60 = 90.0% recall at 3.19
false-positive entities/day (6 seeds, contamination=none). Reproduce with
`walk-forward-eval`; see docs/evaluation.md.

WHY ONE DETECTOR
----------------
Two supplementary tracks were evaluated against this one and both were removed on
measured evidence, not preference:

  * A **volumetric** track (per-entity ECOD over behavioural counts) scored
    15/60 alone, and fusing it with the graph track *lowered* recall to 29/60
    while *raising* false positives to 3.88/day. Under a fixed alert budget its
    mediocre scores displaced strong graph detections. It uniquely caught 2
    attacks and cost 14 -- decisively negative.
  * A **peer** track (Poisson matrix factorization over the user x resource
    matrix) added no technique the graph track did not already catch, was
    correlated with the volumetric track (both functions of the same access
    counts), and carried a dense O(users x dests) rate matrix.

The measured comparison for both removed tracks is recorded in
docs/evaluation.md ("Component evidence").

Raw scores are mapped through :class:`EmpiricalPValue` (frozen ECDF of the
*training* benign distribution), so every view is commensurable. Per (entity,
hour) the most significant view is taken and Sidak-corrected for the number of
views tested; per entity the most significant hour is Sidak-corrected for the
number of hours tested; alerts are the ``alert_budget_per_day`` most significant
entities (or Benjamini-Hochberg at a target FDR).

Research basis: Rubin-Delanchy, Lawson & Heard, "Anomaly detection for cyber
security applications" (2016) for the p-value modus operandi; Heard &
Rubin-Delanchy, Biometrika 105(1) (2018) for per-level combiner selection via
Birnbaum (1954); Bowman et al., RAID 2020, for graph edge-novelty of lateral
movement.

DESIGN CONSTRAINTS (do not regress these)
-----------------------------------------
  * Never fuse uncalibrated scores. Detectors on different scales cannot be
    combined by rescaling each with a constant and OR-ing the results; the
    constants end up mutually inconsistent and the composition is untestable.
    Everything becomes a p-value first.
  * Never aggregate evidence with noisy-OR plus decay. Solving that recursion at
    a 24h halflife, any entity with a recurring per-hour risk >= 0.15 crosses an
    0.85 threshold within a day regardless of severity: it is a frequency
    detector, and it saturates so nothing ranks. The Sidak/Tippett path inverts
    this: an entity's significance is its single most anomalous window, corrected
    for how many windows it was tested in, so more observation cannot manufacture
    significance.
  * Combine with Tippett, not Fisher. Fisher assumes independence and rewards
    several moderate p-values; under a fixed alert budget that let benign-but-busy
    entities displace real detections. Tippett (min-p) makes an entity as
    suspicious as its most anomalous evidence and no more.

STATE CONTRACT
--------------
``score()`` is PURE: it does not mutate the detector, so re-scoring the same
events always gives the same answer and a re-run after a crash cannot
under-report. Online adaptation is an explicit, separate call: :meth:`observe`.
``score_stream`` opts into it deliberately, because a live stream should adapt
while batch scoring must be reproducible.

Persistence is a schema-explicit, non-executable bundle (models/serialization.py),
signed with HMAC-SHA256 and integrity-verified before any field is read.
"""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime

import numpy as np

from ueba_pipeline.features import build_capability_manifest, observed_entity_windows
from ueba_pipeline.graph.auth_graph_anomaly import (
    DIR_OP_CLASS,
    EXECUTION_VIEWS,
    RELATIONAL_VIEWS,
    AuthGraphAnomalyDetector,
    AuthGraphConfig,
)
from ueba_pipeline.graph.sessions import SessionResolver
from ueba_pipeline.models.fisher import benjamini_hochberg, sidak
from ueba_pipeline.models.pvalue import EmpiricalPValue
from ueba_pipeline.parsing.normalize import entity_key as _norm

# Exact event types the detector projects onto edges. Listed explicitly (not by
# prefix) so a new sysmon_1x type cannot be routed into the graph by accident.
GRAPH_EVENT_TYPES = frozenset(
    {"4624", "4625", "4768", "4769", "sysmon_1", "sysmon_10",
     # Candidate views under measurement (pipe / reg / share). Listing the type
     # here only lets edges_for see the event; whether a view is SCORED is decided
     # by the queue's enabled_views, so a view can be ablated without touching this.
     "sysmon_12", "sysmon_13", "sysmon_17", "sysmon_18", "5140", "5145"}
    # Every privileged directory operation the dir_op view classifies: group
    # membership, account lifecycle, AD object access, attribute modification.
    # Coverage grows by adding a row to DIR_OP_CLASS, not a branch here.
    | set(DIR_OP_CLASS)
)

# Graph events whose acting principal is the SubjectUserName (who performed the
# directory operation), not the TargetUserName (which names the group/object
# acted upon). Used by _entity_for to attribute the detection to the actor.
# Share access names the actor the same way: SubjectUserName performed it, and
# the share is the object.
_SUBJECT_ACTOR_EVENT_TYPES = frozenset(DIR_OP_CLASS) | {"5140", "5145"}

# Event types whose acting account is in a plain `User` field.
_DIRECT_USER_EVENT_TYPES = frozenset({"sysmon_12", "sysmon_13", "sysmon_17", "sysmon_18"})


def is_graph_event(event_type: str) -> bool:
    return event_type in GRAPH_EVENT_TYPES


@dataclass
class WindowDetection:
    entity: str
    hour: datetime
    graph_p: float = 1.0        # smallest per-view p-value in this (entity, hour)
    # Distinct (view, edge) pairs examined in this cell. This is the number of
    # hypotheses the Sidak correction answers for; see _score_graph_event.
    tested_edges: set = field(default_factory=set)

    @property
    def p(self) -> float:
        """Significance of this (entity, hour) cell.

        Many homogeneous tests within the hour, where we expect ONE to be
        anomalous -> Tippett (min-p with a Sidak correction for the number of
        DISTINCT relationships examined). Fisher would be wrong here: it adds 2 df
        per test, so a single severe event among 500 benign ones in the same hour
        dilutes below significance (Birnbaum 1954; Heard & Rubin-Delanchy 2018).

        The correction counts distinct relationships rather than events because
        Sidak answers "how many hypotheses did I examine". Observing one edge a
        hundred times examines one hypothesis a hundred times, and charging a
        hundred tests for it would penalise an entity for being busy -- which is
        exactly backwards when volume over an established relationship is itself
        the signal.
        """
        if self.graph_p >= 1.0:
            return 1.0
        return sidak(self.graph_p, max(len(self.tested_edges), 1))

    @property
    def risk(self) -> float:
        return 1.0 - self.p


@dataclass
class EntityRisk:
    entity: str
    p_value: float              # Sidak-corrected significance (lower = worse)
    top_hour: datetime | None
    graph_hits: int
    n_windows: int = 0
    alerted: bool = False

    @property
    def risk(self) -> float:
        return 1.0 - self.p_value

    @property
    def evidence(self) -> str:
        """One-line provenance, in the vocabulary this queue actually has.

        Every alert returned by :meth:`BehavioralEngine.score_queues` carries this,
        whatever its concrete type, so a consumer can render any queue without
        knowing which one it is holding. The queues do NOT share a payload -- a
        relational rollup counts surprising edges, a deviation track names the
        signal that fired -- and flattening them to a common field would throw
        away the part an analyst needs.
        """
        return f"hits={self.graph_hits}"


@dataclass
class EngineConfig:
    window_hours: float = 1.0
    # Alerting mode. Both are implemented and both are benchmarked:
    #
    #   "fdr"    -- Benjamini-Hochberg across entities at ``alert_fdr``.
    #               Statistically principled, and it alerts on NOTHING. That is
    #               not a tuning failure: the empirical null is floored at
    #               1/(n_benign+1) ~ 2.5e-5, while correcting for ~1e6 tests
    #               (250 entities x 192 hours x ~20 events) needs p ~ 1e-8. You
    #               cannot assert significance you do not have evidence for.
    #               No commercial UEBA product alerts on corrected p-values for
    #               this reason.
    #   "budget" -- fixed analyst budget: the ``alert_budget_per_day`` most
    #               significant entities per day. This is what a SOC actually
    #               operates, and it is the mode the published numbers use.
    #
    # The p-values still do the work in "budget" mode: they provide the ranking.
    # A principled ranking is the deliverable; absolute significance is not
    # attainable at this null-sample size.
    alert_mode: str = "budget"
    alert_fdr: float = 0.01
    alert_budget_per_day: float = 5.0
    # Fraction of the training period held out to calibrate each view's benign
    # null against a frozen baseline (see BehavioralEngine._fit_graph). The null
    # must be measured on events the baseline has NOT already absorbed, or it
    # contains no benign-novelty mass and the detector over-flags every first
    # contact in production.
    null_calibration_fraction: float = 0.30
    # Budgets for the two behavioural-deviation queues. They are SEPARATE numbers
    # from alert_budget_per_day on purpose: each queue covers a different threat
    # class with a different base rate, and merging them into one budget was
    # measured to let the broad signal displace the narrow one (see
    # identity/deviation.py). Set either to 0 to silence that queue.
    nhi_budget_per_day: float = 0.5
    insider_budget_per_day: float = 0.5
    # Execution queue (account -> program). Own budget: measured, running it
    # inside the relational budget solves NTDS (0/2 -> 2/2) but costs five
    # detections elsewhere by displacing Kerberos evidence.
    #
    # 1.0 rather than the 0.75 that first reaches full NTDS recall: recall is flat
    # at 2/2 from 0.75 all the way to 5/day (only false positives grow), but it
    # falls to 0/2 at 0.5 -- so 0.75 sits on a cliff edge and 1.0 buys margin for
    # 0.19 FP/day. Choosing the cheapest point that keeps recall would be selection
    # on the estates the figure is reported from.
    execution_budget_per_day: float = 1.0
    # How a raw graph statistic becomes a p-value.
    #   "predictive" -- the model's own discrete predictive p-value (Heard &
    #                   Rubin-Delanchy 2016, eq. 2). SHIPPED. No empirical floor,
    #                   so a sparse view can assert significance its calibration
    #                   sample size could never support.
    #   "empirical"  -- surprise scored against a frozen benign null, floored at
    #                   1/(n_benign+1). The previous default, retained because it
    #                   needs no destination vocabulary and is the cheaper path.
    # Measured on two INDEPENDENT six-seed sets, predictive wins on both recall and
    # false positives, and rescues account manipulation from the floor ties that
    # made its peak-hour attribution degenerate:
    #   seeds A: 52/60 @ 3.27 -> 54/60 @ 3.19   (account manip 0/5 -> 4/5)
    #   seeds B: 47/60 @ 3.10 -> 49/60 @ 2.95   (account manip 1/5 -> 5/5)
    # See docs/evaluation.md.
    pvalue_mode: str = "predictive"


@dataclass
class BehavioralEngine:
    config: EngineConfig = field(default_factory=EngineConfig)
    graph: AuthGraphAnomalyDetector = field(
        default_factory=lambda: AuthGraphAnomalyDetector(
            config=AuthGraphConfig(enabled_views=RELATIONAL_VIEWS)))
    # Execution queue's own detector, restricted to the execution views.
    execution_graph: AuthGraphAnomalyDetector = field(
        default_factory=lambda: AuthGraphAnomalyDetector(
            config=AuthGraphConfig(enabled_views=EXECUTION_VIEWS)))
    _execution_nulls: dict[str, EmpiricalPValue] = field(default_factory=dict)
    manifest: object = None
    # One frozen benign null PER graph view, so each relationship type is scored
    # against its own baseline and cannot pollute the others.
    _graph_nulls: dict[str, EmpiricalPValue] = field(default_factory=dict)
    # Per-view benign novelty rate measured at fit; see _fit_graph.
    view_stats: dict[str, dict] = field(default_factory=dict)
    # Behavioural-deviation queues. They ride in the same bundle so one `train`
    # produces one signed artifact, but they are scored on their own path
    # (score_queues) and never enter the relational Tippett combination or
    # alert budget above -- sharing a file is not fusing a score.
    nhi_track: object = None
    insider_track: object = None

    # -- training ----------------------------------------------------------
    def fit(self, events: list, config_capability=None,
            contaminated: set | None = None) -> BehavioralEngine:
        """Fit the baseline and calibrate the per-view nulls on training events.

        ``contaminated`` is an optional set of ground-truth attack-window event
        keys (from an ``attack_labels`` file, via the CLI ``--exclude-attack-
        labels`` flag or the evaluation harness's ``oracle`` mode); those events
        are excluded from the baseline so a known training-period attack cannot
        teach the baseline it is normal. It is unavailable in an unlabelled
        production cold start, and measured across seeds it changes nothing
        (oracle == none); it is retained because it is correct in principle and
        free, not because it is load bearing -- see docs/evaluation.md.
        """
        self.manifest = build_capability_manifest(events, config_capability)
        graph_events = _time_sorted_graph_events(events)
        self._graph_nulls, self.view_stats = self._fit_graph(
            graph_events, contaminated, graph=self.graph)
        # The execution queue is fit the same way on its own detector, so its null
        # is calibrated independently of the relational views.
        self._execution_nulls, exec_stats = self._fit_graph(
            graph_events, contaminated, graph=self.execution_graph)
        self.view_stats = {**self.view_stats, **exec_stats}
        self._fit_tracks(events)
        return self

    def _fit_tracks(self, events: list) -> None:
        """Fit the behavioural-deviation queues on the same training events.

        These cover the two threat classes the relational path is blind to by
        construction -- a compromised non-human identity (wrong time) and insider
        rate abuse (wrong volume), neither of which creates a new relationship.
        They read the full event stream, not just ``GRAPH_EVENT_TYPES``, because
        an identity's schedule and rate are properties of everything it does.
        """
        from ueba_pipeline.identity.deviation import (
            insider_volume_queue,
            nhi_schedule_queue,
        )

        self.nhi_track = nhi_schedule_queue().fit(events)
        self.insider_track = insider_volume_queue().fit(events)

    def _fit_graph(self, graph_events: list, contaminated: set | None = None,
                   graph=None) -> tuple:
        """Build the graph baseline and freeze one benign null per view.

        The null is calibrated on a HELD-OUT slice of the training period, scored
        against the baseline learnt from the earlier part with absorb=False --
        exactly the situation a live benign event meets in production, where the
        baseline is frozen. This is what puts benign NOVELTY into the null: the
        first time an account legitimately reaches a host it has never used is a
        surprising edge, and real estates produce those constantly (DHCP leases,
        VDI pools, roaming laptops, a new project share).

        Scoring the training set against the *completed* baseline instead would
        mark every training edge "already seen", so it scores ~0 and the null holds
        no novelty mass at all. The detector would then treat any first contact in
        production as extreme -- a flaw a fixture with static IPs hides and a real
        estate exposes immediately as a flood of false positives.

        Each view is calibrated separately, so a relationship type whose benign
        edges are often novel, or whose surprise is structurally high (process
        access, whose reverse conditional is high for every common target), is
        contained to its own view instead of setting the significance bar for a
        low-baseline view such as user->source.

        After calibration the held-out slice is folded in, so the deployed baseline
        uses the whole training period. The null is then calibrated against a
        slightly smaller baseline than the one deployed, which can only make it
        conservative (it over-states benign novelty), never optimistic.
        """
        graph = self.graph if graph is None else graph
        evs = [e for e in graph_events
               if not (contaminated and _event_key(e) in contaminated)]
        cut = max(1, int(len(evs) * (1.0 - self.config.null_calibration_fraction)))
        baseline_evs, calib_evs = evs[:cut], evs[cut:]
        if not calib_evs:                       # too little data to hold any out
            baseline_evs, calib_evs = evs, evs

        for e in baseline_evs:
            graph.observe_baseline(e)

        by_view: dict[str, list] = {}
        novelty: dict[str, list] = {}          # view -> [edges_scored, edges_novel]
        for e in calib_evs:
            for view, edge in graph.edges_for(e):
                st = novelty.setdefault(view, [0, 0])
                st[0] += 1
                # An edge is "seen" iff it is already in the baseline counters;
                # _edges keys ARE the seen-set (both are written together in
                # _absorb), so no separate seen-set is kept.
                if edge not in graph._edges[view]:
                    st[1] += 1
            for view, sc in graph.score_event_views(e, absorb=False):
                by_view.setdefault(view, []).append(sc)
        nulls = {
            view: EmpiricalPValue().fit(np.asarray(scores))
            for view, scores in by_view.items()
        }

        # Fold the calibration slice into the deployed baseline.
        for e in calib_evs:
            graph.observe_baseline(e)
        # Per-view benign novelty rate: the measurable property that decides
        # whether a relationship type carries anomaly signal at all. A view whose
        # benign edges are routinely novel (a high rate) cannot separate a first
        # contact from an attack -- novelty is simply what that relationship does
        # -- so it contributes noise however it is calibrated. A view with a low
        # rate (an account's source hosts, a process's access targets) is stable,
        # so a novel edge is genuine evidence. This is the evidence-based test for
        # admitting a new view, in place of per-attack judgement; it is reported at
        # train time and belongs in any review of a proposed relationship type.
        stats = {
            view: {"edges": n, "novel_rate": (nov / n) if n else 0.0}
            for view, (n, nov) in sorted(novelty.items())
        }
        return nulls, stats

    # -- batch scoring (PURE: does not mutate detector state) --------------
    def score(self, events: list) -> tuple[list[WindowDetection], list[EntityRisk]]:
        # Only the (entity, hour) keys are needed, to count the tests each entity
        # received for the Šidák correction. Computing behavioural feature vectors
        # here would run every extractor and discard every value.
        observed = observed_entity_windows(events, self.config.window_hours)
        # Built fresh from this batch: pure, no cross-call state (state contract
        # above). Deliberately not carried from fit -- a stale session map would
        # silently misattribute months later.
        sessions = SessionResolver().fit(events, _norm)
        cell: dict[tuple[str, datetime], WindowDetection] = {}
        # Batch scoring does not absorb, so the model is fixed for the whole run
        # and the predictive p-value's prefix-sum index stays valid. Without it,
        # each event's reverse conditional scans every principal in the estate,
        # which makes a scoring run quadratic in estate size.
        self.graph.freeze()
        for e in _time_sorted_graph_events(events):
            self._score_graph_event(e, cell, absorb=False, sessions=sessions)
        detections = [d for d in cell.values() if d.graph_p < 1.0]
        hours = [d.hour for d in detections] or [h for _, h in observed]
        days = ((max(hours) - min(hours)).total_seconds() / 86400.0) if hours else 1.0
        return detections, self._rollup(detections, observed, observed_days=max(days, 1.0))

    def score_execution(self, events: list) -> list[EntityRisk]:
        """Rank identities by novel program execution. SEPARATE queue and budget.

        Same machinery as :meth:`score` -- Dirichlet edge surprise, per-view frozen
        null, Tippett within the cell, Sidak over an entity's windows -- run on the
        execution views only, with its own budget. Kept out of the relational queue
        because measurement showed it displaces Kerberos evidence there while
        solving NTDS extraction here.
        """
        if not self._execution_nulls:
            return []
        observed = observed_entity_windows(events, self.config.window_hours)
        sessions = SessionResolver().fit(events, _norm)
        cell: dict[tuple[str, datetime], WindowDetection] = {}
        self.execution_graph.freeze()   # see the note in score()
        for e in _time_sorted_graph_events(events):
            self._score_graph_event(e, cell, absorb=False, sessions=sessions,
                                    graph=self.execution_graph,
                                    nulls=self._execution_nulls)
        detections = [d for d in cell.values() if d.graph_p < 1.0]
        hours = [d.hour for d in detections] or [h for _, h in observed]
        days = ((max(hours) - min(hours)).total_seconds() / 86400.0) if hours else 1.0
        budget = self.config.alert_budget_per_day
        try:
            self.config.alert_budget_per_day = self.config.execution_budget_per_day
            return self._rollup(detections, observed, observed_days=max(days, 1.0))
        finally:
            self.config.alert_budget_per_day = budget

    def score_queues(self, events: list) -> dict[str, list]:
        """Score the behavioural-deviation queues. SEPARATE from ``score``.

        Returns ``{"execution": [...], "nhi": [...], "insider": [...]}``, each a
        ranked list with its own budget applied. Deliberately a different method
        with a different return type from :meth:`score`: these alerts are a
        different queue an analyst triages separately, and keeping them out of the
        relational ranking is the property that stops a broad signal displacing a
        narrow one. Pure -- it does not mutate any track.

        The lists are NOT of one concrete type -- ``execution`` holds
        ``EntityRisk`` from the relational rollup, the deviation queues hold
        ``TrackAlert``. What every element does guarantee is the rendering
        contract a consumer needs: ``entity``, ``p_value``, ``top_hour``,
        ``n_windows``, ``alerted`` and ``evidence``. Anything reading this
        dictionary must stay inside that set; ``test_queue_contract`` enforces it.
        """
        out: dict[str, list] = {}
        if self.config.execution_budget_per_day > 0 and self._execution_nulls:
            out["execution"] = self.score_execution(events)
        for name, budget in (("nhi", self.config.nhi_budget_per_day),
                             ("insider", self.config.insider_budget_per_day)):
            track = getattr(self, f"{name}_track", None)
            if track is None or budget <= 0:
                continue
            out[name] = track.score(events, budget_per_day=budget)
        return out

    def observe(self, events: list) -> BehavioralEngine:
        """Explicitly fold events into the baseline (online adaptation).

        Separated from ``score`` so that batch scoring stays reproducible; a
        caller that wants adaptation calls ``score`` and then ``observe``.
        """
        for e in _time_sorted_graph_events(events):
            self.graph.observe_baseline(e)
        return self

    # -- streaming scoring -------------------------------------------------
    def score_stream(self, events: Iterator) -> Iterator[WindowDetection]:
        """Score in event-time order, adapting as it goes (absorb=True).

        A live stream *should* adapt; batch ``score()`` must not. Detections are
        emitted per event rather than per completed window, so a live consumer
        sees a relational anomaly as it happens instead of waiting out a
        watermark.
        """
        sessions = SessionResolver()
        for e in events:
            if e.event_time is None:
                continue
            # Sessions are maintained incrementally in event order, so a stream
            # resolves a host to whoever logged on earlier in the same stream.
            if e.event_type == "4624":
                sessions.fit([e], _norm) if not sessions._logons else _stream_session(sessions, e)
            if not is_graph_event(e.event_type):
                continue
            cell: dict[tuple[str, datetime], WindowDetection] = {}
            self._score_graph_event(e, cell, absorb=True, sessions=sessions)
            for d in cell.values():
                if d.graph_p < 1.0:
                    yield d

    # -- scoring -----------------------------------------------------------
    def _cell(self, cell: dict, entity: str, hour: datetime) -> WindowDetection:
        key = (entity, hour)
        if key not in cell:
            cell[key] = WindowDetection(entity, hour)
        return cell[key]

    def _entity_for(self, e, sessions: SessionResolver | None) -> str:
        """Resolve a graph event to the ACCOUNT it should be attributed to.

        Host-scoped telemetry (Sysmon ProcessAccess/ProcessCreate) names a host
        and an image but no user. Resolving it to the account logged on at that
        time keeps every track in one entity space -- required, because _rollup
        runs Benjamini-Hochberg across entities and a mixed user/host population
        gives hosts an under-corrected Sidak. Unresolved events keep the host: a
        process opening lsass on a host nobody is logged into is not less
        interesting, it is just not yet an identity.
        """
        # Directory operations name the object acted on in TargetUserName (a
        # group, an AD object); the entity responsible is the SubjectUserName.
        if e.event_type in _SUBJECT_ACTOR_EVENT_TYPES:
            actor = _norm(e.fields.get("subject_user_name"))
            if actor:
                return actor
        # Pipe and registry telemetry carries the acting account directly, so the
        # detection cell is attributed to the same identity the edge is keyed on.
        # Deliberately NOT extended to sysmon_1: that path resolves through the
        # session map today and the headline figure is measured with it.
        if e.event_type in _DIRECT_USER_EVENT_TYPES:
            direct = _norm(e.fields.get("user_norm") or e.fields.get("user"))
            if direct and not direct.endswith("$"):
                return direct
        user = _norm(e.fields.get("target_user_name"))
        if user:
            return user
        host = _norm(e.computer_name)
        if host and sessions is not None:
            owner = sessions.resolve(host, e.event_time)
            if owner:
                return owner
        return host or "endpoint"

    def _score_graph_event(self, e, cell: dict, absorb: bool,
                           sessions: SessionResolver | None = None,
                           graph=None, nulls=None) -> None:
        # ``graph``/``nulls`` default to the relational detector. The execution
        # queue passes its own pair so both queues run one implementation of
        # scoring, correction and rollup -- and one set of bugs.
        graph = self.graph if graph is None else graph
        nulls = self._graph_nulls if nulls is None else nulls
        if not nulls:
            return
        # Score each view against its own frozen null, then take the most
        # significant view (Tippett), Sidak-corrected for the number of views
        # that produced evidence. A view unseen in training has no null and
        # contributes no evidence (p = 1.0) rather than a spurious extreme.
        ps = []
        tested_edges = []
        for view, edge in graph.edges_for(e):
            tested_edges.append((view, edge))
        if self.config.pvalue_mode == "predictive":
            # The model's own predictive p-value: no empirical null, so no
            # 1/(n_benign+1) floor to tie sparse-view evidence together.
            for view, edge in tested_edges:
                if view in nulls:
                    ps.append(graph.predictive_pvalue(view, edge))
            if absorb:
                graph.score_event_views(e, absorb=True)
        else:
            for view, sc in graph.score_event_views(e, absorb=absorb):
                null = nulls.get(view)
                if null is not None:
                    ps.append(float(null.pvalue(sc)[0]))
        if not ps:
            return
        p = sidak(min(ps), len(ps))
        entity = self._entity_for(e, sessions)
        d = self._cell(cell, entity, _floor_hour(e.event_time))
        # The correction counts DISTINCT relationships tested in this hour, not
        # events. Re-observing one edge is one hypothesis examined repeatedly, not
        # a new hypothesis: counting events would make an entity progressively
        # harder to alert on the more it does, so a high-volume abuse of a single
        # established relationship would suppress its own significance.
        d.tested_edges.update(tested_edges)
        d.graph_p = min(d.graph_p, p)

    # -- rollup / alerting -------------------------------------------------
    def _rollup(self, detections: list[WindowDetection], observed=None,
                observed_days: float | None = None) -> list[EntityRisk]:
        """Entity risk = Sidak-corrected minimum hourly p over the entity's hours.

        Each hour's significance is ``WindowDetection.p``. Taking a minimum over n
        windows is itself a test over n windows; without the Sidak correction, any
        entity observed long enough eventually looks significant. Alerts are then
        selected by a fixed analyst budget, or by Benjamini-Hochberg across
        entities.

        ``observed`` is the set of ``(entity, window_start)`` pairs the batch saw,
        which is how many tests each entity received.
        """
        by_entity: dict[str, list[WindowDetection]] = {}
        for d in detections:
            by_entity.setdefault(d.entity, []).append(d)

        # Number of hours each entity was actually observed = tests it received.
        tested: dict[str, int] = {}
        if observed:
            seen: dict[str, set] = {}
            for user, window_start in observed:
                seen.setdefault(_norm(user), set()).add(_floor_hour(window_start))
            tested = {k: len(v) for k, v in seen.items()}

        out: list[EntityRisk] = []
        for entity, ds in by_entity.items():
            ds.sort(key=lambda d: d.hour)
            best = min(ds, key=lambda d: d.p)
            n = max(tested.get(entity, len(ds)), len(ds), 1)
            out.append(EntityRisk(
                entity=entity,
                p_value=sidak(best.p, n),
                top_hour=best.hour,
                graph_hits=sum(1 for d in ds if d.graph_p < 1.0),
                n_windows=n,
            ))

        out.sort(key=lambda r: r.p_value)
        if out:
            if self.config.alert_mode == "fdr":
                mask = benjamini_hochberg([r.p_value for r in out], fdr=self.config.alert_fdr)
                for r, m in zip(out, mask, strict=True):
                    r.alerted = bool(m)
            elif self.config.alert_mode == "budget":
                days = max(observed_days or 1.0, 1e-9)
                k = round(self.config.alert_budget_per_day * days)
                for r in out[:max(k, 0)]:
                    r.alerted = True
            else:
                raise ValueError(f"unknown alert_mode {self.config.alert_mode!r}")
        return out

    def alerts(self, entity_risks: list[EntityRisk]) -> list[EntityRisk]:
        return [r for r in entity_risks if r.alerted]

    # -- persistence (non-executable, signed) -----------------------------
    # The bundle is a schema-explicit JSON + .npy directory, not a pickle: loading
    # never reconstructs an arbitrary object or runs code, only populates known
    # fields with numbers and strings. An HMAC over the bundle still guards
    # integrity. See models/serialization.py for the format and its rationale.
    def save(self, directory: str) -> None:
        from ueba_pipeline.models.serialization import save_engine
        save_engine(self, directory)

    @staticmethod
    def load(directory: str) -> BehavioralEngine:
        from ueba_pipeline.models.serialization import load_engine
        engine = load_engine(directory)
        if not isinstance(engine, BehavioralEngine):
            raise ValueError("bundle is not a BehavioralEngine")
        return engine


def _stream_session(resolver: SessionResolver, e) -> None:
    """Append one logon to a live resolver, preserving ascending order."""
    from ueba_pipeline.graph.sessions import _SESSION_LOGON_TYPES
    if str(e.fields.get("logon_type", "")) not in _SESSION_LOGON_TYPES:
        return
    host, user = _norm(e.computer_name), _norm(e.fields.get("target_user_name"))
    if not host or not user or user.endswith("$"):
        return
    resolver._logons.setdefault(host, []).append((e.event_time, user))


def _time_sorted_graph_events(events) -> list:
    return sorted((e for e in events if e.event_time and is_graph_event(e.event_type)),
                  key=lambda e: e.event_time)


def _floor_hour(t: datetime) -> datetime:
    return t.replace(minute=0, second=0, microsecond=0)


def _event_key(e) -> str:
    u = _norm(e.fields.get("target_user_name"))
    return f"{e.event_time.isoformat()}|{e.event_type}|{u}"

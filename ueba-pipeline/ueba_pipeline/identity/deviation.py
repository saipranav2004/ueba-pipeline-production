"""Behavioural deviation track — a separate, separately-budgeted alert queue.

THE GAP THIS FILLS
------------------
The shipped detector scores *relationships*: it asks whether a principal reached
or did something it never has. That is the right instrument for credential theft
and lateral movement, and it is structurally blind to two threat classes that
create **no new relationship**:

  * a compromised **non-human identity** driving its own server, over its own
    service -- only the *time* is wrong (a backup job working at 15:00);
  * **insider / credential abuse** -- a legitimate account using its own
    workstation against its own file server, where only the *rate* is wrong.

Both are measured blind spots of the relational engine (0/18 and 1/9 respectively;
see docs/evaluation.md). This module is the track that covers them.

WHY A SEPARATE TRACK, NOT MORE VIEWS
------------------------------------
This engine has measured **three times** (`src_dst`, a per-entity volume signal,
and a process-lineage view) that adding a signal into the *shared* Tippett minimum
under one alert budget lowers product recall, even when the signal measures well
alone: a broad, moderately-specific signal dominates the minimum for many
identities and displaces a narrow, highly-specific one. The documented conclusion
is that the way forward is "separate queues, not better fusion".

So this track has its **own ranked queue and its own budget**, and never enters the
relational detector's Tippett combination or its budget. The relational headline is
therefore untouched by construction, which the benchmark verifies rather than
assumes.

THE SIGNALS
-----------
Three, each scored per (entity, hour-window), each calibrated against **its own**
frozen benign null. Per-signal calibration is not decoration: the relational engine
measured that one pooled null lets a high-baseline signal set the significance bar
for a low-baseline one, and the first version of this track reproduced that error
exactly (see `hour` below).

``hour``   -- deviation from the identity's learned hour-of-day, as a
              Dirichlet-smoothed conditional backing off to the cohort marginal.
              **Circularly smoothed**: 23:00 is adjacent to 00:00, and a job that
              slips from 02:30 to 03:05 has done nothing surprising. Scoring raw
              per-hour counts made that slip look as novel as activity twelve hours
              away, which was measured to be the dominant error.

``dow``    -- deviation from the identity's learned day-of-week profile.
              Deliberately **not** circularly smoothed, unlike the hour: Friday and
              Saturday are adjacent on the calendar but are exactly the boundary
              that matters, and letting Friday lend mass to Saturday would erase
              the weekday/weekend distinction the signal exists to capture.

``volume`` -- deviation from the identity's learned *rate*, as the upper tail of a
              Gamma-Poisson posterior predictive (Negative Binomial in closed
              form). See models/counts.py for why a count model and not the robust
              z-score a previous attempt used.

Signals are combined per window by **Tippett** (minimum p, Sidak-corrected for the
number of signals that fired) -- the same combiner, for the same reason, as the
relational engine: the alternative is "one of these signals is anomalous", not
"several are mildly odd". Across an identity's windows the minimum is
Sidak-corrected for the number of windows tested.

COVERAGE IS ADMITTED PER SIGNAL, ON MEASURED EVIDENCE
-----------------------------------------------------
A signal is only scored for an identity it can actually say something about, and
admission is a measured property rather than a name or a label -- the same
discipline the relationship views are held to.

  * ``hour`` / ``dow`` need a *schedule*: the identity's busiest three hour-buckets
    must carry >= 95% of its baseline activity, over >= 50 baseline events.
    Measured on training slices across three seeds, scheduled service accounts sit
    at a top-3-hour share of **1.000**, round-the-clock agents reach at most 0.452,
    and no human with sufficient history exceeds 0.920. Round-the-clock agents are
    excluded deliberately: they have no schedule to deviate from, and including
    them was measured to be actively harmful -- their benign activity constantly
    lands in hours they have not used, which inflated the shared null (p99 benign
    surprise 11.45) and buried the genuine deviation of a scheduled job.
  * ``volume`` needs only a *rate*, so it covers any identity with enough history
    (>= `min_periods` windows). This is what lets the same machinery serve the
    insider case, where the subject is an ordinary person with no schedule.
"""
from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from itertools import pairwise

import numpy as np

from ueba_pipeline.models.counts import GammaPoissonCounts
from ueba_pipeline.models.fisher import sidak
from ueba_pipeline.models.pvalue import EmpiricalPValue

# Dirichlet concentration for the back-off to the cohort marginal. The same
# uninformative default the relational detector uses, and for the same reason:
# tuning a prior against a self-generated estate is curve-fitting, not calibration.
DEFAULT_ALPHA = 1.0
# Fraction of the training period held out to calibrate each benign null against a
# frozen baseline. Mirrors EngineConfig.null_calibration_fraction; calibrating
# in-sample would leave a null with no benign-novelty mass (see engine.py).
DEFAULT_NULL_FRACTION = 0.30
# Schedule-admission gate for the hour/dow signals (see module docstring).
SCHEDULE_HOURS = 3
MIN_SCHEDULE_SHARE = 0.95
MIN_BASELINE_EVENTS = 50
# Width of the circular smoothing kernel for the hour signal, in hours. One hour
# lets a schedule that slips across a bucket boundary borrow most of its
# neighbour's mass, while an hour on the far side of the clock borrows essentially
# nothing (exp(-12) ~ 6e-6).
SMOOTHING_TAU_HOURS = 1.0

ALL_SIGNALS = frozenset({"hour", "dow", "volume", "cadence"})
SCHEDULE_SIGNALS = frozenset({"hour", "dow"})

# --- cadence -----------------------------------------------------------------
# An identity's activity arrives in BURSTS, not as isolated events: one service
# logon emits a 4624, a 4672, a service-state change and a handful of ticket
# requests within seconds. Modelling raw event inter-arrivals therefore measures
# the burst's internal spacing, not the identity's rhythm -- measured on the
# estate, every service account has a median raw gap of ~0.5 minutes while its
# actual polling interval is tens of minutes.
#
# So events are first grouped into bursts (a gap longer than BURST_GAP_MINUTES
# starts a new one) and the model is over the gaps BETWEEN bursts. This is the
# structure Price-Williams, Heard & Turcotte (EISIC 2017) describe, where the
# opening event of a subsequence is the meaningful arrival.
BURST_GAP_MINUTES = 5.0
# Log-spaced bin edges in minutes. Log spacing because a cadence is multiplicative:
# the difference between 5 and 10 minutes matters, between 500 and 505 does not.
CADENCE_BIN_EDGES = (5.0, 10.0, 20.0, 40.0, 80.0, 160.0, 320.0, 640.0, 1440.0)
MIN_CADENCE_BURSTS = 20      # too few bursts and a "usual gap" is not established


def _cadence_bin(gap_minutes: float) -> int:
    """Index of the log-spaced bin a between-burst gap falls in."""
    for i, edge in enumerate(CADENCE_BIN_EDGES):
        if gap_minutes < edge:
            return i
    return len(CADENCE_BIN_EDGES)


def _bursts(times: Sequence[datetime]) -> list[datetime]:
    """Start time of each burst: a gap > BURST_GAP_MINUTES opens a new one."""
    out: list[datetime] = []
    prev = None
    for t in sorted(times):
        if prev is None or (t - prev).total_seconds() / 60.0 > BURST_GAP_MINUTES:
            out.append(t)
        prev = t
    return out


def _circular_kernel(tau: float = SMOOTHING_TAU_HOURS) -> np.ndarray:
    """Weights by circular hour distance: ``w[d] = exp(-d/tau)`` for d = 0..12."""
    d = np.arange(13, dtype=np.float64)      # max circular distance on a 24h clock
    return np.exp(-d / max(tau, 1e-9))


@dataclass
class TrackAlert:
    """One identity ranked by how far its behaviour departed from its own baseline."""

    entity: str
    p_value: float                  # Sidak-corrected over the windows it was tested in
    top_hour: datetime | None    # the window driving the score
    surprise: float                 # raw surprise, in nats, of that window
    signal: str                     # which signal drove it -- analyst provenance
    n_windows: int
    alerted: bool = False


@dataclass
class BehaviouralDeviationTrack:
    """Per-identity temporal and volumetric baselines with frozen, calibrated nulls.

    ``fit`` learns the baselines and freezes one null per signal; ``score`` is pure
    and does not mutate them, so re-scoring the same events always gives the same
    answer -- the state contract the relational detector holds to.
    """

    alpha: float = DEFAULT_ALPHA
    null_calibration_fraction: float = DEFAULT_NULL_FRACTION
    enabled_signals: frozenset[str] = ALL_SIGNALS
    min_schedule_share: float = MIN_SCHEDULE_SHARE
    min_baseline_events: int = MIN_BASELINE_EVENTS
    # Identities admitted to the schedule signals (hour/dow), measured at fit time.
    covered: set = field(default_factory=set)
    _hour_counts: dict[str, dict[int, float]] = field(default_factory=dict)
    _dow_counts: dict[str, dict[int, float]] = field(default_factory=dict)
    _entity_totals: dict[str, float] = field(default_factory=dict)
    _hour_marginal: dict[int, float] = field(default_factory=dict)
    _dow_marginal: dict[int, float] = field(default_factory=dict)
    _total: float = 0.0
    _counts: GammaPoissonCounts = field(default_factory=GammaPoissonCounts)
    # Cadence: per-entity distribution over between-burst gap bins.
    _cadence_counts: dict[str, dict[int, float]] = field(default_factory=dict)
    _cadence_totals: dict[str, float] = field(default_factory=dict)
    _cadence_marginal: dict[int, float] = field(default_factory=dict)
    _cadence_total: float = 0.0
    cadence_covered: set = field(default_factory=set)
    _nulls: dict[str, EmpiricalPValue] = field(default_factory=dict)
    _kernel: np.ndarray = field(default_factory=_circular_kernel)

    # -- training ---------------------------------------------------------
    def fit(self, events: Sequence) -> BehaviouralDeviationTrack:
        """Admit identities, learn their baselines, freeze one null per signal.

        The baseline is learnt from the earlier part of the training period and
        each null is measured on a **later held-out slice scored against that
        frozen baseline** -- the situation a live benign event actually meets.
        Folding all training data in and then scoring it would mark every hour
        "already seen", leaving a null with no benign-novelty mass, so any first
        activity in a new hour would look extreme.
        """
        rows = self._rows(events)
        self.covered = self._admit(rows)

        cut = max(1, int(len(rows) * (1.0 - self.null_calibration_fraction)))
        baseline, calib = rows[:cut], rows[cut:]
        if not calib:                       # too little data to hold any out
            baseline, calib = rows, rows

        for entity, when in baseline:
            self._observe(entity, when)
        self._learn_cadence(baseline)
        base_windows = self._windows(baseline)
        for (entity, _), count in base_windows.items():
            self._counts.observe(entity, count)

        # Per-signal nulls, each measured on the held-out slice only.
        by_signal: dict[str, list[float]] = {}
        calib_gaps = self._window_gaps(calib)
        for (entity, window), count in sorted(self._windows(calib).items()):
            for signal, s in self._window_surprises(
                    entity, window, count, calib_gaps.get((entity, window))):
                by_signal.setdefault(signal, []).append(s)
        self._nulls = {
            signal: EmpiricalPValue().fit(np.asarray(scores))
            for signal, scores in by_signal.items() if scores
        }

        # Fold the calibration slice in, so the deployed baseline uses the whole
        # training period. Each null is then calibrated against a slightly smaller
        # baseline than the one deployed: conservative, never optimistic.
        for entity, when in calib:
            self._observe(entity, when)
        self._learn_cadence(calib)
        for (entity, _), count in self._windows(calib).items():
            self._counts.observe(entity, count)
        return self

    def _learn_cadence(self, rows: Sequence[tuple[str, datetime]]) -> None:
        """Fold between-burst gaps into each entity's cadence baseline."""
        per: dict[str, list[datetime]] = {}
        for entity, when in rows:
            per.setdefault(entity, []).append(when)
        for entity, times in per.items():
            for a, b in pairwise(_bursts(times)):
                idx = _cadence_bin((b - a).total_seconds() / 60.0)
                self._cadence_counts.setdefault(entity, {})[idx] = \
                    self._cadence_counts.setdefault(entity, {}).get(idx, 0.0) + 1.0
                self._cadence_totals[entity] = self._cadence_totals.get(entity, 0.0) + 1.0
                self._cadence_marginal[idx] = self._cadence_marginal.get(idx, 0.0) + 1.0
                self._cadence_total += 1.0
            if self._cadence_totals.get(entity, 0.0) >= MIN_CADENCE_BURSTS:
                self.cadence_covered.add(entity)

    @staticmethod
    def _window_gaps(rows: Sequence[tuple[str, datetime]]) -> dict[tuple[str, datetime], float]:
        """Gap, in minutes, that preceded the burst opening in each (entity, window).

        A window with no new burst (activity continuing from the previous one)
        carries no cadence evidence and is simply absent from the map.
        """
        per: dict[str, list[datetime]] = {}
        for entity, when in rows:
            per.setdefault(entity, []).append(when)
        out: dict[tuple[str, datetime], float] = {}
        for entity, times in per.items():
            for a, b in pairwise(_bursts(times)):
                key = (entity, b.replace(minute=0, second=0, microsecond=0))
                gap = (b - a).total_seconds() / 60.0
                # Keep the SHORTEST gap in the window: a burst arriving far sooner
                # than usual is the anomaly a cadence model exists to see.
                if key not in out or gap < out[key]:
                    out[key] = gap
        return out

    def _cadence_surprise(self, entity: str, gap_minutes: float) -> float:
        """-log P(gap bin | entity), Dirichlet-smoothed to the cohort marginal."""
        idx = _cadence_bin(gap_minutes)
        c = self._cadence_counts.get(entity, {}).get(idx, 0.0)
        n = self._cadence_totals.get(entity, 0.0)
        n_bins = len(CADENCE_BIN_EDGES) + 1
        pi = (self._cadence_marginal.get(idx, 0.0) + 1.0) / (self._cadence_total + n_bins)
        p = (c + self.alpha * pi) / (n + self.alpha)
        return -math.log(max(min(p, 1.0), 1e-12))

    def _admit(self, rows: Sequence[tuple[str, datetime]]) -> set:
        """Identities whose activity is concentrated enough for the schedule signals."""
        hours: dict[str, list[int]] = {}
        for entity, when in rows:
            hours.setdefault(entity, []).append(when.hour)
        admitted = set()
        for entity, hs in hours.items():
            if len(hs) < self.min_baseline_events:
                continue
            counts = np.bincount(np.asarray(hs), minlength=24).astype(float)
            share = float(np.sort(counts)[::-1][:SCHEDULE_HOURS].sum() / counts.sum())
            if share >= self.min_schedule_share:
                admitted.add(entity)
        return admitted

    @staticmethod
    def _windows(rows: Sequence[tuple[str, datetime]]) -> dict[tuple[str, datetime], int]:
        """Event counts per (entity, hour-window)."""
        out: dict[tuple[str, datetime], int] = {}
        for entity, when in rows:
            key = (entity, when.replace(minute=0, second=0, microsecond=0))
            out[key] = out.get(key, 0) + 1
        return out

    @staticmethod
    def _rows(events: Sequence) -> list[tuple[str, datetime]]:
        """Time-ordered ``(entity, timestamp)`` for every attributable event."""
        from ueba_pipeline.features.aggregate import _user_key

        out: list[tuple[str, datetime]] = []
        for e in events:
            if getattr(e, "event_time", None) is None:
                continue
            key = _user_key(e)
            if key:
                out.append((key, e.event_time))
        out.sort(key=lambda r: r[1])
        return out

    def _observe(self, entity: str, when: datetime) -> None:
        h, d = when.hour, when.weekday()
        self._hour_counts.setdefault(entity, {})[h] = \
            self._hour_counts.setdefault(entity, {}).get(h, 0.0) + 1.0
        self._dow_counts.setdefault(entity, {})[d] = \
            self._dow_counts.setdefault(entity, {}).get(d, 0.0) + 1.0
        self._entity_totals[entity] = self._entity_totals.get(entity, 0.0) + 1.0
        self._hour_marginal[h] = self._hour_marginal.get(h, 0.0) + 1.0
        self._dow_marginal[d] = self._dow_marginal.get(d, 0.0) + 1.0
        self._total += 1.0

    # -- per-signal surprise ----------------------------------------------
    def _smoothed(self, counts: dict[int, float], hour: int) -> float:
        """Circularly smoothed hour count: neighbours lend mass by clock distance."""
        w = self._kernel
        total = 0.0
        for h, c in counts.items():
            d = abs(h - hour)
            d = min(d, 24 - d)               # circular distance on a 24-hour clock
            total += c * w[d]
        return total

    def _hour_surprise(self, entity: str, hour: int) -> float:
        """-log P(hour | entity), circularly smoothed on both the conditional and
        its back-off so the two describe the same geometry."""
        c = self._smoothed(self._hour_counts.get(entity, {}), hour)
        n = self._entity_totals.get(entity, 0.0)
        marg = self._smoothed(self._hour_marginal, hour)
        pi = (marg + 1.0) / (self._total + 24.0)
        p = (c + self.alpha * pi) / (n + self.alpha)
        return -math.log(max(min(p, 1.0), 1e-12))

    def _dow_surprise(self, entity: str, dow: int) -> float:
        """-log P(day-of-week | entity). No circular smoothing -- see docstring."""
        c = self._dow_counts.get(entity, {}).get(dow, 0.0)
        n = self._entity_totals.get(entity, 0.0)
        pi = (self._dow_marginal.get(dow, 0.0) + 1.0) / (self._total + 7.0)
        p = (c + self.alpha * pi) / (n + self.alpha)
        return -math.log(max(min(p, 1.0), 1e-12))

    def _window_surprises(self, entity: str, window: datetime, count: int,
                          gap_minutes: float | None = None) -> list[tuple[str, float]]:
        """Every enabled signal that can speak about this (entity, window)."""
        out: list[tuple[str, float]] = []
        if ("cadence" in self.enabled_signals and gap_minutes is not None
                and entity in self.cadence_covered):
            out.append(("cadence", self._cadence_surprise(entity, gap_minutes)))
        if entity in self.covered:
            if "hour" in self.enabled_signals:
                out.append(("hour", self._hour_surprise(entity, window.hour)))
            if "dow" in self.enabled_signals:
                out.append(("dow", self._dow_surprise(entity, window.weekday())))
        if "volume" in self.enabled_signals and self._counts.is_covered(entity):
            out.append(("volume", self._counts.surprise(entity, count)))
        return out

    # -- scoring (PURE) ---------------------------------------------------
    def score(self, events: Sequence, budget_per_day: float = 1.0) -> list[TrackAlert]:
        """Rank identities by their most deviant window.

        Returns every scored identity, ordered by significance, with the top
        ``budget_per_day`` per day flagged ``alerted``. This queue is the track's
        own: it is never merged into the relational detector's ranking or budget.
        """
        if not self._nulls:
            return []
        rows = self._rows(events)
        if not rows:
            return []

        gaps = self._window_gaps(rows)
        best: dict[str, tuple[float, datetime, float, str]] = {}
        for (entity, window), count in self._windows(rows).items():
            scored = []
            for signal, s in self._window_surprises(
                    entity, window, count, gaps.get((entity, window))):
                null = self._nulls.get(signal)
                if null is not None:
                    scored.append((float(null.pvalue(s)[0]), s, signal))
            if not scored:
                continue
            # Tippett across the signals that fired, corrected for how many did.
            p_min, s_at_min, signal = min(scored, key=lambda r: (r[0], -r[1]))
            p = sidak(p_min, len(scored))
            prev = best.get(entity)
            # Ties are the norm: every window whose surprise exceeds the whole
            # benign null floors at the same 1/(n+1), so a plain min() over p would
            # report an arbitrary -- often benign -- window as the peak. Breaking
            # on raw surprise resolves it, p being a monotone transform of it.
            if prev is None or (p, -s_at_min) < (prev[0], -prev[2]):
                best[entity] = (p, window, s_at_min, signal)

        counted: dict[str, int] = {}
        for entity, _ in self._windows(rows):
            counted[entity] = counted.get(entity, 0) + 1

        alerts = [
            TrackAlert(entity=entity, p_value=sidak(p, max(counted.get(entity, 1), 1)),
                       top_hour=window, surprise=s, signal=signal,
                       n_windows=counted.get(entity, 1))
            for entity, (p, window, s, signal) in best.items()
        ]
        alerts.sort(key=lambda a: (a.p_value, -a.surprise))
        span = (rows[-1][1] - rows[0][1]).total_seconds() / 86400.0
        k = round(budget_per_day * max(span, 1.0))
        for a in alerts[:max(k, 0)]:
            a.alerted = True
        return alerts


# ── The two shipped queues ───────────────────────────────────────────────────
# Each threat class gets its OWN queue with its OWN budget. That is not tidiness:
# it is what the measurement forced. Running all three signals in one queue was
# tried and is markedly worse than either queue alone, because `volume` covers
# every identity in the estate while `hour` covers only the handful with a
# schedule -- so under a shared budget the broad signal floods the queue and
# displaces the narrow one. Measured on the NHI corpus, at 0.5 alerts/day:
#
#   signals            recall (covered)   FP/day
#   hour                 9/11 = 81.8%       0.31     <- shipped as the NHI queue
#   hour + volume        1/18 =  5.6%       0.48     <- volume floods it
#   hour + dow + volume  1/18 =  5.6%       0.48
#
# This is the same displacement law the relational engine measured three times
# (`src_dst`, a volume signal, a process-lineage view). Applying "separate queues,
# not better fusion" recursively is the resolution.


def nhi_schedule_queue(**kwargs) -> BehaviouralDeviationTrack:
    """Queue for compromised non-human identities: schedule deviation.

    ``hour`` only. ``dow`` is implemented and deliberately **not** enabled here:
    measured on the NHI corpus it contributes nothing (0/18 alone) and costs a
    detection in combination (9/11 -> 8/11), because every service account in the
    estate runs seven days a week, so no day is unusual for one. That makes the
    corpus structurally unable to exercise it rather than proving the idea wrong --
    the signal would matter for a weekday-only batch job triggered on a Sunday,
    which this estate does not contain. It stays available behind
    ``enabled_signals`` for a deployment that has such identities, and it is not
    shipped on evidence that does not exist yet.
    """
    kwargs.setdefault("enabled_signals", frozenset({"hour"}))
    return BehaviouralDeviationTrack(**kwargs)


def insider_volume_queue(**kwargs) -> BehaviouralDeviationTrack:
    """Queue for insider / credential abuse: rate deviation over existing access.

    ``volume`` only, covering any identity with enough history -- an insider has no
    schedule to deviate from, only a normal working rate.
    """
    kwargs.setdefault("enabled_signals", frozenset({"volume"}))
    return BehaviouralDeviationTrack(**kwargs)


# Alias kept for readability at call sites that mean the NHI track specifically.
NHITemporalDetector = BehaviouralDeviationTrack
NHIAlert = TrackAlert

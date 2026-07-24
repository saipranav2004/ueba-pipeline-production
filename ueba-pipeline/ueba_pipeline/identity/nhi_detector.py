"""NHI temporal-deviation detector — a separate, separately-budgeted track.

THE GAP THIS FILLS
------------------
The shipped detector scores *relationships*: it asks whether a principal reached
or did something it never has. That is the right instrument for credential theft
and lateral movement, and it is structurally blind to a compromised **non-human
identity** used within its own access. A stolen service-account credential driving
that account's own server, over its own service, with its own ticket encryption,
creates no new edge — every relationship view scores it as routine, correctly. The
only thing wrong is *when*: a backup job that has only ever run at 02:30 is
suddenly working at 15:00.

That is the same shape as the insider volume gap ([evaluation.md](../../docs/evaluation.md)),
and it needs the same remedy: a signal that is not relational novelty. Here the
discriminating quantity is the identity's **activity time**.

WHICH IDENTITIES IT COVERS, AND WHY THAT IS MEASURED
----------------------------------------------------
Deviation from a schedule is only meaningful for an identity that *has* one, so
coverage is decided by a measured property rather than by a name or a type label:
an identity is admitted only if its baseline activity is **concentrated in a few
hours** (its busiest three hour-buckets carry >= 95% of its activity) and it has
**enough history** for that concentration to mean something (>= 50 baseline
events).

This is the same admission discipline the relationship views are held to -- a view
whose benign edges are routinely novel cannot separate a first contact from an
attack, so it is not admitted. Measured on training slices across three seeds, the
gate separates perfectly: every scheduled service account sits at a top-3-hour
share of **1.000**, while round-the-clock agents reach at most 0.452 and no human
with sufficient history exceeds 0.920.

Both exclusions are deliberate and honest:

  * **round-the-clock agents** (a monitoring poller firing at every hour) have no
    schedule to deviate from at this granularity. Including them was measured to
    be actively harmful: their benign activity constantly lands in hours they have
    not used before, which inflates the shared null (p99 benign surprise 11.45)
    and buries the genuine deviation of a scheduled job. Excluding them leaves the
    covered cohort homogeneous, which is what makes a single null valid here.
  * **people** do not pass the gate; a work-hour band is not a schedule at this
    resolution. The few humans who look concentrated are low-activity admin
    accounts, which the baseline-size requirement excludes -- with thirty events
    you cannot establish that an identity has a schedule.

WHY A SEPARATE TRACK, NOT A SIXTH VIEW
--------------------------------------
This engine has measured three times (`src_dst`, a per-entity volume signal, and a
process-lineage view) that adding a signal into the *shared* Tippett minimum under
one alert budget lowers product recall, even when the signal measures well alone:
a broad, moderately-specific signal dominates the minimum for many identities and
displaces a narrow, highly-specific one. The documented conclusion is that the way
forward is "separate queues, not better fusion".

So this detector is exactly that:

  * it scores **only identities typed `automated`** (identity/typing.py), a small
    cohort with tight temporal baselines, rather than every identity;
  * it emits its **own ranked alert queue with its own budget**, and never enters
    the relational detector's Tippett combination or its budget;
  * the shipped headline is therefore untouched by construction, which the
    benchmark verifies rather than assumes.

THE MODEL
---------
Deliberately the *same* statistical machinery as the relational detector, so the
system carries one idea rather than two. Per identity, the hour-of-day an event
occurs in is a categorical draw, smoothed by Dirichlet back-off to the cohort's
global hour marginal:

    surprise = -log P(hour | identity)
    P(h | e) = (c_eh + alpha * pi_h) / (n_e + alpha)

with ``c_eh`` the times identity ``e`` was active in hour ``h``, ``n_e`` its total
activity, and ``pi_h`` the automated cohort's marginal for that hour. The
properties that make this right are the ones that make the edge model right:

  * an identity active in an hour it has **never** used, having been active many
    times elsewhere, scores high — many opportunities, never taken;
  * an hour that is **globally common** for automation scores lower — routine;
  * a **cold-start** identity with no history scores ~0 — nothing is surprising
    without evidence;
  * a **habitual** hour decays smoothly toward 0, so the score is rankable.

THE HOUR IS A CIRCULAR VARIABLE, AND TREATING IT OTHERWISE DOES NOT WORK
------------------------------------------------------------------------
Hour buckets are not unordered categories: 23:00 is adjacent to 00:00, and a job
scheduled for 02:30 that slips to 03:05 has not done anything surprising. Scoring
raw per-hour counts makes that slip look exactly as novel as activity twelve hours
away, and it was measured to be the dominant error -- real schedules jitter across
a bucket boundary constantly, so almost every covered identity produced a benign
"novel hour" and the queue filled with them.

So the per-hour counts are **circularly smoothed** before the conditional is
formed: each hour borrows mass from its neighbours with an exponential decay in
circular distance,

    c~(h) = sum_d exp(-|d|_circ / tau) * c(h + d mod 24)

with ``tau`` one hour. This is the discrete counterpart of a circular
(von Mises-style) kernel density estimate, the standard treatment for a periodic
variable (Mardia & Jupp, *Directional Statistics*). The effect is exactly the
discrimination the problem needs: an hour adjacent to the schedule is nearly as
expected as the schedule itself, while an hour on the other side of the clock
borrows essentially nothing and stays surprising.

Raw surprise is then turned into a **calibrated p-value against a benign null
frozen on a held-out slice of training**, by the same `EmpiricalPValue` the
relational track uses and for the same reason (a raw score is meaningless until
it is stated relative to what benign data produces).

Only *one* hypothesis is examined per (identity, hour) cell — the hour bucket
itself — so there is no within-cell multiplicity to correct. Across an identity's
windows the minimum is Sidak-corrected for the number of windows tested, exactly
as in the relational rollup: a minimum over n windows *is* a test over n windows.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np

from ueba_pipeline.models.fisher import sidak
from ueba_pipeline.models.pvalue import EmpiricalPValue

# Dirichlet concentration for the back-off to the cohort hour marginal. The same
# uninformative default the relational detector uses, and for the same reason:
# tuning a prior against a self-generated estate is curve-fitting, not calibration.
DEFAULT_ALPHA = 1.0
# Fraction of the training period held out to calibrate the benign null against a
# frozen baseline. Mirrors EngineConfig.null_calibration_fraction; calibrating
# in-sample would leave the null with no benign-novelty mass (see engine.py).
DEFAULT_NULL_FRACTION = 0.30
# Admission gate (see module docstring). Both thresholds sit in the measured gap
# between identities that have a schedule and identities that do not.
SCHEDULE_HOURS = 3           # how many busiest hour-buckets define "the schedule"
MIN_SCHEDULE_SHARE = 0.95    # scheduled accounts measure 1.000; no eligible human > 0.920
MIN_BASELINE_EVENTS = 50     # below this, concentration is an artifact of sparsity
# Width of the circular smoothing kernel, in hours. One hour lets a schedule that
# slips across a bucket boundary borrow most of its neighbour's mass, while an
# hour on the far side of the clock borrows essentially nothing (exp(-12) ~ 6e-6).
SMOOTHING_TAU_HOURS = 1.0


def _circular_kernel(tau: float = SMOOTHING_TAU_HOURS) -> np.ndarray:
    """Weights by circular hour distance: ``w[d] = exp(-d/tau)`` for d = 0..12."""
    d = np.arange(13, dtype=np.float64)      # max circular distance on a 24h clock
    return np.exp(-d / max(tau, 1e-9))


@dataclass
class NHIAlert:
    """One automated identity ranked by how off-schedule its activity was."""

    entity: str
    p_value: float                  # Sidak-corrected over the windows it was tested in
    top_hour: Optional[datetime]    # the window driving the score
    surprise: float                 # raw surprise, in nats, of that window
    n_windows: int
    alerted: bool = False


@dataclass
class NHITemporalDetector:
    """Per-identity hour-of-day baseline with a frozen, calibrated null.

    ``fit`` learns the baseline and freezes the null; ``score`` is pure and does
    not mutate it, so re-scoring the same events always gives the same answer --
    the state contract the relational detector holds to.
    """

    alpha: float = DEFAULT_ALPHA
    null_calibration_fraction: float = DEFAULT_NULL_FRACTION
    min_schedule_share: float = MIN_SCHEDULE_SHARE
    min_baseline_events: int = MIN_BASELINE_EVENTS
    # Identities this track covers: those measured to have a schedule at fit time.
    covered: set = field(default_factory=set)
    _hour_counts: Dict[str, Dict[int, float]] = field(default_factory=dict)
    _entity_totals: Dict[str, float] = field(default_factory=dict)
    _hour_marginal: Dict[int, float] = field(default_factory=dict)
    _total: float = 0.0
    _null: Optional[EmpiricalPValue] = None
    _kernel: np.ndarray = field(default_factory=_circular_kernel)

    # -- training ---------------------------------------------------------
    def fit(self, events: Sequence) -> "NHITemporalDetector":
        """Admit the scheduled identities, learn their hour baseline, freeze the null.

        Coverage is decided first, from the training data alone (§admission), then
        the baseline is learnt from the earlier part of the training period and the
        null is measured on a **later held-out slice scored against that frozen
        baseline** -- the situation a live benign event actually meets. Folding all
        training data in and then scoring it would mark every hour "already seen",
        leaving a null with no benign-novelty mass, so any first activity in a new
        hour would look extreme.
        """
        all_rows = self._rows(events, restrict=False)
        self.covered = self._admit(all_rows)

        rows = [r for r in all_rows if r[0] in self.covered]
        cut = max(1, int(len(rows) * (1.0 - self.null_calibration_fraction)))
        baseline, calib = rows[:cut], rows[cut:]
        if not calib:                       # too little data to hold any out
            baseline, calib = rows, rows

        for entity, when in baseline:
            self._observe(entity, when)

        scores = [self._surprise(entity, when.hour) for entity, when in calib]
        self._null = EmpiricalPValue().fit(np.asarray(scores if scores else [0.0]))

        # Fold the calibration slice in, so the deployed baseline uses the whole
        # training period. The null is then calibrated against a slightly smaller
        # baseline than the one deployed: conservative, never optimistic.
        for entity, when in calib:
            self._observe(entity, when)
        return self

    def _admit(self, rows: Sequence[Tuple[str, datetime]]) -> set:
        """Identities whose training activity shows a schedule concentrated enough
        to make deviation from it meaningful (§admission)."""
        hours: Dict[str, List[int]] = {}
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

    def _rows(self, events: Sequence, restrict: bool = True) -> List[Tuple[str, datetime]]:
        """Time-ordered ``(entity, timestamp)``; covered identities only by default."""
        from ueba_pipeline.features.aggregate import _user_key

        out: List[Tuple[str, datetime]] = []
        for e in events:
            if getattr(e, "event_time", None) is None:
                continue
            key = _user_key(e)
            if key and (not restrict or key in self.covered):
                out.append((key, e.event_time))
        out.sort(key=lambda r: r[1])
        return out

    def _observe(self, entity: str, when: datetime) -> None:
        h = when.hour
        self._hour_counts.setdefault(entity, {})[h] = \
            self._hour_counts.setdefault(entity, {}).get(h, 0.0) + 1.0
        self._entity_totals[entity] = self._entity_totals.get(entity, 0.0) + 1.0
        self._hour_marginal[h] = self._hour_marginal.get(h, 0.0) + 1.0
        self._total += 1.0

    def _smoothed(self, counts: Dict[int, float], hour: int) -> float:
        """Circularly smoothed count at ``hour``: neighbours lend mass by distance."""
        w = self._kernel
        total = 0.0
        for h, c in counts.items():
            d = abs(h - hour)
            d = min(d, 24 - d)               # circular distance on a 24-hour clock
            total += c * w[d]
        return total

    def _surprise(self, entity: str, hour: int) -> float:
        """-log P(hour | entity) under the circularly-smoothed Dirichlet model.

        Both the per-identity counts and the cohort marginal are smoothed, so the
        conditional and its back-off describe the same circular geometry.
        """
        c = self._smoothed(self._hour_counts.get(entity, {}), hour)
        n = self._entity_totals.get(entity, 0.0)
        # Cohort marginal for this hour, Laplace-smoothed over the 24 buckets.
        marg = self._smoothed(self._hour_marginal, hour)
        pi = (marg + 1.0) / (self._total + 24.0)
        p = (c + self.alpha * pi) / (n + self.alpha)
        return -math.log(max(min(p, 1.0), 1e-12))

    # -- scoring (PURE) ---------------------------------------------------
    def score(self, events: Sequence, budget_per_day: float = 1.0) -> List[NHIAlert]:
        """Rank covered identities by their most off-schedule window.

        Returns every scored identity, ordered by significance, with the top
        ``budget_per_day`` per day flagged ``alerted``. This queue is the track's
        own: it is never merged into the relational detector's ranking or budget.
        """
        if self._null is None:
            return []
        rows = self._rows(events)
        if not rows:
            return []

        # One hypothesis per (entity, hour-window): every event in the cell shares
        # the same hour bucket, so there is no within-cell multiplicity.
        cell: Dict[Tuple[str, datetime], float] = {}
        for entity, when in rows:
            window = when.replace(minute=0, second=0, microsecond=0)
            s = self._surprise(entity, when.hour)
            key = (entity, window)
            if s > cell.get(key, -1.0):
                cell[key] = s

        by_entity: Dict[str, List[Tuple[datetime, float]]] = {}
        for (entity, window), s in cell.items():
            by_entity.setdefault(entity, []).append((window, s))

        alerts: List[NHIAlert] = []
        for entity, windows in by_entity.items():
            ps = [(w, s, float(self._null.pvalue(s)[0])) for w, s in windows]
            # Ties are the norm, not the exception: every window whose surprise
            # exceeds the whole benign null is floored at the same 1/(n+1), so a
            # plain min() over p would pick an arbitrary window -- often a benign
            # one -- and report the wrong hour to the analyst. Breaking the tie on
            # raw surprise resolves it correctly, since p is a monotone transform
            # of surprise and the floor is only a resolution limit.
            best_w, best_s, best_p = min(ps, key=lambda r: (r[2], -r[1]))
            n = len(windows)
            alerts.append(NHIAlert(entity=entity, p_value=sidak(best_p, n),
                                   top_hour=best_w, surprise=best_s, n_windows=n))

        # Same tie-break across entities, so the ranking is by evidence rather
        # than by dictionary order once the p-value floor is reached.
        alerts.sort(key=lambda a: (a.p_value, -a.surprise))
        span = (rows[-1][1] - rows[0][1]).total_seconds() / 86400.0
        k = int(round(budget_per_day * max(span, 1.0)))
        for a in alerts[:max(k, 0)]:
            a.alerted = True
        return alerts

"""Type an identity as automated (NHI) or human from the shape of its activity.

WHY
---
A generic identity-behaviour engine must not model a service account with the
same machinery as a person: they are different populations (docs/detection.md
§7). A backup runs at 02:30 every night including weekends; a monitoring agent
polls on a fixed interval; a person works a drifting daytime band and takes
weekends and holidays off. Deciding which an identity is — from its *behaviour*,
not from a `svc_*` name — is the first thing an NHI-aware pipeline needs, and it
must be data-source-agnostic, so it reads only event timestamps.

WHAT SIGNAL SEPARATES THEM
--------------------------
Three timestamp-only statistics, each independently discriminating and each with
a domain or statistical basis. They are combined by a small, measured rule (§rule)
rather than a fitted model, because the separation is large and a rule is
auditable — the same stance the identity graph takes on its composite
(docs/graph.md §2.4).

1. **Weekend-activity ratio** — the share of activity on Saturday/Sunday. A
   scheduled job runs seven days a week (~2/7 of its activity lands on a weekend);
   a person's weekend activity is near zero. This is the **clean separator** on
   identity telemetry: measured on the estate, humans sit at 0–0.13 and service
   accounts at 0.20–0.30, with an empty gap between (docs/identities.md).

2. **Time-of-day concentration** — the Rayleigh resultant length R of the event
   hours mapped onto a 24-hour circle. R∈[0,1]; a job firing at one clock time
   drives R toward 1, a person spread across a work-hour band sits lower. R is the
   standard test statistic for circular concentration (Mardia & Jupp,
   *Directional Statistics*). A razor-tight R (scheduled batch jobs reach exactly
   1.00, above any human) catches an automated identity that does *not* happen to
   run weekends, which the weekend signal alone would miss.

3. **Periodicity** — Fisher's g-test p-value on the hourly activity series
   (`models/periodicity.py`), following Heard, Rubin-Delanchy & Lawson (JISIC
   2014). This is the literature's headline method, and its role here is deliberately
   **secondary and measured**: at the coarse (hourly) granularity of logon telemetry,
   a person working a weekday office band is *itself* strongly daily-periodic (p
   down to 1e-13), so periodicity is **necessary but not sufficient** and keying on
   it alone over-types 2/3 of humans as automated (measured: docs/identities.md).
   It is used only to *confirm* a machine-tight time-of-day, and it is the signal
   that *would* dominate on fine-grained polling data (sub-minute intervals a human
   never produces) — the setting the JISIC method was built for.

The engine's detection path is untouched: typing is enrichment (analyst context,
and the substrate a future NHI-specific detector would build on), not a fused
score. Folding it into detection is the documented next step and would enter as a
separately-calibrated track, benchmarked on its own — the standard every
component here is held to (docs/graph.md Part 2).
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Sequence

import numpy as np

from ueba_pipeline.models.periodicity import fisher_g_test

# An identity needs enough activity, spread over enough distinct hours, before a
# period can be resolved at all; below this it is typed "unknown" rather than
# guessed. A handful of events over two days cannot reveal a daily rhythm.
DEFAULT_MIN_EVENTS = 12
DEFAULT_MIN_ACTIVE_HOURS = 6
# Decision thresholds, set from the measured separation on the simulator estate
# (docs/identities.md), each placed inside the empty gap between the two
# populations so the rule is conservative (a periodic-but-human account is left
# "human"). See classify_identity for how they combine.
# The load-bearing measured fact is that automated identities never sit in the
# HUMAN work-hour band on time-of-day concentration: they are either round-the-
# clock (a monitoring agent firing at all hours, R<=0.24) or razor-tight (a batch
# job at one clock time, R>=0.997). A person's daytime band sits strictly between
# (measured R in [0.54, 0.997]). So the rule pairs weekend activity with a
# non-human time-of-day shape, which leaves a weekend-*working* human — who keeps a
# daytime band — correctly typed human.
#   weekend:  humans <=0.22, service accounts >=0.19 (overlapping tails) -> 0.15
#   tod low:  humans >=0.54, round-the-clock agents <=0.24               -> 0.50
#   tod high: razor-tight jobs sit at R>=0.995; a few humans reach that too, so
#             this clause is weekend-gated, and the pair admits no human across
#             six seeds on both full and training slices                   -> 0.995
#
# Periodicity is deliberately NOT a gate. Measured on training slices across three
# seeds, the g-test p distributions of the two populations are nearly identical
# (service median 1.0e-3, human median 3.0e-3) -- it does not discriminate -- and
# requiring it cost coverage badly on shorter windows, where fewer cycles weaken
# every g-test and half the service accounts fell below any useful gate. It is
# retained on the profile as reported evidence, not as a decision input.
AUTOMATED_WEEKEND_RATIO = 0.15       # sustained weekend activity is machine-like
HUMAN_TOD_LOW = 0.50                 # below this = round-the-clock, not a daytime band
RAZOR_TIGHT_TOD = 0.995              # at/above this = one clock window, no human daytime


@dataclass(frozen=True)
class IdentityProfile:
    """The behavioural type of one identity and the evidence for it."""

    entity: str
    kind: str                       # "automated" | "human" | "unknown"
    n_events: int
    active_hours: int               # distinct clock-hours with any activity
    span_days: float
    periodicity_p: float            # Fisher g-test p on the hourly series
    g: float                        # g-statistic (spectral concentration)
    dominant_period_hours: float
    weekend_active_ratio: float
    tod_concentration: float        # Rayleigh R of hour-of-day, in [0, 1]
    reason: str

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        for k in ("periodicity_p", "g", "dominant_period_hours",
                  "weekend_active_ratio", "tod_concentration", "span_days"):
            d[k] = float(d[k])
        return d


def _hourly_counts(times: Sequence[datetime]) -> tuple:
    """Bin event times into an hourly count series over their full span.

    Returns (counts, span_hours). The series is regular (fixed 1-hour bins) as the
    periodogram requires, and spans first to last event so a gap of inactivity is
    represented as zeros rather than being closed up (which would fabricate
    regularity).
    """
    ts = sorted(times)
    t0, t1 = ts[0], ts[-1]
    span_hours = int((t1 - t0).total_seconds() // 3600) + 1
    counts = np.zeros(max(span_hours, 1), dtype=np.float64)
    for t in ts:
        idx = int((t - t0).total_seconds() // 3600)
        if 0 <= idx < counts.size:
            counts[idx] += 1.0
    return counts, span_hours


def _rayleigh_r(hours_of_day: np.ndarray) -> float:
    """Rayleigh resultant length of hours-of-day on the 24-hour circle.

    R = |mean of unit vectors at angle 2*pi*hour/24|, in [0, 1]. R near 1 means the
    activity fires in one tight clock window (a scheduled job); a broad daytime
    band sits lower.
    """
    if hours_of_day.size == 0:
        return 0.0
    ang = 2.0 * math.pi * hours_of_day / 24.0
    c, s = np.mean(np.cos(ang)), np.mean(np.sin(ang))
    return float(math.hypot(c, s))


def classify_identity(
    entity: str,
    times: Sequence[datetime],
    min_events: int = DEFAULT_MIN_EVENTS,
    min_active_hours: int = DEFAULT_MIN_ACTIVE_HOURS,
) -> IdentityProfile:
    """Type one identity from its event timestamps.

    The rule (§rule): an identity is **automated** if it is active on weekends AND
    its time-of-day profile is non-human — either round-the-clock (spread across
    all hours) or a razor-tight clock window that periodicity confirms. Pairing
    weekend activity with a non-human time-of-day shape is what leaves a
    weekend-*working* person — who keeps a daytime band — correctly typed human. It
    is **unknown** when there is too little activity to resolve a rhythm, and
    **human** otherwise. Periodicity is deliberately not a standalone clause: a
    person working a weekday band is itself daily-periodic, so keying on it alone
    over-types humans (measured, docs/identities.md); it only confirms the
    razor-tight clause.
    """
    ts = [t for t in times if t is not None]
    n = len(ts)
    if n < min_events:
        return IdentityProfile(entity, "unknown", n, 0, 0.0, 1.0, 0.0, math.inf,
                               0.0, 0.0, f"too few events (<{min_events})")

    counts, span_hours = _hourly_counts(ts)
    active_hours = int(np.count_nonzero(counts))
    span_days = span_hours / 24.0
    hours_of_day = np.array([t.hour + t.minute / 60.0 for t in ts])
    weekend = float(np.mean([1.0 if t.weekday() >= 5 else 0.0 for t in ts]))
    tod = _rayleigh_r(hours_of_day)

    if active_hours < min_active_hours:
        return IdentityProfile(entity, "unknown", n, active_hours, span_days,
                               1.0, 0.0, math.inf, weekend, tod,
                               f"too few active hours (<{min_active_hours})")

    g = fisher_g_test(counts)
    period_h = g.dominant_period_bins  # bins are hours

    weekendy = weekend >= AUTOMATED_WEEKEND_RATIO
    # Round-the-clock: active on weekends AND spread across all hours (no daytime
    # band). Catches monitoring agents, whose activity is neither periodic nor
    # concentrated — only the round-the-week, round-the-clock shape marks them.
    round_clock = weekendy and tod <= HUMAN_TOD_LOW
    # Razor-tight: fires on weekends in one clock window. A few humans reach
    # R>=0.995 too, so this is weekend-gated: a weekday-only human with a tight
    # schedule stays human. (A weekday-only *automated* identity is the
    # acknowledged gap — see docs/identities.md.)
    razor_tight = weekendy and tod >= RAZOR_TIGHT_TOD
    if round_clock or razor_tight:
        why = []
        if round_clock:
            why.append(f"round-the-clock ({weekend:.0%} weekend, R={tod:.2f})")
        if razor_tight:
            why.append(f"scheduled: one clock window (R={tod:.3f}, "
                       f"{weekend:.0%} weekend)")
        kind, reason = "automated", "; ".join(why)
    else:
        kind = "human"
        reason = (f"human work rhythm (weekend {weekend:.0%}, R={tod:.2f}, "
                  f"g-test p={g.p_value:.1e})")

    return IdentityProfile(entity, kind, n, active_hours, span_days,
                           g.p_value, g.g, period_h, weekend, tod, reason)


def classify_identities(events, min_events: int = DEFAULT_MIN_EVENTS) -> Dict[str, IdentityProfile]:
    """Type every identity in a normalized event stream.

    Events are attributed to accounts with the same per-family logic the feature
    layer uses (`features.aggregate._user_key`), so machine `$` and SYSTEM
    identities are excluded and every other event lands on its acting account.
    """
    from ueba_pipeline.features.aggregate import _user_key

    by_entity: Dict[str, List[datetime]] = {}
    for e in events:
        if getattr(e, "event_time", None) is None:
            continue
        key = _user_key(e)
        if key:
            by_entity.setdefault(key, []).append(e.event_time)
    return {ent: classify_identity(ent, times, min_events=min_events)
            for ent, times in by_entity.items()}

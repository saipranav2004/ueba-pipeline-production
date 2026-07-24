"""Bayesian count-anomaly scoring — Gamma-Poisson posterior predictive.

WHAT THIS IS FOR
----------------
Some abuse creates no new relationship and no new time-of-day: an identity uses
exactly the access it always has, at the hours it always works, and only the
*rate* is wrong. Insider data staging is that shape, and so is a service account
that keeps its schedule but does ten times its usual work. The discriminating
quantity there is a **count**, and counts need a count model.

RESEARCH BASIS, AND WHY NOT ROBUST Z-SCORES
-------------------------------------------
Heard, Weston, Platanioti & Hand ("Bayesian anomaly detection methods for social
networks", 2010) score exactly this quantity: counts of activity per entity per
period are modelled as Poisson, a conjugate Gamma prior is placed on the rate, and
a signal is raised when an observed count falls far into the tail of the **Bayesian
posterior predictive distribution**. For a Gamma-Poisson pair that predictive is
**Negative Binomial** in closed form, so the tail probability is exact and cheap.

This is the same modus operandi the rest of the engine already follows -- Turcotte,
Moore, Heard & McPhall (IEEE ISI 2016) score LANL activity by "the upper tail
probability of y_ui given the posterior expected rate" -- so a count score arrives
as a p-value and composes with everything else.

An earlier volume attempt in this codebase used a robust z-score (median and MAD)
and was abandoned. That was the wrong estimator for this data, independently of
how it was integrated:

  * **MAD collapses on sparse counts.** Most identity-hours contain zero or one
    event, so the median absolute deviation is frequently exactly 0, and every
    non-median observation becomes infinitely anomalous. A count model has no such
    degeneracy.
  * **Counts are not symmetric.** A z-score assumes a symmetric spread around a
    centre; Poisson counts are skewed and their variance is tied to their mean, so
    a fixed spread misstates significance at both ends.
  * **It cannot stream.** Median and MAD need the sample (or an approximation of
    it) retained; the Gamma-Poisson posterior needs only two sufficient statistics
    per entity -- the total count and the number of periods -- so updates are O(1)
    and the state is bounded, matching the rest of this engine.

THE MODEL
---------
For an entity with prior ``Gamma(a0, b0)`` on its per-period rate, having been
observed for ``n`` periods carrying ``S`` events in total, the posterior is
``Gamma(a0 + S, b0 + n)`` and the predictive for the next period's count ``Y`` is

    Y ~ NegBinomial(r = a0 + S,  p = (b0 + n) / (b0 + n + 1))

The anomaly score is the upper tail ``P(Y >= y_obs)``, floored away from zero so a
single extreme observation cannot dominate a downstream combination with infinite
weight. Because the prior is proper, a cold-start entity with no history is not
scored as extreme -- with no evidence, nothing is surprising, which is the same
property the relational detector's Dirichlet back-off has.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, Tuple

# Weak, proper Gamma prior on an entity's per-period rate. Mean 1 event per
# period with variance 1: uninformative enough that a few periods of real history
# dominate it, proper enough that a brand-new entity is not scored as extreme.
# Deliberately not tuned against the benchmark, exactly as the Dirichlet
# concentration in the relational detector is not.
DEFAULT_PRIOR_SHAPE = 1.0
DEFAULT_PRIOR_RATE = 1.0
# Periods of history required before an entity is scored at all. THIS is what
# makes cold start safe, and it is a gate rather than a prior choice on purpose.
# A proper Gamma prior is still a *claim* about the rate -- Gamma(1,1) asserts
# roughly one event per period -- so an entity with no history would have any
# busy period judged against that assertion and scored as extreme. Measured
# directly: a count of 50 with zero history scores p ~ 1e-15 under the prior
# alone. Refusing to score until there is evidence is the honest behaviour, and
# it matches how every other component here treats cold start.
DEFAULT_MIN_PERIODS = 5
# Smallest tail probability reported: small enough to preserve ordering deep in
# the tail (two very different extremes must stay rankable), non-zero so a single
# observation cannot carry infinite weight into a downstream combination.
MIN_TAIL_P = 1e-300


def negbinom_upper_tail(y: float, r: float, p: float) -> float:
    """``P(Y >= y)`` for ``Y ~ NegBinomial(r, p)``, computed in log space.

    Uses the regularised incomplete beta identity
    ``P(Y >= y) = I_{1-p}(y, r)``, which is exact and stable for the large ``r``
    a busy entity produces. Falls back to direct summation only for tiny ``y``.
    """
    if y <= 0:
        return 1.0
    try:                                    # scipy is a declared dependency
        from scipy.special import betainc
        return float(max(min(betainc(y, r, 1.0 - p), 1.0), MIN_TAIL_P))
    except Exception:
        # Direct summation of the pmf below y, in log space. Only reached if the
        # optional import fails; correctness matters more than speed here.
        log_p, log_q = math.log(p), math.log1p(-p)
        cdf = 0.0
        term = r * log_p                    # pmf at 0
        cdf += math.exp(term)
        for k in range(1, int(y)):
            term += math.log(k + r - 1) - math.log(k) + log_q
            cdf += math.exp(term)
        return float(max(min(1.0 - cdf, 1.0), MIN_TAIL_P))


@dataclass
class GammaPoissonCounts:
    """Per-entity count baselines with an exact predictive tail.

    State is two floats per entity -- total events and periods observed -- so the
    memory is O(entities) and every update is O(1). ``tail`` is pure: it never
    mutates state, matching the engine's contract that scoring is reproducible.
    """

    prior_shape: float = DEFAULT_PRIOR_SHAPE
    prior_rate: float = DEFAULT_PRIOR_RATE
    min_periods: int = DEFAULT_MIN_PERIODS
    _total: Dict[str, float] = field(default_factory=dict)
    _periods: Dict[str, float] = field(default_factory=dict)

    def observe(self, entity: str, count: float) -> None:
        """Fold one period's count for ``entity`` into its baseline."""
        self._total[entity] = self._total.get(entity, 0.0) + float(count)
        self._periods[entity] = self._periods.get(entity, 0.0) + 1.0

    def posterior(self, entity: str) -> Tuple[float, float]:
        """``(r, p)`` of the current posterior predictive for ``entity``."""
        r = self.prior_shape + self._total.get(entity, 0.0)
        denom = self.prior_rate + self._periods.get(entity, 0.0)
        return r, denom / (denom + 1.0)

    def tail(self, entity: str, count: float) -> float:
        """``P(Y >= count)`` under ``entity``'s posterior predictive.

        Returns 1.0 (not anomalous) until the entity has ``min_periods`` of
        history: with no evidence about an entity's rate, any judgement would be a
        judgement about the prior rather than about the entity.
        """
        if self._periods.get(entity, 0.0) < self.min_periods:
            return 1.0
        r, p = self.posterior(entity)
        return negbinom_upper_tail(float(count), r, p)

    def is_covered(self, entity: str) -> bool:
        """Whether this entity has enough history to be scored at all."""
        return self._periods.get(entity, 0.0) >= self.min_periods

    def surprise(self, entity: str, count: float) -> float:
        """``-log P(Y >= count)`` in nats, for ranking alongside edge surprise."""
        return -math.log(max(self.tail(entity, count), MIN_TAIL_P))

    def periods(self, entity: str) -> float:
        return self._periods.get(entity, 0.0)

    def mean_rate(self, entity: str) -> float:
        """Posterior mean rate, for analyst-facing context ('usually ~3/hour')."""
        r, p = self.posterior(entity)
        return r * (1.0 - p) / p

"""Periodicity detection for identity typing — Fisher's exact g-test.

WHAT THIS IS FOR
----------------
A non-human identity (service account, managed service account, scheduled job,
monitoring agent) is statistically distinct from a person: its activity is
**periodic** — a backup at 02:30 every night, an agent polling on a fixed
interval — with low variance and no weekends off. A person's activity is diffuse:
a work-hour band that drifts, with absences and weekend gaps. Typing an identity
by this behaviour (not by a `svc_*` name) is the first thing an NHI-aware pipeline
needs, and it is data-source-agnostic: it reads only event *timestamps*.

This module implements the primitive the type decision rests on — a test for a
dominant periodic component in an identity's activity — following Heard,
Rubin-Delanchy & Lawson, "Filtering automated polling traffic in computer network
flow data" (IEEE JISIC 2014), which uses **Fisher's g-test** to decide whether an
arrival sequence carries an automated (periodic) component. The g-test itself is
Fisher, "Tests of significance in harmonic analysis" (Proc. R. Soc. A, 1929).

THE TEST
--------
For a real, regularly-sampled series x_1..x_N (here: event counts in equal time
bins), the Schuster periodogram at the Fourier frequencies f_k = k/N is

    I(f_k) = (1/N) | sum_t x_t exp(-2*pi*i*f_k*t) |**2 ,   k = 1..m,  m = floor(N/2)

The g-statistic is the share of total periodogram power carried by its single
largest ordinate:

    g = max_k I(f_k) / sum_k I(f_k)

Under the null of Gaussian white noise (no periodicity) the power is spread evenly
across frequencies, so g is small; a single dominant period concentrates the power
and drives g toward 1. Fisher derived the *exact* upper-tail probability:

    P(g > g0) = sum_{k=1}^{b} (-1)^(k-1) * C(m, k) * (1 - k*g0)^(m-1),
                b = floor(1/g0)

which is the p-value: small p ⇒ a significant periodic component. A sharply
periodic service account produces a p many orders of magnitude below a person's,
which is exactly the separation identity typing needs (measured in
docs/identities.md).

SCOPE AND LIMITS
----------------
- The g-test finds the *single most dominant* Fourier period. It is a test for
  periodicity, not a full spectral model; a series with two comparable periods
  dilutes g. For identity typing that is acceptable — an automated identity is
  dominated by one cadence.
- The null is Gaussian white noise. Event-count series are non-negative and often
  sparse, so the p-value is an approximation, not an exact false-positive rate;
  typing therefore uses it as a *strong, ranked* statistic backed by measurement
  on real streams, not as a calibrated alpha. This mirrors the engine's stance on
  every p-value it computes (see models/pvalue.py).
- Resolving a period needs several cycles of observation. Daily periodicity is
  well resolved over a couple of weeks; weekly periodicity is marginal there and
  the caller is expected to say so.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np


@dataclass(frozen=True)
class PeriodogramResult:
    """Outcome of a Fisher g-test on one count series."""

    g: float                    # share of power in the largest ordinate, in [0, 1]
    p_value: float              # P(g > g_obs) under the white-noise null
    dominant_period_bins: float # period (in bins) of the largest ordinate; inf if none
    n_ordinates: int            # m, the number of Fourier frequencies tested
    n_bins: int                 # N, the length of the count series


def fisher_g_pvalue(g: float, m: int) -> float:
    """Exact upper-tail p-value of Fisher's g-statistic (Fisher 1929).

    ``P(g > g0) = sum_{k=1}^{floor(1/g0)} (-1)^(k-1) C(m,k) (1 - k*g0)^(m-1)``.

    The alternating sum is evaluated directly. For a *significant* result g0 is
    well above 1/m, so ``b = floor(1/g0)`` is small and the sum is short and
    stable; the first term ``m*(1-g0)^(m-1)`` already dominates. For a
    non-significant g0 near 1/m the tail probability is ~1 and the many alternating
    terms cancel toward 1; the sum is capped so an enormous ``b`` cannot blow up,
    since the answer there is simply "not periodic".
    """
    if m <= 0:
        return 1.0
    # Clamp just inside (0, 1): g == 1 (all power in one ordinate) would give an
    # exact 0 that is awkward for downstream -log transforms, and g <= 0 is the
    # no-power degenerate case.
    g = float(min(max(g, 0.0), 1.0 - 1e-15))
    if g <= 0.0:
        return 1.0
    b = math.floor(1.0 / g)
    # Cap the number of terms: beyond this, g0 is so small the tail probability is
    # ~1 and the cost is not worth paying (identity typing only reads the small-p
    # tail). For k <= b, k*g <= 1, so every (1 - k*g) base is non-negative.
    b = min(b, 1000)
    total = 0.0
    for k in range(1, b + 1):
        term = math.comb(m, k) * (1.0 - k * g) ** (m - 1)
        total += -term if (k % 2 == 0) else term
    # Floor at a tiny epsilon: a near-perfect period yields an astronomically small
    # p, and typing only needs "definitely periodic", not the exact magnitude.
    return float(min(max(total, 1e-300), 1.0))


def _periodogram(x: np.ndarray) -> np.ndarray:
    """Schuster periodogram ordinates at the Fourier frequencies k=1..floor(N/2).

    The series is mean-centred first, so the zero-frequency (DC) term — which just
    encodes the overall activity level, not any period — is removed and never
    competes for the maximum.
    """
    x = np.asarray(x, dtype=np.float64)
    x = x - x.mean()
    n = x.size
    m = n // 2
    if m < 1:
        return np.zeros(0)
    fft = np.fft.rfft(x)                 # indices 0..n//2
    power = (np.abs(fft) ** 2) / n
    return power[1:m + 1]                # drop DC; keep k=1..m


def fisher_g_test(counts) -> PeriodogramResult:
    """Fisher's g-test for a dominant periodic component in a count series.

    ``counts`` is a regularly-binned activity series (events per equal-width time
    bin). Returns the g-statistic, its exact p-value, and the period (in bins) of
    the dominant Fourier frequency. A degenerate series (fewer than 4 bins, or no
    variation) is reported as non-periodic (``g=0, p=1``) rather than raising, so
    callers can type sparse identities as "unknown" uniformly.
    """
    x = np.asarray(counts, dtype=np.float64).ravel()
    n = x.size
    ordinates = _periodogram(x)
    m = ordinates.size
    total = float(ordinates.sum())
    if m < 2 or total <= 0.0:
        return PeriodogramResult(g=0.0, p_value=1.0, dominant_period_bins=math.inf,
                                 n_ordinates=m, n_bins=n)
    k_max = int(np.argmax(ordinates)) + 1          # Fourier index of the peak (1-based)
    g = float(ordinates[k_max - 1] / total)
    p = fisher_g_pvalue(g, m)
    period = n / k_max                             # bins per cycle at the peak frequency
    return PeriodogramResult(g=g, p_value=p, dominant_period_bins=period,
                             n_ordinates=m, n_bins=n)

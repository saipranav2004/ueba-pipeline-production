"""The indexed predictive p-value must equal the scan it replaces.

``freeze()`` builds a prefix-sum index so the Heard & Rubin-Delanchy eq. (2) sum
does not scan the whole marginal on every event. That is an optimisation of a
statistic on the detection path, so the only acceptable standard is that it
computes the same number -- and in particular that it never disagrees about
``p == 1.0``, which the engine reads as "no evidence". A disagreement there
invents or suppresses a detection.

Verified separately over all 55,933 edges of four fitted estates (265 to 2,036
employees): zero p==1.0 disagreements, worst relative difference 4.1e-16, i.e.
two units in the last place. These tests pin that property in the suite.
"""
from __future__ import annotations

import random

from ueba_pipeline.graph.auth_graph_anomaly import (
    AuthGraphAnomalyDetector,
    AuthGraphConfig,
)

# Two units in the last place. The paths sum in different orders -- the scan uses
# math.fsum over sorted contributions, the index adds a prefix sum to a short
# tail -- so bit-identity is not available and is not the requirement.
TOLERANCE = 1e-14


def _populated(seed: int, n_src: int, n_dst: int) -> AuthGraphAnomalyDetector:
    """A detector with a deliberately lopsided edge distribution.

    Both extremes matter: a view with many destinations per source, and one with
    a single destination shared by every source. The second is where the index's
    assumption (that a principal's neighbourhood is small) does not hold, so it is
    exactly the case most likely to expose a discrepancy.
    """
    rng = random.Random(seed)
    d = AuthGraphAnomalyDetector(AuthGraphConfig())
    for i in range(n_src):
        for _ in range(rng.randint(1, 4)):
            dst = f"d{rng.randrange(n_dst)}"
            d._absorb("v", (f"s{i}", dst), score=0.0)
    return d


def _all_edges(d):
    return sorted(d._edges["v"])


def test_indexed_path_matches_the_scan_on_a_wide_view():
    d = _populated(seed=1, n_src=60, n_dst=40)
    edges = _all_edges(d)
    scan = [d.predictive_pvalue("v", e) for e in edges]
    d.freeze()
    fast = [d.predictive_pvalue("v", e) for e in edges]
    for e, a, b in zip(edges, scan, fast, strict=True):
        assert (a == 1.0) == (b == 1.0), f"{e}: p==1.0 disagreement {a} vs {b}"
        assert abs(a - b) <= TOLERANCE * max(abs(a), 1e-12), f"{e}: {a} vs {b}"


def test_indexed_path_matches_the_scan_when_one_destination_is_shared():
    """The `proc_access` shape: a single destination every principal reaches.

    Here the reverse conditional's neighbourhood IS the estate, so the index falls
    back to enumerating it. The answer must still agree.
    """
    d = _populated(seed=2, n_src=80, n_dst=1)
    edges = _all_edges(d)
    scan = [d.predictive_pvalue("v", e) for e in edges]
    d.freeze()
    fast = [d.predictive_pvalue("v", e) for e in edges]
    for e, a, b in zip(edges, scan, fast, strict=True):
        assert (a == 1.0) == (b == 1.0), f"{e}: p==1.0 disagreement {a} vs {b}"
        assert abs(a - b) <= TOLERANCE * max(abs(a), 1e-12), f"{e}: {a} vs {b}"


def test_unseen_edges_agree_too():
    """Scoring mostly asks about edges the model has NOT seen -- the novel ones."""
    d = _populated(seed=3, n_src=50, n_dst=30)
    probes = [(f"s{i}", f"d{j}") for i in range(0, 50, 7) for j in range(0, 30, 5)]
    probes = [e for e in probes if e not in d._edges["v"]]
    assert probes, "fixture no longer produces unseen edges"
    scan = [d.predictive_pvalue("v", e) for e in probes]
    d.freeze()
    fast = [d.predictive_pvalue("v", e) for e in probes]
    for e, a, b in zip(probes, scan, fast, strict=True):
        assert (a == 1.0) == (b == 1.0), f"{e}: p==1.0 disagreement {a} vs {b}"
        assert abs(a - b) <= TOLERANCE * max(abs(a), 1e-12), f"{e}: {a} vs {b}"


def test_absorbing_invalidates_the_index():
    """Streaming mutates the model, so a stale index must not survive an absorb.

    A stale index would score against a marginal the detector no longer has --
    silently, and in the direction of under-reporting.
    """
    d = _populated(seed=4, n_src=30, n_dst=20)
    d.freeze()
    assert d._pvalue_index, "freeze() built no index"
    d._absorb("v", ("s0", "d0"), score=0.0)
    assert not d._pvalue_index, "index survived an absorb"
    assert not d._adj

    # And the scan path still answers after invalidation.
    assert 0.0 < d.predictive_pvalue("v", ("s0", "d0")) <= 1.0


def test_freeze_is_idempotent_and_reflects_later_absorbs():
    d = _populated(seed=5, n_src=25, n_dst=15)
    d.freeze()
    before = d.predictive_pvalue("v", ("s0", "d0"))
    d.freeze()
    assert d.predictive_pvalue("v", ("s0", "d0")) == before

    for _ in range(20):
        d._absorb("v", ("s0", "d0"), score=0.0)
    d.freeze()
    after = d.predictive_pvalue("v", ("s0", "d0"))
    # Repeating an edge makes it more probable, so it cannot become more surprising.
    assert after >= before

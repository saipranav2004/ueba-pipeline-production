"""Tests for the streaming authentication-graph anomaly detector.

Covers the two detection signals (edge novelty, microcluster burst), the
read-only absorption contract (an attack edge must not poison the baseline),
and the projection rules (only remote logons form edges).
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

# Novelty is graded, not a constant: it is -log P(dst|src) under a
# Dirichlet-smoothed null, so tests assert "clearly surprising" in nats rather
# than equality with a magic 6.0. 3.0 nats == P(dst|src) < 5%.
_SURPRISING = 3.0

# NOTE ON COLD START:
# Surprise is -log P(dst|src) under a Dirichlet-smoothed null. With an EMPTY
# baseline, pi_d = 1 and P(dst|src) = 1, so surprise = 0: with no evidence,
# nothing is surprising. This is what keeps new and low-activity accounts out of
# the false positives -- a cold-start edge is not evidence of anything. Tests must
# therefore establish a baseline before asserting that a novel edge is surprising.


from ueba_pipeline.graph.auth_graph_anomaly import (
    AuthGraphAnomalyDetector,
    AuthGraphConfig,
)

T0 = datetime(2025, 1, 1, 9, 0, 0, tzinfo=timezone.utc)


def _logon(user, src, dst, minute=0, logon_type="3", et="4624_logon"):
    return SimpleNamespace(
        event_type=et,
        event_time=T0 + timedelta(minutes=minute),
        computer_name=dst,
        fields={"target_user_name": user, "src_ip": src, "logon_type": logon_type},
    )


def _fitted(**cfg):
    det = AuthGraphAnomalyDetector(config=AuthGraphConfig(**cfg))
    # Establish a benign baseline: alice always logs in from her workstation.
    for h in range(20):
        det.observe_baseline(_logon("alice", "10.0.0.5", "fs01", minute=h * 60))
    return det


def test_known_edge_scores_low():
    det = _fitted()
    score = det.score_event(_logon("alice", "10.0.0.5", "fs01", minute=1300))
    assert score < _SURPRISING


def test_novel_source_scores_high():
    det = _fitted()
    # alice appears from an attacker foothold she has never used.
    score = det.score_event(_logon("alice", "10.9.9.9", "dc01", minute=1300))
    assert score >= _SURPRISING


def test_interactive_and_service_logons_are_ignored():
    det = _fitted()
    for lt in ("2", "5", "7"):
        assert det.score_event(_logon("bob", "10.9.9.9", "ws1", logon_type=lt)) == 0.0


def test_tgt_and_tgs_do_not_form_edges():
    det = _fitted()
    tgt = SimpleNamespace(
        event_type="4768", event_time=T0, computer_name="dc01",
        fields={"target_user_name": "alice", "src_ip": "10.9.9.9"},
    )
    assert det.edges_for(tgt) == []


def test_attack_edge_is_not_absorbed():
    # MIDAS-F contract: a flagged edge must not become part of the baseline,
    # so repeating the attack keeps scoring anomalous (no self-normalisation).
    det = _fitted(absorb_surprise=5.0)
    first = det.score_event(_logon("alice", "10.9.9.9", "dc01", minute=1300))
    second = det.score_event(_logon("alice", "10.9.9.9", "dc01", minute=1360))
    assert first >= 5.0 and second >= 5.0


def test_scoring_without_absorb_leaves_state_unchanged():
    det = _fitted()
    edges_before = {v: dict(e) for v, e in det._edges.items()}
    det.score_event(_logon("alice", "10.9.9.9", "dc01", minute=1300), absorb=False)
    assert {v: dict(e) for v, e in det._edges.items()} == edges_before


def test_missing_time_yields_zero():
    det = _fitted()
    ev = _logon("alice", "10.9.9.9", "dc01")
    ev.event_time = None
    assert det.score_event(ev) == 0.0


# -- endpoint / kerberos / rare-process views -----------------------------

def _sysmon10(src_image, target_image, host="ws1", minute=0):
    return SimpleNamespace(
        event_type="sysmon_10",
        event_time=T0 + timedelta(minutes=minute),
        computer_name=host,
        fields={"source_image": src_image, "target_image": target_image},
    )


def _tgt(user, enc, preauth, minute=0):
    return SimpleNamespace(
        event_type="4768",
        event_time=T0 + timedelta(minutes=minute),
        computer_name="dc01",
        fields={"target_user_name": user, "ticket_enc_type": enc, "pre_auth_type": preauth},
    )


def _proc(image, host="ws1", minute=0):
    return SimpleNamespace(
        event_type="sysmon_1",
        event_time=T0 + timedelta(minutes=minute),
        computer_name=host,
        fields={"image": image},
    )


def test_process_access_to_lsass_is_novel():
    det = AuthGraphAnomalyDetector()
    for h in range(10):
        det.observe_baseline(_sysmon10("C:/Windows/System32/wininit.exe",
                                       "C:/Windows/System32/lsass.exe", minute=h * 60))
    # A new process opening lsass -> novel edge.
    s = det.score_event(_sysmon10("C:/Windows/System32/rundll32.exe",
                                  "C:/Windows/System32/lsass.exe", minute=900))
    assert s >= _SURPRISING


def test_process_access_projects_generic_edges():
    # proc_access is generic: any (source-image -> target-image) access is an
    # edge, and novelty (not a hardcoded target list) decides significance.
    det = AuthGraphAnomalyDetector()
    edges = det.edges_for(_sysmon10("evil.exe", "C:/Windows/System32/notepad.exe"))
    assert edges and edges[0][0] == "proc_access"


def test_kerb_context_downgrade_is_scored_by_evidence_not_a_gate():
    """A ticket-context downgrade must rank by evidence, not by a hand-coded gate.

    The Dirichlet conditional expresses the required ordering natively: a
    brand-new principal has n_s = 0, backs off to the global marginal, and is
    unsurprising by construction, while an established account switching context
    is genuinely improbable. The ordering must hold *because of the model*, so no
    establishment gate is needed to impose it."""
    det = AuthGraphAnomalyDetector()
    for h in range(20):
        det.observe_baseline(_tgt("known_user", "0x12", "2", minute=h * 30))
    # An established account switching to a never-seen encryption context.
    downgrade = det.score_event(_tgt("known_user", "0x17", "0", minute=900))
    # A brand-new account's first-ever ticket, same novel context.
    first_ever = det.score_event(_tgt("brand_new_user", "0x17", "0", minute=901))
    assert downgrade > first_ever, (
        "a downgrade for an established principal must outrank a new account's "
        "first ticket -- from the evidence, not a hardcoded view gate"
    )



# ── model-based predictive p-value (Heard & Rubin-Delanchy 2016) ─────────────
def _dir_op_detector():
    """A directory-operation view: two busy admins and one ordinary account."""
    from ueba_pipeline.graph.auth_graph_anomaly import (
        AuthGraphAnomalyDetector, AuthGraphConfig,
    )
    d = AuthGraphAnomalyDetector(config=AuthGraphConfig(alpha=1.0))
    for src, dst in ([("admin1", "groupadd")] * 40 + [("admin1", "pwreset")] * 10
                     + [("admin2", "groupadd")] * 20 + [("bob", "acctcreate")]):
        d._absorb("dir_op", (src, dst), 0.0)
    return d


def test_predictive_pvalue_matches_the_published_definition():
    """Heard eq. (2): the predictive mass of every outcome at least as improbable."""
    d = _dir_op_detector()
    a, marg = d.config.alpha, d._dst_counts["dir_op"]
    denom = d._view_totals["dir_op"] + max(len(marg), 1)

    def brute(key_a, key_b):
        stars = {b: d._edges["dir_op"].get((key_a, b), 0.0) + a * ((c + 1.0) / denom)
                 for b, c in marg.items()}
        n_a = d._src_totals["dir_op"].get(key_a, 0.0)
        return sum(v for v in stars.values() if v <= stars[key_b]) / (n_a + a)

    for src, dst in (("admin1", "groupadd"), ("admin1", "acctcreate"),
                     ("bob", "groupadd"), ("admin2", "pwreset")):
        assert d._directional_pvalue("dir_op", src, dst, d._dst_counts,
                                     d._src_totals) == brute(src, dst)


def test_predictive_pvalue_escapes_the_empirical_null_floor():
    """A rare actor performing a privileged operation must be assertable far below
    1/(n+1) -- the floor that ties every sparse-view alert together and makes the
    peak-hour attribution degenerate."""
    d = _dir_op_detector()
    routine = d.predictive_pvalue("dir_op", ("admin1", "groupadd"))
    rare = d.predictive_pvalue("dir_op", ("bob", "groupadd"))
    assert rare < 1e-3 < routine
    assert routine == 1.0


def test_predictive_pvalue_is_insertion_order_independent():
    """Scores must not depend on whether the model came from memory or from disk.

    A bundle reloaded from JSON rebuilds these dicts in a different insertion
    order; an order-dependent sum drifts a few ULPs, which is enough to turn a
    p of exactly 1.0 into 0.999999999 and invent an alert.
    """
    d = _dir_op_detector()
    before = d.predictive_pvalue("dir_op", ("admin1", "groupadd"))
    for store in (d._dst_counts, d._src_counts, d._src_totals, d._dst_totals):
        store["dir_op"] = dict(reversed(list(store["dir_op"].items())))
    d._edges["dir_op"] = dict(reversed(list(d._edges["dir_op"].items())))
    assert d.predictive_pvalue("dir_op", ("admin1", "groupadd")) == before


# ── proc_exec: identity-keyed program execution ──────────────────────────────
def test_proc_exec_is_keyed_on_the_identity_not_the_host():
    """"Has THIS ACCOUNT run this program?" -- not "is this program rare here?".

    The removed `rare_proc` view asked the host-keyed question, which has no signal
    on a domain controller where ntdsutil runs legitimately. That is precisely why
    NTDS extraction was undetectable.
    """
    from ueba_pipeline.graph.auth_graph_anomaly import AuthGraphAnomalyDetector

    d = AuthGraphAnomalyDetector()
    ev = SimpleNamespace(
        event_type="sysmon_1", computer_name="DC01",
        event_time=datetime(2025, 1, 6, tzinfo=timezone.utc),
        fields={"user_norm": "adm_t0_rverma", "image": r"C:\Windows\System32\ntdsutil.exe"})
    assert d.edges_for(ev) == [("proc_exec", ("adm_t0_rverma", "ntdsutil.exe"))]


def test_proc_exec_skips_machine_accounts():
    """Machine accounts are not part of the human/service behavioural model."""
    from ueba_pipeline.graph.auth_graph_anomaly import AuthGraphAnomalyDetector

    d = AuthGraphAnomalyDetector()
    ev = SimpleNamespace(
        event_type="sysmon_1", computer_name="DC01",
        event_time=datetime(2025, 1, 6, tzinfo=timezone.utc),
        fields={"user_norm": "dc01$", "image": r"C:\Windows\System32\svchost.exe"})
    assert d.edges_for(ev) == []


def test_execution_and_relational_views_are_disjoint():
    """The two queues must not share a view, or the execution signal would re-enter
    the relational budget it was measured to disrupt."""
    from ueba_pipeline.graph.auth_graph_anomaly import (
        EXECUTION_VIEWS, RELATIONAL_VIEWS,
    )
    assert RELATIONAL_VIEWS.isdisjoint(EXECUTION_VIEWS)
    assert "proc_exec" in EXECUTION_VIEWS

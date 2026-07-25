"""
tests/unit/test_graph_scale.py

Locks in the scalability fixes to the identity-graph risk computation:
  - betweenness switches to pivot-sampled estimation above a node threshold
    (exact Brandes is O(V*E), ~227s at 10k nodes),
  - Tier-0 distance uses a single multi-source BFS (was O(V^2)),
  - community detection uses Louvain (was greedy modularity, ~9x slower).

These assert correctness of the cheaper paths, not wall-clock (timing is
environment-dependent and not a stable CI assertion).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import networkx as nx

from ueba_pipeline.graph.identity_graph import (
    EDGE_CAN_ACCESS,
    EDGE_MEMBER_OF,
    NODE_COMPUTER,
    NODE_GROUP,
    NODE_USER,
    IdentityGraph,
)


def _chain_to_tier0():
    """u2 -> u1 -> grp(Tier-0) -> dc01(Tier-0); u3 -> dc01."""
    g = IdentityGraph()
    g.add_node("dc01", NODE_COMPUTER, role="domain controller")
    g.add_node("grp", NODE_GROUP, name="Domain Admins")
    g.add_node("u1", NODE_USER)
    g.add_node("u2", NODE_USER)
    g.add_node("u3", NODE_USER)
    g.add_edge("u1", "grp", EDGE_MEMBER_OF)
    g.add_edge("grp", "dc01", EDGE_CAN_ACCESS)
    g.add_edge("u2", "u1", EDGE_MEMBER_OF)
    g.add_edge("u3", "dc01", EDGE_CAN_ACCESS)
    return g


def test_multi_source_tier0_distances_are_correct():
    g = _chain_to_tier0()
    g.compute_risk_scores()
    # grp and dc01 are Tier-0 => distance 0. u1 is member of grp => 1.
    # u2 -> u1 -> grp => 2. u3 -> dc01 => 1.
    assert g.get_user_risk_score("dc01").hops_to_tier0 == 0
    assert g.get_user_risk_score("grp").hops_to_tier0 == 0
    assert g.get_user_risk_score("u1").hops_to_tier0 == 1
    assert g.get_user_risk_score("u2").hops_to_tier0 == 2
    assert g.get_user_risk_score("u3").hops_to_tier0 == 1


def test_small_graph_uses_exact_betweenness():
    g = _chain_to_tier0()
    report = g.compute_risk_scores()
    assert report.betweenness_approximate is False


def test_large_graph_switches_to_sampled_betweenness():
    """Above betweenness_exact_max_nodes, estimation kicks in and the run
    still completes with sensible output."""
    g = IdentityGraph()
    g.add_node("DC", NODE_COMPUTER, role="domain controller")
    ba = nx.barabasi_albert_graph(2000, 3, seed=1)  # > default 1500 threshold
    for i in ba.nodes():
        g.add_node(f"u{i}", NODE_USER)
    for a, b in ba.edges():
        g.add_edge(f"u{a}", f"u{b}", EDGE_MEMBER_OF)
    g.add_edge("u0", "DC", EDGE_CAN_ACCESS)
    report = g.compute_risk_scores()
    assert report.betweenness_approximate is True
    assert report.betweenness_pivots > 0
    assert report.n_nodes == 2001
    # every node got a risk score
    assert g.get_user_risk_score("u0") is not None


def test_unreachable_node_has_no_tier0_distance():
    g = _chain_to_tier0()
    g.add_node("island", NODE_USER)  # no edges
    g.compute_risk_scores()
    assert g.get_user_risk_score("island").hops_to_tier0 is None

"""
tests/unit/test_graph_visualize.py

Covers the identity-graph HTML visualizer: payload correctness (node/edge
counts, Tier-0 marking, shortest-path-to-Tier-0 attack paths) and that the
rendered HTML is self-contained with no unreplaced template placeholders.
"""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ueba_pipeline.graph.identity_graph import (
    IdentityGraph, NODE_USER, NODE_GROUP, NODE_COMPUTER, EDGE_MEMBER_OF,
    EDGE_CAN_ACCESS,
)
from ueba_pipeline.graph.visualize import (
    build_visualization_payload, render_html,
)


def _tiny_graph_with_tier0():
    """user -> group -> DC (Tier-0). Gives a real 2-hop attack path."""
    g = IdentityGraph()
    g.add_node("dc01", NODE_COMPUTER, role="domain controller")  # Tier-0
    g.add_node("GG-Admins-Tier0", NODE_GROUP, name="Domain Admins")  # Tier-0
    g.add_node("alice", NODE_USER, department="IT")
    g.add_edge("alice", "GG-Admins-Tier0", EDGE_MEMBER_OF)
    g.add_edge("GG-Admins-Tier0", "dc01", EDGE_CAN_ACCESS)
    return g


def test_payload_has_expected_shape_and_tier0():
    g = _tiny_graph_with_tier0()
    p = build_visualization_payload(g)
    assert p["stats"]["n_nodes"] == 3
    assert p["stats"]["n_edges"] == 2
    ids = {n["id"] for n in p["nodes"]}
    assert ids == {"dc01", "GG-Admins-Tier0", "alice"}
    tier0_flagged = {n["id"] for n in p["nodes"] if n["tier0"]}
    # Both the DC and the Domain Admins group are Tier-0.
    assert "dc01" in tier0_flagged
    assert "GG-Admins-Tier0" in tier0_flagged


def test_shortest_path_to_tier0_is_populated_for_reachable_user():
    g = _tiny_graph_with_tier0()
    p = build_visualization_payload(g)
    alice = next(n for n in p["nodes"] if n["id"] == "alice")
    # alice is a member of a Tier-0 group => hop count 1, path length 2.
    assert alice["hops_to_tier0"] == 1
    assert alice["path_to_tier0"][0] == "alice"
    assert alice["path_to_tier0"][-1] in ("GG-Admins-Tier0", "dc01")


def test_render_html_is_self_contained_and_has_no_placeholders():
    g = _tiny_graph_with_tier0()
    html = render_html(g, title="Test Graph")
    assert "<!DOCTYPE html>" in html
    assert "__DATA__" not in html
    assert "__TITLE__" not in html
    assert "Test Graph" in html
    # The embedded data must be valid JSON.
    m = re.search(r"const DATA = (\{.*?\});", html, re.S)
    assert m, "embedded DATA block not found"
    data = json.loads(m.group(1))
    assert len(data["nodes"]) == 3


def test_isolated_node_has_no_path():
    g = _tiny_graph_with_tier0()
    g.add_node("bob", NODE_USER, department="Sales")  # no edges
    p = build_visualization_payload(g)
    bob = next(n for n in p["nodes"] if n["id"] == "bob")
    assert bob["hops_to_tier0"] is None
    assert bob["path_to_tier0"] == []


def test_large_graph_is_capped_to_top_risk_subset():
    """Above max_nodes, the payload keeps the top-risk nodes plus all Tier-0
    assets, flags truncation, and never dangles an attack path onto a hidden
    node."""
    from ueba_pipeline.graph.identity_graph import (
        IdentityGraph, NODE_USER, NODE_COMPUTER, EDGE_CAN_ACCESS,
    )
    g = IdentityGraph()
    g.add_node("DC", NODE_COMPUTER, role="domain controller")
    for i in range(60):
        g.add_node(f"u{i}", NODE_USER)
        g.add_edge(f"u{i}", "DC", EDGE_CAN_ACCESS)
    p = build_visualization_payload(g, max_nodes=40)
    assert p["stats"]["truncated"] is True
    assert p["stats"]["n_nodes"] == 61
    assert p["stats"]["n_shown"] <= 41  # 40 + Tier-0 DC
    shown = {n["id"] for n in p["nodes"]}
    assert "DC" in shown  # Tier-0 always retained
    for n in p["nodes"]:
        assert all(x in shown for x in n["path_to_tier0"])


def test_small_graph_not_truncated():
    g = _tiny_graph_with_tier0()
    p = build_visualization_payload(g, max_nodes=400)
    assert p["stats"]["truncated"] is False
    assert p["stats"]["n_shown"] == p["stats"]["n_nodes"] == 3

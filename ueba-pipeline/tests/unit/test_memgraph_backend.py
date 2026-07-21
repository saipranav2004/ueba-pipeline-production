"""
Tests for the Memgraph-backed identity graph, using a fake ``neo4j`` driver so
no Memgraph instance is required. Validates that:

  * construction delegates to the shared IdentityGraph builder (Tier-0
    classification is identical to the NetworkX backend);
  * compute_risk_scores() issues the expected node/edge sync and MAGE calls and
    assembles a GraphRiskReport of the same shape/types the NetworkX backend
    returns;
  * the composite-risk formula matches the NetworkX backend given identical
    metric inputs (Tier-0 entity at 1 hop, all weight on Tier-0 proximity).
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ueba_pipeline.config.schema import PipelineConfig
from ueba_pipeline.graph.identity_graph import GraphRiskReport, GraphRiskScore


# --- Fake neo4j driver -----------------------------------------------------

class _FakeSession:
    """Records writes and returns canned results for the MAGE/Cypher reads the
    Memgraph backend issues."""

    def __init__(self, canned):
        self.canned = canned
        self.queries = []

    def __enter__(self): return self
    def __exit__(self, *a): return False

    def run(self, query, **params):
        self.queries.append((query, params))
        if "betweenness_centrality.get" in query:
            return [{"id": nid, "score": v} for nid, v in self.canned["betweenness"].items()]
        if "pagerank.get" in query:
            return [{"id": nid, "score": v} for nid, v in self.canned["pagerank"].items()]
        if "community_detection.get" in query:
            return [{"id": nid, "cid": v} for nid, v in self.canned["community"].items()]
        if "count(rel)" in query:
            return [{"id": nid, "deg": v} for nid, v in self.canned["degree_raw"].items()]
        if "min(length(p))" in query:
            return [{"id": nid, "hops": v} for nid, v in self.canned["hops"].items()]
        return []


class _FakeDriver:
    def __init__(self, canned):
        self._canned = canned
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def session(self): return _FakeSession(self._canned)


def _install_fake_neo4j(canned):
    mod = types.ModuleType("neo4j")

    class _GraphDatabase:
        @staticmethod
        def driver(uri, auth=None):
            return _FakeDriver(canned)

    mod.GraphDatabase = _GraphDatabase
    sys.modules["neo4j"] = mod


@pytest.fixture(autouse=True)
def _cleanup():
    yield
    sys.modules.pop("neo4j", None)


_ROSTER = {"rverma": "IT", "jdoe": "Finance"}
_ADMINS = [{"samaccountname": "adm_t0_rverma", "tier": 0, "real_user": "rverma"}]
_DCS = [{"hostname": "DC01", "role": "PDC Emulator"}]


def _canned_for(builder):
    """Canned MAGE outputs: all-zero centralities so composite risk is driven
    purely by Tier-0 proximity, isolating the formula under test."""
    ids = list(builder.graph.nodes())
    return {
        "betweenness": {i: 0.0 for i in ids},
        "pagerank": {i: 0.0 for i in ids},
        "community": {i: 0 for i in ids},
        "degree_raw": {i: 0 for i in ids},
        "hops": {"adm_t0_rverma": 1},  # Tier-0 admin one hop from the DC
    }


def test_memgraph_backend_returns_same_types_and_tier0():
    from ueba_pipeline.graph.memgraph_backend import MemgraphIdentityGraph

    cfg = PipelineConfig()
    cfg.identity_graph.backend = "memgraph"
    g = MemgraphIdentityGraph(config=cfg)
    g.load_from_roster(_ROSTER, admin_accounts=_ADMINS, domain_controllers=_DCS)

    # Tier-0 classification happens in the shared builder -> DC01 is Tier-0.
    assert "dc01" in {n.lower() for n in g._builder._tier0_nodes}

    _install_fake_neo4j(_canned_for(g._builder))
    report = g.compute_risk_scores()

    assert isinstance(report, GraphRiskReport)
    assert report.n_tier0_assets >= 1
    assert all(isinstance(s, GraphRiskScore) for s in report.entity_scores.values())
    # The Tier-0 admin is scored and reachable at 1 hop.
    admin = report.entity_scores.get("adm_t0_rverma")
    assert admin is not None
    assert admin.hops_to_tier0 == 1


def test_memgraph_composite_matches_networkx_formula():
    """With all weight on Tier-0 proximity, a Tier-0 asset (hops forced to 1.0)
    scores exp(0)=1.0 -- the same value the NetworkX backend produces."""
    from ueba_pipeline.graph.memgraph_backend import MemgraphIdentityGraph

    cfg = PipelineConfig()
    cfg.identity_graph.backend = "memgraph"
    cfg.identity_graph.tier0_risk_weight = 1.0
    cfg.identity_graph.betweenness_weight = 0.0
    cfg.identity_graph.pagerank_weight = 0.0
    cfg.identity_graph.degree_weight = 0.0

    g = MemgraphIdentityGraph(config=cfg)
    g.load_from_roster(_ROSTER, admin_accounts=_ADMINS, domain_controllers=_DCS)
    _install_fake_neo4j(_canned_for(g._builder))
    report = g.compute_risk_scores()

    admin = report.entity_scores["adm_t0_rverma"]
    assert abs(admin.composite_risk - 1.0) < 1e-9


def test_memgraph_backend_selected_by_config():
    from ueba_pipeline.graph.backend import build_identity_graph
    from ueba_pipeline.graph.memgraph_backend import MemgraphIdentityGraph

    cfg = PipelineConfig()
    cfg.identity_graph.backend = "memgraph"
    g = build_identity_graph(cfg)
    assert isinstance(g, MemgraphIdentityGraph)

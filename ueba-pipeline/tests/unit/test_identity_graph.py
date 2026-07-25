"""
Tests for the identity-graph Tier-0 classification and attack-path modelling.

Validates that the graph reflects the AD Administrative Tier Model (Microsoft,
"Securing privileged access"; SpecterOps Tier Zero Table): domain controllers,
backup, and SCCM servers are Tier-0 assets, Tier-0 admin accounts sit one hop
from Tier-0, and configured risk weights are honoured.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

nx = pytest.importorskip("networkx")

from ueba_pipeline.graph.identity_graph import IdentityGraph

_ROSTER = {"rverma": "IT", "asharma": "IT", "jdoe": "Finance"}
_ADMINS = [
    {"samaccountname": "adm_t0_rverma", "tier": 0, "real_user": "rverma"},
    {"samaccountname": "adm_t1_asharma", "tier": 1, "real_user": "asharma"},
]
_SVC = [{"samaccountname": "svc_backup", "server": "BACKUP01"}]
_SERVERS = [{"hostname": "BACKUP01", "role": "BackupServer"},
            {"hostname": "FS01", "role": "FileServer"}]
_DCS = [{"hostname": "DC01", "role": "PDC Emulator"},
        {"hostname": "DC02", "role": "Additional DC"}]


def _graph() -> IdentityGraph:
    g = IdentityGraph()
    g.load_from_roster(_ROSTER, admin_accounts=_ADMINS, service_accounts=_SVC,
                       servers=_SERVERS, domain_controllers=_DCS)
    return g


def test_domain_controllers_and_backup_sccm_are_tier0():
    g = _graph()
    t0 = {n.lower() for n in g._tier0_nodes}
    assert "dc01" in t0 and "dc02" in t0, "domain controllers must be Tier-0"
    assert "backup01" in t0, "backup server must be Tier-0 (holds DC backups)"
    # A plain file server is NOT Tier-0.
    assert "fs01" not in t0


def test_tier0_admin_is_one_hop_from_tier0():
    g = _graph()
    report = g.compute_risk_scores()
    t0_admin = report.entity_scores.get("adm_t0_rverma")
    assert t0_admin is not None
    assert t0_admin.hops_to_tier0 == 1, "Tier-0 admin should be adjacent to Tier-0"


def test_configured_weights_are_used(monkeypatch):
    """Composite risk must respond to configured weights, not hardcoded ones."""
    from ueba_pipeline.config.schema import PipelineConfig
    cfg = PipelineConfig()
    cfg.identity_graph.tier0_risk_weight = 1.0
    cfg.identity_graph.betweenness_weight = 0.0
    cfg.identity_graph.pagerank_weight = 0.0
    cfg.identity_graph.degree_weight = 0.0
    g = IdentityGraph(config=cfg)
    g.load_from_roster(_ROSTER, admin_accounts=_ADMINS, service_accounts=_SVC,
                       servers=_SERVERS, domain_controllers=_DCS)
    report = g.compute_risk_scores()
    # With all weight on Tier-0 proximity, a 1-hop entity scores exp(0)=1.0.
    t0_admin = report.entity_scores["adm_t0_rverma"]
    assert abs(t0_admin.composite_risk - 1.0) < 1e-9

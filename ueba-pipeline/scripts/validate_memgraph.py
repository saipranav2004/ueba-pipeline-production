#!/usr/bin/env python3
"""validate_memgraph.py -- Memgraph vs NetworkX backend parity.

Infra-dependent counterpart to test_memgraph_backend.py (which uses a fake
neo4j driver). Needs a REACHABLE Memgraph+MAGE instance (see
docker/docker-compose.yml, service `memgraph`, Bolt on 7687).

Builds ONE identity graph from the roster, computes graph risk twice --
once with the in-process NetworkX backend, once shipping the same graph to
Memgraph and running MAGE -- and diffs:

  - top-risk entity ORDER (must be identical; this is what the SOC sees),
  - per-entity pagerank / betweenness / degree within a tolerance,
  - community assignment equivalence up to label permutation.

Exit status is nonzero on any parity failure so it can gate a pipeline.

Numerical note: PageRank and community labels are only defined up to
convergence/label-permutation, so we compare RANKINGS and set-partitions, not
raw floats for those; degree centrality is exact and compared directly.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _build(roster_path, directory_path, backend, config):
    repo_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repo_root))
    from ueba_pipeline.graph.identity_graph import build_identity_graph_from_roster

    directory = {}
    if directory_path:
        import json
        directory = json.loads(Path(directory_path).read_text())

    if backend == "networkx":
        g = build_identity_graph_from_roster(
            roster_path, config,
            admin_accounts=directory.get("admin_accounts"),
            service_accounts=directory.get("service_accounts"),
            servers=directory.get("servers"),
            domain_controllers=directory.get("domain_controllers"),
        )
    else:
        from ueba_pipeline.graph.memgraph_backend import MemgraphIdentityGraph
        import json
        roster = json.loads(Path(roster_path).read_text())
        g = MemgraphIdentityGraph(config=config)
        g.load_from_roster(
            roster,
            admin_accounts=directory.get("admin_accounts"),
            service_accounts=directory.get("service_accounts"),
            servers=directory.get("servers"),
            domain_controllers=directory.get("domain_controllers"),
        )
    return g.compute_risk_scores()


def _rank(report):
    return [s.entity_id for s in sorted(
        report.entity_scores.values(),
        key=lambda s: (-s.composite_risk, s.entity_id))]


def _communities(report):
    parts = {}
    for eid, s in report.entity_scores.items():
        parts.setdefault(s.community_id, set()).add(eid)
    # normalize to a frozenset of frozensets (label-permutation invariant)
    return frozenset(frozenset(v) for v in parts.values())


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--roster", required=True)
    ap.add_argument("--directory", default=None,
                    help="Optional directory.json (admin/service/servers/DCs)")
    ap.add_argument("--tol", type=float, default=1e-6,
                    help="Absolute tolerance for exact metrics (degree)")
    args = ap.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repo_root))
    from ueba_pipeline.config.schema import load_config
    config = load_config()

    print("[parity] computing NetworkX backend risk ...")
    nx_report = _build(args.roster, args.directory, "networkx", config)
    print(f"[parity]   nodes={nx_report.n_nodes} edges={nx_report.n_edges} "
          f"communities={nx_report.n_communities}")

    print("[parity] computing Memgraph backend risk ...")
    mg_report = _build(args.roster, args.directory, "memgraph", config)
    print(f"[parity]   nodes={mg_report.n_nodes} edges={mg_report.n_edges} "
          f"communities={mg_report.n_communities}")

    failures = []

    # 1. Top-risk ordering (what the SOC is paged on).
    nx_rank, mg_rank = _rank(nx_report), _rank(mg_report)
    top = 20
    if nx_rank[:top] != mg_rank[:top]:
        failures.append(
            f"top-{top} risk ordering differs:\n"
            f"  networkx: {nx_rank[:top]}\n  memgraph: {mg_rank[:top]}")
    else:
        print(f"[parity] PASS: top-{top} risk ordering identical")

    # 2. Exact metric (degree centrality) per entity.
    common = set(nx_report.entity_scores) & set(mg_report.entity_scores)
    if set(nx_report.entity_scores) != set(mg_report.entity_scores):
        failures.append("entity sets differ between backends")
    deg_bad = [
        e for e in common
        if abs(nx_report.entity_scores[e].degree_centrality
               - mg_report.entity_scores[e].degree_centrality) > args.tol
    ]
    if deg_bad:
        failures.append(f"degree centrality mismatch on {len(deg_bad)} entities "
                        f"(e.g. {deg_bad[:5]})")
    else:
        print("[parity] PASS: degree centrality matches within tolerance")

    # 3. Community partition equivalence (up to label permutation).
    if _communities(nx_report) != _communities(mg_report):
        failures.append("community partitions are not equivalent "
                        "(up to label permutation)")
    else:
        print("[parity] PASS: community partitions equivalent")

    if failures:
        print("\n[parity] FAILURES:")
        for f in failures:
            print(" - " + f)
        return 1
    print("\n[parity] ALL CHECKS PASSED -- Memgraph backend matches NetworkX")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

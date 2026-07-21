"""
graph/memgraph_backend.py -- Memgraph-backed identity graph for scale-out.

When the identity graph grows past the range where single-threaded NetworkX
global metrics finish inside a retrain window (betweenness is O(V*E)), the
structural analytics move to Memgraph: an in-memory C++ graph engine that speaks
Bolt + Cypher and ships MAGE (Memgraph Advanced Graph Extensions) with
parallel implementations of betweenness_centrality, pagerank, and
community_detection. Memgraph is accessed through the official ``neo4j`` Python
driver -- Memgraph implements the Bolt protocol, so the same driver targets
either engine and the pipeline is not locked to a Memgraph-specific client
(per Memgraph's own Python client guidance).

This adapter mirrors the public surface of graph/identity_graph.IdentityGraph
(add_node, add_edge, load_from_roster, compute_risk_scores, get_user_risk_score)
and returns the identical GraphRiskScore / GraphRiskReport types, so callers are
backend-agnostic. It reuses IdentityGraph purely as the graph BUILDER (the
roster/tier/Tier-0 construction logic is identical regardless of backend), then
writes the assembled graph to Memgraph and runs the heavy global metrics there.
The composite-risk formula is the same one the NetworkX backend applies, so the
two backends produce comparable scores; only the compute engine differs.

Requires the ``neo4j`` driver and a reachable Memgraph instance (with MAGE).
Both are optional -- the driver is imported lazily and a clear error is raised
if it or the instance is absent, so the NetworkX default has no new dependency.
"""

from __future__ import annotations

import math
from typing import Optional

from ueba_pipeline.config.schema import PipelineConfig
from ueba_pipeline.graph.identity_graph import (
    IdentityGraph, GraphRiskReport, GraphRiskScore,
    NODE_USER, NODE_GROUP, NODE_COMPUTER,
)


class MemgraphIdentityGraph:
    """Identity graph whose global structural metrics are computed in Memgraph.

    Construction (nodes, edges, Tier-0 classification) is delegated to an
    in-memory IdentityGraph builder so tier/Tier-0 logic stays in one place;
    compute_risk_scores() ships that graph to Memgraph and runs MAGE.
    """

    def __init__(self, config: Optional[PipelineConfig] = None):
        self.config = config
        gcfg = getattr(config, "identity_graph", None) if config else None
        self._uri = getattr(gcfg, "memgraph_uri", "bolt://localhost:7687") if gcfg else "bolt://localhost:7687"
        self._user = getattr(gcfg, "memgraph_user", "") if gcfg else ""
        pw = getattr(gcfg, "memgraph_password", "") if gcfg else ""
        # memgraph_password is a SecretStr in config; unwrap for the driver.
        self._password = pw.get_secret_value() if hasattr(pw, "get_secret_value") else pw
        # The builder holds construction state; we do not compute metrics on it.
        self._builder = IdentityGraph(config=config)

    # -- construction (delegated to the builder) --------------------------

    def add_node(self, node_id: str, node_type: str, **attrs) -> None:
        self._builder.add_node(node_id, node_type, **attrs)

    def add_edge(self, source: str, target: str, edge_type: str, **attrs) -> None:
        self._builder.add_edge(source, target, edge_type, **attrs)

    def load_from_roster(self, *args, **kwargs) -> None:
        self._builder.load_from_roster(*args, **kwargs)

    def load_from_canonical_events(self, events: list) -> None:
        self._builder.load_from_canonical_events(events)

    # -- compute (delegated to Memgraph + MAGE) ---------------------------

    def _driver(self):
        try:
            from neo4j import GraphDatabase
        except ImportError as exc:  # pragma: no cover - environment-dependent
            raise RuntimeError(
                "MemgraphIdentityGraph requires the 'neo4j' driver. "
                "Install with: pip install neo4j"
            ) from exc
        auth = (self._user, self._password) if self._user else None
        return GraphDatabase.driver(self._uri, auth=auth)

    def _sync_to_memgraph(self, session) -> None:
        """Replace the graph in Memgraph with the builder's current state.

        Uses parameterized UNWIND batch writes (one round-trip for all nodes,
        one for all edges) rather than per-element queries, so loading a
        thousands-of-node graph is a couple of network calls, not thousands.
        """
        g = self._builder.graph
        session.run("MATCH (n) DETACH DELETE n")  # fresh snapshot each retrain
        nodes = [
            {"id": n,
             "type": self._builder._node_types.get(n, "unknown"),
             "tier0": n in self._builder._tier0_nodes}
            for n in g.nodes()
        ]
        session.run(
            "UNWIND $rows AS row "
            "CREATE (e:Entity {id: row.id, type: row.type, tier0: row.tier0})",
            rows=nodes,
        )
        session.run("CREATE INDEX ON :Entity(id)")
        edges = [{"s": u, "t": v} for u, v in g.edges()]
        if edges:
            session.run(
                "UNWIND $rows AS row "
                "MATCH (a:Entity {id: row.s}), (b:Entity {id: row.t}) "
                "CREATE (a)-[:REL]->(b)",
                rows=edges,
            )

    def compute_risk_scores(self) -> GraphRiskReport:
        """Run global structural metrics in Memgraph via MAGE and assemble the
        same GraphRiskReport the NetworkX backend produces.

        MAGE procedures used:
          * betweenness_centrality.get()  -- parallel Brandes
          * pagerank.get()                -- parallel PageRank
          * community_detection.get()     -- Louvain
        Degree and shortest-path-to-Tier-0 are computed with plain Cypher.
        """
        g = self._builder.graph
        tier0 = self._builder._tier0_nodes
        node_types = self._builder._node_types

        with self._driver() as driver:
            with driver.session() as session:
                self._sync_to_memgraph(session)

                # Degree centrality (normalized by n-1, matching NetworkX).
                n = max(g.number_of_nodes(), 1)
                degree = {
                    r["id"]: (r["deg"] / (n - 1) if n > 1 else 0.0)
                    for r in session.run(
                        "MATCH (e:Entity) "
                        "OPTIONAL MATCH (e)-[rel:REL]-(:Entity) "
                        "RETURN e.id AS id, count(rel) AS deg")
                }
                betweenness = {
                    r["id"]: r["score"]
                    for r in session.run(
                        "CALL betweenness_centrality.get(TRUE, TRUE) "
                        "YIELD node, betweenness_centrality "
                        "RETURN node.id AS id, betweenness_centrality AS score")
                }
                pagerank = {
                    r["id"]: r["score"]
                    for r in session.run(
                        "CALL pagerank.get() YIELD node, rank "
                        "RETURN node.id AS id, rank AS score")
                }
                community = {
                    r["id"]: r["cid"]
                    for r in session.run(
                        "CALL community_detection.get() "
                        "YIELD node, community_id "
                        "RETURN node.id AS id, community_id AS cid")
                }
                # Shortest hops to any Tier-0 asset (undirected), per entity.
                hops = self._compute_hops_to_tier0(session, tier0)

        return self._assemble_report(
            g, node_types, tier0, degree, betweenness, pagerank, community, hops
        )

    def _compute_hops_to_tier0(self, session, tier0) -> dict:
        if not tier0:
            return {}
        # Single BFS query per entity is expensive; instead compute the min
        # distance from each entity to the Tier-0 set with a variable-length
        # undirected match, capped to keep it bounded on large graphs.
        result = session.run(
            "MATCH (e:Entity), (t:Entity {tier0: TRUE}) "
            "WHERE e.id <> t.id "
            "MATCH p = (e)-[:REL*1..6]-(t) "
            "RETURN e.id AS id, min(length(p)) AS hops",
        )
        return {r["id"]: r["hops"] for r in result}

    def _assemble_report(self, g, node_types, tier0, degree, betweenness,
                         pagerank, community, hops) -> GraphRiskReport:
        gcfg = getattr(self.config, "identity_graph", None) if self.config else None
        w_tier0 = gcfg.tier0_risk_weight if gcfg else 0.40
        w_between = gcfg.betweenness_weight if gcfg else 0.25
        w_pr = gcfg.pagerank_weight if gcfg else 0.20
        w_degree = gcfg.degree_weight if gcfg else 0.15
        max_pr = max(pagerank.values()) if pagerank else 1.0
        max_pr = max_pr or 1.0

        scores: dict = {}
        for node in g.nodes():
            hop = hops.get(node)
            # Same decay as the NetworkX backend: half-life of one hop, so
            # hop=1 -> 1.0, hop=2 -> 0.5, ... (exp(-ln2 * (hop-1))).
            hops_score = math.exp(-0.693 * (hop - 1)) if hop is not None else 0.0
            if node in tier0:
                hops_score = 1.0
            pr_norm = pagerank.get(node, 0.0) / max_pr
            composite = (
                w_tier0 * hops_score
                + w_between * betweenness.get(node, 0.0)
                + w_pr * pr_norm
                + w_degree * degree.get(node, 0.0)
            )
            scores[node] = GraphRiskScore(
                entity_id=node,
                entity_type=node_types.get(node, "unknown"),
                degree_centrality=degree.get(node, 0.0),
                betweenness_centrality=betweenness.get(node, 0.0),
                pagerank=pagerank.get(node, 0.0),
                hops_to_tier0=hop,
                community_id=community.get(node),
                composite_risk=composite,
            )

        entity_scores = {
            nid: s for nid, s in scores.items()
            if node_types.get(nid) in (NODE_USER, "service_account")
        }
        risks = [s.composite_risk for s in entity_scores.values()]
        report = GraphRiskReport(
            n_nodes=g.number_of_nodes(),
            n_edges=g.number_of_edges(),
            n_tier0_assets=len(tier0),
            n_communities=len(set(community.values())) if community else 0,
            mean_risk=(sum(risks) / len(risks)) if risks else 0.0,
            max_risk=max(risks) if risks else 0.0,
            entity_scores=entity_scores,
        )
        report.high_risk_entities = sorted(
            entity_scores.values(), key=lambda s: -s.composite_risk
        )[:20]
        return report

    def get_user_risk_score(self, user: str) -> Optional[GraphRiskScore]:
        report = self.compute_risk_scores()
        return report.entity_scores.get(user)

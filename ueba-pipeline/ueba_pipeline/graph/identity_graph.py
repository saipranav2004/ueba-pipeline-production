"""Structural risk scoring for the identity graph -- ANALYST TOOLING, NOT DETECTION.

RESPONSIBILITY
--------------
Given directory state (a roster, optionally plus canonical events), build the
identity graph -- users, groups, computers, service accounts -- and score each
entity by its *structural* position: how much damage its compromise would enable.
This answers a question behaviour cannot: an account that has done nothing
unusual may still be one hop from a Tier-0 asset.

The only consumer is the ``graph-viz`` CLI command, which renders the graph and
its scores to standalone HTML for an analyst to read.
That is the whole of it.

THIS MODULE IS NOT PART OF DETECTION
------------------------------------
It contributes nothing to any alert. No code path multiplies a behavioural score
by a graph risk. If structural risk is ever fused into scoring, the honest way in
is as another calibrated p-value through models/pvalue.py, benchmarked as its own
track in evaluation/honest_eval.py, and kept only if it earns its place -- the
standard every detection component is held to. This is the natural home for the
Tier-0 directory context a privileged-group-change detection needs.

SCORING
-------
Composite risk is a weighted sum of four normalised terms, weights from
``IdentityGraphConfig`` and validated to sum to 1.0:

  * hops to the nearest Tier-0 asset -- blast radius (weight 0.40)
  * betweenness centrality -- choke points that bridge otherwise separate groups
    (0.25); above ``betweenness_exact_max_nodes`` this switches to pivot sampling
    (Brandes & Pich 2007), because exact Brandes is O(V*E) and unusable past ~10k
    nodes
  * PageRank -- influence disproportionate to group membership (0.20)
  * degree centrality -- breadth of direct access (0.15)

Greedy modularity (Clauset-Newman-Moore) also assigns a community id, surfaced
for visual grouping only; it does not feed the composite.

PASS --directory, OR THE SCORE IS NOT WHAT IT CLAIMS. Measured: with
`graph-viz --roster X` alone, the roster carries no Tier-0 designation, so
`n_tier0_assets = 0` and the largest-weighted term (0.40) is constant zero for
every entity -- the composite silently degrades to a 0.25/0.20/0.15 centrality
blend that no longer sums to 1, and reads as a blast-radius ranking while being
nothing of the kind. The simulator now emits `directory.json` for exactly this
(285 nodes / 0 Tier-0 -> 311 nodes / 5 Tier-0); supply the equivalent for a real
estate.

These weights are asserted, not fitted. That is defensible here in a way it was
not for the detection constants: nothing downstream consumes them but a
visualisation, so a wrong weight misorders a display rather than silently killing
an alert path. Do not promote them into scoring without calibrating them first.

BACKEND
-------
NetworkX, in-memory. Structural metrics are recomputed on a rolling snapshot
rather than per event, so the backend only has to finish inside the retrain
window: at this project's scale (a few hundred to a few thousand nodes) the full
five-metric pass completes in well under a second on one core.

Analysis patterns follow BloodHound Enterprise (shortest path to Tier-0, exposure
scoring) and Cartography (declarative node/edge schema), implemented over
NetworkX rather than Neo4j.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field

# NetworkX is a heavy dependency — guard the import and provide a clear
# error message rather than a cryptic ImportError at runtime.
try:
    import networkx as nx
except ImportError:
    nx = None  # type: ignore[assignment]

from ueba_pipeline.config.schema import PipelineConfig

# Node type constants
NODE_USER = "user"
NODE_GROUP = "group"
NODE_COMPUTER = "computer"
NODE_SERVICE_ACCOUNT = "service_account"
NODE_APPLICATION = "application"

# Edge type constants
EDGE_MEMBER_OF = "member_of"
EDGE_MANAGES = "manages"
EDGE_OWNS = "owns"
EDGE_DELEGATED_TO = "delegated_to"
EDGE_CAN_ACCESS = "can_access"

# Tier-0 asset identifiers (high-value targets). Control of any Tier-0 asset is
# equivalent to control of the domain, so these anchor the attack-path /
# blast-radius analysis. Per Microsoft's AD Administrative Tier Model and the
# SpecterOps Tier Zero Table (github.com/SpecterOps/TierZeroTable): Tier 0 is
# not only the privileged directory groups but also the assets that grant direct
# OR INDIRECT control of the directory -- domain controllers, backup
# infrastructure (a DC backup contains all password hashes), systems-management
# servers that can push code to DCs (SCCM), and PKI/ADCS. Classifying these as
# Tier 0 is what lets shortest-path-to-Tier-0 reflect real domain-takeover paths
# rather than only group membership.
TIER0_ASSET_TYPES = frozenset({NODE_GROUP})
TIER0_GROUP_NAMES = frozenset({
    "domain admins", "enterprise admins", "schema admins",
    "administrators", "account operators", "backup operators",
    "server operators", "print operators",
    "group policy creator owners",
})
# Server roles that constitute Tier-0 by indirect control of the directory.
TIER0_SERVER_ROLES = frozenset({
    "pdc emulator", "additional dc", "domain controller",
    "backupserver", "sccm", "adcs", "pki", "adfs",
})


@dataclass
class GraphRiskScore:
    """Per-entity graph risk score with component breakdown."""
    entity_id: str
    entity_type: str
    degree_centrality: float = 0.0
    betweenness_centrality: float = 0.0
    pagerank: float = 0.0
    hops_to_tier0: int | None = None  # None = unreachable
    community_id: int | None = None
    composite_risk: float = 0.0  # 0-1 normalized

    def to_dict(self) -> dict:
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "degree_centrality": self.degree_centrality,
            "betweenness_centrality": self.betweenness_centrality,
            "pagerank": self.pagerank,
            "hops_to_tier0": self.hops_to_tier0,
            "community_id": self.community_id,
            "composite_risk": self.composite_risk,
        }


@dataclass
class GraphRiskReport:
    """Aggregate risk metrics for the entire identity graph."""
    n_nodes: int = 0
    n_edges: int = 0
    n_tier0_assets: int = 0
    n_communities: int = 0
    betweenness_approximate: bool = False
    betweenness_pivots: int = 0
    mean_risk: float = 0.0
    max_risk: float = 0.0
    high_risk_entities: list[GraphRiskScore] = field(default_factory=list)
    entity_scores: dict[str, GraphRiskScore] = field(default_factory=dict)


class IdentityGraph:
    """Builds and analyzes an identity/access graph for structural risk scoring.

    The graph is built from directory *state* via ``load_from_roster``: a roster
    (user -> department) plus optional admin accounts, service accounts, servers
    and domain controllers. Real deployments load the same shape from AD / LDAP /
    IDP directory APIs; the simulator emits it as ``directory.json`` / ``roster.json``.

    It is deliberately NOT built from the live event stream. Structural risk is a
    property of the directory (who can reach a Tier-0 asset), so it is recomputed
    on a rolling directory snapshot, not per event -- see the module docstring.
    Each node carries metadata (type, department, tier level) used for tier-based
    risk weighting and visual grouping.
    """

    def __init__(self, config: PipelineConfig | None = None):
        if nx is None:
            raise ImportError(
                "NetworkX is required for graph-based structural risk scoring. "
                "Install it: pip install networkx. This module provides the "
                "identity graph layer that complements behavioral "
                "detection with structural risk analysis."
            )
        self.config = config
        self.graph = nx.DiGraph()
        self._tier0_nodes: set[str] = set()
        self._node_types: dict[str, str] = {}

    def add_node(self, node_id: str, node_type: str, **attrs) -> None:
        """Add an entity node to the graph. Nodes are classified Tier-0 either
        by privileged group name or by server role (see TIER0_* sets)."""
        self.graph.add_node(node_id, node_type=node_type, **attrs)
        self._node_types[node_id] = node_type
        if node_type == NODE_GROUP and attrs.get("name", "").lower() in TIER0_GROUP_NAMES:
            self._tier0_nodes.add(node_id)
        if node_type == NODE_COMPUTER and attrs.get("role", "").lower() in TIER0_SERVER_ROLES:
            self._tier0_nodes.add(node_id)

    def add_edge(self, source: str, target: str, edge_type: str, **attrs) -> None:
        """Add a relationship edge. source acts on target (e.g. user → group = member_of)."""
        self.graph.add_edge(source, target, edge_type=edge_type, **attrs)

    def load_from_roster(self, roster: dict[str, str],
                         admin_accounts: list[dict] | None = None,
                         service_accounts: list[dict] | None = None,
                         servers: list[dict] | None = None,
                         domain_controllers: list[dict] | None = None) -> None:
        """Load an identity/access graph from roster data.

        The graph models the AD Administrative Tier Model (Microsoft, "Securing
        privileged access"): department groups for horizontal structure, tiered
        admin groups (T0/T1/T2) for privilege, service accounts bound to the
        servers they run on, and domain controllers / Tier-0 servers as the
        crown-jewel targets that shortest-path-to-Tier-0 measures blast radius
        against. Real deployments load the same shape from AD/LDAP/IDP APIs;
        this roster path is the simulator/bootstrap source.
        """
        # Domain controllers first -- they are the canonical Tier-0 assets, so
        # they must exist before admin/tier edges are drawn toward them.
        if domain_controllers:
            for dc in domain_controllers:
                host = dc.get("hostname", "").lower()
                if host:
                    self.add_node(host, NODE_COMPUTER, role=dc.get("role", "domain controller"),
                                  fqdn=dc.get("fqdn", ""))

        # Add user nodes
        for username, department in roster.items():
            self.add_node(username, NODE_USER, department=department)

        # Add department group nodes and member_of edges
        departments = set(roster.values())
        for dept in departments:
            group_id = f"GG-Dept-{dept}"
            self.add_node(group_id, NODE_GROUP, name=dept)
            for username, dept_name in roster.items():
                if dept_name == dept:
                    self.add_edge(username, group_id, EDGE_MEMBER_OF)

        # Add admin account relationships (AD Administrative Tier Model).
        if admin_accounts:
            dc_hosts = [dc.get("hostname", "").lower()
                        for dc in (domain_controllers or []) if dc.get("hostname")]
            for acct in admin_accounts:
                sam = acct.get("samaccountname", "").lower()
                real_user = acct.get("real_user", "").lower()
                tier = acct.get("tier", 2)
                self.add_node(sam, NODE_USER, is_admin=True, tier=tier,
                              real_user=real_user)
                tier_group = f"GG-Admins-Tier{tier}"
                if tier_group not in self.graph:
                    tier_label = {0: "Domain Admins", 1: "Server Admins",
                                  2: "Helpdesk Admins"}.get(tier, "Unknown")
                    # Tier-0 admin group is itself a Tier-0 asset (its name is in
                    # TIER0_GROUP_NAMES via "domain admins").
                    self.add_node(tier_group, NODE_GROUP, name=tier_label)
                self.add_edge(sam, tier_group, EDGE_MEMBER_OF)
                # Tier-0 admins control the domain controllers -- the edge that
                # makes DCs reachable from the Tier-0 admin group in the attack
                # path (Rule: control of a Tier-0 asset = control of the domain).
                if tier == 0:
                    for dc_host in dc_hosts:
                        self.add_edge(tier_group, dc_host, EDGE_CAN_ACCESS,
                                      relationship="tier0_admin_of")
                # Credential-exposure edge: the admin account belongs to a real
                # user, so compromising that user's session can expose the admin
                # credential (the core credential-theft lateral-movement path).
                if real_user and real_user in roster:
                    self.add_edge(sam, real_user, EDGE_MANAGES,
                                  relationship="admin_account_of")

        # Add service account nodes and server relationships
        if service_accounts:
            for svc in service_accounts:
                sam = svc.get("samaccountname", "").lower()
                server = svc.get("server", "").lower()
                self.add_node(sam, NODE_SERVICE_ACCOUNT,
                              display=svc.get("display", ""))
                if server:
                    server_id = server
                    if server_id not in self.graph:
                        self.add_node(server_id, NODE_COMPUTER)
                    self.add_edge(sam, server_id, EDGE_CAN_ACCESS,
                                  relationship="runs_on")

        # Add server nodes
        if servers:
            for srv in servers:
                hostname = srv.get("hostname", "").lower()
                role = srv.get("role", "")
                self.add_node(hostname, NODE_COMPUTER, role=role,
                              fqdn=srv.get("fqdn", ""))

        # Add file server access relationships (department → share)
        file_servers = {"FS01", "FS02"}
        for fs in file_servers:
            if fs.lower() in self.graph:
                for dept in departments:
                    group_id = f"GG-Dept-{dept}"
                    if group_id in self.graph:
                        self.add_edge(group_id, fs.lower(), EDGE_CAN_ACCESS,
                                      relationship="file_share_read")

    def compute_risk_scores(self) -> GraphRiskReport:
        """Compute graph-based structural risk scores for all entities.

        Uses four complementary metrics:
        1. Degree centrality: many connections = broad access surface
        2. Betweenness centrality: bridge role = lateral movement enabler
        3. PageRank: influence disproportionate to direct connections
        4. Hops to Tier-0: shortest path to high-value target = blast radius
        """
        if len(self.graph) == 0:
            return GraphRiskReport()

        # Graph config (weights + scale thresholds), resolved once up front so
        # both the centrality computation and the per-node composite scoring
        # below can use it.
        gcfg = getattr(self.config, "identity_graph", None) if self.config else None

        report = GraphRiskReport(
            n_nodes=self.graph.number_of_nodes(),
            n_edges=self.graph.number_of_edges(),
        )

        # Convert to undirected for centrality metrics (relationships are
        # bidirectional in practice — if you're a member of a group, the
        # group "connects" to you)
        undirected = self.graph.to_undirected()

        # 1. Degree centrality
        try:
            degree_cent = nx.degree_centrality(undirected)
        except Exception:
            degree_cent = dict.fromkeys(self.graph, 0.0)

        # 2. Betweenness centrality — the graph-analytics scale bottleneck.
        # Exact Brandes betweenness is O(V*E): ~0.15s at 300 nodes but ~227s at
        # 10k nodes (measured), which is unusable in a streaming pipeline. Above
        # a threshold we switch to pivot-sampled betweenness (Brandes & Pich
        # 2007, "Centrality Estimation in Large Networks"): estimate from k
        # source pivots instead of all V. Measured ~50x faster at 10k nodes
        # (4.6s vs 227s) with rank-order preserved for the high-centrality nodes
        # that dominate risk. Exact is kept for small graphs where it is both
        # cheap and precise. Seed is fixed so scores are reproducible.
        n_nodes = undirected.number_of_nodes()
        exact_threshold = getattr(gcfg, "betweenness_exact_max_nodes", 1500) if gcfg else 1500
        pivot_count = getattr(gcfg, "betweenness_pivots", 300) if gcfg else 300
        try:
            if n_nodes > exact_threshold:
                k = min(pivot_count, n_nodes)
                between_cent = nx.betweenness_centrality(
                    undirected, k=k, normalized=True, seed=42
                )
                report.betweenness_approximate = True
                report.betweenness_pivots = k
            else:
                between_cent = nx.betweenness_centrality(undirected, normalized=True)
                report.betweenness_approximate = False
        except Exception:
            between_cent = dict.fromkeys(self.graph, 0.0)

        # 3. PageRank — treats the graph as a directed influence network
        try:
            pagerank = nx.pagerank(self.graph, alpha=0.85, max_iter=100)
        except Exception:
            pagerank = {n: 1.0 / max(self.graph.number_of_nodes(), 1)
                        for n in self.graph}

        # 4. Shortest path to Tier-0 assets.
        # A full BFS from every node to every Tier-0 node would be
        # O(V * k * (V+E)) — quadratic in V and the second scale bottleneck
        # after betweenness. Replaced with a SINGLE multi-source BFS: seed the
        # frontier with all Tier-0 nodes at once and let it expand outward, so
        # every node's distance to its NEAREST Tier-0 asset is found in one
        # O(V+E) pass. Identical results (nearest-Tier-0 hop count), linear cost.
        tier0_distances: dict[str, int | None] = dict.fromkeys(self.graph)
        if self._tier0_nodes:
            present_t0 = [t for t in self._tier0_nodes if t in undirected]
            if present_t0:
                # multi_source_dijkstra_path_length with default unit weights
                # is BFS seeded from every Tier-0 node simultaneously.
                dist_map = nx.multi_source_dijkstra_path_length(
                    undirected, set(present_t0)
                )
                for node, d in dist_map.items():
                    tier0_distances[node] = d

        # 5. Community detection.
        # greedy_modularity_communities (CNM) is O(V*log^2 V) in practice but
        # measured ~36s at 10k nodes — the dominant cost after the betweenness
        # fix. Louvain (Blondel et al. 2008) produces comparable modularity
        # partitions ~9x faster (measured 3.9s vs 36s at 10k) and is the modern
        # production standard. Use Louvain when available (NetworkX >= 3.0),
        # fall back to greedy modularity, then to "no communities".
        communities: dict[str, int] = {}
        try:
            try:
                from networkx.algorithms.community import louvain_communities
                comm_list = louvain_communities(undirected, seed=42)
            except ImportError:  # older NetworkX without Louvain
                from networkx.algorithms.community import greedy_modularity_communities
                comm_list = list(greedy_modularity_communities(undirected))
            report.n_communities = len(comm_list)
            for i, comm in enumerate(comm_list):
                for node in comm:
                    communities[node] = i
        except Exception:
            report.n_communities = 0

        report.n_tier0_assets = len(self._tier0_nodes)

        # Compute composite risk score for each entity
        scores: dict[str, GraphRiskScore] = {}
        max_pagerank = max(pagerank.values()) if pagerank else 1.0
        max_pagerank = max(max_pagerank, 1e-12)

        for node in self.graph:
            node_type = self._node_types.get(node, "unknown")
            gs = GraphRiskScore(
                entity_id=node,
                entity_type=node_type,
                degree_centrality=degree_cent.get(node, 0.0),
                betweenness_centrality=between_cent.get(node, 0.0),
                pagerank=pagerank.get(node, 0.0),
                hops_to_tier0=tier0_distances.get(node),
                community_id=communities.get(node),
            )

            # Composite risk: weighted combination of structural metrics
            # Weights chosen so that Tier-0 proximity dominates:
            # - hops_to_tier0: exponential decay (closer = much higher risk)
            # - betweenness: high betweenness = lateral movement enabler
            # - pagerank: influence metric
            # - degree: many connections = broad access surface
            hops_score = 0.0
            if gs.hops_to_tier0 is not None:
                # Exponential decay: 1 hop = 1.0, 2 hops = 0.5, 3 hops = 0.25, ...
                hops_score = math.exp(-0.693 * (gs.hops_to_tier0 - 1))  # ln(2)/1 per hop
                hops_score = min(hops_score, 1.0)

            pr_normalized = gs.pagerank / max_pagerank

            # Weighted composite (0-1 range). Weights come from
            # IdentityGraphConfig when a config is present (validated to sum to
            # 1.0), so the risk model is tunable without code changes; the
            # literals are the documented defaults, used only when no config is
            # supplied (e.g. ad-hoc analysis).
            w_tier0 = gcfg.tier0_risk_weight if gcfg else 0.40
            w_between = gcfg.betweenness_weight if gcfg else 0.25
            w_pr = gcfg.pagerank_weight if gcfg else 0.20
            w_degree = gcfg.degree_weight if gcfg else 0.15

            gs.composite_risk = (
                w_tier0 * hops_score +
                w_between * gs.betweenness_centrality +
                w_pr * pr_normalized +
                w_degree * gs.degree_centrality
            )

            # Clamp to [0, 1]
            gs.composite_risk = max(0.0, min(1.0, gs.composite_risk))
            scores[node] = gs

        report.entity_scores = scores
        report.mean_risk = (
            sum(s.composite_risk for s in scores.values()) / len(scores)
            if scores else 0.0
        )
        report.max_risk = (
            max(s.composite_risk for s in scores.values())
            if scores else 0.0
        )
        report.high_risk_entities = sorted(
            [s for s in scores.values() if s.entity_type in
             (NODE_USER, NODE_SERVICE_ACCOUNT)],
            key=lambda s: -s.composite_risk
        )[:20]

        return report

    def get_user_risk_score(self, user: str) -> GraphRiskScore | None:
        """Get the graph risk score for a specific user."""
        report = self.compute_risk_scores()
        return report.entity_scores.get(user)

def build_identity_graph_from_roster(
    roster_path: str,
    config: PipelineConfig | None = None,
    admin_accounts: list[dict] | None = None,
    service_accounts: list[dict] | None = None,
    servers: list[dict] | None = None,
    domain_controllers: list[dict] | None = None,
) -> IdentityGraph:
    """Build an IdentityGraph from roster data plus optional directory metadata.

    When admin_accounts / service_accounts / servers / domain_controllers are
    provided, the graph includes tiered admin groups, service-account-to-server
    edges, Tier-0 assets (DCs and Tier-0 server roles), and the admin-to-DC and
    admin-to-real-user edges that make shortest-path-to-Tier-0 reflect real
    domain-takeover paths. Without them, the graph is limited to users and
    department groups.
    """
    import json
    with open(roster_path) as f:
        roster = json.load(f)

    graph = IdentityGraph(config)
    graph.load_from_roster(
        roster,
        admin_accounts=admin_accounts,
        service_accounts=service_accounts,
        servers=servers,
        domain_controllers=domain_controllers,
    )
    return graph

"""
graph/visualize.py — Standalone HTML visualization of the identity graph.

Renders the IdentityGraph (users, groups, computers, service accounts and
their membership / access / delegation edges) as a self-contained interactive
HTML file: no server, no build step, opens in any browser. This exists so the
graph the pipeline reasons over —
can be reviewed by eye rather than only queried through Bolt.

What the view shows:
  - Node colour by entity type (user / group / computer / service account).
  - Tier-0 assets (domain controllers, Domain Admins, Tier-0 admin groups)
    drawn with a red ring: these are the crown-jewel targets that
    shortest-path-to-Tier-0 measures blast radius against.
  - Node size scaled by composite graph risk (degree / betweenness / PageRank /
    hops-to-Tier-0), so structurally dangerous entities are visually larger.
  - Clicking a node highlights its shortest path to the nearest Tier-0 asset —
    the concrete attack path an operator wants to see.

The layout runs in the browser (D3 force simulation) so this module only has to
emit data + a small template; it does no layout math in Python. D3 is loaded
from a CDN with an offline-safe fallback message if unavailable.

References:
  - Microsoft AD Administrative Tier Model ("Securing privileged access").
  - SpecterOps Tier Zero definition (github.com/SpecterOps/TierZeroTable) —
    the same Tier-0 set the risk module scores blast radius toward.
"""
from __future__ import annotations

import json

import networkx as nx

from ueba_pipeline.graph.identity_graph import IdentityGraph

# Distinct, colour-blind-friendly palette per node type. Kept deliberately
# small and legible rather than "pretty"; this is a review tool.
_TYPE_COLORS = {
    "user": "#4E79A7",
    "group": "#F28E2B",
    "computer": "#59A14F",
    "service_account": "#B07AA1",
    "application": "#EDC948",
    "unknown": "#9C9C9C",
}


def _shortest_path_to_tier0(
    graph: nx.Graph, tier0_nodes: list[str]
) -> dict[str, list[str]]:
    """For every node, the node list of its shortest path to the nearest
    Tier-0 asset (empty if unreachable). Uses the undirected projection, the
    same basis compute_risk_scores uses for hops-to-Tier-0, so the drawn path
    and the numeric hop count agree.

    Built from a single multi-source BFS: add a synthetic super-source
    connected to every Tier-0 node, BFS once from it, and read each node's
    parent chain back to whichever Tier-0 node it attached to. O(V+E) total
    rather than O(V * k * (V+E)) shortest-path calls — the same fix applied to
    the risk module's Tier-0 distance.
    """
    undirected = graph.to_undirected()
    present = [t for t in tier0_nodes if t in undirected]
    if not present:
        return {n: [] for n in graph}

    SUPER = ("__tier0_super_source__",)  # tuple id can't collide with str nodes
    undirected.add_node(SUPER)
    for t in present:
        undirected.add_edge(SUPER, t)

    # BFS predecessor tree from the super-source.
    preds = nx.bfs_predecessors(undirected, SUPER)
    parent = dict(preds)

    paths: dict[str, list[str]] = {}
    for node in graph:
        if node not in parent and node not in present:
            paths[node] = []       # unreachable from any Tier-0
            continue
        # Walk parent pointers up to (but not including) the super-source; the
        # last real node reached is the Tier-0 asset this node attached to.
        chain = [node]
        cur = node
        while cur in parent and parent[cur] != SUPER:
            cur = parent[cur]
            chain.append(cur)
        paths[node] = chain  # node -> ... -> nearest Tier-0
    return paths


def _as_identity_graph(graph) -> IdentityGraph:
    """Validate that the caller passed a constructed IdentityGraph."""
    if isinstance(graph, IdentityGraph):
        return graph
    raise TypeError(
        f"visualize expects an IdentityGraph, got {type(graph).__name__}"
    )


def build_visualization_payload(graph, max_nodes: int = 400) -> dict:
    """Assemble the nodes/edges/paths payload the HTML template renders.

    Risk scores are computed here (compute_risk_scores) so node size and the
    per-node metric breakdown reflect the same numbers the pipeline uses.
    Accepts either graph backend.

    Scale: a force-directed view of 10^4+ nodes is an unreadable hairball that
    also freezes the browser. For triage, what matters is the high-risk
    neighborhood and the paths to Tier-0, not every benign leaf. When the graph
    exceeds `max_nodes`, the view is capped to the highest-composite-risk nodes
    PLUS all Tier-0 assets PLUS every node lying on a retained node's shortest
    path to Tier-0 (so attack paths are never broken by truncation). The full
    counts are still reported so the reviewer knows the view is a focused subset.
    Pass max_nodes=0 to disable capping (render everything).
    """
    graph = _as_identity_graph(graph)
    graph.compute_risk_scores()  # populates per-node GraphRiskScore cache
    tier0 = sorted(graph._tier0_nodes)
    paths = _shortest_path_to_tier0(graph.graph, tier0)

    total_nodes = graph.graph.number_of_nodes()
    total_edges = graph.graph.number_of_edges()

    # Decide which nodes to include.
    all_ids = list(graph.graph)
    truncated = bool(max_nodes) and total_nodes > max_nodes
    if truncated:
        def _risk(n):
            rs = graph.get_user_risk_score(n)
            return rs.composite_risk if rs else 0.0
        ranked = sorted(all_ids, key=_risk, reverse=True)
        keep = set(ranked[:max_nodes])
        keep.update(graph._tier0_nodes)  # always show crown jewels
        # Keep every node on a retained node's attack path so paths stay whole.
        for n in list(keep):
            keep.update(paths.get(n, []))
        included = keep
    else:
        included = set(all_ids)

    nodes = []
    for n in graph.graph:
        if n not in included:
            continue
        rs = graph.get_user_risk_score(n)
        risk = rs.composite_risk if rs else 0.0
        hops = rs.hops_to_tier0 if rs else None
        nodes.append({
            "id": n,
            "type": graph._node_types.get(n, "unknown"),
            "tier0": n in graph._tier0_nodes,
            "risk": round(risk, 4),
            "hops_to_tier0": hops,
            "degree": round(rs.degree_centrality, 4) if rs else 0.0,
            "betweenness": round(rs.betweenness_centrality, 4) if rs else 0.0,
            "pagerank": round(rs.pagerank, 5) if rs else 0.0,
            "path_to_tier0": [p for p in paths.get(n, []) if p in included],
        })

    edges = [
        {"source": u, "target": v,
         "type": graph.graph[u][v].get("edge_type", "unknown")}
        for u, v in graph.graph.edges
        if u in included and v in included
    ]

    return {
        "nodes": nodes,
        "edges": edges,
        "tier0": [t for t in tier0 if t in included],
        "colors": _TYPE_COLORS,
        "stats": {
            "n_nodes": total_nodes,
            "n_edges": total_edges,
            "n_tier0": len(tier0),
            "n_shown": len(nodes),
            "truncated": truncated,
        },
    }


def render_html(graph, title: str = "Identity Graph", max_nodes: int = 400) -> str:
    """Return a complete standalone HTML document for the graph. Accepts either
    the IdentityGraph.
    Large graphs are capped to the top-risk subgraph (see
    build_visualization_payload); pass max_nodes=0 to render everything."""
    payload = build_visualization_payload(graph, max_nodes=max_nodes)
    data_json = json.dumps(payload)
    # The template is intentionally plain: one <script> of data, one of D3
    # rendering. All interaction (drag, zoom, click-to-trace-path, legend
    # toggles) is client-side.
    return _HTML_TEMPLATE.replace("__TITLE__", title).replace(
        "__DATA__", data_json
    )


def write_html(graph, path: str, title: str = "Identity Graph",
               max_nodes: int = 400) -> str:
    """Render and write the HTML file. Returns the path written. Accepts either
    graph backend."""
    html = render_html(graph, title=title, max_nodes=max_nodes)
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path


_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>__TITLE__</title>
<style>
  :root { --bg:#0f1116; --panel:#1a1d26; --ink:#e6e8ee; --muted:#9aa0ad;
          --tier0:#e15759; --line:#2a2e3a; }
  html,body{margin:0;height:100%;background:var(--bg);color:var(--ink);
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;}
  #wrap{display:flex;height:100vh;}
  #graph{flex:1;position:relative;}
  #side{width:300px;background:var(--panel);border-left:1px solid var(--line);
    padding:16px;overflow-y:auto;box-sizing:border-box;}
  h1{font-size:15px;margin:0 0 4px;font-weight:600;}
  .sub{color:var(--muted);font-size:12px;margin-bottom:14px;line-height:1.4;}
  .stat{display:flex;justify-content:space-between;font-size:12px;padding:3px 0;
    border-bottom:1px solid var(--line);}
  .stat b{font-weight:600;}
  .legend{margin:14px 0;}
  .legrow{display:flex;align-items:center;font-size:12px;padding:3px 0;cursor:pointer;}
  .dot{width:11px;height:11px;border-radius:50%;margin-right:8px;flex:none;}
  .legrow.off{opacity:.35;}
  #detail{margin-top:14px;font-size:12px;line-height:1.6;}
  #detail .k{color:var(--muted);}
  #detail .name{font-size:14px;font-weight:600;word-break:break-all;margin-bottom:6px;}
  .pathnote{color:var(--tier0);font-size:12px;margin-top:8px;}
  .hint{color:var(--muted);font-size:11px;margin-top:10px;line-height:1.4;}
  svg{width:100%;height:100%;display:block;cursor:grab;}
  .node{cursor:pointer;stroke:#0f1116;stroke-width:1px;}
  .node.tier0{stroke:var(--tier0);stroke-width:2.5px;}
  .node.dim{opacity:.12;}
  .link{stroke:var(--line);stroke-opacity:.55;}
  .link.path{stroke:var(--tier0);stroke-opacity:1;stroke-width:2.5px;}
  .link.dim{stroke-opacity:.05;}
  .label{fill:var(--ink);font-size:9px;pointer-events:none;}
  .label.dim{opacity:.1;}
  #fallback{display:none;padding:40px;color:var(--muted);}
</style>
</head>
<body>
<div id="wrap">
  <div id="graph">
    <div id="fallback">D3 could not be loaded (offline). The graph data is
      embedded in this file's &lt;script&gt; block and can be rendered with any
      D3 v7 host.</div>
  </div>
  <div id="side">
    <h1>__TITLE__</h1>
    <div class="sub">Identity graph structural view. Node size = graph risk.
      Red ring = Tier-0 asset. Click a node to trace its shortest path to the
      nearest Tier-0 asset.</div>
    <div class="stat"><span>Nodes</span><b id="s_nodes">-</b></div>
    <div class="stat"><span>Edges</span><b id="s_edges">-</b></div>
    <div class="stat"><span>Tier-0 assets</span><b id="s_tier0">-</b></div>
    <div class="stat" id="shown_row" style="display:none"><span>Shown (top risk)</span><b id="s_shown">-</b></div>
    <div class="legend" id="legend"></div>
    <div id="detail"><div class="hint">No node selected.</div></div>
  </div>
</div>
<script>const DATA = __DATA__;</script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
<script>
(function(){
  if (typeof d3 === "undefined") {
    document.getElementById("fallback").style.display = "block";
    return;
  }
  const colors = DATA.colors;
  document.getElementById("s_nodes").textContent = DATA.stats.n_nodes;
  document.getElementById("s_edges").textContent = DATA.stats.n_edges;
  document.getElementById("s_tier0").textContent = DATA.stats.n_tier0;
  if (DATA.stats.truncated) {
    document.getElementById("shown_row").style.display = "flex";
    document.getElementById("s_shown").textContent = DATA.stats.n_shown;
    var note = document.createElement("div");
    note.className = "sub";
    note.style.marginTop = "10px";
    note.textContent = "Large graph: showing the " + DATA.stats.n_shown +
      " highest-risk entities plus all Tier-0 assets and the nodes on their " +
      "attack paths. " + DATA.stats.n_nodes + " total in the graph.";
    document.getElementById("legend").parentNode.insertBefore(
      note, document.getElementById("legend"));
  }

  const el = document.getElementById("graph");
  const W = el.clientWidth, H = el.clientHeight;
  const svg = d3.select("#graph").append("svg");
  const g = svg.append("g");
  svg.call(d3.zoom().scaleExtent([0.15, 6]).on("zoom", e => g.attr("transform", e.transform)));

  const idset = new Set(DATA.nodes.map(n => n.id));
  const links = DATA.edges.filter(e => idset.has(e.source) && idset.has(e.target))
    .map(e => Object.assign({}, e));
  const nodes = DATA.nodes.map(n => Object.assign({}, n));
  const rscale = d3.scaleSqrt().domain([0, d3.max(nodes, n => n.risk) || 1]).range([3.5, 16]);

  const sim = d3.forceSimulation(nodes)
    .force("link", d3.forceLink(links).id(d => d.id).distance(38).strength(.4))
    .force("charge", d3.forceManyBody().strength(-70))
    .force("center", d3.forceCenter(W/2, H/2))
    .force("collide", d3.forceCollide().radius(d => rscale(d.risk) + 2));

  const link = g.append("g").selectAll("line").data(links).join("line")
    .attr("class", "link");
  const node = g.append("g").selectAll("circle").data(nodes).join("circle")
    .attr("class", d => "node" + (d.tier0 ? " tier0" : ""))
    .attr("r", d => rscale(d.risk))
    .attr("fill", d => colors[d.type] || colors.unknown)
    .call(d3.drag()
      .on("start", (e,d)=>{if(!e.active)sim.alphaTarget(.3).restart();d.fx=d.x;d.fy=d.y;})
      .on("drag", (e,d)=>{d.fx=e.x;d.fy=e.y;})
      .on("end", (e,d)=>{if(!e.active)sim.alphaTarget(0);d.fx=null;d.fy=null;}))
    .on("click", (e,d)=>selectNode(d));
  const label = g.append("g").selectAll("text").data(nodes.filter(n=>n.tier0||n.risk>0.25))
    .join("text").attr("class","label").text(d=>d.id).attr("dx",6).attr("dy",3);

  sim.on("tick", () => {
    link.attr("x1",d=>d.source.x).attr("y1",d=>d.source.y)
        .attr("x2",d=>d.target.x).attr("y2",d=>d.target.y);
    node.attr("cx",d=>d.x).attr("cy",d=>d.y);
    label.attr("x",d=>d.x).attr("y",d=>d.y);
  });

  // Legend with per-type toggle.
  const types = Array.from(new Set(nodes.map(n=>n.type)));
  const hidden = new Set();
  const legend = d3.select("#legend");
  types.forEach(t => {
    const row = legend.append("div").attr("class","legrow").on("click", function(){
      if(hidden.has(t)){hidden.delete(t);d3.select(this).classed("off",false);}
      else{hidden.add(t);d3.select(this).classed("off",true);}
      applyFilter();
    });
    row.append("span").attr("class","dot").style("background", colors[t]||colors.unknown);
    row.append("span").text(t + " (" + nodes.filter(n=>n.type===t).length + ")");
  });

  function applyFilter(){
    node.style("display", d => hidden.has(d.type) ? "none" : null);
    label.style("display", d => hidden.has(d.type) ? "none" : null);
    link.style("display", d => (hidden.has(d.source.type)||hidden.has(d.target.type)) ? "none" : null);
  }

  function selectNode(d){
    const path = d.path_to_tier0 || [];
    const pathSet = new Set(path);
    const pathEdges = new Set();
    for(let i=0;i<path.length-1;i++){pathEdges.add(path[i]+"|"+path[i+1]);pathEdges.add(path[i+1]+"|"+path[i]);}
    node.classed("dim", n => path.length ? !pathSet.has(n.id) : false);
    label.classed("dim", n => path.length ? !pathSet.has(n.id) : false);
    link.classed("path", l => pathEdges.has(l.source.id+"|"+l.target.id))
        .classed("dim", l => path.length ? !pathEdges.has(l.source.id+"|"+l.target.id) : false);
    const hops = d.hops_to_tier0==null ? "unreachable" : d.hops_to_tier0;
    let html = '<div class="name">'+d.id+'</div>';
    html += '<div><span class="k">type:</span> '+d.type+(d.tier0?' <b style="color:var(--tier0)">[Tier-0]</b>':'')+'</div>';
    html += '<div><span class="k">composite risk:</span> '+d.risk.toFixed(3)+'</div>';
    html += '<div><span class="k">hops to Tier-0:</span> '+hops+'</div>';
    html += '<div><span class="k">degree cent.:</span> '+d.degree.toFixed(3)+'</div>';
    html += '<div><span class="k">betweenness:</span> '+d.betweenness.toFixed(3)+'</div>';
    html += '<div><span class="k">pagerank:</span> '+d.pagerank.toFixed(4)+'</div>';
    if(path.length>1){
      html += '<div class="pathnote">Attack path ('+(path.length-1)+' hops): '+path.join(" \u2192 ")+'</div>';
    } else if(d.tier0){
      html += '<div class="pathnote">This node is itself a Tier-0 asset.</div>';
    } else {
      html += '<div class="pathnote">No path to any Tier-0 asset.</div>';
    }
    html += '<div class="hint">Click empty space to clear.</div>';
    document.getElementById("detail").innerHTML = html;
  }

  svg.on("click", function(e){
    if(e.target.tagName!=="circle"){
      node.classed("dim",false);label.classed("dim",false);
      link.classed("path",false).classed("dim",false);
      document.getElementById("detail").innerHTML='<div class="hint">No node selected.</div>';
    }
  });
})();
</script>
</body>
</html>
"""

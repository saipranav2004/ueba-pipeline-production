/* Self-contained force-directed layout and SVG helpers.
 *
 * This replaces a CDN-loaded D3. The generated file is handed to an analyst and
 * is described as standalone, so it must render with no network: an air-gapped
 * SOC is the normal case for this tool, not the exception, and fetching an
 * unpinned third-party script at render time is not something a security product
 * should do to its own output.
 *
 * Only eleven D3 entry points were ever used here -- a force simulation, zoom,
 * drag, a sqrt scale, min/max, and selection. The simulation below reimplements
 * the four forces that were configured, following the published algorithm in
 * d3-force 3.0.0 (BSD-3-Clause, Mike Bostock) so the layout behaves the same:
 *
 *   integration   alpha decays toward alphaTarget by alphaDecay each tick,
 *                 x += (vx *= velocityDecay); defaults alpha 1, alphaMin 0.001,
 *                 alphaDecay 1 - alphaMin^(1/300), velocityDecay 0.6
 *   seeding       phyllotaxis spiral, radius 10*sqrt(0.5+i), angle i*PI*(3-sqrt5)
 *   link          l = (dist - target)/dist * alpha * strength, split between the
 *                 endpoints by bias = deg(src)/(deg(src)+deg(tgt))
 *   many-body     v += d * strength * alpha / |d|^2, computed exactly over all
 *                 pairs. D3 uses a Barnes-Hut quadtree with theta=0.9; at the
 *                 few hundred nodes this view caps to, the exact sum is both
 *                 faster than building a quadtree per tick and free of the
 *                 approximation error
 *   collide       resolve overlap between pairs, weighted by radius^2
 *   center        translate so the centroid sits at the requested point
 */
(function (global) {
  "use strict";

  var PHI_ANGLE = Math.PI * (3 - Math.sqrt(5));

  function jiggle() { return (Math.random() - 0.5) * 1e-6; }

  function ForceGraph(nodes, links, opts) {
    this.nodes = nodes;
    this.links = links;
    this.o = opts || {};
    this.alpha = 1;
    this.alphaMin = 0.001;
    this.alphaTarget = 0;
    this.alphaDecay = 1 - Math.pow(0.001, 1 / 300);
    this.velocityDecay = 0.6;
    this._seed();
    this._indexLinks();
  }

  ForceGraph.prototype._seed = function () {
    // Phyllotaxis: deterministic, isotropic, and avoids the coincident starting
    // points that make a random seed jitter on the first few ticks.
    for (var i = 0; i < this.nodes.length; ++i) {
      var n = this.nodes[i];
      n.index = i;
      if (n.x == null || n.y == null) {
        var r = 10 * Math.sqrt(0.5 + i), a = i * PHI_ANGLE;
        n.x = r * Math.cos(a);
        n.y = r * Math.sin(a);
      }
      n.vx = n.vx || 0;
      n.vy = n.vy || 0;
    }
  };

  ForceGraph.prototype._indexLinks = function () {
    var byId = new Map();
    for (var i = 0; i < this.nodes.length; ++i) byId.set(this.nodes[i].id, this.nodes[i]);
    var deg = new Array(this.nodes.length).fill(0);
    var kept = [];
    for (var j = 0; j < this.links.length; ++j) {
      var l = this.links[j];
      var s = typeof l.source === "object" ? l.source : byId.get(l.source);
      var t = typeof l.target === "object" ? l.target : byId.get(l.target);
      if (!s || !t) continue;      // an edge to a node the view dropped
      l.source = s; l.target = t;
      deg[s.index]++; deg[t.index]++;
      kept.push(l);
    }
    this.links = kept;
    for (var k = 0; k < kept.length; ++k) {
      var lk = kept[k], ds = deg[lk.source.index], dt = deg[lk.target.index];
      lk._bias = ds / (ds + dt);
      lk._strength = 1 / Math.min(ds, dt);
    }
    this._deg = deg;
  };

  ForceGraph.prototype.tick = function () {
    var nodes = this.nodes, n = nodes.length, i, j, node, other;
    this.alpha += (this.alphaTarget - this.alpha) * this.alphaDecay;
    var alpha = this.alpha;

    // -- link: spring toward the configured distance -------------------------
    var linkDistance = this.o.linkDistance, linkStrength = this.o.linkStrength;
    for (i = 0; i < this.links.length; ++i) {
      var l = this.links[i], s = l.source, t = l.target;
      var x = t.x + t.vx - s.x - s.vx || jiggle();
      var y = t.y + t.vy - s.y - s.vy || jiggle();
      var d = Math.sqrt(x * x + y * y);
      // The caller sets an explicit link strength, which in d3 overrides the
      // degree-based default of 1/min(deg(src), deg(tgt)); so no degree term here.
      var f = (d - linkDistance) / d * alpha * linkStrength;
      x *= f; y *= f;
      t.vx -= x * l._bias; t.vy -= y * l._bias;
      s.vx += x * (1 - l._bias); s.vy += y * (1 - l._bias);
    }

    // -- many-body: exact inverse-square repulsion over all pairs ------------
    var charge = this.o.charge;
    for (i = 0; i < n; ++i) {
      node = nodes[i];
      for (j = i + 1; j < n; ++j) {
        other = nodes[j];
        var dx = other.x - node.x, dy = other.y - node.y;
        var l2 = dx * dx + dy * dy;
        if (dx === 0) { dx = jiggle(); l2 += dx * dx; }
        if (dy === 0) { dy = jiggle(); l2 += dy * dy; }
        if (l2 < 1) l2 = Math.sqrt(l2);     // d3's distanceMin2 clamp
        var w = charge * alpha / l2;
        node.vx += dx * w; node.vy += dy * w;
        other.vx -= dx * w; other.vy -= dy * w;
      }
    }

    // -- collide: push overlapping circles apart -----------------------------
    var radius = this.o.radius;
    for (i = 0; i < n; ++i) {
      node = nodes[i];
      var ri = radius(node), ri2 = ri * ri;
      var xi = node.x + node.vx, yi = node.y + node.vy;
      for (j = i + 1; j < n; ++j) {
        other = nodes[j];
        var rj = radius(other), r = ri + rj;
        var ox = xi - other.x - other.vx, oy = yi - other.y - other.vy;
        var ol = ox * ox + oy * oy;
        if (ol >= r * r) continue;
        if (ox === 0) { ox = jiggle(); ol += ox * ox; }
        if (oy === 0) { oy = jiggle(); ol += oy * oy; }
        ol = Math.sqrt(ol);
        var push = (r - ol) / ol;
        var rj2 = rj * rj, share = rj2 / (ri2 + rj2);
        ox *= push; oy *= push;
        node.vx += ox * share; node.vy += oy * share;
        other.vx -= ox * (1 - share); other.vy -= oy * (1 - share);
      }
    }

    // -- integrate, honouring pinned nodes -----------------------------------
    for (i = 0; i < n; ++i) {
      node = nodes[i];
      if (node.fx != null) { node.x = node.fx; node.vx = 0; }
      else node.x += node.vx *= this.velocityDecay;
      if (node.fy != null) { node.y = node.fy; node.vy = 0; }
      else node.y += node.vy *= this.velocityDecay;
    }

    // -- center: translate the centroid to the requested point ---------------
    var sx = 0, sy = 0;
    for (i = 0; i < n; ++i) { sx += nodes[i].x; sy += nodes[i].y; }
    sx = sx / n - this.o.cx; sy = sy / n - this.o.cy;
    for (i = 0; i < n; ++i) { nodes[i].x -= sx; nodes[i].y -= sy; }
  };

  ForceGraph.prototype.run = function (onTick) {
    var self = this;
    function step() {
      // A few ticks per frame: the layout settles in roughly 300 ticks and an
      // analyst should not watch it crawl.
      for (var k = 0; k < 3 && self.alpha >= self.alphaMin; ++k) self.tick();
      onTick();
      if (self.alpha >= self.alphaMin || self.alphaTarget > 0) {
        global.requestAnimationFrame(step);
      }
    }
    global.requestAnimationFrame(step);
  };

  ForceGraph.prototype.reheat = function (target) {
    this.alphaTarget = target;
    if (target > 0 && this.alpha < 0.3) this.alpha = 0.3;
  };

  global.ForceGraph = ForceGraph;

  // -- small helpers that stand in for the d3 utilities this view used --------
  global.svgEl = function (name, attrs) {
    var e = document.createElementNS("http://www.w3.org/2000/svg", name);
    for (var k in attrs) if (attrs[k] != null) e.setAttribute(k, attrs[k]);
    return e;
  };

  global.sqrtScale = function (maxDomain, lo, hi) {
    var d = Math.sqrt(maxDomain || 1);
    return function (v) {
      return lo + (hi - lo) * (Math.sqrt(Math.max(v, 0)) / (d || 1));
    };
  };

  // Pan and zoom by rewriting one transform on a container <g>, which is what
  // d3.zoom did here -- no behaviour of its own worth importing.
  global.attachZoom = function (svg, g, minScale, maxScale) {
    var t = { k: 1, x: 0, y: 0 }, dragging = false, lx = 0, ly = 0;
    function apply() { g.setAttribute("transform", "translate(" + t.x + "," + t.y + ") scale(" + t.k + ")"); }
    svg.addEventListener("wheel", function (e) {
      e.preventDefault();
      var r = svg.getBoundingClientRect();
      var mx = e.clientX - r.left, my = e.clientY - r.top;
      var k = Math.min(maxScale, Math.max(minScale, t.k * Math.pow(2, -e.deltaY * 0.002)));
      // Keep the point under the cursor fixed while scaling.
      t.x = mx - (mx - t.x) * (k / t.k);
      t.y = my - (my - t.y) * (k / t.k);
      t.k = k; apply();
    }, { passive: false });
    svg.addEventListener("pointerdown", function (e) {
      if (e.target.classList && e.target.classList.contains("node")) return;
      dragging = true; lx = e.clientX; ly = e.clientY; svg.setPointerCapture(e.pointerId);
    });
    svg.addEventListener("pointermove", function (e) {
      if (!dragging) return;
      t.x += e.clientX - lx; t.y += e.clientY - ly; lx = e.clientX; ly = e.clientY; apply();
    });
    svg.addEventListener("pointerup", function (e) {
      dragging = false;
      if (svg.hasPointerCapture(e.pointerId)) svg.releasePointerCapture(e.pointerId);
    });
    return { transform: t, apply: apply };
  };
})(window);

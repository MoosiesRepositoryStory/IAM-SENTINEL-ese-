/* Blast Radius permission graph (§6.2, Phase 3 Slice 2).
 * Renders one principal's neighborhood with Cytoscape.js (vendored, no CDN)
 * and drives a side panel from node click. Deliberately its own module,
 * separate from app.js's Sentinel (findings-table/palette/shortcuts) —
 * this page has nothing to do with that surface. */
window.SentinelGraph = (function () {
  function styles() {
    return [
      {
        selector: "node",
        style: {
          label: "data(label)",
          "font-size": 9,
          color: "#E4E7EB",
          "text-valign": "bottom",
          "text-margin-y": 6,
          "text-wrap": "ellipsis",
          "text-max-width": "90px",
          "border-width": 2,
          "border-color": "#313A4B",
        },
      },
      {
        selector: 'node[type="principal"]',
        style: {
          shape: "ellipse",
          "background-color": "#4C8DFF",
          width: "mapData(blast_radius_score, 0, 100, 26, 64)",
          height: "mapData(blast_radius_score, 0, 100, 26, 64)",
        },
      },
      { selector: 'node[kind="role"]', style: { "background-color": "#8A6CFF" } },
      {
        selector: 'node[type="policy"]',
        style: { shape: "round-rectangle", "background-color": "#8A94A6", width: 22, height: 22 },
      },
      {
        selector: 'node[type="action"]',
        style: { shape: "diamond", "background-color": "#FFD24C", width: 18, height: 18 },
      },
      {
        selector: 'node[type="resource"]',
        style: { shape: "hexagon", "background-color": "#6AD19A", width: 18, height: 18 },
      },
      { selector: "node[?is_focus]", style: { "border-width": 4, "border-color": "#FF5470" } },
      { selector: "node.selected", style: { "border-width": 4, "border-color": "#4C8DFF" } },
      {
        // Structural "grants" edges (HAS_POLICY / GRANTS_ACTION / ON_RESOURCE)
        // stay neutral gray — the colored edges below are reserved for the
        // principal-to-principal "risk" relations so they read as a distinct
        // category at a glance, not just another line in the chain.
        selector: "edge",
        style: {
          width: 1.5,
          "line-color": "#5B6472",
          "target-arrow-color": "#5B6472",
          "target-arrow-shape": "triangle",
          "curve-style": "bezier",
          "arrow-scale": 0.8,
          opacity: 1,
        },
      },
      {
        selector: 'edge[relation="CAN_ASSUME"]',
        style: { "line-color": "#4C8DFF", "target-arrow-color": "#4C8DFF" },
      },
      {
        // Dimmed by default — a principal can often CAN_ESCALATE to many
        // others (e.g. "mint anyone's credentials"), and drawing all of them
        // at full strength would drown out the one path this page highlights.
        selector: 'edge[relation="CAN_ESCALATE"]',
        style: {
          "line-color": "#FF9F45",
          "target-arrow-color": "#FF9F45",
          "line-style": "dashed",
          opacity: 0.45,
        },
      },
      {
        // The headline: the real escalation path to an admin-equivalent node,
        // drawn bold/opaque/red over everything else (§6.2 "animated/emphasized").
        selector: "edge[?on_path]",
        style: {
          width: 4,
          "line-color": "#FF5470",
          "target-arrow-color": "#FF5470",
          "line-style": "dashed",
          opacity: 1,
          "z-index": 999,
        },
      },
    ];
  }

  function esc(s) {
    const div = document.createElement("div");
    div.textContent = s == null ? "" : String(s);
    return div.innerHTML;
  }

  function row(label, value) {
    return '<div class="gp-row"><span>' + esc(label) + "</span><b>" + esc(value) + "</b></div>";
  }

  function panelHtml(data) {
    let html = '<div class="graph-panel-title">' + esc(data.label) + "</div>";
    html += row("Type", data.type);
    html += '<div class="gp-row"><span>ID</span><span class="mono small">' + esc(data.uid) + "</span></div>";
    if (data.type === "principal") {
      html += row("Kind", data.kind || "—");
      html += row("Blast radius", data.blast_radius_score);
      html += row("Reachable actions", data.reachable_actions);
      html += row("Sensitive actions", data.reachable_sensitive);
    }
    return html;
  }

  function init(canvasId, dataElId, panelId) {
    const raw = document.getElementById(dataElId).textContent;
    const graph = JSON.parse(raw);
    const panel = document.getElementById(panelId);

    const cy = cytoscape({
      container: document.getElementById(canvasId),
      elements: { nodes: graph.nodes, edges: graph.edges },
      style: styles(),
      wheelSensitivity: 0.3,
    });

    const focusId = "principal:" + graph.focus;
    cy.layout({
      name: "breadthfirst",
      roots: cy.$id(focusId),
      directed: true,
      spacingFactor: 1.4,
      animate: false,
    }).run();

    function showEmpty() {
      panel.innerHTML = '<div class="graph-panel-empty">Click a node to see its details.</div>';
    }

    cy.on("tap", "node", function (evt) {
      cy.nodes().removeClass("selected");
      evt.target.addClass("selected");
      panel.innerHTML = panelHtml(evt.target.data());
    });
    cy.on("tap", function (evt) {
      if (evt.target === cy) {
        cy.nodes().removeClass("selected");
        showEmpty();
      }
    });

    // Playwright verification hook — not used by app logic.
    window.__sentinelCy = cy;
    return cy;
  }

  return { init: init };
})();

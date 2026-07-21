/* Blast Radius permission graph (§6.2, Phase 3 Slice 2).
 * Renders one principal's neighborhood with Cytoscape.js (vendored, no CDN)
 * and drives a side panel from node click. Deliberately its own module,
 * separate from app.js's Sentinel (findings-table/palette/shortcuts) —
 * this page has nothing to do with that surface. */
window.SentinelGraph = (function () {
  // Cytoscape draws to a <canvas>, which — unlike the rest of the app's DOM —
  // never picks up CSS custom properties on its own, so these color values
  // must be read explicitly and re-read on every theme change (see the
  // MutationObserver in init(), below). A WCAG contrast audit found this
  // page's text/lines had been hardcoded to the DARK theme's variable values
  // (e.g. node-label color #E4E7EB is exactly dark's --text) — harmless in
  // dark mode by coincidence, but 1.24:1 (near-invisible) in light mode,
  // since light's --bg-elev is white. Reading the live variables fixes both
  // themes and any future theme addition, instead of a second hardcoded copy.
  function themeColor(name, fallback) {
    const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return v || fallback;
  }

  function styles() {
    const text = themeColor("--text", "#E4E7EB");
    const borderStrong = themeColor("--border-strong", "#313A4B");
    const textFaint = themeColor("--text-faint", "#5B6472");
    const sevHigh = themeColor("--sev-high", "#FF9F45");
    return [
      {
        selector: "node",
        style: {
          label: "data(label)",
          "font-size": 9,
          color: text,
          "text-valign": "bottom",
          "text-margin-y": 6,
          "text-wrap": "ellipsis",
          "text-max-width": "90px",
          "border-width": 2,
          "border-color": borderStrong,
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
        // NOTE (contrast audit): policy/action/resource fills below, plus the
        // matching CSS legend swatches, measure under the 3:1 non-text
        // minimum against a WHITE (light-theme) canvas — e.g. the action
        // diamond's yellow is ~1.4:1. Left as fixed categorical colors rather
        // than wired to the (much darker, text-tuned) --sev-medium/--sev-low
        // variables: each node's SHAPE already distinguishes its type
        // independent of color (round-rect/diamond/hexagon), so color here
        // is a supplementary cue, not the sole channel — and matching the
        // darkened text variables would be a much bigger visual change than
        // a lightness nudge. Flagged for manual review, not auto-fixed.
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
        // category at a glance, not just another line in the chain. Wired to
        // --text-faint (contrast audit: this literal WAS exactly dark's old
        // --text-faint value already, just not read live).
        selector: "edge",
        style: {
          width: 1.5,
          "line-color": textFaint,
          "target-arrow-color": textFaint,
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
        // Wired to --sev-high (contrast audit: was a hardcoded copy of dark's
        // value); opacity raised 0.45->0.7 — even wired, 0.45 measured
        // 2.72:1/1.38:1 (dark/light) against bg-elev, since the low opacity
        // itself was most of the shortfall. 0.7 is the minimum that clears
        // 3:1 in the harder (light) case with a small margin, still visibly
        // dimmer than the full-strength on-path edge below.
        selector: 'edge[relation="CAN_ESCALATE"]',
        style: {
          "line-color": sevHigh,
          "target-arrow-color": sevHigh,
          "line-style": "dashed",
          opacity: 0.7,
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

    // The theme toggle (base.html) flips <html data-theme> live, with no page
    // reload — but the canvas colors above were read once, at init, so
    // without this they'd go stale (right theme on load, wrong theme after a
    // toggle). Re-applying styles() on every data-theme change keeps the
    // canvas in sync the same way the rest of the (CSS-variable-driven) page
    // already is for free.
    const themeObserver = new MutationObserver(() => cy.style(styles()));
    themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });

    // Playwright verification hook — not used by app logic.
    window.__sentinelCy = cy;
    return cy;
  }

  return { init: init };
})();

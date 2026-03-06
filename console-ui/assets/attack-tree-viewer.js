/**
 * Attack Tree Viewer — Native rendering module.
 * Renders threat data (summary, selector, graph, metadata, TTP table)
 * directly in the console-ui layout using vis-network for graphs.
 */

import { parseMermaidToGraph } from './mermaid-parser.js';

// ---------------------------------------------------------------------------
// Utility functions (Task 4.1)
// ---------------------------------------------------------------------------

/**
 * Format a confidence score (0–1) as a percentage string.
 * @param {number} score - Value between 0.0 and 1.0
 * @returns {string} e.g. "72%"
 */
export function formatConfidence(score) {
  if (typeof score !== 'number' || isNaN(score)) return '0%';
  return Math.round(score * 100) + '%';
}

/**
 * Map a priority string to a CSS badge class.
 * @param {string} priority - "High", "Medium", or "Low"
 * @returns {string} CSS class string
 */
export function priorityBadgeClass(priority) {
  switch (priority) {
    case 'High':   return 'tf-badge tf-badge--error';
    case 'Medium': return 'tf-badge tf-badge--warning';
    case 'Low':    return 'tf-badge tf-badge--info';
    default:       return 'tf-badge';
  }
}

/**
 * Render the summary statistics bar.
 * @param {HTMLElement} container
 * @param {Object} data - The full threatforest data object
 * @param {Document} [doc] - Document reference (for testability)
 */
export function renderSummaryBar(container, data, doc) {
  var d = doc || document;
  container.innerHTML = '';

  var extraction = (data && data.extraction_summary) || {};
  var mapping    = (data && data.mapping_summary) || {};

  var bar = d.createElement('div');
  bar.className = 'tf-summary-bar tf-meta-bar';

  var items = [
    { label: 'Total Threats',    value: extraction.total_threats != null ? extraction.total_threats : 0 },
    { label: 'High Severity',    value: extraction.high_severity_count != null ? extraction.high_severity_count : 0 },
    { label: 'TTP Mappings',     value: mapping.total_mappings != null ? mapping.total_mappings : 0 }
  ];

  for (var i = 0; i < items.length; i++) {
    var dl = d.createElement('dl');
    var dt = d.createElement('dt');
    dt.textContent = items[i].label;
    var dd = d.createElement('dd');
    dd.textContent = String(items[i].value);
    dl.appendChild(dt);
    dl.appendChild(dd);
    bar.appendChild(dl);
  }

  container.appendChild(bar);
}

// ---------------------------------------------------------------------------
// Threat Selector (Task 4.3)
// ---------------------------------------------------------------------------

/**
 * Render the threat selector sidebar.
 * @param {HTMLElement} container
 * @param {Array} attackTrees - Array of attack tree objects
 * @param {Function} onSelect - Callback receiving the selected index
 * @param {Document} [doc] - Document reference (for testability)
 */
export function renderThreatSelector(container, attackTrees, onSelect, doc) {
  var d = doc || document;
  container.innerHTML = '';

  var trees = Array.isArray(attackTrees) ? attackTrees : [];
  var selectedIndex = 0;

  var list = d.createElement('ul');
  list.className = 'tf-threat-selector';
  list.style.listStyle = 'none';
  list.style.margin = '0';
  list.style.padding = '0';

  function renderItems() {
    list.innerHTML = '';
    for (var i = 0; i < trees.length; i++) {
      (function (idx) {
        var tree = trees[idx];
        var li = d.createElement('li');
        li.className = 'tf-threat-selector__item';
        if (idx === selectedIndex) {
          li.classList.add('tf-threat-selector__item--active');
        }
        li.style.padding = '10px 16px';
        li.style.cursor = 'pointer';
        li.style.borderBottom = '1px solid var(--tf-border, #e5e7eb)';

        var idSpan = d.createElement('span');
        idSpan.className = 'tf-threat-selector__id';
        idSpan.textContent = tree.threat_id || '—';
        idSpan.style.fontWeight = '600';
        idSpan.style.marginRight = '8px';

        var catSpan = d.createElement('span');
        catSpan.className = 'tf-threat-selector__category';
        catSpan.textContent = tree.threat_category || '';
        catSpan.style.marginRight = '8px';

        var badge = d.createElement('span');
        badge.className = priorityBadgeClass(tree.priority);
        badge.textContent = tree.priority || '';

        li.appendChild(idSpan);
        li.appendChild(catSpan);
        li.appendChild(badge);

        li.addEventListener('click', function () {
          selectedIndex = idx;
          renderItems();
          if (typeof onSelect === 'function') onSelect(idx);
        });

        list.appendChild(li);
      })(i);
    }
  }

  renderItems();
  container.appendChild(list);

  // Select first tree by default
  if (trees.length > 0 && typeof onSelect === 'function') {
    onSelect(0);
  }
}

// ---------------------------------------------------------------------------
// Metadata Panel (Task 4.4)
// ---------------------------------------------------------------------------

/**
 * Render the metadata panel for a single attack tree.
 * @param {HTMLElement} container
 * @param {Object} attackTree
 * @param {Document} [doc] - Document reference (for testability)
 */
export function renderMetadataPanel(container, attackTree, doc) {
  var d = doc || document;
  container.innerHTML = '';

  var tree = attackTree || {};

  var panel = d.createElement('div');
  panel.className = 'tf-meta-bar';
  panel.style.flexWrap = 'wrap';

  var fields = [
    { label: 'Threat ID',       value: tree.threat_id },
    { label: 'Category',        value: tree.threat_category },
    { label: 'Statement',       value: tree.threat_statement },
    { label: 'Action',          value: tree.threat_action },
    { label: 'Source',          value: tree.threatSource },
    { label: 'Priority',        value: tree.priority, isBadge: true }
  ];

  for (var i = 0; i < fields.length; i++) {
    var dl = d.createElement('dl');
    var dt = d.createElement('dt');
    dt.textContent = fields[i].label;
    var dd = d.createElement('dd');

    if (fields[i].isBadge && fields[i].value) {
      var badge = d.createElement('span');
      badge.className = priorityBadgeClass(fields[i].value);
      badge.textContent = fields[i].value;
      dd.appendChild(badge);
    } else {
      dd.textContent = fields[i].value || '—';
    }

    dl.appendChild(dt);
    dl.appendChild(dd);
    panel.appendChild(dl);
  }

  container.appendChild(panel);
}

// ---------------------------------------------------------------------------
// TTP Table (Task 4.5)
// ---------------------------------------------------------------------------

/**
 * Render the TTP mappings table for a single attack tree.
 * @param {HTMLElement} container
 * @param {Object} attackTree
 * @param {Document} [doc] - Document reference (for testability)
 */
export function renderTTPTable(container, attackTree, doc) {
  var d = doc || document;
  container.innerHTML = '';

  var tree = attackTree || {};
  var mappings = Array.isArray(tree.ttc_mappings) ? tree.ttc_mappings : [];

  if (mappings.length === 0) {
    var msg = d.createElement('p');
    msg.textContent = 'No MITRE ATT&CK mappings available';
    msg.style.color = 'var(--tf-text-secondary, #6b7280)';
    msg.style.fontStyle = 'italic';
    container.appendChild(msg);
    return;
  }

  var table = d.createElement('table');
  table.className = 'tf-table';

  // Header
  var thead = d.createElement('thead');
  var headerRow = d.createElement('tr');
  var cols = ['Attack Step', 'Technique ID', 'Technique Name', 'Confidence', 'Tactics'];
  for (var c = 0; c < cols.length; c++) {
    var th = d.createElement('th');
    th.textContent = cols[c];
    headerRow.appendChild(th);
  }
  thead.appendChild(headerRow);
  table.appendChild(thead);

  // Body
  var tbody = d.createElement('tbody');
  for (var i = 0; i < mappings.length; i++) {
    var m = mappings[i];
    var tr = d.createElement('tr');

    var tdStep = d.createElement('td');
    tdStep.textContent = m.attack_step || '—';
    tr.appendChild(tdStep);

    var tdId = d.createElement('td');
    tdId.textContent = m.technique_id || '—';
    tr.appendChild(tdId);

    var tdName = d.createElement('td');
    tdName.textContent = m.technique_name || '—';
    tr.appendChild(tdName);

    var tdConf = d.createElement('td');
    tdConf.textContent = formatConfidence(m.confidence);
    tr.appendChild(tdConf);

    var tdTactics = d.createElement('td');
    var tactics = Array.isArray(m.tactics) ? m.tactics : [];
    for (var t = 0; t < tactics.length; t++) {
      var tacticBadge = d.createElement('span');
      tacticBadge.className = 'tf-badge tf-badge--info';
      tacticBadge.textContent = tactics[t];
      tacticBadge.style.marginRight = '4px';
      tdTactics.appendChild(tacticBadge);
    }
    tr.appendChild(tdTactics);

    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  container.appendChild(table);
}

// ---------------------------------------------------------------------------
// Graph Rendering (Task 4.6)
// ---------------------------------------------------------------------------

/**
 * Render the vis-network graph for a single attack tree.
 * @param {HTMLElement} container
 * @param {Object} attackTree
 * @param {Document} [doc] - Document reference (for testability)
 */
export function renderGraph(container, attackTree, doc) {
  var d = doc || document;
  container.innerHTML = '';

  var tree = attackTree || {};
  var mermaidCode = tree.mermaid_code || '';
  var attackSteps = Array.isArray(tree.attack_steps) ? tree.attack_steps : [];

  var graph = parseMermaidToGraph(mermaidCode, attackSteps);

  if (!graph.nodes.length) {
    var placeholder = d.createElement('div');
    placeholder.className = 'tf-empty-state';
    placeholder.innerHTML = '<p class="tf-empty-state__message">No graph data available</p>';
    container.appendChild(placeholder);
    return;
  }

  // Check if vis-network is available globally
  var vis = (typeof window !== 'undefined' && window.vis) ? window.vis : null;
  if (!vis) {
    var fallback = d.createElement('div');
    fallback.className = 'tf-empty-state';
    fallback.innerHTML = '<p class="tf-empty-state__message">Graph visualization library not available</p>';
    container.appendChild(fallback);
    return;
  }

  var graphDiv = d.createElement('div');
  graphDiv.className = 'tf-viewer__graph-canvas';
  graphDiv.style.height = '450px';
  graphDiv.style.border = '1px solid var(--tf-border, #e5e7eb)';
  graphDiv.style.borderRadius = '8px';
  graphDiv.style.background = 'var(--tf-surface, #ffffff)';
  container.appendChild(graphDiv);

  var nodes = new vis.DataSet(graph.nodes);
  var edges = new vis.DataSet(
    graph.edges.map(function (e) {
      return { from: e.from, to: e.to, arrows: 'to' };
    })
  );

  var options = {
    layout: {
      hierarchical: {
        direction: 'UD',
        sortMethod: 'directed',
        levelSeparation: 100,
        nodeSpacing: 150
      }
    },
    nodes: {
      shape: 'box',
      font: { size: 13 },
      margin: 10,
      color: {
        background: '#dcfce7',
        border: '#15803d',
        highlight: { background: '#bbf7d0', border: '#166534' }
      }
    },
    edges: {
      color: { color: '#6b7280' },
      smooth: { type: 'cubicBezier' }
    },
    interaction: { tooltipDelay: 200 },
    physics: false
  };

  new vis.Network(graphDiv, { nodes: nodes, edges: edges }, options);
}

// ---------------------------------------------------------------------------
// Main Entry Point (Task 4.7)
// ---------------------------------------------------------------------------

/**
 * Initialize the attack tree viewer with data.
 * Creates the full layout: summary bar, two-column (selector + content).
 * @param {HTMLElement} container - Root DOM element to render into
 * @param {Object} data - Parsed threatforest_data.json content
 * @param {Document} [doc] - Document reference (for testability)
 */
export function renderAttackTreeViewer(container, data, doc) {
  var d = doc || document;
  container.innerHTML = '';

  var viewer = d.createElement('div');
  viewer.className = 'tf-viewer';

  // Summary bar
  var summaryContainer = d.createElement('div');
  summaryContainer.className = 'tf-viewer__summary';
  renderSummaryBar(summaryContainer, data, d);
  viewer.appendChild(summaryContainer);

  // Two-column layout
  var layout = d.createElement('div');
  layout.className = 'tf-viewer__layout';
  layout.style.display = 'flex';
  layout.style.gap = '20px';
  layout.style.marginTop = '16px';

  // Sidebar (threat selector)
  var sidebar = d.createElement('div');
  sidebar.className = 'tf-viewer__sidebar';
  sidebar.style.width = '280px';
  sidebar.style.flexShrink = '0';
  sidebar.style.background = 'var(--tf-surface, #ffffff)';
  sidebar.style.border = '1px solid var(--tf-border, #e5e7eb)';
  sidebar.style.borderRadius = '8px';
  sidebar.style.overflow = 'hidden';

  // Content area
  var content = d.createElement('div');
  content.className = 'tf-viewer__content';
  content.style.flex = '1';
  content.style.minWidth = '0';

  var graphContainer = d.createElement('div');
  graphContainer.className = 'tf-viewer__graph';
  graphContainer.style.marginBottom = '16px';

  var metaContainer = d.createElement('div');
  metaContainer.className = 'tf-viewer__metadata';
  metaContainer.style.marginBottom = '16px';

  var ttpContainer = d.createElement('div');
  ttpContainer.className = 'tf-viewer__ttp';

  content.appendChild(graphContainer);
  content.appendChild(metaContainer);
  content.appendChild(ttpContainer);

  layout.appendChild(sidebar);
  layout.appendChild(content);
  viewer.appendChild(layout);
  container.appendChild(viewer);

  var attackTrees = (data && Array.isArray(data.attack_trees)) ? data.attack_trees : [];

  function onSelect(index) {
    var tree = attackTrees[index];
    if (!tree) return;
    renderGraph(graphContainer, tree, d);
    renderMetadataPanel(metaContainer, tree, d);
    renderTTPTable(ttpContainer, tree, d);
  }

  renderThreatSelector(sidebar, attackTrees, onSelect, d);
}

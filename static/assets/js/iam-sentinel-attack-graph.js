(() => {
  const ui = window.IamSentinelUI || {};
  const formatIdentityLabel = ui.formatIdentityLabel || ((name, id) => name || id || '');
  const formatResourceLabel = ui.formatResourceLabel || ((name, id) => name || id || '');
  const state = {
    graph: { nodes: [], edges: [], paths: [] },
    filteredPaths: [],
    selectedNodeId: null,
    selectedPathId: null,
    filterMode: 'all'
  };
  const columns = {
    user: { label: 'Identity', x: 110 },
    group: { label: 'Group', x: 350 },
    role: { label: 'Role', x: 530 },
    permission: { label: 'Permission', x: 750 },
    resource: { label: 'Resource', x: 990 }
  };

  function escapeHtml(value) {
    if (ui.escapeHtml) {
      return ui.escapeHtml(value);
    }
    return String(value ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#039;');
  }

  function setLoading(isLoading) {
    document.getElementById('attack-graph-loading').classList.toggle('d-none', !isLoading);
  }

  function showError(message) {
    const error = document.getElementById('attack-graph-error');
    error.textContent = message;
    error.classList.toggle('d-none', !message);
  }

  async function fetchGraph() {
    if (ui.fetchJson) {
      return ui.fetchJson('/api/attack-graph');
    }
    const response = await fetch('/api/attack-graph');
    if (!response.ok) {
      throw new Error(`Request failed: ${response.status}`);
    }
    return response.json();
  }

  function layoutNodes(nodes) {
    const grouped = nodes.reduce((accumulator, node) => {
      const type = columns[node.type] ? node.type : 'permission';
      accumulator[type] = accumulator[type] || [];
      accumulator[type].push(node);
      return accumulator;
    }, {});
    const positions = {};

    Object.entries(columns).forEach(([type, column]) => {
      const typeNodes = (grouped[type] || []).sort((left, right) => left.label.localeCompare(right.label));
      const spacing = Math.min(95, Math.max(50, 500 / Math.max(typeNodes.length, 1)));
      const startY = 90 + Math.max(0, (500 - spacing * (typeNodes.length - 1)) / 2);
      typeNodes.forEach((node, index) => {
        positions[node.id] = {
          x: column.x,
          y: startY + index * spacing
        };
      });
    });

    return positions;
  }

  function edgeBelongsToSelectedPath(edge) {
    const selectedPath = getSelectedPath();
    if (!selectedPath) {
      return false;
    }
    return selectedPath.path_nodes.some((nodeId, index) => (
      nodeId === edge.source && selectedPath.path_nodes[index + 1] === edge.target
    ));
  }

  function getSelectedPath() {
    return state.filteredPaths.find((path) => path.id === state.selectedPathId);
  }

  function getSelectedNode() {
    return getVisibleNodes().find((node) => node.id === state.selectedNodeId);
  }

  function getFilteredPaths() {
    return state.graph.paths.filter((path) => {
      if (state.filterMode === 'critical-high') {
        return ['CRITICAL', 'HIGH'].includes(path.finding_severity);
      }
      if (state.filterMode === 'sensitive') {
        return path.resource_sensitive;
      }
      return true;
    });
  }

  function getVisibleNodeIds() {
    const nodeIds = new Set();
    state.filteredPaths.forEach((path) => {
      path.path_nodes.forEach((nodeId) => nodeIds.add(nodeId));
    });
    return nodeIds;
  }

  function getVisibleEdgeIds() {
    const edgeIds = new Set();
    state.filteredPaths.forEach((path) => {
      path.path_nodes.forEach((nodeId, index) => {
        const targetId = path.path_nodes[index + 1];
        if (targetId) {
          edgeIds.add(`${nodeId}->${targetId}`);
        }
      });
    });
    return edgeIds;
  }

  function getVisibleNodes() {
    const visibleNodeIds = getVisibleNodeIds();
    return state.graph.nodes.filter((node) => visibleNodeIds.has(node.id));
  }

  function getVisibleEdges() {
    const visibleEdgeIds = getVisibleEdgeIds();
    return state.graph.edges.filter((edge) => visibleEdgeIds.has(edge.id));
  }

  function getPathSeverityClass(severity) {
    if (severity === 'CRITICAL') {
      return 'attack-graph-path-critical';
    }
    if (severity === 'HIGH') {
      return 'attack-graph-path-high';
    }
    return 'attack-graph-path-neutral';
  }

  function getEdgeSeverity(edge) {
    const path = state.filteredPaths.find((candidate) => candidate.path_nodes.some((nodeId, index) => (
      nodeId === edge.source && candidate.path_nodes[index + 1] === edge.target
    )));
    return path ? path.finding_severity : 'NONE';
  }

  function nodeClass(node) {
    const classes = ['attack-graph-node', `attack-graph-node-${node.type}`];
    const selectedPath = getSelectedPath();
    if (node.risky) {
      classes.push('attack-graph-node-risky');
    }
    if (node.id === state.selectedNodeId) {
      classes.push('attack-graph-node-selected');
    }
    if (selectedPath && selectedPath.path_nodes.includes(node.id)) {
      classes.push('attack-graph-node-path');
      classes.push(getPathSeverityClass(selectedPath.finding_severity));
    } else if (selectedPath) {
      classes.push('attack-graph-node-faded');
    }
    return classes.join(' ');
  }

  function renderGraph() {
    const svg = document.getElementById('attack-graph-svg');
    const selectedPath = getSelectedPath();
    const visibleNodes = getVisibleNodes();
    const visibleEdges = getVisibleEdges();
    const positions = layoutNodes(visibleNodes);
    const edges = visibleEdges.map((edge) => {
      const source = positions[edge.source];
      const target = positions[edge.target];
      if (!source || !target) {
        return '';
      }
      const severityClass = getPathSeverityClass(getEdgeSeverity(edge));
      const selectedClass = edgeBelongsToSelectedPath(edge) ? ' attack-graph-edge-selected' : '';
      const fadedClass = selectedPath && !edgeBelongsToSelectedPath(edge) ? ' attack-graph-edge-faded' : '';
      return `
        <g class="attack-graph-edge ${severityClass}${selectedClass}${fadedClass}" data-edge-id="${escapeHtml(edge.id)}">
          <path d="M ${source.x + 58} ${source.y} C ${source.x + 120} ${source.y}, ${target.x - 120} ${target.y}, ${target.x - 58} ${target.y}"></path>
          <text x="${(source.x + target.x) / 2}" y="${(source.y + target.y) / 2 - 5}">${escapeHtml(formatRelationship(edge.relationship))}</text>
        </g>
      `;
    }).join('');
    const nodes = visibleNodes.map((node) => {
      const position = positions[node.id];
      if (!position) {
        return '';
      }
      return `
        <g class="${nodeClass(node)}" data-node-id="${escapeHtml(node.id)}" tabindex="0" role="button" aria-label="${escapeHtml(node.label)}">
          <rect x="${position.x - 62}" y="${position.y - 24}" width="124" height="48" rx="6"></rect>
          <text class="attack-graph-node-label" x="${position.x}" y="${position.y - 4}">${escapeHtml(truncateLabel(node.label, 20))}</text>
          <text class="attack-graph-node-type" x="${position.x}" y="${position.y + 13}">${escapeHtml(formatNodeType(node.type))}</text>
        </g>
      `;
    }).join('');
    const headers = Object.values(columns).map((column) => `
      <text class="attack-graph-column-label" x="${column.x}" y="34">${escapeHtml(column.label)}</text>
    `).join('');

    svg.classList.toggle('attack-graph-focus-mode', Boolean(selectedPath));
    svg.innerHTML = `${headers}${edges}${nodes}`;
  }

  function renderPathList() {
    const list = document.getElementById('attack-graph-path-list');
    if (!state.filteredPaths.length) {
      list.innerHTML = '<div class="text-muted small">No attack paths match this filter.</div>';
      return;
    }
    list.innerHTML = state.filteredPaths.slice(0, 12).map((path) => `
      <button class="list-group-item list-group-item-action attack-graph-path-item ${getPathSeverityClass(path.finding_severity)}${path.id === state.selectedPathId ? ' active' : ''}" type="button" data-path-id="${escapeHtml(path.id)}">
        <span class="attack-graph-path-title">${escapeHtml(formatIdentityLabel(path.identity_name, path.identity_id))} to ${escapeHtml(formatResourceLabel(path.resource_name, path.resource_id))}</span>
        <span class="attack-graph-path-meta">${escapeHtml(path.finding_severity)} &middot; Length ${escapeHtml(path.path_length)} &middot; ${escapeHtml(path.related_finding_count)} findings</span>
      </button>
    `).join('');
  }

  function renderDetails() {
    const detail = document.getElementById('attack-graph-detail');
    const selectedPath = getSelectedPath();
    const selectedNode = getSelectedNode();

    if (selectedPath) {
      detail.innerHTML = `
        <dl class="row mb-0 attack-graph-detail-list">
          <dt class="col-5">Identity</dt><dd class="col-7">${escapeHtml(formatIdentityLabel(selectedPath.identity_name, selectedPath.identity_id))}</dd>
          <dt class="col-5">Resource</dt><dd class="col-7">${escapeHtml(formatResourceLabel(selectedPath.resource_name, selectedPath.resource_id))}</dd>
          <dt class="col-5">Path Length</dt><dd class="col-7">${escapeHtml(selectedPath.path_length)}</dd>
          <dt class="col-5">Severity</dt><dd class="col-7">${escapeHtml(selectedPath.finding_severity)}</dd>
          <dt class="col-5">Sensitivity</dt><dd class="col-7">${selectedPath.resource_sensitive ? 'Sensitive' : 'Not sensitive'}</dd>
          <dt class="col-5">Findings</dt><dd class="col-7">${escapeHtml(selectedPath.related_finding_count)}</dd>
        </dl>
      `;
      return;
    }

    if (selectedNode) {
      detail.innerHTML = `
        <dl class="row mb-0 attack-graph-detail-list">
          <dt class="col-5">Label</dt><dd class="col-7">${escapeHtml(selectedNode.label)}</dd>
          <dt class="col-5">Type</dt><dd class="col-7">${escapeHtml(formatNodeType(selectedNode.type))}</dd>
          <dt class="col-5">Findings</dt><dd class="col-7">${escapeHtml(selectedNode.related_finding_count)}</dd>
          <dt class="col-5">Sensitivity</dt><dd class="col-7">${selectedNode.sensitive_resource ? 'Sensitive resource' : 'N/A'}</dd>
          <dt class="col-5">Risk Flags</dt><dd class="col-7">${escapeHtml(formatRiskFlags(selectedNode))}</dd>
        </dl>
      `;
      return;
    }

    detail.textContent = 'Select a node or path.';
    detail.classList.add('text-muted');
  }

  function formatRiskFlags(node) {
    const flags = [];
    if (node.external_identity) flags.push('External identity');
    if (node.service_account) flags.push('Service account');
    if (node.privileged_role) flags.push('Privileged role');
    if (node.sensitive_resource) flags.push('Sensitive resource');
    if (node.critical_high_finding) flags.push('Critical/high finding');
    return flags.join(', ') || 'None';
  }

  function formatNodeType(type) {
    return String(type || 'unknown').replaceAll('_', ' ');
  }

  function formatRelationship(relationship) {
    return String(relationship || 'related_to').replaceAll('_', ' ');
  }

  function truncateLabel(label, maxLength) {
    const value = String(label || '');
    return value.length > maxLength ? `${value.slice(0, maxLength - 3)}...` : value;
  }

  function selectNode(nodeId) {
    state.selectedNodeId = nodeId;
    state.selectedPathId = null;
    renderGraph();
    renderPathList();
    renderDetails();
  }

  function selectPath(pathId) {
    state.selectedPathId = pathId;
    state.selectedNodeId = null;
    renderGraph();
    renderPathList();
    renderDetails();
  }

  function setFilterMode(filterMode) {
    state.filterMode = filterMode;
    refreshFilteredGraph();
  }

  function refreshFilteredGraph() {
    state.filteredPaths = getFilteredPaths();
    if (state.selectedPathId && !state.filteredPaths.some((path) => path.id === state.selectedPathId)) {
      state.selectedPathId = null;
    }
    if (state.selectedNodeId && !getVisibleNodeIds().has(state.selectedNodeId)) {
      state.selectedNodeId = null;
    }
    renderGraph();
    renderPathList();
    renderDetails();
  }

  function wireEvents() {
    document.getElementById('attack-graph-svg').addEventListener('click', (event) => {
      const node = event.target.closest('.attack-graph-node');
      if (node) {
        selectNode(node.dataset.nodeId);
      }
    });
    document.getElementById('attack-graph-path-list').addEventListener('click', (event) => {
      const path = event.target.closest('.attack-graph-path-item');
      if (path) {
        selectPath(path.dataset.pathId);
      }
    });
    document.getElementById('attack-graph-filter-controls').addEventListener('click', (event) => {
      const button = event.target.closest('[data-filter-mode]');
      if (!button) {
        return;
      }
      document.querySelectorAll('[data-filter-mode]').forEach((control) => {
        control.classList.toggle('active', control === button);
      });
      setFilterMode(button.dataset.filterMode);
    });
  }

  async function initAttackGraph() {
    setLoading(true);
    showError('');
    try {
      state.graph = await fetchGraph();
      refreshFilteredGraph();
    } catch (error) {
      showError('Attack graph data could not be loaded.');
    } finally {
      setLoading(false);
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    wireEvents();
    initAttackGraph();
  });
})();

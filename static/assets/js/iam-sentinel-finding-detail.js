(() => {
  const ui = window.IamSentinelUI || {};
  const formatTimestamp = ui.formatTimestamp || ((timestamp) => timestamp);
  const formatStatus = ui.formatStatus || ((status) => status);
  const severityBadgeClasses = {
    CRITICAL: 'badge bg-danger',
    HIGH: 'badge bg-warning text-dark',
    MEDIUM: 'badge bg-warning-subtle text-dark border border-warning',
    LOW: 'badge bg-success'
  };

  const state = {
    findingId: null,
    finding: null
  };

  function getElement(id) {
    return document.getElementById(id);
  }

  function escapeHtml(value) {
    return String(value ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#039;');
  }

  function setText(id, value) {
    const element = getElement(id);
    if (!element) {
      return;
    }

    element.textContent = value ?? '';
  }

  function setHtml(id, value) {
    const element = getElement(id);
    if (!element) {
      return;
    }

    element.innerHTML = value ?? '';
  }

  function setInputValue(id, value) {
    const element = getElement(id);
    if (!element) {
      return;
    }

    element.value = value ?? '';
  }

  function getInputValue(id) {
    const element = getElement(id);
    return element ? element.value : '';
  }

  function showAlert(id, message, type = 'success') {
    const alert = getElement(id);
    if (!alert) {
      return;
    }

    alert.textContent = message;
    alert.className = `alert alert-${type}`;
    alert.classList.toggle('d-none', !message);
  }

  function showLoading(isLoading) {
    const loading = getElement('finding-detail-loading');
    if (!loading) {
      return;
    }

    loading.classList.toggle('d-none', !isLoading);
  }

  function showNotFound(isNotFound) {
    const notFound = getElement('finding-not-found');
    const content = getElement('finding-detail-content');
    if (notFound) {
      notFound.classList.toggle('d-none', !isNotFound);
    }
    if (content) {
      content.classList.toggle('d-none', isNotFound);
    }
  }

  async function fetchJson(url, options = {}) {
    const response = await fetch(url, options);
    if (!response.ok) {
      throw new Error(`Request failed: ${response.status}`);
    }
    return response.json();
  }

  function normalizeItems(items) {
    if (Array.isArray(items)) {
      return items;
    }
    return items ? [items] : [];
  }

  function renderList(id, items) {
    const normalizedItems = normalizeItems(items);
    if (!normalizedItems.length) {
      setHtml(id, '<li class="text-muted">None</li>');
      return;
    }

    setHtml(id, normalizedItems.map((item) => `<li>${escapeHtml(item)}</li>`).join(''));
  }

  function renderLinks(finding) {
    setHtml('finding-detail-links', `
      <a class="btn btn-sm btn-outline-primary" href="/identities/${encodeURIComponent(finding.identity_id)}">Identity ${escapeHtml(finding.identity_id)}</a>
      ${finding.resource_id ? `<a class="btn btn-sm btn-outline-primary" href="/resources/${encodeURIComponent(finding.resource_id)}">Resource ${escapeHtml(finding.resource_id)}</a>` : ''}
    `);
  }

  function renderActivityList(finding) {
    const activityItems = normalizeItems(finding.activity);
    const activity = activityItems.length
      ? activityItems
      : [{
        type: 'CREATED',
        message: 'Finding created.',
        created_at: finding.created_at
      }];

    setHtml('finding-detail-activity', activity.map((entry) => {
      const safeEntry = {
        type: entry.type || 'ACTIVITY',
        message: entry.message || '',
        created_at: entry.created_at || finding.created_at
      };
      return `
        <li class="list-group-item">
          <div class="d-flex justify-content-between gap-3">
            <strong>${escapeHtml(safeEntry.type)}</strong>
            <span class="text-muted small">${escapeHtml(formatTimestamp(safeEntry.created_at))}</span>
          </div>
          <div>${escapeHtml(safeEntry.message)}</div>
        </li>
      `;
    }).join(''));
  }

  function renderFinding(finding) {
    const severityClass = severityBadgeClasses[finding.severity] || 'badge bg-secondary';

    setText('finding-detail-title', finding.title);
    setText('finding-detail-meta', `${finding.id} | ${finding.identity_id}`);
    renderLinks(finding);
    setHtml('finding-detail-severity', `<span class="${severityClass}">${escapeHtml(finding.severity)}</span>`);
    setText('finding-detail-score', finding.score);
    setText('finding-detail-status', formatStatus(finding.status));
    setText('finding-detail-owner', finding.owner || 'Unassigned');
    setText('finding-detail-created-at', formatTimestamp(finding.created_at));
    setText('finding-detail-updated-at', formatTimestamp(finding.updated_at));
    setText('finding-detail-description', finding.description);
    setText('finding-detail-risk-explanation', finding.risk_explanation || 'No risk explanation available.');
    setText('finding-detail-recommendation', finding.recommendation);
    setInputValue('finding-status-select', finding.status);
    setInputValue('finding-owner-input', finding.owner || '');
    setInputValue('finding-note-input', '');

    renderList('finding-detail-evidence', finding.evidence);
    renderList('finding-detail-risk-factors', finding.risk_factors);
    renderList('finding-detail-attack-paths', finding.attack_paths);
    renderList('finding-detail-notes', finding.analyst_notes);
    renderActivityList(finding);
  }

  async function refreshFinding() {
    showLoading(true);
    showAlert('finding-action-feedback', '');

    try {
      const findings = await fetchJson('/api/findings');
      const findingsList = Array.isArray(findings) ? findings : (findings && findings.value) || [];
      state.finding = findingsList.find((finding) => finding.id === state.findingId);
      if (!state.finding) {
        console.error('Finding detail finding not found.', state.findingId);
        showNotFound(true);
        return;
      }

      showNotFound(false);
      try {
        renderFinding(state.finding);
      } catch (error) {
        console.error('Finding detail render failed.', error);
        showAlert('finding-action-feedback', 'Finding data could not be rendered.', 'danger');
      }
    } catch (error) {
      console.error('Finding detail fetch failed.', error);
      showAlert('finding-action-feedback', 'Finding data could not be loaded.', 'danger');
    } finally {
      showLoading(false);
    }
  }

  async function updateFinding(endpointSuffix, payload, successMessage) {
    try {
      await fetchJson(`/api/findings/${encodeURIComponent(state.findingId)}/${endpointSuffix}`, {
        method: endpointSuffix === 'notes' ? 'POST' : 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      await refreshFinding();
      showAlert('finding-action-feedback', successMessage, 'success');
    } catch (error) {
      showAlert('finding-action-feedback', 'Finding update failed.', 'danger');
    }
  }

  async function saveFindingStatus() {
    await updateFinding(
      'status',
      { status: getInputValue('finding-status-select') },
      'Status updated.'
    );
  }

  async function saveFindingOwner() {
    await updateFinding(
      'owner',
      { owner: getInputValue('finding-owner-input') },
      'Owner updated.'
    );
  }

  async function addFindingNote() {
    const note = getInputValue('finding-note-input').trim();
    if (!note) {
      showAlert('finding-action-feedback', 'Enter a note before adding it.', 'warning');
      return;
    }

    await updateFinding('notes', { note }, 'Note added.');
  }

  function wireEvents() {
    const saveStatusButton = getElement('save-status-button');
    const saveOwnerButton = getElement('save-owner-button');
    const addNoteButton = getElement('add-note-button');

    if (saveStatusButton) {
      saveStatusButton.addEventListener('click', saveFindingStatus);
    }
    if (saveOwnerButton) {
      saveOwnerButton.addEventListener('click', saveFindingOwner);
    }
    if (addNoteButton) {
      addNoteButton.addEventListener('click', addFindingNote);
    }
  }

  function initFindingDetail() {
    const page = getElement('finding-investigation-page');
    if (!page) {
      console.error('Finding detail page root is missing.');
      return;
    }

    state.findingId = page.dataset.findingId;
    if (!state.findingId) {
      console.error('Finding detail findingId is missing.');
      return;
    }

    wireEvents();
    refreshFinding();
  }

  document.addEventListener('DOMContentLoaded', initFindingDetail);
})();

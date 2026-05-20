(() => {
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

  function escapeHtml(value) {
    return String(value ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#039;');
  }

  function setText(id, value) {
    document.getElementById(id).textContent = value ?? '';
  }

  function showAlert(id, message, type = 'success') {
    const alert = document.getElementById(id);
    alert.textContent = message;
    alert.className = `alert alert-${type}`;
    alert.classList.toggle('d-none', !message);
  }

  function showLoading(isLoading) {
    document.getElementById('finding-detail-loading').classList.toggle('d-none', !isLoading);
  }

  function showNotFound(isNotFound) {
    document.getElementById('finding-not-found').classList.toggle('d-none', !isNotFound);
    document.getElementById('finding-detail-content').classList.toggle('d-none', isNotFound);
  }

  async function fetchJson(url, options = {}) {
    const response = await fetch(url, options);
    if (!response.ok) {
      throw new Error(`Request failed: ${response.status}`);
    }
    return response.json();
  }

  function renderList(id, items) {
    const list = document.getElementById(id);
    if (!items || !items.length) {
      list.innerHTML = '<li class="text-muted">None</li>';
      return;
    }

    list.innerHTML = items.map((item) => `<li>${escapeHtml(item)}</li>`).join('');
  }

  function renderActivityList(finding) {
    const list = document.getElementById('finding-detail-activity');
    const activity = finding.activity && finding.activity.length
      ? finding.activity
      : [{
        type: 'CREATED',
        message: 'Finding created.',
        created_at: finding.created_at
      }];

    list.innerHTML = activity.map((entry) => `
      <li class="list-group-item">
        <div class="d-flex justify-content-between gap-3">
          <strong>${escapeHtml(entry.type)}</strong>
          <span class="text-muted small">${escapeHtml(entry.created_at)}</span>
        </div>
        <div>${escapeHtml(entry.message)}</div>
      </li>
    `).join('');
  }

  function renderFinding(finding) {
    const severityClass = severityBadgeClasses[finding.severity] || 'badge bg-secondary';

    setText('finding-detail-title', finding.title);
    setText('finding-detail-meta', `${finding.id} | ${finding.identity_id}`);
    document.getElementById('finding-detail-links').innerHTML = `
      <a class="btn btn-sm btn-outline-primary" href="/identities/${encodeURIComponent(finding.identity_id)}">Identity ${escapeHtml(finding.identity_id)}</a>
      ${finding.resource_id ? `<a class="btn btn-sm btn-outline-primary" href="/resources/${encodeURIComponent(finding.resource_id)}">Resource ${escapeHtml(finding.resource_id)}</a>` : ''}
    `;
    document.getElementById('finding-detail-severity').innerHTML = `<span class="${severityClass}">${escapeHtml(finding.severity)}</span>`;
    setText('finding-detail-score', finding.score);
    setText('finding-detail-status', finding.status);
    setText('finding-detail-owner', finding.owner || 'Unassigned');
    setText('finding-detail-created-at', finding.created_at);
    setText('finding-detail-updated-at', finding.updated_at);
    setText('finding-detail-description', finding.description);
    setText('finding-detail-risk-explanation', finding.risk_explanation || 'No risk explanation available.');
    setText('finding-detail-recommendation', finding.recommendation);
    document.getElementById('finding-status-select').value = finding.status;
    document.getElementById('finding-owner-input').value = finding.owner || '';
    document.getElementById('finding-note-input').value = '';

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
      state.finding = findings.find((finding) => finding.id === state.findingId);
      if (!state.finding) {
        showNotFound(true);
        return;
      }

      showNotFound(false);
      renderFinding(state.finding);
    } catch (error) {
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
      { status: document.getElementById('finding-status-select').value },
      'Status updated.'
    );
  }

  async function saveFindingOwner() {
    await updateFinding(
      'owner',
      { owner: document.getElementById('finding-owner-input').value },
      'Owner updated.'
    );
  }

  async function addFindingNote() {
    const note = document.getElementById('finding-note-input').value.trim();
    if (!note) {
      showAlert('finding-action-feedback', 'Enter a note before adding it.', 'warning');
      return;
    }

    await updateFinding('notes', { note }, 'Note added.');
  }

  function wireEvents() {
    document.getElementById('save-status-button').addEventListener('click', saveFindingStatus);
    document.getElementById('save-owner-button').addEventListener('click', saveFindingOwner);
    document.getElementById('add-note-button').addEventListener('click', addFindingNote);
  }

  function initFindingDetail() {
    const page = document.getElementById('finding-investigation-page');
    state.findingId = page.dataset.findingId;
    wireEvents();
    refreshFinding();
  }

  document.addEventListener('DOMContentLoaded', initFindingDetail);
})();

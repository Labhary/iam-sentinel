(() => {
  const severityBadgeClasses = {
    CRITICAL: 'badge bg-danger',
    HIGH: 'badge bg-warning text-dark',
    MEDIUM: 'badge bg-warning-subtle text-dark border border-warning',
    LOW: 'badge bg-success'
  };

  const state = {
    currentFindings: [],
    filteredFindings: [],
    selectedFindingIds: new Set(),
    selectedFindingId: null,
    findingModal: null
  };

  function setText(id, value) {
    document.getElementById(id).textContent = value ?? '0';
  }

  function escapeHtml(value) {
    return String(value ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#039;');
  }

  function showAlert(id, message, type = 'success') {
    const alert = document.getElementById(id);
    alert.textContent = message;
    alert.className = `alert alert-${type}`;
    alert.classList.toggle('d-none', !message);
  }

  function showLoading(isLoading) {
    document.getElementById('dashboard-loading').classList.toggle('d-none', !isLoading);
  }

  function showError(message) {
    const error = document.getElementById('dashboard-error');
    error.textContent = message;
    error.classList.toggle('d-none', !message);
  }

  async function fetchJson(url, options = {}) {
    const response = await fetch(url, options);
    if (!response.ok) {
      throw new Error(`Request failed: ${response.status}`);
    }
    return response.json();
  }

  function getControlValue(id) {
    return document.getElementById(id).value;
  }

  function getOwnerState(finding) {
    return finding.owner ? 'ASSIGNED' : 'UNASSIGNED';
  }

  function matchesSearch(finding, searchTerm) {
    if (!searchTerm) {
      return true;
    }

    return [
      finding.title,
      finding.identity_id,
      finding.finding_type,
      finding.owner
    ].some((value) => String(value ?? '').toLowerCase().includes(searchTerm));
  }

  function sortFindings(findings) {
    const severityRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    const sortValue = getControlValue('findings-sort');

    return [...findings].sort((left, right) => {
      if (sortValue === 'severity_desc') {
        return (severityRank[right.severity] || 0) - (severityRank[left.severity] || 0);
      }
      if (sortValue === 'score_desc') {
        return (right.score || 0) - (left.score || 0);
      }
      if (sortValue === 'status') {
        return String(left.status || '').localeCompare(String(right.status || ''));
      }
      return String(left.title || '').localeCompare(String(right.title || ''));
    });
  }

  function getFilteredFindings() {
    const severityFilter = getControlValue('severity-filter');
    const statusFilter = getControlValue('status-filter');
    const ownerFilter = getControlValue('owner-filter');
    const searchTerm = getControlValue('findings-search').trim().toLowerCase();

    return sortFindings(state.currentFindings.filter((finding) => {
      const matchesSeverity = severityFilter === 'ALL' || finding.severity === severityFilter;
      const matchesStatus = statusFilter === 'ALL' || finding.status === statusFilter;
      const matchesOwner = ownerFilter === 'ALL' || getOwnerState(finding) === ownerFilter;
      return matchesSeverity && matchesStatus && matchesOwner && matchesSearch(finding, searchTerm);
    }));
  }

  function renderFindingsCount() {
    document.getElementById('findings-count').textContent = `Showing ${state.filteredFindings.length} of ${state.currentFindings.length} findings`;
    document.getElementById('export-csv-button').disabled = state.filteredFindings.length === 0;
  }

  function renderSelectionControls() {
    const visibleIds = state.filteredFindings.map((finding) => finding.id);
    const selectedVisibleCount = visibleIds.filter((id) => state.selectedFindingIds.has(id)).length;
    const selectAll = document.getElementById('select-all-findings');

    document.getElementById('selected-findings-count').textContent = `${state.selectedFindingIds.size} selected`;
    selectAll.checked = visibleIds.length > 0 && selectedVisibleCount === visibleIds.length;
    selectAll.indeterminate = selectedVisibleCount > 0 && selectedVisibleCount < visibleIds.length;
    document.getElementById('bulk-status-button').disabled = state.selectedFindingIds.size === 0;
    document.getElementById('bulk-owner-button').disabled = state.selectedFindingIds.size === 0;
  }

  function renderFindings(findings) {
    const tableBody = document.getElementById('findings-table-body');
    const rows = findings.length
      ? findings.map((finding) => {
        const severity = escapeHtml(finding.severity);
        const badgeClass = severityBadgeClasses[finding.severity] || 'badge bg-secondary';
        const checked = state.selectedFindingIds.has(finding.id) ? 'checked' : '';
        return `
          <tr class="finding-row" data-finding-id="${escapeHtml(finding.id)}" role="button" tabindex="0">
            <td>
              <input class="form-check-input finding-checkbox" type="checkbox" value="${escapeHtml(finding.id)}" aria-label="Select finding" ${checked}>
            </td>
            <td><span class="${badgeClass}">${severity}</span></td>
            <td>${escapeHtml(finding.title)}</td>
            <td>${escapeHtml(finding.identity_id)}</td>
            <td>${escapeHtml(finding.score)}</td>
            <td>${escapeHtml(finding.status)}</td>
            <td>${escapeHtml(finding.owner || 'Unassigned')}</td>
          </tr>
        `;
      }).join('')
      : '<tr><td colspan="7" class="text-muted">No findings match the current filters.</td></tr>';
    tableBody.innerHTML = rows;
  }

  function applyFindingControls() {
    state.filteredFindings = getFilteredFindings();
    renderFindings(state.filteredFindings);
    renderFindingsCount();
    renderSelectionControls();
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

  function getSelectedFinding() {
    return state.currentFindings.find((finding) => finding.id === state.selectedFindingId);
  }

  function renderFindingDetail(finding) {
    if (!finding) {
      return;
    }

    const severityClass = severityBadgeClasses[finding.severity] || 'badge bg-secondary';
    document.getElementById('finding-detail-title').textContent = finding.title;
    document.getElementById('finding-detail-meta').textContent = `${finding.id} | ${finding.identity_id}`;
    document.getElementById('finding-detail-severity').innerHTML = `<span class="${severityClass}">${escapeHtml(finding.severity)}</span>`;
    document.getElementById('finding-detail-score').textContent = finding.score;
    document.getElementById('finding-detail-status').textContent = finding.status;
    document.getElementById('finding-detail-owner').textContent = finding.owner || 'Unassigned';
    document.getElementById('finding-detail-created-at').textContent = finding.created_at || '';
    document.getElementById('finding-detail-updated-at').textContent = finding.updated_at || '';
    document.getElementById('finding-detail-description').textContent = finding.description || '';
    document.getElementById('finding-detail-recommendation').textContent = finding.recommendation || '';
    document.getElementById('finding-status-select').value = finding.status;
    document.getElementById('finding-owner-input').value = finding.owner || '';
    document.getElementById('finding-note-input').value = '';

    renderList('finding-detail-evidence', finding.evidence);
    renderList('finding-detail-attack-paths', finding.attack_paths);
    renderList('finding-detail-notes', finding.analyst_notes);
    renderActivityList(finding);
  }

  function openFindingDetail(findingId) {
    state.selectedFindingId = findingId;
    showAlert('finding-action-feedback', '');
    renderFindingDetail(getSelectedFinding());
    state.findingModal.show();
  }

  function refreshSelectedFindingDetail() {
    const selectedFinding = getSelectedFinding();
    if (selectedFinding) {
      renderFindingDetail(selectedFinding);
      return;
    }

    state.selectedFindingId = null;
  }

  async function refreshDashboard() {
    showLoading(true);
    showError('');

    try {
      const findings = await fetchJson('/api/findings');
      state.currentFindings = findings;
      state.selectedFindingIds = new Set([...state.selectedFindingIds].filter((id) => state.currentFindings.some((finding) => finding.id === id)));
      applyFindingControls();
      refreshSelectedFindingDetail();
    } catch (error) {
      showError('Dashboard data could not be loaded.');
    } finally {
      showLoading(false);
    }
  }

  async function updateFinding(url, payload, successMessage) {
    if (!state.selectedFindingId) {
      return;
    }

    try {
      await fetchJson(url, {
        method: url.endsWith('/notes') ? 'POST' : 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      await refreshDashboard();
      showAlert('finding-action-feedback', successMessage, 'success');
    } catch (error) {
      showAlert('finding-action-feedback', 'Finding update failed.', 'danger');
    }
  }

  async function saveFindingStatus() {
    await updateFinding(
      `/api/findings/${state.selectedFindingId}/status`,
      { status: document.getElementById('finding-status-select').value },
      'Status updated.'
    );
  }

  async function saveFindingOwner() {
    await updateFinding(
      `/api/findings/${state.selectedFindingId}/owner`,
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

    await updateFinding(
      `/api/findings/${state.selectedFindingId}/notes`,
      { note },
      'Note added.'
    );
  }

  function csvEscape(value) {
    const text = String(value ?? '');
    if (/[",\r\n]/.test(text)) {
      return `"${text.replaceAll('"', '""')}"`;
    }
    return text;
  }

  function exportFilteredFindings() {
    const columns = [
      'id',
      'severity',
      'score',
      'status',
      'owner',
      'identity_id',
      'finding_type',
      'title'
    ];
    const rows = state.filteredFindings.map((finding) => columns.map((column) => csvEscape(finding[column])).join(','));
    const csv = [columns.join(','), ...rows].join('\r\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'iam-sentinel-findings.csv';
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  function toggleFindingSelection(findingId, isSelected) {
    if (isSelected) {
      state.selectedFindingIds.add(findingId);
    } else {
      state.selectedFindingIds.delete(findingId);
    }
    renderSelectionControls();
  }

  function toggleVisibleFindingsSelection(isSelected) {
    state.filteredFindings.forEach((finding) => {
      if (isSelected) {
        state.selectedFindingIds.add(finding.id);
      } else {
        state.selectedFindingIds.delete(finding.id);
      }
    });
    renderFindings(state.filteredFindings);
    renderSelectionControls();
  }

  async function applyBulkAction(endpointSuffix, payload, successMessage) {
    const findingIds = [...state.selectedFindingIds];
    if (!findingIds.length) {
      showAlert('bulk-action-feedback', 'Select at least one finding.', 'warning');
      return;
    }

    showAlert('bulk-action-feedback', '');
    try {
      await Promise.all(findingIds.map((findingId) => fetchJson(`/api/findings/${findingId}/${endpointSuffix}`, {
        method: endpointSuffix === 'notes' ? 'POST' : 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      })));
      state.selectedFindingIds.clear();
      await refreshDashboard();
      showAlert('bulk-action-feedback', successMessage, 'success');
    } catch (error) {
      showAlert('bulk-action-feedback', 'Bulk action failed.', 'danger');
    }
  }

  async function applyBulkStatus() {
    const status = document.getElementById('bulk-status-select').value;
    if (!status) {
      showAlert('bulk-action-feedback', 'Choose a status before applying a bulk update.', 'warning');
      return;
    }

    await applyBulkAction('status', { status }, 'Bulk status update complete.');
  }

  async function applyBulkOwner() {
    const owner = document.getElementById('bulk-owner-input').value;
    await applyBulkAction('owner', { owner }, 'Bulk owner assignment complete.');
  }

  function wireEvents() {
    document.getElementById('findings-search').addEventListener('input', applyFindingControls);
    document.getElementById('severity-filter').addEventListener('change', applyFindingControls);
    document.getElementById('status-filter').addEventListener('change', applyFindingControls);
    document.getElementById('owner-filter').addEventListener('change', applyFindingControls);
    document.getElementById('findings-sort').addEventListener('change', applyFindingControls);
    document.getElementById('export-csv-button').addEventListener('click', exportFilteredFindings);
    document.getElementById('select-all-findings').addEventListener('change', (event) => {
      toggleVisibleFindingsSelection(event.target.checked);
    });
    document.getElementById('bulk-status-button').addEventListener('click', applyBulkStatus);
    document.getElementById('bulk-owner-button').addEventListener('click', applyBulkOwner);
    document.getElementById('findings-table-body').addEventListener('click', handleTableClick);
    document.getElementById('findings-table-body').addEventListener('change', handleTableChange);
    document.getElementById('findings-table-body').addEventListener('keydown', handleTableKeydown);
    document.getElementById('save-status-button').addEventListener('click', saveFindingStatus);
    document.getElementById('save-owner-button').addEventListener('click', saveFindingOwner);
    document.getElementById('add-note-button').addEventListener('click', addFindingNote);
  }

  function handleTableClick(event) {
    if (event.target.closest('.finding-checkbox')) {
      return;
    }

    const row = event.target.closest('.finding-row');
    if (row) {
      openFindingDetail(row.dataset.findingId);
    }
  }

  function handleTableChange(event) {
    const checkbox = event.target.closest('.finding-checkbox');
    if (checkbox) {
      toggleFindingSelection(checkbox.value, checkbox.checked);
    }
  }

  function handleTableKeydown(event) {
    if (event.key !== 'Enter' || event.target.closest('.finding-checkbox')) {
      return;
    }

    const row = event.target.closest('.finding-row');
    if (row) {
      openFindingDetail(row.dataset.findingId);
    }
  }

  function initDashboard() {
    state.findingModal = new bootstrap.Modal(document.getElementById('finding-detail-modal'));
    wireEvents();
    refreshDashboard();
  }

  document.addEventListener('DOMContentLoaded', initDashboard);
})();

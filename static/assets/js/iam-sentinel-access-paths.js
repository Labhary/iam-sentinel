(() => {
  const ui = window.IamSentinelUI || {};
  const formatIdentityLabel = ui.formatIdentityLabel || ((name, id) => name || id || '');
  const formatResourceLabel = ui.formatResourceLabel || ((name, id) => name || id || '');
  const state = {
    accessPaths: [],
    filteredAccessPaths: [],
    pager: null
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
    document.getElementById(id).textContent = value ?? '0';
  }

  function showLoading(isLoading) {
    document.getElementById('access-paths-loading').classList.toggle('d-none', !isLoading);
  }

  function showError(message) {
    const error = document.getElementById('access-paths-error');
    error.textContent = message;
    error.classList.toggle('d-none', !message);
  }

  function showFeedback(message, type = 'success') {
    const feedback = document.getElementById('access-paths-feedback');
    feedback.textContent = message;
    feedback.className = `alert alert-${type}`;
    feedback.classList.toggle('d-none', !message);
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

  function buildApiUrl() {
    const params = new URLSearchParams();
    const identityId = getControlValue('access-path-identity-filter').trim();
    const resourceId = getControlValue('access-path-resource-filter').trim();
    const sensitiveOnly = document.getElementById('access-path-sensitive-only').checked;

    if (identityId) {
      params.set('identity_id', identityId);
    }
    if (resourceId) {
      params.set('resource_id', resourceId);
    }
    if (sensitiveOnly) {
      params.set('sensitive_only', 'true');
    }

    const queryString = params.toString();
    return queryString ? `/api/access-paths?${queryString}` : '/api/access-paths';
  }

  function matchesSearch(accessPath, searchTerm) {
    if (!searchTerm) {
      return true;
    }

    return [
      accessPath.identity_id,
      accessPath.identity_name,
      accessPath.resource_id,
      accessPath.resource_name,
      accessPath.path_display
    ].some((value) => String(value ?? '').toLowerCase().includes(searchTerm));
  }

  function getFilteredAccessPaths() {
    const searchTerm = getControlValue('access-paths-search').trim().toLowerCase();
    return state.accessPaths.filter((accessPath) => matchesSearch(accessPath, searchTerm));
  }

  function renderSummary() {
    setText('total-access-paths', state.accessPaths.length);
    setText('sensitive-resource-paths', state.accessPaths.filter((path) => path.resource_sensitive).length);
    setText('external-identity-paths', state.accessPaths.filter((path) => path.identity_external_user).length);
    setText('service-account-paths', state.accessPaths.filter((path) => path.identity_service_account).length);
  }

  function sensitiveBadge(isSensitive) {
    const badgeClass = isSensitive ? 'badge bg-danger' : 'badge bg-success';
    return `<span class="${badgeClass}">${isSensitive ? 'Sensitive' : 'Not Sensitive'}</span>`;
  }

  function renderAccessPaths(accessPaths) {
    const tableBody = document.getElementById('access-paths-table-body');
    const rows = accessPaths.length
      ? accessPaths.map((accessPath) => {
        const pathDisplay = escapeHtml(accessPath.path_display);
        return `
        <tr class="access-path-row">
          <td>
            <div class="access-path-name">${escapeHtml(formatIdentityLabel(accessPath.identity_name, accessPath.identity_id))}</div>
          </td>
          <td>
            <div class="access-path-name">${escapeHtml(formatResourceLabel(accessPath.resource_name, accessPath.resource_id))}</div>
          </td>
          <td>${sensitiveBadge(accessPath.resource_sensitive)}</td>
          <td>${escapeHtml(accessPath.path_length)}</td>
          <td><span class="table-truncate access-path-display" title="${pathDisplay}">${pathDisplay}</span></td>
          <td>
            <div class="btn-group btn-group-sm access-path-actions" role="group" aria-label="Access path actions">
              <a class="btn btn-outline-secondary access-path-action-button" href="/identities/${encodeURIComponent(accessPath.identity_id)}">Identity</a>
              <a class="btn btn-outline-secondary" href="/resources/${encodeURIComponent(accessPath.resource_id)}">Resource</a>
              <button class="btn btn-outline-secondary create-review-button" type="button" data-identity-id="${escapeHtml(accessPath.identity_id)}" data-resource-id="${escapeHtml(accessPath.resource_id)}">Create Review</button>
            </div>
          </td>
        </tr>
      `;
      }).join('')
      : '<tr><td colspan="6" class="text-muted">No access paths match the current filters.</td></tr>';
    tableBody.innerHTML = rows;
  }

  function applyAccessPathSearch() {
    state.filteredAccessPaths = getFilteredAccessPaths();
    renderAccessPaths(state.pager.paginate(state.filteredAccessPaths));
  }

  function resetPaginationAndApplySearch() {
    state.pager.resetPage();
    applyAccessPathSearch();
  }

  async function refreshAccessPathsWorkbench() {
    showLoading(true);
    showError('');

    try {
      state.accessPaths = await fetchJson(buildApiUrl());
      renderSummary();
      applyAccessPathSearch();
    } catch (error) {
      showError('Access path data could not be loaded.');
    } finally {
      showLoading(false);
    }
  }

  function wireEvents() {
    state.pager.wireEvents(applyAccessPathSearch);
    document.getElementById('access-paths-search').addEventListener('input', resetPaginationAndApplySearch);
    document.getElementById('access-path-identity-filter').addEventListener('input', resetPaginationAndRefreshWorkbench);
    document.getElementById('access-path-resource-filter').addEventListener('input', resetPaginationAndRefreshWorkbench);
    document.getElementById('access-path-sensitive-only').addEventListener('change', resetPaginationAndRefreshWorkbench);
    document.getElementById('access-paths-table-body').addEventListener('click', handleAccessPathAction);
  }

  function resetPaginationAndRefreshWorkbench() {
    state.pager.resetPage();
    refreshAccessPathsWorkbench();
  }

  async function handleAccessPathAction(event) {
    const button = event.target.closest('.create-review-button');
    if (!button) {
      return;
    }

    showFeedback('');
    try {
      await fetchJson('/api/access-reviews', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identity_id: button.dataset.identityId,
          resource_id: button.dataset.resourceId
        })
      });
      showFeedback('Access review created.');
    } catch (error) {
      showFeedback('An active review already exists or the review could not be created.', 'warning');
    }
  }

  function initAccessPathsWorkbench() {
    state.pager = window.IamSentinelPagination.createTablePager({
      countId: 'access-paths-count',
      summaryId: 'access-paths-pagination-summary',
      pageSizeId: 'access-paths-page-size',
      prevButtonId: 'access-paths-prev-page',
      nextButtonId: 'access-paths-next-page',
      itemLabel: 'paths'
    });
    wireEvents();
    refreshAccessPathsWorkbench();
  }

  document.addEventListener('DOMContentLoaded', initAccessPathsWorkbench);
})();

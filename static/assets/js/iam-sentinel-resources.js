(() => {
  const ui = window.IamSentinelUI || {};
  const formatResourceLabel = ui.formatResourceLabel || ((name, id) => name || id || '');
  const state = {
    resources: [],
    filteredResources: [],
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
    document.getElementById('resources-loading').classList.toggle('d-none', !isLoading);
  }

  function showError(message) {
    const error = document.getElementById('resources-error');
    error.textContent = message;
    error.classList.toggle('d-none', !message);
  }

  async function fetchJson(url) {
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`Request failed: ${response.status}`);
    }
    return response.json();
  }

  function getControlValue(id) {
    return document.getElementById(id).value;
  }

  function formatResourceType(type) {
    const typeLabels = {
      document_store: 'Document Store',
      code_repository: 'Code Repository',
      application: 'Application',
      database: 'Database',
      identity_store: 'Identity Store',
      iam_configuration: 'IAM Configuration',
      business_application: 'Business Application',
      log_archive: 'Log Archive',
      security_application: 'Security Application',
      data_warehouse: 'Data Warehouse'
    };

    if (typeLabels[type]) {
      return typeLabels[type];
    }

    return String(type ?? '')
      .split('_')
      .filter(Boolean)
      .map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
      .join(' ');
  }

  function matchesSearch(resource, searchTerm) {
    if (!searchTerm) {
      return true;
    }

    return [
      resource.id,
      resource.name,
      resource.type,
      formatResourceType(resource.type)
    ].some((value) => String(value ?? '').toLowerCase().includes(searchTerm));
  }

  function getFilteredResources() {
    const sensitiveFilter = getControlValue('sensitive-filter');
    const externalAccessFilter = getControlValue('external-access-filter');
    const serviceAccountAccessFilter = getControlValue('service-account-access-filter');
    const searchTerm = getControlValue('resources-search').trim().toLowerCase();

    return state.resources.filter((resource) => {
      const matchesSensitive = sensitiveFilter === 'ALL' || resource.sensitive;
      const matchesExternalAccess = externalAccessFilter === 'ALL' || resource.external_access_count > 0;
      const matchesServiceAccountAccess = serviceAccountAccessFilter === 'ALL' || resource.service_account_access_count > 0;
      return matchesSensitive && matchesExternalAccess && matchesServiceAccountAccess && matchesSearch(resource, searchTerm);
    });
  }

  function renderSummary() {
    setText('total-resources', state.resources.length);
    setText('sensitive-resources', state.resources.filter((resource) => resource.sensitive).length);
    setText('resources-with-external-access', state.resources.filter((resource) => resource.external_access_count > 0).length);
    setText('resources-with-service-account-access', state.resources.filter((resource) => resource.service_account_access_count > 0).length);
  }

  function statusBadge(isEnabled, enabledText, disabledText) {
    const badgeClass = isEnabled ? 'badge bg-danger' : 'badge bg-success';
    return `<span class="${badgeClass}">${isEnabled ? enabledText : disabledText}</span>`;
  }

  function renderResources(resources) {
    const tableBody = document.getElementById('resources-table-body');
    const rows = resources.length
      ? resources.map((resource) => `
        <tr>
          <td>${escapeHtml(resource.label || formatResourceLabel(resource.name, resource.id))}</td>
          <td><span class="table-nowrap">${escapeHtml(formatResourceType(resource.type))}</span></td>
          <td>${statusBadge(resource.sensitive, 'Sensitive', 'Not Sensitive')}</td>
          <td>${escapeHtml(resource.accessible_by_count)}</td>
          <td>${escapeHtml(resource.external_access_count)}</td>
          <td>${escapeHtml(resource.service_account_access_count)}</td>
          <td>${escapeHtml(resource.related_findings_count)}</td>
          <td>
            <a class="btn btn-sm btn-outline-primary" href="/resources/${encodeURIComponent(resource.id)}">View</a>
          </td>
        </tr>
      `).join('')
      : '<tr><td colspan="8" class="text-muted">No resources match the current filters.</td></tr>';
    tableBody.innerHTML = rows;
  }

  function applyResourceControls() {
    state.filteredResources = getFilteredResources();
    renderResources(state.pager.paginate(state.filteredResources));
  }

  function resetPaginationAndApplyControls() {
    state.pager.resetPage();
    applyResourceControls();
  }

  async function refreshResourcesWorkbench() {
    showLoading(true);
    showError('');

    try {
      state.resources = await fetchJson('/api/resources');
      renderSummary();
      applyResourceControls();
    } catch (error) {
      showError('Resource data could not be loaded.');
    } finally {
      showLoading(false);
    }
  }

  function wireEvents() {
    state.pager.wireEvents(applyResourceControls);
    document.getElementById('resources-search').addEventListener('input', resetPaginationAndApplyControls);
    document.getElementById('sensitive-filter').addEventListener('change', resetPaginationAndApplyControls);
    document.getElementById('external-access-filter').addEventListener('change', resetPaginationAndApplyControls);
    document.getElementById('service-account-access-filter').addEventListener('change', resetPaginationAndApplyControls);
  }

  function initResourcesWorkbench() {
    state.pager = window.IamSentinelPagination.createTablePager({
      countId: 'resources-count',
      summaryId: 'resources-pagination-summary',
      pageSizeId: 'resources-page-size',
      prevButtonId: 'resources-prev-page',
      nextButtonId: 'resources-next-page',
      itemLabel: 'resources'
    });
    wireEvents();
    refreshResourcesWorkbench();
  }

  document.addEventListener('DOMContentLoaded', initResourcesWorkbench);
})();

(() => {
  const state = {
    resources: [],
    filteredResources: []
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

  function matchesSearch(resource, searchTerm) {
    if (!searchTerm) {
      return true;
    }

    return [
      resource.id,
      resource.name,
      resource.type
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

  function renderResourcesCount() {
    document.getElementById('resources-count').textContent = `Showing ${state.filteredResources.length} of ${state.resources.length} resources`;
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
          <td>${escapeHtml(resource.name)}</td>
          <td>${escapeHtml(resource.type)}</td>
          <td>${statusBadge(resource.sensitive, 'Sensitive', 'Not Sensitive')}</td>
          <td>${escapeHtml(resource.accessible_by_count)}</td>
          <td>${escapeHtml(resource.external_access_count)}</td>
          <td>${escapeHtml(resource.service_account_access_count)}</td>
          <td>${escapeHtml(resource.related_findings_count)}</td>
          <td>
            <a class="btn btn-sm btn-outline-primary" href="/resources/${encodeURIComponent(resource.id)}">${escapeHtml(resource.id)}</a>
          </td>
        </tr>
      `).join('')
      : '<tr><td colspan="8" class="text-muted">No resources match the current filters.</td></tr>';
    tableBody.innerHTML = rows;
  }

  function applyResourceControls() {
    state.filteredResources = getFilteredResources();
    renderResources(state.filteredResources);
    renderResourcesCount();
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
    document.getElementById('resources-search').addEventListener('input', applyResourceControls);
    document.getElementById('sensitive-filter').addEventListener('change', applyResourceControls);
    document.getElementById('external-access-filter').addEventListener('change', applyResourceControls);
    document.getElementById('service-account-access-filter').addEventListener('change', applyResourceControls);
  }

  function initResourcesWorkbench() {
    wireEvents();
    refreshResourcesWorkbench();
  }

  document.addEventListener('DOMContentLoaded', initResourcesWorkbench);
})();

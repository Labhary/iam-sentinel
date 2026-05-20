(() => {
  const state = {
    identities: [],
    filteredIdentities: []
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
    document.getElementById('identities-loading').classList.toggle('d-none', !isLoading);
  }

  function showError(message) {
    const error = document.getElementById('identities-error');
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

  function matchesSearch(identity, searchTerm) {
    if (!searchTerm) {
      return true;
    }

    return [
      identity.name,
      identity.email,
      identity.type,
      ...(identity.roles || []),
      ...(identity.groups || [])
    ].some((value) => String(value ?? '').toLowerCase().includes(searchTerm));
  }

  function getFilteredIdentities() {
    const mfaFilter = getControlValue('mfa-filter');
    const externalFilter = getControlValue('external-filter');
    const serviceAccountFilter = getControlValue('service-account-filter');
    const searchTerm = getControlValue('identities-search').trim().toLowerCase();

    return state.identities.filter((identity) => {
      const matchesMfa = mfaFilter === 'ALL'
        || (mfaFilter === 'ENABLED' && identity.mfa_enabled)
        || (mfaFilter === 'DISABLED' && !identity.mfa_enabled);
      const matchesExternal = externalFilter === 'ALL'
        || (externalFilter === 'EXTERNAL' && identity.external_user)
        || (externalFilter === 'INTERNAL' && !identity.external_user);
      const matchesServiceAccount = serviceAccountFilter === 'ALL'
        || (serviceAccountFilter === 'SERVICE_ACCOUNT' && identity.service_account)
        || (serviceAccountFilter === 'HUMAN' && !identity.service_account);
      return matchesMfa && matchesExternal && matchesServiceAccount && matchesSearch(identity, searchTerm);
    });
  }

  function renderSummary() {
    setText('total-identities', state.identities.length);
    setText('external-identities', state.identities.filter((identity) => identity.external_user).length);
    setText('service-accounts', state.identities.filter((identity) => identity.service_account).length);
    setText('identities-without-mfa', state.identities.filter((identity) => !identity.mfa_enabled).length);
  }

  function renderIdentitiesCount() {
    document.getElementById('identities-count').textContent = `Showing ${state.filteredIdentities.length} of ${state.identities.length} identities`;
  }

  function statusBadge(isEnabled, enabledText, disabledText) {
    const badgeClass = isEnabled ? 'badge bg-success' : 'badge bg-warning text-dark';
    return `<span class="${badgeClass}">${isEnabled ? enabledText : disabledText}</span>`;
  }

  function renderIdentities(identities) {
    const tableBody = document.getElementById('identities-table-body');
    const rows = identities.length
      ? identities.map((identity) => `
        <tr>
          <td>${escapeHtml(identity.name)}</td>
          <td>${escapeHtml(identity.email)}</td>
          <td>${escapeHtml(identity.type)}</td>
          <td>${statusBadge(identity.mfa_enabled, 'Enabled', 'Disabled')}</td>
          <td>${statusBadge(identity.external_user, 'External', 'Internal')}</td>
          <td>${statusBadge(identity.service_account, 'Service', 'Human')}</td>
          <td>${escapeHtml((identity.roles || []).length)}</td>
          <td>${escapeHtml((identity.groups || []).length)}</td>
          <td>
            <a class="btn btn-sm btn-outline-primary" href="/identities/${encodeURIComponent(identity.id)}">${escapeHtml(identity.id)}</a>
          </td>
        </tr>
      `).join('')
      : '<tr><td colspan="9" class="text-muted">No identities match the current filters.</td></tr>';
    tableBody.innerHTML = rows;
  }

  function applyIdentityControls() {
    state.filteredIdentities = getFilteredIdentities();
    renderIdentities(state.filteredIdentities);
    renderIdentitiesCount();
  }

  async function refreshIdentitiesWorkbench() {
    showLoading(true);
    showError('');

    try {
      state.identities = await fetchJson('/api/identities');
      renderSummary();
      applyIdentityControls();
    } catch (error) {
      showError('Identity data could not be loaded.');
    } finally {
      showLoading(false);
    }
  }

  function wireEvents() {
    document.getElementById('identities-search').addEventListener('input', applyIdentityControls);
    document.getElementById('mfa-filter').addEventListener('change', applyIdentityControls);
    document.getElementById('external-filter').addEventListener('change', applyIdentityControls);
    document.getElementById('service-account-filter').addEventListener('change', applyIdentityControls);
  }

  function initIdentitiesWorkbench() {
    wireEvents();
    refreshIdentitiesWorkbench();
  }

  document.addEventListener('DOMContentLoaded', initIdentitiesWorkbench);
})();

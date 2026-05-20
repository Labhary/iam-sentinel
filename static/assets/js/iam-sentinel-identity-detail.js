(() => {
  const severityBadgeClasses = {
    CRITICAL: 'badge bg-danger',
    HIGH: 'badge bg-warning text-dark',
    MEDIUM: 'badge bg-warning-subtle text-dark border border-warning',
    LOW: 'badge bg-success'
  };

  const state = {
    identityId: null,
    identity: null,
    findings: []
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

  function showLoading(isLoading) {
    document.getElementById('identity-detail-loading').classList.toggle('d-none', !isLoading);
  }

  function showError(message) {
    const error = document.getElementById('identity-detail-error');
    error.textContent = message;
    error.classList.toggle('d-none', !message);
  }

  function showNotFound(isNotFound) {
    document.getElementById('identity-not-found').classList.toggle('d-none', !isNotFound);
    document.getElementById('identity-detail-content').classList.toggle('d-none', isNotFound);
  }

  async function fetchJson(url) {
    const response = await fetch(url);
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

  function statusBadge(isEnabled, enabledText, disabledText) {
    const badgeClass = isEnabled ? 'badge bg-success' : 'badge bg-warning text-dark';
    return `<span class="${badgeClass}">${isEnabled ? enabledText : disabledText}</span>`;
  }

  function renderRelatedFindings() {
    const tableBody = document.getElementById('identity-related-findings');
    const relatedFindings = state.findings.filter((finding) => finding.identity_id === state.identityId);

    if (!relatedFindings.length) {
      tableBody.innerHTML = '<tr><td colspan="6" class="text-muted">No related findings.</td></tr>';
      return;
    }

    tableBody.innerHTML = relatedFindings.map((finding) => {
      const severityClass = severityBadgeClasses[finding.severity] || 'badge bg-secondary';
      return `
        <tr>
          <td><span class="${severityClass}">${escapeHtml(finding.severity)}</span></td>
          <td><a href="/findings/${encodeURIComponent(finding.id)}">${escapeHtml(finding.title)}</a></td>
          <td>${escapeHtml(finding.score)}</td>
          <td>${escapeHtml(finding.status)}</td>
          <td>${escapeHtml(finding.owner || 'Unassigned')}</td>
          <td>
            <a class="btn btn-sm btn-outline-primary" href="/findings/${encodeURIComponent(finding.id)}">${escapeHtml(finding.id)}</a>
          </td>
        </tr>
      `;
    }).join('');
  }

  function renderIdentity(identity) {
    setText('identity-detail-name', identity.name);
    setText('identity-detail-meta', identity.id);
    setText('identity-detail-email', identity.email);
    setText('identity-detail-type', identity.type);
    document.getElementById('identity-detail-mfa').innerHTML = statusBadge(identity.mfa_enabled, 'Enabled', 'Disabled');
    document.getElementById('identity-detail-external').innerHTML = statusBadge(identity.external_user, 'External', 'Internal');
    document.getElementById('identity-detail-service-account').innerHTML = statusBadge(identity.service_account, 'Service', 'Human');
    renderList('identity-detail-roles', identity.roles);
    renderList('identity-detail-groups', identity.groups);
    renderRelatedFindings();
  }

  async function refreshIdentityDetail() {
    showLoading(true);
    showError('');

    try {
      const [identities, findings] = await Promise.all([
        fetchJson('/api/identities'),
        fetchJson('/api/findings')
      ]);
      state.identity = identities.find((identity) => identity.id === state.identityId);
      state.findings = findings;

      if (!state.identity) {
        showNotFound(true);
        return;
      }

      showNotFound(false);
      renderIdentity(state.identity);
    } catch (error) {
      showError('Identity data could not be loaded.');
    } finally {
      showLoading(false);
    }
  }

  function initIdentityDetail() {
    const page = document.getElementById('identity-detail-page');
    state.identityId = page.dataset.identityId;
    refreshIdentityDetail();
  }

  document.addEventListener('DOMContentLoaded', initIdentityDetail);
})();

(() => {
  const ui = window.IamSentinelUI || {};
  const formatStatus = ui.formatStatus || ((status) => status);
  const formatIdentityLabel = ui.formatIdentityLabel || ((name, id) => name || id || '');
  const severityBadgeClasses = {
    CRITICAL: 'badge bg-danger',
    HIGH: 'badge bg-warning text-dark',
    MEDIUM: 'badge bg-warning-subtle text-dark border border-warning',
    LOW: 'badge bg-success'
  };

  const state = {
    resourceId: null,
    resource: null,
    identities: [],
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
    document.getElementById('resource-detail-loading').classList.toggle('d-none', !isLoading);
  }

  function showError(message) {
    const error = document.getElementById('resource-detail-error');
    error.textContent = message;
    error.classList.toggle('d-none', !message);
  }

  function showNotFound(isNotFound) {
    document.getElementById('resource-not-found').classList.toggle('d-none', !isNotFound);
    document.getElementById('resource-detail-content').classList.toggle('d-none', isNotFound);
  }

  async function fetchJson(url) {
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`Request failed: ${response.status}`);
    }
    return response.json();
  }

  function statusBadge(isEnabled, enabledText, disabledText) {
    const badgeClass = isEnabled ? 'badge bg-danger' : 'badge bg-success';
    return `<span class="${badgeClass}">${isEnabled ? enabledText : disabledText}</span>`;
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

  function renderIdentityList(id, identities) {
    const list = document.getElementById(id);
    if (!identities.length) {
      list.innerHTML = '<li class="text-muted">None</li>';
      return;
    }

    list.innerHTML = identities.map((identity) => `
      <li>
        <a href="/identities/${encodeURIComponent(identity.id)}">${escapeHtml(formatIdentityLabel(identity.name, identity.id))}</a>
      </li>
    `).join('');
  }

  function getAccessibleIdentities() {
    const accessibleIds = new Set(state.resource.accessible_by || []);
    return state.identities.filter((identity) => accessibleIds.has(identity.id));
  }

  function renderRelatedFindings() {
    const tableBody = document.getElementById('resource-related-findings');
    const relatedFindings = state.findings.filter((finding) => finding.resource_id === state.resourceId);

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
          <td>${escapeHtml(formatIdentityLabel(finding.identity_name, finding.identity_id))}</td>
          <td>${escapeHtml(finding.score)}</td>
          <td>${escapeHtml(formatStatus(finding.status))}</td>
          <td>
            <a class="btn btn-sm btn-outline-primary" href="/findings/${encodeURIComponent(finding.id)}">Open Investigation</a>
          </td>
        </tr>
      `;
    }).join('');
  }

  function renderResource(resource) {
    const accessibleIdentities = getAccessibleIdentities();

    setText('resource-detail-name', resource.name);
    setText('resource-detail-meta', resource.label || resource.id);
    setText('resource-detail-type', formatResourceType(resource.type));
    document.getElementById('resource-detail-sensitive').innerHTML = statusBadge(resource.sensitive, 'Sensitive', 'Not Sensitive');
    setText('resource-detail-accessible-count', resource.accessible_by_count);
    setText('resource-detail-related-findings-count', resource.related_findings_count);
    renderIdentityList('resource-accessible-identities', accessibleIdentities);
    renderIdentityList('resource-external-identities', accessibleIdentities.filter((identity) => identity.external_user));
    renderIdentityList('resource-service-accounts', accessibleIdentities.filter((identity) => identity.service_account));
    renderRelatedFindings();
  }

  async function refreshResourceDetail() {
    showLoading(true);
    showError('');

    try {
      const [resources, identities, findings] = await Promise.all([
        fetchJson('/api/resources'),
        fetchJson('/api/identities'),
        fetchJson('/api/findings')
      ]);
      state.resource = resources.find((resource) => resource.id === state.resourceId);
      state.identities = identities;
      state.findings = findings;

      if (!state.resource) {
        showNotFound(true);
        return;
      }

      showNotFound(false);
      renderResource(state.resource);
    } catch (error) {
      showError('Resource data could not be loaded.');
    } finally {
      showLoading(false);
    }
  }

  function initResourceDetail() {
    const page = document.getElementById('resource-detail-page');
    state.resourceId = page.dataset.resourceId;
    refreshResourceDetail();
  }

  document.addEventListener('DOMContentLoaded', initResourceDetail);
})();

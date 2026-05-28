(() => {
  const ui = window.IamSentinelUI || {};
  const formatStatus = ui.formatStatus || ((status) => status);
  const formatIdentityLabel = ui.formatIdentityLabel || ((name, id) => name || id || '');
  const formatResourceLabel = ui.formatResourceLabel || ((name, id) => name || id || '');
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
    findings: [],
    accessPaths: []
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

  function showFeedback(message, type = 'success') {
    const feedback = document.getElementById('resource-detail-feedback');
    feedback.textContent = message;
    feedback.className = `alert alert-${type}`;
    feedback.classList.toggle('d-none', !message);
  }

  function showNotFound(isNotFound) {
    document.getElementById('resource-not-found').classList.toggle('d-none', !isNotFound);
    document.getElementById('resource-detail-content').classList.toggle('d-none', isNotFound);
  }

  async function fetchJson(url, options = {}) {
    const response = await fetch(url, options);
    if (!response.ok) {
      throw new Error(`Request failed: ${response.status}`);
    }
    return response.json();
  }

  function statusBadge(isEnabled, enabledText, disabledText) {
    const badgeClass = isEnabled ? 'badge bg-danger' : 'badge bg-success';
    return `<span class="${badgeClass}">${isEnabled ? enabledText : disabledText}</span>`;
  }

  function neutralBadge(label) {
    return `<span class="badge bg-light text-dark border">${escapeHtml(label)}</span>`;
  }

  function severityBadge(severity) {
    const severityClass = severityBadgeClasses[severity] || 'badge bg-light text-dark border';
    return `<span class="${severityClass}">${escapeHtml(severity || 'None')}</span>`;
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

  function getRelatedFindings() {
    return state.findings.filter((finding) => finding.resource_id === state.resourceId);
  }

  function getSeverityRank(severity) {
    return { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }[severity] || 0;
  }

  function getHighestSeverity(findings) {
    if (!findings.length) {
      return 'NONE';
    }
    return findings
      .map((finding) => finding.severity)
      .sort((left, right) => getSeverityRank(right) - getSeverityRank(left))[0];
  }

  function getIdentityAccessPaths(identityId) {
    return state.accessPaths.filter((path) => path.identity_id === identityId);
  }

  function getIdentityFindings(identityId) {
    return getRelatedFindings().filter((finding) => finding.identity_id === identityId);
  }

  function getCriticalHighIdentityIds() {
    return new Set(
      getRelatedFindings()
        .filter((finding) => ['CRITICAL', 'HIGH'].includes(finding.severity))
        .map((finding) => finding.identity_id)
    );
  }

  function renderInvestigationActions() {
    document.getElementById('resource-view-attack-graph-link').href = `/attack-graph?resource_id=${encodeURIComponent(state.resourceId)}`;
    document.getElementById('resource-view-access-paths-link').href = `/access-paths?resource_id=${encodeURIComponent(state.resourceId)}`;
    document.getElementById('resource-view-findings-link').href = `/findings?search=${encodeURIComponent(state.resourceId)}`;
    const createReviewButton = document.getElementById('resource-create-access-review');
    createReviewButton.disabled = state.accessPaths.length === 0;
    createReviewButton.title = state.accessPaths.length ? 'Create review for a related identity and this resource' : 'No access paths available';
  }

  function renderInvestigationSummary(accessibleIdentities) {
    const criticalHighIdentityIds = getCriticalHighIdentityIds();
    setText('resource-summary-identities', accessibleIdentities.length);
    setText('resource-summary-critical-high-identities', criticalHighIdentityIds.size);
    setText('resource-summary-access-paths', state.accessPaths.length);
    setText('resource-summary-related-findings', getRelatedFindings().length);
  }

  function renderWhyThisResourceMatters(resource) {
    const criticalHighIdentityCount = getCriticalHighIdentityIds().size;
    document.getElementById('resource-matters-badges').innerHTML = `
      ${statusBadge(resource.sensitive, 'Sensitive', 'Not Sensitive')}
      ${neutralBadge(`${criticalHighIdentityCount} critical/high identities`)}
      ${neutralBadge(`${state.accessPaths.length} access paths`)}
    `;
    setText(
      'resource-matters-summary',
      `${formatResourceLabel(resource.name, resource.id)} is reachable by ${resource.accessible_by_count} identities. ${criticalHighIdentityCount} identities have critical/high exposure connected to this resource, so analysts should review access paths and related findings before approving access.`
    );
  }

  function renderRelatedIdentities(identities) {
    const tableBody = document.getElementById('resource-related-identities');
    if (!identities.length) {
      tableBody.innerHTML = '<tr><td colspan="5" class="text-muted">No related identities.</td></tr>';
      return;
    }

    tableBody.innerHTML = identities.map((identity) => {
      const identityFindings = getIdentityFindings(identity.id);
      const identityPaths = getIdentityAccessPaths(identity.id);
      return `
        <tr>
          <td><a href="/identities/${encodeURIComponent(identity.id)}">${escapeHtml(formatIdentityLabel(identity.name, identity.id))}</a></td>
          <td>${severityBadge(getHighestSeverity(identityFindings))}</td>
          <td>${escapeHtml(identityFindings.length)}</td>
          <td>${escapeHtml(identityPaths.length)}</td>
          <td>
            <div class="btn-group btn-group-sm" role="group" aria-label="Identity investigation actions">
              <a class="btn btn-outline-primary" href="/identities/${encodeURIComponent(identity.id)}">Identity</a>
              <a class="btn btn-outline-primary" href="/access-paths?identity_id=${encodeURIComponent(identity.id)}&resource_id=${encodeURIComponent(state.resourceId)}">Paths</a>
            </div>
          </td>
        </tr>
      `;
    }).join('');
  }

  function renderRelatedAccessPaths() {
    const tableBody = document.getElementById('resource-related-access-paths');
    if (!state.accessPaths.length) {
      tableBody.innerHTML = '<tr><td colspan="5" class="text-muted">No related access paths.</td></tr>';
      return;
    }

    tableBody.innerHTML = state.accessPaths.map((path) => {
      const pathDisplay = escapeHtml(path.path_display);
      const severity = getHighestSeverity(getIdentityFindings(path.identity_id));
      return `
        <tr>
          <td>${escapeHtml(formatIdentityLabel(path.identity_name, path.identity_id))}</td>
          <td>${severityBadge(severity)}</td>
          <td>${neutralBadge(`Length ${path.path_length}`)}</td>
          <td><span class="table-truncate" title="${pathDisplay}">${pathDisplay}</span></td>
          <td><a class="btn btn-sm btn-outline-primary" href="/access-paths?identity_id=${encodeURIComponent(path.identity_id)}&resource_id=${encodeURIComponent(state.resourceId)}">Open Path</a></td>
        </tr>
      `;
    }).join('');
  }

  function renderRelatedFindings() {
    const tableBody = document.getElementById('resource-related-findings');
    const relatedFindings = getRelatedFindings();

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
          <td>${neutralBadge(formatStatus(finding.status))}</td>
          <td>
            <a class="btn btn-sm btn-outline-primary" href="/findings/${encodeURIComponent(finding.id)}">Investigate</a>
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
    renderInvestigationActions();
    renderInvestigationSummary(accessibleIdentities);
    renderWhyThisResourceMatters(resource);
    renderIdentityList('resource-accessible-identities', accessibleIdentities);
    renderIdentityList('resource-external-identities', accessibleIdentities.filter((identity) => identity.external_user));
    renderIdentityList('resource-service-accounts', accessibleIdentities.filter((identity) => identity.service_account));
    renderRelatedIdentities(accessibleIdentities);
    renderRelatedAccessPaths();
    renderRelatedFindings();
  }

  async function createAccessReview() {
    const accessPath = state.accessPaths.find((path) => path.resource_sensitive) || state.accessPaths[0];
    if (!accessPath) {
      showFeedback('No access path is available for review creation.', 'warning');
      return;
    }

    showFeedback('');
    try {
      await fetchJson('/api/access-reviews', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identity_id: accessPath.identity_id,
          resource_id: state.resourceId
        })
      });
      showFeedback('Access review created.', 'success');
    } catch (error) {
      showFeedback('An active review already exists or the review could not be created.', 'warning');
    }
  }

  async function refreshResourceDetail() {
    showLoading(true);
    showError('');

    try {
      const [resources, identities, findings, accessPaths] = await Promise.all([
        fetchJson('/api/resources'),
        fetchJson('/api/identities'),
        fetchJson('/api/findings'),
        fetchJson(`/api/access-paths?resource_id=${encodeURIComponent(state.resourceId)}`)
      ]);
      state.resource = resources.find((resource) => resource.id === state.resourceId);
      state.identities = identities;
      state.findings = findings;
      state.accessPaths = accessPaths;

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
    document.getElementById('resource-create-access-review').addEventListener('click', createAccessReview);
    refreshResourceDetail();
  }

  document.addEventListener('DOMContentLoaded', initResourceDetail);
})();

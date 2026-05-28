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
    identityId: null,
    identity: null,
    findings: [],
    accessPaths: [],
    lastPreview: null
  };
  const actionLabels = {
    ENABLE_MFA: 'Enable MFA',
    DISABLE_ACCOUNT: 'Disable account',
    REENABLE_ACCOUNT: 'Re-enable account',
    ADD_TO_GROUP: 'Add to group',
    CHANGE_GROUP: 'Change group',
    REMOVE_FROM_GROUP: 'Remove from group',
    REPLACE_ROLE: 'Replace role',
    ACCEPT_RISK: 'Accept risk'
  };
  const actionFieldMap = {
    ENABLE_MFA: [],
    DISABLE_ACCOUNT: [],
    REENABLE_ACCOUNT: [],
    ACCEPT_RISK: [],
    ADD_TO_GROUP: ['new-group'],
    REMOVE_FROM_GROUP: ['old-group'],
    CHANGE_GROUP: ['old-group', 'new-group'],
    REPLACE_ROLE: ['old-role', 'new-role']
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

  function showFeedback(message, type = 'success') {
    const feedback = document.getElementById('identity-remediation-feedback');
    feedback.textContent = message;
    feedback.className = `alert alert-${type}`;
    feedback.classList.toggle('d-none', !message);
  }

  function showNotFound(isNotFound) {
    document.getElementById('identity-not-found').classList.toggle('d-none', !isNotFound);
    document.getElementById('identity-detail-content').classList.toggle('d-none', isNotFound);
  }

  async function fetchJson(url, options = {}) {
    const response = await fetch(url, options);
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.error || `Request failed: ${response.status}`);
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

  function neutralBadge(label) {
    return `<span class="badge bg-light text-dark border">${escapeHtml(label)}</span>`;
  }

  function sensitivityBadge(isSensitive) {
    return isSensitive
      ? '<span class="badge bg-danger">Sensitive</span>'
      : '<span class="badge bg-success">Not Sensitive</span>';
  }

  function getRelatedFindings() {
    return state.findings.filter((finding) => finding.identity_id === state.identityId);
  }

  function getSensitiveResourceIds() {
    return new Set(
      state.accessPaths
        .filter((path) => path.resource_sensitive)
        .map((path) => path.resource_id)
    );
  }

  function getIdentityTypeLabel(identity) {
    if (identity.service_account) {
      return 'Service';
    }
    if (identity.external_user) {
      return 'External';
    }
    return 'Human';
  }

  function isPrivilegedRole(roleId) {
    return /(admin|privileged|break|security|root|owner)/i.test(String(roleId || ''));
  }

  function getPermissionIds() {
    const permissionIds = new Set();
    state.accessPaths.forEach((path) => {
      (path.path_nodes || []).forEach((nodeId) => {
        if (String(nodeId).startsWith('perm-')) {
          permissionIds.add(nodeId);
        }
      });
    });
    return permissionIds;
  }

  function renderRiskSummary(identity) {
    const relatedFindings = getRelatedFindings();
    const criticalHighCount = relatedFindings.filter((finding) => ['CRITICAL', 'HIGH'].includes(finding.severity)).length;
    setText('identity-risk-total-findings', relatedFindings.length);
    setText('identity-risk-critical-high-findings', criticalHighCount);
    setText('identity-risk-sensitive-resources', getSensitiveResourceIds().size);
    document.getElementById('identity-risk-mfa').innerHTML = statusBadge(identity.mfa_enabled, 'Enabled', 'Disabled');
    document.getElementById('identity-risk-account-state').innerHTML = statusBadge(!identity.disabled, 'Enabled', 'Disabled');
    document.getElementById('identity-risk-identity-type').innerHTML = neutralBadge(getIdentityTypeLabel(identity));
  }

  function renderPrivilegeOverview(identity) {
    const permissionIds = getPermissionIds();
    const privilegedRoleCount = (identity.roles || []).filter(isPrivilegedRole).length;
    setText('identity-privilege-total-groups', (identity.groups || []).length);
    setText('identity-privilege-total-roles', (identity.roles || []).length);
    setText('identity-privilege-total-permissions', permissionIds.size);
    setText('identity-privilege-privileged-roles', privilegedRoleCount);
    document.getElementById('identity-privilege-sensitive-access').innerHTML = statusBadge(
      getSensitiveResourceIds().size > 0,
      'Yes',
      'No'
    );
  }

  function renderQuickActions() {
    const accessPathsUrl = `/access-paths?identity_id=${encodeURIComponent(state.identityId)}`;
    document.getElementById('identity-view-findings-link').href = '/findings';
    document.getElementById('identity-view-access-paths-link').href = accessPathsUrl;
    document.getElementById('identity-view-attack-graph-link').href = '/attack-graph';
    const createReviewButton = document.getElementById('identity-create-access-review');
    createReviewButton.disabled = state.accessPaths.length === 0;
    createReviewButton.title = state.accessPaths.length ? 'Create review for the highest-priority reachable resource' : 'No access paths available';
  }

  function renderRelatedFindings() {
    const tableBody = document.getElementById('identity-related-findings');
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
          <td>${escapeHtml(finding.score)}</td>
          <td>${neutralBadge(formatStatus(finding.status))}</td>
          <td>${escapeHtml(finding.owner || 'Unassigned')}</td>
          <td>
            <a class="btn btn-sm btn-outline-primary" href="/findings/${encodeURIComponent(finding.id)}">Investigate</a>
          </td>
        </tr>
      `;
    }).join('');
  }

  function renderAccessPaths() {
    const tableBody = document.getElementById('identity-access-paths');
    if (!state.accessPaths.length) {
      tableBody.innerHTML = '<tr><td colspan="4" class="text-muted">No access paths found.</td></tr>';
      return;
    }

    tableBody.innerHTML = state.accessPaths.slice(0, 10).map((accessPath) => {
      const pathDisplay = escapeHtml(accessPath.path_display);
      return `
        <tr>
          <td>${escapeHtml(formatResourceLabel(accessPath.resource_name, accessPath.resource_id))}</td>
          <td>${sensitivityBadge(accessPath.resource_sensitive)}</td>
          <td>${neutralBadge(`Length ${accessPath.path_length}`)}</td>
          <td><span class="table-truncate" title="${pathDisplay}">${pathDisplay}</span></td>
        </tr>
      `;
    }).join('');
  }

  function getDefaultRemediationAction(identity) {
    return getAvailableRemediationActions(identity)[0] || '';
  }

  function getAvailableRemediationActions(identity) {
    const actions = [];
    const groups = identity.groups || [];
    const roles = identity.roles || [];
    const availableGroups = identity.available_groups || [];
    const availableRoles = identity.available_roles || [];

    if (!identity.mfa_enabled) {
      actions.push('ENABLE_MFA');
    }
    actions.push(identity.disabled ? 'REENABLE_ACCOUNT' : 'DISABLE_ACCOUNT');
    if (availableGroups.length) {
      actions.push('ADD_TO_GROUP');
    }
    if (groups.length) {
      actions.push('REMOVE_FROM_GROUP');
    }
    if (groups.length && availableGroups.length) {
      actions.push('CHANGE_GROUP');
    }
    if (roles.length && availableRoles.length) {
      actions.push('REPLACE_ROLE');
    }
    return actions;
  }

  function renderIdentity(identity) {
    setText('identity-detail-name', identity.name);
    setText('identity-detail-meta', identity.label || formatIdentityLabel(identity.name, identity.id));
    setText('identity-detail-email', identity.email);
    setText('identity-detail-type', identity.type);
    document.getElementById('identity-detail-mfa').innerHTML = statusBadge(identity.mfa_enabled, 'Enabled', 'Disabled');
    document.getElementById('identity-detail-external').innerHTML = statusBadge(identity.external_user, 'External', 'Internal');
    document.getElementById('identity-detail-service-account').innerHTML = statusBadge(identity.service_account, 'Service', 'Human');
    renderList('identity-detail-roles', identity.roles);
    renderList('identity-detail-groups', identity.groups);
    renderQuickActions();
    renderRiskSummary(identity);
    renderPrivilegeOverview(identity);
    renderRemediationOptions(identity);
    renderRelatedFindings();
    renderAccessPaths();
  }

  function renderRemediationOptions(identity) {
    const actionSelect = document.getElementById('identity-remediation-action');
    const previousAction = actionSelect.value;
    const availableActions = getAvailableRemediationActions(identity);
    const oldGroupSelect = document.getElementById('identity-remediation-old-group');
    const newGroupSelect = document.getElementById('identity-remediation-new-group');
    const roleSelect = document.getElementById('identity-remediation-old-role');
    const newRoleSelect = document.getElementById('identity-remediation-new-role');
    const groups = identity.groups || [];
    const roles = identity.roles || [];
    const availableGroups = identity.available_groups || [];
    const availableRoles = identity.available_roles || [];
    actionSelect.innerHTML = availableActions
      .map((actionType) => `<option value="${escapeHtml(actionType)}">${escapeHtml(actionLabels[actionType] || actionType)}</option>`)
      .join('');
    actionSelect.value = availableActions.includes(previousAction)
      ? previousAction
      : getDefaultRemediationAction(identity);
    oldGroupSelect.innerHTML = groups.length
      ? groups.map((groupId) => `<option value="${escapeHtml(groupId)}">${escapeHtml(groupId)}</option>`).join('')
      : '';
    newGroupSelect.innerHTML = availableGroups.length
      ? availableGroups.map((group) => `<option value="${escapeHtml(group.id)}">${escapeHtml(group.name)} (${escapeHtml(group.id)})</option>`).join('')
      : '<option value="">No groups</option>';
    roleSelect.innerHTML = roles.length
      ? roles.map((roleId) => `<option value="${escapeHtml(roleId)}">${escapeHtml(roleId)}</option>`).join('')
      : '';
    newRoleSelect.innerHTML = availableRoles.length
      ? availableRoles.map((role) => `<option value="${escapeHtml(role.id)}">${escapeHtml(role.name)} (${escapeHtml(role.id)})</option>`).join('')
      : '<option value="">No roles</option>';
    updateRemediationFieldVisibility();
  }

  function updateRemediationFieldVisibility() {
    const actionType = document.getElementById('identity-remediation-action').value;
    const visibleFields = new Set(actionFieldMap[actionType] || []);
    [
      ['old-group', 'identity-remediation-old-group-field'],
      ['new-group', 'identity-remediation-new-group-field'],
      ['old-role', 'identity-remediation-old-role-field'],
      ['new-role', 'identity-remediation-new-role-field']
    ].forEach(([fieldName, elementId]) => {
      document.getElementById(elementId).classList.toggle('d-none', !visibleFields.has(fieldName));
    });
  }

  function buildPreviewPayload() {
    const actionType = document.getElementById('identity-remediation-action').value;
    const reason = document.getElementById('identity-remediation-reason').value.trim();
    const payload = {
      action_type: actionType,
      identity_id: state.identityId,
      reason
    };
    if (actionType === 'ADD_TO_GROUP') {
      payload.group_id = document.getElementById('identity-remediation-new-group').value;
    }
    if (actionType === 'CHANGE_GROUP') {
      payload.old_group_id = document.getElementById('identity-remediation-old-group').value;
      payload.new_group_id = document.getElementById('identity-remediation-new-group').value;
    }
    if (actionType === 'REMOVE_FROM_GROUP') {
      payload.group_id = document.getElementById('identity-remediation-old-group').value;
    }
    if (actionType === 'REPLACE_ROLE') {
      payload.old_role_id = document.getElementById('identity-remediation-old-role').value;
      payload.new_role_id = document.getElementById('identity-remediation-new-role').value;
    }
    return payload;
  }

  function renderNoImpactPreview(message = 'No impact preview yet') {
    state.lastPreview = null;
    const preview = document.getElementById('identity-remediation-preview');
    preview.classList.remove('d-none');
    preview.className = 'alert alert-secondary mt-3 mb-0';
    preview.textContent = message;
  }

  function hideImpactPreview() {
    state.lastPreview = null;
    document.getElementById('identity-remediation-preview').classList.add('d-none');
  }

  function hideVerifiedImpact() {
    document.getElementById('identity-remediation-verified-impact').classList.add('d-none');
  }

  function resetRemediationImpactOutput() {
    renderNoImpactPreview();
    hideVerifiedImpact();
  }

  function formatInlineList(items, fallback = 'None') {
    if (!items || !items.length) {
      return fallback;
    }
    return items.map((item) => escapeHtml(item.name || item.id || item)).join(', ');
  }

  function formatStateSummary(value) {
    return `
      MFA ${value.mfa_enabled ? 'enabled' : 'disabled'};
      ${value.disabled ? 'disabled' : 'active'};
      groups ${formatInlineList(value.groups)};
      roles ${formatInlineList(value.roles)}
    `;
  }

  function renderImpactPreview(preview) {
    state.lastPreview = preview;
    const before = preview.impact.before;
    const after = preview.impact.after;
    const warning = !preview.impact.risk_reduction;
    const container = document.getElementById('identity-remediation-preview');
    container.className = warning
      ? 'alert alert-warning mt-3 mb-0'
      : 'alert alert-info mt-3 mb-0';
    container.innerHTML = `
      <div class="fw-semibold mb-1">Impact preview</div>
      <div class="small mb-2"><span class="text-muted">Action:</span> ${escapeHtml(actionLabels[preview.action_type] || preview.action_type)}</div>
      <div class="row g-2 small">
        <div class="col-lg-6"><span class="text-muted">Current:</span> ${formatStateSummary(preview.before)}</div>
        <div class="col-lg-6"><span class="text-muted">Expected:</span> ${formatStateSummary(preview.after)}</div>
        <div class="col-md-4"><span class="text-muted">Access paths:</span> ${before.access_paths_count} &rarr; ${after.access_paths_count}</div>
        <div class="col-md-4"><span class="text-muted">Sensitive resources:</span> ${before.sensitive_resources_count} &rarr; ${after.sensitive_resources_count}</div>
        <div class="col-md-4"><span class="text-muted">Affected findings:</span> ${preview.impact.affected_findings_count}</div>
        <div class="col-lg-6"><span class="text-muted">Current sensitive:</span> ${formatInlineList(before.sensitive_resources)}</div>
        <div class="col-lg-6"><span class="text-muted">Expected sensitive:</span> ${formatInlineList(after.sensitive_resources)}</div>
      </div>
      ${warning ? '<div class="mt-2 fw-semibold">Warning: this preview does not reduce access paths or sensitive resource reachability.</div>' : ''}
    `;
  }

  async function refreshImpactPreview() {
    if (!state.identityId || !state.identity) {
      renderNoImpactPreview();
      return;
    }

    try {
      const preview = await fetchJson('/api/remediation-actions/preview', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(buildPreviewPayload())
      });
      renderImpactPreview(preview);
    } catch (error) {
      renderNoImpactPreview(`Impact preview unavailable: ${error.message}`);
    }
  }

  async function renderVerifiedImpactSummary(preview) {
    if (!preview) {
      return;
    }

    const accessPaths = await fetchJson(`/api/access-paths?identity_id=${encodeURIComponent(state.identityId)}`);
    const sensitiveResourceCount = new Set(
      accessPaths
        .filter((path) => path.resource_sensitive)
        .map((path) => path.resource_id)
    ).size;
    const verified = document.getElementById('identity-remediation-verified-impact');
    hideImpactPreview();
    verified.classList.remove('d-none');
    verified.innerHTML = `
      <div class="fw-semibold">Verified impact</div>
      <div class="small">
        Access paths: ${preview.impact.before.access_paths_count} &rarr; ${accessPaths.length};
        sensitive resources: ${preview.impact.before.sensitive_resources_count} &rarr; ${sensitiveResourceCount};
        affected findings: ${preview.impact.affected_findings_count}
      </div>
    `;
  }

  async function applyRemediationAction() {
    const actionType = document.getElementById('identity-remediation-action').value;
    const reason = document.getElementById('identity-remediation-reason').value.trim();
    const payload = {
      action_type: actionType,
      identity_id: state.identityId,
      reason
    };
    if (actionType === 'ADD_TO_GROUP') {
      payload.group_id = document.getElementById('identity-remediation-new-group').value;
    }
    if (actionType === 'CHANGE_GROUP') {
      payload.old_group_id = document.getElementById('identity-remediation-old-group').value;
      payload.new_group_id = document.getElementById('identity-remediation-new-group').value;
    }
    if (actionType === 'REMOVE_FROM_GROUP') {
      payload.group_id = document.getElementById('identity-remediation-old-group').value;
    }
    if (actionType === 'REPLACE_ROLE') {
      payload.old_role_id = document.getElementById('identity-remediation-old-role').value;
      payload.new_role_id = document.getElementById('identity-remediation-new-role').value;
    }

    showFeedback('');
    try {
      const previewBeforeApply = state.lastPreview || await fetchJson('/api/remediation-actions/preview', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const result = await fetchJson('/api/remediation-actions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      document.getElementById('identity-remediation-reason').value = '';
      await refreshIdentityDetail();
      await renderVerifiedImpactSummary(previewBeforeApply);
      showFeedback(`${actionLabels[actionType] || actionType} simulated. ${formatStateChange(result.audit_event)}`, 'success');
    } catch (error) {
      showFeedback(`Remediation action failed. ${error.message}`, 'danger');
    }
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
          identity_id: state.identityId,
          resource_id: accessPath.resource_id
        })
      });
      showFeedback('Access review created.', 'success');
    } catch (error) {
      showFeedback('An active review already exists or the review could not be created.', 'warning');
    }
  }

  function formatStateChange(event) {
    if (!event || !event.before || !event.after) {
      return '';
    }
    const changes = ['mfa_enabled', 'disabled', 'groups', 'roles']
      .filter((field) => JSON.stringify(event.before[field]) !== JSON.stringify(event.after[field]))
      .map((field) => `${field.replaceAll('_', ' ')} updated`);
    return changes.length ? changes.join(', ') + '.' : '';
  }

  async function refreshIdentityDetail() {
    showLoading(true);
    showError('');

    try {
      const [identities, findings, accessPaths] = await Promise.all([
        fetchJson('/api/identities'),
        fetchJson('/api/findings'),
        fetchJson(`/api/access-paths?identity_id=${encodeURIComponent(state.identityId)}`)
      ]);
      state.identity = identities.find((identity) => identity.id === state.identityId);
      state.findings = findings;
      state.accessPaths = accessPaths;

      if (!state.identity) {
        showNotFound(true);
        return;
      }

      showNotFound(false);
      renderIdentity(state.identity);
      renderNoImpactPreview();
    } catch (error) {
      showError('Identity data could not be loaded.');
    } finally {
      showLoading(false);
    }
  }

  function initIdentityDetail() {
    const page = document.getElementById('identity-detail-page');
    state.identityId = page.dataset.identityId;
    document.getElementById('identity-remediation-action').addEventListener('change', () => {
      updateRemediationFieldVisibility();
      resetRemediationImpactOutput();
    });
    [
      'identity-remediation-old-group',
      'identity-remediation-new-group',
      'identity-remediation-old-role',
      'identity-remediation-new-role'
    ].forEach((elementId) => {
      document.getElementById(elementId).addEventListener('change', resetRemediationImpactOutput);
    });
    document.getElementById('identity-remediation-reason').addEventListener('change', resetRemediationImpactOutput);
    document.getElementById('identity-remediation-reason').addEventListener('input', resetRemediationImpactOutput);
    document.getElementById('identity-remediation-preview-button').addEventListener('click', refreshImpactPreview);
    document.getElementById('identity-remediation-apply').addEventListener('click', applyRemediationAction);
    document.getElementById('identity-create-access-review').addEventListener('click', createAccessReview);
    updateRemediationFieldVisibility();
    renderNoImpactPreview();
    refreshIdentityDetail();
  }

  document.addEventListener('DOMContentLoaded', initIdentityDetail);
})();

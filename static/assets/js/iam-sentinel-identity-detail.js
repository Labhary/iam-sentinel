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
    identityId: null,
    identity: null,
    findings: [],
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
          <td>${escapeHtml(formatStatus(finding.status))}</td>
          <td>${escapeHtml(finding.owner || 'Unassigned')}</td>
          <td>
            <a class="btn btn-sm btn-outline-primary" href="/findings/${encodeURIComponent(finding.id)}">Open Investigation</a>
          </td>
        </tr>
      `;
    }).join('');
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
    renderRemediationOptions(identity);
    renderRelatedFindings();
  }

  function renderRemediationOptions(identity) {
    const oldGroupSelect = document.getElementById('identity-remediation-old-group');
    const newGroupSelect = document.getElementById('identity-remediation-new-group');
    const roleSelect = document.getElementById('identity-remediation-old-role');
    const newRoleSelect = document.getElementById('identity-remediation-new-role');
    const availableGroups = identity.available_groups || [];
    const availableRoles = identity.available_roles || [];
    oldGroupSelect.innerHTML = identity.groups.length
      ? identity.groups.map((groupId) => `<option value="${escapeHtml(groupId)}">${escapeHtml(groupId)}</option>`).join('')
      : '<option value="">No groups</option>';
    newGroupSelect.innerHTML = availableGroups.length
      ? availableGroups.map((group) => `<option value="${escapeHtml(group.id)}">${escapeHtml(group.name)} (${escapeHtml(group.id)})</option>`).join('')
      : '<option value="">No groups</option>';
    roleSelect.innerHTML = identity.roles.length
      ? identity.roles.map((roleId) => `<option value="${escapeHtml(roleId)}">${escapeHtml(roleId)}</option>`).join('')
      : '<option value="">No roles</option>';
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
    preview.className = 'alert alert-secondary mt-3 mb-0';
    preview.textContent = message;
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
      <div class="fw-semibold mb-2">Impact preview: ${escapeHtml(preview.action_label)} for ${escapeHtml(formatIdentityLabel(preview.identity_name, preview.identity_id))}</div>
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
      document.getElementById('identity-remediation-verified-impact').classList.add('d-none');
      refreshImpactPreview();
    });
    [
      'identity-remediation-old-group',
      'identity-remediation-new-group',
      'identity-remediation-old-role',
      'identity-remediation-new-role',
      'identity-remediation-reason'
    ].forEach((elementId) => {
      document.getElementById(elementId).addEventListener('change', refreshImpactPreview);
      document.getElementById(elementId).addEventListener('input', refreshImpactPreview);
    });
    document.getElementById('identity-remediation-apply').addEventListener('click', applyRemediationAction);
    updateRemediationFieldVisibility();
    renderNoImpactPreview();
    refreshIdentityDetail();
  }

  document.addEventListener('DOMContentLoaded', initIdentityDetail);
})();

(() => {
  const ui = window.IamSentinelUI || {};
  const formatTimestamp = ui.formatTimestamp || ((timestamp) => timestamp || 'Unknown');
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

  function escapeHtml(value) {
    if (ui.escapeHtml) {
      return ui.escapeHtml(value);
    }
    return String(value ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#039;');
  }

  async function fetchAudit() {
    if (ui.fetchJson) {
      return ui.fetchJson('/api/remediation-audit');
    }
    const response = await fetch('/api/remediation-audit');
    if (!response.ok) {
      throw new Error(`Request failed: ${response.status}`);
    }
    return response.json();
  }

  function setLoading(isLoading) {
    document.getElementById('remediation-audit-loading').classList.toggle('d-none', !isLoading);
  }

  function showError(message) {
    const error = document.getElementById('remediation-audit-error');
    error.textContent = message;
    error.classList.toggle('d-none', !message);
  }

  function renderAudit(events) {
    const sortedEvents = [...events].sort((left, right) => String(right.timestamp).localeCompare(String(left.timestamp)));
    document.getElementById('remediation-audit-count').textContent = `${sortedEvents.length} events`;
    const tableBody = document.getElementById('remediation-audit-table-body');
    if (!sortedEvents.length) {
      tableBody.innerHTML = '<tr><td colspan="7" class="text-muted">No remediation audit events.</td></tr>';
      return;
    }
    tableBody.innerHTML = sortedEvents.map((event) => `
      <tr>
        <td class="table-nowrap">${escapeHtml(formatTimestamp(event.timestamp))}</td>
        <td>${escapeHtml(event.actor)}</td>
        <td><span class="badge bg-light text-dark border">${escapeHtml(formatAction(event.action_type))}</span></td>
        <td>${escapeHtml(formatTargetType(event.target_type))}<br><span class="text-muted small">${escapeHtml(event.target_id)}</span></td>
        <td>${formatState(event.before)}</td>
        <td>${formatState(event.after)}</td>
        <td class="remediation-audit-reason">${escapeHtml(event.reason || 'None')}</td>
      </tr>
    `).join('');
  }

  function formatAction(actionType) {
    return actionLabels[actionType] || String(actionType || '').replaceAll('_', ' ');
  }

  function formatTargetType(targetType) {
    return String(targetType || 'target').replaceAll('_', ' ');
  }

  function formatState(state) {
    if (!state || typeof state !== 'object') {
      return '<span class="text-muted">None</span>';
    }
    const entries = Object.entries(state);
    if (!entries.length) {
      return '<span class="text-muted">None</span>';
    }
    return `<div class="remediation-audit-state">${entries.map(([key, value]) => `
      <div class="remediation-audit-state-row">
        <span class="remediation-audit-state-key">${escapeHtml(formatStateKey(key))}</span>
        <span class="remediation-audit-state-value">${escapeHtml(formatValue(value))}</span>
      </div>
    `).join('')}</div>`;
  }

  function formatStateKey(key) {
    return String(key || '').replaceAll('_', ' ');
  }

  function formatValue(value) {
    if (Array.isArray(value)) {
      return value.length ? value.join(', ') : 'None';
    }
    if (typeof value === 'boolean') {
      return value ? 'true' : 'false';
    }
    return value ?? 'None';
  }

  async function initAuditPage() {
    setLoading(true);
    showError('');
    try {
      renderAudit(await fetchAudit());
    } catch (error) {
      showError('Remediation audit could not be loaded.');
    } finally {
      setLoading(false);
    }
  }

  document.addEventListener('DOMContentLoaded', initAuditPage);
})();

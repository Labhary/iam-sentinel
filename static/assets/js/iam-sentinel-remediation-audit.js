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
    const timeline = document.getElementById('remediation-audit-events');
    if (!sortedEvents.length) {
      timeline.innerHTML = '<div class="text-muted">No remediation audit events.</div>';
      return;
    }
    timeline.innerHTML = sortedEvents.map((event) => `
      <article class="remediation-audit-event border rounded p-3 mb-3">
        <div class="d-flex flex-wrap align-items-start justify-content-between gap-2">
          <div>
            <div class="fw-semibold">${escapeHtml(formatAction(event.action_type))}</div>
            <div class="text-muted small">${escapeHtml(formatTimestamp(event.timestamp))}</div>
          </div>
          <span class="badge bg-light text-dark border">${escapeHtml(formatTargetType(event.target_type))}: ${escapeHtml(event.target_id)}</span>
        </div>
        <div class="row g-3 small mt-1">
          <div class="col-md-4">
            <span class="text-muted d-block">Actor</span>
            <span>${escapeHtml(event.actor || 'Unknown')}</span>
          </div>
          <div class="col-md-8">
            <span class="text-muted d-block">Reason</span>
            <span class="remediation-audit-reason">${escapeHtml(event.reason || 'None')}</span>
          </div>
        </div>
        <div class="remediation-audit-changes mt-3">
          ${formatChangedFields(event.before, event.after)}
        </div>
      </article>
    `).join('');
  }

  function formatAction(actionType) {
    return actionLabels[actionType] || String(actionType || '').replaceAll('_', ' ');
  }

  function formatTargetType(targetType) {
    return String(targetType || 'target').replaceAll('_', ' ');
  }

  function formatChangedFields(before, after) {
    const changes = getChangedFields(before, after);
    if (!changes.length) {
      return '<div class="text-muted small">No field-level changes recorded.</div>';
    }
    return `<div class="remediation-audit-state">${changes.map((change) => `
      <div class="remediation-audit-state-row d-flex flex-wrap gap-2 py-1 border-top">
        <span class="remediation-audit-state-key">${escapeHtml(formatStateKey(change.key))}</span>
        <span class="remediation-audit-state-value">${escapeHtml(formatValue(change.before))} &rarr; ${escapeHtml(formatValue(change.after))}</span>
      </div>
    `).join('')}</div>`;
  }

  function getChangedFields(before, after) {
    const beforeState = before && typeof before === 'object' ? before : {};
    const afterState = after && typeof after === 'object' ? after : {};
    return [...new Set([...Object.keys(beforeState), ...Object.keys(afterState)])]
      .filter((key) => JSON.stringify(beforeState[key]) !== JSON.stringify(afterState[key]))
      .map((key) => ({
        key,
        before: beforeState[key],
        after: afterState[key]
      }));
  }

  function formatStateKey(key) {
    return String(key || '')
      .replaceAll('_', ' ')
      .replace(/\bmfa\b/i, 'MFA')
      .replace(/\b\w/g, (letter) => letter.toUpperCase());
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

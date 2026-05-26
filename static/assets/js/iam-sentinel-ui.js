window.IamSentinelUI = (() => {
  function escapeHtml(value) {
    return String(value ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#039;');
  }

  function setText(id, value, fallback = '0') {
    const element = document.getElementById(id);
    if (element) {
      element.textContent = value ?? fallback;
    }
  }

  function toggleLoading(id, isLoading) {
    const element = document.getElementById(id);
    if (element) {
      element.classList.toggle('d-none', !isLoading);
    }
  }

  function showAlert(id, message, type = 'danger') {
    const element = document.getElementById(id);
    if (!element) {
      return;
    }

    element.textContent = message;
    element.className = `alert alert-${type}`;
    element.classList.toggle('d-none', !message);
  }

  async function fetchJson(url, options = {}) {
    const response = await fetch(url, options);
    if (!response.ok) {
      throw new Error(`Request failed: ${response.status}`);
    }
    return response.json();
  }

  function severityBadgeClass(severity) {
    return {
      CRITICAL: 'badge bg-danger',
      HIGH: 'badge bg-warning text-dark',
      MEDIUM: 'badge bg-warning-subtle text-dark border border-warning',
      LOW: 'badge bg-success'
    }[severity] || 'badge bg-secondary';
  }

  function statusBadge(isEnabled, enabledText, disabledText, enabledClass = 'badge bg-success', disabledClass = 'badge bg-warning text-dark') {
    return `<span class="${isEnabled ? enabledClass : disabledClass}">${isEnabled ? enabledText : disabledText}</span>`;
  }

  function formatStatus(status) {
    const statusLabels = {
      OPEN: 'Open',
      UNDER_REVIEW: 'Under Review',
      REMEDIATED: 'Remediated',
      FALSE_POSITIVE: 'False Positive',
      SUPPRESSED: 'Suppressed',
      CLOSED: 'Closed'
    };

    if (statusLabels[status]) {
      return statusLabels[status];
    }

    return String(status ?? '')
      .split('_')
      .filter(Boolean)
      .map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
      .join(' ');
  }

  function formatIdentityLabel(identityOrName, identityId) {
    if (identityOrName && typeof identityOrName === 'object') {
      return formatEntityLabel(identityOrName.name || identityOrName.identity_name, identityOrName.id || identityOrName.identity_id);
    }
    return formatEntityLabel(identityOrName, identityId);
  }

  function formatResourceLabel(resourceOrName, resourceId) {
    if (resourceOrName && typeof resourceOrName === 'object') {
      return formatEntityLabel(resourceOrName.name || resourceOrName.resource_name, resourceOrName.id || resourceOrName.resource_id);
    }
    return formatEntityLabel(resourceOrName, resourceId);
  }

  function formatEntityLabel(displayName, entityId) {
    const id = String(entityId ?? '').trim();
    const name = String(displayName ?? '').trim();
    if (name && id && name !== id) {
      return `${name} (${id})`;
    }
    return name || id || '';
  }

  function formatTimestamp(timestamp) {
    if (!timestamp) {
      return timestamp;
    }

    const date = new Date(timestamp);
    if (Number.isNaN(date.getTime())) {
      return timestamp;
    }

    try {
      return new Intl.DateTimeFormat('en-US', {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        hour12: false,
        timeZone: 'UTC',
        timeZoneName: 'short'
      }).format(date);
    } catch (error) {
      return timestamp;
    }
  }

  return {
    escapeHtml,
    fetchJson,
    formatIdentityLabel,
    formatResourceLabel,
    formatStatus,
    formatTimestamp,
    setText,
    severityBadgeClass,
    showAlert,
    statusBadge,
    toggleLoading
  };
})();

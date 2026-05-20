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

  return {
    escapeHtml,
    fetchJson,
    setText,
    severityBadgeClass,
    showAlert,
    statusBadge,
    toggleLoading
  };
})();

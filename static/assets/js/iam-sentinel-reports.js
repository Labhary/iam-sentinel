(() => {
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
    document.getElementById('reports-loading').classList.toggle('d-none', !isLoading);
  }

  function showError(message) {
    const error = document.getElementById('reports-error');
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

  function renderMetricCards(report) {
    setText('governance-summary-generated-at', `Generated at ${report.generated_at || ''}`);
    setText('report-total-findings', report.total_findings);
    setText('report-critical-findings', report.critical_findings);
    setText('report-high-findings', report.high_findings);
    setText('report-risky-external-identities', report.risky_external_identities);
    setText('report-stale-reviews', report.stale_reviews);
    setText('report-revoke-decisions', report.revoke_decisions);
    setText('report-open-access-reviews', report.open_access_reviews);
    setText('report-completed-access-reviews', report.completed_access_reviews);
  }

  function renderTopList(tableId, rows, idKey) {
    const tableBody = document.getElementById(tableId);
    if (!rows || !rows.length) {
      tableBody.innerHTML = '<tr><td colspan="3" class="text-muted">No report data.</td></tr>';
      return;
    }

    tableBody.innerHTML = rows.slice(0, 10).map((row) => `
      <tr>
        <td>${escapeHtml(row[idKey])}</td>
        <td>${escapeHtml(row.finding_count)}</td>
        <td>${escapeHtml(row.highest_score)}</td>
      </tr>
    `).join('');
  }

  function renderReport(report) {
    renderMetricCards(report);
    renderTopList('top-risky-resources-table', report.top_risky_resources, 'resource_id');
    renderTopList('top-risky-identities-table', report.top_risky_identities, 'identity_id');
  }

  async function refreshReport() {
    showLoading(true);
    showError('');

    try {
      renderReport(await fetchJson('/api/reports/governance-summary?format=json'));
    } catch (error) {
      showError('Governance summary could not be loaded.');
    } finally {
      showLoading(false);
    }
  }

  document.addEventListener('DOMContentLoaded', refreshReport);
})();

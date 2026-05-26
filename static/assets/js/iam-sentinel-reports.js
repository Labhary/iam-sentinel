(() => {
  const ui = window.IamSentinelUI;

  function renderMetricCards(report) {
    ui.setText('governance-summary-generated-at', `Generated at ${report.generated_at || ''}`);
    ui.setText('report-total-findings', report.total_findings);
    ui.setText('report-critical-findings', report.critical_findings);
    ui.setText('report-high-findings', report.high_findings);
    ui.setText('report-risky-external-identities', report.risky_external_identities);
    ui.setText('report-stale-reviews', report.stale_reviews);
    ui.setText('report-revoke-decisions', report.revoke_decisions);
    ui.setText('report-open-access-reviews', report.open_access_reviews);
    ui.setText('report-completed-access-reviews', report.completed_access_reviews);
  }

  function renderTopList(tableId, rows, idKey, displayMap) {
    const tableBody = document.getElementById(tableId);
    if (!rows || !rows.length) {
      tableBody.innerHTML = '<tr><td colspan="3" class="text-muted">No report data.</td></tr>';
      return;
    }

    tableBody.innerHTML = rows.slice(0, 10).map((row) => `
      <tr>
        <td>${ui.escapeHtml((displayMap && displayMap[row[idKey]]) || row[idKey])}</td>
        <td>${ui.escapeHtml(row.finding_count)}</td>
        <td>${ui.escapeHtml(row.highest_score)}</td>
      </tr>
    `).join('');
  }

  function renderReport(report) {
    renderMetricCards(report);
    renderTopList('top-risky-resources-table', report.top_risky_resources, 'resource_id', report.resource_display_names);
    renderTopList('top-risky-identities-table', report.top_risky_identities, 'identity_id', report.identity_display_names);
  }

  async function refreshReport() {
    ui.toggleLoading('reports-loading', true);
    ui.showAlert('reports-error', '');

    try {
      renderReport(await ui.fetchJson('/api/reports/governance-summary?format=json'));
    } catch (error) {
      ui.showAlert('reports-error', 'Governance summary could not be loaded.');
    } finally {
      ui.toggleLoading('reports-loading', false);
    }
  }

  document.addEventListener('DOMContentLoaded', refreshReport);
})();

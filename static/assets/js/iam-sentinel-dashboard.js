(() => {
  const state = {
    severityChart: null,
    statusChart: null
  };

  function setText(id, value) {
    document.getElementById(id).textContent = value ?? '0';
  }

  function showLoading(isLoading) {
    document.getElementById('dashboard-loading').classList.toggle('d-none', !isLoading);
    document.getElementById('run-analysis-button').disabled = isLoading;
  }

  function showError(message) {
    const error = document.getElementById('dashboard-error');
    error.textContent = message;
    error.classList.toggle('d-none', !message);
  }

  async function fetchJson(url, options = {}) {
    const response = await fetch(url, options);
    if (!response.ok) {
      throw new Error(`Request failed: ${response.status}`);
    }
    return response.json();
  }

  function getStatusCounts(findings) {
    return findings.reduce((counts, finding) => {
      counts[finding.status] = (counts[finding.status] || 0) + 1;
      return counts;
    }, {});
  }

  function renderSummary(summary) {
    const counts = summary.count_per_severity || {};
    setText('total-findings', summary.total_findings);
    setText('highest-score', summary.highest_score);
    setText('severity-critical', counts.CRITICAL);
    setText('severity-high', counts.HIGH);
    setText('severity-medium', counts.MEDIUM);
    setText('severity-low', counts.LOW);
  }

  function renderOperationalKpis(findings) {
    const statusCounts = getStatusCounts(findings);
    setText('open-findings', statusCounts.OPEN);
    setText('in-progress-findings', statusCounts.IN_PROGRESS);
    setText('resolved-findings', statusCounts.RESOLVED);
    setText('critical-findings', findings.filter((finding) => finding.severity === 'CRITICAL').length);
  }

  function renderChart(existingChart, canvasId, labels, data, colors) {
    const canvas = document.getElementById(canvasId);
    if (!window.Chart || !canvas) {
      return existingChart;
    }

    if (existingChart) {
      existingChart.data.datasets[0].data = data;
      existingChart.update();
      return existingChart;
    }

    return new Chart(canvas, {
      type: 'doughnut',
      data: {
        labels,
        datasets: [{
          data,
          backgroundColor: colors
        }]
      },
      options: {
        plugins: {
          legend: {
            position: 'bottom'
          }
        }
      }
    });
  }

  function renderDistributionCharts(summary, findings) {
    const severityCounts = summary.count_per_severity || {};
    const statusCounts = getStatusCounts(findings);

    state.severityChart = renderChart(
      state.severityChart,
      'severity-distribution-chart',
      ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
      [
        severityCounts.CRITICAL || 0,
        severityCounts.HIGH || 0,
        severityCounts.MEDIUM || 0,
        severityCounts.LOW || 0
      ],
      ['#dc3545', '#fd7e14', '#ffc107', '#198754']
    );

    state.statusChart = renderChart(
      state.statusChart,
      'status-distribution-chart',
      ['OPEN', 'IN_PROGRESS', 'RESOLVED', 'SUPPRESSED'],
      [
        statusCounts.OPEN || 0,
        statusCounts.IN_PROGRESS || 0,
        statusCounts.RESOLVED || 0,
        statusCounts.SUPPRESSED || 0
      ],
      ['#0d6efd', '#ffc107', '#198754', '#6c757d']
    );
  }

  async function refreshDashboard() {
    showLoading(true);
    showError('');

    try {
      const [summary, findings] = await Promise.all([
        fetchJson('/api/findings/summary'),
        fetchJson('/api/findings')
      ]);
      renderSummary(summary);
      renderOperationalKpis(findings);
      renderDistributionCharts(summary, findings);
    } catch (error) {
      showError('Dashboard data could not be loaded.');
    } finally {
      showLoading(false);
    }
  }

  async function runAnalysis() {
    showLoading(true);
    showError('');

    try {
      await fetchJson('/api/analysis/run', { method: 'POST' });
      await refreshDashboard();
    } catch (error) {
      showError('Analysis could not be started.');
      showLoading(false);
    }
  }

  function initDashboard() {
    document.getElementById('run-analysis-button').addEventListener('click', runAnalysis);
    refreshDashboard();
  }

  document.addEventListener('DOMContentLoaded', initDashboard);
})();

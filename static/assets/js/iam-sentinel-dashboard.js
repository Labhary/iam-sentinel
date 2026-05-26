(() => {
  const state = {
    severityChart: null,
    statusChart: null
  };

  const severityBadgeClasses = {
    CRITICAL: 'badge bg-danger',
    HIGH: 'badge bg-warning text-dark',
    MEDIUM: 'badge bg-warning-subtle text-dark border border-warning',
    LOW: 'badge bg-success'
  };

  const severityRank = {
    CRITICAL: 4,
    HIGH: 3,
    MEDIUM: 2,
    LOW: 1
  };

  const donutCenterTextPlugin = {
    id: 'iamSentinelDonutCenterText',
    afterDraw(chart) {
      const centerText = chart.options.plugins.centerText;
      if (!centerText || !centerText.value) {
        return;
      }

      const { ctx, chartArea } = chart;
      const x = (chartArea.left + chartArea.right) / 2;
      const y = (chartArea.top + chartArea.bottom) / 2;
      ctx.save();
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillStyle = '#012970';
      ctx.font = '600 22px Nunito, sans-serif';
      ctx.fillText(centerText.value, x, y - 7);
      ctx.fillStyle = '#6c757d';
      ctx.font = '12px Open Sans, sans-serif';
      ctx.fillText(centerText.label, x, y + 14);
      ctx.restore();
    }
  };

  function setText(id, value) {
    document.getElementById(id).textContent = value ?? '0';
  }

  function escapeHtml(value) {
    return String(value ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#039;');
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
    setText('in-progress-findings', statusCounts.UNDER_REVIEW);
    setText('resolved-findings', statusCounts.REMEDIATED);
    setText('critical-findings', findings.filter((finding) => finding.severity === 'CRITICAL').length);
  }

  function renderLastAnalysisRun(timestamp) {
    const label = document.getElementById('last-analysis-run');
    if (!label || !timestamp) {
      return;
    }

    label.textContent = `Last analysis run: ${formatAnalysisTimestamp(timestamp)}`;
  }

  function formatAnalysisTimestamp(timestamp) {
    const date = new Date(timestamp);
    if (Number.isNaN(date.getTime())) {
      return timestamp;
    }

    const formattedDate = new Intl.DateTimeFormat('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      timeZone: 'UTC'
    }).format(date);
    const formattedTime = new Intl.DateTimeFormat('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
      timeZone: 'UTC'
    }).format(date);

    return `${formattedDate} ${formattedTime} UTC`;
  }

  function renderChart(existingChart, canvasId, labels, data, colors, centerText) {
    const canvas = document.getElementById(canvasId);
    if (!window.Chart || !canvas) {
      return existingChart;
    }

    if (existingChart) {
      existingChart.data.datasets[0].data = data;
      existingChart.options.plugins.centerText = centerText;
      existingChart.update();
      return existingChart;
    }

    return new Chart(canvas, {
      type: 'doughnut',
      data: {
        labels,
        datasets: [{
          data,
          backgroundColor: colors,
          borderWidth: 2,
          hoverOffset: 4
        }]
      },
      options: {
        maintainAspectRatio: false,
        cutout: '68%',
        layout: {
          padding: 4
        },
        plugins: {
          centerText,
          legend: {
            position: 'bottom',
            labels: {
              boxWidth: 10,
              padding: 10,
              usePointStyle: true
            }
          }
        }
      },
      plugins: [donutCenterTextPlugin]
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
      ['#dc3545', '#fd7e14', '#ffc107', '#198754'],
      {
        value: String(summary.total_findings || 0),
        label: 'findings'
      }
    );

    const openFindings = statusCounts.OPEN || 0;
    state.statusChart = renderChart(
      state.statusChart,
      'status-distribution-chart',
      ['Open', 'Under Review', 'Remediated', 'Suppressed'],
      [
        statusCounts.OPEN || 0,
        statusCounts.UNDER_REVIEW || 0,
        statusCounts.REMEDIATED || 0,
        statusCounts.SUPPRESSED || 0
      ],
      ['#0d6efd', '#ffc107', '#198754', '#6c757d'],
      {
        value: String(openFindings),
        label: 'open'
      }
    );
  }

  function compareRiskFindings(left, right) {
    return (
      (severityRank[right.severity] || 0) - (severityRank[left.severity] || 0)
      || (right.score || 0) - (left.score || 0)
      || String(left.id || '').localeCompare(String(right.id || ''))
    );
  }

  function getTopRiskFindings(findings) {
    const sortedFindings = [...findings].sort(compareRiskFindings);
    const selectedFindings = [];
    const selectedTypes = new Set();

    sortedFindings.forEach((finding) => {
      if (selectedFindings.length >= 5 || selectedTypes.has(finding.finding_type)) {
        return;
      }
      selectedFindings.push(finding);
      selectedTypes.add(finding.finding_type);
    });

    sortedFindings.forEach((finding) => {
      if (
        selectedFindings.length < 5
        && !selectedFindings.some((selected) => selected.id === finding.id)
      ) {
        selectedFindings.push(finding);
      }
    });

    return selectedFindings;
  }

  function renderTopRiskFindings(findings) {
    const tableBody = document.getElementById('top-risk-findings-table');
    const topFindings = getTopRiskFindings(findings);
    if (!topFindings.length) {
      tableBody.innerHTML = '<tr><td colspan="5" class="text-muted">No risk findings available.</td></tr>';
      return;
    }

    tableBody.innerHTML = topFindings.map((finding) => {
      const severityClass = severityBadgeClasses[finding.severity] || 'badge bg-secondary';
      return `
        <tr>
          <td><span class="${severityClass}">${escapeHtml(finding.severity)}</span></td>
          <td>${escapeHtml(finding.title)}</td>
          <td><a href="/identities/${encodeURIComponent(finding.identity_id)}">${escapeHtml(finding.identity_label || finding.identity_id)}</a></td>
          <td>${escapeHtml(finding.score)}</td>
          <td><a class="btn btn-sm btn-outline-primary" href="/findings/${encodeURIComponent(finding.id)}">Open</a></td>
        </tr>
      `;
    }).join('');
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
      renderTopRiskFindings(findings);
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
      const result = await fetchJson('/api/analysis/run', { method: 'POST' });
      renderLastAnalysisRun(result.execution_timestamp);
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

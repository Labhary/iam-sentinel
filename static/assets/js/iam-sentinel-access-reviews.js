(() => {
  const ui = window.IamSentinelUI;

  const state = {
    reviews: [],
    metrics: null,
    decisionChart: null,
    statusChart: null
  };

  function renderSummary() {
    const metrics = state.metrics || {};
    ui.setText('total-access-reviews', metrics.total_reviews || 0);
    ui.setText('open-access-reviews', metrics.open_reviews || 0);
    ui.setText('completed-access-reviews', metrics.completed_reviews || 0);
    ui.setText('revoke-access-reviews', metrics.revoke_decisions || 0);
    ui.setText('in-review-access-reviews', metrics.in_review_reviews || 0);
    ui.setText('stale-access-reviews', metrics.stale_open_reviews || 0);
    ui.setText('needs-follow-up-access-reviews', metrics.needs_follow_up_decisions || 0);
    ui.setText('unique-access-reviewers', metrics.unique_reviewers || 0);
    document.getElementById('access-reviews-count').textContent = `Showing ${state.reviews.length} reviews`;
  }

  function option(value, selectedValue, label = value) {
    const selected = value === selectedValue ? 'selected' : '';
    return `<option value="${ui.escapeHtml(value)}" ${selected}>${ui.escapeHtml(label)}</option>`;
  }

  function renderReviews() {
    const tableBody = document.getElementById('access-reviews-table-body');
    const rows = state.reviews.length
      ? state.reviews.map((review) => `
        <tr data-review-id="${ui.escapeHtml(review.id)}">
          <td><a href="/identities/${encodeURIComponent(review.identity_id)}">${ui.escapeHtml(review.identity_id)}</a></td>
          <td><a href="/resources/${encodeURIComponent(review.resource_id)}">${ui.escapeHtml(review.resource_id)}</a></td>
          <td>
            <select class="form-select form-select-sm review-status">
              ${option('OPEN', review.status)}
              ${option('IN_REVIEW', review.status)}
              ${option('COMPLETED', review.status)}
            </select>
          </td>
          <td>
            <input class="form-control form-control-sm review-reviewer" type="text" value="${ui.escapeHtml(review.reviewer || '')}" placeholder="reviewer@example.local">
          </td>
          <td>
            <select class="form-select form-select-sm review-decision">
              ${option('UNDECIDED', review.decision)}
              ${option('APPROVE', review.decision)}
              ${option('REVOKE', review.decision)}
              ${option('NEEDS_FOLLOW_UP', review.decision)}
            </select>
          </td>
          <td>
            ${ui.escapeHtml(review.updated_at)}
            ${review.stale ? '<span class="badge bg-warning text-dark ms-1">Stale</span>' : ''}
          </td>
          <td>
            <div class="d-flex flex-column gap-2">
              <textarea class="form-control form-control-sm review-notes" rows="2" placeholder="Review notes">${ui.escapeHtml(review.notes || '')}</textarea>
              <button class="btn btn-sm btn-outline-primary save-review-button" type="button">Save</button>
            </div>
          </td>
        </tr>
      `).join('')
      : '<tr><td colspan="7" class="text-muted">No access reviews have been created.</td></tr>';
    tableBody.innerHTML = rows;
  }

  function renderMetricTable(id, rows, labelKey) {
    const tableBody = document.getElementById(id);
    if (!rows || !rows.length) {
      tableBody.innerHTML = '<tr><td colspan="2" class="text-muted">No analytics data available.</td></tr>';
      return;
    }

    tableBody.innerHTML = rows.slice(0, 5).map((row) => `
      <tr>
        <td>${ui.escapeHtml(row[labelKey])}</td>
        <td class="text-end">${ui.escapeHtml(row.count)}</td>
      </tr>
    `).join('');
  }

  function renderAnalyticsTables() {
    const metrics = state.metrics || {};
    renderMetricTable('top-reviewed-resources-table', metrics.most_reviewed_resources, 'resource_id');
    renderMetricTable('top-reviewed-identities-table', metrics.most_reviewed_identities, 'identity_id');
    renderMetricTable('reviewer-workload-table', metrics.reviews_per_reviewer, 'reviewer');
  }

  function renderCharts() {
    if (!window.Chart || !state.metrics) {
      return;
    }

    const decisionData = [
      state.metrics.approve_decisions,
      state.metrics.revoke_decisions,
      state.metrics.needs_follow_up_decisions,
      state.metrics.undecided_reviews
    ];
    const statusData = [
      state.metrics.open_reviews,
      state.metrics.in_review_reviews,
      state.metrics.completed_reviews
    ];

    state.decisionChart = renderChart(
      state.decisionChart,
      'access-review-decision-chart',
      ['Approve', 'Revoke', 'Needs Follow-up', 'Undecided'],
      decisionData,
      ['#198754', '#dc3545', '#ffc107', '#6c757d']
    );
    state.statusChart = renderChart(
      state.statusChart,
      'access-review-status-chart',
      ['Open', 'In Review', 'Completed'],
      statusData,
      ['#0d6efd', '#ffc107', '#198754']
    );
  }

  function renderChart(existingChart, canvasId, labels, data, colors) {
    const canvas = document.getElementById(canvasId);
    if (!window.Chart || !canvas) {
      return existingChart;
    }

    if (existingChart) {
      existingChart.destroy();
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
        responsive: true,
        plugins: {
          legend: {
            position: 'bottom'
          }
        }
      }
    });
  }

  async function refreshAccessReviews() {
    ui.toggleLoading('access-reviews-loading', true);
    ui.showAlert('access-reviews-error', '');

    try {
      const [reviews, metrics] = await Promise.all([
        ui.fetchJson('/api/access-reviews'),
        ui.fetchJson('/api/access-review-metrics')
      ]);
      state.reviews = reviews;
      state.metrics = metrics;
      renderSummary();
      renderAnalyticsTables();
      renderCharts();
      renderReviews();
    } catch (error) {
      ui.showAlert('access-reviews-error', 'Access review data could not be loaded.');
    } finally {
      ui.toggleLoading('access-reviews-loading', false);
    }
  }

  async function saveReview(row) {
    const reviewId = row.dataset.reviewId;
    const payload = {
      status: row.querySelector('.review-status').value,
      reviewer: row.querySelector('.review-reviewer').value,
      decision: row.querySelector('.review-decision').value,
      notes: row.querySelector('.review-notes').value
    };

    ui.showAlert('access-reviews-feedback', '', 'success');
    try {
      await ui.fetchJson(`/api/access-reviews/${encodeURIComponent(reviewId)}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      await refreshAccessReviews();
      ui.showAlert('access-reviews-feedback', 'Access review updated.', 'success');
    } catch (error) {
      ui.showAlert('access-reviews-feedback', 'Access review update failed.', 'danger');
    }
  }

  function wireEvents() {
    document.getElementById('access-reviews-table-body').addEventListener('click', (event) => {
      const button = event.target.closest('.save-review-button');
      if (!button) {
        return;
      }

      const row = button.closest('tr[data-review-id]');
      if (row) {
        saveReview(row);
      }
    });
  }

  function initAccessReviewsWorkbench() {
    wireEvents();
    refreshAccessReviews();
  }

  document.addEventListener('DOMContentLoaded', initAccessReviewsWorkbench);
})();

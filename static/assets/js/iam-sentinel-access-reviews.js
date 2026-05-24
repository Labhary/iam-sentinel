(() => {
  const ui = window.IamSentinelUI;

  const state = {
    reviews: [],
    metrics: null,
    decisionChart: null,
    statusChart: null,
    historyModal: null,
    currentPage: 1,
    pageSize: 5
  };

  const statusOptions = ['OPEN', 'IN_REVIEW', 'COMPLETED'];
  const decisionOptions = ['UNDECIDED', 'APPROVE', 'REVOKE', 'NEEDS_FOLLOW_UP'];
  const analystStorageKey = 'iamSentinelAccessReviewAnalyst';

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
    ui.setText('pending-remediations', metrics.pending_remediations || 0);
    ui.setText('completed-remediations', metrics.completed_remediations || 0);
    ui.setText('access-review-decision-summary', `${metrics.total_reviews || 0} reviews`);
    ui.setText('access-review-status-summary', `${(metrics.open_reviews || 0) + (metrics.in_review_reviews || 0)} active`);
  }

  function option(value, selectedValue, label = value) {
    const selected = value === selectedValue ? 'selected' : '';
    return `<option value="${ui.escapeHtml(value)}" ${selected}>${ui.escapeHtml(label)}</option>`;
  }

  function formatReviewStatus(status) {
    return {
      OPEN: 'Open',
      IN_REVIEW: 'In Review',
      COMPLETED: 'Completed',
      COMPLET: 'Completed'
    }[status] || ui.formatStatus(status);
  }

  function formatReviewDecision(decision) {
    return {
      UNDECIDED: 'Undecided',
      APPROVE: 'Approve',
      REVOKE: 'Revoke',
      NEEDS_FOLLOW_UP: 'Needs Follow-up',
      NEEDS_FOLLOW: 'Needs Follow-up'
    }[decision] || ui.formatStatus(decision);
  }

  function formatRemediationStatus(status) {
    return {
      NOT_REQUIRED: 'Not Required',
      PENDING: 'Pending',
      COMPLETED: 'Completed'
    }[status] || ui.formatStatus(status);
  }

  function formatHistoryField(field) {
    return {
      status: 'Status',
      decision: 'Decision',
      remediation_status: 'Remediation Status',
      remediation_completed: 'Remediation Completion',
      reviewer: 'Reviewer',
      notes: 'Notes'
    }[field] || field;
  }

  function formatHistoryValue(field, value) {
    if (value === null || value === undefined || value === '') {
      return '(empty)';
    }
    if (field === 'status') {
      return formatReviewStatus(value);
    }
    if (field === 'decision') {
      return formatReviewDecision(value);
    }
    if (field === 'remediation_status' || field === 'remediation_completed') {
      return formatRemediationStatus(value);
    }
    return value;
  }

  function getCurrentAnalyst() {
    const input = document.getElementById('access-review-current-analyst');
    return (input?.value || '').trim() || 'Unassigned Analyst';
  }

  function loadCurrentAnalyst() {
    const input = document.getElementById('access-review-current-analyst');
    if (!input) {
      return;
    }
    input.value = localStorage.getItem(analystStorageKey) || input.value || 'Unassigned Analyst';
  }

  function saveCurrentAnalyst() {
    localStorage.setItem(analystStorageKey, getCurrentAnalyst());
  }

  function getTotalPages() {
    return Math.max(1, Math.ceil(state.reviews.length / state.pageSize));
  }

  function clampCurrentPage() {
    state.currentPage = Math.min(Math.max(state.currentPage, 1), getTotalPages());
  }

  function getPaginatedReviews() {
    clampCurrentPage();
    const start = (state.currentPage - 1) * state.pageSize;
    return state.reviews.slice(start, start + state.pageSize);
  }

  function renderPaginationControls(visibleReviews) {
    const totalReviews = state.reviews.length;
    const totalPages = getTotalPages();
    const start = totalReviews ? ((state.currentPage - 1) * state.pageSize) + 1 : 0;
    const end = totalReviews ? Math.min(start + visibleReviews.length - 1, totalReviews) : 0;

    document.getElementById('access-reviews-count').textContent = `Showing ${start}\u2013${end} of ${totalReviews} reviews`;
    document.getElementById('access-reviews-pagination-summary').textContent = totalReviews
      ? `Page ${state.currentPage} of ${totalPages}`
      : 'Page 0 of 0';
    document.getElementById('access-reviews-prev-page').disabled = state.currentPage <= 1;
    document.getElementById('access-reviews-next-page').disabled = state.currentPage >= totalPages;
  }

  function renderReviews() {
    const tableBody = document.getElementById('access-reviews-table-body');
    const visibleReviews = getPaginatedReviews();
    const rows = visibleReviews.length
      ? visibleReviews.map((review) => {
        const identityId = ui.escapeHtml(review.identity_id);
        const reviewer = ui.escapeHtml(review.reviewer || '');
        const resourceId = ui.escapeHtml(review.resource_id);
        const notes = ui.escapeHtml(review.notes || '');
        const notesStateClass = review.notes ? 'access-review-notes-filled' : 'access-review-notes-empty';
        const updatedAt = ui.escapeHtml(ui.formatTimestamp(review.updated_at));
        return `
        <tr data-review-id="${ui.escapeHtml(review.id)}">
          <td><a class="table-truncate access-review-identity" href="/identities/${encodeURIComponent(review.identity_id)}" title="${identityId}">${identityId}</a></td>
          <td><a class="table-truncate access-review-resource" href="/resources/${encodeURIComponent(review.resource_id)}" title="${resourceId}">${resourceId}</a></td>
          <td>
            <select class="form-select form-select-sm review-status">
              ${statusOptions.map((status) => option(status, review.status, formatReviewStatus(status))).join('')}
            </select>
          </td>
          <td>
            <input class="form-control form-control-sm table-truncate access-review-reviewer review-reviewer" type="text" value="${reviewer}" title="${reviewer}" placeholder="reviewer@example.local">
          </td>
          <td>
            <select class="form-select form-select-sm review-decision">
              ${decisionOptions.map((decision) => option(decision, review.decision, formatReviewDecision(decision))).join('')}
            </select>
          </td>
          <td>
            <span class="badge bg-light text-dark border">${ui.escapeHtml(formatRemediationStatus(review.remediation_status))}</span>
            ${review.remediation_status === 'PENDING' ? '<button class="btn btn-sm btn-outline-secondary complete-remediation-button ms-1" type="button">Complete</button>' : ''}
          </td>
          <td>
            <span class="table-nowrap">${updatedAt}</span>
            ${review.stale ? '<span class="badge bg-warning text-dark ms-1">Stale</span>' : ''}
          </td>
          <td>
            <input class="form-control form-control-sm table-truncate access-review-notes ${notesStateClass} review-notes" type="text" value="${notes}" title="${notes}" placeholder="No notes">
          </td>
          <td>
            <div class="d-inline-flex gap-1 access-review-actions">
              <button class="btn btn-sm btn-outline-secondary save-review-button" type="button">Save</button>
              <button class="btn btn-sm btn-link text-secondary review-history-button" type="button">History</button>
            </div>
          </td>
        </tr>
      `;
      }).join('')
      : '<tr><td colspan="9" class="text-muted">No access reviews have been created.</td></tr>';
    tableBody.innerHTML = rows;
    renderPaginationControls(visibleReviews);
  }

  function renderMetricTable(id, rows, labelKey) {
    const tableBody = document.getElementById(id);
    if (!rows || !rows.length) {
      tableBody.innerHTML = '<tr><td colspan="2" class="text-muted">No analytics data available.</td></tr>';
      return;
    }

    tableBody.innerHTML = rows.slice(0, 5).map((row) => {
      const label = ui.escapeHtml(row[labelKey]);
      const count = ui.escapeHtml(row.count);
      if (id === 'reviewer-workload-table') {
        return `
          <tr>
            <td><span class="table-truncate reviewer-workload-label" title="${label}">${label}</span></td>
            <td class="text-end reviewer-workload-count">${count}</td>
          </tr>
        `;
      }
      return `
        <tr>
          <td>${label}</td>
          <td class="text-end">${count}</td>
        </tr>
      `;
    }).join('');
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
        maintainAspectRatio: false,
        cutout: '68%',
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
      notes: row.querySelector('.review-notes').value,
      actor: getCurrentAnalyst()
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

  async function completeRemediation(row) {
    const reviewId = row.dataset.reviewId;

    ui.showAlert('access-reviews-feedback', '', 'success');
    try {
      await ui.fetchJson(`/api/access-reviews/${encodeURIComponent(reviewId)}/remediation`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          actor: getCurrentAnalyst()
        })
      });
      await refreshAccessReviews();
      ui.showAlert('access-reviews-feedback', 'Remediation completed.', 'success');
    } catch (error) {
      ui.showAlert('access-reviews-feedback', 'Remediation update failed.', 'danger');
    }
  }

  async function showReviewHistory(row) {
    const reviewId = row.dataset.reviewId;
    const identity = row.querySelector('.access-review-identity')?.getAttribute('title') || '';
    const resource = row.querySelector('.access-review-resource')?.getAttribute('title') || '';
    const historyTable = document.getElementById('access-review-history-table');
    const loading = document.getElementById('access-review-history-loading');
    const historyMeta = document.getElementById('access-review-history-meta');

    historyMeta.innerHTML = `
      <span class="text-body">${ui.escapeHtml(identity)} &rarr; ${ui.escapeHtml(resource)}</span>
      <span class="ms-2">Review ID: ${ui.escapeHtml(reviewId)}</span>
    `;
    loading.classList.remove('d-none');
    historyTable.innerHTML = '<tr><td colspan="4" class="text-muted">Loading history...</td></tr>';
    state.historyModal.show();

    try {
      const history = await ui.fetchJson(`/api/access-reviews/${encodeURIComponent(reviewId)}/history`);
      historyTable.innerHTML = history.length
        ? history.map((event) => {
          const oldValue = ui.escapeHtml(formatHistoryValue(event.changed_field, event.old_value));
          const newValue = ui.escapeHtml(formatHistoryValue(event.changed_field, event.new_value));
          return `
            <tr>
              <td><span class="table-nowrap">${ui.escapeHtml(ui.formatTimestamp(event.timestamp))}</span></td>
              <td>${ui.escapeHtml(event.actor || 'Unassigned Analyst')}</td>
              <td>${ui.escapeHtml(formatHistoryField(event.changed_field))}</td>
              <td><span class="text-muted">${oldValue}</span> → <strong>${newValue}</strong></td>
            </tr>
          `;
        }).join('')
        : '<tr><td colspan="4" class="text-muted">No history events yet.</td></tr>';
    } catch (error) {
      historyTable.innerHTML = '<tr><td colspan="4" class="text-danger">History could not be loaded.</td></tr>';
    } finally {
      loading.classList.add('d-none');
    }
  }

  function wireEvents() {
    document.getElementById('access-review-current-analyst').addEventListener('input', saveCurrentAnalyst);
    document.getElementById('access-reviews-page-size').addEventListener('change', () => {
      state.pageSize = Number.parseInt(document.getElementById('access-reviews-page-size').value, 10) || 5;
      state.currentPage = 1;
      renderReviews();
    });
    document.getElementById('access-reviews-prev-page').addEventListener('click', () => {
      state.currentPage -= 1;
      renderReviews();
    });
    document.getElementById('access-reviews-next-page').addEventListener('click', () => {
      state.currentPage += 1;
      renderReviews();
    });
    document.getElementById('access-reviews-table-body').addEventListener('click', (event) => {
      const saveButton = event.target.closest('.save-review-button');
      const historyButton = event.target.closest('.review-history-button');
      const remediationButton = event.target.closest('.complete-remediation-button');
      if (!saveButton && !historyButton && !remediationButton) {
        return;
      }

      const row = event.target.closest('tr[data-review-id]');
      if (row && saveButton) {
        saveReview(row);
      }
      if (row && historyButton) {
        showReviewHistory(row);
      }
      if (row && remediationButton) {
        completeRemediation(row);
      }
    });
  }

  function initAccessReviewsWorkbench() {
    state.historyModal = new bootstrap.Modal(document.getElementById('access-review-history-modal'));
    loadCurrentAnalyst();
    wireEvents();
    refreshAccessReviews();
  }

  document.addEventListener('DOMContentLoaded', initAccessReviewsWorkbench);
})();

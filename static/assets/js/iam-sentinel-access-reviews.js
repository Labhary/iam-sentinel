(() => {
  const ui = window.IamSentinelUI;

  const state = {
    reviews: [],
    metrics: null,
    findings: [],
    accessPaths: [],
    resourcesById: {},
    decisionChart: null,
    statusChart: null,
    historyModal: null,
    selectedReviewId: null,
    currentPage: 1,
    pageSize: 5
  };

  const statusOptions = ['OPEN', 'IN_REVIEW', 'COMPLETED'];
  const decisionOptions = ['UNDECIDED', 'APPROVE', 'REVOKE', 'NEEDS_FOLLOW_UP'];
  const analystStorageKey = 'iamSentinelAccessReviewAnalyst';

  function renderSummary() {
    const metrics = state.metrics || {};
    const highCriticalReviews = state.reviews.filter((review) => ['CRITICAL', 'HIGH'].includes(getReviewSeverity(review))).length;
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
    ui.setText('pending-access-reviews', (metrics.open_reviews || 0) + (metrics.in_review_reviews || 0));
    ui.setText('high-critical-access-reviews', highCriticalReviews);
    ui.setText('overdue-access-reviews', metrics.stale_open_reviews || 0);
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

  function getReviewCard(reviewId) {
    return Array.from(document.querySelectorAll('.access-review-card'))
      .find((card) => card.dataset.reviewId === reviewId) || null;
  }

  function showCardFeedback(reviewId, message, type = 'success') {
    const feedback = getReviewCard(reviewId)?.querySelector('.access-review-card-feedback');
    if (!feedback) {
      return;
    }

    feedback.textContent = message;
    feedback.className = `access-review-card-feedback alert alert-${type} mt-2 mb-0`;
    feedback.classList.toggle('d-none', !message);
  }

  function focusReviewCard(reviewId) {
    const card = getReviewCard(reviewId);
    if (!card) {
      return;
    }

    card.focus({ preventScroll: true });
    card.scrollIntoView({ block: 'center', behavior: 'smooth' });
  }

  function showWorkbenchFeedback(message, type = 'success', reviewId = null) {
    ui.showAlert('access-reviews-feedback', message, type);

    if (reviewId) {
      showCardFeedback(reviewId, message, type);
      return;
    }

    ui.showAlert('access-reviews-inline-feedback', message, type);
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

  function showReviewOnCurrentPage(reviewId) {
    const reviewIndex = state.reviews.findIndex((review) => review.id === reviewId);
    if (reviewIndex >= 0) {
      state.currentPage = Math.floor(reviewIndex / state.pageSize) + 1;
    }
  }

  function getRelatedFindings(review) {
    return state.findings.filter((finding) => (
      finding.identity_id === review.identity_id || finding.resource_id === review.resource_id
    ));
  }

  function getReviewAccessPaths(review) {
    return state.accessPaths.filter((path) => (
      path.identity_id === review.identity_id && path.resource_id === review.resource_id
    ));
  }

  function severityRank(severity) {
    return { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }[severity] || 0;
  }

  function getReviewSeverity(review) {
    const relatedFindings = getRelatedFindings(review);
    if (!relatedFindings.length) {
      return 'NONE';
    }
    return relatedFindings
      .map((finding) => finding.severity)
      .sort((left, right) => severityRank(right) - severityRank(left))[0];
  }

  function severityBadge(severity) {
    const badgeClass = {
      CRITICAL: 'badge bg-danger',
      HIGH: 'badge bg-warning text-dark',
      MEDIUM: 'badge bg-warning-subtle text-dark border border-warning',
      LOW: 'badge bg-success'
    }[severity] || 'badge bg-light text-dark border';
    return `<span class="${badgeClass}">${ui.escapeHtml(severity)}</span>`;
  }

  function neutralBadge(label) {
    return `<span class="badge bg-light text-dark border">${ui.escapeHtml(label)}</span>`;
  }

  function getResource(review) {
    return state.resourcesById[review.resource_id] || {};
  }

  function getReviewLabels(review) {
    return {
      identity: ui.escapeHtml(review.identity_label || ui.formatIdentityLabel(review.identity_id, review.identity_id)),
      resource: ui.escapeHtml(review.resource_label || ui.formatResourceLabel(review.resource_id, review.resource_id))
    };
  }

  function isSensitiveReview(review) {
    return Boolean(getResource(review).sensitive || getReviewAccessPaths(review).some((path) => path.resource_sensitive));
  }

  function getIdentityRiskLevel(review) {
    const severity = getReviewSeverity(review);
    if (['CRITICAL', 'HIGH'].includes(severity)) {
      return 'High';
    }
    if (getRelatedFindings(review).length || getReviewAccessPaths(review).length > 3) {
      return 'Medium';
    }
    return 'Low';
  }

  function riskContext(review) {
    return `
      <div class="d-flex flex-wrap gap-1">
        ${severityBadge(getReviewSeverity(review))}
        ${isSensitiveReview(review) ? '<span class="badge bg-danger">Sensitive</span>' : '<span class="badge bg-success">Not Sensitive</span>'}
        ${neutralBadge(`${getReviewAccessPaths(review).length} paths`)}
        ${neutralBadge(`${getIdentityRiskLevel(review)} identity risk`)}
      </div>
    `;
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
    const reviewList = document.getElementById('access-reviews-table-body');
    const visibleReviews = getPaginatedReviews();
    const rows = visibleReviews.length
      ? visibleReviews.map((review) => {
        const reviewLabels = getReviewLabels(review);
        const reviewer = ui.escapeHtml(review.reviewer || '');
        const notes = ui.escapeHtml(review.notes || '');
        const notesStateClass = review.notes ? 'access-review-notes-filled' : 'access-review-notes-empty';
        const updatedAt = ui.escapeHtml(ui.formatTimestamp(review.updated_at));
        return `
        <article class="access-review-card" data-review-id="${ui.escapeHtml(review.id)}" tabindex="0">
          <div class="access-review-card-header">
            <div class="access-review-principal">
              <a class="table-truncate access-review-title access-review-identity" href="/identities/${encodeURIComponent(review.identity_id)}" title="${reviewLabels.identity}">${reviewLabels.identity}</a>
              <a class="table-truncate access-review-subtitle access-review-resource" href="/resources/${encodeURIComponent(review.resource_id)}" title="${reviewLabels.resource}">${reviewLabels.resource}</a>
            </div>
            <div class="access-review-risk">${riskContext(review)}</div>
          </div>
          <div class="access-review-fields">
            <label class="access-review-field">
              <span>Status</span>
              <select class="form-select form-select-sm review-status">
                ${statusOptions.map((status) => option(status, review.status, formatReviewStatus(status))).join('')}
              </select>
            </label>
            <label class="access-review-field">
              <span>Reviewer</span>
              <input class="form-control form-control-sm table-truncate access-review-reviewer review-reviewer" type="text" value="${reviewer}" title="${reviewer}" placeholder="reviewer@example.local">
            </label>
            <label class="access-review-field">
              <span>Decision</span>
              <select class="form-select form-select-sm review-decision">
                ${decisionOptions.map((decision) => option(decision, review.decision, formatReviewDecision(decision))).join('')}
              </select>
            </label>
            <div class="access-review-field">
              <span>Remediation</span>
              <div>
                <span class="badge bg-light text-dark border">${ui.escapeHtml(formatRemediationStatus(review.remediation_status))}</span>
                ${review.remediation_status === 'PENDING' ? '<button class="btn btn-sm btn-outline-secondary complete-remediation-button ms-1" type="button">Complete</button>' : ''}
              </div>
            </div>
            <div class="access-review-field">
              <span>Updated</span>
              <div>
                <span class="table-nowrap">${updatedAt}</span>
                ${review.stale ? '<span class="badge bg-warning text-dark ms-1">Stale</span>' : ''}
              </div>
            </div>
            <label class="access-review-field access-review-notes-field">
              <span>Notes</span>
              <input class="form-control form-control-sm table-truncate access-review-notes ${notesStateClass} review-notes" type="text" value="${notes}" title="${notes}" placeholder="No notes">
            </label>
          </div>
          <div class="access-review-actions">
              <button class="btn btn-sm btn-primary save-review-button" type="button">Save</button>
              <button class="btn btn-sm btn-link text-secondary review-history-button" type="button">History</button>
          </div>
          <div class="access-review-card-feedback alert d-none mt-2 mb-0" role="alert"></div>
        </article>
      `;
      }).join('')
      : '<div class="text-muted">No access reviews have been created.</div>';
    reviewList.innerHTML = `${rows}<span id="access-review-actions-marker" class="visually-hidden">Access review actions</span>`;
    renderPaginationControls(visibleReviews);
    renderSelectedReviewDetail();
  }

  function whyReviewMatters(review) {
    const reasons = [];
    const pathCount = getReviewAccessPaths(review).length;
    if (isSensitiveReview(review)) reasons.push('privileged access to sensitive resource');
    if (['CRITICAL', 'HIGH'].includes(getReviewSeverity(review))) reasons.push('critical identity exposure');
    if (pathCount > 3) reasons.push('excessive access path count');
    if (getRelatedFindings(review).some((finding) => /external/i.test(`${finding.title} ${finding.description || ''}`))) {
      reasons.push('external identity involved');
    }
    return reasons.length ? reasons.join('; ') : 'review requested access entitlement for business justification';
  }

  function getSelectedReview() {
    return state.reviews.find((review) => review.id === state.selectedReviewId) || state.reviews[0] || null;
  }

  function renderSelectedReviewDetail() {
    const panel = document.getElementById('access-review-detail-panel');
    const review = getSelectedReview();
    if (!review) {
      panel.classList.add('text-muted');
      panel.textContent = 'Select a review to inspect risk context and investigation actions.';
      return;
    }
    state.selectedReviewId = review.id;
    panel.classList.remove('text-muted');
    document.querySelectorAll('.access-review-card').forEach((card) => {
      card.classList.toggle('is-selected', card.dataset.reviewId === review.id);
    });
    panel.innerHTML = `
      <div class="row g-2 small">
        <div class="col-md-3"><span class="text-muted d-block">Highest Severity</span>${severityBadge(getReviewSeverity(review))}</div>
        <div class="col-md-3"><span class="text-muted d-block">Sensitive Resource</span>${isSensitiveReview(review) ? '<span class="badge bg-danger">Yes</span>' : '<span class="badge bg-success">No</span>'}</div>
        <div class="col-md-3"><span class="text-muted d-block">Access Paths</span><strong>${getReviewAccessPaths(review).length}</strong></div>
        <div class="col-md-3"><span class="text-muted d-block">Identity Risk</span><strong>${ui.escapeHtml(getIdentityRiskLevel(review))}</strong></div>
        <div class="col-12"><span class="text-muted d-block">Why this review matters</span><strong>${ui.escapeHtml(whyReviewMatters(review))}</strong></div>
      </div>
      <div class="d-flex flex-wrap gap-2 mt-3">
        <a class="btn btn-sm btn-outline-primary" href="/identities/${encodeURIComponent(review.identity_id)}">View Identity</a>
        <a class="btn btn-sm btn-outline-primary" href="/resources/${encodeURIComponent(review.resource_id)}">View Resource</a>
        <a class="btn btn-sm btn-outline-primary" href="/access-paths?identity_id=${encodeURIComponent(review.identity_id)}&resource_id=${encodeURIComponent(review.resource_id)}">View Access Paths</a>
        <a class="btn btn-sm btn-outline-primary" href="/attack-graph?resource_id=${encodeURIComponent(review.resource_id)}">View Attack Graph</a>
        <a class="btn btn-sm btn-outline-primary" href="/findings?search=${encodeURIComponent(review.identity_id)}">View Related Findings</a>
      </div>
    `;
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

  async function refreshAccessReviews(reviewIdToShow = null) {
    ui.toggleLoading('access-reviews-loading', true);
    ui.showAlert('access-reviews-error', '');

    try {
      const [reviews, metrics, findings, accessPaths, resources] = await Promise.all([
        ui.fetchJson('/api/access-reviews'),
        ui.fetchJson('/api/access-review-metrics'),
        ui.fetchJson('/api/findings'),
        ui.fetchJson('/api/access-paths'),
        ui.fetchJson('/api/resources')
      ]);
      state.reviews = reviews;
      state.metrics = metrics;
      state.findings = findings;
      state.accessPaths = accessPaths;
      state.resourcesById = Object.fromEntries(resources.map((resource) => [resource.id, resource]));
      if (reviewIdToShow) {
        state.selectedReviewId = reviewIdToShow;
        showReviewOnCurrentPage(reviewIdToShow);
      }
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

    state.selectedReviewId = reviewId;
    showWorkbenchFeedback('', 'success', reviewId);
    try {
      await ui.fetchJson(`/api/access-reviews/${encodeURIComponent(reviewId)}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      await refreshAccessReviews(reviewId);
      showWorkbenchFeedback('Access review updated.', 'success', reviewId);
      focusReviewCard(reviewId);
    } catch (error) {
      showWorkbenchFeedback('Access review update failed.', 'danger', reviewId);
    }
  }

  async function renderRevokeImpactPreview(row) {
    const reviewId = row.dataset.reviewId;
    const review = state.reviews.find((candidate) => candidate.id === reviewId);
    const preview = document.getElementById('access-review-revoke-preview');
    if (!review) {
      return;
    }
    preview.className = 'alert alert-info mt-3 mb-0';
    preview.textContent = 'Loading revoke impact preview simulation...';
    try {
      const impact = await ui.fetchJson('/api/remediation-actions/preview', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action_type: 'DISABLE_ACCOUNT',
          identity_id: review.identity_id,
          reason: 'Access review revoke preview'
        })
      });
      const relatedFindings = getRelatedFindings(review).length;
      const relatedPaths = getReviewAccessPaths(review).length;
      const identityLabel = review.identity_label || review.identity_id;
      const resourceLabel = review.resource_label || review.resource_id;
      const before = impact.impact.before;
      const after = impact.impact.after;
      preview.innerHTML = `
        <div class="fw-semibold">Revoke impact preview simulation</div>
        <div class="small text-muted">Preview only. No access changes are applied from this panel.</div>
        <div class="small text-muted">Context: ${ui.escapeHtml(identityLabel)} &rarr; ${ui.escapeHtml(resourceLabel)}</div>
        <div class="small">
          findings affected: ${relatedFindings};
          review paths affected: ${relatedPaths};
          sensitive resources affected: ${before.sensitive_resources_count};
          path count reduction: ${before.access_paths_count} &rarr; ${after.access_paths_count}
        </div>
      `;
      showWorkbenchFeedback('Revoke impact preview simulation loaded. Select Save to persist the review.', 'info', reviewId);
    } catch (error) {
      preview.className = 'alert alert-warning mt-3 mb-0';
      preview.textContent = 'Revoke impact preview simulation unavailable.';
      showWorkbenchFeedback('Revoke impact preview simulation unavailable.', 'warning', reviewId);
    }
  }

  async function handleDecisionChange(row) {
    if (row.querySelector('.review-decision').value === 'REVOKE') {
      await renderRevokeImpactPreview(row);
      return;
    }
    document.getElementById('access-review-revoke-preview').classList.add('d-none');
    showWorkbenchFeedback('Decision selected. Select Save to persist status, reviewer, decision, and notes.', 'info', row.dataset.reviewId);
  }

  async function completeRemediation(row) {
    const reviewId = row.dataset.reviewId;

    state.selectedReviewId = reviewId;
    showWorkbenchFeedback('', 'success', reviewId);
    try {
      await ui.fetchJson(`/api/access-reviews/${encodeURIComponent(reviewId)}/remediation`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          actor: getCurrentAnalyst()
        })
      });
      await refreshAccessReviews(reviewId);
      showWorkbenchFeedback('Remediation completed.', 'success', reviewId);
      focusReviewCard(reviewId);
    } catch (error) {
      showWorkbenchFeedback('Remediation update failed.', 'danger', reviewId);
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
              <td><span class="text-muted">${oldValue}</span> &rarr; <strong>${newValue}</strong></td>
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
    document.getElementById('access-reviews-table-body').addEventListener('click', async (event) => {
      const row = event.target.closest('[data-review-id]');
      if (row) {
        state.selectedReviewId = row.dataset.reviewId;
        renderSelectedReviewDetail();
      }

      const saveButton = event.target.closest('.save-review-button');
      const historyButton = event.target.closest('.review-history-button');
      const remediationButton = event.target.closest('.complete-remediation-button');
      if (!row || (!saveButton && !historyButton && !remediationButton)) {
        return;
      }

      if (saveButton) {
        saveReview(row);
      }
      if (historyButton) {
        showReviewHistory(row);
      }
      if (remediationButton) {
        completeRemediation(row);
      }
    });
    document.getElementById('access-reviews-table-body').addEventListener('focusin', (event) => {
      const row = event.target.closest('[data-review-id]');
      if (row) {
        state.selectedReviewId = row.dataset.reviewId;
        renderSelectedReviewDetail();
      }
    });
    document.getElementById('access-reviews-table-body').addEventListener('change', async (event) => {
      const decisionSelect = event.target.closest('.review-decision');
      const row = event.target.closest('[data-review-id]');
      if (decisionSelect && row) {
        await handleDecisionChange(row);
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

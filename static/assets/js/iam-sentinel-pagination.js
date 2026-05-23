(() => {
  function createTablePager(options) {
    const state = {
      currentPage: 1,
      pageSize: 10,
      totalItems: 0,
      visibleItems: 0
    };

    function getElement(id) {
      return document.getElementById(id);
    }

    function getTotalPages() {
      return Math.max(1, Math.ceil(state.totalItems / state.pageSize));
    }

    function clampCurrentPage() {
      state.currentPage = Math.min(Math.max(state.currentPage, 1), getTotalPages());
    }

    function render() {
      const totalPages = getTotalPages();
      const start = state.totalItems ? ((state.currentPage - 1) * state.pageSize) + 1 : 0;
      const end = state.totalItems ? Math.min(start + state.visibleItems - 1, state.totalItems) : 0;

      getElement(options.countId).textContent = `Showing ${start}\u2013${end} of ${state.totalItems} ${options.itemLabel}`;
      getElement(options.summaryId).textContent = state.totalItems
        ? `Page ${state.currentPage} of ${totalPages}`
        : 'Page 0 of 0';
      getElement(options.prevButtonId).disabled = state.currentPage <= 1;
      getElement(options.nextButtonId).disabled = state.currentPage >= totalPages;
    }

    function paginate(items) {
      state.totalItems = items.length;
      clampCurrentPage();

      const start = (state.currentPage - 1) * state.pageSize;
      const pageItems = items.slice(start, start + state.pageSize);
      state.visibleItems = pageItems.length;
      render();
      return pageItems;
    }

    function resetPage() {
      state.currentPage = 1;
    }

    function changePage(delta, applyControls) {
      state.currentPage += delta;
      applyControls();
    }

    function changePageSize(applyControls) {
      state.pageSize = Number.parseInt(getElement(options.pageSizeId).value, 10) || 10;
      resetPage();
      applyControls();
    }

    function wireEvents(applyControls) {
      getElement(options.pageSizeId).addEventListener('change', () => changePageSize(applyControls));
      getElement(options.prevButtonId).addEventListener('click', () => changePage(-1, applyControls));
      getElement(options.nextButtonId).addEventListener('click', () => changePage(1, applyControls));
    }

    return {
      paginate,
      resetPage,
      wireEvents
    };
  }

  window.IamSentinelPagination = {
    createTablePager
  };
})();

import React from 'react';

export function Pagination({page, count, size = 25, onPage, busy = false}) {
  return <div className="action-group pagination" aria-label="Pagination">
    <button className="btn btn-secondary" disabled={busy || page === 0} onClick={() => onPage(page - 1)}>Previous page</button>
    <span>Page {page + 1} · {count} records</span>
    <button className="btn btn-secondary" disabled={busy || count < size} onClick={() => onPage(page + 1)}>Next page</button>
  </div>;
}

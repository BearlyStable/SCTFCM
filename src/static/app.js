// ─────────────────────────────────────────────────────────────────────────────
// Utilities
// ─────────────────────────────────────────────────────────────────────────────

function qs(sel, ctx = document) { return ctx.querySelector(sel); }
function qsa(sel, ctx = document) { return ctx.querySelectorAll(sel); }

function showToast(msg, type = 'ok') {
  const el = qs('#toast');
  el.textContent = msg;
  el.style.background = type === 'ok' ? '#14532d' : '#7f1d1d';
  el.style.color       = type === 'ok' ? '#86efac' : '#fca5a5';
  el.style.border      = type === 'ok' ? '1px solid #16a34a' : '1px solid #991b1b';
  el.style.opacity = '1';
  clearTimeout(el._t);
  el._t = setTimeout(() => { el.style.opacity = '0'; }, 3000);
}

function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function fmtDate(s) {
  if (!s) return '—';
  return s.slice(0, 16);
}

async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    showToast('Copied to clipboard');
  } catch {
    showToast('Copy failed', 'err');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Credential cell (masked value + reveal + copy) — event-delegated, no re-fetch
// ─────────────────────────────────────────────────────────────────────────────

function credCellHtml(value) {
  if (!value) return '<span class="cred-empty">—</span>';
  return `<span class="cred-value">
    <span class="cred-masked">••••••••</span>
    <span class="cred-full" hidden>${esc(value)}</span>
    <button class="btn-icon reveal-toggle" type="button" title="Show / hide">&#128065;</button>
    <button class="btn-icon copy-btn" type="button" title="Copy" data-copy="${esc(value)}">&#10697;</button>
  </span>`;
}

function passwordCellHtml(entry) {
  if (entry.password_is_blank) {
    return '<span class="badge badge-blankpass" title="Password confirmed empty">&#128274; empty</span>';
  }
  return credCellHtml(entry.password);
}

// Wires a password <input> + lock <button> pair so the button toggles a
// "confirmed empty password" state: locked disables/clears the input and
// shows a closed-lock icon; unlocked restores normal typing. Returns an
// accessor used when building the save payload.
function wirePasswordLock(inputSel, lockBtnSel, initialLocked) {
  const input = qs(inputSel);
  const btn = qs(lockBtnSel);
  let locked = !!initialLocked;

  function render() {
    btn.classList.toggle('active', locked);
    btn.innerHTML = locked ? '&#128274;' : '&#128275;';
    btn.title = locked ? 'Password confirmed empty — click to unlock' : 'Mark password as confirmed empty';
    input.disabled = locked;
    input.placeholder = locked ? '(confirmed empty)' : '';
    if (locked) input.value = '';
  }

  btn.onclick = () => {
    locked = !locked;
    render();
    if (!locked) input.focus();
  };

  render();
  return () => locked;
}

document.addEventListener('click', e => {
  const revealBtn = e.target.closest('.reveal-toggle');
  if (revealBtn) {
    e.stopPropagation();
    const wrap = revealBtn.closest('.cred-value');
    const masked = wrap.querySelector('.cred-masked');
    const full = wrap.querySelector('.cred-full');
    const hidden = full.hasAttribute('hidden');
    if (hidden) { full.removeAttribute('hidden'); masked.setAttribute('hidden', ''); }
    else { full.setAttribute('hidden', ''); masked.removeAttribute('hidden'); }
    return;
  }
  const copyBtn = e.target.closest('.copy-btn');
  if (copyBtn) {
    e.stopPropagation();
    copyToClipboard(copyBtn.dataset.copy);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// State
// ─────────────────────────────────────────────────────────────────────────────

const state = {
  targets: [],
  selectedTargetId: null,   // null = all targets, 'none' = unassigned, or a numeric id
  search: '',
  userpassOnly: false,
  notesOnly: false,
  reusedOnly: false,
  page: 1,
  perPage: 50,
  total: 0,
  selectedEntryId: null,
  sortBy: '',
  sortDir: 'desc',
  selectedIds: new Set(),
  currentPageIds: [],
};

// ─────────────────────────────────────────────────────────────────────────────
// Column visibility (per-viewer preference, persisted locally)
// ─────────────────────────────────────────────────────────────────────────────

const COLUMN_DEFS = [
  ['password', 'Password'],
  ['host',     'Host / Domain'],
  ['hash',     'Hash'],
  ['hashcat_mode', 'Hashcat Mode', false],
  ['target',   'Target'],
  ['tags',     'Tags'],
  ['notes',    'Notes'],
  ['updated',  'Updated'],
];

function defaultColumnVisibility() {
  return Object.fromEntries(COLUMN_DEFS.map(([k, , def]) => [k, def !== false]));
}

function loadVisibleColumns() {
  try {
    // sctfcm-visible-columns is the current key; ccm-visible-columns is the
    // pre-rename key, read once as a fallback so an existing viewer's column
    // choices survive the CCM -> SCTFCM rename.
    const raw = localStorage.getItem('sctfcm-visible-columns') || localStorage.getItem('ccm-visible-columns');
    if (raw) return { ...defaultColumnVisibility(), ...JSON.parse(raw) };
  } catch {}
  return defaultColumnVisibility();
}

const visibleColumns = loadVisibleColumns();

function saveVisibleColumns() {
  try { localStorage.setItem('sctfcm-visible-columns', JSON.stringify(visibleColumns)); } catch {}
}

function applyColumnVisibility() {
  COLUMN_DEFS.forEach(([key]) => {
    const show = visibleColumns[key] !== false;
    qsa(`[data-col="${key}"]`).forEach(el => { el.style.display = show ? '' : 'none'; });
  });
}

function renderColumnsPanel() {
  const panel = qs('#columns-panel');
  panel.innerHTML = COLUMN_DEFS.map(([key, label]) => `
    <label><input type="checkbox" class="col-toggle" data-key="${key}" ${visibleColumns[key] !== false ? 'checked' : ''}> ${esc(label)}</label>
  `).join('');
  qsa('.col-toggle', panel).forEach(cb => {
    cb.addEventListener('change', () => {
      visibleColumns[cb.dataset.key] = cb.checked;
      saveVisibleColumns();
      applyColumnVisibility();
    });
  });
}

qs('#columns-btn').addEventListener('click', e => {
  e.stopPropagation();
  const panel = qs('#columns-panel');
  panel.style.display = panel.style.display === 'none' ? 'flex' : 'none';
});
document.addEventListener('click', e => {
  const panel = qs('#columns-panel');
  if (panel.style.display !== 'none' && !e.target.closest('#columns-panel') && !e.target.closest('#columns-btn')) {
    panel.style.display = 'none';
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// API
// ─────────────────────────────────────────────────────────────────────────────

async function api(url, opts = {}) {
  const r = await fetch(url, opts);
  if (!r.ok) {
    let msg = await r.text();
    try { msg = JSON.parse(msg).error || msg; } catch {}
    throw new Error(msg);
  }
  if (r.status === 204) return null;
  return r.json();
}

// ─────────────────────────────────────────────────────────────────────────────
// Targets
// ─────────────────────────────────────────────────────────────────────────────

async function loadTargets() {
  const data = await api('/api/targets');
  state.targets = data.targets;
  state.unassignedCount = data.unassigned_count;
  renderTargetList();
  populateTargetSelect(qs('#entry-target'));
  populateTargetSelect(qs('#import-target'));
}

function renderTargetList() {
  const container = qs('#target-list');
  const totalEntries = state.targets.reduce((a, t) => a + t.entry_count, 0) + state.unassignedCount;

  let html = `<div class="target-item ${state.selectedTargetId === null ? 'active' : ''}" data-target="">
    <span>All targets</span><span style="color:#475569;font-size:0.7rem">${totalEntries}</span>
  </div>`;

  html += state.targets.map(t => `
    <div class="target-item ${state.selectedTargetId === String(t.id) ? 'active' : ''}" data-target="${t.id}">
      <span><span class="badge badge-target">${esc(t.name)}</span></span>
      <span style="color:#475569;font-size:0.7rem">${t.entry_count}</span>
    </div>`).join('');

  if (state.unassignedCount > 0) {
    html += `<div class="target-item ${state.selectedTargetId === 'none' ? 'active' : ''}" data-target="none">
      <span style="color:#94a3b8">Unassigned</span><span style="color:#475569;font-size:0.7rem">${state.unassignedCount}</span>
    </div>`;
  }

  container.innerHTML = html;
  qsa('.target-item', container).forEach(el => {
    el.addEventListener('click', () => {
      const val = el.dataset.target;
      state.selectedTargetId = val === '' ? null : val;
      state.page = 1;
      renderTargetList();
      loadEntries();
    });
  });
}

function populateTargetSelect(sel, keepValue) {
  const prev = keepValue !== undefined ? keepValue : sel.value;
  sel.innerHTML = '<option value="">— unassigned —</option>' +
    state.targets.map(t => `<option value="${t.id}">${esc(t.name)}</option>`).join('');
  if (prev) sel.value = prev;
}

// ─────────────────────────────────────────────────────────────────────────────
// Stats
// ─────────────────────────────────────────────────────────────────────────────

async function loadStats() {
  const s = await api('/api/stats');
  qs('#stat-total').textContent    = s.total;
  qs('#stat-users').textContent    = s.users;
  qs('#stat-password').textContent = s.with_password;
  qs('#stat-hash').textContent     = s.with_hash;
  qs('#stat-reused').textContent   = s.reused;
  qs('#stat-targets').textContent  = s.targets;
}

// ─────────────────────────────────────────────────────────────────────────────
// Entries list
// ─────────────────────────────────────────────────────────────────────────────

function buildQueryParams() {
  const p = new URLSearchParams();
  if (state.selectedTargetId !== null) p.set('target_id', state.selectedTargetId);
  if (state.search)       p.set('search', state.search);
  if (state.userpassOnly) p.set('userpass_only', '1');
  if (state.notesOnly)    p.set('notes_only', '1');
  if (state.reusedOnly)   p.set('reused_only', '1');
  if (state.sortBy) {
    p.set('sort_by', state.sortBy);
    p.set('sort_dir', state.sortDir);
  }
  p.set('page', state.page);
  p.set('per_page', state.perPage);
  return p;
}

function setSortColumn(col) {
  if (state.sortBy === col) {
    state.sortDir = state.sortDir === 'asc' ? 'desc' : 'asc';
  } else {
    state.sortBy = col;
    state.sortDir = col === 'updated_at' ? 'desc' : 'asc';
  }
  state.page = 1;
  updateSortHeaders();
  loadEntries();
}

function updateSortHeaders() {
  qsa('th[data-sort]').forEach(th => {
    const icon = th.querySelector('.sort-icon');
    if (!icon) return;
    if (th.dataset.sort === state.sortBy) {
      icon.textContent = state.sortDir === 'asc' ? '↑' : '↓';
      icon.style.opacity = '1';
      th.style.color = '#93c5fd';
    } else {
      icon.textContent = '↕';
      icon.style.opacity = '0.4';
      th.style.color = '';
    }
  });
}

async function loadEntries() {
  const tbody = qs('#entries-tbody');
  tbody.innerHTML = `<tr><td colspan="11" style="text-align:center;padding:24px;color:#475569">Loading…</td></tr>`;

  const data = await api('/api/entries?' + buildQueryParams());
  state.total = data.total;
  renderEntries(data.entries);
  renderPagination(data.total, data.page, data.per_page);

  qs('#filter-info').textContent = data.total > 0
    ? `Showing ${(data.page - 1) * data.per_page + 1}–${Math.min(data.page * data.per_page, data.total)} of ${data.total}`
    : 'No results';
}

function textPreview(s, len = 50) {
  if (!s) return '<span class="cred-empty">—</span>';
  const t = s.length > len ? s.slice(0, len - 2) + '…' : s;
  return `<span title="${esc(s)}" style="color:#94a3b8">${esc(t)}</span>`;
}

function tagsPreview(tags) {
  if (!tags || !tags.length) return '<span class="cred-empty">—</span>';
  return tags.slice(0, 4).map(t => `<span class="badge" style="background:#1e293b;color:#93c5fd;border-color:#334155">#${esc(t)}</span>`).join(' ') +
    (tags.length > 4 ? ` <span style="color:#475569;font-size:0.7rem">+${tags.length - 4}</span>` : '');
}

function reuseBadge(count, label) {
  if (count <= 1) return '';
  return `<span class="badge badge-reused" title="${label} reused across ${count} entries">&#9888; ${count}</span>`;
}

function renderEntries(entries) {
  const tbody = qs('#entries-tbody');
  state.currentPageIds = entries.map(en => en.id);

  if (!entries.length) {
    tbody.innerHTML = `<tr><td colspan="11" style="text-align:center;padding:40px;color:#475569">No entries match the current filters.</td></tr>`;
    updateBulkBar();
    applyColumnVisibility();
    return;
  }

  tbody.innerHTML = entries.map(en => {
    const bg = en.id === state.selectedEntryId ? 'background:#1e3a5f' : '';
    const reusedRow = (en.password_reuse_count > 1 || en.hash_reuse_count > 1) ? ' row-reused' : '';
    const checked = state.selectedIds.has(en.id) ? 'checked' : '';

    const targetCell = en.target_name
      ? `<span class="badge badge-target">${esc(en.target_name)}</span>`
      : `<span class="badge badge-none">unassigned</span>`;

    const hostCell = (en.host || en.domain)
      ? `${en.host ? `<div style="color:#e2e8f0">${esc(en.host)}</div>` : ''}${en.domain ? `<div style="color:#64748b;font-size:0.7rem">${esc(en.domain)}${en.service ? ' · ' + esc(en.service) : ''}</div>` : (en.service ? `<div style="color:#64748b;font-size:0.7rem">${esc(en.service)}</div>` : '')}`
      : (en.service ? `<div style="color:#64748b;font-size:0.7rem">${esc(en.service)}</div>` : '<span class="cred-empty">—</span>');

    const hashCell = en.hash
      ? `${en.hash_type ? `<span class="badge badge-hashtype">${esc(en.hash_type)}</span> ` : ''}${credCellHtml(en.hash)}`
      : (en.hash_type ? `<span class="badge badge-hashtype">${esc(en.hash_type)}</span>` : '<span class="cred-empty">—</span>');

    const hashcatCell = (en.hashcat_mode !== null && en.hashcat_mode !== undefined)
      ? `<span class="badge badge-hashtype" title="Hashcat mode ${en.hashcat_mode}">${en.hashcat_mode}</span>`
      : '<span class="cred-empty">—</span>';

    return `<tr class="row-hover${reusedRow}" data-id="${en.id}" style="border-bottom:1px solid #1e293b;${bg}">
      <td style="padding:7px 6px;text-align:center"><input type="checkbox" class="row-select-cb" data-id="${en.id}" style="width:auto;accent-color:#3b82f6" ${checked}></td>
      <td style="padding:7px 10px;font-weight:600;color:#e2e8f0">${en.username ? esc(en.username) : '<span class="cred-empty">—</span>'}</td>
      <td data-col="password" style="padding:7px 10px">${passwordCellHtml(en)} ${reuseBadge(en.password_reuse_count, 'Password')}</td>
      <td data-col="host" style="padding:7px 10px">${hostCell}</td>
      <td data-col="hash" style="padding:7px 10px">${hashCell} ${reuseBadge(en.hash_reuse_count, 'Hash')}</td>
      <td data-col="hashcat_mode" style="padding:7px 10px">${hashcatCell}</td>
      <td data-col="target" style="padding:7px 10px">${targetCell}</td>
      <td data-col="tags" style="padding:7px 10px">${tagsPreview(en.tags)}</td>
      <td data-col="notes" style="padding:7px 10px">${textPreview(en.notes)}</td>
      <td data-col="updated" style="padding:7px 10px;color:#64748b;font-size:0.72rem">${fmtDate(en.updated_at)}</td>
      <td style="padding:4px 6px;text-align:center">
        <button class="btn-icon row-delete-btn" data-id="${en.id}" title="Delete">&#128465;</button>
      </td>
    </tr>`;
  }).join('');

  applyColumnVisibility();
  updateBulkBar();

  qsa('tr[data-id]', tbody).forEach(row => {
    row.addEventListener('click', e => {
      if (e.target.closest('.row-delete-btn') || e.target.closest('.cred-value') || e.target.closest('.row-select-cb')) return;
      showDetail(parseInt(row.dataset.id));
    });
  });

  qsa('.row-select-cb', tbody).forEach(cb => {
    cb.addEventListener('change', () => {
      const id = parseInt(cb.dataset.id);
      if (cb.checked) state.selectedIds.add(id);
      else state.selectedIds.delete(id);
      updateBulkBar();
    });
  });

  qsa('.row-delete-btn', tbody).forEach(btn => {
    btn.addEventListener('click', async e => {
      e.stopPropagation();
      await deleteEntry(parseInt(btn.dataset.id));
    });
  });
}

async function deleteEntry(id) {
  if (!confirm('Delete this entry? This cannot be undone.')) return;
  try {
    await api(`/api/entries/${id}`, { method: 'DELETE' });
    if (state.selectedEntryId === id) closeDetail();
    state.selectedIds.delete(id);
    showToast('Entry deleted');
    await Promise.all([loadEntries(), loadStats(), loadTargets()]);
  } catch (err) {
    showToast('Delete failed: ' + err.message, 'err');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pagination
// ─────────────────────────────────────────────────────────────────────────────

function renderPagination(total, page, perPage) {
  const totalPages = Math.ceil(total / perPage);
  const ctrl = qs('#pagination-controls');
  if (totalPages <= 1) { ctrl.innerHTML = ''; return; }

  const pageNums = [];
  for (let p = 1; p <= totalPages; p++) {
    if (p === 1 || p === totalPages || (p >= page - 2 && p <= page + 2)) {
      pageNums.push(p);
    } else if (pageNums.at(-1) !== '…') {
      pageNums.push('…');
    }
  }

  ctrl.innerHTML = `
    <button class="pagination-btn" id="pg-prev" ${page <= 1 ? 'disabled' : ''}>&#8592;</button>
    ${pageNums.map(p => p === '…'
      ? `<span style="color:#475569;padding:0 4px">…</span>`
      : `<button class="pagination-btn ${p === page ? 'current' : ''}" data-page="${p}">${p}</button>`
    ).join('')}
    <button class="pagination-btn" id="pg-next" ${page >= totalPages ? 'disabled' : ''}>&#8594;</button>
  `;

  qs('#pg-prev')?.addEventListener('click', () => { if (state.page > 1) { state.page--; loadEntries(); } });
  qs('#pg-next')?.addEventListener('click', () => { if (state.page < totalPages) { state.page++; loadEntries(); } });
  qsa('[data-page]', ctrl).forEach(btn => {
    btn.addEventListener('click', () => { state.page = parseInt(btn.dataset.page); loadEntries(); });
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Bulk selection & actions
// ─────────────────────────────────────────────────────────────────────────────

function updateBulkBar() {
  const n = state.selectedIds.size;
  qs('#bulk-bar').style.display = n ? 'flex' : 'none';
  qs('#bulk-count').textContent = `${n} selected`;

  const selectAll = qs('#select-all-cb');
  const onPage = state.currentPageIds;
  const selectedOnPage = onPage.filter(id => state.selectedIds.has(id)).length;
  selectAll.checked = onPage.length > 0 && selectedOnPage === onPage.length;
  selectAll.indeterminate = selectedOnPage > 0 && selectedOnPage < onPage.length;
}

qs('#select-all-cb').addEventListener('change', e => {
  if (e.target.checked) state.currentPageIds.forEach(id => state.selectedIds.add(id));
  else state.currentPageIds.forEach(id => state.selectedIds.delete(id));
  qsa('.row-select-cb').forEach(cb => { cb.checked = state.selectedIds.has(parseInt(cb.dataset.id)); });
  updateBulkBar();
});

qs('#bulk-clear-btn').addEventListener('click', () => {
  state.selectedIds.clear();
  qsa('.row-select-cb').forEach(cb => { cb.checked = false; });
  updateBulkBar();
});

qs('#bulk-delete-btn').addEventListener('click', async () => {
  const ids = Array.from(state.selectedIds);
  if (!ids.length) return;
  if (!confirm(`Delete ${ids.length} selected entr${ids.length === 1 ? 'y' : 'ies'}? This cannot be undone.`)) return;
  try {
    const result = await api('/api/entries/bulk', {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids }),
    });
    state.selectedIds.clear();
    showToast(`Deleted ${result.deleted} entries`);
    await Promise.all([loadEntries(), loadStats(), loadTargets()]);
  } catch (err) {
    showToast('Bulk delete failed: ' + err.message, 'err');
  }
});

// ── Bulk edit modal ─────────────────────────────────────────────────────────

const BULK_EDIT_FIELDS = [
  ['target_id', 'Target', 'select'],
  ['host',      'Host / IP', 'text'],
  ['domain',    'Domain', 'text'],
  ['service',   'Service / Port', 'text'],
  ['hash_type', 'Hash Type', 'text'],
  ['hashcat_mode', 'Hashcat Mode', 'text'],
];

function renderBulkEditFields() {
  const container = qs('#bulk-edit-fields');
  container.innerHTML = BULK_EDIT_FIELDS.map(([key, label, type]) => {
    const control = type === 'select'
      ? `<select id="bulk-f-${key}" disabled><option value="">— unassigned —</option>${
          state.targets.map(t => `<option value="${t.id}">${esc(t.name)}</option>`).join('')
        }</select>`
      : `<input type="text" id="bulk-f-${key}" disabled>`;
    return `<div class="form-field" style="display:flex;align-items:center;gap:8px">
      <input type="checkbox" class="bulk-f-toggle" data-key="${key}" style="width:auto;accent-color:#3b82f6">
      <span style="min-width:110px;color:#94a3b8;font-size:0.78rem">${esc(label)}</span>
      ${control}
    </div>`;
  }).join('');

  qsa('.bulk-f-toggle', container).forEach(cb => {
    cb.addEventListener('change', () => {
      qs(`#bulk-f-${cb.dataset.key}`).disabled = !cb.checked;
    });
  });
}

qs('#bulk-edit-btn').addEventListener('click', () => {
  const n = state.selectedIds.size;
  if (!n) return;
  qs('#bulk-edit-count').textContent = `Applying to ${n} selected entr${n === 1 ? 'y' : 'ies'}.`;
  renderBulkEditFields();
  qs('#bulk-tags-add').value = '';
  qs('#bulk-tags-remove').value = '';
  qs('#bulk-edit-modal').style.display = 'flex';
});

qs('#cancel-bulk-edit-btn').addEventListener('click', () => { qs('#bulk-edit-modal').style.display = 'none'; });
qs('#bulk-edit-modal').addEventListener('click', e => {
  if (e.target === qs('#bulk-edit-modal')) qs('#bulk-edit-modal').style.display = 'none';
});

qs('#do-bulk-edit-btn').addEventListener('click', async () => {
  const fields = {};
  qsa('.bulk-f-toggle:checked').forEach(cb => {
    const key = cb.dataset.key;
    const el = qs(`#bulk-f-${key}`);
    fields[key] = key === 'target_id' ? (el.value || null) : el.value;
  });
  const tagsAdd = qs('#bulk-tags-add').value.split(',').map(t => t.trim().replace(/^#+/, '')).filter(Boolean);
  const tagsRemove = qs('#bulk-tags-remove').value.split(',').map(t => t.trim().replace(/^#+/, '')).filter(Boolean);

  if (!Object.keys(fields).length && !tagsAdd.length && !tagsRemove.length) {
    showToast('Enable at least one field to change', 'err');
    return;
  }

  try {
    const result = await api('/api/entries/bulk', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: Array.from(state.selectedIds), fields, tags_add: tagsAdd, tags_remove: tagsRemove }),
    });
    let msg = `Updated ${result.updated} entries`;
    if (result.skipped_empty.length) msg += `, skipped ${result.skipped_empty.length} (would have no username/password/hash)`;
    showToast(msg);
    qs('#bulk-edit-modal').style.display = 'none';
    state.selectedIds.clear();
    await Promise.all([loadEntries(), loadStats(), loadTargets()]);
  } catch (err) {
    showToast('Bulk edit failed: ' + err.message, 'err');
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Detail panel
// ─────────────────────────────────────────────────────────────────────────────

function fieldRow(label, valueHtml) {
  return `<tr><td class="detail-key" style="padding:5px 10px 5px 0;vertical-align:top;white-space:nowrap">${esc(label)}</td>
    <td class="detail-val" style="padding:5px 0">${valueHtml}</td></tr>`;
}

async function showDetail(id) {
  state.selectedEntryId = id;
  qsa('tr[data-id]').forEach(r => {
    r.style.background = parseInt(r.dataset.id) === id ? '#1e3a5f' : '';
  });

  qs('#detail-panel').style.display = 'flex';
  qs('#detail-content').innerHTML = '<div style="color:#475569;padding:20px">Loading…</div>';

  const entry = await api(`/api/entries/${id}`);
  renderDetail(entry);
}

function closeDetail() {
  qs('#detail-panel').style.display = 'none';
  state.selectedEntryId = null;
  qsa('tr[data-id]').forEach(r => r.style.background = '');
}

function renderDetail(entry) {
  qs('#detail-title').textContent = entry.username || entry.host || `Entry #${entry.id}`;

  const targetOptions = '<option value="">— unassigned —</option>' +
    state.targets.map(t => `<option value="${t.id}" ${t.id === entry.target_id ? 'selected' : ''}>${esc(t.name)}</option>`).join('');

  const detailContent = qs('#detail-content');
  detailContent.innerHTML = `
    <div class="form-grid">
      <div class="form-field">
        <label>Target</label>
        <select id="d-target">${targetOptions}</select>
      </div>
      <div class="form-field"></div>
      <div class="form-field">
        <label>Username</label>
        <input type="text" id="d-username" value="${esc(entry.username || '')}">
      </div>
      <div class="form-field">
        <label>Password</label>
        <div class="password-field-row">
          <input type="text" id="d-password" value="${esc(entry.password || '')}">
          <button type="button" class="btn-icon lock-toggle" id="d-password-lock" title="Mark password as confirmed empty">&#128275;</button>
        </div>
      </div>
      <div class="form-field">
        <label>Host / IP</label>
        <input type="text" id="d-host" value="${esc(entry.host || '')}">
      </div>
      <div class="form-field">
        <label>Domain</label>
        <input type="text" id="d-domain" value="${esc(entry.domain || '')}">
      </div>
      <div class="form-field">
        <label>Service / Port</label>
        <input type="text" id="d-service" value="${esc(entry.service || '')}">
      </div>
      <div class="form-field">
        <label>Hash Type</label>
        <input type="text" id="d-hashtype" value="${esc(entry.hash_type || '')}">
      </div>
      <div class="form-field">
        <label>Hashcat Mode <span style="color:#475569;font-weight:400">(number)</span></label>
        <input type="text" inputmode="numeric" id="d-hashcatmode" value="${entry.hashcat_mode === null || entry.hashcat_mode === undefined ? '' : entry.hashcat_mode}">
      </div>
      <div class="form-field" style="grid-column:1 / -1">
        <label>Hash</label>
        <input type="text" id="d-hash" value="${esc(entry.hash || '')}">
      </div>
    </div>
    <div style="display:flex;align-items:center;gap:8px;margin-top:10px">
      <button class="btn btn-primary" id="d-save-btn" style="padding:4px 14px">Save</button>
      <span id="d-save-status" class="comment-status"></span>
    </div>

    <div style="margin-top:16px" id="d-reuse-block"></div>

    <div style="margin-top:16px">
      <div class="detail-section-label">Tags</div>
      <div class="tag-chips" id="d-tag-chips"></div>
      <div class="tag-input-row">
        <span class="tag-hash">#</span>
        <input type="text" id="d-tag-input" placeholder="add tag, press Enter">
      </div>
    </div>

    <div style="margin-top:16px">
      <div class="detail-section-label">Notes</div>
      <textarea id="d-notes" rows="5" placeholder="Add notes about this entry…">${esc(entry.notes || '')}</textarea>
    </div>

    <div style="margin-top:16px;color:#475569;font-size:0.7rem">
      Created ${fmtDate(entry.created_at)} · Updated ${fmtDate(entry.updated_at)}
    </div>
  `;

  // ── Reuse info ──────────────────────────────────────────────────────────
  const reuseBlock = qs('#d-reuse-block');
  let reuseHtml = '';
  if (entry.reused_password_with && entry.reused_password_with.length) {
    reuseHtml += `<div class="detail-section-label" style="color:#f59e0b">Password also used by</div>` +
      entry.reused_password_with.map(r =>
        `<div><a href="#" class="reuse-link" data-goto="${r.id}">${esc(r.username || 'entry #' + r.id)}</a>` +
        `${r.target_name ? ` <span style="color:#475569;font-size:0.72rem">@ ${esc(r.target_name)}</span>` : ''}</div>`
      ).join('') + '<div style="margin-bottom:10px"></div>';
  }
  if (entry.reused_hash_with && entry.reused_hash_with.length) {
    reuseHtml += `<div class="detail-section-label" style="color:#f59e0b">Hash also used by</div>` +
      entry.reused_hash_with.map(r =>
        `<div><a href="#" class="reuse-link" data-goto="${r.id}">${esc(r.username || 'entry #' + r.id)}</a>` +
        `${r.target_name ? ` <span style="color:#475569;font-size:0.72rem">@ ${esc(r.target_name)}</span>` : ''}</div>`
      ).join('');
  }
  reuseBlock.innerHTML = reuseHtml;
  qsa('.reuse-link', reuseBlock).forEach(a => {
    a.addEventListener('click', e => { e.preventDefault(); showDetail(parseInt(a.dataset.goto)); });
  });

  const detailPasswordLocked = wirePasswordLock('#d-password', '#d-password-lock', entry.password_is_blank);

  // ── Save core fields + notes ───────────────────────────────────────────
  qs('#d-save-btn').addEventListener('click', async () => {
    const btn = qs('#d-save-btn');
    const status = qs('#d-save-status');
    btn.disabled = true;
    status.textContent = 'Saving…';
    try {
      const updated = await api(`/api/entries/${entry.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_id: qs('#d-target').value || null,
          username:  qs('#d-username').value,
          password:  qs('#d-password').value,
          password_is_blank: detailPasswordLocked(),
          host:      qs('#d-host').value,
          domain:    qs('#d-domain').value,
          service:   qs('#d-service').value,
          hash_type: qs('#d-hashtype').value,
          hashcat_mode: qs('#d-hashcatmode').value,
          hash:      qs('#d-hash').value,
          notes:     qs('#d-notes').value,
        }),
      });
      status.textContent = 'Saved';
      setTimeout(() => { status.textContent = ''; }, 2000);
      await Promise.all([loadEntries(), loadStats(), loadTargets()]);
      renderDetail(updated);
    } catch (err) {
      status.style.color = '#f87171';
      status.textContent = 'Save failed: ' + err.message;
    } finally {
      btn.disabled = false;
    }
  });

  // ── Tags ─────────────────────────────────────────────────────────────────
  let entryTags = Array.isArray(entry.tags) ? [...entry.tags] : [];

  function renderTagChips() {
    const chips = qs('#d-tag-chips');
    chips.innerHTML = entryTags.map(t =>
      `<span class="tag-chip" data-tag="${esc(t)}">` +
      `<span class="tag-chip-text">#${esc(t)}</span>` +
      `<button class="tag-remove-btn" title="Remove">×</button></span>`
    ).join('');
    chips.querySelectorAll('.tag-remove-btn').forEach(btn => {
      btn.onclick = async () => {
        const tag = btn.closest('.tag-chip').dataset.tag;
        entryTags = entryTags.filter(t => t !== tag);
        await persistTags();
        renderTagChips();
      };
    });
  }

  async function persistTags() {
    const result = await api(`/api/entries/${entry.id}/tags`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tags: entryTags }),
    });
    entry.tags = result.tags;
    loadEntries();
  }

  const tagInput = qs('#d-tag-input');
  tagInput.addEventListener('keydown', async e => {
    if (e.key !== 'Enter') return;
    e.preventDefault();
    const raw = tagInput.value.trim().replace(/^#+/, '');
    if (!raw || entryTags.includes(raw)) { tagInput.value = ''; return; }
    entryTags.push(raw);
    tagInput.value = '';
    await persistTags();
    renderTagChips();
  });

  renderTagChips();

  qs('#detail-delete-btn').onclick = () => deleteEntry(entry.id);
}

qs('#close-detail-btn').addEventListener('click', closeDetail);

// ─────────────────────────────────────────────────────────────────────────────
// Filters
// ─────────────────────────────────────────────────────────────────────────────

let searchTimer = null;
qs('#search-input').addEventListener('input', e => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    state.search = e.target.value.trim();
    state.page = 1;
    loadEntries();
  }, 300);
});

qs('#userpass-only').addEventListener('change', e => {
  state.userpassOnly = e.target.checked;
  state.page = 1;
  loadEntries();
});

qs('#notes-only').addEventListener('change', e => {
  state.notesOnly = e.target.checked;
  state.page = 1;
  loadEntries();
});

qs('#reused-only').addEventListener('change', e => {
  state.reusedOnly = e.target.checked;
  state.page = 1;
  loadEntries();
});

qs('#per-page-select').addEventListener('change', e => {
  state.perPage = parseInt(e.target.value);
  state.page = 1;
  loadEntries();
});

qs('#clear-filters-btn').addEventListener('click', () => {
  state.search = '';      qs('#search-input').value = '';
  state.userpassOnly = false; qs('#userpass-only').checked = false;
  state.notesOnly = false; qs('#notes-only').checked = false;
  state.reusedOnly = false; qs('#reused-only').checked = false;
  state.selectedTargetId = null;
  state.page = 1;
  renderTargetList();
  loadEntries();
});

qsa('th[data-sort]').forEach(th => {
  th.addEventListener('click', () => setSortColumn(th.dataset.sort));
});
updateSortHeaders();

// ─────────────────────────────────────────────────────────────────────────────
// Add Entry modal
// ─────────────────────────────────────────────────────────────────────────────

let entryPasswordLocked = () => false;

function openEntryModal() {
  qs('#entry-modal-title').textContent = 'Add Entry';
  qs('#entry-target').value = (state.selectedTargetId && state.selectedTargetId !== 'none') ? state.selectedTargetId : '';
  qs('#entry-username').value = '';
  qs('#entry-password').value = '';
  qs('#entry-host').value = '';
  qs('#entry-domain').value = '';
  qs('#entry-service').value = '';
  qs('#entry-hashtype').value = '';
  qs('#entry-hashcatmode').value = '';
  qs('#entry-hash').value = '';
  qs('#entry-tags').value = '';
  qs('#entry-notes').value = '';
  entryPasswordLocked = wirePasswordLock('#entry-password', '#entry-password-lock', false);
  qs('#entry-modal').style.display = 'flex';
}

qs('#add-entry-btn').addEventListener('click', openEntryModal);
qs('#cancel-entry-btn').addEventListener('click', () => { qs('#entry-modal').style.display = 'none'; });
qs('#entry-modal').addEventListener('click', e => {
  if (e.target === qs('#entry-modal')) qs('#entry-modal').style.display = 'none';
});

qs('#save-entry-btn').addEventListener('click', async () => {
  const tags = qs('#entry-tags').value.split(',').map(t => t.trim().replace(/^#+/, '')).filter(Boolean);
  const body = {
    target_id: qs('#entry-target').value || null,
    username:  qs('#entry-username').value,
    password:  qs('#entry-password').value,
    password_is_blank: entryPasswordLocked(),
    host:      qs('#entry-host').value,
    domain:    qs('#entry-domain').value,
    service:   qs('#entry-service').value,
    hash_type: qs('#entry-hashtype').value,
    hashcat_mode: qs('#entry-hashcatmode').value,
    hash:      qs('#entry-hash').value,
    notes:     qs('#entry-notes').value,
    tags,
  };
  try {
    const result = await api('/api/entries', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    qs('#entry-modal').style.display = 'none';
    const messages = {
      inserted: 'Entry added',
      updated: 'Matching entry already existed — updated it in place instead of creating a duplicate',
      annotated: 'Matching entry already had a different credential type set — flagged it #check and added your value to its notes instead of overwriting',
    };
    showToast(messages[result._merge_action] || 'Entry added');
    if (result._merge_action !== 'inserted') showDetail(result.id);
    await Promise.all([loadEntries(), loadStats(), loadTargets()]);
  } catch (err) {
    showToast('Failed: ' + err.message, 'err');
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Manage Targets modal
// ─────────────────────────────────────────────────────────────────────────────

function renderManageTargetsList() {
  const list = qs('#targets-manage-list');
  if (!state.targets.length) {
    list.innerHTML = '<div style="color:#475569;font-size:0.8rem;padding:6px">No targets yet.</div>';
    return;
  }
  list.innerHTML = state.targets.map(t => `
    <div class="target-manage-row" data-id="${t.id}">
      <input type="text" class="target-name-input" value="${esc(t.name)}">
      <span style="color:#475569;font-size:0.72rem;white-space:nowrap">${t.entry_count} entries</span>
      <button class="btn-icon target-delete-btn" title="Delete target">&#128465;</button>
    </div>`).join('');

  qsa('.target-name-input', list).forEach(input => {
    const original = input.value;
    input.addEventListener('keydown', e => { if (e.key === 'Enter') input.blur(); });
    input.addEventListener('blur', async () => {
      const row = input.closest('.target-manage-row');
      const id = parseInt(row.dataset.id);
      const name = input.value.trim();
      if (!name || name === original) { input.value = original; return; }
      try {
        await api(`/api/targets/${id}`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name }),
        });
        showToast('Target renamed');
        await loadTargets();
        renderManageTargetsList();
        loadEntries();
      } catch (err) {
        showToast('Rename failed: ' + err.message, 'err');
        input.value = original;
      }
    });
  });

  qsa('.target-delete-btn', list).forEach(btn => {
    btn.addEventListener('click', async () => {
      const row = btn.closest('.target-manage-row');
      const id = parseInt(row.dataset.id);
      const name = qs('.target-name-input', row).value;
      if (!confirm(`Delete target "${name}"? Its entries will become unassigned (not deleted).`)) return;
      try {
        await api(`/api/targets/${id}`, { method: 'DELETE' });
        showToast('Target deleted');
        if (state.selectedTargetId === String(id)) state.selectedTargetId = null;
        await loadTargets();
        renderManageTargetsList();
        loadEntries();
      } catch (err) {
        showToast('Delete failed: ' + err.message, 'err');
      }
    });
  });
}

qs('#manage-targets-btn').addEventListener('click', () => {
  renderManageTargetsList();
  qs('#targets-modal').style.display = 'flex';
});
qs('#close-targets-btn').addEventListener('click', () => { qs('#targets-modal').style.display = 'none'; });
qs('#targets-modal').addEventListener('click', e => {
  if (e.target === qs('#targets-modal')) qs('#targets-modal').style.display = 'none';
});

qs('#add-target-btn').addEventListener('click', async () => {
  const input = qs('#new-target-name');
  const name = input.value.trim();
  if (!name) return;
  try {
    await api('/api/targets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name }),
    });
    input.value = '';
    showToast('Target added');
    await loadTargets();
    renderManageTargetsList();
  } catch (err) {
    showToast('Failed: ' + err.message, 'err');
  }
});
qs('#new-target-name').addEventListener('keydown', e => {
  if (e.key === 'Enter') qs('#add-target-btn').click();
});

// ─────────────────────────────────────────────────────────────────────────────
// Bulk import modal
// ─────────────────────────────────────────────────────────────────────────────

function updateImportFormatUI() {
  const fmt = qs('#import-format').value;
  qs('#import-hashtype-field').style.display = (fmt === 'user_hash') ? '' : 'none';
}

qs('#import-btn').addEventListener('click', () => {
  qs('#import-format').value = 'user_pass';
  qs('#import-target').value = (state.selectedTargetId && state.selectedTargetId !== 'none') ? state.selectedTargetId : '';
  qs('#import-hashtype').value = '';
  qs('#import-tags').value = '';
  qs('#import-textarea').value = '';
  qs('#import-status').textContent = '';
  updateImportFormatUI();
  qs('#import-modal').style.display = 'flex';
});
qs('#import-format').addEventListener('change', updateImportFormatUI);

qs('#cancel-import-btn').addEventListener('click', () => { qs('#import-modal').style.display = 'none'; });
qs('#import-modal').addEventListener('click', e => {
  if (e.target === qs('#import-modal')) qs('#import-modal').style.display = 'none';
});

qs('#import-browse-link').addEventListener('click', () => qs('#import-file-input').click());
qs('#import-drop-zone').addEventListener('click', () => qs('#import-file-input').click());

function loadFileIntoTextarea(file) {
  const reader = new FileReader();
  reader.onload = () => { qs('#import-textarea').value = reader.result; };
  reader.readAsText(file);
}
qs('#import-file-input').addEventListener('change', e => {
  if (e.target.files[0]) loadFileIntoTextarea(e.target.files[0]);
});
const importDropZone = qs('#import-drop-zone');
importDropZone.addEventListener('dragover', e => { e.preventDefault(); importDropZone.classList.add('dragover'); });
importDropZone.addEventListener('dragleave', () => importDropZone.classList.remove('dragover'));
importDropZone.addEventListener('drop', e => {
  e.preventDefault();
  importDropZone.classList.remove('dragover');
  if (e.dataTransfer.files[0]) loadFileIntoTextarea(e.dataTransfer.files[0]);
});

qs('#do-import-btn').addEventListener('click', async () => {
  const text = qs('#import-textarea').value;
  if (!text.trim()) { showToast('Nothing to import', 'err'); return; }
  const tags = qs('#import-tags').value.split(',').map(t => t.trim().replace(/^#+/, '')).filter(Boolean);
  const btn = qs('#do-import-btn');
  const status = qs('#import-status');
  btn.disabled = true;
  status.textContent = 'Importing…';
  try {
    const result = await api('/api/entries/bulk_import', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        format: qs('#import-format').value,
        target_id: qs('#import-target').value || null,
        hash_type: qs('#import-hashtype').value,
        tags,
        text,
      }),
    });
    const parts = [`created ${result.created}`];
    if (result.updated)   parts.push(`updated ${result.updated}`);
    if (result.annotated) parts.push(`flagged ${result.annotated} for review (tagged #check)`);
    if (result.skipped)   parts.push(`skipped ${result.skipped}`);
    const msg = parts.join(', ');
    status.textContent = msg + (result.errors.length ? ':\n' + result.errors.join('\n') : '');
    status.style.whiteSpace = 'pre-wrap';
    showToast(msg);
    await Promise.all([loadEntries(), loadStats(), loadTargets()]);
    if (!result.errors.length) {
      setTimeout(() => { qs('#import-modal').style.display = 'none'; }, 1400);
    }
  } catch (err) {
    status.textContent = 'Import failed: ' + err.message;
  } finally {
    btn.disabled = false;
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Export modal
// ─────────────────────────────────────────────────────────────────────────────

const EXPORT_FIELDS = [
  ['username',    'Username',   true],
  ['password',    'Password',   true],
  ['hash_type',   'Hash Type',  true],
  ['hash',        'Hash',       true],
  ['hashcat_mode', 'Hashcat Mode', false],
  ['host',        'Host',       false],
  ['domain',      'Domain',     false],
  ['service',     'Service',    false],
  ['target_name', 'Target',     false],
  ['tags',        'Tags',       false],
  ['notes',       'Notes',      false],
  ['created_at',  'Created',    false],
  ['updated_at',  'Updated',    false],
];

qs('#export-btn').addEventListener('click', () => {
  qs('#export-fields').innerHTML = EXPORT_FIELDS.map(([key, label, def]) => `
    <label style="display:flex;align-items:center;gap:7px;cursor:pointer;font-size:0.82rem;color:#94a3b8">
      <input type="checkbox" class="export-field-cb" value="${key}" ${def ? 'checked' : ''} style="width:auto;accent-color:#3b82f6"> ${esc(label)}
    </label>`).join('');
  qs('#export-modal').style.display = 'flex';
});

qs('#cancel-export-btn').addEventListener('click', () => { qs('#export-modal').style.display = 'none'; });
qs('#export-modal').addEventListener('click', e => {
  if (e.target === qs('#export-modal')) qs('#export-modal').style.display = 'none';
});

qs('#do-backup-btn').addEventListener('click', () => {
  window.location.href = '/api/backup';
});

qs('#do-hashcat-export-btn').addEventListener('click', () => {
  const params = buildQueryParams();
  params.delete('page');
  params.delete('per_page');
  window.location.href = '/api/entries/export/hashcat?' + params.toString();
});

qs('#do-export-btn').addEventListener('click', () => {
  const fields = Array.from(qsa('.export-field-cb:checked', qs('#export-fields'))).map(cb => cb.value);
  if (!fields.length) {
    showToast('Select at least one field', 'err');
    return;
  }
  const params = buildQueryParams();
  params.delete('page');
  params.delete('per_page');
  params.set('fields', fields.join(','));
  window.location.href = '/api/entries/export?' + params.toString();
  qs('#export-modal').style.display = 'none';
});

// ─────────────────────────────────────────────────────────────────────────────
// Init
// ─────────────────────────────────────────────────────────────────────────────

async function init() {
  renderColumnsPanel();
  applyColumnVisibility();
  await loadTargets();
  await Promise.all([loadStats(), loadEntries()]);
}

init();

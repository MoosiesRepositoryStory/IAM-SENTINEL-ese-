/*
 * IAM Sentinel — Phase 1 Slice 3: context menu, command palette, keyboard
 * shortcuts (§8.3-8.6). Vanilla JS (no framework) so it keeps working across
 * htmx-swapped content without a re-mount step; Alpine stays reserved for
 * small local UI state as in earlier slices (theme, facet dropdowns, the
 * drawer's exception-form reveal).
 *
 * Every mutation here calls the *exact* routes built in 2a/2b/2c — this file
 * only decides which route to call and how to render the result; it does not
 * re-implement any validation or state-machine rule (the server remains the
 * single source of truth, same as the htmx-driven forms already in the app).
 */

window.Sentinel = (function () {
  'use strict';

  const ROUTES = {
    drawer: (id) => `/findings/${id}`,
    transition: (id) => `/findings/${id}/transition`,
    suppress: (id) => `/findings/${id}/suppress`,
    acceptRisk: (id) => `/findings/${id}/accept-risk`,
    assign: (id) => `/findings/${id}/assign`,
    bulkTransition: '/findings/bulk/transition',
    bulkAssign: '/findings/bulk/assign',
    bulkSuppress: '/findings/bulk/suppress',
    bulkAcceptRisk: '/findings/bulk/accept-risk',
    paletteSearch: '/command-palette/search',
  };

  // ------------------------------------------------------------------ rbac --
  // Mirrors app.services.rbac's read_only < analyst < admin ladder (§10.2).
  // The server is the actual authority (every route is decorated with
  // require_role and 403s + audits an unauthorized POST regardless of this) —
  // this only decides which client-built controls (context menu items,
  // keyboard shortcuts) to offer, so a role never sees a control for
  // something it can't do. Role comes from <body data-role> (base.html),
  // set once per page load from the real session.
  const ROLE_RANK = { read_only: 1, analyst: 2, admin: 3 };
  function currentRole() { return document.body.dataset.role || ''; }
  function roleAtLeast(min) { return (ROLE_RANK[currentRole()] || 0) >= ROLE_RANK[min]; }

  // ---------------------------------------------------------------- utils --
  function currentQueryString() {
    // Bulk actions re-render the table; carrying the page's current sort/
    // filter/page query string keeps that render showing the same view
    // instead of silently resetting to defaults.
    return window.location.search || '';
  }

  function rowEls() {
    return Array.from(document.querySelectorAll('table.findings tbody tr'));
  }

  function toast(message) {
    const region = document.getElementById('toast-region');
    if (!region) return;
    region.innerHTML = '';
    const el = document.createElement('div');
    el.className = 'toast';
    el.textContent = message;
    region.appendChild(el);
    setTimeout(() => el.remove(), 3500);
  }

  function isEditableTarget(el) {
    if (!el) return false;
    const tag = el.tagName;
    return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || el.isContentEditable;
  }

  // ------------------------------------------------------------ selection --
  const selection = new Set();

  function groupIdOf(tr) {
    return tr.dataset.groupId;
  }

  function refreshRowVisuals() {
    rowEls().forEach((tr) => {
      const on = selection.has(groupIdOf(tr));
      tr.classList.toggle('row-selected', on);
      const cb = tr.querySelector('.row-select');
      if (cb) cb.checked = on;
    });
    const bar = document.getElementById('bulk-bar');
    if (bar) {
      const n = selection.size;
      // §8.4: the bulk bar docks once 2+ rows are selected, not on a single check.
      bar.style.display = n >= 2 ? 'flex' : 'none';
      const countEl = bar.querySelector('.bulk-count');
      if (countEl) countEl.textContent = `${n} selected`;
    }
    const headCb = document.querySelector('.select-all');
    if (headCb) {
      const rows = rowEls();
      headCb.checked = rows.length > 0 && rows.every((tr) => selection.has(groupIdOf(tr)));
    }
  }

  function clearSelection() {
    selection.clear();
    refreshRowVisuals();
  }

  function selectAll(on) {
    selection.clear();
    if (on) rowEls().forEach((tr) => selection.add(groupIdOf(tr)));
    refreshRowVisuals();
  }

  let lastClickedIndex = null;

  function onCheckboxClick(evt, checkbox) {
    evt.stopPropagation();
    const rows = rowEls();
    const tr = checkbox.closest('tr');
    const idx = rows.indexOf(tr);
    const id = groupIdOf(tr);

    if (evt.shiftKey && lastClickedIndex !== null) {
      const [lo, hi] = [lastClickedIndex, idx].sort((a, b) => a - b);
      for (let i = lo; i <= hi; i++) selection.add(groupIdOf(rows[i]));
    } else {
      if (checkbox.checked) selection.add(id); else selection.delete(id);
      lastClickedIndex = idx;
    }
    refreshRowVisuals();
  }

  // ------------------------------------------------------------- toolbar --
  // Sorting: header buttons mutate #sortField then fire a custom event the
  // filter form listens for. Shift-click appends to a multi-column sort;
  // plain click replaces.
  function setSort(key, additive) {
    const field = document.getElementById('sortField');
    let parts = field.value ? field.value.split(',').filter(Boolean) : [];
    const idx = parts.findIndex((p) => p.replace(/^-/, '') === key);
    let next = '-' + key;
    if (idx !== -1) {
      const cur = parts[idx];
      next = cur.startsWith('-') ? key : '-' + key;
    }
    if (additive) {
      if (idx === -1) parts.push(next); else parts[idx] = next;
    } else {
      parts = [next];
    }
    field.value = parts.join(',');
    field.dispatchEvent(new Event('sort-changed', { bubbles: true }));
  }

  let columnOrder = [];
  function setColumnOrder(order) { columnOrder = order; }
  function toggleColumn(key, on) {
    const field = document.getElementById('colsField');
    const set = new Set(field.value.split(',').filter(Boolean));
    if (on) set.add(key); else set.delete(key);
    field.value = columnOrder.filter((k) => set.has(k)).join(',');
    field.dispatchEvent(new Event('change', { bubbles: true }));
  }

  // --------------------------------------------------------------- drawer --
  function closeDrawer() {
    document.getElementById('drawer').innerHTML = '';
  }
  function drawerTab(btn, name) {
    const panel = btn.closest('.drawer-panel');
    panel.querySelectorAll('.drawer-tab').forEach((t) => t.classList.toggle('on', t === btn));
    panel.querySelectorAll('[data-tab]').forEach((p) => {
      p.style.display = p.dataset.tab === name ? '' : 'none';
    });
  }
  function openDrawer(groupId, opts) {
    opts = opts || {};
    let url = ROUTES.drawer(groupId);
    const qs = [];
    if (opts.tab) qs.push('tab=' + encodeURIComponent(opts.tab));
    if (opts.action) qs.push('action=' + encodeURIComponent(opts.action));
    if (qs.length) url += '?' + qs.join('&');
    // This JS-triggered path (context menu, keyboard shortcuts, next/prev
    // stepping) has no declarative hx-get to hang an hx-indicator off of —
    // htmx.ajax's context object has no equivalent option — so toggle the
    // skeleton manually. htmx.ajax returns a promise that resolves once the
    // swap+settle finishes, same lifecycle point hx-indicator itself uses.
    const skeleton = document.getElementById('drawer-skeleton');
    if (skeleton) skeleton.classList.add('htmx-request');
    const req = htmx.ajax('GET', url, { target: '#drawer', swap: 'innerHTML settle:200ms' });
    if (skeleton && req && req.finally) req.finally(() => skeleton.classList.remove('htmx-request'));
  }
  function drawerGroupId() {
    const panel = document.querySelector('.drawer-panel');
    return panel ? panel.dataset.groupId : null;
  }
  function stepDrawer(dir) {
    const id = drawerGroupId();
    if (!id) return;
    const ids = rowEls().map(groupIdOf);
    const idx = ids.indexOf(id);
    if (idx === -1) return;
    const next = ids[(idx + dir + ids.length) % ids.length];
    openDrawer(next);
  }

  // A "quiet" mutation: the response is a drawer fragment with an OOB row
  // swap, but the caller (context menu / keyboard shortcut on a row that
  // isn't open in the drawer) doesn't want the drawer to pop open as a side
  // effect. swap:'none' skips the main target while OOB swaps still apply —
  // htmx applies hx-swap-oob elements independent of the primary swap target.
  function quietPost(url, values) {
    htmx.ajax('POST', url, { target: 'body', swap: 'none', values: values || {} });
  }

  // ----------------------------------------------------------- row actions --
  function rowStatus(tr) { return tr.dataset.status; }
  function rowActions(tr) {
    try { return JSON.parse(tr.dataset.actions || '[]'); } catch (e) { return []; }
  }
  function rowFinding(tr) {
    try { return JSON.parse(tr.dataset.finding || '{}'); } catch (e) { return {}; }
  }

  function singleTransition(tr, toStatus) {
    quietPost(ROUTES.transition(groupIdOf(tr)), { to_status: toStatus });
  }
  function singleAssign(tr, assigneeId) {
    quietPost(ROUTES.assign(groupIdOf(tr)), { assignee_id: assigneeId });
  }

  function bulkAct(url, extraValues) {
    const ids = Array.from(selection).join(',');
    if (!ids) return;
    htmx.ajax('POST', url + currentQueryString(), {
      target: '#table-region',
      swap: 'innerHTML',
      values: Object.assign({ group_ids: ids }, extraValues || {}),
    });
    clearSelection();
  }

  function promptBulkException(kind) {
    const reason = window.prompt(
      kind === 'suppressed'
        ? `Reason to suppress ${selection.size} finding(s):`
        : `Reason to accept risk on ${selection.size} finding(s):`
    );
    if (reason === null) return; // cancelled
    if (!reason.trim()) { toast('A reason is required'); return; }
    let expiresAt = null;
    if (kind === 'accepted_risk') {
      expiresAt = window.prompt('Optional expiry date (YYYY-MM-DD), or leave blank:') || null;
    }
    bulkAct(kind === 'suppressed' ? ROUTES.bulkSuppress : ROUTES.bulkAcceptRisk, {
      reason, expires_at: expiresAt,
    });
  }

  // ------------------------------------------------------------- copy (§8.3) --
  function copyText(text, label) {
    navigator.clipboard.writeText(text).then(
      () => toast(label + ' copied'),
      () => toast('Copy failed — clipboard access was denied')
    );
  }

  // Reusable copy-to-clipboard affordance for hard-to-select values (ARNs,
  // resource identifiers, principal names, policy JSON, evidence blocks) —
  // the small-icon-button-with-a-checkmark pattern, distinct from the
  // toast-based copyText() above (that one backs whole-finding "copy as
  // Markdown/JSON…" context-menu actions, which have no persistent button
  // of their own to animate). One handler for every instance of the button
  // across every template: `<button class="copy-btn" data-copy-text="…"
  // data-copy-label="Copy X" aria-label="Copy X" onclick="Sentinel.
  // copyValue(this)"><span class="copy-ico">⎘</span></button>`.
  const _copyResetTimers = new WeakMap();
  function copyValue(btn) {
    const text = btn.dataset.copyText || '';
    const label = btn.dataset.copyLabel || 'Copy';
    const icon = btn.querySelector('.copy-ico');
    navigator.clipboard.writeText(text).then(
      () => {
        window.clearTimeout(_copyResetTimers.get(btn));
        btn.classList.add('copied');
        btn.setAttribute('aria-label', 'Copied');
        if (icon) icon.textContent = '✓';
        const timer = window.setTimeout(() => {
          btn.classList.remove('copied');
          btn.setAttribute('aria-label', label);
          if (icon) icon.textContent = '⎘';
        }, 1500);
        _copyResetTimers.set(btn, timer);
      },
      () => toast('Copy failed — clipboard access was denied')
    );
  }
  function copyFinding(tr, format) {
    const f = rowFinding(tr);
    const id = groupIdOf(tr);
    if (format === 'markdown') {
      const md = `**${f.title}**\n- Severity: ${f.severity} (risk ${f.risk}/100)\n- Principal: ${f.principal || '—'}\n- Category: ${f.category}\n- Check: ${f.check_id}\n\n${f.recommendation || ''}`;
      copyText(md, 'Markdown');
    } else if (format === 'json') {
      copyText(JSON.stringify(Object.assign({ group_id: Number(id) }, f), null, 2), 'JSON');
    } else if (format === 'remediation') {
      copyText(f.remediation || '(no remediation snippet for this check)', 'Remediation snippet');
    } else if (format === 'link') {
      copyText(window.location.origin + ROUTES.drawer(id), 'Link');
    }
  }
  function copySelectedAsJson() {
    const rows = rowEls().filter((tr) => selection.has(groupIdOf(tr)));
    const payload = rows.map((tr) => Object.assign({ group_id: Number(groupIdOf(tr)) }, rowFinding(tr)));
    copyText(JSON.stringify(payload, null, 2), `${payload.length} findings (JSON)`);
  }

  // ----------------------------------------------------------- roster (Assign to…) --
  function roster() {
    const el = document.getElementById('roster-data');
    if (!el) return [];
    try { return JSON.parse(el.textContent || '[]'); } catch (e) { return []; }
  }

  // --------------------------------------------------------- context menu --
  const STATUS_LABELS = {
    open: 'Open', investigating: 'Investigating', resolved: 'Resolved',
    accepted_risk: 'Accepted risk', suppressed: 'Suppressed',
  };

  function closeContextMenu() {
    const el = document.getElementById('ctx-menu');
    if (el) el.remove();
    document.removeEventListener('click', closeContextMenu);
    document.removeEventListener('keydown', ctxMenuKeydown);
  }

  function ctxMenuKeydown(evt) {
    const menu = document.getElementById('ctx-menu');
    if (!menu) return;
    const items = Array.from(menu.querySelectorAll('.ctx-item:not(.disabled)'));
    let idx = items.findIndex((i) => i.classList.contains('focus'));
    if (evt.key === 'Escape') { closeContextMenu(); return; }
    if (evt.key === 'ArrowDown') {
      evt.preventDefault();
      items.forEach((i) => i.classList.remove('focus'));
      idx = (idx + 1) % items.length;
      items[idx].classList.add('focus');
      items[idx].scrollIntoView({ block: 'nearest' });
    } else if (evt.key === 'ArrowUp') {
      evt.preventDefault();
      items.forEach((i) => i.classList.remove('focus'));
      idx = idx <= 0 ? items.length - 1 : idx - 1;
      items[idx].classList.add('focus');
      items[idx].scrollIntoView({ block: 'nearest' });
    } else if (evt.key === 'Enter') {
      if (idx >= 0) { evt.preventDefault(); items[idx].click(); }
    }
  }

  function item(label, opts) {
    opts = opts || {};
    const el = document.createElement('div');
    el.className = 'ctx-item' + (opts.disabled ? ' disabled' : '');
    el.setAttribute('role', 'menuitem');
    el.textContent = label;
    if (opts.hint) {
      const span = document.createElement('span');
      span.className = 'ctx-hint';
      span.textContent = opts.hint;
      el.appendChild(span);
    }
    if (!opts.disabled && opts.onClick) {
      el.addEventListener('click', () => { opts.onClick(); closeContextMenu(); });
    }
    return el;
  }
  function sep() {
    const el = document.createElement('div');
    el.className = 'ctx-sep';
    return el;
  }
  function submenuGroup(label, children) {
    const wrap = document.createElement('div');
    wrap.className = 'ctx-group';
    const head = document.createElement('div');
    head.className = 'ctx-group-label';
    head.textContent = label;
    wrap.appendChild(head);
    children.forEach((c) => wrap.appendChild(c));
    return wrap;
  }

  function buildSingleMenu(tr) {
    const menu = document.createElement('div');
    menu.className = 'ctx-menu';
    const status = rowStatus(tr);
    const actions = rowActions(tr); // [[to_status,label], ...] from workflow_service.available_actions()
    const changeStatus = actions.filter(([to]) => to !== 'suppressed' && to !== 'accepted_risk');
    const suppressAction = actions.find(([to]) => to === 'suppressed');
    const acceptAction = actions.find(([to]) => to === 'accepted_risk');

    menu.appendChild(item('View evidence / details', {
      onClick: () => openDrawer(groupIdOf(tr), { tab: 'evidence' }),
    }));
    menu.appendChild(item('Open principal in graph', { disabled: true, hint: 'Phase 3' }));
    menu.appendChild(sep());

    if (changeStatus.length) {
      menu.appendChild(submenuGroup('Change status', changeStatus.map(([to, label]) =>
        item(label, { onClick: () => singleTransition(tr, to) }))));
    }
    // Assign is analyst+ (§10.2) — actions[] is already server-filtered by
    // role (see workflow_service.available_actions), but Assign isn't a
    // status transition so it isn't covered by that filter and needs its own
    // check here.
    if (roleAtLeast('analyst')) {
      const assignItems = [item('Assign to me', { onClick: () => singleAssign(tr, 'me') })];
      roster().forEach(([uid, name]) => {
        assignItems.push(item('Assign to ' + name, { onClick: () => singleAssign(tr, String(uid)) }));
      });
      menu.appendChild(submenuGroup('Assign', assignItems));
      menu.appendChild(sep());
    }

    if (suppressAction) {
      menu.appendChild(item('Suppress finding…', {
        onClick: () => openDrawer(groupIdOf(tr), { action: 'suppressed' }),
      }));
    }
    if (acceptAction) {
      menu.appendChild(item('Accept risk…', {
        onClick: () => openDrawer(groupIdOf(tr), { action: 'accepted_risk' }),
      }));
    }
    menu.appendChild(item('Re-run this check', { disabled: true, hint: 'Phase 2' }));
    if (roleAtLeast('analyst')) {
      menu.appendChild(item('Create ticket…', {
        onClick: () => openDrawer(groupIdOf(tr), { action: 'create_ticket' }),
      }));
    }
    menu.appendChild(sep());

    menu.appendChild(submenuGroup('Copy', [
      item('Copy as Markdown', { onClick: () => copyFinding(tr, 'markdown') }),
      item('Copy as JSON', { onClick: () => copyFinding(tr, 'json') }),
      item('Copy remediation snippet', { onClick: () => copyFinding(tr, 'remediation') }),
      item('Copy finding link', { onClick: () => copyFinding(tr, 'link') }),
    ]));
    if (roleAtLeast('analyst')) {
      menu.appendChild(sep());
      menu.appendChild(item('Add comment…', {
        onClick: () => { _focusCommentNext = true; openDrawer(groupIdOf(tr), { tab: 'activity' }); },
      }));
    }
    void status; // status already folded into `actions`; kept for readability/debugging
    return menu;
  }

  function buildBulkMenu() {
    const n = selection.size;
    const menu = document.createElement('div');
    menu.className = 'ctx-menu';
    // Bulk actions inherit their single-item gate (§10.2): transition/assign/
    // suppress are analyst+, accept-risk is admin-only. The row checkboxes
    // that build `selection` are themselves hidden below analyst
    // (findings_table.html), but keyboard shortcuts (Shift+j/k, x) can still
    // add to `selection` regardless of role, so this menu re-checks role
    // independently rather than trusting that selection is only ever
    // non-empty for a role that's allowed to act on it.
    if (roleAtLeast('analyst')) {
      menu.appendChild(submenuGroup(`Change status for ${n} findings`, [
        item('Investigating', { onClick: () => bulkAct(ROUTES.bulkTransition, { to_status: 'investigating' }) }),
        item('Resolved', { onClick: () => bulkAct(ROUTES.bulkTransition, { to_status: 'resolved' }) }),
        item('Reopen', { onClick: () => bulkAct(ROUTES.bulkTransition, { to_status: 'open' }) }),
      ]));
      const assignItems = [item('Assign to me', { onClick: () => bulkAct(ROUTES.bulkAssign, { assignee_id: 'me' }) })];
      roster().forEach(([uid, name]) => {
        assignItems.push(item('Assign to ' + name, { onClick: () => bulkAct(ROUTES.bulkAssign, { assignee_id: String(uid) }) }));
      });
      menu.appendChild(submenuGroup(`Assign ${n} findings`, assignItems));
      menu.appendChild(item(`Suppress ${n} findings…`, { onClick: () => promptBulkException('suppressed') }));
    }
    if (roleAtLeast('admin')) {
      menu.appendChild(item(`Accept risk for ${n} findings…`, { onClick: () => promptBulkException('accepted_risk') }));
    }
    menu.appendChild(item(`Re-run checks for ${n} findings`, { disabled: true, hint: 'Phase 2' }));
    menu.appendChild(sep());
    menu.appendChild(item('Export selected…', { disabled: true, hint: 'not built' }));
    menu.appendChild(item(`Copy ${n} as JSON`, { onClick: copySelectedAsJson }));
    menu.appendChild(sep());
    menu.appendChild(item('Clear selection', { onClick: clearSelection }));
    return menu;
  }

  function showContextMenu(x, y, menuEl) {
    closeContextMenu();
    menuEl.id = 'ctx-menu';
    document.body.appendChild(menuEl);
    const rect = menuEl.getBoundingClientRect();
    const clampedX = Math.min(x, window.innerWidth - rect.width - 8);
    const clampedY = Math.min(y, window.innerHeight - rect.height - 8);
    menuEl.style.left = Math.max(4, clampedX) + 'px';
    menuEl.style.top = Math.max(4, clampedY) + 'px';
    setTimeout(() => {
      document.addEventListener('click', closeContextMenu);
      document.addEventListener('keydown', ctxMenuKeydown);
    }, 0);
  }

  function onRowContextMenu(evt, tr) {
    evt.preventDefault();
    const id = groupIdOf(tr);
    // Right-clicking a row that's already part of a 2+ multi-selection opens
    // the bulk menu for the whole selection; right-clicking anything else (an
    // unselected row, or a row that's part of a smaller selection) opens the
    // single-row menu for *that* row without touching the checkbox selection
    // — deliberately not "collapsing" it, so a single-row action here can't
    // leave a stray 1-item selection that silently taints a later bulk action.
    if (selection.size >= 2 && selection.has(id)) {
      showContextMenu(evt.clientX, evt.clientY, buildBulkMenu());
    } else {
      showContextMenu(evt.clientX, evt.clientY, buildSingleMenu(tr));
    }
    return false;
  }

  function onMenuButtonClick(evt, tr) {
    evt.stopPropagation();
    const rect = evt.target.getBoundingClientRect();
    const id = groupIdOf(tr);
    if (selection.size >= 2 && selection.has(id)) {
      showContextMenu(rect.left, rect.bottom, buildBulkMenu());
    } else {
      showContextMenu(rect.left, rect.bottom, buildSingleMenu(tr));
    }
  }

  // ---------------------------------------------------------- command palette --
  const PALETTE_ITEMS = [
    { group: 'Navigate', label: 'Go to Dashboard', shortcut: 'g d', enabled: false },
    { group: 'Navigate', label: 'Go to Findings', shortcut: 'g f', enabled: true, action: () => navigate('/findings') },
    { group: 'Navigate', label: 'Go to Graph', shortcut: '', enabled: false },
    { group: 'Navigate', label: 'Go to Compliance', shortcut: 'g c', enabled: false },
    { group: 'Navigate', label: 'Go to Runs', shortcut: 'g r', enabled: true, action: () => navigate('/runs') },
    { group: 'Navigate', label: 'Go to Accounts', shortcut: '', enabled: true, action: () => navigate('/accounts') },
    { group: 'Navigate', label: 'Go to Exceptions', shortcut: '', enabled: false },
    { group: 'Navigate', label: 'Go to Settings', shortcut: '', enabled: true, action: () => navigate('/settings') },
    { group: 'Actions', label: 'Toggle theme', shortcut: 't', enabled: true, action: () => toggleTheme() },
    { group: 'Actions', label: 'Run scan', shortcut: '', enabled: false },
    { group: 'Actions', label: 'Connect account', shortcut: '', enabled: false },
    // §8.9 lists the palette as a diff entry point. The route resolves the
    // default previous-vs-latest pair itself, so no run ids are needed here.
    { group: 'Actions', label: 'Compare last two runs', shortcut: '', enabled: true, action: () => navigate('/runs/diff') },
    { group: 'Actions', label: 'Create saved view', shortcut: '', enabled: false },
    { group: 'Actions', label: 'Toggle density', shortcut: '', enabled: false },
  ];

  function navigate(url) { window.location.href = url; }
  function toggleTheme() {
    const data = window.Alpine && Alpine.$data(document.documentElement);
    if (data) data.toggle();
  }

  function subsequenceMatch(query, text) {
    // Lightweight fuzzy match: every char of `query` must appear in order in
    // `text` (not necessarily contiguous) — enough for a short static list
    // and short finding titles without pulling in a fuzzy-match library.
    query = query.toLowerCase(); text = text.toLowerCase();
    let qi = 0;
    for (let ti = 0; ti < text.length && qi < query.length; ti++) {
      if (text[ti] === query[qi]) qi++;
    }
    return qi === query.length;
  }

  function paletteEl() { return document.getElementById('palette'); }
  function paletteInput() { return document.getElementById('palette-input'); }
  function paletteStaticList() { return document.getElementById('palette-static'); }

  function renderPaletteStatic(query) {
    const list = paletteStaticList();
    list.innerHTML = '';
    let currentGroup = null;
    PALETTE_ITEMS.forEach((entry) => {
      if (query && !subsequenceMatch(query, entry.label)) return;
      if (entry.group !== currentGroup) {
        const head = document.createElement('div');
        head.className = 'palette-group-label';
        head.textContent = entry.group;
        list.appendChild(head);
        currentGroup = entry.group;
      }
      const el = document.createElement('div');
      el.className = 'palette-item' + (entry.enabled ? '' : ' disabled');
      el.setAttribute('role', 'option');
      el.tabIndex = -1;
      const label = document.createElement('span');
      label.className = 'pi-label';
      label.textContent = entry.label;
      el.appendChild(label);
      if (!entry.enabled) {
        const soon = document.createElement('span');
        soon.className = 'pi-soon';
        soon.textContent = 'Soon';
        el.appendChild(soon);
      } else if (entry.shortcut) {
        const kbd = document.createElement('span');
        kbd.className = 'pi-kbd';
        kbd.textContent = entry.shortcut;
        el.appendChild(kbd);
      }
      if (entry.enabled) {
        el.addEventListener('click', () => { entry.action(); closePalette(); });
      }
      list.appendChild(el);
    });
    highlightFirstPaletteItem();
  }

  // Enter activates whichever item carries `.on`. Without seeding that on the
  // first enabled item, a freshly opened (or freshly filtered) palette has no
  // selection, so typing a query and hitting Enter — the way every command
  // palette is used — silently did nothing until you pressed ArrowDown first.
  // Called after both render paths: the static list here, and the
  // server-searched findings that htmx swaps into #palette-results.
  function highlightFirstPaletteItem() {
    const items = paletteVisibleItems();
    items.forEach((i) => i.classList.remove('on'));
    if (items[0]) items[0].classList.add('on');
  }

  function openPalette() {
    const el = paletteEl();
    el.style.display = 'flex';
    renderPaletteStatic('');
    document.getElementById('palette-results').innerHTML = '';
    const input = paletteInput();
    input.value = '';
    input.focus();
    document.addEventListener('keydown', paletteKeydown);
  }
  function closePalette() {
    const el = paletteEl();
    if (!el) return;
    el.style.display = 'none';
    document.removeEventListener('keydown', paletteKeydown);
  }
  function togglePalette() {
    const el = paletteEl();
    if (el.style.display === 'flex') closePalette(); else openPalette();
  }

  function paletteVisibleItems() {
    return Array.from(document.querySelectorAll('#palette .palette-item:not(.disabled)'));
  }
  function paletteKeydown(evt) {
    if (evt.key === 'Escape') { evt.preventDefault(); closePalette(); return; }
    const items = paletteVisibleItems();
    let idx = items.findIndex((i) => i.classList.contains('on'));
    if (evt.key === 'ArrowDown') {
      evt.preventDefault();
      items.forEach((i) => i.classList.remove('on'));
      idx = (idx + 1) % items.length;
      if (items[idx]) { items[idx].classList.add('on'); items[idx].scrollIntoView({ block: 'nearest' }); }
    } else if (evt.key === 'ArrowUp') {
      evt.preventDefault();
      items.forEach((i) => i.classList.remove('on'));
      idx = idx <= 0 ? items.length - 1 : idx - 1;
      if (items[idx]) { items[idx].classList.add('on'); items[idx].scrollIntoView({ block: 'nearest' }); }
    } else if (evt.key === 'Enter') {
      if (idx >= 0 && items[idx]) items[idx].click();
    }
  }

  function onPaletteInput(evt) {
    const q = evt.target.value.trim();
    renderPaletteStatic(q);
  }

  // ------------------------------------------------------- keyboard shortcuts --
  let focusIndex = -1;
  function setRowFocus(idx) {
    const rows = rowEls();
    rows.forEach((tr) => tr.classList.remove('row-focus'));
    if (idx < 0 || idx >= rows.length) { focusIndex = -1; return; }
    focusIndex = idx;
    rows[idx].classList.add('row-focus');
    rows[idx].scrollIntoView({ block: 'nearest' });
  }
  function focusedRow() {
    const rows = rowEls();
    return focusIndex >= 0 && focusIndex < rows.length ? rows[focusIndex] : null;
  }

  let _focusCommentNext = false;
  let gPressedAt = null;
  const G_CHORD_WINDOW = 600;

  function drawerOpen() { return !!document.querySelector('.drawer-panel'); }

  // Every shortcut below fires an analyst+ action (workflow transition,
  // assign, suppress, comment — §10.2); guard here too, not just in the
  // context-menu builders, since row selection itself (Shift+j/k, x) has no
  // role check and can't be relied on to stay empty for a read_only viewer.
  function handleStatusShortcut(toStatus) {
    if (!roleAtLeast('analyst')) { toast('Not permitted for your role'); return; }
    if (selection.size >= 2) {
      bulkAct(ROUTES.bulkTransition, { to_status: toStatus });
    } else {
      const tr = focusedRow();
      if (tr) singleTransition(tr, toStatus);
    }
  }
  function handleAssignToMeShortcut() {
    if (!roleAtLeast('analyst')) { toast('Not permitted for your role'); return; }
    if (selection.size >= 2) {
      bulkAct(ROUTES.bulkAssign, { assignee_id: 'me' });
    } else {
      const tr = focusedRow();
      if (tr) singleAssign(tr, 'me');
    }
  }
  function handleSuppressShortcut() {
    if (!roleAtLeast('analyst')) { toast('Not permitted for your role'); return; }
    if (selection.size >= 2) {
      promptBulkException('suppressed');
    } else {
      const tr = focusedRow();
      if (tr) openDrawer(groupIdOf(tr), { action: 'suppressed' });
    }
  }
  function handleCommentShortcut() {
    if (!roleAtLeast('analyst')) { toast('Not permitted for your role'); return; }
    const tr = focusedRow();
    if (tr) { _focusCommentNext = true; openDrawer(groupIdOf(tr), { tab: 'activity' }); }
  }
  function toggleCheatsheet() {
    const el = document.getElementById('cheatsheet');
    if (!el) return;
    el.style.display = el.style.display === 'flex' ? 'none' : 'flex';
  }

  function onKeydown(evt) {
    // While the guided tour is active it owns the keyboard entirely (its own
    // handler drives Escape / arrows / the focus-trap Tab) — bail before any
    // app shortcut (j/k/x/e/i/s/a/c, Cmd+K, etc.) can fire behind the backdrop.
    if (tourActive) return;
    const editing = isEditableTarget(document.activeElement);
    const paletteIsOpen = paletteEl() && paletteEl().style.display === 'flex';

    // Cmd/Ctrl+K: always available, even while typing.
    if ((evt.metaKey || evt.ctrlKey) && evt.key.toLowerCase() === 'k') {
      evt.preventDefault();
      togglePalette();
      return;
    }
    if (paletteIsOpen) return; // palette has its own keydown handler

    if (editing) {
      if (evt.key === 'Escape' && drawerOpen()) closeDrawer();
      return;
    }

    // '/' focuses the findings search box.
    if (evt.key === '/') {
      const search = document.querySelector('input[name=q]');
      if (search) { evt.preventDefault(); search.focus(); }
      return;
    }

    // 'g' chord: g then d/f/r/c within G_CHORD_WINDOW ms.
    if (evt.key === 'g' && !evt.metaKey && !evt.ctrlKey) {
      gPressedAt = Date.now();
      return;
    }
    if (gPressedAt && Date.now() - gPressedAt <= G_CHORD_WINDOW) {
      const key = evt.key.toLowerCase();
      gPressedAt = null;
      if (key === 'f') { navigate('/findings'); return; }
      if (key === 'd' || key === 'r' || key === 'c') { toast('Not built yet'); return; }
    } else {
      gPressedAt = null;
    }

    if (evt.key === 't') { toggleTheme(); return; }
    if (evt.key === '?') { toggleCheatsheet(); return; }
    if (evt.key === 'Escape') {
      if (drawerOpen()) closeDrawer();
      else if (document.getElementById('ctx-menu')) closeContextMenu();
      return;
    }

    // Drawer-scoped: [ / ] step to the previous/next finding.
    if (drawerOpen() && (evt.key === '[' || evt.key === ']')) {
      evt.preventDefault();
      stepDrawer(evt.key === ']' ? 1 : -1);
      return;
    }

    // Findings-table-scoped shortcuts.
    if (evt.key === 'j' || (evt.key === 'J' && evt.shiftKey)) {
      evt.preventDefault();
      const rows = rowEls();
      if (!rows.length) return;
      const next = Math.min((focusIndex < 0 ? -1 : focusIndex) + 1, rows.length - 1);
      setRowFocus(next);
      if (evt.shiftKey) selection.add(groupIdOf(rows[next]));
      refreshRowVisuals();
      return;
    }
    if (evt.key === 'k' || (evt.key === 'K' && evt.shiftKey)) {
      evt.preventDefault();
      const rows = rowEls();
      if (!rows.length) return;
      const prev = Math.max((focusIndex < 0 ? rows.length : focusIndex) - 1, 0);
      setRowFocus(prev);
      if (evt.shiftKey) selection.add(groupIdOf(rows[prev]));
      refreshRowVisuals();
      return;
    }
    if (evt.key === 'x') {
      const tr = focusedRow();
      if (!tr) return;
      const id = groupIdOf(tr);
      if (selection.has(id)) selection.delete(id); else selection.add(id);
      refreshRowVisuals();
      return;
    }
    if (evt.key === 'Enter' || evt.key === 'o') {
      const tr = focusedRow();
      if (tr) openDrawer(groupIdOf(tr));
      return;
    }
    if (evt.key === 'e') { handleStatusShortcut('resolved'); return; }
    if (evt.key === 'i') { handleStatusShortcut('investigating'); return; }
    if (evt.key === 'a') { handleAssignToMeShortcut(); return; }
    if (evt.key === 's') { handleSuppressShortcut(); return; }
    if (evt.key === 'c') { handleCommentShortcut(); return; }
    if (evt.key === '.') {
      const tr = focusedRow();
      if (tr) {
        const rect = tr.getBoundingClientRect();
        onMenuButtonClick({ stopPropagation() {}, target: { getBoundingClientRect: () => rect } }, tr);
      }
    }
  }

  // ------------------------------------------------------- schedule editor --
  // §5.5 / §11.4, Slice 5: one shared modal for every account's recurring-scan
  // settings, driven the same way the command palette overlay is (plain JS,
  // display:none toggle) rather than a second Alpine component — its content
  // is set fresh from the clicked row's data-schedule attribute on each open,
  // so there is no per-row state to keep in sync.
  function scheduleModalEl() { return document.getElementById('schedule-modal'); }
  function scheduleKeydown(evt) {
    if (evt.key === 'Escape') { evt.preventDefault(); closeScheduleModal(); }
  }
  function openScheduleModal(data) {
    const modal = scheduleModalEl();
    const form = document.getElementById('schedule-form');
    form.action = `/accounts/${data.account_id}/schedule`;
    modal.dataset.accountId = data.account_id;
    document.getElementById('schedule-account-name').textContent = data.account_name || '';
    document.getElementById('schedule-cron-input').value = data.cron || '';
    document.getElementById('schedule-enabled-input').checked = data.enabled !== false;

    const info = document.getElementById('schedule-run-info');
    if (data.exists) {
      const fmt = (iso) => (iso ? new Date(iso).toLocaleString() : 'never');
      info.textContent = `Last run: ${fmt(data.last_run_at)} · Next run: ${data.next_run_at ? fmt(data.next_run_at) : '—'}`;
    } else {
      info.textContent = 'No recurring scan configured yet — saving will create one.';
    }
    document.getElementById('schedule-delete-btn').style.display = data.exists ? '' : 'none';
    document.getElementById('schedule-runnow-btn').style.display = data.exists ? '' : 'none';

    modal.style.display = 'flex';
    document.addEventListener('keydown', scheduleKeydown);
  }
  function closeScheduleModal() {
    const modal = scheduleModalEl();
    if (!modal) return;
    modal.style.display = 'none';
    document.removeEventListener('keydown', scheduleKeydown);
  }
  function deleteScheduleFromModal() {
    if (!window.confirm('Delete this recurring scan?')) return;
    const accountId = scheduleModalEl().dataset.accountId;
    const form = document.getElementById('schedule-form');
    form.action = `/accounts/${accountId}/schedule/delete`;
    form.submit();
  }
  function runScheduleNowFromModal() {
    const accountId = scheduleModalEl().dataset.accountId;
    const form = document.getElementById('schedule-form');
    form.action = `/accounts/${accountId}/schedule/run-now`;
    form.submit();
  }

  // ------------------------------------------------------- guided tour (§UX) --
  // Manual only — launched from the top-right menu's "Start tutorial", never
  // automatically (an auto-launched tour would appear mid-E2E-test and
  // intercept clicks meant for the real UI). Vanilla JS + CSS, no new
  // dependency: the spotlight is one box-shadow element (see .tour-* in
  // app.css). Steps anchor to real elements; any step whose anchor isn't on
  // the current page is dropped at start, so the tour never points at
  // nothing (the drawer + graph are described in copy rather than navigated
  // to, keeping it a single-page tour with no fragile mid-tour navigation).
  const TOUR_DEFS = [
    { centered: true, title: 'Welcome to IAM Sentinel',
      body: 'A quick tour of the main views. Use Next and Back, or press Escape any time to leave.' },
    { selector: '.sidebar', title: 'Navigation',
      body: 'Move between Findings, the blast-radius Graph, Compliance, the Checks catalog, Runs, and cloud Accounts.' },
    { selector: '.filterbar', title: 'Search and filter',
      body: 'Search by title or principal and filter by severity, status, or category. The full view state lives in the URL, so any filtered view is shareable.' },
    { selector: '#table-region .table-wrap', title: 'Findings',
      body: 'Every finding from the latest scan. Click a row to open its detail drawer — evidence, a suggested least-privilege fix, and the full workflow (assign, comment, suppress, accept risk).' },
    { selector: '[data-tour="palette"]', title: 'Command palette',
      body: 'Press Cmd/Ctrl + K anywhere to jump to a finding or run a command. The search is typo-tolerant — a misspelling still surfaces close matches.' },
    { selector: '[data-tour="menu"]', title: 'Settings and this tour',
      body: 'Switch between light and dark mode, and re-launch this tour whenever you like, right here.' },
    { centered: true, title: "You're all set",
      body: 'Head to the Graph view to see escalation paths, or Compliance for CIS / SOC 2 / NIST coverage. Enjoy.' },
  ];

  let tourActive = false;
  let tourStep = 0;
  let tourSteps = [];
  let tourEls = null;
  let tourPrevFocus = null;
  let tourCurrentEl = null;

  function startTour() {
    if (tourActive) return;
    // Clear transient overlays so the tour isn't stacked on top of them.
    closePalette();
    if (document.getElementById('ctx-menu')) closeContextMenu();
    if (drawerOpen()) closeDrawer();

    // Keep only steps whose anchor actually exists right now (centered steps
    // are always kept) — a guarantee the positioning code can rely on.
    tourSteps = TOUR_DEFS.filter((s) => s.centered || document.querySelector(s.selector));
    if (!tourSteps.length) return;

    tourActive = true;
    tourStep = 0;
    tourPrevFocus = document.activeElement;

    const backdrop = document.createElement('div');
    backdrop.className = 'tour-backdrop';
    backdrop.addEventListener('click', endTour); // clicking the backdrop exits
    const spotlight = document.createElement('div');
    spotlight.className = 'tour-spotlight';
    const tip = document.createElement('div');
    tip.className = 'tour-tooltip';
    tip.setAttribute('role', 'dialog');
    tip.setAttribute('aria-modal', 'true');
    tip.setAttribute('aria-labelledby', 'tour-title');
    document.body.appendChild(backdrop);
    document.body.appendChild(spotlight);
    document.body.appendChild(tip);
    tourEls = { backdrop, spotlight, tip };

    document.addEventListener('keydown', tourKeydown, true);
    window.addEventListener('resize', tourReposition);
    renderTourStep();
  }

  function endTour() {
    if (!tourActive) return;
    tourActive = false;
    document.removeEventListener('keydown', tourKeydown, true);
    window.removeEventListener('resize', tourReposition);
    if (tourEls) {
      // Remove every node outright — nothing left behind to intercept clicks.
      tourEls.backdrop.remove();
      tourEls.spotlight.remove();
      tourEls.tip.remove();
      tourEls = null;
    }
    tourCurrentEl = null;
    if (tourPrevFocus && typeof tourPrevFocus.focus === 'function') {
      try { tourPrevFocus.focus(); } catch (e) { /* element may be gone/hidden */ }
    }
    tourPrevFocus = null;
  }

  function tourNext() {
    if (!tourActive) return;
    if (tourStep >= tourSteps.length - 1) { endTour(); return; }
    tourStep += 1;
    renderTourStep();
  }
  function tourBack() {
    if (!tourActive || tourStep === 0) return;
    tourStep -= 1;
    renderTourStep();
  }

  function renderTourStep() {
    const step = tourSteps[tourStep];
    const { backdrop, spotlight, tip } = tourEls;
    const isFirst = tourStep === 0;
    const isLast = tourStep === tourSteps.length - 1;

    tip.innerHTML =
      '<div class="tour-tip-head">' +
        '<span class="tour-step-count"></span>' +
        '<button type="button" class="tour-x" aria-label="End tour">✕</button>' +
      '</div>' +
      '<h3 id="tour-title" class="tour-tip-title"></h3>' +
      '<p class="tour-tip-body"></p>' +
      '<div class="tour-tip-controls">' +
        '<button type="button" class="btn ghost tiny tour-skip">Skip tour</button>' +
        '<div class="tour-nav">' +
          '<button type="button" class="btn ghost tiny tour-back"' + (isFirst ? ' disabled' : '') + '>Back</button>' +
          '<button type="button" class="btn primary tiny tour-next"></button>' +
        '</div>' +
      '</div>';
    // textContent (not innerHTML) for anything derived from step copy.
    tip.querySelector('.tour-step-count').textContent = (tourStep + 1) + ' / ' + tourSteps.length;
    tip.querySelector('.tour-tip-title').textContent = step.title;
    tip.querySelector('.tour-tip-body').textContent = step.body;
    tip.querySelector('.tour-next').textContent = isLast ? 'Done' : 'Next';
    tip.querySelector('.tour-x').addEventListener('click', endTour);
    tip.querySelector('.tour-skip').addEventListener('click', endTour);
    tip.querySelector('.tour-back').addEventListener('click', tourBack);
    tip.querySelector('.tour-next').addEventListener('click', tourNext);

    if (step.centered || !step.selector) {
      tourCurrentEl = null;
      backdrop.classList.add('tour-backdrop--dim');
      spotlight.style.display = 'none';
      tip.classList.add('tour-tooltip--centered');
      tip.style.top = '';
      tip.style.left = '';
    } else {
      const el = document.querySelector(step.selector);
      if (!el) { tourNext(); return; } // guarded at start, but stay safe
      tourCurrentEl = el;
      backdrop.classList.remove('tour-backdrop--dim');
      spotlight.style.display = '';
      tip.classList.remove('tour-tooltip--centered');
      el.scrollIntoView({ block: 'center', inline: 'nearest' });
      // Measure after the scroll settles + the new tooltip content lays out.
      window.requestAnimationFrame(() => positionTourFor(el));
    }

    // Focus trapped inside the tooltip: seed it on the primary action.
    const focusTarget = tip.querySelector('.tour-next') || tip.querySelector('.tour-x');
    if (focusTarget) focusTarget.focus();
  }

  function positionTourFor(el) {
    if (!tourActive || !tourEls) return;
    const { spotlight, tip } = tourEls;
    const r = el.getBoundingClientRect();
    const pad = 6;
    spotlight.style.top = (r.top - pad) + 'px';
    spotlight.style.left = (r.left - pad) + 'px';
    spotlight.style.width = (r.width + pad * 2) + 'px';
    spotlight.style.height = (r.height + pad * 2) + 'px';

    const tipR = tip.getBoundingClientRect();
    const gap = 14;
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    let top = r.bottom + gap;
    if (top + tipR.height > vh - 12) {
      const above = r.top - gap - tipR.height;
      top = above >= 12 ? above : Math.max(12, (vh - tipR.height) / 2);
    }
    let left = Math.min(Math.max(12, r.left), vw - tipR.width - 12);
    tip.style.top = top + 'px';
    tip.style.left = left + 'px';
  }

  function tourReposition() {
    if (tourActive && tourCurrentEl) positionTourFor(tourCurrentEl);
  }

  function tourKeydown(evt) {
    if (!tourActive) return;
    if (evt.key === 'Escape') { evt.preventDefault(); endTour(); return; }
    if (evt.key === 'ArrowRight') { evt.preventDefault(); tourNext(); return; }
    if (evt.key === 'ArrowLeft') { evt.preventDefault(); tourBack(); return; }
    if (evt.key === 'Tab') {
      // Trap focus within the tooltip's own controls so Tab can't reach the
      // dimmed page behind the backdrop.
      const btns = Array.from(tourEls.tip.querySelectorAll('button:not([disabled])'));
      if (!btns.length) return;
      const first = btns[0];
      const last = btns[btns.length - 1];
      const active = document.activeElement;
      if (!tourEls.tip.contains(active)) { evt.preventDefault(); first.focus(); }
      else if (evt.shiftKey && active === first) { evt.preventDefault(); last.focus(); }
      else if (!evt.shiftKey && active === last) { evt.preventDefault(); first.focus(); }
    }
  }

  // -------------------------------------------------------------------- init --
  function init() {
    document.addEventListener('keydown', onKeydown);

    // Auto-focus the comment box when a drawer swap lands on the Activity tab
    // as a result of "Add comment…" / the 'c' shortcut.
    document.body.addEventListener('htmx:afterSwap', (evt) => {
      if (evt.target && evt.target.id === 'table-region') {
        clearSelection();
        setRowFocus(-1);
      }
      if (_focusCommentNext && evt.target && evt.target.id === 'drawer') {
        _focusCommentNext = false;
        const box = document.querySelector('.drawer-panel [data-tab="activity"] textarea[name=body]');
        if (box) box.focus();
      }
      // Server-searched findings just landed in the palette: re-seed the Enter
      // selection so it points at a result that actually exists now.
      if (evt.target && evt.target.id === 'palette-results') highlightFirstPaletteItem();
    });

    // The row-status OOB swap (transition/suppress/accept-risk) is a genuine
    // out-of-band swap (htmx:afterSwap only ever fires for the *primary*
    // target — 'body' here, since single-row mutations use swap:'none' on it
    // — so oobAfterSwap is the one that actually targets this <td>). It
    // carries the fresh status + available-actions as data attributes (see
    // finding_drawer.html); mirror them onto the row's own dataset so a
    // context menu built right after stays in sync instead of reflecting the
    // pre-mutation status until the next full-table render.
    document.body.addEventListener('htmx:oobAfterSwap', (evt) => {
      if (evt.target && evt.target.id && evt.target.id.startsWith('row-status-')) {
        const tr = evt.target.closest('tr');
        if (tr) {
          tr.dataset.status = evt.target.dataset.status;
          tr.dataset.actions = evt.target.dataset.actions;
        }
      }
    });
  }

  return {
    init, setSort, toggleColumn, setColumnOrder,
    closeDrawer, drawerTab, openDrawer, stepDrawer,
    onCheckboxClick, selectAll, clearSelection,
    onRowContextMenu, onMenuButtonClick, closeContextMenu,
    openPalette, closePalette, togglePalette, onPaletteInput,
    toggleCheatsheet, toast, copyValue,
    startTour, endTour,
    openScheduleModal, closeScheduleModal, deleteScheduleFromModal, runScheduleNowFromModal,
  };
})();

document.addEventListener('DOMContentLoaded', Sentinel.init);

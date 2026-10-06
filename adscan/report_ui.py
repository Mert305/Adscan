"""Offline, dependency-free interactions for the HTML report."""

STYLE = """
[hidden] { display:none !important; }
.filters { display:flex; flex-wrap:wrap; gap:10px; margin:16px 0; }
.filters label { display:flex; flex-direction:column; gap:4px; flex:1; min-width:130px; }
input, select, button { font:inherit; padding:8px; color:var(--fg); background:var(--card);
  border:1px solid var(--line); border-radius:6px; }
button, a { cursor:pointer; } a { color:#299dcf; }
.table-scroll { overflow-x:auto; }
.priority li { margin:12px 0; }
.finding:target { outline:2px solid #299dcf; }
.app-header { display:flex; align-items:center; justify-content:space-between; gap:16px; margin-bottom:24px; }
.brand-mark { display:inline-flex; align-items:center; gap:10px; font-weight:750; letter-spacing:2px; }
.brand-icon { display:grid; place-items:center; width:36px; height:36px; border-radius:10px;
  background:#2463eb; color:white; letter-spacing:0; }
.eyebrow { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:1.4px; }
.hero { margin-bottom:24px; }
.wrap.report-shell { max-width:1240px; padding:28px 24px; }
.hero h1 { font-size:30px; letter-spacing:-.6px; }
.dashboard-stats { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:14px; margin:20px 0; }
.stat-card, .context-card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:18px; }
.stat-card strong { display:block; font-size:30px; letter-spacing:-1px; margin:6px 0; }
.stat-card small, .context-card p { color:var(--muted); }
.tabs { display:flex; gap:6px; flex-wrap:wrap; border-bottom:1px solid var(--line); padding-bottom:10px; }
.tabs button { border:0; background:transparent; color:var(--muted); font-weight:600; }
.tabs button[aria-selected="true"] { background:rgba(36,99,235,.13); color:#2463eb; }
.tabs .tab-count { font-size:11px; padding:2px 6px; border-radius:5px; background:rgba(127,127,127,.13); }
.toolbar { margin:20px 0; padding:16px; background:var(--card); border:1px solid var(--line); border-radius:12px; }
.toolbar .filters { margin:0 0 12px; }
.toolbar-note { color:var(--muted); font-size:12px; margin-bottom:0; }
.panel { animation:appear .15s ease-out; }
.panel h2 { margin-top:20px; }
.context-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); gap:12px; margin:20px 0; }
.context-card h3 { margin:8px 0 4px; overflow-wrap:anywhere; }
.section-heading { display:flex; align-items:center; justify-content:space-between; gap:12px; }
.section-heading p { color:var(--muted); }
.state { display:inline-block; border-radius:6px; padding:4px 8px; font-size:11px; font-weight:650; white-space:nowrap; }
.state-completed, .state-findings, .state-granted { background:rgba(22,163,74,.13); color:#15803d; }
.state-access_denied, .state-denied, .state-failed { background:rgba(220,38,38,.13); color:#dc2626; }
.state-unknown, .state-skipped, .state-planned { background:rgba(217,119,6,.13); color:#b45309; }
.state-not_tested, .state-not_applicable { background:rgba(127,127,127,.12); color:var(--muted); }
table small { display:block; color:var(--muted); font-weight:400; font-size:11px; margin-top:5px; overflow-wrap:anywhere; }
.table-scroll { border:1px solid var(--line); border-radius:10px; margin:12px 0; background:var(--card); }
.table-scroll table { min-width:600px; }
th { background:var(--card); position:sticky; top:0; }
.cell-evidence summary { cursor:pointer; list-style:none; }
.cell-evidence p { min-width:180px; }
.permission-trace li { margin:12px 0; }
.token-path { margin-top:6px; font-size:12px; overflow-wrap:anywhere; color:#2463eb; }
.notice { padding:14px 18px; background:rgba(36,99,235,.06); border-left:3px solid #2463eb; border-radius:6px; }
.empty-state { text-align:center; padding:55px 24px; border:1px dashed var(--line); border-radius:12px; margin:24px 0; }
.empty-state p { max-width:560px; margin:12px auto; color:var(--muted); }
.check-label { display:flex; align-items:center; gap:8px; white-space:nowrap; }
.pagination { display:flex; align-items:center; flex-wrap:wrap; gap:10px; margin:16px 0; }
.report-footer { color:var(--muted); border-top:1px solid var(--line); padding-top:16px; margin-top:30px; font-size:12px; }
button:hover { filter:brightness(.95); }
button:focus-visible, input:focus-visible, select:focus-visible, a:focus-visible { outline:2px solid #2463eb; outline-offset:3px; }
button:disabled { opacity:.4; cursor:default; }
html[data-theme="dark"] { --bg:#0c1220; --card:#141e30; --fg:#e8edf5; --muted:#9caac0; --line:#27354d; color-scheme:dark; }
html[data-theme="light"] { --bg:#f4f6fa; --card:#fff; --fg:#17243b; --muted:#62728a; --line:#dfe5ee; color-scheme:light; }
@keyframes appear { from { opacity:.7; } to { opacity:1; } }
@media (prefers-reduced-motion:reduce) { .panel { animation:none; } }
@media (max-width:640px) { .dashboard-stats { grid-template-columns:repeat(2,minmax(0,1fr)); }
  .hero h1 { font-size:24px; } .tabs button { font-size:12px; padding:8px; }
  .app-header { align-items:flex-start; } .section-heading { align-items:flex-start; flex-direction:column; }
  .finding summary { flex-wrap:wrap; } .src { overflow-wrap:anywhere; }
  .permission-filters label { min-width:100%; } }
@media print { .tabs, .toolbar, .pagination, .app-header button { display:none; }
  .panel[hidden] { display:block !important; } .dashboard-stats { break-inside:avoid; }
  .table-scroll { overflow:visible; } }
@media print { .filters, .actions { display:none; } [hidden] { display:none !important; } }
"""

SCRIPT = r"""
<script>
(() => {
  const cards = [...document.querySelectorAll('.finding')];
  const coverage = [...document.querySelectorAll('.coverage-row')];
  const byId = id => document.getElementById(id);
  const comparisons = [...document.querySelectorAll('.comparison-row')];
  const permissions = [...document.querySelectorAll('.permission-row')];
  let currentPage = 1;
  let lastMatches = [];
  const tabs = [...document.querySelectorAll('[role="tab"]')];
  const panels = [...document.querySelectorAll('.panel')];
  function activate(id, focus = false) {
    if (!byId(id) || !byId(id).classList.contains('panel')) return;
    panels.forEach(panel => panel.hidden = panel.id !== id);
    byId('export-visible').disabled = !byId(id).querySelector('table');
    tabs.forEach(tab => {
      const selected = tab.getAttribute('aria-controls') === id;
      tab.setAttribute('aria-selected', String(selected)); tab.tabIndex = selected ? 0 : -1;
      if (selected && focus) tab.focus();
    });
  }
  tabs.forEach((tab, index) => {
    tab.addEventListener('click', () => activate(tab.getAttribute('aria-controls')));
    tab.addEventListener('keydown', event => {
      let next;
      if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
      if (event.key === 'ArrowLeft') next = (index - 1 + tabs.length) % tabs.length;
      if (event.key === 'Home') next = 0;
      if (event.key === 'End') next = tabs.length - 1;
      if (next !== undefined) { event.preventDefault(); activate(tabs[next].getAttribute('aria-controls'), true); }
    });
  });
  byId('theme-toggle').addEventListener('click', () => {
    const dark = document.documentElement.dataset.theme !== 'dark';
    document.documentElement.dataset.theme = dark ? 'dark' : 'light';
    byId('theme-toggle').setAttribute('aria-pressed', String(dark));
  });
  if (byId('permission-principal')) {
    [...new Set(permissions.map(row => row.dataset.principal))].sort().forEach(value => {
      const option = document.createElement('option'); option.value = value; option.textContent = value;
      byId('permission-principal').append(option);
    });
  }
  const selects = {severity:'severity', target:'target', verification:'verification', module:'module'};
  for (const [id, field] of Object.entries(selects)) {
    const values = [...new Set(cards.map(c => c.dataset[field]))];
    if (id === 'module' || id === 'target') values.push(...coverage.map(c => c.dataset[field]));
    for (const value of [...new Set(values)].filter(Boolean).sort()) {
      const option = document.createElement('option');
      option.value = value; option.textContent = value; byId(id).append(option);
    }
  }
  function filter() {
    const query = byId('search').value.toLocaleLowerCase('tr').trim();
    const view = byId('view').value;
    byId('chain-details').open = view === 'technical';
    let shown = 0;
    const matches = [];
    for (const card of cards) {
      card.hidden = !Object.entries(selects).every(([id, field]) =>
        !byId(id).value || card.dataset[field] === byId(id).value) ||
        !card.textContent.toLocaleLowerCase('tr').includes(query);
      card.open = view === 'technical';
      if (!card.hidden) { shown++; matches.push(card); }
    }
    const pageSize = Number(byId('page-size').value);
    lastMatches = matches;
    const pages = Math.max(1, Math.ceil(matches.length / pageSize));
    currentPage = Math.min(currentPage, pages);
    matches.forEach((card, i) => card.hidden = i < (currentPage - 1) * pageSize || i >= currentPage * pageSize);
    byId('page-position').textContent = currentPage + ' / ' + pages;
    byId('page-prev').disabled = currentPage === 1;
    byId('page-next').disabled = currentPage === pages;
    let controls = 0;
    for (const row of coverage) {
      row.hidden = ['module', 'target', 'status'].some(id =>
        byId(id).value && row.dataset[id] !== byId(id).value) ||
        !row.textContent.toLocaleLowerCase('tr').includes(query);
      if (!row.hidden) controls++;
    }
    byId('result-count').textContent = shown + ' / ' + cards.length + ' bulgu gösteriliyor';
    byId('coverage-count').textContent = controls + ' / ' + coverage.length + ' kontrol gösteriliyor';
    let comparisonCount = 0;
    for (const row of comparisons) {
      row.hidden = ['module', 'target'].some(id => byId(id).value && row.dataset[id] !== byId(id).value) ||
        !row.textContent.toLocaleLowerCase('tr').includes(query) ||
        (byId('different-only').checked && row.dataset.different !== 'true');
      if (!row.hidden) comparisonCount++;
    }
    if (byId('comparison-count')) byId('comparison-count').textContent = comparisonCount + ' / ' + comparisons.length + ' karşılaştırma satırı';
    let permissionCount = 0;
    for (const row of permissions) {
      row.hidden = ['principal', 'decision', 'verification'].some(field =>
        byId('permission-' + field).value && row.dataset[field] !== byId('permission-' + field).value) ||
        !row.textContent.toLocaleLowerCase('tr').includes(query);
      if (!row.hidden) permissionCount++;
    }
    if (byId('permission-count')) byId('permission-count').textContent = permissionCount + ' / ' + permissions.length + ' yetki kontrolü';
  }
  function reveal() {
    let id;
    try { id = decodeURIComponent(location.hash.slice(1)); } catch { return; }
    if (byId(id)?.classList.contains('panel')) { activate(id); return; }
    const target = byId(id);
    const card = target && (target.closest('.finding') || target);
    if (card && card.classList.contains('finding')) {
      activate('findings');
      if (!lastMatches.includes(card)) {
        byId('search').value = '';
        Object.keys(selects).forEach(id => byId(id).value = '');
        filter();
      }
      currentPage = Math.floor(lastMatches.indexOf(card) / Number(byId('page-size').value)) + 1;
      filter();
      card.hidden = false; card.open = true; target.scrollIntoView({block:'center'});
    }
    if (target?.closest('#permissions')) { activate('permissions'); target.open = true; target.scrollIntoView({block:'center'}); }
  }
  document.querySelectorAll('.filters input, .filters select').forEach(el =>
    el.addEventListener('input', () => { currentPage = 1; filter(); }));
  byId('different-only')?.addEventListener('change', filter);
  byId('page-size').addEventListener('change', () => { currentPage = 1; filter(); });
  byId('page-prev').addEventListener('click', () => { currentPage--; filter(); });
  byId('page-next').addEventListener('click', () => { currentPage++; filter(); });
  byId('reset-filters').addEventListener('click', () => {
    document.querySelectorAll('.filters input, .filters select').forEach(el => el.value = '');
    byId('view').value = 'executive';
    if (byId('different-only')) byId('different-only').checked = false;
    currentPage = 1; filter();
  });
  byId('expand-all').addEventListener('click', () => cards.filter(c => !c.hidden).forEach(c => c.open = true));
  byId('collapse-all').addEventListener('click', () => cards.forEach(c => c.open = false));
  window.addEventListener('hashchange', reveal);
  document.querySelectorAll('th[data-sortable]').forEach(th => {
    const button = document.createElement('button'); button.textContent = th.textContent;
    th.textContent = ''; th.append(button);
    button.addEventListener('click', () => {
      const tbody = th.closest('table').tBodies[0];
      const ascending = th.getAttribute('aria-sort') !== 'ascending';
      th.closest('tr').querySelectorAll('th').forEach(cell => cell.removeAttribute('aria-sort'));
      th.setAttribute('aria-sort', ascending ? 'ascending' : 'descending');
      [...tbody.rows].sort((a, b) => (ascending ? 1 : -1) *
        a.cells[th.cellIndex].textContent.localeCompare(b.cells[th.cellIndex].textContent, 'tr'))
        .forEach(row => tbody.append(row));
    });
  });
  byId('print-report').addEventListener('click', () => window.print());
  byId('export-visible').addEventListener('click', () => {
    const active = panels.find(panel => !panel.hidden);
    const rows = [...active.querySelectorAll('table tr')].filter(row => !row.hidden);
    const quote = text => '"' + (/^[=+@-]/.test(text) ? "'" : '') + text.replaceAll('"', '""') + '"';
    const csv = rows.map(row => [...row.cells].map(cell => quote(cell.textContent.trim())).join(',')).join('\r\n');
    const blob = new Blob(['\ufeff' + csv], {type:'text/csv;charset=utf-8'});
    const url = URL.createObjectURL(blob); const a = document.createElement('a');
    a.href = url; a.download = 'adscan-' + active.id + '.csv'; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  activate(byId('comparison-table') ? 'comparison' : permissions.length && !cards.length ? 'permissions' : 'overview');
  filter(); reveal();
})();
</script>
"""

FILTERS = """
<div class="filters" role="search" aria-label="Rapor filtreleri">
  <label>Ara<input id="search" type="search" placeholder="Bulgu, kanıt veya kontrol…"></label>
  <label>Önem derecesi<select id="severity"><option value="">Tümü</option></select></label>
  <label>Hedef<select id="target"><option value="">Tümü</option></select></label>
  <label>Doğrulama<select id="verification"><option value="">Tümü</option></select></label>
  <label>Modül<select id="module"><option value="">Tümü</option></select></label>
  <label>Kontrol durumu<select id="status"><option value="">Tümü</option>
    <option>completed</option><option>access_denied</option><option>skipped</option>
    <option>failed</option><option>unknown</option><option>planned</option>
    <option>not_applicable</option></select></label>
  <label>Görünüm<select id="view"><option value="executive">Yönetici özeti</option>
    <option value="technical">Teknik ayrıntılar</option></select></label>
</div>
<div class="actions"><button id="reset-filters" type="button">Filtreleri sıfırla</button>
<button id="expand-all" type="button">Görünen bulguları aç</button>
<button id="collapse-all" type="button">Bulguları kapat</button>
<button id="export-visible" type="button">Görünen tabloları CSV indir</button></div>
<p class="toolbar-note">Önem ve doğrulama filtreleri bulgulara; kontrol durumu kapsam tablosuna uygulanır.
Yetki kontrollerinin kimlik ve karar filtreleri kendi bölümündedir.</p>
<noscript>Filtreler için JavaScript gerekir. Raporun tüm içeriği aşağıda okunabilir.</noscript>
"""

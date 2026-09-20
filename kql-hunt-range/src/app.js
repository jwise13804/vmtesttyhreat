
(function () {
  'use strict';

  // ---------------- Data & engine setup ----------------
  const ds = FabrikamData.buildDataset();
  const TABLES = {
    DeviceProcessEvents: ds.DeviceProcessEvents,
    DeviceNetworkEvents: ds.DeviceNetworkEvents,
    DeviceFileEvents: ds.DeviceFileEvents,
    DeviceLogonEvents: ds.DeviceLogonEvents,
    EmailEvents: ds.EmailEvents,
    AlertInfo: ds.AlertInfo,
    AlertEvidence: ds.AlertEvidence,
    SigninLogs: ds.SigninLogs,
    AuditLogs: ds.AuditLogs,
    NetworkAccessTraffic: ds.NetworkAccessTraffic,
  };
  const SCHEMA = ds.SCHEMA_COLUMNS;
  const TABLE_NAMES = Object.keys(TABLES);
  const TABLE_DESCRIPTIONS = {
    DeviceProcessEvents: 'Process creation events (Microsoft Defender advanced hunting schema)',
    DeviceNetworkEvents: 'Network connection events',
    DeviceFileEvents: 'File creation, rename & modification events',
    DeviceLogonEvents: 'Device sign-in / authentication events',
    EmailEvents: 'Inbound & outbound email processing events (Defender for Office 365)',
    AlertInfo: 'One row per fired alert — title, severity, MITRE ATT&CK techniques (Defender XDR)',
    AlertEvidence: 'One row per entity linked to an alert — join to AlertInfo on AlertId',
    SigninLogs: 'Microsoft Entra ID interactive user sign-ins (Microsoft Sentinel / Log Analytics)',
    AuditLogs: 'Microsoft Entra ID directory admin activity — user, group & app management (Sentinel)',
    NetworkAccessTraffic: 'Entra Internet/Private Access outbound network traffic (Global Secure Access)',
  };

  let scenarios = KQL_SCENARIOS.slice();
  let currentScenario = null;
  let completed = loadCompleted();
  let stepIndex = loadStepIndex();
  // Learning-matrix filter state: 'all' or a specific domain/discipline/cyberSkill string. Not persisted —
  // resets each visit, same as any other in-page filter.
  let skillFilter = { domain: 'all', discipline: 'all' };
  const ALL_DOMAINS = [...new Set(KQL_SCENARIOS.map(s => s.domain).filter(Boolean))];
  const ALL_DISCIPLINES = [...new Set(KQL_SCENARIOS.map(s => s.discipline).filter(Boolean))];

  function loadCompleted() {
    try {
      const raw = localStorage.getItem('kqlrange.completed');
      return new Set(raw ? JSON.parse(raw) : []);
    } catch (e) { return new Set(); }
  }
  function saveCompleted() {
    try { localStorage.setItem('kqlrange.completed', JSON.stringify([...completed])); } catch (e) { /* ignore */ }
  }

  // ---- multi-step "start to finish" investigations: which step (0-indexed) each such mission is on ----
  function loadStepIndex() {
    try {
      const raw = localStorage.getItem('kqlrange.stepIndex');
      return raw ? JSON.parse(raw) : {};
    } catch (e) { return {}; }
  }
  function saveStepIndex() {
    try { localStorage.setItem('kqlrange.stepIndex', JSON.stringify(stepIndex)); } catch (e) { /* ignore */ }
  }

  // ---------------- CodeMirror: KQL mode ----------------
  const KEYWORDS = ['let', 'where', 'filter', 'project', 'project-away', 'project-keep', 'project-rename',
    'project-reorder', 'extend', 'summarize', 'make-series', 'from', 'step', 'by', 'sort', 'order', 'asc', 'desc',
    'nulls', 'first', 'last', 'top', 'take', 'limit', 'distinct', 'count', 'join', 'kind', 'on', 'union', 'render',
    'and', 'or', 'not', 'has', 'has_cs', 'has_any', 'has_all', 'contains', 'contains_cs', 'startswith', 'startswith_cs', 'endswith',
    'endswith_cs', 'in', 'between', 'matches', 'regex', 'true', 'false'];
  const FUNCTIONS = ['ago', 'now', 'datetime', 'bin', 'strcat', 'tostring', 'toint', 'tolong', 'todouble',
    'toreal', 'tobool', 'strlen', 'substring', 'indexof', 'split', 'tolower', 'toupper', 'isempty',
    'isnotempty', 'isnull', 'isnotnull', 'case', 'iif', 'iff', 'coalesce', 'count', 'countif', 'dcount', 'dcountif', 'sum',
    'sumif', 'avg', 'avgif', 'max', 'maxif', 'min', 'minif', 'make_set', 'make_list', 'arg_max', 'arg_min',
    'series_decompose_anomalies'];

  function esc(list) { return list.slice().sort((a, b) => b.length - a.length).map(k => k.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&')).join('|'); }

  CodeMirror.defineSimpleMode('kql', {
    start: [
      { regex: /\/\/.*/, token: 'comment' },
      { regex: /"(?:[^"\\]|\\.)*"?/, token: 'string' },
      { regex: /'(?:[^'\\]|\\.)*'?/, token: 'string' },
      { regex: /\b\d+(?:\.\d+)?(?:ms|s|m|h|d)?\b/, token: 'number' },
      { regex: new RegExp('\\b(?:' + esc(TABLE_NAMES) + ')\\b'), token: 'variable-2' },
      { regex: new RegExp('\\b(?:' + esc(FUNCTIONS) + ')(?=\\s*\\()', 'i'), token: 'builtin' },
      { regex: new RegExp('\\b(?:' + esc(KEYWORDS) + ')\\b', 'i'), token: 'keyword' },
      { regex: /==|!=|=~|!~|<=|>=|<|>|\||!/, token: 'operator' },
      { regex: /[a-zA-Z_$][a-zA-Z0-9_]*/, token: 'variable' },
    ],
  });

  // ---------------- CodeMirror: autocomplete ----------------
  function currentTablesInScope(textUpToCursor) {
    const found = [];
    for (const t of TABLE_NAMES) if (new RegExp('\\b' + t + '\\b').test(textUpToCursor)) found.push(t);
    return found.length ? found : TABLE_NAMES; // fallback: offer everything
  }

  CodeMirror.registerHelper('hint', 'kql', function (cm) {
    const cur = cm.getCursor();
    const line = cm.getLine(cur.line);
    const beforeCursor = line.slice(0, cur.ch);
    const wordMatch = /[A-Za-z0-9_.]*$/.exec(beforeCursor);
    const start = cur.ch - wordMatch[0].length;
    const word = wordMatch[0].toLowerCase();

    const fullTextBefore = cm.getRange({ line: 0, ch: 0 }, cur);
    const trimmedBefore = fullTextBefore.replace(/\s+$/, '');
    const lastNonWordChar = (() => {
      const m = /([|,()=]|\bby\b|\bwhere\b|\band\b|\bor\b|\bon\b)\s*$/i.exec(trimmedBefore.slice(0, trimmedBefore.length - word.length));
      return m ? m[0].trim().toLowerCase() : '';
    })();

    let items = [];
    const textBeforeWord = fullTextBefore.slice(0, fullTextBefore.length - wordMatch[0].length);
    const sourcePosition = textBeforeWord.replace(/\/\/.*$/gm, '').split(';').pop().split('|')[0];
    const atStart = !/\S/.test(sourcePosition);

    if (atStart) {
      items = TABLE_NAMES.map(t => ({ text: t, kind: 'table' }));
      items.push({ text: 'let', kind: 'kw' });
    } else if (lastNonWordChar === '|' || lastNonWordChar === '') {
      items = KEYWORDS.filter(k => !['and', 'or', 'not', 'true', 'false', 'asc', 'desc', 'by', 'on', 'kind', 'nulls', 'first', 'last', 'regex'].includes(k))
        .map(k => ({ text: k, kind: 'op' }));
    } else {
      const tables = currentTablesInScope(fullTextBefore);
      const cols = new Set();
      tables.forEach(t => (SCHEMA[t] || []).forEach(c => cols.add(c)));
      items = [...cols].map(c => ({ text: c, kind: 'col' }));
      items = items.concat(FUNCTIONS.map(f => ({ text: f + '(', kind: 'fn' })));
      items = items.concat(['and', 'or', 'not', 'contains', 'has', 'startswith', 'endswith', 'in', 'between']
        .map(k => ({ text: k, kind: 'op' })));
    }

    const KIND_LABEL = { table: 'table', col: 'column', op: 'keyword', fn: 'function', kw: 'keyword' };
    const filtered = (word ? items.filter(i => i.text.toLowerCase().startsWith(word)) : items)
      .sort((a, b) => a.text.localeCompare(b.text));

    return {
      list: filtered.map(i => ({
        text: i.text,
        displayText: i.text,
        render: (el) => {
          el.innerHTML = '';
          const span = document.createElement('span'); span.textContent = i.text;
          const kind = document.createElement('span'); kind.className = 'hint-kind'; kind.textContent = KIND_LABEL[i.kind] || '';
          el.appendChild(span); el.appendChild(kind);
        },
      })),
      from: CodeMirror.Pos(cur.line, start),
      to: CodeMirror.Pos(cur.line, cur.ch),
    };
  });

  // ---------------- editor instance ----------------
  const editor = CodeMirror.fromTextArea(document.getElementById('editor'), {
    mode: 'kql', theme: 'default', lineNumbers: true, matchBrackets: true,
    styleActiveLine: true, indentUnit: 2, tabSize: 2, viewportMargin: Infinity,
    extraKeys: {
      // Shift+Enter matches the real Kusto tooling (Azure Data Explorer web UI, Kusto.Explorer,
      // Fabric Real-Time Intelligence all run the query on Shift+Enter). Kusto.Explorer actually
      // binds Ctrl+Enter to "insert new line + pipe", a different action — so we don't double-bind it here.
      'Shift-Enter': runQuery,
      'Ctrl-Space': 'autocomplete',
    },
  });
  editor.setValue('DeviceProcessEvents\n| take 10');

  // On a touch device, a virtual keyboard is already fighting for the same screen space and input
  // pipeline as CodeMirror's hidden input — popping a full suggestion list open on every single
  // keystroke (which is what desktop does) has been reported to leave the on-screen keyboard unable
  // to deliver further characters. So: no auto-popup on coarse-pointer/touch devices — the "Suggest"
  // toolbar button (added below) triggers it manually there instead. Desktop keeps live-as-you-type.
  const isTouchDevice = (window.matchMedia && window.matchMedia('(pointer: coarse)').matches) || ('ontouchstart' in window);

  function triggerHint(cm) {
    if (cm.state.completionActive) return; // never re-open on top of an already-open list
    CodeMirror.showHint(cm, CodeMirror.hint.kql, { completeSingle: false });
  }

  let hintTimer = null;
  if (!isTouchDevice) {
    editor.on('inputRead', function (cm, change) {
      if (cm.state.completionActive) return;
      if (change.text.join('') && /[A-Za-z0-9_]/.test(change.text.join(''))) {
        clearTimeout(hintTimer);
        hintTimer = setTimeout(() => { if (cm.hasFocus()) triggerHint(cm); }, 60);
      }
    });
  }
  document.getElementById('btnSuggest').addEventListener('click', () => {
    editor.focus();
    triggerHint(editor);
  });

  // ---------------- run / results ----------------
  function flattenScalar(v, vals) {
    if (v === null || v === undefined || v === '') return;
    if (Array.isArray(v)) { v.forEach(el => flattenScalar(el, vals)); return; }
    vals.push(String(v instanceof Date ? v.toISOString() : v).toLowerCase());
  }
  function flattenRows(rows) {
    const vals = [];
    for (const r of rows) for (const k of Object.keys(r)) flattenScalar(r[k], vals);
    return vals;
  }

  function fmtCell(v) {
    if (v === null || v === undefined) return { text: 'null', cls: 'null' };
    if (v instanceof Date) return { text: v.toISOString(), cls: '' };
    if (Array.isArray(v)) return { text: JSON.stringify(v), cls: '' };
    if (typeof v === 'boolean') return { text: v ? 'true' : 'false', cls: '' };
    return { text: String(v), cls: '' };
  }

  function renderResults(rows, ms) {
    const area = document.getElementById('resultsArea');
    const summary = document.getElementById('resultsSummary');
    area.innerHTML = '';
    if (!rows.length) {
      summary.textContent = '0 rows · ' + ms.toFixed(1) + ' ms';
      area.innerHTML = '<div class="results-empty">Query ran fine — just no rows matched.</div>';
      return;
    }
    const cols = Object.keys(rows[0]);
    const cap = 300;
    summary.textContent = rows.length + (rows.length === 1 ? ' row' : ' rows') +
      (rows.length > cap ? ' (showing first ' + cap + ')' : '') + ' · ' + ms.toFixed(1) + ' ms';
    const table = document.createElement('table');
    table.className = 'results';
    const thead = document.createElement('thead');
    const trh = document.createElement('tr');
    cols.forEach(c => { const th = document.createElement('th'); th.textContent = c; trh.appendChild(th); });
    thead.appendChild(trh); table.appendChild(thead);
    const tbody = document.createElement('tbody');
    rows.slice(0, cap).forEach(r => {
      const tr = document.createElement('tr');
      cols.forEach(c => {
        const td = document.createElement('td');
        const f = fmtCell(r[c]);
        td.textContent = f.text; if (f.cls) td.className = f.cls;
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    area.appendChild(table);
  }

  function showError(msg) {
    const area = document.getElementById('resultsArea');
    document.getElementById('resultsSummary').textContent = 'Query failed';
    area.innerHTML = '';
    const box = document.createElement('div');
    box.className = 'err-box';
    box.textContent = msg;
    area.appendChild(box);
  }

  function runQuery() {
    const q = editor.getValue().trim();
    if (!q) return;
    const t0 = performance.now();
    try {
      const rows = KQL.run(q, TABLES, { now: ds.NOW });
      const ms = performance.now() - t0;
      renderResults(rows, ms);
      renderQueryNotes(q, rows.length);
      return rows;
    } catch (e) {
      showError(e.message || String(e));
      hideQueryNotes();
      return null;
    }
  }

  // ---------------- query-quality coaching ----------------
  // Splits a query into pipeline stages on top-level "|" (not inside strings/parens/brackets) —
  // mirrors how KQL's own tabular-expression-statement | operator pipeline works.
  function splitStages(qText) {
    const noComments = qText.replace(/\/\/.*$/gm, '');
    const stages = [];
    let depth = 0, inStr = null, cur = '';
    for (let i = 0; i < noComments.length; i++) {
      const c = noComments[i];
      if (inStr) { cur += c; if (c === inStr && noComments[i - 1] !== '\\') inStr = null; continue; }
      if (c === '"' || c === "'") { inStr = c; cur += c; continue; }
      if (c === '(' || c === '[') { depth++; cur += c; continue; }
      if (c === ')' || c === ']') { depth--; cur += c; continue; }
      if (c === '|' && depth === 0) { stages.push(cur); cur = ''; continue; }
      cur += c;
    }
    if (cur.trim()) stages.push(cur);
    return stages.map(s => s.trim()).filter(Boolean);
  }

  function lintQuery(qText) {
    const stages = splitStages(qText);
    const tips = [];
    const primaryTable = TABLE_NAMES.find(t => new RegExp('^' + t + '\\b').test(stages[0] || ''));
    const scanned = primaryTable ? TABLES[primaryTable].length : null;

    // 1. filter early — right after the table reference is the cheapest place to cut rows down.
    const firstIsWhere = /^where\b/i.test(stages[1] || '');
    const anyWhere = stages.slice(1).some(s => /^where\b/i.test(s));
    if (anyWhere && !firstIsWhere) {
      tips.push('Move your <b>where</b> clause right after the table reference. Filtering as early as possible in the pipeline — before summarize, joins, or extend — cuts down how much a real Kusto cluster has to scan before it does anything else.');
    } else if (!anyWhere && stages.length > 1) {
      tips.push('This pipeline has no <b>where</b> at all. Even an exploratory query benefits from a narrowing filter — it keeps the scan (and your results) small.');
    }

    // 2. contains vs has — has/has_cs matches whole terms and is meant to be faster than a full substring scan.
    if (/\bcontains(_cs)?\b/i.test(qText) && !/\bhas(_cs)?\b/i.test(qText)) {
      tips.push('You\'re using <b>contains</b>, which does a full substring scan. If you\'re actually matching a whole term (a filename, a domain, a command), <b>has</b> / <b>has_cs</b> uses term indexing and is the faster choice for that case.');
    }

    // 3. case-insensitive operators (=~ / in~) cost more than their case-sensitive counterparts.
    if (/=~|!~|\bin~\s*\(/.test(qText)) {
      tips.push('You\'re using a case-insensitive operator (<b>=~</b> / <b>in~</b>). If the case of the values you\'re comparing is already known and consistent, the case-sensitive form (<b>==</b> / <b>in</b>) is cheaper to evaluate.');
    }

    // 4. bound the result set — an exploratory query with no limiting stage can return everything.
    const lastStage = stages[stages.length - 1] || '';
    const bounded = /^(take|limit|count|summarize|top)\b/i.test(lastStage) || stages.some(s => /^summarize\b/i.test(s));
    if (!bounded) {
      tips.push('Nothing in this pipeline bounds the result set — no <b>take</b>/<b>limit</b>/<b>summarize</b>/<b>top</b>. Ending exploratory queries with one of these keeps result sets predictable.');
    }

    return { scanned, tips: tips.slice(0, 3) };
  }

  function hideQueryNotes() {
    const el = document.getElementById('queryNotes');
    if (el) { el.className = ''; el.innerHTML = ''; }
  }

  function renderQueryNotes(qText, rowCount) {
    const el = document.getElementById('queryNotes');
    if (!el) return;
    const { scanned, tips } = lintQuery(qText);
    let html = '<div class="qn-head">Query quality</div>';
    if (scanned !== null) {
      html += '<div class="qn-scan">This range scans every row of the table it\'s pointed at (no indexing) — ' +
        scanned + ' row' + (scanned === 1 ? '' : 's') + ' touched, ' + rowCount + ' returned. On a real Kusto/Log Analytics cluster, an early, selective <b>where</b> is what keeps that "touched" number down.</div>';
    }
    if (tips.length) {
      tips.forEach(t => { html += '<div class="qn-tip">' + t + '</div>'; });
    } else {
      html += '<div class="qn-tip">No obvious efficiency issues in this pipeline — nicely filtered.</div>';
    }
    html += '<div class="qn-src">Grounded in Microsoft Learn: <a href="https://learn.microsoft.com/kusto/query/best-practices" target="_blank">KQL query best practices</a>.</div>';
    el.innerHTML = html;
    el.className = 'show';
  }
  document.getElementById('btnRun').addEventListener('click', runQuery);
  document.getElementById('btnClear').addEventListener('click', () => { editor.setValue(''); editor.focus(); });

  // ---------------- schema sidebar ----------------
  function renderSchema() {
    const pane = document.getElementById('paneSchema');
    pane.innerHTML = '';
    TABLE_NAMES.forEach(t => {
      const wrap = document.createElement('div'); wrap.className = 'schema-table';
      const head = document.createElement('div'); head.className = 'schema-table-head';
      head.innerHTML = '<span class="chev">▸</span><span>' + t + '</span><span class="schema-table-count">' + TABLES[t].length + ' rows</span>';
      head.title = TABLE_DESCRIPTIONS[t];
      const cols = document.createElement('div'); cols.className = 'schema-cols';
      (SCHEMA[t] || []).forEach(c => {
        const el = document.createElement('div'); el.className = 'schema-col';
        el.innerHTML = '<span>' + c + '</span>';
        el.addEventListener('click', (e) => { e.stopPropagation(); insertAtCursor(c); });
        cols.appendChild(el);
      });
      head.addEventListener('click', () => {
        const open = head.classList.toggle('open');
        cols.classList.toggle('open', open);
        head.querySelector('.chev').textContent = open ? '▾' : '▸';
      });
      head.addEventListener('dblclick', () => insertTable(t));
      wrap.appendChild(head); wrap.appendChild(cols);
      pane.appendChild(wrap);
    });
    const note = document.createElement('div');
    note.style.cssText = 'padding:10px 12px;font-size:11px;color:var(--text-faint);line-height:1.5';
    note.textContent = 'Click a table name to open it, double-click to insert. Click a column to insert it at the cursor. Columns and table names match the real Microsoft Defender advanced-hunting schema (learn.microsoft.com/defender-xdr).';
    pane.appendChild(note);
  }

  function insertAtCursor(text) {
    editor.replaceRange(text, editor.getCursor());
    editor.focus();
  }
  function insertTable(t) {
    if (!editor.getValue().trim()) editor.setValue(t + '\n| ');
    else insertAtCursor(t);
    editor.focus();
  }

  // ---------------- scenarios sidebar ----------------
  function scenarioMatchesFilter(s) {
    if (skillFilter.domain !== 'all' && s.domain !== skillFilter.domain) return false;
    if (skillFilter.discipline !== 'all' && s.discipline !== skillFilter.discipline) return false;
    return true;
  }
  function renderFilterBar(pane) {
    const bar = document.createElement('div');
    bar.className = 'skill-filter-bar';
    const mkSelect = (label, options, current, onChange) => {
      const wrap = document.createElement('label');
      wrap.className = 'skill-filter-field';
      const sel = document.createElement('select');
      sel.innerHTML = '<option value="all">All ' + label + '</option>' +
        options.map(o => '<option value="' + escapeHtml(o) + '"' + (o === current ? ' selected' : '') + '>' + escapeHtml(o) + '</option>').join('');
      sel.addEventListener('change', () => { onChange(sel.value); renderScenarios(); });
      wrap.appendChild(sel);
      return wrap;
    };
    bar.appendChild(mkSelect('domains', ALL_DOMAINS, skillFilter.domain === 'all' ? null : skillFilter.domain, v => skillFilter.domain = v));
    bar.appendChild(mkSelect('disciplines', ALL_DISCIPLINES, skillFilter.discipline === 'all' ? null : skillFilter.discipline, v => skillFilter.discipline = v));
    if (skillFilter.domain !== 'all' || skillFilter.discipline !== 'all') {
      const clear = document.createElement('button');
      clear.className = 'linkbtn skill-filter-clear'; clear.textContent = 'Clear filter';
      clear.addEventListener('click', () => { skillFilter = { domain: 'all', discipline: 'all' }; renderScenarios(); });
      bar.appendChild(clear);
    }
    pane.appendChild(bar);
  }
  function renderScenarios() {
    const pane = document.getElementById('paneScenarios');
    pane.innerHTML = '';
    renderFilterBar(pane);
    const visible = scenarios.filter(scenarioMatchesFilter);
    if (!visible.length) {
      const empty = document.createElement('div');
      empty.className = 'scn-empty';
      empty.textContent = 'No missions match this filter yet.';
      pane.appendChild(empty);
    }
    const levels = ['Beginner', 'Intermediate', 'Advanced', 'Expert', 'Claude-generated'];
    levels.forEach(level => {
      const items = visible.filter(s => (s.generated ? 'Claude-generated' : s.level) === level);
      if (!items.length) return;
      const label = document.createElement('div'); label.className = 'scn-group-label'; label.textContent = level;
      pane.appendChild(label);
      items.forEach(s => {
        const el = document.createElement('div'); el.className = 'scn-item' + (currentScenario === s ? ' active' : '');
        const isDone = completed.has(s.id);
        const done = isDone ? '<span class="done">✓</span>' : '';
        let sub = s.table + (s.domain ? ' · ' + s.domain : '');
        if (s.multiStep && !isDone) {
          sub = 'Step ' + (currentStepIndex(s) + 1) + '/' + s.steps.length + ' · ' + sub;
        }
        // escapeHtml(s.title): every other render site for a scenario title does this (shift queue,
        // learning matrix, learning paths) — this one didn't, and s.title can come from the optional
        // Claude-generated-scenario feature (an LLM response steered by free user text), so an
        // unescaped title here was a real (low-severity, self-XSS-only) injection path.
        el.innerHTML = '<div class="scn-item-title">' + done + '<span>' + escapeHtml(s.title) + '</span></div><div class="scn-item-sub">' + escapeHtml(sub) + '</div>';
        el.addEventListener('click', () => selectScenario(s));
        pane.appendChild(el);
      });
    });
    if (typeof renderShiftQueue === 'function') renderShiftQueue();
    if (typeof checkBadges === 'function') checkBadges();
  }

  // ---------------- multi-step "start to finish" investigations ----------------
  // A multiStep scenario (sc.multiStep === true, sc.steps === [...]) is walked one step at a time:
  // each step has its own prompt/hints/solutionQuery/facts/answer, just like a normal single-step
  // mission. effectiveScenario() returns a "virtual" merged view — the parent scenario with the current
  // step's fields overlaid — so every existing hint/reveal/answer/facts code path below can treat it
  // exactly like any other scenario object without knowing multi-step exists. The virtual object keeps
  // the REAL scenario id (so completed/badges/war-room all key correctly) plus a back-reference to the
  // parent and the active step index, which is all tryAdvanceStep() needs to know whether "correct
  // answer" should advance to the next step instead of completing the mission.
  function currentStepIndex(s) {
    if (!s.multiStep) return 0;
    return Math.min(stepIndex[s.id] || 0, s.steps.length - 1);
  }
  function effectiveScenario(s) {
    if (!s || !s.multiStep) return s;
    const idx = currentStepIndex(s);
    return Object.assign({}, s, s.steps[idx], { id: s.id, _multiStepParent: s, _stepIndex: idx });
  }
  function hintKey(sc) {
    return sc._multiStepParent ? sc.id + '#' + sc._stepIndex : sc.id;
  }
  function tryAdvanceStep(sc) {
    if (sc._multiStepParent && sc._stepIndex < sc._multiStepParent.steps.length - 1) {
      const parent = sc._multiStepParent;
      stepIndex[parent.id] = sc._stepIndex + 1;
      saveStepIndex();
      selectScenario(parent);
      return true;
    }
    return false;
  }
  function renderMissionSteps(s, eff) {
    const el = document.getElementById('missionSteps');
    if (!el) return;
    if (!s.multiStep) { el.hidden = true; el.innerHTML = ''; return; }
    el.hidden = false;
    const idx = eff._stepIndex;
    el.innerHTML = '<div class="mission-intro">' + escapeHtml(s.intro || '') + '</div>' +
      '<div class="step-pills">' + s.steps.map((st, i) => {
        const cls = 'step-pill' + (i < idx ? ' step-done' : (i === idx ? ' step-active' : ''));
        const marker = i < idx ? '✓ ' : (i + 1) + '. ';
        return '<span class="' + cls + '">' + marker + escapeHtml(st.label || ('Step ' + (i + 1))) + '</span>';
      }).join('') + '</div>';
  }

  function selectScenario(s) {
    currentScenario = s;
    const eff = effectiveScenario(s);
    document.getElementById('mission').hidden = false;
    document.getElementById('missionLevel').textContent = s.generated ? 'Claude' : s.level;
    document.getElementById('missionTitle').textContent = s.title;
    const mitreEl = document.getElementById('missionMitre');
    if (eff.mitre) { mitreEl.textContent = eff.mitre; mitreEl.hidden = false; } else { mitreEl.hidden = true; }
    renderMissionSteps(s, eff);
    document.getElementById('missionPrompt').textContent = eff.prompt;
    document.getElementById('hintBox').innerHTML = '';
    renderScenarios();
    if (window.__warroomSyncScenario) window.__warroomSyncScenario(s);
  }

  document.getElementById('btnCloseMission').addEventListener('click', () => {
    currentScenario = null;
    document.getElementById('mission').hidden = true;
    renderScenarios();
  });
  // ---------------- peer hint toast ----------------
  const PEER_ANALYSTS = [
    { name: 'Priya', role: 'SOC, Tier 2' }, { name: 'Marcus', role: 'Threat Hunter' },
    { name: 'Jade', role: 'SOC, night shift' }, { name: 'Sam', role: 'IR on-call' },
    { name: 'Noor', role: 'SOC, Tier 1' }, { name: 'Devon', role: 'Threat Intel' },
  ];
  function hashStrLocal(s) { let h = 0; for (let i = 0; i < s.length; i++) h = (Math.imul(31, h) + s.charCodeAt(i)) | 0; return h >>> 0; }
  // Progressive breadcrumb hints: sc.hints is a 3-tier array (conceptual nudge -> structural pointer ->
  // near-solution). Older/Claude-generated scenarios may only have a single sc.hint string — treat that
  // as a one-tier fallback rather than breaking.
  function getHints(sc) {
    if (Array.isArray(sc.hints) && sc.hints.length) return sc.hints;
    if (sc.hint) return [sc.hint];
    return [];
  }
  const TIER_LABEL = ['Nudge', 'Pointer', 'Near-solution'];
  let hintProgress = {}; // scenarioId -> index of the next tier to reveal
  function showPeerHint(scenarioId, text, tier, total) {
    const wrap = document.getElementById('peerToastWrap');
    const peer = PEER_ANALYSTS[hashStrLocal(scenarioId) % PEER_ANALYSTS.length];
    const el = document.createElement('div');
    el.className = 'peer-toast';
    const tierLabel = TIER_LABEL[tier - 1] || ('Hint ' + tier);
    const footer = tier < total
      ? 'Still stuck? Ask again for a closer nudge (' + tier + '/' + total + ').'
      : 'That\'s as close as a teammate will get you (' + tier + '/' + total + ') — the rest is on you.';
    el.innerHTML =
      '<div class="avatar">' + peer.name[0] + '</div>' +
      '<div class="body">' +
      '<div class="who">' + peer.name + ' <span class="role">· ' + peer.role + '</span> <span class="hint-tier">· ' + tierLabel + '</span></div>' +
      '<div class="msg">' + escapeHtml(text) + '</div>' +
      '<div class="caveat">' + footer + '</div>' +
      '</div><button class="close" aria-label="Dismiss">×</button>';
    const closeBtn = el.querySelector('.close');
    function dismiss() {
      el.classList.add('closing');
      setTimeout(() => el.remove(), 200);
    }
    closeBtn.addEventListener('click', dismiss);
    wrap.appendChild(el);
    setTimeout(dismiss, 20000);
    // cap how many stack up at once
    while (wrap.children.length > 3) wrap.removeChild(wrap.firstChild);
  }
  document.getElementById('btnHint').addEventListener('click', () => {
    if (!currentScenario) return;
    const sc = effectiveScenario(currentScenario);
    const hints = getHints(sc);
    if (!hints.length) return;
    const key = hintKey(sc);
    const idx = Math.min(hintProgress[key] || 0, hints.length - 1);
    showPeerHint(sc.id, hints[idx], idx + 1, hints.length);
    hintProgress[key] = Math.min(idx + 1, hints.length - 1);
  });
  document.getElementById('btnSolution').addEventListener('click', () => {
    if (!currentScenario) return;
    const box = document.getElementById('hintBox');
    const pre = document.createElement('pre');
    pre.textContent = effectiveScenario(currentScenario).solutionQuery;
    const div = document.createElement('div'); div.className = 'reveal-box';
    div.innerHTML = 'One straightforward way to solve it:';
    div.appendChild(pre);
    const note = document.createElement('div');
    note.style.cssText = 'margin-top:8px;font-style:italic;color:var(--text-faint)';
    note.textContent = 'This isn\'t the only correct query — KQL usually has more than one valid path to the same answer. If yours gets there differently and still checks out, that\'s a win too.';
    div.appendChild(note);
    box.innerHTML = ''; box.appendChild(div);
  });
  document.getElementById('btnCheckAnswer').addEventListener('click', () => {
    if (!currentScenario) return;
    const sc = effectiveScenario(currentScenario);
    const rows = runQuery();
    const box = document.getElementById('hintBox');
    if (!rows) { box.innerHTML = '<div class="reveal-box">Fix the error above first, then check again.</div>'; return; }

    if (sc.expectEmpty) {
      if (rows.length === 0) {
        if (tryAdvanceStep(sc)) return;
        completed.add(sc.id); saveCompleted(); renderScenarios();
        box.innerHTML = '<div class="pass-box">✓ Confirmed — empty result. That\'s the answer this mission was after.</div>';
      } else {
        box.innerHTML = '<div class="reveal-box">Not empty yet — your query returned ' + rows.length + ' row' + (rows.length === 1 ? '' : 's') + '. This mission is asking you to prove nothing\'s there; check your filter matches the scope described.</div>';
      }
      return;
    }

    // Real analysts don't get an "are you even close" gate before they're allowed to state a finding —
    // any query that RUNS (no syntax/format error) earns a chance to answer. If the results don't look
    // like they contain what this mission is after, say so as a heads-up, not a hard stop.
    const flat = flattenRows(rows);
    const missing = sc.facts ? sc.facts.filter(f => !flat.some(v => v.includes(f.toLowerCase()))) : [];
    const advisory = missing.length
      ? 'Heads up — your results don\'t obviously show what this mission is after. You can still state an answer if you\'re confident, or adjust your filters/columns and check again first.'
      : null;

    if (sc.answer) {
      renderAnswerBox(sc, rows.length, advisory);
      return;
    }

    if (tryAdvanceStep(sc)) return;

    if (sc.disposition) {
      renderDispositionStep(sc, rows.length);
      return;
    }

    completed.add(sc.id); saveCompleted(); renderScenarios();
    renderPassBox(sc, rows.length);
  });

  // Called after a correct answer-box submission. sc is the effectiveScenario() (possibly a per-step
  // virtual view) — tryAdvanceStep() handles "this was step N of a multi-step investigation, not the
  // last one" by moving to the next step's prompt instead of completing. On the final step (or any
  // ordinary single-step mission) it returns false and the normal disposition/completion flow below
  // runs exactly as it always has.
  function proceedAfterAnswer(sc, rowCount) {
    if (tryAdvanceStep(sc)) return;
    if (sc.disposition) {
      renderDispositionStep(sc, rowCount);
      return;
    }
    completed.add(sc.id); saveCompleted(); renderScenarios();
    renderPassBox(sc, rowCount);
  }

  // ---------------- answer box: state the finding, know it's correct, move on ----------------
  function normAnswer(s) {
    return String(s == null ? '' : s).trim().toLowerCase().replace(/\s+/g, ' ').replace(/^["']|["']$/g, '');
  }
  function answerIsCorrect(sc, input) {
    const norm = normAnswer(input);
    if (!norm) return false;
    if (norm === normAnswer(sc.answer)) return true;
    if (Array.isArray(sc.answerAliases) && sc.answerAliases.some(a => normAnswer(a) === norm)) return true;
    return false;
  }
  function renderAnswerBox(sc, rowCount, advisory) {
    const box = document.getElementById('hintBox');
    const head = advisory
      ? '<div class="warn-box" style="margin-bottom:8px">' + escapeHtml(advisory) + '</div>'
      : '';
    box.innerHTML =
      head +
      '<div class="ans-box">' +
      '<div class="ans-head">' + (advisory ? 'State the answer: ' : '✓ Your query found it. Now state the answer: ') + '<b>' + escapeHtml(sc.answerLabel || 'What\'s the answer?') + '</b></div>' +
      '<div class="ans-row">' +
      '<input type="text" class="ans-input" placeholder="Type your answer…" autocomplete="off" spellcheck="false">' +
      '<button class="iconbtn primary" id="btnSubmitAnswer">Submit</button>' +
      '</div>' +
      '<div id="ansResult"></div>' +
      '</div>';
    let attempts = 0;
    const input = box.querySelector('.ans-input');
    const submitBtn = box.querySelector('#btnSubmitAnswer');
    const resultEl = box.querySelector('#ansResult');
    function submit() {
      const val = input.value;
      if (!val.trim()) return;
      const correct = answerIsCorrect(sc, val);
      if (correct) {
        if (attempts === 0) recordFirstTryCorrect(sc.id);
        resultEl.innerHTML = '<div class="pass-box">✓ Correct.</div>';
        input.disabled = true; submitBtn.disabled = true;
        setTimeout(() => proceedAfterAnswer(sc, rowCount), 450);
      } else {
        attempts++;
        resultEl.innerHTML = '<div class="warn-box">Not quite — check your results again and try once more.</div>';
      }
    }
    submitBtn.addEventListener('click', submit);
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
    input.focus();
  }
  function recordFirstTryCorrect(id) {
    let set;
    try { set = new Set(JSON.parse(localStorage.getItem('kqlrange.firstTryCorrect') || '[]')); } catch (e) { set = new Set(); }
    if (!set.has(id)) {
      set.add(id);
      try { localStorage.setItem('kqlrange.firstTryCorrect', JSON.stringify([...set])); } catch (e) { /* ignore */ }
      checkBadges();
    }
  }

  function renderPassBox(sc, rowCount) {
    const box = document.getElementById('hintBox');
    if (sc.maxExpectedRows && rowCount > sc.maxExpectedRows) {
      box.innerHTML = '<div class="warn-box">✓ Found it — but your query returned ' + rowCount + ' rows where ' + sc.maxExpectedRows +
        ' would\'ve nailed it.<span class="warn-sub">A real analyst has to hand this off — extra rows mean extra noise for whoever reads it next. Try narrowing your filter further.</span></div>';
    } else {
      box.innerHTML = '<div class="pass-box">✓ That answers it — your results contain what this mission was looking for.</div>';
    }
  }

  // ---------------- disposition step: close the alert like a real analyst would ----------------
  function renderDispositionStep(sc, rowCount) {
    const box = document.getElementById('hintBox');
    box.innerHTML =
      '<div class="disp-box">' +
      '<div class="disp-head">✓ Evidence found. Now close it out like a real analyst would — what\'s your disposition?</div>' +
      '<div class="disp-btns">' +
      '<button class="disp-btn" data-v="TP">True Positive</button>' +
      '<button class="disp-btn" data-v="FP">False Positive</button>' +
      '<button class="disp-btn" data-v="BP">Benign Positive</button>' +
      '</div>' +
      '<textarea class="disp-note" placeholder="One line: why? (required to close)"></textarea>' +
      '<div class="disp-actions"><button class="iconbtn primary" id="btnSubmitDisposition" disabled>Close alert</button></div>' +
      '<div id="dispResult"></div>' +
      '</div>';
    let chosen = null;
    const buttons = box.querySelectorAll('.disp-btn');
    const noteEl = box.querySelector('.disp-note');
    const submitBtn = box.querySelector('#btnSubmitDisposition');
    function refreshEnabled() { submitBtn.disabled = !(chosen && noteEl.value.trim().length >= 8); }
    buttons.forEach(b => b.addEventListener('click', () => {
      chosen = b.dataset.v;
      buttons.forEach(x => x.classList.toggle('active', x === b));
      refreshEnabled();
    }));
    noteEl.addEventListener('input', refreshEnabled);
    submitBtn.addEventListener('click', () => {
      completed.add(sc.id); saveCompleted(); renderScenarios();
      const correct = chosen === sc.disposition;
      if (correct && (sc.disposition === 'FP' || sc.disposition === 'BP')) {
        try { localStorage.setItem('kqlrange.notFooled', 'true'); } catch (e) { /* ignore */ }
        checkBadges();
      }
      const label = { TP: 'True Positive', FP: 'False Positive', BP: 'Benign Positive' };
      const msg = correct
        ? '✓ Correct disposition: ' + label[chosen] + '.'
        : 'Logged as ' + label[chosen] + ' — a real analyst reviewing this would\'ve closed it as ' + label[sc.disposition] + ' instead.';
      const resultEl = box.querySelector('#dispResult');
      resultEl.innerHTML = '<div class="' + (correct ? 'pass-box' : 'warn-box') + '">' + msg +
        '<span class="warn-sub">' + escapeHtml(sc.dispositionWhy || '') + '</span></div>';
      submitBtn.disabled = true;
      buttons.forEach(b => b.disabled = true);
      noteEl.disabled = true;
      if (sc.maxExpectedRows && rowCount > sc.maxExpectedRows) {
        const warnEl = document.createElement('div');
        warnEl.className = 'warn-box';
        warnEl.style.marginTop = '8px';
        warnEl.innerHTML = 'Also worth noting — your query returned ' + rowCount + ' rows where ' + sc.maxExpectedRows + ' would\'ve nailed it.';
        box.appendChild(warnEl);
      }
    });
  }

  // ---------------- war room: per-incident notes, saved locally on this device ----------------
  (function initWarRoom() {
    const panel = document.getElementById('warroom');
    const backdrop = document.getElementById('warroomBackdrop');
    const toggleBtn = document.getElementById('btnWarRoom');
    const closeBtn = document.getElementById('btnCloseWarRoom');
    const select = document.getElementById('warroomSelect');
    const text = document.getElementById('warroomText');
    const saveBtn = document.getElementById('btnSaveWarRoom');
    const savedLabel = document.getElementById('warroomSaved');
    if (!panel || !select) return;

    function rebuildOptions(selectId) {
      const keep = selectId || select.value || 'general';
      select.innerHTML = '<option value="general">General / scratch notes</option>' +
        scenarios.map(s => '<option value="' + s.id + '">' + escapeHtml(s.title) + '</option>').join('');
      select.value = [...select.options].some(o => o.value === keep) ? keep : 'general';
    }
    rebuildOptions();

    function storageKey(id) { return 'kqlrange.warroom.' + id; }
    function loadNote(id) {
      try {
        const raw = localStorage.getItem(storageKey(id));
        return raw ? JSON.parse(raw) : null;
      } catch (e) { return null; }
    }
    function fmtSavedAt(ts) {
      const diffMin = Math.round((Date.now() - ts) / 60000);
      if (diffMin < 1) return 'Saved just now';
      if (diffMin < 60) return 'Saved ' + diffMin + ' min ago';
      const d = new Date(ts);
      return 'Saved ' + d.toLocaleString();
    }
    function refreshForSelection() {
      const note = loadNote(select.value);
      text.value = note ? note.text : '';
      savedLabel.textContent = note ? fmtSavedAt(note.savedAt) : 'Not saved yet on this device';
    }
    select.addEventListener('change', refreshForSelection);
    saveBtn.addEventListener('click', () => {
      const entry = { text: text.value, savedAt: Date.now() };
      try { localStorage.setItem(storageKey(select.value), JSON.stringify(entry)); } catch (e) { /* ignore */ }
      savedLabel.textContent = fmtSavedAt(entry.savedAt);
    });

    function openPanel() {
      rebuildOptions(currentScenario ? currentScenario.id : null);
      refreshForSelection();
      panel.classList.add('open');
      if (backdrop) backdrop.classList.add('open');
    }
    function closePanel() {
      panel.classList.remove('open');
      if (backdrop) backdrop.classList.remove('open');
    }
    toggleBtn.addEventListener('click', () => {
      panel.classList.contains('open') ? closePanel() : openPanel();
    });
    closeBtn.addEventListener('click', closePanel);
    if (backdrop) backdrop.addEventListener('click', closePanel);

    // expose so selectScenario() can keep the panel's dropdown following the active mission
    window.__warroomSyncScenario = function (s) {
      if (!panel.classList.contains('open') || !s) return;
      rebuildOptions(s.id);
      refreshForSelection();
    };
  })();

  function escapeHtml(s) {
    const d = document.createElement('div'); d.textContent = s; return d.innerHTML;
  }

  // ---------------- sidebar tabs ----------------
  document.querySelectorAll('.sidebar-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.sidebar-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById('paneScenarios').hidden = tab.dataset.tab !== 'scenarios';
      document.getElementById('paneSchema').hidden = tab.dataset.tab !== 'schema';
      document.getElementById('paneShift').hidden = tab.dataset.tab !== 'shift';
      if (tab.dataset.tab === 'shift') renderShiftQueue();
    });
  });

  // ---------------- shift queue: alert-driven missions, triaged like a real on-call queue ----------------
  const SEVERITY_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3 };
  // Illustrative SOC triage targets for this simulation (not a cited external standard) — Critical/High
  // get the tightest turnaround, Low the loosest, so the queue has something real to be "overdue" against.
  const SLA_TARGET_MS = { Critical: 30 * 60000, High: 4 * 3600000, Medium: 24 * 3600000, Low: 72 * 3600000 };

  function fmtAge(ms) {
    if (ms < 0) ms = 0;
    const min = Math.floor(ms / 60000);
    if (min < 60) return min + 'm ago';
    const hr = Math.floor(min / 60);
    if (hr < 48) return hr + 'h ' + (min % 60) + 'm ago';
    const day = Math.floor(hr / 24);
    return day + 'd ' + (hr % 24) + 'h ago';
  }

  function alertQueueItems() {
    const alertRows = TABLES.AlertInfo || [];
    const byId = {};
    alertRows.forEach(a => { byId[a.AlertId] = a; });
    return scenarios
      .filter(s => s.alertId && byId[s.alertId])
      .map(s => {
        const alert = byId[s.alertId];
        const ageMs = ds.NOW.getTime() - new Date(alert.Timestamp).getTime();
        return { sc: s, alert, ageMs, done: completed.has(s.id) };
      })
      .sort((a, b) => {
        if (a.done !== b.done) return a.done ? 1 : -1;
        const sevDiff = (SEVERITY_ORDER[a.alert.Severity] ?? 9) - (SEVERITY_ORDER[b.alert.Severity] ?? 9);
        if (sevDiff !== 0) return sevDiff;
        return b.ageMs - a.ageMs;
      });
  }

  function renderShiftQueue() {
    const pane = document.getElementById('paneShift');
    if (!pane) return;
    pane.innerHTML = '';
    const items = alertQueueItems();
    if (!items.length) {
      pane.innerHTML = '<div class="shift-empty">No alert-linked missions loaded.</div>';
      return;
    }
    const note = document.createElement('div');
    note.className = 'shift-empty';
    note.textContent = 'Fired alerts, oldest and most severe first — the way a real triage queue sorts. Each one needs a disposition to close.';
    pane.appendChild(note);
    items.forEach(({ sc, alert, ageMs, done }) => {
      const sla = SLA_TARGET_MS[alert.Severity];
      const breached = sla && ageMs > sla;
      const el = document.createElement('div');
      el.className = 'queue-item' + (done ? ' queue-done' : '');
      const sevClass = 'sev-' + String(alert.Severity || 'low').toLowerCase();
      el.innerHTML =
        '<div class="queue-top">' +
        '<span class="sev-badge ' + sevClass + '">' + escapeHtml(alert.Severity || '') + '</span>' +
        (done ? '<span class="done">✓ closed</span>' : '') +
        '<span class="queue-age' + (breached && !done ? ' sla-breach' : '') + '">' + fmtAge(ageMs) + (breached && !done ? ' · SLA breached' : '') + '</span>' +
        '</div>' +
        '<div class="queue-title">' + escapeHtml(alert.Title || sc.title) + '</div>' +
        '<div class="queue-sub">' + escapeHtml(alert.ServiceSource || '') + ' · ' + escapeHtml(sc.mitre || '') + '</div>';
      el.addEventListener('click', () => {
        selectScenario(sc);
        document.querySelectorAll('.sidebar-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === 'scenarios'));
        document.getElementById('paneScenarios').hidden = false;
        document.getElementById('paneSchema').hidden = true;
        document.getElementById('paneShift').hidden = true;
        if (window.matchMedia('(max-width: 820px)').matches) {
          document.getElementById('sidebar').classList.remove('open');
          document.getElementById('sidebarBackdrop').classList.remove('open');
        }
      });
      pane.appendChild(el);
    });
  }

  // ---------------- cheat sheet ----------------
  function renderCheatSheet() {
    const c = document.getElementById('cheatContent');
    c.innerHTML =
      '<h4>Tabular operators</h4>' +
      '<ul>' +
      '<li><code>where Predicate</code> — filter rows</li>' +
      '<li><code>project Col1, Col2 = Expr</code> — pick/compute columns</li>' +
      '<li><code>extend NewCol = Expr</code> — add a computed column</li>' +
      '<li><code>summarize Agg() by Col</code> — group &amp; aggregate</li>' +
      '<li><code>sort by Col [asc|desc]</code> (alias <code>order by</code>, default is <b>desc</b>)</li>' +
      '<li><code>top N by Col</code> — sort + limit combined</li>' +
      '<li><code>take N</code> (alias <code>limit</code>) — first N rows, no ordering guarantee</li>' +
      '<li><code>distinct Col1, Col2</code></li>' +
      '<li><code>count</code></li>' +
      '<li><code>join kind=inner|leftouter|... (T2) on Col</code></li>' +
      '<li><code>project-away / project-keep / project-rename</code></li>' +
      '</ul>' +
      '<h4>String operators (all support a leading <code>!</code> to negate)</h4>' +
      '<ul><li><code>== != </code> case-sensitive equals</li>' +
      '<li><code>=~ !~</code> case-insensitive equals</li>' +
      '<li><code>contains / has</code> — substring vs. whole-term match, both case-insensitive (add <code>_cs</code> for case-sensitive)</li>' +
      '<li><code>has_any (...) / has_all (...)</code> — whole-term match against any/all of a list (the pattern Microsoft\'s own hunting docs use, e.g. <code>ProcessCommandLine has_any("DownloadFile","IEX")</code>)</li>' +
      '<li><code>startswith / endswith</code></li>' +
      '<li><code>in (...)</code> case-sensitive list match, <code>in~ (...)</code> case-insensitive</li></ul>' +
      '<h4>Date/time</h4>' +
      '<ul><li><code>ago(1h)</code>, <code>ago(7d)</code> — time relative to now</li>' +
      '<li><code>bin(Timestamp, 5m)</code> — round down into buckets, for time-series summarize</li></ul>' +
      '<h4>Common functions</h4>' +
      '<ul><li>strings: <code>strcat() tostring() strlen() substring() split() tolower() toupper()</code></li>' +
      '<li>aggregations (inside summarize): <code>count() countif() dcount() sum() avg() max() min() make_set() make_list() arg_max() arg_min()</code></li>' +
      '<li>logic: <code>case() iif() / iff() coalesce() isempty() isnotempty() isnull() isnotnull()</code></li></ul>' +
      '<p style="color:var(--text-faint)">This range implements a teaching subset of KQL — enough to cover everything KC7 missions typically ask for. Not supported here: dynamic/JSON columns (so no <code>parse_json()</code> or bracket member-access on columns like AuditLogs.TargetResources), <code>parse</code>, <code>extract()</code>, <code>mv-expand</code>, <code>materialize</code>, window functions, geospatial functions, <code>print</code>, <code>datatable</code>, the <code>search</code> operator, and user-defined <code>let</code> functions (<code>let</code> here only binds scalars/tables, not <code>(x:long) {{ ... }}</code>-style functions). If a real portal query fails only here, it\'s likely leaning on one of those.</p>' +
      '<div class="src">Verified against Microsoft Learn: ' +
      '<a href="https://learn.microsoft.com/kusto/query/kql-quick-reference" target="_blank">KQL quick reference</a>, ' +
      '<a href="https://learn.microsoft.com/kusto/query/where-operator" target="_blank">where</a>, ' +
      '<a href="https://learn.microsoft.com/kusto/query/summarize-operator" target="_blank">summarize</a>, ' +
      '<a href="https://learn.microsoft.com/kusto/query/join-operator" target="_blank">join</a>, ' +
      '<a href="https://learn.microsoft.com/kusto/query/sort-operator" target="_blank">sort</a>, ' +
      '<a href="https://learn.microsoft.com/kusto/query/has-any-operator" target="_blank">has_any</a>, ' +
      '<a href="https://learn.microsoft.com/kusto/query/coalesce-function" target="_blank">coalesce</a>, ' +
      '<a href="https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-tables" target="_blank">advanced hunting schema</a>, ' +
      '<a href="https://learn.microsoft.com/azure/azure-monitor/reference/tables/signinlogs" target="_blank">SigninLogs schema</a>.</div>';
  }
  renderCheatSheet();
  document.getElementById('btnCheat').addEventListener('click', () => { document.getElementById('cheatModal').hidden = false; });
  document.getElementById('btnCloseCheat').addEventListener('click', () => { document.getElementById('cheatModal').hidden = true; });

  // ---------------- modal close: top-right ✕ on every modal, plus Escape ----------------
  // The bottom "Close" button stays (some modals pair it with another action, e.g. genModal's
  // Cancel/Generate), but every modal now also gets a clearer, always-in-the-same-spot ✕ up top.
  document.querySelectorAll('.modal-x').forEach(btn => {
    btn.addEventListener('click', () => { btn.closest('.modal-backdrop').hidden = true; });
  });
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    document.querySelectorAll('.modal-backdrop:not([hidden])').forEach(m => { m.hidden = true; });
  });

  // ---------------- theme toggle ----------------
  (function initTheme() {
    let mode = 'system';
    try { mode = localStorage.getItem('kqlrange.theme') || 'system'; } catch (e) {}
    apply(mode);
    document.getElementById('btnTheme').addEventListener('click', () => {
      mode = mode === 'system' ? 'light' : mode === 'light' ? 'dark' : 'system';
      apply(mode);
      try { localStorage.setItem('kqlrange.theme', mode); } catch (e) {}
    });
    function apply(m) {
      if (m === 'system') document.documentElement.removeAttribute('data-theme');
      else document.documentElement.setAttribute('data-theme', m);
      const btn = document.getElementById('btnTheme');
      const full = btn.querySelector('.full-label'), short = btn.querySelector('.short-label');
      if (full) full.textContent = 'Theme: ' + m;
      if (short) short.textContent = m === 'light' ? '☀' : m === 'dark' ? '☾' : '◐';
    }
  })();

  // ---------------- mobile sidebar toggle ----------------
  (function initMobileMenu() {
    const sidebar = document.getElementById('sidebar');
    const backdrop = document.getElementById('sidebarBackdrop');
    const menuBtn = document.getElementById('btnMenu');
    if (!sidebar || !backdrop || !menuBtn) return;
    function openSidebar() { sidebar.classList.add('open'); backdrop.classList.add('open'); }
    function closeSidebar() { sidebar.classList.remove('open'); backdrop.classList.remove('open'); }
    menuBtn.addEventListener('click', () => {
      if (sidebar.classList.contains('open')) closeSidebar(); else openSidebar();
    });
    backdrop.addEventListener('click', closeSidebar);
    sidebar.addEventListener('click', (e) => {
      if (e.target.closest('.scn-item') || e.target.closest('.schema-col')) {
        if (window.matchMedia('(max-width: 820px)').matches) closeSidebar();
      }
    });
  })();

  // ---------------- table hint under toolbar ----------------
  document.getElementById('tableHint').textContent = TABLE_NAMES.join(' · ');

  // ---------------- Claude "generate scenario" (sample capability) ----------------
  (function initSample() {
    if (typeof window.claude === 'undefined' || typeof window.claude.use !== 'function') return;
    window.claude.use('sample').then(sample => {
      if (!sample) return;
      document.getElementById('btnGenerate').hidden = false;
      document.getElementById('btnGenerate').addEventListener('click', () => { document.getElementById('genModal').hidden = false; });
      document.getElementById('btnGenCancel').addEventListener('click', () => { document.getElementById('genModal').hidden = true; });
      document.getElementById('btnGenGo').addEventListener('click', () => generateScenario(sample));
    }).catch(() => {});
  })();

  function schemaSummaryForPrompt() {
    return TABLE_NAMES.map(t => t + ': ' + (SCHEMA[t] || []).slice(0, 16).join(', ')).join('\n');
  }

  async function generateScenario(sample) {
    const status = document.getElementById('genStatus');
    const topic = document.getElementById('genTopic').value.trim();
    status.textContent = 'Asking Claude to write a scenario...';
    document.getElementById('btnGenGo').disabled = true;
    try {
      const authorPrompt =
        'You are writing one practice scenario for a KQL (Kusto Query Language) training tool that simulates a ' +
        'Microsoft Defender advanced-hunting-style log workspace. The workspace has these tables and columns:\n' +
        schemaSummaryForPrompt() + '\n\n' +
        'The environment is a fictional company "Fabrikam" and contains, among lots of benign noise, three ' +
        'embedded incidents: (1) a phishing email to kwalters@fabrikam.example led to a malicious Excel macro ' +
        'spawning powershell.exe on FAB-FIN-07, which beaconed out to a domain; (2) the account svc_backup on ' +
        'FAB-IT-01 was brute-forced from an external IP and then logged on with local admin rights; (3) many files ' +
        'were renamed with a ".locked" extension in a tight time window on FAB-ENG-03 by a process running from a ' +
        'Temp folder.\n' +
        (topic ? ('The user asked you to focus on: ' + topic + '\n') : '') +
        'Write ONE new investigative question that is answerable using only the operators: where, project, extend, ' +
        'summarize/by, sort by, top, take, distinct, count, join (kind=inner/leftouter/leftsemi/leftanti), and the ' +
        'functions ago(), bin(), contains, has, startswith, endswith, in, tostring, strcat, case, iif, count(), ' +
        'countif(), dcount(), sum(), avg(), max(), min(), make_set(). Do NOT use parse, mv-expand, or geospatial ' +
        'functions — they are not supported. Respond with ONLY a JSON object, no markdown fences, with this exact ' +
        'shape: {"title": "short title", "level": "Beginner|Intermediate|Advanced", "prompt": "1-3 sentence mission ' +
        'briefing written the way a SOC lead would brief an analyst", "hint": "one sentence hint pointing at the ' +
        'right operator/column without giving the answer away", "solutionQuery": "the exact KQL query that answers ' +
        'it", "keyFacts": ["2-4 short strings you expect to literally appear in the query result that prove it was ' +
        'answered correctly, e.g. a hostname, domain, username, or a specific number"]}';

      const result = await sample.json(authorPrompt, { modelTier: 'default' });
      const spec = result && result.json ? result.json : result;
      if (!spec || !spec.solutionQuery) throw new Error('Claude did not return a usable scenario.');

      let rows;
      try {
        rows = KQL.run(spec.solutionQuery, TABLES, { now: ds.NOW });
      } catch (e) {
        throw new Error('Claude\'s solution query did not run: ' + e.message);
      }
      const flat = flattenRows(rows);
      let facts = Array.isArray(spec.keyFacts) ? spec.keyFacts.filter(f => typeof f === 'string' && flat.some(v => v.includes(f.toLowerCase()))) : [];
      if (!facts.length) {
        // fall back to picking distinctive real values straight out of the verified result
        const informative = flat.filter(v => v.length >= 3 && v.length <= 60 && !/^\d{4}-\d{2}-\d{2}t/.test(v));
        facts = [...new Set(informative)].slice(0, 3);
      }
      if (!facts.length) throw new Error('Claude\'s query ran but returned nothing to check against — try again.');

      const id = 'gen-' + Date.now();
      const newScenario = {
        id, level: spec.level && ['Beginner', 'Intermediate', 'Advanced'].includes(spec.level) ? spec.level : 'Intermediate',
        table: 'generated', title: String(spec.title || 'Claude-generated scenario').slice(0, 80),
        prompt: String(spec.prompt || '').slice(0, 600),
        hint: String(spec.hint || 'Think about which table and operator this needs.').slice(0, 300),
        solutionQuery: spec.solutionQuery, facts, generated: true,
      };
      scenarios.push(newScenario);
      renderScenarios();
      selectScenario(newScenario);
      document.getElementById('genModal').hidden = true;
      document.getElementById('genTopic').value = '';
      status.textContent = '';
    } catch (e) {
      status.textContent = 'Could not generate a scenario: ' + e.message;
    } finally {
      document.getElementById('btnGenGo').disabled = false;
    }
  }

  // ---------------- ATT&CK coverage heatmap ----------------
  // MITRE ATT&CK Enterprise v19 (released April 28, 2026) — all 15 tactics, verified directly against
  // attack.mitre.org. v19 split the former "Defense Evasion" tactic into "Stealth" (kept ID TA0005) and
  // a new "Defense Impairment" (TA0112) tactic.
  const TACTICS = ['Reconnaissance', 'Resource Development', 'Initial Access', 'Execution', 'Persistence',
    'Privilege Escalation', 'Stealth', 'Defense Impairment', 'Credential Access', 'Discovery', 'Lateral Movement',
    'Collection', 'Command and Control', 'Exfiltration', 'Impact'];
  // Technique -> tactic(s), each verified individually against its attack.mitre.org technique page.
  // T1078 (Valid Accounts) genuinely maps to four tactics at once — that's not a data-entry accident,
  // it's how MITRE documents it: the same technique can serve initial access, persistence, and priv-esc.
  const TECHNIQUE_TACTIC = {
    'T1566.001': ['Initial Access'],
    'T1033': ['Discovery'],
    'T1110.001': ['Credential Access'],
    'T1078': ['Stealth', 'Persistence', 'Privilege Escalation', 'Initial Access'],
    'T1059.001': ['Execution'],
    'T1486': ['Impact'],
    'T1071.001': ['Command and Control'],
    'T1105': ['Command and Control'],
    'T1003.002': ['Credential Access'],
    'T1021.002': ['Lateral Movement'],
    // Added this round: s23-s27's techniques were never wired into this map, so the coverage heatmap
    // was silently skipping every mission that used them (the lookup returns undefined and the code
    // bails out — see renderCoverage() below). Each mapping re-verified individually against its own
    // attack.mitre.org technique page before being added, same standard as every entry above.
    'T1110.004': ['Credential Access'],
    'T1078.004': ['Stealth', 'Persistence', 'Privilege Escalation', 'Initial Access'],
    'T1528': ['Credential Access'],
    'T1071': ['Command and Control'],
    'T1496': ['Impact'],
    // Added this round: T1027.018 (Obfuscated Files or Information: Invisible Unicode), verified
    // individually against attack.mitre.org/techniques/T1027/018/ — parent T1027 maps to the v19
    // "Stealth" tactic (the renamed former Defense Evasion, see note above TACTICS).
    'T1027.018': ['Stealth'],
    // Added this round for the 3 new real-attack-grounded scenarios (s30-s32) — each individually
    // checked against its own attack.mitre.org technique page:
    // T1621 (Multi-Factor Authentication Request Generation) -> Credential Access.
    // T1110.003 (Password Spraying, a Brute Force sub-technique) -> Credential Access.
    // T1098.001 (Account Manipulation: Additional Cloud Credentials) -> Persistence.
    // T1656 (Impersonation) -> parent tactic is the v19 "Stealth" tactic (the renamed Defense Evasion).
    // T1566.004 (Phishing: Spearphishing Voice) -> Initial Access.
    'T1621': ['Credential Access'],
    'T1110.003': ['Credential Access'],
    'T1098.001': ['Persistence'],
    'T1656': ['Stealth'],
    'T1566.004': ['Initial Access'],
    // Added this round: T1190 (Exploit Public-Facing Application) -> Initial Access, verified individually
    // against attack.mitre.org/techniques/T1190/ (the pre-auth-RCE-against-an-internet-facing-service
    // technique — a better fit for the PaperCut chain than T1210, whose own ATT&CK page scopes it to
    // Lateral Movement, not initial foothold).
    'T1190': ['Initial Access'],
    // Added this round: T1068 (Exploitation for Privilege Escalation) -> Privilege Escalation, verified
    // individually against attack.mitre.org/techniques/T1068/ (fits the ShieldBreak Defender-engine
    // local-privesc zero-day — exploiting a vulnerability in a privileged process to reach SYSTEM).
    'T1068': ['Privilege Escalation'],
    // Added this round: T1036.005 (Masquerading: Match Legitimate Resource Name or Location) ->
    // Stealth, verified individually against attack.mitre.org/techniques/T1036/005/ (fits the
    // REVSTEALER "LockAppHost" module — a malicious process using a real Windows binary's name but
    // not its real filesystem location).
    'T1036.005': ['Stealth'],
    // Added this round: T1219 (Remote Access Tools) -> Command and Control, verified individually
    // against attack.mitre.org/techniques/T1219/ (fits the rogue-ScreenConnect-session VBScript-worm
    // story — a legitimate remote-support tool's own procedure examples on that ATT&CK page name this
    // exact tool, under its former name "ConnectWise Control," being abused for post-compromise C2).
    'T1219': ['Command and Control'],
    // Added this round: T1090.002 (External Proxy) -> Command and Control, verified individually against
    // attack.mitre.org/techniques/T1090/002/ (fits the PREY-0058 stolen-session-replayed-through-a-
    // residential-proxy story; that page's own procedure examples name APT29's documented use of
    // compromised residential endpoints as proxies — the same infrastructure class, not a claim that
    // APT29 is behind this specific campaign).
    'T1090.002': ['Command and Control'],
    // Added this round: T1490 (Inhibit System Recovery) -> Impact, verified individually against
    // attack.mitre.org/techniques/T1490/ (fits the vssadmin.exe shadow-copy-deletion ransomware
    // pre-encryption story — that page's own procedure examples name BlackCat/ALPHV, Conti, and
    // WannaCry all using this exact class of command).
    'T1490': ['Impact'],
    // Added this round: T1053.005 (Scheduled Task/Job: Scheduled Task) -> Execution, Persistence,
    // Privilege Escalation, verified individually against attack.mitre.org/techniques/T1053/005/ (fits
    // the UTA0560 scheduled-task persistence story from Volexity's Chrome/Windows-kernel 0-day-chain
    // report — genuinely new to this range, and genuinely maps to three tactics at once, the same way
    // T1078 above already spans four).
    'T1053.005': ['Execution', 'Persistence', 'Privilege Escalation'],
    // Added this round: T1574.001 (Hijack Execution Flow: DLL, formerly "DLL Search Order Hijacking")
    // -> Stealth, Execution, verified individually against attack.mitre.org/techniques/T1574/001/ (fits
    // the UNC3569/GRAYRABBIT story: a legitimate 7-Zip executable sideloading a malicious 7z.dll placed
    // in the same non-standard folder — that page's own procedure examples name Storm-1811 doing the
    // identical thing with a modified 7zG.exe sideloading a malicious 7z.DLL). Genuinely new to this
    // range (never used in s1-s39), though both tactics it maps to were already lit up by earlier
    // scenarios.
    'T1574.001': ['Stealth', 'Execution'],
    // Added this round: T1003.001 (OS Credential Dumping: LSASS Memory) -> Credential Access, verified
    // individually against attack.mitre.org/techniques/T1003/001/ (fits the Task-Manager-dumps-LSASS
    // story from Prophet Security's quarterly report/BleepingComputer, cross-confirmed by that page's own
    // procedure examples for the Cutting Edge campaign, Magic Hound, and Play ransomware). Genuinely new
    // to this range (never used in s1-s40), though Credential Access was already lit up by earlier
    // scenarios (T1110.001, T1003.002, T1110.004, T1528, T1621, T1110.003), so this doesn't add a new
    // green square to the heatmap — same as T1574.001 above.
    'T1003.001': ['Credential Access'],
    // Added this round: T1562.001 (Impair Defenses: Disable or Modify Tools) -> Defense Impairment,
    // verified individually against attack.mitre.org/techniques/T1562/001/ and against the tactic page
    // itself, attack.mitre.org/tactics/TA0112/ (fits the fake-AI-installer story: PowerShell adding a
    // Windows Defender scan exclusion for the installer's own non-standard folder before it runs).
    // Genuinely new to this range (never used in s1-s41) — and unlike T1574.001/T1003.001 above, this
    // DOES light up a brand-new heatmap square: no earlier mission in this range has touched the
    // "Defense Impairment" tactic (TA0112, MITRE's April 2026 v19 split of the old "Defense Evasion"
    // tactic into "Stealth" and this one) at all.
    'T1562.001': ['Defense Impairment'],
    // Added this round: T1204.004 (User Execution: Malicious Copy and Paste) -> Execution, verified
    // individually against attack.mitre.org/techniques/T1204/004/ (fits the "Operation PasteSwitch"
    // HBO-Max-Reddit-hijack ClickFix story: a victim pastes an attacker's command into the Windows Run
    // dialog believing they're fixing an error or CAPTCHA). That page's own procedure-examples table names
    // Contagious Interview, Havoc, Kali365, Kimsuky, and MuddyWater all using this exact copy-paste
    // technique — none of them is claimed to be behind the HBO Max campaign specifically. Genuinely new to
    // this range (never used in s1-s42), though Execution was already lit up by T1059.001 and T1053.005,
    // so this doesn't add a new green square to the heatmap — same situation as T1574.001/T1003.001 two
    // rounds ago.
    'T1204.004': ['Execution'],
    // Added this round: T1595 (Active Scanning) -> Reconnaissance, verified individually against
    // attack.mitre.org/techniques/T1595/ (fits the SecFlow/"Nie" AI-orchestrated active-scanning story:
    // Hunt.io's own MITRE ATT&CK mapping for the campaign lists T1595 among its techniques). Genuinely
    // new to this range (never used in s1-s43) AND the first mission ever to touch the Reconnaissance
    // tactic (TA0043) — no earlier scenario has used any Reconnaissance-tactic technique, confirmed by
    // checking this table before adding the entry, not assumed. This lights up a brand-new coverage-
    // heatmap square, the same kind of first this range saw for T1562.001/Defense Impairment a few
    // rounds ago.
    'T1595': ['Reconnaissance'],
    // Added this round: T1572 (Protocol Tunneling) -> Command and Control, verified individually
    // against attack.mitre.org/techniques/T1572/ (fits the Microsoft "TerminalFix" campaign's final
    // stage: a real Python runtime used to open a persistent reverse tunnel over port 443). Genuinely
    // new to this range (never used in s1-s44), but Command and Control was already lit up by T1219
    // and T1090.002, so this doesn't add a new green square to the heatmap — the same situation
    // T1574.001/T1003.001/T1204.004 were each in previously.
    'T1572': ['Command and Control'],
    // Added this round: T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys / Startup
    // Folder) -> Persistence, Privilege Escalation, verified individually against
    // attack.mitre.org/techniques/T1547/001/ (fits the Handala/HEAVYGRAM-and-CHOSEN-BRICK story: a
    // reported HKCU\Software\Microsoft\Windows\CurrentVersion\Run key entry launching a dropped file at
    // every logon). Genuinely new to this range (never used in s1-s46) — but both tactics it maps to
    // were already lit up by earlier scenarios (Persistence by T1098.001/T1053.005, Privilege Escalation
    // by T1078/T1078.004/T1068/T1053.005), so this doesn't add a new green square to the heatmap — the
    // same situation T1574.001/T1003.001/T1204.004/T1572 were each in previously.
    'T1547.001': ['Persistence', 'Privilege Escalation'],
    // Added this round for the 5-mission Beginner Fundamentals batch — each individually verified against
    // its own attack.mitre.org technique page before being added, same standard as every entry above.
    // T1566.002 (Phishing: Spearphishing Link) -> Initial Access; genuinely new to this range (T1566.001
    // was already used, in Incident A/alert-a0, but the .002 sub-technique itself was not).
    'T1566.002': ['Initial Access'],
    // T1204.002 (User Execution: Malicious File) -> Execution; genuinely new to this range.
    'T1204.002': ['Execution'],
    // T1189 (Drive-by Compromise) -> Initial Access; genuinely new to this range, but Initial Access was
    // already lit up by T1566.001/T1566.002/T1078/etc., so this doesn't add a new green square to the
    // coverage heatmap. T1110.001 and T1078 (this batch's other two techniques) already existed in this
    // table before this round, so neither is re-added here.
    'T1189': ['Initial Access'],
  };

  function renderCoverage() {
    const content = document.getElementById('coverageContent');
    if (!content) return;
    const tacticInfo = {};
    TACTICS.forEach(t => { tacticInfo[t] = { done: false, open: false, missions: [] }; });
    scenarios.forEach(s => {
      if (!s.mitre) return;
      const m = /^([A-Z0-9.]+)/.exec(s.mitre);
      if (!m) return;
      const tactics = TECHNIQUE_TACTIC[m[1]];
      if (!tactics) return;
      const done = completed.has(s.id);
      tactics.forEach(t => {
        if (!tacticInfo[t]) return;
        tacticInfo[t].missions.push(s.title);
        if (done) tacticInfo[t].done = true; else tacticInfo[t].open = true;
      });
    });
    let html = '<div class="cov-grid">';
    TACTICS.forEach(t => {
      const info = tacticInfo[t];
      const cls = info.done ? 'cov-done' : (info.open ? 'cov-open' : 'cov-none');
      const title = info.missions.length ? (info.missions.length + ' mission(s): ' + info.missions.join(', ')) : 'No mission in this range currently covers this tactic';
      html += '<div class="cov-cell ' + cls + '" title="' + escapeHtml(title) + '">' + escapeHtml(t) + '</div>';
    });
    html += '</div>';
    const doneCount = TACTICS.filter(t => tacticInfo[t].done).length;
    html += '<div class="cov-note">' + doneCount + ' / ' + TACTICS.length + ' tactics covered by a closed mission. ' +
      'Tactic list and technique mappings verified against <a href="https://attack.mitre.org/tactics/enterprise/" target="_blank">MITRE ATT&CK Enterprise (v19)</a> — ' +
      'including the April 2026 split of the former "Defense Evasion" tactic into <a href="https://attack.mitre.org/tactics/TA0005/" target="_blank">Stealth</a> and ' +
      '<a href="https://attack.mitre.org/tactics/TA0112/" target="_blank">Defense Impairment</a>.</div>';
    content.innerHTML = html;
  }
  document.getElementById('btnCoverage').addEventListener('click', () => {
    renderCoverage();
    document.getElementById('coverageModal').hidden = false;
  });
  document.getElementById('btnCloseCoverage').addEventListener('click', () => { document.getElementById('coverageModal').hidden = true; });

  // ---------------- learning matrix: which cyber domain / career discipline / skill each mission builds ----------------
  function renderLearningMatrix() {
    const content = document.getElementById('learningMatrixContent');
    if (!content) return;
    const domains = ALL_DOMAINS.length ? ALL_DOMAINS : [...new Set(scenarios.map(s => s.domain).filter(Boolean))];
    const doneCount = scenarios.filter(s => completed.has(s.id)).length;
    let html = '<div class="matrix-summary">' + doneCount + ' / ' + scenarios.length + ' missions closed, across ' + domains.length + ' domains.</div>';
    domains.forEach(domain => {
      const items = scenarios.filter(s => s.domain === domain);
      if (!items.length) return;
      const domainDone = items.filter(s => completed.has(s.id)).length;
      html += '<div class="matrix-domain-head">' + escapeHtml(domain) + ' — ' + domainDone + '/' + items.length + '</div>';
      html += '<div class="matrix-table-wrap"><table class="matrix-table"><thead><tr><th>Mission</th><th>Discipline</th><th>KQL skills</th><th>Cyber skill</th></tr></thead><tbody>';
      items.forEach(s => {
        const done = completed.has(s.id);
        const kql = (s.teaches || []).map(t => '<span class="matrix-tag">' + escapeHtml(t) + '</span>').join('');
        const cyber = (s.cyberSkills || []).map(t => '<span class="matrix-tag">' + escapeHtml(t) + '</span>').join('');
        html += '<tr class="' + (done ? 'matrix-done' : '') + '"><td>' + (done ? '✓ ' : '') + escapeHtml(s.title) + '</td>' +
          '<td>' + escapeHtml(s.discipline || '—') + '</td><td>' + kql + '</td><td>' + cyber + '</td></tr>';
      });
      html += '</tbody></table></div>';
    });
    content.innerHTML = html;
  }
  const btnLearningMatrix = document.getElementById('btnLearningMatrix');
  if (btnLearningMatrix) {
    btnLearningMatrix.addEventListener('click', () => {
      renderLearningMatrix();
      document.getElementById('learningMatrixModal').hidden = false;
    });
    document.getElementById('btnCloseLearningMatrix').addEventListener('click', () => { document.getElementById('learningMatrixModal').hidden = true; });
  }

  // ---------------- learning paths: curated, ordered mission sequences ----------------
  // Progress is derived on the fly from the existing `completed` Set — no new localStorage key needed.
  // Two paths intentionally fold in the automated-scheduled-task scenarios (s28 cryptomining, s29
  // invisible-Unicode phishing) as later missions in an existing sequence, ahead of that discipline's
  // pre-existing capstone (s19), rather than getting their own path.
  const LEARNING_PATHS = [
    {
      id: 'soc-tier1',
      icon: '🛡️',
      name: 'SOC Tier 1: First Line',
      description: 'Triage the first alert: recognize the obvious red flags across identity, endpoint, and email.',
      scenarioIds: ['s1', 's9', 's2', 's3', 's4', 's48', 's49', 's50', 's51', 's52', 's23', 's30', 's32'],
    },
    {
      id: 'soc-tier2',
      icon: '🔎',
      name: 'SOC Tier 2: Escalation Ready',
      description: 'Go past the first signal — chain evidence, spot living-off-the-land techniques, and separate signal from noise.',
      scenarioIds: ['s5', 's6', 's7', 's22', 's8', 's21', 's24', 's26'],
    },
    {
      id: 'soc-tier3',
      icon: '📋',
      name: 'SOC Tier 3: Incident Owner',
      description: 'Own a case end to end: work alert evidence, prove containment, and run a full multi-step investigation.',
      scenarioIds: ['s17', 's18', 's20', 's25', 's27', 's31'],
    },
    {
      id: 'threat-hunting',
      icon: '🏹',
      name: 'Threat Hunting',
      description: 'Hunt without a ready-made alert: beacons, lateral movement, and statistical anomaly detection.',
      scenarioIds: ['s10', 's11', 's12', 's13', 's15', 's16', 's28', 's19'],
    },
    {
      id: 'detection-engineering',
      icon: '⚙️',
      name: 'Detection Engineering',
      description: 'Write detections that generalize — precise enough to skip the noise, broad enough to catch the real thing.',
      scenarioIds: ['s14', 's6', 's7', 's22', 's13', 's29', 's19'],
    },
  ];

  function pathProgress(path) {
    const ids = path.scenarioIds;
    const doneCount = ids.filter(id => completed.has(id)).length;
    return { doneCount, total: ids.length, complete: doneCount >= ids.length && ids.length > 0 };
  }

  function renderLearningPaths() {
    const content = document.getElementById('learningPathsContent');
    if (!content) return;
    let html = '';
    LEARNING_PATHS.forEach(path => {
      const prog = pathProgress(path);
      const pct = prog.total > 0 ? Math.round((prog.doneCount / prog.total) * 100) : 0;
      html += '<div class="path-card' + (prog.complete ? ' path-complete' : '') + '" data-path="' + path.id + '">' +
        '<div class="path-head"><span class="path-name">' + path.icon + ' ' + escapeHtml(path.name) + '</span>' +
        (prog.complete ? '<span class="path-badge-earned">✓ Complete</span>' : '') + '</div>' +
        '<div class="path-desc">' + escapeHtml(path.description) + '</div>' +
        '<div class="path-progress-track"><div class="path-progress-fill" style="width:' + pct + '%"></div></div>' +
        '<div class="path-progress-label">' + prog.doneCount + ' / ' + prog.total + '</div>' +
        '<div class="path-missions">';
      let nextMarked = false;
      path.scenarioIds.forEach((id, i) => {
        const s = scenarios.find(x => x.id === id);
        if (!s) return;
        const done = completed.has(id);
        const isNext = !done && !nextMarked;
        if (isNext) nextMarked = true;
        html += '<div class="path-mission-row' + (done ? ' path-mission-done' : '') + (isNext ? ' path-mission-next' : '') + '" data-scn-id="' + id + '">' +
          '<span class="path-step-num">' + (done ? '✓' : (i + 1)) + '</span>' +
          '<span>' + escapeHtml(s.title) + '</span></div>';
      });
      html += '</div></div>';
    });
    content.innerHTML = html;
    content.querySelectorAll('.path-mission-row').forEach(el => {
      el.addEventListener('click', () => {
        const s = scenarios.find(x => x.id === el.dataset.scnId);
        if (!s) return;
        document.getElementById('learningPathsModal').hidden = true;
        selectScenario(s);
      });
    });
  }
  const btnLearningPaths = document.getElementById('btnLearningPaths');
  if (btnLearningPaths) {
    btnLearningPaths.addEventListener('click', () => {
      renderLearningPaths();
      document.getElementById('learningPathsModal').hidden = false;
    });
    const btnCloseLearningPaths = document.getElementById('btnCloseLearningPaths');
    if (btnCloseLearningPaths) {
      btnCloseLearningPaths.addEventListener('click', () => { document.getElementById('learningPathsModal').hidden = true; });
    }
  }

  // ---------------- detection-engineering mode ----------------
  // Ground-truth timestamps live in the dataset (ds.GROUND_TRUTH), derived arithmetically from the same
  // incident-anchor timestamps used to generate the events themselves — never exposed as a queryable column.
  const DETECTION_TARGETS = [
    {
      id: 'officeToPowerShell',
      title: 'Detect: Office app spawning PowerShell',
      sub: 'DeviceProcessEvents · parent/child process relationship',
      briefing: 'Write a detection meant to run continuously against DeviceProcessEvents: flag any process where an Office application (winword.exe / excel.exe / powerpnt.exe) is the parent of powershell.exe. It should catch the real malicious launch on FAB-FIN-07 without you having hand-picked that device or account — a detection has to generalize.',
      starter: 'DeviceProcessEvents\n| where FileName == "powershell.exe"\n| where ',
    },
    {
      id: 'credentialDumpRegistry',
      title: 'Detect: credential-dumping registry hive export',
      sub: 'DeviceProcessEvents · T1003.002 OS Credential Dumping (SAM)',
      briefing: 'Write a detection for reg.exe saving the SAM or SYSTEM registry hives on FAB-IT-01 — the pattern behind T1003.002. Watch out: a legitimate nightly backup job on the same box also runs reg.exe save, against a different hive (Veeam). A detection that fires on any reg.exe save at all will false-positive on that backup every night.',
      starter: 'DeviceProcessEvents\n| where FileName == "reg.exe"\n| where ',
    },
  ];

  function initDetectionLab() {
    const content = document.getElementById('detectionContent');
    if (!content) return;
    function renderTargetList() {
      let html = '';
      DETECTION_TARGETS.forEach(t => {
        html += '<div class="det-item" data-id="' + t.id + '"><div class="det-item-title">' + escapeHtml(t.title) +
          '</div><div class="det-item-sub">' + escapeHtml(t.sub) + '</div></div>';
      });
      content.innerHTML = html;
      content.querySelectorAll('.det-item').forEach(el => {
        el.addEventListener('click', () => renderTargetBriefing(DETECTION_TARGETS.find(t => t.id === el.dataset.id)));
      });
    }
    function renderTargetBriefing(target) {
      content.innerHTML =
        '<button class="linkbtn" id="btnDetBack">‹ Back to targets</button>' +
        '<h3 style="margin-top:8px">' + escapeHtml(target.title) + '</h3>' +
        '<p>' + escapeHtml(target.briefing) + '</p>' +
        '<textarea class="det-editor" id="detEditor">' + escapeHtml(target.starter) + '</textarea>' +
        '<div class="modal-actions" style="margin-top:10px;justify-content:flex-start">' +
        '<button class="iconbtn primary" id="btnTestDetection">Test detection</button></div>' +
        '<div id="detResult"></div>';
      document.getElementById('btnDetBack').addEventListener('click', renderTargetList);
      document.getElementById('btnTestDetection').addEventListener('click', () => runDetectionTest(target));
    }
    function runDetectionTest(target) {
      const resultEl = document.getElementById('detResult');
      const qText = document.getElementById('detEditor').value;
      let rows;
      try {
        rows = KQL.run(qText, TABLES, { now: ds.NOW });
      } catch (e) {
        resultEl.innerHTML = '<div class="det-err">' + escapeHtml(e.message || String(e)) + '</div>';
        return;
      }
      if (rows.length && !('Timestamp' in rows[0])) {
        resultEl.innerHTML = '<div class="det-err">Your result set has no Timestamp column — a detection needs to keep it (via project/extend) so it can be matched against when the real activity happened.</div>';
        return;
      }
      const gt = ds.GROUND_TRUTH[target.id];
      const truthSet = new Set(gt.ts);
      const resultTsSet = new Set(rows.map(r => new Date(r.Timestamp).getTime()).filter(t => !Number.isNaN(t)));
      let tp = 0;
      truthSet.forEach(t => { if (resultTsSet.has(t)) tp++; });
      const fn = truthSet.size - tp;
      const fp = resultTsSet.size - tp;
      const precision = (tp + fp) > 0 ? (tp / (tp + fp)) : (tp === 0 ? 1 : 0);
      const recall = truthSet.size > 0 ? (tp / truthSet.size) : 1;
      const perfect = fp === 0 && fn === 0 && truthSet.size > 0;
      if (perfect) {
        try { localStorage.setItem('kqlrange.detectionAce', 'true'); } catch (e) { /* ignore */ }
        checkBadges();
      }
      resultEl.innerHTML =
        '<div class="det-score-row">' +
        '<div class="det-score"><b>' + tp + '</b><span>True positive</span></div>' +
        '<div class="det-score"><b>' + fp + '</b><span>False positive</span></div>' +
        '<div class="det-score"><b>' + fn + '</b><span>Missed</span></div>' +
        '<div class="det-score"><b>' + Math.round(precision * 100) + '%</b><span>Precision</span></div>' +
        '<div class="det-score"><b>' + Math.round(recall * 100) + '%</b><span>Recall</span></div>' +
        '</div>' +
        '<div class="det-verdict ' + (perfect ? 'good' : 'bad') + '">' +
        (perfect
          ? '✓ Textbook detection — caught every real hit, raised nothing else.'
          : (fp > 0 && fn > 0
            ? 'Too broad in some ways, too narrow in others — missing ' + fn + ' real event(s) and still raising ' + fp + ' that aren\'t the real pattern.'
            : (fp > 0
              ? 'Catches the real activity, but also flags ' + fp + ' event(s) that aren\'t actually the pattern — that\'s alert fatigue for whoever\'s on shift. Tighten the filter.'
              : 'Precise, but missing ' + fn + ' real event(s) — the filter is too narrow. Loosen it without losing the precision.'))) +
        '</div>';
    }
    document.getElementById('btnDetectionLab').addEventListener('click', () => {
      renderTargetList();
      document.getElementById('detectionModal').hidden = false;
    });
    document.getElementById('btnCloseDetectionLab').addEventListener('click', () => { document.getElementById('detectionModal').hidden = true; });
  }
  initDetectionLab();

  // ---------------- achievement badges ----------------
  const BADGES = [
    { id: 'first-blood', icon: '🩸', name: 'First Blood', desc: 'Close your first mission.', check: st => st.completedCount >= 1 },
    { id: 'beginner-sweep', icon: '🌱', name: 'Fresh Eyes', desc: 'Complete every Beginner mission.', check: st => st.levelDone.Beginner },
    { id: 'intermediate-sweep', icon: '🔍', name: 'Getting Warmer', desc: 'Complete every Intermediate mission.', check: st => st.levelDone.Intermediate },
    { id: 'advanced-sweep', icon: '🧠', name: 'Advanced Practitioner', desc: 'Complete every Advanced mission.', check: st => st.levelDone.Advanced },
    { id: 'expert-sweep', icon: '🏆', name: 'Expert Tier', desc: 'Complete every Expert mission.', check: st => st.levelDone.Expert },
    { id: 'range-complete', icon: '🎓', name: 'Range Complete', desc: 'Complete every mission in the range.', check: st => st.totalCount > 0 && st.completedCount >= st.totalCount },
    { id: 'full-coverage', icon: '🗺️', name: 'Full ATT&CK Coverage', desc: 'Light up all 15 tactics on the coverage heatmap.', check: st => st.coverageDoneCount >= 15 },
    { id: 'not-fooled', icon: '🕵️', name: 'Not Fooled', desc: 'Correctly call a False Positive or Benign Positive disposition.', check: st => st.notFooled },
    { id: 'detection-ace', icon: '🎯', name: 'Detection Ace', desc: 'Score 100% precision and 100% recall in the Detection Lab.', check: st => st.detectionAce },
    { id: 'quick-draw', icon: '⚡', name: 'Quick Draw', desc: 'Get 5 answer boxes right on the first try.', check: st => st.firstTryCount >= 5 },
    { id: 'path-soc-tier1', icon: '🛡️', name: 'First Line', desc: 'Complete the SOC Tier 1 learning path.', check: st => st.pathDone['soc-tier1'] },
    { id: 'path-soc-tier2', icon: '🔎', name: 'Escalation Ready', desc: 'Complete the SOC Tier 2 learning path.', check: st => st.pathDone['soc-tier2'] },
    { id: 'path-soc-tier3', icon: '📋', name: 'Incident Owner', desc: 'Complete the SOC Tier 3 learning path.', check: st => st.pathDone['soc-tier3'] },
    { id: 'path-threat-hunting', icon: '🏹', name: 'Hunter', desc: 'Complete the Threat Hunting learning path.', check: st => st.pathDone['threat-hunting'] },
    { id: 'path-detection-engineering', icon: '⚙️', name: 'Rule Writer', desc: 'Complete the Detection Engineering learning path.', check: st => st.pathDone['detection-engineering'] },
  ];

  function buildBadgeState() {
    const levels = ['Beginner', 'Intermediate', 'Advanced', 'Expert'];
    const levelDone = {};
    levels.forEach(l => {
      const items = scenarios.filter(s => !s.generated && s.level === l);
      levelDone[l] = items.length > 0 && items.every(s => completed.has(s.id));
    });
    const tacticHit = {};
    TACTICS.forEach(t => { tacticHit[t] = false; });
    scenarios.forEach(s => {
      if (!s.mitre || !completed.has(s.id)) return;
      const m = /^([A-Z0-9.]+)/.exec(s.mitre);
      const tactics = m && TECHNIQUE_TACTIC[m[1]];
      if (!tactics) return;
      tactics.forEach(t => { if (t in tacticHit) tacticHit[t] = true; });
    });
    const coverageDoneCount = Object.values(tacticHit).filter(Boolean).length;
    let notFooled = false, detectionAce = false, firstTryCount = 0;
    try { notFooled = localStorage.getItem('kqlrange.notFooled') === 'true'; } catch (e) { /* ignore */ }
    try { detectionAce = localStorage.getItem('kqlrange.detectionAce') === 'true'; } catch (e) { /* ignore */ }
    try { firstTryCount = JSON.parse(localStorage.getItem('kqlrange.firstTryCorrect') || '[]').length; } catch (e) { /* ignore */ }
    const pathDone = {};
    LEARNING_PATHS.forEach(p => { pathDone[p.id] = pathProgress(p).complete; });
    return {
      completedCount: completed.size,
      totalCount: scenarios.filter(s => !s.generated).length,
      levelDone, coverageDoneCount, notFooled, detectionAce, firstTryCount, pathDone,
    };
  }

  function loadEarnedBadges() {
    try { return new Set(JSON.parse(localStorage.getItem('kqlrange.badges') || '[]')); } catch (e) { return new Set(); }
  }
  function checkBadges() {
    const state = buildBadgeState();
    const earned = loadEarnedBadges();
    const newlyEarned = [];
    BADGES.forEach(b => {
      if (!earned.has(b.id) && b.check(state)) { earned.add(b.id); newlyEarned.push(b); }
    });
    if (newlyEarned.length) {
      try { localStorage.setItem('kqlrange.badges', JSON.stringify([...earned])); } catch (e) { /* ignore */ }
      newlyEarned.forEach(b => showBadgeToast(b));
    }
    return earned;
  }
  function showBadgeToast(b) {
    const wrap = document.getElementById('peerToastWrap');
    if (!wrap) return;
    const el = document.createElement('div');
    el.className = 'peer-toast badge-toast';
    el.innerHTML =
      '<div class="avatar badge-avatar">' + b.icon + '</div>' +
      '<div class="body">' +
      '<div class="who">Badge unlocked!</div>' +
      '<div class="msg"><b>' + escapeHtml(b.name) + '</b> — ' + escapeHtml(b.desc) + '</div>' +
      '</div><button class="close" aria-label="Dismiss">×</button>';
    const closeBtn = el.querySelector('.close');
    function dismiss() { el.classList.add('closing'); setTimeout(() => el.remove(), 200); }
    closeBtn.addEventListener('click', dismiss);
    wrap.appendChild(el);
    setTimeout(dismiss, 6000);
    while (wrap.children.length > 3) wrap.removeChild(wrap.firstChild);
  }
  function renderBadgesModal() {
    const content = document.getElementById('badgesContent');
    if (!content) return;
    const earned = loadEarnedBadges();
    let html = '<div class="badge-grid">';
    BADGES.forEach(b => {
      const got = earned.has(b.id);
      html += '<div class="badge-cell' + (got ? ' badge-got' : '') + '">' +
        '<div class="badge-icon">' + (got ? b.icon : '🔒') + '</div>' +
        '<div class="badge-name">' + escapeHtml(b.name) + '</div>' +
        '<div class="badge-desc">' + escapeHtml(b.desc) + '</div>' +
        '</div>';
    });
    html += '</div><div class="badge-progress">' + earned.size + ' / ' + BADGES.length + ' badges earned</div>';
    content.innerHTML = html;
  }
  const btnBadges = document.getElementById('btnBadges');
  if (btnBadges) {
    btnBadges.addEventListener('click', () => {
      renderBadgesModal();
      document.getElementById('badgesModal').hidden = false;
    });
    document.getElementById('btnCloseBadges').addEventListener('click', () => { document.getElementById('badgesModal').hidden = true; });
  }

  // ---------------- initial render ----------------
  renderSchema();
  renderScenarios();
  checkBadges();
})();

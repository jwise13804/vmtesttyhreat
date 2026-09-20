// KQL practice engine — a hand-written subset interpreter of Kusto Query Language.
// Supports: let, where, project/project-away/project-keep/project-rename/project-reorder,
// extend, summarize ... by ..., make-series ... on ... from/to/step [by ...], sort by/order by,
// top N by, take/limit, distinct, count,
// join (kind=inner/innerunique/leftouter/rightouter/fullouter/leftsemi/rightsemi/leftanti/rightanti),
// union, render (acknowledged, not visualized).
// Scalar language: comparisons (==, !=, =~, !~, <, <=, >, >=), string ops (contains, !contains,
// contains_cs, !contains_cs, has, !has, has_cs, !has_cs, has_any, has_all, startswith[_cs], endswith[_cs],
// in, in~, !in, !in~, matches regex), and/or/not, arithmetic (+ - * / %), function calls.
// Functions: ago, now, datetime, bin, strcat, tostring, toint, tolong, todouble, toreal, tobool,
// strlen, substring, indexof, split, tolower, toupper, isempty, isnotempty, isnull, isnotnull, case, iif/iff,
// coalesce, series_decompose_anomalies (simplified — see its implementation comment).
// Aggregations (inside summarize/make-series): count, countif, dcount, dcountif, sum, sumif, avg, avgif,
// max, maxif, min, minif, make_set, make_list, arg_max, arg_min.
(function (root) {
  'use strict';

  // ---------- Tokenizer ----------
  const TIMESPAN_RE = /^(\d+(?:\.\d+)?)(ms|s|m|h|d|microsecond|tick)$/;

  function tokenize(src) {
    const tokens = [];
    let i = 0;
    const n = src.length;
    while (i < n) {
      const c = src[i];
      if (c === ' ' || c === '\t' || c === '\r' || c === '\n') { i++; continue; }
      if (c === '/' && src[i + 1] === '/') { while (i < n && src[i] !== '\n') i++; continue; }
      if (c === '"' || c === "'") {
        const quote = c; let j = i + 1; let s = '';
        while (j < n && src[j] !== quote) {
          if (src[j] === '\\' && j + 1 < n) { s += unescapeChar(src[j + 1]); j += 2; }
          else { s += src[j]; j++; }
        }
        tokens.push({ type: 'string', value: s, pos: i });
        i = j + 1;
        continue;
      }
      if (/[0-9]/.test(c)) {
        let j = i; while (j < n && /[0-9.]/.test(src[j])) j++;
        let numStr = src.slice(i, j);
        // check for adjacent unit suffix forming a timespan literal (no whitespace)
        let k = j;
        while (k < n && /[a-zA-Z]/.test(src[k])) k++;
        const maybeUnit = src.slice(j, k);
        const combo = numStr + maybeUnit;
        const m = combo.match(TIMESPAN_RE);
        if (m && maybeUnit.length > 0) {
          tokens.push({ type: 'timespan', value: timespanToMs(parseFloat(m[1]), m[2]), pos: i });
          i = k;
        } else {
          tokens.push({ type: 'number', value: parseFloat(numStr), pos: i });
          i = j;
        }
        continue;
      }
      if (/[A-Za-z_$]/.test(c)) {
        let j = i; while (j < n && /[A-Za-z0-9_]/.test(src[j])) j++;
        let word = src.slice(i, j);
        // allow hyphenated keywords like project-away, project-rename, project-keep, project-reorder
        while (src[j] === '-' && /[A-Za-z]/.test(src[j + 1] || '')) {
          let k = j + 1; while (k < n && /[A-Za-z0-9_]/.test(src[k])) k++;
          word += src.slice(j, k); j = k;
        }
        // datetime(2024-01-15 10:30:00) / datetime(2015-12-31 23:59:59.9) — Microsoft's own canonical
        // datetime-literal syntax example is exactly this unquoted "date space time" form, but the
        // general expression grammar has no ':' operator to parse the time part with, and would
        // otherwise fail with a confusing "expected ')'" error on syntax straight out of the docs.
        // Special-case it at the tokenizer level: read the raw text up to the matching ')' and, if it
        // isn't already a quoted string or the `null` keyword (datetime(null) stays handled the normal
        // way), emit it as a single string token — same as if the user had written it quoted.
        if (word === 'datetime') {
          let k = j; while (k < n && (src[k] === ' ' || src[k] === '\t')) k++;
          if (src[k] === '(') {
            let depth = 1; let m = k + 1;
            while (m < n && depth > 0) { if (src[m] === '(') depth++; else if (src[m] === ')') depth--; if (depth > 0) m++; }
            if (depth === 0) {
              const raw = src.slice(k + 1, m).trim();
              if (raw && !/^["']/.test(raw) && !/^null$/i.test(raw) && /^[0-9][0-9:./TZ+\- ]*$/.test(raw)) {
                tokens.push({ type: 'ident', value: word, pos: i });
                tokens.push({ type: 'op', value: '(', pos: k });
                tokens.push({ type: 'string', value: raw, pos: k + 1 });
                tokens.push({ type: 'op', value: ')', pos: m });
                i = m + 1;
                continue;
              }
            }
          }
        }
        tokens.push({ type: 'ident', value: word, pos: i });
        i = j;
        continue;
      }
      // multi-char operators
      const two = src.slice(i, i + 2);
      if (['==', '!=', '<=', '>=', '=~', '!~'].includes(two)) { tokens.push({ type: 'op', value: two, pos: i }); i += 2; continue; }
      if ('()[]{},.;|=<>+-*/%!'.includes(c)) { tokens.push({ type: 'op', value: c, pos: i }); i++; continue; }
      // unknown char, skip
      i++;
    }
    tokens.push({ type: 'eof', value: null, pos: n });
    return tokens;
  }

  function unescapeChar(c) {
    if (c === 'n') return '\n';
    if (c === 't') return '\t';
    if (c === '\\') return '\\';
    if (c === '"') return '"';
    if (c === "'") return "'";
    return c;
  }

  function timespanToMs(num, unit) {
    switch (unit) {
      case 'ms': return num;
      case 's': return num * 1000;
      case 'm': return num * 60000;
      case 'h': return num * 3600000;
      case 'd': return num * 86400000;
      case 'tick': return num / 10000; // 1 tick = 100ns
      default: return num;
    }
  }

  // ---------- Parser ----------
  const STRING_OPS = new Set(['contains', 'contains_cs', 'has', 'has_cs', 'has_any', 'has_all', 'startswith', 'startswith_cs',
    'endswith', 'endswith_cs', 'in', 'in~', 'matches']);

  class Parser {
    constructor(tokens, src) { this.t = tokens; this.p = 0; this.src = src; }
    peek(o) {
      const idx = this.p + (o || 0);
      // clamp out-of-bounds lookahead to the trailing eof token so callers never dereference undefined
      return idx < this.t.length ? this.t[idx] : this.t[this.t.length - 1];
    }
    next() { return this.t[this.p++]; }
    isOp(v) { const tk = this.peek(); return tk.type === 'op' && tk.value === v; }
    isIdent(v) { const tk = this.peek(); return tk.type === 'ident' && tk.value.toLowerCase() === v; }
    expectOp(v) { if (!this.isOp(v)) this.err(`expected '${v}'`); return this.next(); }
    err(msg) {
      const tk = this.peek();
      throw new KqlError(`${msg} near position ${tk.pos} (found ${tk.type} ${JSON.stringify(tk.value)})`);
    }

    parseProgram() {
      const lets = [];
      while (this.isIdent('let')) {
        this.next();
        const nameTok = this.next();
        if (nameTok.type !== 'ident') this.err('expected identifier after let');
        this.expectOp('=');
        // could be tabular or scalar. Try tabular if next token looks like a table/ident followed by '|' eventually,
        // otherwise treat as scalar expression. We detect by parsing a "value" that may itself contain pipes.
        const value = this.parseLetValue();
        if (!this.isOp(';')) this.err("expected ';' after let statement");
        this.next();
        lets.push({ name: nameTok.value, value });
      }
      const query = this.parseTabularExpr();
      // Guard against silently-dropped trailing input, e.g. a clause typed without its
      // leading '|' ("T\nwhere x" or "T | where x\ntake 5") — without this check the
      // parser just stops and returns whatever it already built, which quietly runs a
      // different (wrong) query instead of failing.
      if (this.peek().type !== 'eof') {
        const tk = this.peek();
        if (tk.type === 'ident') {
          throw new KqlError(`Missing '|' before '${tk.value}' near position ${tk.pos}. Every operator after the table name must be introduced with a pipe, e.g. "| ${tk.value} ...".`);
        }
        throw new KqlError(`Unexpected input near position ${tk.pos} (found ${tk.type} ${JSON.stringify(tk.value)}) — did you forget a '|'?`);
      }
      return { lets, query };
    }

    parseLetValue() {
      // Heuristic: if it starts with an identifier that is a known-shape table/pipe expr, parse as tabular.
      // We parse a scalar expression first; if a '|' follows at the top level, convert to tabular by continuing.
      const startP = this.p;
      // Try tabular: identifier (table or previous let ref) then '|' ...
      if (this.peek().type === 'ident' && this.peek(1).type === 'op' && this.peek(1).value === '|') {
        return { kind: 'tabular', expr: this.parseTabularExpr() };
      }
      // scalar
      const expr = this.parseExpr();
      return { kind: 'scalar', expr };
    }

    parseTabularExpr() {
      const sourceTok = this.next();
      if (sourceTok.type !== 'ident') this.err('expected table name');
      const ops = [];
      let source = { type: 'TableRef', name: sourceTok.value };
      while (this.isOp('|')) {
        this.next();
        ops.push(this.parseOperator());
      }
      return { source, ops };
    }

    parseOperator() {
      const kwTok = this.next();
      if (kwTok.type !== 'ident') this.err('expected operator keyword after |');
      const kw = kwTok.value.toLowerCase();
      switch (kw) {
        case 'where': case 'filter':
          return { op: 'where', pred: this.parseExpr() };
        case 'project':
          return { op: 'project', items: this.parseAssignList() };
        case 'extend':
          return { op: 'extend', items: this.parseAssignList() };
        case 'project-away':
          return { op: 'project-away', names: this.parseIdentList() };
        case 'project-keep':
          return { op: 'project-keep', names: this.parseIdentList() };
        case 'project-rename':
          return { op: 'project-rename', items: this.parseAssignList() };
        case 'project-reorder':
          return { op: 'project-reorder', names: this.parseIdentListWithModifiers() };
        case 'summarize':
          return this.parseSummarize();
        case 'make-series': case 'make_series':
          return this.parseMakeSeries();
        case 'sort': case 'order':
          this.expectIdent('by');
          return { op: 'sort', items: this.parseSortList() };
        case 'top':
          return this.parseTop();
        case 'take': case 'limit':
          return { op: 'take', n: this.parseExpr() };
        case 'distinct':
          if (this.isOp('*')) { this.next(); return { op: 'distinct', names: null }; }
          return { op: 'distinct', names: this.parseIdentList() };
        case 'count':
          return { op: 'count' };
        case 'join':
          return this.parseJoin();
        case 'union':
          return { op: 'union', tables: this.parseUnionList() };
        case 'render':
          { const t = this.next(); return { op: 'render', chart: t.value }; }
        case 'mv-expand':
          this.err("'mv-expand' isn't supported by this practice engine yet");
          break;
        case 'parse':
          this.err("'parse' isn't supported by this practice engine yet");
          break;
        default:
          this.err(`unsupported or unknown operator '${kwTok.value}'`);
      }
    }

    expectIdent(v) { if (!this.isIdent(v)) this.err(`expected '${v}'`); this.next(); }

    parseIdentList() {
      const names = [];
      names.push(this.next().value);
      while (this.isOp(',')) { this.next(); names.push(this.next().value); }
      return names;
    }

    parseIdentListWithModifiers() {
      // project-reorder allows trailing asc/desc/Col* wildcards; we only keep plain names for simplicity
      const names = [];
      const readOne = () => {
        const tok = this.next();
        let name = tok.value;
        if (this.isOp('*')) { this.next(); name += '*'; }
        if (this.isIdent('asc') || this.isIdent('desc')) this.next();
        names.push(name);
      };
      readOne();
      while (this.isOp(',')) { this.next(); readOne(); }
      return names;
    }

    parseAssignList() {
      const items = [];
      items.push(this.parseAssign());
      while (this.isOp(',')) { this.next(); items.push(this.parseAssign()); }
      return items;
    }

    parseAssign() {
      // Name = Expr  |  Expr  (name inferred)
      if (this.peek().type === 'ident' && this.peek(1).type === 'op' && this.peek(1).value === '=' &&
          !(this.peek(2).type === 'op' && this.peek(2).value === '=')) {
        const name = this.next().value;
        this.next(); // '='
        const expr = this.parseExpr();
        return { name, expr };
      }
      const expr = this.parseExpr();
      return { name: exprToName(expr), expr };
    }

    parseSortList() {
      const items = [];
      const readOne = () => {
        const expr = this.parseExpr();
        let dir = 'desc';
        if (this.isIdent('asc')) { this.next(); dir = 'asc'; }
        else if (this.isIdent('desc')) { this.next(); dir = 'desc'; }
        let nulls = null;
        if (this.isIdent('nulls')) { this.next(); nulls = this.isIdent('first') ? 'first' : 'last'; this.next(); }
        items.push({ expr, dir, nulls });
      };
      readOne();
      while (this.isOp(',')) { this.next(); readOne(); }
      return items;
    }

    parseTop() {
      const nExpr = this.parseExpr();
      this.expectIdent('by');
      const items = this.parseSortList();
      return { op: 'top', n: nExpr, items };
    }

    parseSummarize() {
      let aggs = [];
      if (!this.isIdent('by')) {
        aggs.push(this.parseAssign());
        while (this.isOp(',')) { this.next(); aggs.push(this.parseAssign()); }
      }
      let by = [];
      if (this.isIdent('by')) {
        this.next();
        by.push(this.parseAssign());
        while (this.isOp(',')) { this.next(); by.push(this.parseAssign()); }
      }
      return { op: 'summarize', aggs, by };
    }

    // make-series [Col =] Agg() [, ...] on AxisCol [from start] [to end] step step [by [Col =] Expr [, ...]]
    // https://learn.microsoft.com/en-us/kusto/query/make-series-operator
    parseMakeSeries() {
      const aggs = [];
      aggs.push(this.parseAssign());
      while (this.isOp(',')) { this.next(); aggs.push(this.parseAssign()); }
      this.expectIdent('on');
      const axis = this.parseExpr();
      let from = null, to = null;
      if (this.isIdent('from')) { this.next(); from = this.parseExpr(); }
      if (this.isIdent('to')) { this.next(); to = this.parseExpr(); }
      this.expectIdent('step');
      const step = this.parseExpr();
      let by = [];
      if (this.isIdent('by')) {
        this.next();
        by.push(this.parseAssign());
        while (this.isOp(',')) { this.next(); by.push(this.parseAssign()); }
      }
      return { op: 'make-series', aggs, axis, from, to, step, by };
    }

    parseJoin() {
      let kind = 'innerunique';
      if (this.isIdent('kind')) {
        this.next(); this.expectOp('=');
        kind = this.next().value.toLowerCase();
      }
      this.expectOp('(');
      const right = this.parseTabularExpr();
      this.expectOp(')');
      this.expectIdent('on');
      const conds = [];
      const readCond = () => {
        // $left.Col == $right.Col  OR  Col  OR  $left.A == $right.B
        const leftExpr = this.parsePrimaryPath();
        if (this.isOp('==')) {
          this.next();
          const rightExpr = this.parsePrimaryPath();
          conds.push({ left: leftExpr, right: rightExpr });
        } else {
          conds.push({ left: leftExpr, right: leftExpr, sameName: true });
        }
      };
      readCond();
      while (this.isOp(',') || this.isIdent('and')) { this.next(); readCond(); }
      return { op: 'join', kind, right, conds };
    }

    parsePrimaryPath() {
      // supports $left.Col / $right.Col / Col
      let tok = this.next();
      let base = tok.value;
      if (this.isOp('.')) {
        this.next();
        const field = this.next().value;
        return { side: base, name: field };
      }
      return { side: null, name: base };
    }

    parseUnionList() {
      const names = [];
      names.push(this.next().value);
      while (this.isOp(',')) { this.next(); names.push(this.next().value); }
      return names;
    }

    // ---------- Expressions (Pratt-ish recursive descent) ----------
    parseExpr() { return this.parseOr(); }

    parseOr() {
      let left = this.parseAnd();
      while (this.isIdent('or')) { this.next(); const right = this.parseAnd(); left = { type: 'or', left, right }; }
      return left;
    }
    parseAnd() {
      let left = this.parseNot();
      while (this.isIdent('and')) { this.next(); const right = this.parseNot(); left = { type: 'and', left, right }; }
      return left;
    }
    parseNot() {
      if (this.isIdent('not')) { this.next(); return { type: 'not', expr: this.parseNot() }; }
      return this.parseComparison();
    }
    parseComparison() {
      let left = this.parseAdd();
      const tk = this.peek();
      // between
      if (tk.type === 'ident' && tk.value.toLowerCase() === 'between') {
        this.next(); this.expectOp('(');
        const lo = this.parseAdd(); this.expectIdent2dot();
        const hi = this.parseAdd(); this.expectOp(')');
        return { type: 'between', target: left, lo, hi };
      }
      let neg = false;
      if (tk.type === 'op' && tk.value === '!') {
        // lookahead: !contains, !has, !startswith, !endswith, !in  -> tokenized as op '!' followed by ident
        const nxt = this.peek(1);
        if (nxt.type === 'ident' && STRING_OPS.has(nxt.value.toLowerCase())) { neg = true; this.next(); }
      }
      const opTok = this.peek();
      if (opTok.type === 'op' && ['==', '!=', '=~', '!~', '<', '<=', '>', '>='].includes(opTok.value)) {
        this.next();
        const right = this.parseAdd();
        return { type: 'cmp', op: opTok.value, left, right };
      }
      if (opTok.type === 'ident' && (STRING_OPS.has(opTok.value.toLowerCase()) || opTok.value.toLowerCase() === '!in')) {
        let name = this.next().value.toLowerCase();
        if (name === 'matches') { this.expectIdent('regex'); const right = this.parseAdd(); return { type: 'matches', left, right, neg }; }
        if (name === 'in' || name === 'in~') {
          this.expectOp('(');
          const list = [];
          if (!this.isOp(')')) { list.push(this.parseExpr()); while (this.isOp(',')) { this.next(); list.push(this.parseExpr()); } }
          this.expectOp(')');
          return { type: 'in', left, list, ci: name === 'in~', neg };
        }
        if (name === 'has_any' || name === 'has_all') {
          this.expectOp('(');
          const list = [];
          if (!this.isOp(')')) { list.push(this.parseExpr()); while (this.isOp(',')) { this.next(); list.push(this.parseExpr()); } }
          this.expectOp(')');
          return { type: 'hasanyall', left, list, all: name === 'has_all', neg };
        }
        const right = this.parseAdd();
        return { type: 'strop', name, left, right, neg };
      }
      if (neg) this.err('expected string operator after !');
      return left;
    }
    expectIdent2dot() { if (this.isOp('.') && this.peek(1).value === '.') { this.next(); this.next(); } else this.err("expected '..' in between()"); }

    parseAdd() {
      let left = this.parseMul();
      while (this.isOp('+') || this.isOp('-')) {
        const op = this.next().value;
        const right = this.parseMul();
        left = { type: 'bin', op, left, right };
      }
      return left;
    }
    parseMul() {
      let left = this.parseUnary();
      while (this.isOp('*') || this.isOp('/') || this.isOp('%')) {
        const op = this.next().value;
        const right = this.parseUnary();
        left = { type: 'bin', op, left, right };
      }
      return left;
    }
    parseUnary() {
      if (this.isOp('-')) { this.next(); return { type: 'neg', expr: this.parseUnary() }; }
      return this.parsePrimary();
    }
    parsePrimary() {
      const tk = this.peek();
      if (tk.type === 'number') { this.next(); return { type: 'lit', value: tk.value }; }
      if (tk.type === 'string') { this.next(); return { type: 'lit', value: tk.value }; }
      if (tk.type === 'timespan') { this.next(); return { type: 'lit', value: tk.value, timespan: true }; }
      if (this.isOp('(')) {
        this.next();
        // could be a subquery (tabular) used e.g. in `in (...)`, but we already special-case `in`.
        const e = this.parseExpr();
        this.expectOp(')');
        return e;
      }
      if (this.isOp('*')) { this.next(); return { type: 'star' }; }
      if (tk.type === 'ident') {
        const lower = tk.value.toLowerCase();
        if (lower === 'true') { this.next(); return { type: 'lit', value: true }; }
        if (lower === 'false') { this.next(); return { type: 'lit', value: false }; }
        // function call?
        if (this.peek(1).type === 'op' && this.peek(1).value === '(') {
          const name = this.next().value;
          this.next(); // (
          const args = [];
          if (!this.isOp(')')) {
            args.push(this.parseExpr());
            while (this.isOp(',')) { this.next(); args.push(this.parseExpr()); }
          }
          this.expectOp(')');
          return { type: 'call', name: name.toLowerCase(), args };
        }
        this.next();
        return { type: 'col', name: tk.value };
      }
      this.err('unexpected token in expression');
    }
  }

  function exprToName(expr) {
    if (expr.type === 'col') return expr.name;
    if (expr.type === 'call') {
      // Mirrors Kusto's real auto-naming for unaliased expressions in project/extend/summarize:
      // bin(Col, size) takes the column's own name; aggregations become "<func>_<arg>" (e.g. sum_CounterValue),
      // or just "<func>_" when there's no plain-column argument (e.g. count_).
      if (expr.name === 'bin' && expr.args[0] && expr.args[0].type === 'col') return expr.args[0].name;
      const firstColArg = expr.args.find(a => a.type === 'col');
      return firstColArg ? expr.name + '_' + firstColArg.name : expr.name + '_';
    }
    return 'Column1';
  }

  class KqlError extends Error {}

  // ---------- Evaluator ----------
  function evalScalar(expr, row, ctx) {
    switch (expr.type) {
      case 'lit': return expr.value;
      case 'star': return '*';
      case 'col': {
        // hasOwnProperty, not the `in` operator: `in` also matches inherited properties, so a column
        // literally named "constructor"/"toString"/"hasOwnProperty"/etc. would silently resolve to the
        // inherited Object.prototype function instead of correctly throwing "Column not found".
        if (!Object.prototype.hasOwnProperty.call(row, expr.name)) {
          throw new KqlError(`Column not found: '${expr.name}'`);
        }
        return row[expr.name];
      }
      case 'neg': return -toNumber(evalScalar(expr.expr, row, ctx));
      case 'not': return !truthy(evalScalar(expr.expr, row, ctx));
      case 'and': return truthy(evalScalar(expr.left, row, ctx)) && truthy(evalScalar(expr.right, row, ctx));
      case 'or': return truthy(evalScalar(expr.left, row, ctx)) || truthy(evalScalar(expr.right, row, ctx));
      case 'bin': {
        const l = evalScalar(expr.left, row, ctx), r = evalScalar(expr.right, row, ctx);
        if (expr.op === '+' && (typeof l === 'string' || typeof r === 'string') && !(isDate(l) && isDate(r))) return toStr(l) + toStr(r);
        if (isDate(l) || isDate(r)) {
          const lm = isDate(l) ? l.getTime() : toNumber(l);
          const rm = isDate(r) ? r.getTime() : toNumber(r);
          if (expr.op === '-' && isDate(l) && isDate(r)) return lm - rm; // ms difference
          if (expr.op === '+') return new Date(lm + rm);
          if (expr.op === '-') return new Date(lm - rm);
        }
        const ln = toNumber(l), rn = toNumber(r);
        switch (expr.op) {
          case '+': return ln + rn;
          case '-': return ln - rn;
          case '*': return ln * rn;
          case '/': return ln / rn;
          case '%': return ln % rn;
        }
        break;
      }
      case 'cmp': {
        let l = evalScalar(expr.left, row, ctx), r = evalScalar(expr.right, row, ctx);
        return compare(expr.op, l, r);
      }
      case 'strop': {
        const l = toStr(evalScalar(expr.left, row, ctx));
        const r = toStr(evalScalar(expr.right, row, ctx));
        let res = stringOp(expr.name, l, r);
        return expr.neg ? !res : res;
      }
      case 'in': {
        const l = evalScalar(expr.left, row, ctx);
        const vals = [];
        for (const e of expr.list) {
          if (e.type === 'col' && ctx && ctx.env && Array.isArray(ctx.env[e.name]) && !(e.name in row)) {
            const tbl = ctx.env[e.name];
            const cols = tbl.length ? Object.keys(tbl[0]) : [];
            if (cols.length !== 1) throw new KqlError(`in(): tabular value '${e.name}' must have exactly one column (has ${cols.length})`);
            for (const r of tbl) vals.push(r[cols[0]]);
          } else {
            vals.push(evalScalar(e, row, ctx));
          }
        }
        let res;
        if (expr.ci) res = vals.some(v => toStr(v).toLowerCase() === toStr(l).toLowerCase());
        else res = vals.some(v => v === l || toStr(v) === toStr(l));
        return expr.neg ? !res : res;
      }
      case 'hasanyall': {
        const l = toStr(evalScalar(expr.left, row, ctx));
        const vals = expr.list.map(e => toStr(evalScalar(e, row, ctx)));
        const res = expr.all ? vals.every(v => isTermMatch(l, v)) : vals.some(v => isTermMatch(l, v));
        return expr.neg ? !res : res;
      }
      case 'matches': {
        const l = toStr(evalScalar(expr.left, row, ctx));
        const pat = toStr(evalScalar(expr.right, row, ctx));
        let res = false;
        // Cheap ReDoS guard: a pathological pattern (e.g. "(a+)+b") run against JS's backtracking
        // regex engine can hang the tab on a long-enough input. This can only ever hang the query
        // author's own browser tab (self-DoS, no other visitor affected), but capping the tested
        // string's length keeps a runaway match from being trivial to trigger by accident.
        try { res = new RegExp(pat).test(l.length > 2000 ? l.slice(0, 2000) : l); } catch (e) { res = false; }
        return expr.neg ? !res : res;
      }
      case 'between': {
        const v = evalScalar(expr.target, row, ctx);
        const lo = evalScalar(expr.lo, row, ctx), hi = evalScalar(expr.hi, row, ctx);
        const vn = isDate(v) ? v.getTime() : toNumber(v);
        const lon = isDate(lo) ? lo.getTime() : toNumber(lo);
        const hin = isDate(hi) ? hi.getTime() : toNumber(hi);
        return vn >= lon && vn <= hin;
      }
      case 'call': return evalCall(expr, row, ctx);
    }
    throw new KqlError('Cannot evaluate expression');
  }

  function isDate(v) { return v instanceof Date; }
  function truthy(v) { return !!v; }
  function toNumber(v) { if (v instanceof Date) return v.getTime(); if (typeof v === 'boolean') return v ? 1 : 0; const n = Number(v); return n; }
  function toStr(v) {
    if (v === null || v === undefined) return '';
    if (v instanceof Date) return v.toISOString();
    if (Array.isArray(v)) return JSON.stringify(v);
    return String(v);
  }

  function compare(op, l, r) {
    if (isDate(l) || isDate(r)) {
      const lm = isDate(l) ? l.getTime() : (typeof l === 'number' ? l : new Date(l).getTime());
      const rm = isDate(r) ? r.getTime() : (typeof r === 'number' ? r : new Date(r).getTime());
      return numCompare(op, lm, rm);
    }
    if (typeof l === 'number' || typeof r === 'number') {
      if (op === '==' ) return toNumber(l) === toNumber(r) || toStr(l) === toStr(r);
      if (op === '!=' ) return !(toNumber(l) === toNumber(r) || toStr(l) === toStr(r));
      return numCompare(op, toNumber(l), toNumber(r));
    }
    const ls = toStr(l), rs = toStr(r);
    switch (op) {
      case '==': return ls === rs;
      case '!=': return ls !== rs;
      case '=~': return ls.toLowerCase() === rs.toLowerCase();
      case '!~': return ls.toLowerCase() !== rs.toLowerCase();
      case '<': return ls < rs;
      case '<=': return ls <= rs;
      case '>': return ls > rs;
      case '>=': return ls >= rs;
    }
  }
  function numCompare(op, ln, rn) {
    switch (op) {
      case '==': return ln === rn; case '!=': return ln !== rn;
      case '=~': return ln === rn; case '!~': return ln !== rn;
      case '<': return ln < rn; case '<=': return ln <= rn;
      case '>': return ln > rn; case '>=': return ln >= rn;
    }
  }

  // `has`/`has_cs` should differ ONLY in case sensitivity, not in what counts as a term boundary —
  // per Microsoft's docs, a term is a maximal run of alphanumeric characters, and underscore is a
  // delimiter (not part of a term) for both flavors. `has_cs` previously used a different regex that
  // included underscore in terms, so e.g. "foo_bar" has_cs "foo_bar" wrongly matched (true) while
  // "foo_bar" has "foo_bar" correctly didn't (false) — same string, same semantics, different answer.
  function isTermMatch(hay, needle, caseSensitive) {
    const terms = (caseSensitive ? hay : hay.toLowerCase()).match(/[a-zA-Z0-9]+/g) || [];
    return terms.includes(caseSensitive ? needle : needle.toLowerCase());
  }

  function stringOp(name, l, r) {
    switch (name) {
      case 'contains': return l.toLowerCase().includes(r.toLowerCase());
      case 'contains_cs': return l.includes(r);
      case 'has': return isTermMatch(l, r, false);
      case 'has_cs': return isTermMatch(l, r, true);
      case 'startswith': return l.toLowerCase().startsWith(r.toLowerCase());
      case 'startswith_cs': return l.startsWith(r);
      case 'endswith': return l.toLowerCase().endsWith(r.toLowerCase());
      case 'endswith_cs': return l.endsWith(r);
    }
    return false;
  }

  function evalCall(expr, row, ctx) {
    const a = expr.args;
    const name = expr.name;
    const ev = (i) => evalScalar(a[i], row, ctx);
    const now = () => (ctx && ctx.now) || new Date();
    switch (name) {
      case 'ago': return new Date(now().getTime() - toNumber(ev(0)));
      case 'now': return a.length ? new Date(now().getTime() + toNumber(ev(0))) : now();
      case 'datetime': {
        // datetime(2024-01-01) or datetime(2024-01-01 12:30:00) — the tokenizer special-cases the
        // unquoted "date [space time]" form (see tokenize()) into a plain string literal here, and
        // datetime("...") with an explicit quoted string works the same way.
        if (a.length === 1 && a[0].type === 'lit' && typeof a[0].value === 'string') return parseKustoDatetime(a[0].value);
        // numeric arithmetic case (2024-01-01 parsed as 2024 - 01 - 01 = 2022): reconstruct from bin sub-tree
        const s = datetimeExprToIso(a[0]);
        return new Date(s);
      }
      case 'bin': {
        const v = ev(0); const size = ev(1);
        if (isDate(v)) return new Date(Math.floor(v.getTime() / size) * size);
        return Math.floor(toNumber(v) / size) * size;
      }
      case 'strcat': return a.map(x => toStr(evalScalar(x, row, ctx))).join('');
      case 'tostring': return toStr(ev(0));
      case 'toint': case 'tolong': return Math.trunc(toNumber(ev(0)));
      case 'todouble': case 'toreal': return toNumber(ev(0));
      case 'tobool': { const v = ev(0); if (typeof v === 'boolean') return v; const s = toStr(v).toLowerCase(); return s === 'true' || s === '1'; }
      case 'strlen': return toStr(ev(0)).length;
      case 'substring': { const s = toStr(ev(0)); const start = toNumber(ev(1)); const len = a.length > 2 ? toNumber(ev(2)) : undefined; return len === undefined ? s.substring(start < 0 ? Math.max(0, s.length + start) : start) : s.substr(start < 0 ? Math.max(0, s.length + start) : start, len); }
      case 'indexof': { const s = toStr(ev(0)); const sub = toStr(ev(1)); return s.indexOf(sub); }
      case 'split': { const s = toStr(ev(0)); const delim = toStr(ev(1)); return s.split(delim); }
      case 'tolower': return toStr(ev(0)).toLowerCase();
      case 'toupper': return toStr(ev(0)).toUpperCase();
      case 'isempty': { const v = ev(0); return v === null || v === undefined || v === ''; }
      case 'isnotempty': { const v = ev(0); return !(v === null || v === undefined || v === ''); }
      case 'isnull': { const v = ev(0); return v === null || v === undefined; }
      case 'isnotnull': { const v = ev(0); return !(v === null || v === undefined); }
      case 'iif': case 'iff': return truthy(ev(0)) ? ev(1) : ev(2);
      case 'coalesce': { for (let i = 0; i < a.length; i++) { const v = ev(i); if (v !== null && v !== undefined && v !== '') return v; } return null; }
      case 'case': {
        for (let i = 0; i + 1 < a.length; i += 2) { if (truthy(ev(i))) return ev(i + 1); }
        return ev(a.length - 1);
      }
      case 'array_length': { const v = ev(0); return Array.isArray(v) ? v.length : 0; }
      case 'series_decompose_anomalies': {
        const series = ev(0);
        if (!Array.isArray(series)) throw new KqlError('series_decompose_anomalies() expects a dynamic array — typically a column produced by make-series');
        const threshold = a.length > 1 ? toNumber(ev(1)) : undefined;
        return seriesDecomposeAnomalies(series, threshold);
      }
    }
    throw new KqlError(`Unsupported function: ${name}()`);
  }

  // Real Kusto datetime literals are always UTC. An ISO string with an explicit 'T' and/or timezone
  // (Z or +hh:mm) is unambiguous, so `new Date(...)` handles it correctly. But the space-separated
  // "YYYY-MM-DD HH:MM:SS[.fraction]" form the tokenizer produces for an unquoted `datetime(2024-01-15
  // 10:30:00)` literal is exactly the pattern JS's own Date constructor treats as LOCAL time when
  // there's no 'T'/timezone marker — so naively doing `new Date(rawString)` here would silently give
  // a different instant depending on the visitor's own timezone, when the whole point of a KQL
  // datetime literal is that it means the same UTC instant for everyone. Parse the components
  // ourselves and build the instant with Date.UTC() instead.
  function parseKustoDatetime(str) {
    const s = str.trim();
    const m = s.match(/^(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{2}):(\d{2})(?::(\d{2}(?:\.\d+)?))?)?\s*Z?$/);
    if (m) {
      const [, y, mo, d, h, mi, se] = m;
      const seconds = se ? parseFloat(se) : 0;
      const wholeSeconds = Math.floor(seconds);
      const ms = Math.round((seconds - wholeSeconds) * 1000);
      return new Date(Date.UTC(+y, +mo - 1, +d, h ? +h : 0, mi ? +mi : 0, wholeSeconds, ms));
    }
    // Already has an explicit timezone (Z/+hh:mm) or isn't in the plain form above — unambiguous,
    // let the platform Date parser handle it (covers full ISO-8601 datetime("...Z") strings).
    return new Date(s);
  }

  function datetimeExprToIso(expr) {
    // handle patterns like (2024 - 1 - 1) or ((2024-1-1) something 12:30:00) minimally:
    // fallback — flatten arithmetic subtree into "Y-M-D" using bin op '-' nesting produced by tokenizer for "2024-01-01"
    function flatten(e) {
      if (e.type === 'lit') return [e.value];
      if (e.type === 'bin' && e.op === '-') return [...flatten(e.left), ...flatten(e.right)];
      if (e.type === 'neg') return [-flatten(e.expr)[0]];
      return [NaN];
    }
    const parts = flatten(expr);
    if (parts.length >= 3) {
      const [y, mo, d] = parts;
      return `${String(y).padStart(4, '0')}-${String(mo).padStart(2, '0')}-${String(d).padStart(2, '0')}T00:00:00Z`;
    }
    if (parts.length === 1) return new Date(parts[0]).toISOString();
    return new Date().toISOString();
  }

  // ---------- Aggregations ----------
  function evalAggregate(expr, rows, ctx) {
    if (expr.type !== 'call') {
      // non-aggregate scalar in summarize (rare) — evaluate on first row
      return rows.length ? evalScalar(expr, rows[0], ctx) : null;
    }
    const name = expr.name;
    const a = expr.args;
    const vals = (idx) => rows.map(r => evalScalar(a[idx], r, ctx));
    switch (name) {
      case 'count': return rows.length;
      case 'countif': return rows.filter(r => truthy(evalScalar(a[0], r, ctx))).length;
      case 'dcount': return new Set(vals(0).map(toStr)).size;
      case 'dcountif': return new Set(rows.filter(r => truthy(evalScalar(a[1], r, ctx))).map(r => toStr(evalScalar(a[0], r, ctx)))).size;
      case 'sum': return vals(0).reduce((s, v) => s + toNumber(v), 0);
      case 'sumif': return rows.filter(r => truthy(evalScalar(a[1], r, ctx))).reduce((s, r) => s + toNumber(evalScalar(a[0], r, ctx)), 0);
      // Real Kusto's avg()/avgif() exclude nulls from both the sum and the count (confirmed against
      // Microsoft's own summarize-operator doc example). toNumber(null) === 0, not NaN, so nulls must
      // be dropped *before* the numeric conversion — converting first and NaN-filtering after would
      // silently keep every null as a 0, dragging the average down whenever a column has gaps (which
      // this dataset's normalize() deliberately fills with null for every unset field).
      case 'avg': { const v = vals(0).filter(x => x !== null && x !== undefined).map(toNumber).filter(x => !Number.isNaN(x)); return v.length ? v.reduce((s, x) => s + x, 0) / v.length : null; }
      case 'avgif': { const v = rows.filter(r => truthy(evalScalar(a[1], r, ctx))).map(r => evalScalar(a[0], r, ctx)).filter(x => x !== null && x !== undefined).map(toNumber).filter(x => !Number.isNaN(x)); return v.length ? v.reduce((s, x) => s + x, 0) / v.length : null; }
      case 'max': { const v = vals(0); return v.length ? v.reduce((m, x) => (m === null || x > m) ? x : m, null) : null; }
      case 'min': { const v = vals(0); return v.length ? v.reduce((m, x) => (m === null || x < m) ? x : m, null) : null; }
      case 'maxif': { const v = rows.filter(r => truthy(evalScalar(a[1], r, ctx))).map(r => evalScalar(a[0], r, ctx)); return v.length ? v.reduce((m, x) => (m === null || x > m) ? x : m, null) : null; }
      case 'minif': { const v = rows.filter(r => truthy(evalScalar(a[1], r, ctx))).map(r => evalScalar(a[0], r, ctx)); return v.length ? v.reduce((m, x) => (m === null || x < m) ? x : m, null) : null; }
      case 'make_set': { const seen = []; const seenS = new Set(); for (const v of vals(0)) { const s = toStr(v); if (!seenS.has(s)) { seenS.add(s); seen.push(v); } } return seen; }
      case 'make_list': return vals(0);
      case 'arg_max': { let best = null, bestKey = null; for (const r of rows) { const k = toNumber(evalScalar(a[0], r, ctx)); if (bestKey === null || k > bestKey) { bestKey = k; best = r; } } return best ? evalScalar(a[1], best, ctx) : null; }
      case 'arg_min': { let best = null, bestKey = null; for (const r of rows) { const k = toNumber(evalScalar(a[0], r, ctx)); if (bestKey === null || k < bestKey) { bestKey = k; best = r; } } return best ? evalScalar(a[1], best, ctx) : null; }
    }
    throw new KqlError(`Unsupported aggregation function: ${name}()`);
  }

  // ---------- Execution ----------
  function run(queryText, tables, opts) {
    opts = opts || {};
    const tokens = tokenize(queryText);
    const parser = new Parser(tokens, queryText);
    const program = parser.parseProgram();
    const ctx = { now: opts.now || new Date() };
    const env = Object.assign({}, tables); // name -> array of rows (also holds let-tabular bindings)
    ctx.env = env;
    const scalars = {};
    for (const l of program.lets) {
      if (l.value.kind === 'tabular') {
        env[l.name] = execTabular(l.value.expr, env, scalars, ctx);
      } else {
        scalars[l.name] = evalScalar(l.value.expr, {}, ctx);
        env[l.name] = undefined;
      }
    }
    // allow scalar let names to be referenced inside expressions as columns —
    // patch evalScalar's 'col' case via a wrapper ctx.scalars
    ctx.scalars = scalars;
    const result = execTabular(program.query, env, scalars, ctx, true);
    return result;
  }

  // wrap evalScalar to check scalars map for unresolved column names bound via let
  const _origEvalScalarCol = evalScalar;
  function evalScalarWithLets(expr, row, ctx) {
    if (expr.type === 'col' && ctx && ctx.scalars && (expr.name in ctx.scalars) && !(expr.name in row)) {
      return ctx.scalars[expr.name];
    }
    return evalScalar(expr, row, ctx);
  }

  function execTabular(tabExpr, env, scalars, ctx) {
    let rows;
    const srcName = tabExpr.source.name;
    if (srcName in env) {
      rows = env[srcName];
      if (!rows) throw new KqlError(`'${srcName}' is not a tabular source`);
    } else {
      throw new KqlError(`Unknown table: '${srcName}'. Available: ${Object.keys(env).filter(k=>Array.isArray(env[k])).join(', ')}`);
    }
    rows = rows.slice();
    for (const op of tabExpr.ops) {
      rows = applyOp(op, rows, env, ctx);
    }
    return rows;
  }

  function applyOp(op, rows, env, ctx) {
    switch (op.op) {
      case 'where':
        return rows.filter(r => truthy(evalScalarWithLets(op.pred, r, ctx)));
      case 'project': {
        return rows.map(r => { const o = {}; for (const it of op.items) o[it.name] = evalScalarWithLets(it.expr, r, ctx); return o; });
      }
      case 'extend': {
        return rows.map(r => { const o = Object.assign({}, r); for (const it of op.items) o[it.name] = evalScalarWithLets(it.expr, r, ctx); return o; });
      }
      case 'project-away': {
        const drop = new Set(op.names);
        return rows.map(r => { const o = Object.assign({}, r); for (const k of drop) delete o[k]; return o; });
      }
      case 'project-keep': {
        const keep = new Set(op.names);
        return rows.map(r => { const o = {}; for (const k of Object.keys(r)) if (keep.has(k)) o[k] = r[k]; return o; });
      }
      case 'project-rename': {
        return rows.map(r => { const o = Object.assign({}, r); for (const it of op.items) { const oldName = it.expr.type === 'col' ? it.expr.name : null; if (oldName && oldName in o) { o[it.name] = o[oldName]; delete o[oldName]; } } return o; });
      }
      case 'project-reorder': {
        return rows.map(r => {
          const o = {}; const used = new Set();
          for (const n of op.names) {
            if (n.endsWith('*')) { const pre = n.slice(0, -1); for (const k of Object.keys(r)) if (k.startsWith(pre) && !used.has(k)) { o[k] = r[k]; used.add(k); } }
            else if (n in r) { o[n] = r[n]; used.add(n); }
          }
          for (const k of Object.keys(r)) if (!used.has(k)) o[k] = r[k];
          return o;
        });
      }
      case 'summarize': return applySummarize(op, rows, ctx);
      case 'make-series': return applyMakeSeries(op, rows, ctx);
      case 'sort': {
        const items = op.items;
        const withKeys = rows.map(r => ({ r, keys: items.map(it => evalScalarWithLets(it.expr, r, ctx)) }));
        withKeys.sort((a, b) => {
          for (let i = 0; i < items.length; i++) {
            const dir = items[i].dir === 'asc' ? 1 : -1;
            const av = a.keys[i], bv = b.keys[i];
            const c = compareSortKey(av, bv, dir, items[i].nulls);
            if (c !== 0) return c;
          }
          return 0;
        });
        return withKeys.map(x => x.r);
      }
      case 'top': {
        const n = toNumber(evalScalarWithLets(op.n, {}, ctx));
        const items = op.items;
        const withKeys = rows.map(r => ({ r, keys: items.map(it => evalScalarWithLets(it.expr, r, ctx)) }));
        withKeys.sort((a, b) => {
          for (let i = 0; i < items.length; i++) {
            const dir = items[i].dir === 'asc' ? 1 : -1;
            const c = compareSortKey(a.keys[i], b.keys[i], dir, items[i].nulls);
            if (c !== 0) return c;
          }
          return 0;
        });
        return withKeys.slice(0, n).map(x => x.r);
      }
      case 'take': {
        const n = toNumber(evalScalarWithLets(op.n, {}, ctx));
        return rows.slice(0, n);
      }
      case 'distinct': {
        const names = op.names || (rows.length ? Object.keys(rows[0]) : []);
        const seen = new Set(); const out = [];
        for (const r of rows) {
          const key = names.map(n => toStr(r[n])).join('');
          if (!seen.has(key)) { seen.add(key); const o = {}; for (const n of names) o[n] = r[n]; out.push(o); }
        }
        return out;
      }
      case 'count': return [{ Count: rows.length }];
      case 'join': return applyJoin(op, rows, env, ctx);
      case 'union': {
        let out = rows.slice();
        for (const t of op.tables) { if (env[t]) out = out.concat(env[t]); }
        return out;
      }
      case 'render': return rows; // acknowledged but not visualized as a chart
    }
    throw new KqlError(`Unhandled operator '${op.op}'`);
  }

  function compareForSort(a, b) {
    if (a === null || a === undefined) return (b === null || b === undefined) ? 0 : -1;
    if (b === null || b === undefined) return 1;
    if (isDate(a) || isDate(b)) return (isDate(a) ? a.getTime() : toNumber(a)) - (isDate(b) ? b.getTime() : toNumber(b));
    if (typeof a === 'number' && typeof b === 'number') return a - b;
    const as = toStr(a), bs = toStr(b);
    return as < bs ? -1 : as > bs ? 1 : 0;
  }

  // Direction-and-nulls-aware comparator for a single sort key. `dir` is +1 (asc) or -1 (desc).
  // `nullsPlacement` is 'first'/'last' when the query explicitly wrote `nulls first`/`nulls last`,
  // or null to keep this engine's existing default (nulls sort as the smallest value, then the
  // normal direction multiplier applies — asc puts them first, desc puts them last, which already
  // matches Kusto's documented default). An explicit placement is absolute regardless of asc/desc,
  // same as real Kusto — previously this modifier was parsed and silently discarded, so writing
  // `sort by X asc nulls last` looked accepted but had no effect (stayed nulls-first).
  function compareSortKey(av, bv, dir, nullsPlacement) {
    const aNull = av === null || av === undefined;
    const bNull = bv === null || bv === undefined;
    if (aNull && bNull) return 0;
    if (aNull || bNull) {
      if (!nullsPlacement) return compareForSort(av, bv) * dir;
      return nullsPlacement === 'first' ? (aNull ? -1 : 1) : (aNull ? 1 : -1);
    }
    return compareForSort(av, bv) * dir;
  }

  function applySummarize(op, rows, ctx) {
    const byItems = op.by;
    if (!byItems.length) {
      const out = {};
      for (const agg of op.aggs) out[agg.name] = evalAggregate(agg.expr, rows, ctx);
      if (!op.aggs.length) return [{}];
      return [out];
    }
    const groups = new Map();
    for (const r of rows) {
      const keyVals = byItems.map(it => evalScalarWithLets(it.expr, r, ctx));
      const key = keyVals.map(toStr).join('');
      if (!groups.has(key)) groups.set(key, { keyVals, rows: [] });
      groups.get(key).rows.push(r);
    }
    const out = [];
    for (const { keyVals, rows: grows } of groups.values()) {
      const o = {};
      byItems.forEach((it, i) => { o[it.name] = keyVals[i]; });
      for (const agg of op.aggs) o[agg.name] = evalAggregate(agg.expr, grows, ctx);
      out.push(o);
    }
    return out;
  }

  // make-series bins rows along a datetime axis into equal-width steps and aggregates each bin,
  // producing one row per group with array-valued (dynamic) columns for the axis and each aggregation
  // — matching https://learn.microsoft.com/en-us/kusto/query/make-series-operator. `default=` per-column
  // overrides aren't parsed by this practice engine; empty bins always default to 0.
  function applyMakeSeries(op, rows, ctx) {
    const axisVals = rows.map(r => evalScalarWithLets(op.axis, r, ctx));
    const numericAxis = axisVals.map(v => isDate(v) ? v.getTime() : toNumber(v));
    const from = op.from !== null ? toNumber(evalScalarWithLets(op.from, {}, ctx))
      : (numericAxis.length ? Math.min(...numericAxis) : 0);
    const to = op.to !== null ? toNumber(evalScalarWithLets(op.to, {}, ctx))
      : (numericAxis.length ? Math.max(...numericAxis) : from);
    const step = toNumber(evalScalarWithLets(op.step, {}, ctx));
    if (!step || step <= 0) throw new KqlError("make-series: 'step' must be a positive timespan or number");
    const numBins = Math.max(1, Math.ceil((to - from) / step));
    const axisIsDate = axisVals.some(isDate);
    const binStarts = [];
    for (let i = 0; i < numBins; i++) binStarts.push(from + i * step);

    function groupRows(grows) {
      const binned = binStarts.map(() => []);
      grows.forEach(r => {
        const v = evalScalarWithLets(op.axis, r, ctx);
        const nv = isDate(v) ? v.getTime() : toNumber(v);
        let idx = Math.floor((nv - from) / step);
        if (idx < 0) idx = 0;
        if (idx >= numBins) idx = numBins - 1;
        binned[idx].push(r);
      });
      const axisName = op.axis.type === 'col' ? op.axis.name : 'axis';
      const out = { [axisName]: binStarts.map(b => axisIsDate ? new Date(b) : b) };
      for (const agg of op.aggs) {
        out[agg.name] = binned.map(bucketRows => {
          const val = bucketRows.length ? evalAggregate(agg.expr, bucketRows, ctx) : 0;
          return (val === null || val === undefined) ? 0 : val;
        });
      }
      return out;
    }

    if (!op.by.length) return [groupRows(rows)];
    const groups = new Map();
    for (const r of rows) {
      const keyVals = op.by.map(it => evalScalarWithLets(it.expr, r, ctx));
      const key = keyVals.map(toStr).join('');
      if (!groups.has(key)) groups.set(key, { keyVals, rows: [] });
      groups.get(key).rows.push(r);
    }
    const out = [];
    for (const { keyVals, rows: grows } of groups.values()) {
      const o = groupRows(grows);
      const withKeys = {};
      op.by.forEach((it, i) => { withKeys[it.name] = keyVals[i]; });
      Object.assign(withKeys, o);
      out.push(withKeys);
    }
    return out;
  }

  // Simplified series_decompose_anomalies(series [, threshold]) — flags entries whose deviation from
  // the series' overall average falls outside a Tukey ("ctukey") fence built from the 10th/90th
  // percentiles of the residuals, scaled by `threshold` (default 1.5), matching the *default* parameter
  // set at https://learn.microsoft.com/en-us/kusto/query/series-decompose-anomalies-function. Seasonality
  // detection, linear-trend fitting and forecasting (test_points) aren't modeled — this engine's synthetic
  // data has no seasonal component, so the default 'avg' trend mode covers every practice scenario.
  function seriesDecomposeAnomalies(series, threshold) {
    const k = (threshold === undefined || threshold === null) ? 1.5 : threshold;
    const nums = series.map(toNumber);
    if (!nums.length) return [];
    const mean = nums.reduce((s, v) => s + v, 0) / nums.length;
    const residuals = nums.map(v => v - mean);
    const sorted = residuals.slice().sort((a, b) => a - b);
    function percentile(p) {
      if (sorted.length === 1) return sorted[0];
      const idx = (p / 100) * (sorted.length - 1);
      const lo = Math.floor(idx), hi = Math.ceil(idx);
      if (lo === hi) return sorted[lo];
      return sorted[lo] + (sorted[hi] - sorted[lo]) * (idx - lo);
    }
    const p10 = percentile(10), p90 = percentile(90);
    const fence = (p90 - p10) * k;
    const lowerBound = p10 - fence, upperBound = p90 + fence;
    return residuals.map(r => r > upperBound ? 1 : r < lowerBound ? -1 : 0);
  }

  function applyJoin(op, leftRows, env, ctx) {
    const rightRows = execTabular(op.right, env, {}, ctx);
    const kind = op.kind;
    const conds = op.conds;
    // explicit left/right field name resolution ($left.X == $right.Y, or bare ColName)
    function fieldName(cond, side) {
      if (cond.sameName) return cond.left.name;
      if (side === 'left') return cond.left.side === '$right' ? cond.right.name : cond.left.name;
      return cond.left.side === '$right' ? cond.left.name : cond.right.name;
    }
    const leftKeyFields = conds.map(c => fieldName(c, 'left'));
    const rightKeyFields = conds.map(c => fieldName(c, 'right'));
    const rightIndex = new Map();
    rightRows.forEach(rr => {
      const k = rightKeyFields.map(f => toStr(rr[f])).join('');
      if (!rightIndex.has(k)) rightIndex.set(k, []);
      rightIndex.get(k).push(rr);
    });
    function merge(lr, rr) {
      // Real Kusto keeps BOTH copies of a same-named join key (left's under its own name, right's
      // suffixed `<Key>1`) rather than collapsing them into one column — confirmed against Microsoft's
      // own `join` doc example (`X | join Y on Key` → `Key, Value1, Key1, Value2`). The previous
      // exemption for leftKeyFields silently overwrote the left key's value with the right's and never
      // produced the `Key1` column real Kusto always adds, which would surprise a learner the first
      // time they ran the equivalent query against a real workspace.
      const o = Object.assign({}, lr);
      for (const k of Object.keys(rr)) {
        if (k in o) o[k + '1'] = rr[k];
        else o[k] = rr[k];
      }
      return o;
    }
    const usedLeftUniq = new Set();
    const out = [];
    const matchedRightKeys = new Set();
    for (const lr of leftRows) {
      const k = leftKeyFields.map(f => toStr(lr[f])).join('');
      if (kind === 'innerunique' && usedLeftUniq.has(k)) continue;
      const matches = rightIndex.get(k) || [];
      if (matches.length) {
        matchedRightKeys.add(k);
        if (kind === 'innerunique') { out.push(merge(lr, matches[0])); usedLeftUniq.add(k); }
        else if (kind === 'leftsemi') out.push(lr);
        else if (kind === 'leftanti') { /* skip, matched */ }
        else { for (const rr of matches) out.push(merge(lr, rr)); }
      } else {
        if (kind === 'leftouter' || kind === 'fullouter') out.push(merge(lr, {}));
        else if (kind === 'leftanti') out.push(lr);
        // inner / innerunique / leftsemi / rightsemi / rightanti: no row
      }
    }
    if (kind === 'rightouter' || kind === 'fullouter' || kind === 'rightsemi' || kind === 'rightanti') {
      for (const rr of rightRows) {
        const k = rightKeyFields.map(f => toStr(rr[f])).join('');
        const hasMatch = leftRows.some(lr => leftKeyFields.map(f => toStr(lr[f])).join('') === k);
        if (kind === 'rightsemi') { if (hasMatch) out.push(rr); continue; }
        if (kind === 'rightanti') { if (!hasMatch) out.push(rr); continue; }
        if (!hasMatch) out.push(merge({}, rr));
      }
    }
    return out;
  }

  root.KQL = {
    run,
    tokenize,
    KqlError,
  };
})(typeof window !== 'undefined' ? window : (typeof module !== 'undefined' ? module.exports : this));

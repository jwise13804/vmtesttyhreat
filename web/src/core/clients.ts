// Ported from the client management + contamination-check subsystem in
// src/threatpad.py (_get_client_patterns, run_contamination_check,
// _passive_contamination_scan). A "client" is an MSSP customer/tenant whose
// identifiers must not leak into another customer's notes.

export interface ClientRecord {
  emailDomains: string[];
  hostnamePrefixes: string[];
  ipRanges: string[];
  keywords: string[];
}

export type ClientMap = Record<string, ClientRecord>;

export function emptyClient(): ClientRecord {
  return { emailDomains: [], hostnamePrefixes: [], ipRanges: [], keywords: [] };
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

interface ClientPattern {
  regex: RegExp;
  label: string;
  client: string;
  value: string;
}

/** Mirrors _get_client_patterns(): literal substring match for domains/hostnames,
 *  first-3-octets match for IP ranges, word-boundary match for keywords. */
export function buildClientPatterns(clientName: string, record: ClientRecord): ClientPattern[] {
  const patterns: ClientPattern[] = [];
  for (const domain of record.emailDomains) {
    if (!domain.trim()) continue;
    patterns.push({
      regex: new RegExp(escapeRegExp(domain.trim()), "gi"),
      label: "Email Domain",
      client: clientName,
      value: domain.trim(),
    });
  }
  for (const prefix of record.hostnamePrefixes) {
    if (!prefix.trim()) continue;
    patterns.push({
      regex: new RegExp(escapeRegExp(prefix.trim()), "gi"),
      label: "Hostname Prefix",
      client: clientName,
      value: prefix.trim(),
    });
  }
  for (const range of record.ipRanges) {
    const base = range.trim().split("/")[0]?.split(".").slice(0, 3).join(".");
    if (!base) continue;
    patterns.push({
      regex: new RegExp(escapeRegExp(base), "gi"),
      label: "IP Range",
      client: clientName,
      value: range.trim(),
    });
  }
  for (const keyword of record.keywords) {
    if (!keyword.trim()) continue;
    patterns.push({
      regex: new RegExp(`\\b${escapeRegExp(keyword.trim())}\\b`, "gi"),
      label: "Keyword",
      client: clientName,
      value: keyword.trim(),
    });
  }
  return patterns;
}

export interface ContaminationFinding {
  client: string;
  type: string;
  value: string;
  line: number;
  matchedText: string;
}

/** Scans text against every OTHER client's patterns (excludes activeClient). */
export function scanForContamination(
  text: string,
  clients: ClientMap,
  activeClient: string,
): ContaminationFinding[] {
  const findings: ContaminationFinding[] = [];
  const lineStarts = computeLineStarts(text);

  for (const [name, record] of Object.entries(clients)) {
    if (name === activeClient) continue;
    for (const pattern of buildClientPatterns(name, record)) {
      pattern.regex.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = pattern.regex.exec(text)) !== null) {
        findings.push({
          client: name,
          type: pattern.label,
          value: pattern.value,
          line: lineNumberFor(m.index, lineStarts),
          matchedText: m[0],
        });
        if (m[0].length === 0) pattern.regex.lastIndex++;
      }
    }
  }
  return findings;
}

function computeLineStarts(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i++) {
    if (text[i] === "\n") starts.push(i + 1);
  }
  return starts;
}
function lineNumberFor(index: number, lineStarts: number[]): number {
  let lo = 0;
  let hi = lineStarts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (lineStarts[mid] <= index) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

// Live (undefanged) IOC patterns — used by the traffic-light "amber" check.
// No "g" flag: these are stateless single-shot tests, not used for iteration.
const LIVE_URL = /\bhttps?:\/\/[^\s<>"]+/i;
const LIVE_IPV4 = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/;
const LIVE_EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/;

export function hasLiveIocs(text: string): boolean {
  return LIVE_URL.test(text) || LIVE_IPV4.test(text) || LIVE_EMAIL.test(text);
}

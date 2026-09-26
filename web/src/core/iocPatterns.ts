export type IocType =
  | "ipv4"
  | "ipv6"
  | "domain"
  | "url"
  | "email"
  | "hash_md5"
  | "hash_sha1"
  | "hash_sha256";

// Order doubles as extraction priority (most specific first) so e.g. a URL's
// host isn't claimed by the generic domain pattern before the URL pattern runs.
export const IOC_TYPES: IocType[] = [
  "hash_sha256",
  "hash_sha1",
  "hash_md5",
  "url",
  "email",
  "ipv6",
  "ipv4",
  "domain",
];

export const IOC_LABELS: Record<IocType, string> = {
  ipv4: "IPv4",
  ipv6: "IPv6",
  domain: "Domain",
  url: "URL",
  email: "Email",
  hash_md5: "MD5",
  hash_sha1: "SHA1",
  hash_sha256: "SHA256",
};

// Ported from src/threatpad.py's self.ioc_patterns.
// Order matters: hashes/urls/emails are matched before the generic domain
// pattern so a hex hash or an email's host isn't also reported as a domain.
export const IOC_PATTERNS: Record<IocType, RegExp> = {
  hash_sha256: /\b[a-fA-F0-9]{64}\b/g,
  hash_sha1: /\b[a-fA-F0-9]{40}\b/g,
  hash_md5: /\b[a-fA-F0-9]{32}\b/g,
  url: /\bhttps?:\/\/[^\s<>"]{2,}\b/gi,
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  ipv6: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g,
  ipv4: /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g,
  domain: /\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b/g,
};

export interface IocMatch {
  type: IocType;
  value: string;
  start: number;
  end: number;
}

/** Scans text for every IOC type, avoiding overlapping matches (first match wins by pattern priority). */
export function extractIocs(text: string): IocMatch[] {
  const claimed: Array<[number, number]> = [];
  const matches: IocMatch[] = [];

  const overlaps = (start: number, end: number) =>
    claimed.some(([s, e]) => start < e && end > s);

  for (const type of IOC_TYPES) {
    const pattern = new RegExp(IOC_PATTERNS[type].source, IOC_PATTERNS[type].flags);
    let m: RegExpExecArray | null;
    while ((m = pattern.exec(text)) !== null) {
      const start = m.index;
      const end = start + m[0].length;
      if (!overlaps(start, end)) {
        claimed.push([start, end]);
        matches.push({ type, value: m[0], start, end });
      }
      if (m[0].length === 0) pattern.lastIndex++;
    }
  }

  matches.sort((a, b) => a.start - b.start);
  return matches;
}

export function groupIocs(matches: IocMatch[]): Record<IocType, string[]> {
  const grouped = Object.fromEntries(IOC_TYPES.map((t) => [t, [] as string[]])) as Record<
    IocType,
    string[]
  >;
  for (const m of matches) {
    if (!grouped[m.type].includes(m.value)) grouped[m.type].push(m.value);
  }
  return grouped;
}

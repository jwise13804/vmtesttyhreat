// Threat hunt tracking — local-only (localStorage), same pattern as the rest
// of ThreatPad's storage layer. A "hunt" is a structured record of one
// hypothesis-driven investigation: what you're looking for, where you looked,
// what you ran, what you found, and how it maps to MITRE ATT&CK.

import { extractIocs, IOC_LABELS, type IocMatch } from "./iocPatterns";
import { mitreEntryById, tagCoversTechnique } from "./mitre";

export type HuntStatus = "open" | "in_progress" | "closed";

export const HUNT_STATUS_LABELS: Record<HuntStatus, string> = {
  open: "Open",
  in_progress: "In Progress",
  closed: "Closed",
};

export type HuntPriority = "low" | "medium" | "high";

export const HUNT_PRIORITY_LABELS: Record<HuntPriority, string> = {
  low: "Low",
  medium: "Medium",
  high: "High",
};

export interface Hunt {
  id: string;
  title: string;
  hypothesis: string;
  techniques: string[]; // MITRE technique or sub-technique IDs, e.g. "T1059" or "T1059.001"
  dataSources: string[];
  queries: string; // freeform KQL/query text, one or more queries
  findings: string;
  iocs: IocMatch[]; // snapshot captured from findings via "Extract IOCs"
  status: HuntStatus;
  priority: HuntPriority;
  recurringDays?: number; // if set, this hunt is due again `recurringDays` after updatedAt
  createdAt: string;
  updatedAt: string;
  closedAt?: string;
}

export interface Playbook {
  id: string;
  title: string;
  description: string;
  techniques: string[];
  suggestedQuery: string;
}

const KEYS = {
  hunts: "threatpad:hunts",
  playbooks: "threatpad:playbooks",
} as const;

function read<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}
function write(key: string, value: unknown): void {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch (e) {
    console.error(`Failed to persist ${key}`, e);
  }
}

export function loadHunts(): Hunt[] {
  return read<Hunt[]>(KEYS.hunts, []);
}
export const saveHunts = (hunts: Hunt[]) => write(KEYS.hunts, hunts);

export const DEFAULT_PLAYBOOKS: Playbook[] = [
  {
    id: "pb-encoded-powershell",
    title: "Encoded / Obfuscated PowerShell",
    description:
      "Hunt for PowerShell invoked with base64-encoded or otherwise obfuscated command lines, a common way to smuggle payloads past simple string-matching detections.",
    techniques: ["T1059", "T1027"],
    suggestedQuery:
      'DeviceProcessEvents\n| where FileName =~ "powershell.exe"\n| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "FromBase64String", "-nop", "-w hidden")\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine',
  },
  {
    id: "pb-scheduled-task-persistence",
    title: "Suspicious Scheduled Task Persistence",
    description:
      "Look for scheduled tasks created outside normal change windows, especially ones running from user-writable paths (Temp, AppData, Downloads).",
    techniques: ["T1053"],
    suggestedQuery:
      'DeviceProcessEvents\n| where FileName in~ ("schtasks.exe", "at.exe")\n| where ProcessCommandLine has "/create"\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine',
  },
  {
    id: "pb-lateral-movement-remote-services",
    title: "Lateral Movement via Remote Services",
    description:
      "Identify accounts authenticating to an unusually large number of distinct hosts in a short window — a common signature of manual or tooled lateral movement.",
    techniques: ["T1021", "T1570"],
    suggestedQuery:
      'DeviceLogonEvents\n| where LogonType == "Network"\n| summarize DistinctHosts = dcount(DeviceName) by AccountName, bin(Timestamp, 1h)\n| where DistinctHosts > 5',
  },
  {
    id: "pb-credential-dumping",
    title: "Credential Dumping (LSASS Access)",
    description:
      "Hunt for tools and techniques commonly used to dump credentials from LSASS memory (procdump, comsvcs.dll MiniDump, Mimikatz-style access patterns).",
    techniques: ["T1003"],
    suggestedQuery:
      'DeviceProcessEvents\n| where FileName =~ "procdump.exe" or ProcessCommandLine has "lsass"\n| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine',
  },
  {
    id: "pb-anomalous-signins",
    title: "Anomalous Sign-ins / Password Spray",
    description:
      "Look for accounts with a high volume of failed logons followed by a success, or logons from an unusual number of source IPs — signatures of brute-force or password-spray activity.",
    techniques: ["T1110", "T1078"],
    suggestedQuery:
      'DeviceLogonEvents\n| where ActionType == "LogonFailed"\n| summarize FailCount = count(), DistinctIPs = dcount(RemoteIP) by AccountName, bin(Timestamp, 1h)\n| where FailCount > 10 or DistinctIPs > 5',
  },
  {
    id: "pb-c2-beaconing",
    title: "C2 Beaconing (Regular-Interval Connections)",
    description:
      "Hunt for a device making highly regular, repeated connections to the same external endpoint — a classic beaconing pattern for command-and-control callback.",
    techniques: ["T1071", "T1568"],
    suggestedQuery:
      'DeviceNetworkEvents\n| where RemoteIPType == "Public"\n| summarize ConnCount = count() by DeviceName, RemoteUrl, RemoteIP\n| where ConnCount > 100\n| order by ConnCount desc',
  },
  {
    id: "pb-data-staging",
    title: "Data Staging Before Exfiltration",
    description:
      "Look for archive files (zip/rar/7z) being created in staging locations shortly before large outbound transfers — a common precursor to exfiltration.",
    techniques: ["T1074", "T1560"],
    suggestedQuery:
      'DeviceFileEvents\n| where FileName endswith ".zip" or FileName endswith ".rar" or FileName endswith ".7z"\n| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName',
  },
  {
    id: "pb-new-admin-account",
    title: "New Privileged Account Creation",
    description:
      "Hunt for accounts newly created and immediately added to a privileged group, a common persistence mechanism after initial compromise.",
    techniques: ["T1136", "T1098"],
    suggestedQuery:
      'DeviceEvents\n| where ActionType in ("UserAccountCreated", "AccountAddedToGroup")\n| project Timestamp, DeviceName, ActionType, AccountName, AdditionalFields',
  },
];

export function loadPlaybooks(): Playbook[] {
  try {
    const raw = localStorage.getItem(KEYS.playbooks);
    if (!raw) {
      savePlaybooks(DEFAULT_PLAYBOOKS);
      return [...DEFAULT_PLAYBOOKS];
    }
    return JSON.parse(raw) as Playbook[];
  } catch {
    return [...DEFAULT_PLAYBOOKS];
  }
}
export const savePlaybooks = (playbooks: Playbook[]) => write(KEYS.playbooks, playbooks);

function randomId(prefix: string): string {
  return `${prefix}_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}
export const newHuntId = () => randomId("hunt");
export const newPlaybookId = () => randomId("pb");

export function emptyHunt(): Hunt {
  const now = new Date().toISOString();
  return {
    id: newHuntId(),
    title: "Untitled Hunt",
    hypothesis: "",
    techniques: [],
    dataSources: [],
    queries: "",
    findings: "",
    iocs: [],
    status: "open",
    priority: "medium",
    createdAt: now,
    updatedAt: now,
  };
}

/** True once a recurring hunt's revisit interval has elapsed since it was last saved. */
export function isDueForReview(hunt: Hunt): boolean {
  if (!hunt.recurringDays || hunt.recurringDays <= 0) return false;
  return daysSince(hunt.updatedAt) >= hunt.recurringDays;
}

export function huntFromPlaybook(pb: Playbook): Hunt {
  const hunt = emptyHunt();
  hunt.title = pb.title;
  hunt.hypothesis = pb.description;
  hunt.techniques = [...pb.techniques];
  hunt.queries = pb.suggestedQuery;
  return hunt;
}

// -----------------------------------------------------------------------
// Coverage (MITRE ATT&CK) + staleness
// -----------------------------------------------------------------------
export type CoverageStatus = "never" | "open" | "closed";

export interface TechniqueCoverage {
  techniqueId: string;
  hunts: Hunt[];
  status: CoverageStatus;
  lastHuntedAt: string | null;
}

export function computeCoverage(hunts: Hunt[], techniqueIds: string[]): TechniqueCoverage[] {
  return techniqueIds.map((id) => {
    // A hunt tagged with a sub-technique (e.g. "T1059.001") also counts
    // toward its parent's coverage (e.g. "T1059").
    const related = hunts.filter((h) => h.techniques.some((t) => tagCoversTechnique(t, id)));
    let status: CoverageStatus = "never";
    if (related.some((h) => h.status === "closed")) status = "closed";
    else if (related.length > 0) status = "open";
    const lastHuntedAt =
      related.length > 0 ? related.map((h) => h.updatedAt).sort().slice(-1)[0] : null;
    return { techniqueId: id, hunts: related, status, lastHuntedAt };
  });
}

export function daysSince(iso: string): number {
  return Math.floor((Date.now() - new Date(iso).getTime()) / 86_400_000);
}

// A "closed" technique fades over time rather than staying a flat green
// forever — hunted-yesterday and hunted-six-months-ago shouldn't look the
// same on the coverage grid.
export type CoverageFreshness = "fresh" | "aging" | "stale";

export function coverageFreshness(lastHuntedAt: string | null): CoverageFreshness {
  if (!lastHuntedAt) return "fresh";
  const days = daysSince(lastHuntedAt);
  if (days >= 90) return "stale";
  if (days >= 30) return "aging";
  return "fresh";
}

// -----------------------------------------------------------------------
// Mileage-style stats
// -----------------------------------------------------------------------
export interface HuntStats {
  total: number;
  open: number;
  inProgress: number;
  closed: number;
  techniquesCovered: number;
  techniquesTotal: number;
  avgTimeToCloseHours: number | null;
  dueForReview: number;
}

export function computeHuntStats(hunts: Hunt[], totalTechniques: number): HuntStats {
  const open = hunts.filter((h) => h.status === "open").length;
  const inProgress = hunts.filter((h) => h.status === "in_progress").length;
  const closed = hunts.filter((h) => h.status === "closed").length;
  const techniquesCovered = new Set(hunts.flatMap((h) => h.techniques)).size;
  const closedWithTimes = hunts.filter((h) => h.status === "closed" && h.closedAt);
  const avgTimeToCloseHours =
    closedWithTimes.length > 0
      ? closedWithTimes.reduce(
          (sum, h) => sum + (new Date(h.closedAt!).getTime() - new Date(h.createdAt).getTime()),
          0,
        ) /
        closedWithTimes.length /
        3_600_000
      : null;
  return {
    total: hunts.length,
    open,
    inProgress,
    closed,
    techniquesCovered,
    techniquesTotal: totalTechniques,
    avgTimeToCloseHours,
    dueForReview: hunts.filter(isDueForReview).length,
  };
}

// -----------------------------------------------------------------------
// Findings -> IOCs, and report export
// -----------------------------------------------------------------------
export function extractHuntIocs(hunt: Hunt): IocMatch[] {
  return extractIocs(hunt.findings);
}

function techniqueLabel(id: string): string {
  const t = mitreEntryById(id);
  return t ? `${id} — ${t.name}` : id;
}

export function buildHuntReport(hunt: Hunt): string {
  const techniqueLines = hunt.techniques.length ? hunt.techniques.map(techniqueLabel).join(", ") : "(none tagged)";

  const lines: string[] = [
    "=== THREAT HUNT REPORT ===",
    `Title: ${hunt.title}`,
    `Status: ${HUNT_STATUS_LABELS[hunt.status]}`,
    `Priority: ${HUNT_PRIORITY_LABELS[hunt.priority]}`,
    `Created: ${hunt.createdAt}`,
    `Updated: ${hunt.updatedAt}`,
  ];
  if (hunt.closedAt) lines.push(`Closed: ${hunt.closedAt}`);
  if (hunt.recurringDays) lines.push(`Recurring: every ${hunt.recurringDays} day(s)`);
  lines.push(`MITRE ATT&CK Techniques: ${techniqueLines}`, "");
  lines.push("--- HYPOTHESIS ---", hunt.hypothesis || "(none)", "");
  lines.push(
    "--- DATA SOURCES ---",
    hunt.dataSources.length ? hunt.dataSources.map((s) => `- ${s}`).join("\n") : "(none)",
    "",
  );
  lines.push("--- QUERIES ---", hunt.queries.trim() || "(none)", "");
  lines.push("--- FINDINGS ---", hunt.findings || "(none)", "");
  lines.push(
    "--- IOCs ---",
    hunt.iocs.length ? hunt.iocs.map((i) => `${IOC_LABELS[i.type]}: ${i.value}`).join("\n") : "(none)",
  );
  return lines.join("\n");
}

/** One combined report of every hunt, newest-updated first. */
export function buildAllHuntsReport(hunts: Hunt[]): string {
  const sorted = [...hunts].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  const header = `=== ALL THREAT HUNTS (${sorted.length}) — exported ${new Date().toISOString()} ===\n`;
  return header + sorted.map(buildHuntReport).join("\n\n" + "=".repeat(60) + "\n\n");
}

// -----------------------------------------------------------------------
// Backup / restore (JSON export of everything, merge-on-import so a restore
// never silently clobbers hunts created after the backup was taken)
// -----------------------------------------------------------------------
export interface HuntsBackup {
  exportedAt: string;
  hunts: Hunt[];
  playbooks: Playbook[];
}

export function buildBackup(hunts: Hunt[], playbooks: Playbook[]): string {
  const backup: HuntsBackup = { exportedAt: new Date().toISOString(), hunts, playbooks };
  return JSON.stringify(backup, null, 2);
}

/** Parses and loosely validates a backup file's contents. Returns null if it doesn't look like one. */
export function parseBackup(json: string): HuntsBackup | null {
  try {
    const data = JSON.parse(json);
    if (!data || !Array.isArray(data.hunts) || !Array.isArray(data.playbooks)) return null;
    return data as HuntsBackup;
  } catch {
    return null;
  }
}

export interface MergeResult<T> {
  merged: T[];
  addedCount: number;
  skippedCount: number;
}

/** Adds any imported record whose id isn't already present; never overwrites an existing one. */
export function mergeById<T extends { id: string }>(existing: T[], imported: T[]): MergeResult<T> {
  const existingIds = new Set(existing.map((r) => r.id));
  const toAdd = imported.filter((r) => !existingIds.has(r.id));
  return { merged: [...existing, ...toAdd], addedCount: toAdd.length, skippedCount: imported.length - toAdd.length };
}

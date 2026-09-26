// Threat hunt tracking — local-only (localStorage), same pattern as the rest
// of ThreatPad's storage layer. A "hunt" is a structured record of one
// hypothesis-driven investigation, tracked through a pipeline (kanban-style)
// from first idea to closed, with a service-ticket-style activity log for
// running notes.

import { extractIocs, IOC_LABELS, type IocMatch } from "./iocPatterns";
import { mitreEntryById, tagCoversTechnique } from "./mitre";

export type HuntStage =
  | "ideas"
  | "hypothesis"
  | "research"
  | "hunting"
  | "results"
  | "disclosure"
  | "recurring"
  | "closed";

export interface HuntStageDef {
  id: HuntStage;
  label: string;
  icon: string;
  color: string;
}

// Order here is the pipeline order — drives the kanban board's column order
// and the ticket page's stage-pill stepper.
export const HUNT_STAGES: HuntStageDef[] = [
  { id: "ideas", label: "Ideas", icon: "💡", color: "#8a97ad" },
  { id: "hypothesis", label: "Hypothesis", icon: "🧭", color: "#0b6ecb" },
  { id: "research", label: "Research", icon: "🔎", color: "#7c3aed" },
  { id: "hunting", label: "Hunting", icon: "🎯", color: "#f5a524" },
  { id: "results", label: "Results", icon: "📊", color: "#14b8a6" },
  { id: "disclosure", label: "Disclosure", icon: "📣", color: "#ec4899" },
  { id: "recurring", label: "Recurring", icon: "🔁", color: "#06b6d4" },
  { id: "closed", label: "Closed", icon: "✅", color: "#22c55e" },
];

export const HUNT_STAGE_LABELS: Record<HuntStage, string> = Object.fromEntries(
  HUNT_STAGES.map((s) => [s.id, s.label]),
) as Record<HuntStage, string>;

export const HUNT_STAGE_COLORS: Record<HuntStage, string> = Object.fromEntries(
  HUNT_STAGES.map((s) => [s.id, s.color]),
) as Record<HuntStage, string>;

const STAGE_ORDER: HuntStage[] = HUNT_STAGES.map((s) => s.id);
export function stageIndex(stage: HuntStage): number {
  return STAGE_ORDER.indexOf(stage);
}
export function stageAtOffset(stage: HuntStage, offset: number): HuntStage | null {
  const next = stageIndex(stage) + offset;
  return next >= 0 && next < STAGE_ORDER.length ? STAGE_ORDER[next] : null;
}

// A technique only counts as "covered" on the Coverage grid once a hunt
// about it has produced something — earlier pipeline stages are still
// in-progress (amber), not done.
const COVERING_STAGES: HuntStage[] = ["results", "disclosure", "recurring", "closed"];
export function stageCoverageStatus(stage: HuntStage): "open" | "closed" {
  return COVERING_STAGES.includes(stage) ? "closed" : "open";
}

export type HuntPriority = "low" | "medium" | "high";

export const HUNT_PRIORITY_LABELS: Record<HuntPriority, string> = {
  low: "Low",
  medium: "Medium",
  high: "High",
};

export interface ActivityEntry {
  timestamp: string;
  text: string;
}

export interface Hunt {
  id: string;
  ticketNo: number; // stable display number, e.g. "#HT-007"
  title: string;
  hypothesis: string;
  techniques: string[]; // MITRE technique or sub-technique IDs, e.g. "T1059" or "T1059.001"
  dataSources: string[];
  queries: string; // freeform KQL/query text, one or more queries
  findings: string;
  iocs: IocMatch[]; // snapshot captured from findings via "Extract IOCs"
  activityLog: ActivityEntry[]; // running, append-only notes/updates — like ticket comments
  stage: HuntStage;
  priority: HuntPriority;
  recurringDays?: number; // if set, this hunt is due again `recurringDays` after updatedAt
  createdAt: string;
  updatedAt: string;
  closedAt?: string;
  intelId?: string; // set when this hunt was created from an imported threat-intel feed item, for dedup
}

export function ticketLabel(hunt: Hunt): string {
  return `#HT-${String(hunt.ticketNo).padStart(3, "0")}`;
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
  huntSeq: "threatpad:huntSeq",
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

function nextTicketNo(): number {
  const n = read<number>(KEYS.huntSeq, 0) + 1;
  write(KEYS.huntSeq, n);
  return n;
}

// Pre-pipeline hunts only had a 3-value status; map it onto the new 8-stage
// pipeline so hunts created before this feature don't just vanish.
function migrateLegacyStage(legacyStatus: unknown): HuntStage {
  switch (legacyStatus) {
    case "closed":
      return "closed";
    case "in_progress":
      return "hunting";
    default:
      return "hypothesis";
  }
}

/** Backfills any fields a hunt from an older version of the app is missing. */
function normalizeHunt(raw: Record<string, unknown>): Hunt {
  const stage = typeof raw.stage === "string" ? (raw.stage as HuntStage) : migrateLegacyStage(raw.status);
  const ticketNo = typeof raw.ticketNo === "number" ? raw.ticketNo : nextTicketNo();
  return {
    id: raw.id as string,
    ticketNo,
    title: (raw.title as string) ?? "Untitled Hunt",
    hypothesis: (raw.hypothesis as string) ?? "",
    techniques: Array.isArray(raw.techniques) ? (raw.techniques as string[]) : [],
    dataSources: Array.isArray(raw.dataSources) ? (raw.dataSources as string[]) : [],
    queries: (raw.queries as string) ?? "",
    findings: (raw.findings as string) ?? "",
    iocs: Array.isArray(raw.iocs) ? (raw.iocs as IocMatch[]) : [],
    activityLog: Array.isArray(raw.activityLog) ? (raw.activityLog as ActivityEntry[]) : [],
    stage,
    priority: (raw.priority as HuntPriority) ?? "medium",
    recurringDays: typeof raw.recurringDays === "number" ? raw.recurringDays : undefined,
    createdAt: (raw.createdAt as string) ?? new Date().toISOString(),
    updatedAt: (raw.updatedAt as string) ?? new Date().toISOString(),
    closedAt: raw.closedAt as string | undefined,
    intelId: raw.intelId as string | undefined,
  };
}

export function loadHunts(): Hunt[] {
  const raw = read<Record<string, unknown>[]>(KEYS.hunts, []);
  let touched = false;
  const hunts = raw.map((h) => {
    if (typeof h.stage !== "string" || typeof h.ticketNo !== "number") touched = true;
    return normalizeHunt(h);
  });
  if (touched) saveHunts(hunts); // persist backfilled ticketNo/stage so they stay stable
  return hunts;
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
    ticketNo: nextTicketNo(),
    title: "Untitled Hunt",
    hypothesis: "",
    techniques: [],
    dataSources: [],
    queries: "",
    findings: "",
    iocs: [],
    activityLog: [],
    stage: "ideas",
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

/** Moves a hunt to `stage`, keeping closedAt in sync (set on entering "closed", cleared on leaving it). */
export function setHuntStage(hunt: Hunt, stage: HuntStage): void {
  if (hunt.stage === stage) return;
  const wasClosed = hunt.stage === "closed";
  hunt.stage = stage;
  if (stage === "closed" && !wasClosed) hunt.closedAt = new Date().toISOString();
  if (stage !== "closed") hunt.closedAt = undefined;
  hunt.updatedAt = new Date().toISOString();
}

export function huntFromPlaybook(pb: Playbook): Hunt {
  const hunt = emptyHunt();
  hunt.title = pb.title;
  hunt.hypothesis = pb.description;
  hunt.techniques = [...pb.techniques];
  hunt.queries = pb.suggestedQuery;
  hunt.stage = "hypothesis"; // a playbook already supplies the hypothesis + a starting query
  return hunt;
}

// -----------------------------------------------------------------------
// Threat-intel feed import — a static JSON file (published alongside
// ThreatPad, not part of its own build output) that an external process,
// e.g. a scheduled daily CTI task, can drop new Ideas-stage hunts into.
// ThreatPad only ever reads this on an explicit user click — never
// automatically or in the background.
// -----------------------------------------------------------------------
export interface IntelFeedItem {
  id: string; // stable, unique — reused across days to avoid re-importing the same item
  title: string;
  summary?: string;
  sourceName?: string;
  sourceUrl?: string;
  date?: string;
  techniques?: string[];
  suggestedQuery?: string;
}

export interface IntelFeed {
  generatedAt?: string;
  items: IntelFeedItem[];
}

/** Parses and loosely validates a fetched feed. Returns null if it doesn't look like one. */
export function parseIntelFeed(json: string): IntelFeed | null {
  try {
    const data = JSON.parse(json);
    if (!data || !Array.isArray(data.items)) return null;
    return data as IntelFeed;
  } catch {
    return null;
  }
}

export function huntFromIntelItem(item: IntelFeedItem): Hunt {
  const hunt = emptyHunt();
  hunt.title = item.title;
  const sourceLine = item.sourceUrl ? `\n\nSource: ${item.sourceName ?? "link"} — ${item.sourceUrl}` : "";
  hunt.hypothesis = `${item.summary ?? ""}${sourceLine}`.trim();
  hunt.techniques = (item.techniques ?? []).filter((id) => mitreEntryById(id));
  hunt.queries = item.suggestedQuery ?? "";
  hunt.stage = "ideas";
  hunt.intelId = item.id;
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
    if (related.some((h) => stageCoverageStatus(h.stage) === "closed")) status = "closed";
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
  byStage: Record<HuntStage, number>;
  techniquesCovered: number;
  techniquesTotal: number;
  avgTimeToCloseHours: number | null;
  dueForReview: number;
}

export function computeHuntStats(hunts: Hunt[], totalTechniques: number): HuntStats {
  const byStage = Object.fromEntries(HUNT_STAGES.map((s) => [s.id, 0])) as Record<HuntStage, number>;
  for (const h of hunts) byStage[h.stage] = (byStage[h.stage] ?? 0) + 1;
  const techniquesCovered = new Set(hunts.flatMap((h) => h.techniques)).size;
  const closedWithTimes = hunts.filter((h) => h.stage === "closed" && h.closedAt);
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
    byStage,
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
  const stageDef = HUNT_STAGES.find((s) => s.id === hunt.stage);

  const lines: string[] = [
    `=== THREAT HUNT REPORT ${ticketLabel(hunt)} ===`,
    `Title: ${hunt.title}`,
    `Stage: ${stageDef ? `${stageDef.icon} ${stageDef.label}` : hunt.stage}`,
    `Priority: ${HUNT_PRIORITY_LABELS[hunt.priority]}`,
    `Created: ${hunt.createdAt}`,
    `Updated: ${hunt.updatedAt}`,
  ];
  if (hunt.closedAt) lines.push(`Closed: ${hunt.closedAt}`);
  if (hunt.recurringDays) lines.push(`Recurring: every ${hunt.recurringDays} day(s)`);
  if (hunt.intelId) lines.push(`Origin: imported from daily threat-intel feed (${hunt.intelId})`);
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
    "",
  );
  lines.push(
    "--- ACTIVITY LOG ---",
    hunt.activityLog.length
      ? [...hunt.activityLog].reverse().map((e) => `[${e.timestamp}] ${e.text}`).join("\n")
      : "(no notes yet)",
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
    return { exportedAt: data.exportedAt, hunts: data.hunts.map(normalizeHunt), playbooks: data.playbooks };
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

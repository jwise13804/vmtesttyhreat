// Everything here is local-only (localStorage) by design — no network calls,
// matching the single-user/local-only scope for the ThreatPad web port.

import type { ClientMap } from "./clients";

export interface TabState {
  id: string;
  title: string;
  content: string;
}

export interface SessionState {
  tabs: TabState[];
  activeTabId: string | null;
}

export interface Settings {
  darkMode: boolean;
  lineNumbers: boolean;
  wordWrap: boolean;
  fontSize: number;
  iocHighlighting: boolean;
  trainingWheelsEnabled: boolean;
  sidebarHidden: boolean;
}

export const DEFAULT_SETTINGS: Settings = {
  darkMode: true,
  lineNumbers: true,
  wordWrap: true,
  fontSize: 13,
  iocHighlighting: true,
  trainingWheelsEnabled: false,
  sidebarHidden: false,
};

export interface Mileage {
  sessionStart: string;
  defangs: number;
  iocsExtracted: number;
  copies: number;
  nearMisses: number;
  contaminationChecks: number;
  breakglassEvents: number;
}

export function defaultMileage(): Mileage {
  return {
    sessionStart: new Date().toISOString(),
    defangs: 0,
    iocsExtracted: 0,
    copies: 0,
    nearMisses: 0,
    contaminationChecks: 0,
    breakglassEvents: 0,
  };
}

export const DEFAULT_TEMPLATES: Record<string, string> = {
  "Phishing Investigation":
    "=== PHISHING INVESTIGATION ===\nDate: {date}\nAnalyst: \n\nSubject Line:\nSender:\nRecipients:\n\n--- ANALYSIS ---\n\n--- VERDICT ---\nPhishing: [YES/NO]\nAction Taken:\n\n",
  "Malware Analysis":
    "=== MALWARE ANALYSIS ===\nDate: {date}\nAnalyst: \n\nSample Hash:\nFile Name:\nFile Type:\n\n--- BEHAVIORAL ANALYSIS ---\n\n--- NETWORK INDICATORS ---\n\n--- CONCLUSION ---\n\n",
  "Security Incident Report":
    "=== SECURITY INCIDENT REPORT ===\nIncident ID: \nDate/Time: {datetime}\nSeverity: [LOW/MEDIUM/HIGH/CRITICAL]\nStatus: [OPEN/INVESTIGATING/RESOLVED]\n\n--- INCIDENT SUMMARY ---\n\n--- AFFECTED SYSTEMS ---\n\n--- INDICATORS OF COMPROMISE ---\n\n--- ACTIONS TAKEN ---\n\n--- RECOMMENDATIONS ---\n\n",
};

export const DEFAULT_SNIPPETS: Record<string, string> = {
  "Incident Header":
    "=== INCIDENT ANALYSIS ===\nDate: {date}\nAnalyst: \nSeverity: [LOW/MEDIUM/HIGH/CRITICAL]\n\n",
  "IOC Section":
    "\n--- INDICATORS OF COMPROMISE (IOCs) ---\nIPs:\n- \n\nDomains:\n- \n\nHashes:\n- \n\nURLs:\n- \n\n",
  Timeline: "\n--- TIMELINE ---\n[TIME] Event description\n[TIME] Event description\n\n",
  Remediation: "\n--- REMEDIATION STEPS ---\n1. \n2. \n3. \n\n",
  "Executive Summary":
    "\n--- EXECUTIVE SUMMARY ---\nThreat Level: \nImpact: \nRecommended Actions: \n\n",
};

const KEYS = {
  session: "threatpad:session",
  settings: "threatpad:settings",
  templates: "threatpad:templates",
  snippets: "threatpad:snippets",
  kqlSnippets: "threatpad:kqlSnippets",
  clients: "threatpad:clients",
  activeClient: "threatpad:activeClient",
  mileage: "threatpad:mileage",
} as const;

function read<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return fallback;
    return { ...fallback, ...JSON.parse(raw) };
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

export function loadSession(): SessionState | null {
  try {
    const raw = localStorage.getItem(KEYS.session);
    return raw ? (JSON.parse(raw) as SessionState) : null;
  } catch {
    return null;
  }
}
export const saveSession = (state: SessionState) => write(KEYS.session, state);

export const loadSettings = (): Settings => read(KEYS.settings, DEFAULT_SETTINGS);
export const saveSettings = (settings: Settings) => write(KEYS.settings, settings);

export function loadTemplates(): Record<string, string> {
  try {
    const raw = localStorage.getItem(KEYS.templates);
    if (!raw) {
      saveTemplates(DEFAULT_TEMPLATES);
      return { ...DEFAULT_TEMPLATES };
    }
    return JSON.parse(raw) as Record<string, string>;
  } catch {
    return { ...DEFAULT_TEMPLATES };
  }
}
export const saveTemplates = (templates: Record<string, string>) =>
  write(KEYS.templates, templates);

export function loadSnippets(): Record<string, string> {
  try {
    const raw = localStorage.getItem(KEYS.snippets);
    if (!raw) {
      saveSnippets(DEFAULT_SNIPPETS);
      return { ...DEFAULT_SNIPPETS };
    }
    return JSON.parse(raw) as Record<string, string>;
  } catch {
    return { ...DEFAULT_SNIPPETS };
  }
}
export const saveSnippets = (snippets: Record<string, string>) => write(KEYS.snippets, snippets);

export function loadKqlSnippets(): Record<string, string> {
  try {
    const raw = localStorage.getItem(KEYS.kqlSnippets);
    return raw ? (JSON.parse(raw) as Record<string, string>) : {};
  } catch {
    return {};
  }
}
export const saveKqlSnippets = (kqlSnippets: Record<string, string>) =>
  write(KEYS.kqlSnippets, kqlSnippets);

export function loadClients(): ClientMap {
  try {
    const raw = localStorage.getItem(KEYS.clients);
    return raw ? (JSON.parse(raw) as ClientMap) : {};
  } catch {
    return {};
  }
}
export const saveClients = (clients: ClientMap) => write(KEYS.clients, clients);

export function loadActiveClient(): string {
  try {
    return localStorage.getItem(KEYS.activeClient) ?? "";
  } catch {
    return "";
  }
}
export function saveActiveClient(name: string): void {
  try {
    localStorage.setItem(KEYS.activeClient, name);
  } catch (e) {
    console.error("Failed to persist active client", e);
  }
}

export function loadMileage(): Mileage {
  try {
    const raw = localStorage.getItem(KEYS.mileage);
    if (!raw) return defaultMileage();
    return { ...defaultMileage(), ...JSON.parse(raw) };
  } catch {
    return defaultMileage();
  }
}
export const saveMileage = (mileage: Mileage) => write(KEYS.mileage, mileage);

export function fillPlaceholders(content: string): string {
  const now = new Date();
  const date = now.toISOString().slice(0, 10);
  const time = now.toTimeString().slice(0, 8);
  return content
    .replaceAll("{date}", date)
    .replaceAll("{time}", time)
    .replaceAll("{datetime}", `${date} ${time}`);
}

// Ported from self._action_log / _log_action() in src/threatpad.py. In-memory
// only (a browser tab reload resets it, same as launching the Python app
// fresh each time) — capped at 500 entries, FIFO eviction.

export interface ActionLogEntry {
  time: string; // HH:MM:SS
  action: string;
  detail: string;
  client: string;
}

const MAX_ENTRIES = 500;
let log: ActionLogEntry[] = [];

export function logAction(action: string, detail = "", client = ""): void {
  log.push({
    time: new Date().toTimeString().slice(0, 8),
    action,
    detail: detail.slice(0, 200),
    client,
  });
  if (log.length > MAX_ENTRIES) log = log.slice(-MAX_ENTRIES);
}

export function getActionLog(): readonly ActionLogEntry[] {
  return log;
}

export function clearActionLog(): void {
  log = [];
}

/** Ported from _analyse_mistake_patterns() — proactive "you keep doing X" detection. */
export function analyseMistakePatterns(): string[] {
  if (log.length < 5) return [];
  const warnings: string[] = [];

  const nearMisses = log.filter((e) => e.action === "near_miss_defang").length;
  if (nearMisses >= 3) {
    warnings.push(
      `You've overridden the defang warning ${nearMisses} times this session — consider defanging before copying.`,
    );
  }

  const contamination = log.filter((e) => e.action === "contamination_found").length;
  if (contamination >= 2) {
    warnings.push(
      `Contamination was detected ${contamination} times this session — review your client identifier configuration.`,
    );
  }

  const noClientCopies = log.filter((e) => e.action === "copy" && !e.client).length;
  if (noClientCopies >= 2) {
    warnings.push(
      `You've copied text ${noClientCopies} times with no active client selected — make a habit of selecting a client first.`,
    );
  }

  return warnings;
}

import { TabManager } from "../editor/tabs";
import { analyseMistakePatterns, clearActionLog, getActionLog, logAction } from "../core/actionLog";
import {
  type ClientMap,
  type ContaminationFinding,
  emptyClient,
  hasLiveIocs,
  scanForContamination,
} from "../core/clients";
import { computeHuntStats, loadHunts } from "../core/hunts";
import { MITRE_TECHNIQUES } from "../core/mitre";
import { TrainingWheelsPanel } from "./trainingWheels";
import {
  defaultMileage,
  loadActiveClient,
  loadClients,
  loadMileage,
  saveActiveClient,
  saveClients,
  saveMileage,
  type Mileage,
  type Settings,
} from "../core/storage";

export interface Phase3Context {
  tabs: TabManager;
  flashStatus: (msg: string) => void;
  openModal: (title: string, bodyHtml: string, opts?: { wide?: boolean }) => void;
  closeModal: () => void;
  escapeHtml: (s: string) => string;
  getSettings: () => Settings;
  patchSettings: (patch: Partial<Settings>) => void;
}

export interface Phase3Hooks {
  onDefang: () => void;
  onExtractIocs: (count: number) => void;
  onTabClosed: (id: string) => void;
  onTextChanged: () => void;
  getActiveClient: () => string;
}

function escapeAttr(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/"/g, "&quot;");
}

export function initPhase3(ctx: Phase3Context): Phase3Hooks {
  const { tabs, flashStatus, openModal, closeModal, escapeHtml } = ctx;

  let clients: ClientMap = loadClients();
  let activeClient = loadActiveClient();
  let mileage: Mileage = loadMileage();
  const tabStartTimes = new Map<string, number>();

  const clientSelect = document.querySelector<HTMLSelectElement>("#client-select")!;
  const trafficLight = document.querySelector<HTMLSpanElement>("#traffic-light")!;
  const timerDisplay = document.querySelector<HTMLSpanElement>("#timer-display")!;
  const twPanel = document.querySelector<HTMLDivElement>("#tw-panel")!;

  // -------------------------------------------------------------------------
  // Client selector
  // -------------------------------------------------------------------------
  function renderClientSelect() {
    const names = Object.keys(clients).sort();
    clientSelect.innerHTML =
      `<option value="">— No Client —</option>` +
      names.map((n) => `<option value="${escapeAttr(n)}" ${n === activeClient ? "selected" : ""}>${escapeHtml(n)}</option>`).join("");
  }
  renderClientSelect();

  clientSelect.addEventListener("change", () => {
    activeClient = clientSelect.value;
    saveActiveClient(activeClient);
    logAction("client_selected", activeClient || "(none)", activeClient);
    flashStatus(activeClient ? `Active client: ${activeClient}` : "No active client");
    updateTrafficLight();
  });

  // -------------------------------------------------------------------------
  // Client management modal
  // -------------------------------------------------------------------------
  function openClientManager() {
    const names = Object.keys(clients).sort();
    openModal(
      "Manage Clients",
      `
      <div style="display:flex;gap:10px;">
        <div style="width:140px;">
          <select id="cm-list" size="8" style="width:100%;">
            ${names.map((n) => `<option value="${escapeAttr(n)}">${escapeHtml(n)}</option>`).join("")}
          </select>
          <button id="cm-add" style="width:100%;margin-top:6px;">+ Add</button>
          <button id="cm-delete" style="width:100%;margin-top:4px;">Delete</button>
        </div>
        <div style="flex:1;">
          <label style="display:block;font-size:12px;margin-bottom:2px;">Email domains (one per line)</label>
          <textarea class="snippet-editor" id="cm-domains"></textarea>
          <label style="display:block;font-size:12px;margin:6px 0 2px;">Hostname prefixes</label>
          <textarea class="snippet-editor" id="cm-hosts"></textarea>
          <label style="display:block;font-size:12px;margin:6px 0 2px;">IP ranges (CIDR)</label>
          <textarea class="snippet-editor" id="cm-ips"></textarea>
          <label style="display:block;font-size:12px;margin:6px 0 2px;">Keywords</label>
          <textarea class="snippet-editor" id="cm-keywords"></textarea>
        </div>
      </div>
      <div class="modal-actions">
        <button class="primary" id="cm-save">Save Identifiers</button>
        <button id="cm-close">Close</button>
      </div>
    `,
      { wide: true },
    );

    const listEl = document.querySelector<HTMLSelectElement>("#cm-list")!;
    const domainsEl = document.querySelector<HTMLTextAreaElement>("#cm-domains")!;
    const hostsEl = document.querySelector<HTMLTextAreaElement>("#cm-hosts")!;
    const ipsEl = document.querySelector<HTMLTextAreaElement>("#cm-ips")!;
    const keywordsEl = document.querySelector<HTMLTextAreaElement>("#cm-keywords")!;

    function loadIntoForm(name: string) {
      const c = clients[name] ?? emptyClient();
      domainsEl.value = c.emailDomains.join("\n");
      hostsEl.value = c.hostnamePrefixes.join("\n");
      ipsEl.value = c.ipRanges.join("\n");
      keywordsEl.value = c.keywords.join("\n");
    }
    if (names.length > 0) {
      listEl.selectedIndex = 0;
      loadIntoForm(names[0]);
    }
    listEl.addEventListener("change", () => loadIntoForm(listEl.value));

    document.querySelector("#cm-add")!.addEventListener("click", () => {
      const name = prompt("New client name:");
      if (!name || !name.trim()) return;
      if (clients[name]) return alert("A client with that name already exists.");
      clients[name] = emptyClient();
      saveClients(clients);
      renderClientSelect();
      openClientManager();
    });
    document.querySelector("#cm-delete")!.addEventListener("click", () => {
      const name = listEl.value;
      if (!name) return;
      if (!confirm(`Delete client "${name}"? This cannot be undone.`)) return;
      delete clients[name];
      saveClients(clients);
      if (activeClient === name) {
        activeClient = "";
        saveActiveClient("");
      }
      renderClientSelect();
      openClientManager();
    });
    document.querySelector("#cm-save")!.addEventListener("click", () => {
      const name = listEl.value;
      if (!name) return alert("Select or add a client first.");
      const parseLines = (v: string) => v.split("\n").map((l) => l.trim()).filter(Boolean);
      clients[name] = {
        emailDomains: parseLines(domainsEl.value),
        hostnamePrefixes: parseLines(hostsEl.value),
        ipRanges: parseLines(ipsEl.value),
        keywords: parseLines(keywordsEl.value),
      };
      saveClients(clients);
      flashStatus(`Saved identifiers for ${name}`);
    });
    document.querySelector("#cm-close")!.addEventListener("click", closeModal);
  }
  document.querySelector("#btn-manage-clients")!.addEventListener("click", openClientManager);

  // -------------------------------------------------------------------------
  // Contamination check
  // -------------------------------------------------------------------------
  function runContaminationCheck() {
    if (!activeClient) {
      openModal("Select a Client First", `<p style="font-size:13px;">Select an active client before running a contamination check.</p>`);
      return;
    }
    if (Object.keys(clients).filter((n) => n !== activeClient).length === 0) {
      openModal("No Other Clients", `<p style="font-size:13px;">No other clients are registered, so there's nothing to check against.</p>`);
      return;
    }
    const findings = scanForContamination(tabs.getContent(), clients, activeClient);
    mileage.contaminationChecks++;
    saveMileage(mileage);
    if (findings.length === 0) {
      logAction("contamination_check_clean", "", activeClient);
      flashStatus("No contamination detected");
      openModal("Clean", `<p style="font-size:13px;">No cross-client contamination detected in the active tab.</p>`);
      return;
    }
    logAction("contamination_found", findings.slice(0, 3).map((f) => f.matchedText).join(", "), activeClient);
    flashStatus(`⚠ ${findings.length} contamination match(es) found`);
    showContaminationReport(findings);
  }
  document.querySelector("#btn-contamination-check")!.addEventListener("click", runContaminationCheck);

  function showContaminationReport(findings: ContaminationFinding[]) {
    const rows = findings
      .map(
        (f) =>
          `<tr><td>${f.line}</td><td>${escapeHtml(f.matchedText)}</td><td>${escapeHtml(f.type)}</td><td>${escapeHtml(f.client)}</td></tr>`,
      )
      .join("");
    openModal(
      `⚠ ${findings.length} Contamination Match(es) — active client: ${activeClient}`,
      `
      <div style="max-height:320px;overflow:auto;">
        <table class="report-table">
          <thead><tr><th>Line</th><th>Matched Value</th><th>Identifier Type</th><th>Belongs To</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      <div class="modal-actions">
        <button id="cr-copy">Copy Report</button>
        <button class="primary" id="cr-close">Close</button>
      </div>
    `,
    );
    document.querySelector("#cr-copy")!.addEventListener("click", () => {
      const text = findings.map((f) => `Line ${f.line}: "${f.matchedText}" (${f.type}) belongs to ${f.client}`).join("\n");
      navigator.clipboard.writeText(text);
      flashStatus("Contamination report copied");
    });
    document.querySelector("#cr-close")!.addEventListener("click", closeModal);
  }

  // -------------------------------------------------------------------------
  // Safe Copy
  // -------------------------------------------------------------------------
  function safeCopy() {
    const text = tabs.getContent();
    if (!text.trim()) return flashStatus("Nothing to copy");

    if (activeClient) {
      const findings = scanForContamination(text, clients, activeClient);
      if (findings.length > 0) {
        logAction("contamination_found", findings.slice(0, 3).map((f) => f.matchedText).join(", "), activeClient);
        openModal(
          "Cross-Client Contamination Detected — Copy Blocked",
          `<p style="font-size:13px;">This note contains ${findings.length} identifier(s) belonging to other clients. Copy has been blocked to prevent cross-client data leakage. Run "⚠ Check" for details.</p>`,
        );
        return;
      }
    }

    if (hasLiveIocs(text)) {
      logAction("near_miss_defang", "", activeClient);
      mileage.nearMisses++;
      saveMileage(mileage);
      if (!confirm("This note contains undefanged (live) IOCs. Copy anyway?")) {
        flashStatus("Copy cancelled — defang before copying");
        return;
      }
    }

    navigator.clipboard.writeText(text);
    logAction("copy", "", activeClient);
    mileage.copies++;
    saveMileage(mileage);
    flashStatus("Copied (safe copy)");
  }
  document.querySelector("#btn-safe-copy")!.addEventListener("click", safeCopy);

  // -------------------------------------------------------------------------
  // Training Wheels
  // -------------------------------------------------------------------------
  const trainingWheels = new TrainingWheelsPanel(twPanel, {
    onInsertNote: (note) => {
      tabs.insertAtCursor(`\n${note}\n`);
      flashStatus("Incident note inserted into active tab");
    },
    onCopyNote: () => flashStatus("Incident note copied to clipboard"),
    onStatus: flashStatus,
  });
  trainingWheels.setVisible(ctx.getSettings().trainingWheelsEnabled);

  document.querySelector("#btn-training-wheels")!.addEventListener("click", () => {
    const next = !trainingWheels.isVisible();
    trainingWheels.setVisible(next);
    ctx.patchSettings({ trainingWheelsEnabled: next });
  });

  // -------------------------------------------------------------------------
  // Breakglass
  // -------------------------------------------------------------------------
  function buildBreakglassPrompts(): string {
    const log = getActionLog();
    const prompts: string[] = [];

    const nearMisses = log.filter((e) => e.action === "near_miss_defang");
    if (nearMisses.length > 0) {
      const last = nearMisses[nearMisses.length - 1];
      prompts.push(
        `⚠️ DEFANG WARNING OVERRIDDEN at ${last.time} — check whether that note was already pasted into a ticket, and defang it now if so.`,
      );
    }
    const contamination = log.filter((e) => e.action === "contamination_found");
    if (contamination.length > 0) {
      const last = contamination[contamination.length - 1];
      prompts.push(
        `⚠️ CONTAMINATION DETECTED at ${last.time} (${escapeHtml(last.detail)}) — review anything copied from that tab since.`,
      );
    }
    const distinctClients = new Set(log.map((e) => e.client).filter(Boolean));
    if (distinctClients.size > 1) {
      prompts.push(`⚠️ Multiple clients (${distinctClients.size}) active this session — verify each tab matches its correct client.`);
    }
    const noClientCopies = log.filter((e) => e.action === "copy" && !e.client).length;
    if (noClientCopies > 0) {
      prompts.push(`⚠️ ${noClientCopies} copy action(s) logged with no client selected — check those weren't mixed with client data.`);
    }

    prompts.push(
      "",
      "GENERAL CONTAINMENT STEPS:",
      "1. Stop and breathe — acting in a panic makes mistakes worse.",
      "2. Check your SIEM/ticketing system for anything recently pasted.",
      "3. If client data may have been mixed, notify your team lead now.",
      "4. Document what happened in the ticket.",
      "5. If a breach is suspected, follow your MSSP breach procedure.",
      "",
      "The session activity log below shows everything logged this session.",
    );
    return prompts.join("\n");
  }

  function openBreakglass() {
    mileage.breakglassEvents++;
    saveMileage(mileage);
    logAction("breakglass_triggered", "", activeClient);

    const log = getActionLog();
    const rows = [...log]
      .slice(-100)
      .reverse()
      .map(
        (e) =>
          `<tr class="${e.action === "contamination_found" || e.action === "breakglass_triggered" ? "row-critical" : ""}"><td>${e.time}</td><td>${escapeHtml(e.action)}</td><td>${escapeHtml(e.client)}</td><td>${escapeHtml(e.detail)}</td></tr>`,
      )
      .join("");

    openModal(
      "🚨 I Think I've Made a Mistake",
      `
      <div style="display:flex;gap:12px;">
        <div style="flex:1;min-width:260px;">
          <h4 style="margin:4px 0;">IMMEDIATE CHECKS</h4>
          <pre class="breakglass-prompts">${escapeHtml(buildBreakglassPrompts())}</pre>
        </div>
        <div style="flex:1;min-width:260px;">
          <h4 style="margin:4px 0;">SESSION ACTIVITY LOG</h4>
          <div style="max-height:300px;overflow:auto;">
            <table class="report-table">
              <thead><tr><th>Time</th><th>Action</th><th>Client</th><th>Detail</th></tr></thead>
              <tbody>${rows || '<tr><td colspan="4">No actions logged yet</td></tr>'}</tbody>
            </table>
          </div>
        </div>
      </div>
      <div class="modal-actions">
        <button id="bg-copy">Copy Full Log</button>
        <button class="primary" id="bg-close">Close</button>
      </div>
    `,
      { wide: true },
    );
    document.querySelector("#bg-copy")!.addEventListener("click", () => {
      const text = getActionLog()
        .map((e) => `[${e.time}] ${e.action}${e.client ? ` (client: ${e.client})` : ""}${e.detail ? ` — ${e.detail}` : ""}`)
        .join("\n");
      navigator.clipboard.writeText(text);
      flashStatus("Full session log copied");
    });
    document.querySelector("#bg-close")!.addEventListener("click", closeModal);
  }
  document.querySelector("#btn-breakglass")!.addEventListener("click", openBreakglass);

  // -------------------------------------------------------------------------
  // Mileage
  // -------------------------------------------------------------------------
  function openMileage() {
    const start = new Date(mileage.sessionStart);
    const ageMs = Date.now() - start.getTime();
    const hours = Math.floor(ageMs / 3_600_000);
    const minutes = Math.floor((ageMs % 3_600_000) / 60_000);
    const ageStr = hours > 0 ? `${hours}h ${minutes}m` : `${minutes}m`;
    const patterns = analyseMistakePatterns();
    const huntStats = computeHuntStats(loadHunts(), MITRE_TECHNIQUES.length);
    const avgCloseStr =
      huntStats.avgTimeToCloseHours === null
        ? "—"
        : huntStats.avgTimeToCloseHours < 1
          ? `${Math.round(huntStats.avgTimeToCloseHours * 60)}m`
          : `${huntStats.avgTimeToCloseHours.toFixed(1)}h`;

    openModal(
      "📊 Session Mileage",
      `
      <div class="mileage-grid">
        <div><span>Session age</span><b>${ageStr}</b></div>
        <div><span>Safe copies</span><b>${mileage.copies}</b></div>
        <div><span>Defangs performed</span><b>${mileage.defangs}</b></div>
        <div><span>Contamination checks</span><b>${mileage.contaminationChecks}</b></div>
        <div><span>IOC extractions</span><b>${mileage.iocsExtracted}</b></div>
        <div><span>Near-misses logged</span><b>${mileage.nearMisses}</b></div>
        <div><span>Breakglass events</span><b>${mileage.breakglassEvents}</b></div>
        <div><span>Actions logged</span><b>${getActionLog().length}</b></div>
      </div>
      <h4 style="margin:12px 0 4px;">🎯 Hunt Tracker</h4>
      <div class="mileage-grid">
        <div><span>Hunts total</span><b>${huntStats.total}</b></div>
        <div><span>Open / In Progress / Closed</span><b>${huntStats.open} / ${huntStats.inProgress} / ${huntStats.closed}</b></div>
        <div><span>MITRE techniques covered</span><b>${huntStats.techniquesCovered} / ${huntStats.techniquesTotal}</b></div>
        <div><span>Avg time to close</span><b>${avgCloseStr}</b></div>
      </div>
      <h4 style="margin:12px 0 4px;">Mistake Memory</h4>
      ${
        patterns.length > 0
          ? `<ul class="mileage-warnings">${patterns.map((p) => `<li>${escapeHtml(p)}</li>`).join("")}</ul>`
          : `<p style="color:#4caf50;font-size:13px;">No recurring patterns detected this session.</p>`
      }
      <div class="modal-actions">
        <button id="ml-reset">↺ Reset Mileage</button>
        <button class="primary" id="ml-close">Close</button>
      </div>
    `,
    );
    document.querySelector("#ml-reset")!.addEventListener("click", () => {
      if (!confirm("Reset all session mileage counters and clear the action log?")) return;
      mileage = defaultMileage();
      saveMileage(mileage);
      clearActionLog();
      openMileage();
    });
    document.querySelector("#ml-close")!.addEventListener("click", closeModal);
  }
  document.querySelector("#btn-mileage")!.addEventListener("click", openMileage);

  // -------------------------------------------------------------------------
  // Traffic light (content-safety indicator) + per-tab timer
  // -------------------------------------------------------------------------
  function updateTrafficLight() {
    const text = tabs.getContent();
    let color = "#555555"; // grey: empty / no active tab
    if (text.trim()) {
      if (activeClient && Object.keys(clients).filter((n) => n !== activeClient).length > 0) {
        const findings = scanForContamination(text, clients, activeClient);
        if (findings.length > 0) color = "#FF3333"; // red: contamination
        else color = hasLiveIocs(text) ? "#FFAA00" : "#44CC44"; // amber / green
      } else {
        color = hasLiveIocs(text) ? "#FFAA00" : "#44CC44";
      }
    }
    trafficLight.style.background = color;
    trafficLight.style.boxShadow = color === "#555555" ? "none" : `0 0 8px ${color}`;
  }

  // High-severity tabs track a 15-minute SLA: on-track green, then amber, then
  // a red flash that speeds up as 15:00 approaches, then fades to muted grey
  // past the SLA — by then it may have turned out to not be a High after all.
  const HIGH_SLA_SECONDS = 15 * 60;
  const TIMER_FLASH_CLASSES = ["timer-flash-warn", "timer-flash-critical", "timer-faded"];

  function updateTimer() {
    const id = tabs.activeTabId();
    if (!id) {
      timerDisplay.textContent = "⏱ --:--";
      timerDisplay.style.color = "";
      timerDisplay.classList.remove(...TIMER_FLASH_CLASSES);
      return;
    }
    if (!tabStartTimes.has(id)) tabStartTimes.set(id, Date.now());
    const elapsedMs = Date.now() - tabStartTimes.get(id)!;
    const totalSeconds = Math.floor(elapsedMs / 1000);
    const h = Math.floor(totalSeconds / 3600);
    const m = Math.floor((totalSeconds % 3600) / 60);
    const s = totalSeconds % 60;
    const label = h > 0 ? `${h}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}` : `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
    timerDisplay.textContent = `⏱ ${label}`;
    timerDisplay.classList.remove(...TIMER_FLASH_CLASSES);

    if (tabs.getSeverity(id) === "high") {
      const pct = totalSeconds / HIGH_SLA_SECONDS;
      if (totalSeconds >= HIGH_SLA_SECONDS) {
        // Past the 15-minute SLA — fade out rather than stay alarmed; it may
        // no longer be a High.
        timerDisplay.style.color = "";
        timerDisplay.classList.add("timer-faded");
      } else if (pct >= 0.93) {
        timerDisplay.style.color = "#ff3344";
        timerDisplay.classList.add("timer-flash-critical");
      } else if (pct >= 0.8) {
        timerDisplay.style.color = "#ff6644";
        timerDisplay.classList.add("timer-flash-warn");
      } else if (pct >= 0.6) {
        timerDisplay.style.color = "#ffaa44";
      } else {
        timerDisplay.style.color = "#88aa88";
      }
      return;
    }

    let color = "#88aa88";
    if (h >= 1) color = "#ff9944";
    else if (m >= 30) color = "#ff6644";
    else if (m >= 15) color = "#ffaa44";
    timerDisplay.style.color = color;
  }

  setInterval(() => {
    updateTrafficLight();
    updateTimer();
  }, 1000);
  updateTrafficLight();
  updateTimer();

  // Hooks main.ts calls into on relevant events.
  return {
    onDefang: () => {
      mileage.defangs++;
      saveMileage(mileage);
      logAction("defang", "", activeClient);
      updateTrafficLight();
    },
    onExtractIocs: (count: number) => {
      mileage.iocsExtracted++;
      saveMileage(mileage);
      logAction("ioc_extract", `${count} IOC(s)`, activeClient);
    },
    onTabClosed: (id: string) => {
      tabStartTimes.delete(id);
      logAction("tab_closed", "", activeClient);
    },
    onTextChanged: () => updateTrafficLight(),
    getActiveClient: () => activeClient,
  };
}

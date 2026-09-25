import { downloadTextFile, exportIocsCsv, exportIocsJson, exportIocsText } from "../core/exportIocs";
import {
  buildAllHuntsReport,
  buildBackup,
  buildHuntReport,
  computeCoverage,
  computeHuntStats,
  coverageFreshness,
  daysSince,
  emptyHunt,
  extractHuntIocs,
  HUNT_PRIORITY_LABELS,
  HUNT_STAGE_LABELS,
  HUNT_STAGES,
  huntFromPlaybook,
  isDueForReview,
  loadHunts,
  loadPlaybooks,
  mergeById,
  newPlaybookId,
  parseBackup,
  saveHunts,
  savePlaybooks,
  setHuntStage,
  stageAtOffset,
  stageIndex,
  ticketLabel,
  type ActivityEntry,
  type Hunt,
  type HuntPriority,
  type HuntStage,
  type Playbook,
} from "../core/hunts";
import { groupIocs, IOC_LABELS, type IocType } from "../core/iocPatterns";
import {
  MITRE_SUBTECHNIQUES,
  MITRE_TACTICS,
  MITRE_TECHNIQUES,
  MITRE_TECHNIQUE_BY_ID,
  mitreEntryById,
  techniquesForTactic,
} from "../core/mitre";

export interface HuntsViewContext {
  flashStatus: (msg: string) => void;
  getKqlSnippets: () => Record<string, string>;
}

function escapeHtml(s: string): string {
  const div = document.createElement("div");
  div.textContent = s;
  return div.innerHTML;
}
function escapeAttr(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/"/g, "&quot;");
}
function relTime(iso: string): string {
  const days = daysSince(iso);
  if (days <= 0) return "today";
  if (days === 1) return "1 day ago";
  return `${days} days ago`;
}

type HuntsTab = "board" | "list" | "coverage" | "playbooks";

export function initHuntsView(container: HTMLElement, ctx: HuntsViewContext): void {
  let hunts: Hunt[] = loadHunts();
  let playbooks: Playbook[] = loadPlaybooks();
  let activeTab: HuntsTab = "board";
  let stageFilter: "all" | HuntStage = "all";
  let priorityFilter: "all" | HuntPriority = "all";
  let dueOnlyFilter = false;
  let keywordFilter = "";
  let editingPlaybookId: string | null = null;

  // The ticket currently open (if any) and its working copy. Kept as a
  // persistent object (not re-cloned on every render) so that structural
  // edits — title, hypothesis, techniques, etc — survive re-renders
  // triggered by other actions (stage pill clicks, notes) until the user
  // explicitly hits Save, exactly like the old side-panel draft did.
  let ticketOpenId: string | null = null;
  let draftHunt: Hunt | null = null;

  // All MITRE technique/sub-technique ids+names in one place, for chip
  // labels, the add-technique lookup, and the autocomplete datalist.
  const MITRE_ALL = [
    ...MITRE_TECHNIQUES.map((t) => ({ id: t.id, name: t.name })),
    ...MITRE_SUBTECHNIQUES.map((t) => ({ id: t.id, name: t.name })),
  ];

  function cloneHunt(h: Hunt): Hunt {
    return {
      ...h,
      techniques: [...h.techniques],
      dataSources: [...h.dataSources],
      iocs: [...h.iocs],
      activityLog: [...h.activityLog],
    };
  }

  function openTicket(id: string) {
    const hunt = hunts.find((h) => h.id === id);
    if (!hunt) return;
    ticketOpenId = id;
    draftHunt = cloneHunt(hunt);
  }
  function closeTicket() {
    ticketOpenId = null;
    draftHunt = null;
  }

  /** Creates a hunt, persists it immediately (so it shows up on the board/list right away), and returns it. */
  function createHunt(overrides: Partial<Hunt> = {}): Hunt {
    const hunt = { ...emptyHunt(), ...overrides };
    hunts.push(hunt);
    saveHunts(hunts);
    return hunt;
  }

  /** Writes `hunt` (title/hypothesis/etc, or a stage/note change) into the persisted hunts array. */
  function commitDraft(hunt: Hunt) {
    hunt.updatedAt = new Date().toISOString();
    const idx = hunts.findIndex((h) => h.id === hunt.id);
    if (idx === -1) hunts.push(hunt);
    else hunts[idx] = hunt;
    saveHunts(hunts);
  }

  // -------------------------------------------------------------------------
  // Top-level render
  // -------------------------------------------------------------------------
  function render() {
    container.innerHTML = `
      <div class="hunts-toolbar">
        <div class="hunts-tabs">
          <button data-htab="board" class="${activeTab === "board" ? "active" : ""}">🗂 Board</button>
          <button data-htab="list" class="${activeTab === "list" ? "active" : ""}">📋 List</button>
          <button data-htab="coverage" class="${activeTab === "coverage" ? "active" : ""}">🗺 Coverage</button>
          <button data-htab="playbooks" class="${activeTab === "playbooks" ? "active" : ""}">📖 Playbooks</button>
        </div>
        <div class="hunts-toolbar-actions">
          <button id="btn-backup" title="Download all hunts + playbooks as a JSON backup">⬇ Backup</button>
          <button id="btn-restore" title="Restore hunts + playbooks from a JSON backup (merges, never overwrites)">⬆ Restore</button>
          <button id="btn-all-report" title="Download every hunt as one combined text report">📄 All Hunts Report</button>
          <input type="file" id="hunts-restore-input" accept=".json" style="display:none" />
        </div>
      </div>
      <div class="hunts-body" id="hunts-body"></div>
    `;
    container.querySelectorAll<HTMLButtonElement>("[data-htab]").forEach((btn) => {
      btn.addEventListener("click", () => {
        closeTicket();
        activeTab = btn.dataset.htab as HuntsTab;
        render();
      });
    });

    container.querySelector("#btn-backup")!.addEventListener("click", () => {
      downloadTextFile(`threatpad-hunts-backup-${new Date().toISOString().slice(0, 10)}.json`, buildBackup(hunts, playbooks));
      ctx.flashStatus("Backup downloaded");
    });
    const restoreInput = container.querySelector<HTMLInputElement>("#hunts-restore-input")!;
    container.querySelector("#btn-restore")!.addEventListener("click", () => restoreInput.click());
    restoreInput.addEventListener("change", async () => {
      const file = restoreInput.files?.[0];
      restoreInput.value = "";
      if (!file) return;
      const text = await file.text();
      const backup = parseBackup(text);
      if (!backup) {
        ctx.flashStatus("That file doesn't look like a hunts backup");
        return;
      }
      const huntsResult = mergeById(hunts, backup.hunts);
      const pbResult = mergeById(playbooks, backup.playbooks);
      hunts = huntsResult.merged;
      playbooks = pbResult.merged;
      saveHunts(hunts);
      savePlaybooks(playbooks);
      ctx.flashStatus(
        `Restored ${huntsResult.addedCount} hunt(s) and ${pbResult.addedCount} playbook(s) (${huntsResult.skippedCount + pbResult.skippedCount} already present, skipped)`,
      );
      render();
    });
    container.querySelector("#btn-all-report")!.addEventListener("click", () => {
      if (hunts.length === 0) return ctx.flashStatus("No hunts to export yet");
      downloadTextFile(`threatpad-all-hunts-${new Date().toISOString().slice(0, 10)}.txt`, buildAllHuntsReport(hunts));
      ctx.flashStatus(`Exported ${hunts.length} hunt(s) as a combined report`);
    });

    const body = container.querySelector<HTMLDivElement>("#hunts-body")!;
    if (ticketOpenId && draftHunt) {
      renderTicketPage(body);
      return;
    }
    if (activeTab === "board") renderBoardTab(body);
    else if (activeTab === "list") renderListTab(body);
    else if (activeTab === "coverage") renderCoverageTab(body);
    else renderPlaybooksTab(body);
  }

  // -------------------------------------------------------------------------
  // Board tab: kanban pipeline, drag-and-drop
  // -------------------------------------------------------------------------
  function renderKanbanCard(h: Hunt): string {
    const chips = h.techniques.slice(0, 2).map((id) => `<span class="tag-chip-mini">${escapeHtml(id)}</span>`).join("");
    const more = h.techniques.length > 2 ? `<span class="tag-chip-mini">+${h.techniques.length - 2}</span>` : "";
    const due = isDueForReview(h) ? `<span class="due-badge" title="Recurring — due for another look">⏰</span>` : "";
    const idx = stageIndex(h.stage);
    const canPrev = idx > 0;
    const canNext = idx < HUNT_STAGES.length - 1;
    return `
      <div class="kanban-card" draggable="true" data-hunt-id="${h.id}">
        <div class="kanban-card-top">
          <span class="ticket-id-mini">${ticketLabel(h)}</span>
          <span class="priority-dot priority-${h.priority}" title="${HUNT_PRIORITY_LABELS[h.priority]} priority"></span>
        </div>
        <div class="kanban-card-title">${escapeHtml(h.title)}</div>
        <div class="kanban-card-chips">${chips}${more}${due}</div>
        <div class="kanban-card-bottom">
          <button class="kanban-nav-btn" data-shift-hunt="${h.id}" data-dir="-1" ${canPrev ? "" : "disabled"} title="Move to previous stage">◀</button>
          <span class="kanban-card-updated">${relTime(h.updatedAt)}</span>
          <button class="kanban-nav-btn" data-shift-hunt="${h.id}" data-dir="1" ${canNext ? "" : "disabled"} title="Move to next stage">▶</button>
        </div>
      </div>`;
  }

  function renderBoardTab(body: HTMLDivElement) {
    body.innerHTML = `
      <div class="kanban-board" id="kanban-board">
        ${HUNT_STAGES.map((stage) => {
          const cards = hunts.filter((h) => h.stage === stage.id).sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
          return `
          <div class="kanban-column">
            <div class="kanban-column-header" style="border-color:${stage.color}">
              <span class="kanban-column-title">${stage.icon} ${stage.label}</span>
              <span class="kanban-count">${cards.length}</span>
            </div>
            <button class="kanban-add-card" data-add-to-stage="${stage.id}">+ New</button>
            <div class="kanban-column-body" data-drop-stage="${stage.id}">
              ${cards.map(renderKanbanCard).join("") || `<div class="kanban-empty">No hunts here</div>`}
            </div>
          </div>`;
        }).join("")}
      </div>
    `;

    body.querySelectorAll<HTMLButtonElement>("[data-add-to-stage]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const hunt = createHunt({ stage: btn.dataset.addToStage as HuntStage });
        openTicket(hunt.id);
        render();
      });
    });

    body.querySelectorAll<HTMLDivElement>(".kanban-card").forEach((card) => {
      card.addEventListener("click", (e) => {
        if ((e.target as HTMLElement).closest("[data-shift-hunt]")) return;
        openTicket(card.dataset.huntId!);
        render();
      });
      card.addEventListener("dragstart", (e) => {
        e.dataTransfer?.setData("text/plain", card.dataset.huntId!);
        if (e.dataTransfer) e.dataTransfer.effectAllowed = "move";
        card.classList.add("dragging");
      });
      card.addEventListener("dragend", () => card.classList.remove("dragging"));
    });

    body.querySelectorAll<HTMLButtonElement>("[data-shift-hunt]").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const hunt = hunts.find((h) => h.id === btn.dataset.shiftHunt);
        if (!hunt) return;
        const nextStage = stageAtOffset(hunt.stage, Number(btn.dataset.dir));
        if (!nextStage) return;
        setHuntStage(hunt, nextStage);
        saveHunts(hunts);
        ctx.flashStatus(`${ticketLabel(hunt)} → ${HUNT_STAGE_LABELS[nextStage]}`);
        render();
      });
    });

    body.querySelectorAll<HTMLDivElement>(".kanban-column-body").forEach((col) => {
      col.addEventListener("dragover", (e) => {
        e.preventDefault();
        col.classList.add("drag-over");
      });
      col.addEventListener("dragleave", () => col.classList.remove("drag-over"));
      col.addEventListener("drop", (e) => {
        e.preventDefault();
        col.classList.remove("drag-over");
        const id = e.dataTransfer?.getData("text/plain");
        const hunt = hunts.find((h) => h.id === id);
        const stage = col.dataset.dropStage as HuntStage;
        if (!hunt || hunt.stage === stage) return;
        setHuntStage(hunt, stage);
        saveHunts(hunts);
        ctx.flashStatus(`${ticketLabel(hunt)} → ${HUNT_STAGE_LABELS[stage]}`);
        render();
      });
    });
  }

  // -------------------------------------------------------------------------
  // List tab: a filterable/searchable queue table
  // -------------------------------------------------------------------------
  function matchesKeyword(h: Hunt, needle: string): boolean {
    const haystack = [h.title, h.hypothesis, h.findings, h.queries, ...h.dataSources, ...h.techniques]
      .join("\n")
      .toLowerCase();
    return haystack.includes(needle);
  }

  function renderHuntsTable(): string {
    const needle = keywordFilter.trim().toLowerCase();
    const filtered = hunts
      .filter((h) => stageFilter === "all" || h.stage === stageFilter)
      .filter((h) => priorityFilter === "all" || h.priority === priorityFilter)
      .filter((h) => !dueOnlyFilter || isDueForReview(h))
      .filter((h) => !needle || matchesKeyword(h, needle))
      .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
    if (filtered.length === 0) {
      return hunts.length === 0
        ? `<p class="ioc-empty">No hunts yet. Click "+ New Hunt" to start one, or pick a playbook.</p>`
        : `<p class="ioc-empty">No hunts match the current filters.</p>`;
    }
    const rows = filtered
      .map((h) => {
        const stageDef = HUNT_STAGES.find((s) => s.id === h.stage)!;
        const chips = h.techniques.slice(0, 3).map((id) => `<span class="tag-chip-mini">${escapeHtml(id)}</span>`).join("");
        const due = isDueForReview(h) ? `<span class="due-badge">⏰ Due</span>` : "";
        return `
        <tr class="hunts-table-row" data-hunt-id="${h.id}">
          <td class="hunts-table-id">${ticketLabel(h)}</td>
          <td class="hunts-table-title">${escapeHtml(h.title)}</td>
          <td><span class="stage-badge" style="color:${stageDef.color};border-color:${stageDef.color}">${stageDef.icon} ${stageDef.label}</span></td>
          <td><span class="priority-badge priority-${h.priority}">${HUNT_PRIORITY_LABELS[h.priority]}</span></td>
          <td class="hunts-table-techniques">${chips}</td>
          <td class="hunts-table-updated">${relTime(h.updatedAt)} ${due}</td>
        </tr>`;
      })
      .join("");
    return `
      <table class="hunts-table">
        <thead><tr><th>#</th><th>Title</th><th>Stage</th><th>Priority</th><th>Techniques</th><th>Updated</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
  }

  function wireTableRows(wrap: HTMLDivElement) {
    wrap.querySelectorAll<HTMLTableRowElement>(".hunts-table-row").forEach((row) => {
      row.addEventListener("click", () => {
        openTicket(row.dataset.huntId!);
        render();
      });
    });
  }

  function renderListTab(body: HTMLDivElement) {
    body.innerHTML = `
      <div class="hunts-list-toolbar">
        <input type="text" class="text-input" id="hunt-search" placeholder="Search hunts…" value="${escapeAttr(keywordFilter)}" />
        <button class="primary" id="btn-new-hunt">+ New Hunt</button>
      </div>
      <div class="hunts-list-toolbar">
        <select id="hunt-stage-filter">
          <option value="all">All stages</option>
          ${HUNT_STAGES.map((s) => `<option value="${s.id}">${s.icon} ${s.label}</option>`).join("")}
        </select>
        <select id="hunt-priority-filter">
          <option value="all">All priorities</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <label class="hunt-due-filter"><input type="checkbox" id="hunt-due-filter" ${dueOnlyFilter ? "checked" : ""} /> Due only</label>
      </div>
      <div class="hunts-table-wrap" id="hunts-table-wrap">${renderHuntsTable()}</div>
    `;
    const searchEl = body.querySelector<HTMLInputElement>("#hunt-search")!;
    searchEl.addEventListener("input", () => {
      keywordFilter = searchEl.value;
      const wrap = body.querySelector<HTMLDivElement>("#hunts-table-wrap")!;
      wrap.innerHTML = renderHuntsTable();
      wireTableRows(wrap);
    });
    const stageFilterEl = body.querySelector<HTMLSelectElement>("#hunt-stage-filter")!;
    stageFilterEl.value = stageFilter;
    stageFilterEl.addEventListener("change", () => {
      stageFilter = stageFilterEl.value as typeof stageFilter;
      render();
    });
    const priorityFilterEl = body.querySelector<HTMLSelectElement>("#hunt-priority-filter")!;
    priorityFilterEl.value = priorityFilter;
    priorityFilterEl.addEventListener("change", () => {
      priorityFilter = priorityFilterEl.value as typeof priorityFilter;
      render();
    });
    body.querySelector<HTMLInputElement>("#hunt-due-filter")!.addEventListener("change", (e) => {
      dueOnlyFilter = (e.target as HTMLInputElement).checked;
      render();
    });
    body.querySelector("#btn-new-hunt")!.addEventListener("click", () => {
      const hunt = createHunt();
      openTicket(hunt.id);
      render();
    });
    wireTableRows(body.querySelector<HTMLDivElement>("#hunts-table-wrap")!);
  }

  // -------------------------------------------------------------------------
  // Ticket page: the full-page detail view for one hunt
  // -------------------------------------------------------------------------
  function renderTechniqueChips(techniques: string[]): string {
    if (techniques.length === 0) return `<span class="hunt-empty-note">No techniques tagged yet</span>`;
    return techniques
      .map((id) => {
        const t = mitreEntryById(id);
        const label = t ? `${escapeHtml(id)} ${escapeHtml(t.name)}` : escapeHtml(id);
        return `<span class="tag-chip">${label}<span class="tag-chip-remove" data-remove-technique="${escapeAttr(id)}">✕</span></span>`;
      })
      .join("");
  }

  function renderHuntIocs(hunt: Hunt): string {
    if (hunt.iocs.length === 0) return `<p class="ioc-empty">No IOCs extracted yet — write findings above, then click Extract.</p>`;
    const grouped = groupIocs(hunt.iocs);
    let html = `<div class="export-row"><button id="hd-ioc-csv">CSV</button><button id="hd-ioc-json">JSON</button><button id="hd-ioc-txt">TXT</button></div>`;
    for (const [type, values] of Object.entries(grouped)) {
      if (values.length === 0) continue;
      html += `<div class="ioc-group"><h4>${IOC_LABELS[type as IocType]} (${values.length})</h4>`;
      for (const v of values) {
        html += `<div class="ioc-value" data-copy="${escapeAttr(v)}" title="Click to copy">${escapeHtml(v)}</div>`;
      }
      html += `</div>`;
    }
    return html;
  }

  function renderActivityLog(log: ActivityEntry[]): string {
    if (log.length === 0) return `<p class="ioc-empty">No notes yet — the first one is a good place to jot why you started this.</p>`;
    return [...log]
      .reverse()
      .map(
        (e) => `
      <div class="activity-entry">
        <div class="activity-time">${escapeHtml(new Date(e.timestamp).toLocaleString())}</div>
        <div class="activity-text">${escapeHtml(e.text)}</div>
      </div>`,
      )
      .join("");
  }

  function renderTicketPage(body: HTMLDivElement) {
    const hunt = draftHunt!;
    const kqlNames = Object.keys(ctx.getKqlSnippets()).sort();
    const due = isDueForReview(hunt);
    const curIdx = stageIndex(hunt.stage);

    body.innerHTML = `
      <div class="hunt-ticket">
        <div class="ticket-topbar">
          <button id="ticket-back">← Back</button>
          <span class="ticket-id">${ticketLabel(hunt)}</span>
        </div>

        <div class="ticket-header">
          <input class="text-input ticket-title-input" id="hd-title" value="${escapeAttr(hunt.title)}" placeholder="Hunt title" />
          <select id="hd-priority" title="Triage priority">
            <option value="high">🔺 High</option>
            <option value="medium">▪ Medium</option>
            <option value="low">▫ Low</option>
          </select>
        </div>

        <div class="stage-pipeline">
          ${HUNT_STAGES.map((s, i) => {
            const cls = s.id === hunt.stage ? "active" : i < curIdx ? "done" : "";
            return `<button class="stage-pill ${cls}" style="--stage-color:${s.color}" data-set-stage="${s.id}" title="${s.label}"><span class="stage-pill-icon">${s.icon}</span><span class="stage-pill-label">${s.label}</span></button>`;
          }).join("")}
        </div>

        <div class="ticket-meta-line">
          Created ${relTime(hunt.createdAt)} · Updated ${relTime(hunt.updatedAt)}${hunt.closedAt ? ` · Closed ${relTime(hunt.closedAt)}` : ""}
          ${due ? `<span class="due-badge" title="Recurring hunt — due for another look">⏰ Due for review</span>` : ""}
        </div>

        <div class="ticket-body">
          <div class="ticket-main">
            <label class="hunt-field-label">Hypothesis</label>
            <textarea class="snippet-editor" id="hd-hypothesis" placeholder="What do you think is happening, and why?">${escapeHtml(hunt.hypothesis)}</textarea>

            <label class="hunt-field-label">MITRE ATT&amp;CK Techniques</label>
            <div class="tag-input-row">
              <input list="mitre-datalist" class="text-input" id="hd-technique-input" placeholder="e.g. T1059, T1059.001, or Command and Scripting" />
              <button id="hd-add-technique">+ Add</button>
            </div>
            <datalist id="mitre-datalist">
              ${MITRE_ALL.map((t) => `<option value="${escapeAttr(t.id)} — ${escapeAttr(t.name)}">`).join("")}
            </datalist>
            <div class="technique-chips">${renderTechniqueChips(hunt.techniques)}</div>

            <label class="hunt-field-label">Data Sources (one per line)</label>
            <textarea class="snippet-editor" id="hd-datasources" placeholder="DeviceProcessEvents&#10;DeviceLogonEvents">${escapeHtml(hunt.dataSources.join("\n"))}</textarea>

            <label class="hunt-field-label">Queries</label>
            <select id="hd-kql-picker">
              <option value="">Insert saved KQL…</option>
              ${kqlNames.map((n) => `<option value="${escapeAttr(n)}">${escapeHtml(n)}</option>`).join("")}
            </select>
            <textarea class="snippet-editor hunt-queries" id="hd-queries" placeholder="Paste or write the queries you ran">${escapeHtml(hunt.queries)}</textarea>

            <label class="hunt-field-label">Findings</label>
            <textarea class="snippet-editor" id="hd-findings" placeholder="What did you find? Include raw values here, then extract IOCs below.">${escapeHtml(hunt.findings)}</textarea>
            <button id="hd-extract-iocs">🔎 Extract IOCs from Findings</button>

            <div class="hunt-iocs-section">
              <label class="hunt-field-label">IOCs (${hunt.iocs.length})</label>
              ${renderHuntIocs(hunt)}
            </div>
          </div>

          <div class="ticket-sidebar">
            <div class="ticket-panel">
              <h4>Recurring</h4>
              <div class="recurring-row">
                Every <input type="number" min="1" class="text-input recurring-input" id="hd-recurring" value="${hunt.recurringDays ?? ""}" placeholder="—" /> day(s)
              </div>
              <p class="ticket-panel-hint">Blank = one-off hunt. Once set, a "⏰ Due" badge appears here after this many days without an update.</p>
            </div>

            <div class="ticket-panel ticket-activity">
              <h4>Activity Log</h4>
              <div class="activity-list" id="activity-list">${renderActivityLog(hunt.activityLog)}</div>
              <textarea class="snippet-editor" id="hd-new-note" placeholder="Add a note — progress update, a teammate ping, anything worth timestamping…"></textarea>
              <button class="primary" id="hd-add-note" style="width:100%;margin-top:6px;">+ Add Note</button>
            </div>
          </div>
        </div>

        <div class="modal-actions hunt-actions">
          <button id="hd-delete">🗑 Delete</button>
          <button id="hd-copy-report">📋 Copy Report</button>
          <button id="hd-download-report">⬇ Download</button>
          <button class="primary" id="hd-save">💾 Save</button>
        </div>
      </div>
    `;

    wireTicketPage(body);
  }

  // Any button that mutates draftHunt and re-renders must first pull the
  // live (possibly unsaved) field values out of the DOM — otherwise the
  // re-render rebuilds the form from the stale draftHunt object and
  // silently discards whatever the user had typed but not yet saved.
  function syncFormFieldsToDraft(root: HTMLElement) {
    if (!draftHunt) return;
    const title = root.querySelector<HTMLInputElement>("#hd-title");
    if (title) draftHunt.title = title.value;
    const priority = root.querySelector<HTMLSelectElement>("#hd-priority");
    if (priority) draftHunt.priority = priority.value as HuntPriority;
    const hypothesis = root.querySelector<HTMLTextAreaElement>("#hd-hypothesis");
    if (hypothesis) draftHunt.hypothesis = hypothesis.value;
    const dataSources = root.querySelector<HTMLTextAreaElement>("#hd-datasources");
    if (dataSources) draftHunt.dataSources = dataSources.value.split("\n").map((s) => s.trim()).filter(Boolean);
    const queries = root.querySelector<HTMLTextAreaElement>("#hd-queries");
    if (queries) draftHunt.queries = queries.value;
    const findings = root.querySelector<HTMLTextAreaElement>("#hd-findings");
    if (findings) draftHunt.findings = findings.value;
    const recurring = root.querySelector<HTMLInputElement>("#hd-recurring");
    if (recurring) {
      const n = parseInt(recurring.value, 10);
      draftHunt.recurringDays = Number.isFinite(n) && n > 0 ? n : undefined;
    }
  }

  function wireTicketPage(root: HTMLDivElement) {
    if (!draftHunt) return;
    (root.querySelector("#hd-priority") as HTMLSelectElement).value = draftHunt.priority;

    root.querySelector("#ticket-back")!.addEventListener("click", () => {
      closeTicket();
      render();
    });

    root.querySelectorAll<HTMLButtonElement>("[data-set-stage]").forEach((btn) => {
      btn.addEventListener("click", () => {
        syncFormFieldsToDraft(root);
        const newStage = btn.dataset.setStage as HuntStage;
        setHuntStage(draftHunt!, newStage);
        commitDraft(draftHunt!);
        ctx.flashStatus(`${ticketLabel(draftHunt!)} → ${HUNT_STAGE_LABELS[newStage]}`);
        render();
      });
    });

    root.querySelector("#hd-add-technique")!.addEventListener("click", () => {
      const input = root.querySelector<HTMLInputElement>("#hd-technique-input")!;
      const raw = input.value.trim();
      if (!raw) return;
      const idToken = raw.split(/\s+/)[0].toUpperCase();
      const technique = mitreEntryById(idToken);
      if (!technique) {
        ctx.flashStatus(`Unknown technique: ${raw}`);
        return;
      }
      syncFormFieldsToDraft(root);
      if (!draftHunt!.techniques.includes(technique.id)) draftHunt!.techniques.push(technique.id);
      render();
    });
    root.querySelectorAll<HTMLSpanElement>("[data-remove-technique]").forEach((btn) => {
      btn.addEventListener("click", () => {
        syncFormFieldsToDraft(root);
        draftHunt!.techniques = draftHunt!.techniques.filter((t) => t !== btn.dataset.removeTechnique);
        render();
      });
    });

    root.querySelector("#hd-kql-picker")!.addEventListener("change", (e) => {
      const select = e.target as HTMLSelectElement;
      const name = select.value;
      if (!name) return;
      const text = ctx.getKqlSnippets()[name] ?? "";
      const queriesEl = root.querySelector<HTMLTextAreaElement>("#hd-queries")!;
      queriesEl.value = queriesEl.value.trim() ? `${queriesEl.value.trim()}\n\n${text}` : text;
      select.value = "";
      ctx.flashStatus(`Inserted KQL: ${name}`);
    });

    root.querySelector("#hd-extract-iocs")!.addEventListener("click", () => {
      syncFormFieldsToDraft(root);
      draftHunt!.iocs = extractHuntIocs(draftHunt!);
      ctx.flashStatus(`Extracted ${draftHunt!.iocs.length} IOC(s)`);
      render();
    });

    root.querySelectorAll<HTMLDivElement>(".ioc-value[data-copy]").forEach((el) => {
      el.addEventListener("click", () => {
        navigator.clipboard.writeText(el.dataset.copy ?? "");
        ctx.flashStatus(`Copied ${el.dataset.copy}`);
      });
    });
    root.querySelector("#hd-ioc-csv")?.addEventListener("click", () => exportIocsCsv(draftHunt!.iocs));
    root.querySelector("#hd-ioc-json")?.addEventListener("click", () => exportIocsJson(draftHunt!.iocs));
    root.querySelector("#hd-ioc-txt")?.addEventListener("click", () =>
      exportIocsText(
        Object.fromEntries(Object.entries(groupIocs(draftHunt!.iocs)).map(([k, v]) => [IOC_LABELS[k as IocType], v])),
      ),
    );

    root.querySelector("#hd-add-note")!.addEventListener("click", () => {
      const noteEl = root.querySelector<HTMLTextAreaElement>("#hd-new-note")!;
      const text = noteEl.value.trim();
      if (!text) return;
      syncFormFieldsToDraft(root);
      draftHunt!.activityLog.push({ timestamp: new Date().toISOString(), text });
      commitDraft(draftHunt!);
      ctx.flashStatus("Note added");
      render();
    });

    root.querySelector("#hd-copy-report")!.addEventListener("click", () => {
      syncFormFieldsToDraft(root);
      navigator.clipboard.writeText(buildHuntReport(draftHunt!));
      ctx.flashStatus("Hunt report copied");
    });
    root.querySelector("#hd-download-report")!.addEventListener("click", () => {
      syncFormFieldsToDraft(root);
      const slug = draftHunt!.title.replace(/[^a-z0-9]+/gi, "-").toLowerCase() || "hunt";
      downloadTextFile(`hunt-${slug}.txt`, buildHuntReport(draftHunt!));
    });

    root.querySelector("#hd-delete")!.addEventListener("click", () => {
      if (!confirm(`Delete ${ticketLabel(draftHunt!)} — "${draftHunt!.title}"? This cannot be undone.`)) return;
      hunts = hunts.filter((h) => h.id !== draftHunt!.id);
      saveHunts(hunts);
      closeTicket();
      ctx.flashStatus("Hunt deleted");
      render();
    });

    root.querySelector("#hd-save")!.addEventListener("click", () => {
      syncFormFieldsToDraft(root);
      draftHunt!.title = draftHunt!.title.trim() || "Untitled Hunt";
      commitDraft(draftHunt!);
      ctx.flashStatus(`Saved ${ticketLabel(draftHunt!)}`);
      render();
    });
  }

  // -------------------------------------------------------------------------
  // Coverage tab
  // -------------------------------------------------------------------------
  function renderCoverageTab(body: HTMLDivElement) {
    const coverage = computeCoverage(hunts, MITRE_TECHNIQUES.map((t) => t.id));
    const stats = computeHuntStats(hunts, MITRE_TECHNIQUES.length);
    const neverCount = coverage.filter((c) => c.status === "never").length;

    let html = `
      <div class="coverage-summary">
        <div><b>${stats.techniquesCovered}</b> / ${stats.techniquesTotal} techniques covered</div>
        <div><b>${stats.total}</b> hunts total</div>
        <div><b>${neverCount}</b> never hunted</div>
        ${stats.dueForReview > 0 ? `<div><b>${stats.dueForReview}</b> due for review</div>` : ""}
      </div>
      <p class="coverage-note">A curated subset of top-level MITRE ATT&amp;CK Enterprise techniques (plus a smaller
      set of sub-techniques, rolled up into their parent here), tracked locally — click a technique to jump to its
      hunts, or start a new one. A technique counts as covered once a hunt reaches Results or later. Closed coverage
      fades as it ages: solid green under 30 days, dimmer past 30, faint past 90.</p>
      <div class="coverage-grid">
    `;
    for (const tactic of MITRE_TACTICS) {
      const techs = techniquesForTactic(tactic.name);
      html += `<div class="tactic-section"><h4>${escapeHtml(tactic.name)}</h4><div class="technique-cells">`;
      for (const t of techs) {
        const cov = coverage.find((c) => c.techniqueId === t.id)!;
        const freshness = cov.status === "closed" ? coverageFreshness(cov.lastHuntedAt) : "fresh";
        const dueNote = cov.hunts.some(isDueForReview) ? " · due for review" : "";
        const title = `${t.id} — ${t.name} · ${cov.lastHuntedAt ? `last hunted ${relTime(cov.lastHuntedAt)}` : "never hunted"}${dueNote}`;
        html += `<div class="technique-cell technique-${cov.status} freshness-${freshness}" data-technique-cell="${escapeAttr(t.id)}" title="${escapeAttr(title)}">${escapeHtml(t.id)}</div>`;
      }
      html += `</div></div>`;
    }
    html += `</div>`;
    body.innerHTML = html;

    body.querySelectorAll<HTMLDivElement>("[data-technique-cell]").forEach((cell) => {
      cell.addEventListener("click", () => {
        const id = cell.dataset.techniqueCell!;
        const cov = coverage.find((c) => c.techniqueId === id)!;
        if (cov.hunts.length > 0) {
          const hunt = [...cov.hunts].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))[0];
          openTicket(hunt.id);
        } else {
          const technique = MITRE_TECHNIQUE_BY_ID[id];
          const hunt = createHunt({ title: `${technique.name} hunt`, techniques: [id], stage: "hypothesis" });
          openTicket(hunt.id);
        }
        render();
      });
    });
  }

  // -------------------------------------------------------------------------
  // Playbooks tab
  // -------------------------------------------------------------------------
  function renderPlaybookCard(pb: Playbook): string {
    if (editingPlaybookId === pb.id) {
      return `
        <div class="playbook-card playbook-card-editing">
          <input class="text-input" id="pbe-title-${pb.id}" value="${escapeAttr(pb.title)}" placeholder="Playbook title" />
          <textarea class="snippet-editor" id="pbe-desc-${pb.id}" placeholder="Description / hypothesis">${escapeHtml(pb.description)}</textarea>
          <input class="text-input" id="pbe-techniques-${pb.id}" value="${escapeAttr(pb.techniques.join(", "))}" placeholder="Technique IDs, comma separated e.g. T1059, T1027" />
          <textarea class="snippet-editor" id="pbe-query-${pb.id}" placeholder="Suggested query">${escapeHtml(pb.suggestedQuery)}</textarea>
          <div class="modal-actions">
            <button data-pb-cancel="${pb.id}">Cancel</button>
            <button class="primary" data-pb-save="${pb.id}">Save</button>
          </div>
        </div>`;
    }
    const chips = pb.techniques.map((id) => `<span class="tag-chip-mini">${escapeHtml(id)}</span>`).join("");
    return `
      <div class="playbook-card">
        <div class="playbook-card-header">
          <b>${escapeHtml(pb.title)}</b>
          <div class="technique-chips">${chips}</div>
        </div>
        <p class="playbook-desc">${escapeHtml(pb.description)}</p>
        ${pb.suggestedQuery ? `<pre class="playbook-query">${escapeHtml(pb.suggestedQuery)}</pre>` : ""}
        <div class="modal-actions">
          <button data-pb-edit="${pb.id}">✎ Edit</button>
          <button data-pb-delete="${pb.id}">🗑 Delete</button>
          <button class="primary" data-pb-start="${pb.id}">▶ Start Hunt</button>
        </div>
      </div>`;
  }

  function renderPlaybooksTab(body: HTMLDivElement) {
    body.innerHTML = `
      <div class="playbooks-toolbar"><button class="primary" id="btn-new-playbook">+ New Playbook</button></div>
      <div class="playbooks-list" id="playbooks-list">${playbooks.map(renderPlaybookCard).join("")}</div>
    `;
    body.querySelector("#btn-new-playbook")!.addEventListener("click", () => {
      const pb: Playbook = { id: newPlaybookId(), title: "New Playbook", description: "", techniques: [], suggestedQuery: "" };
      playbooks.push(pb);
      savePlaybooks(playbooks);
      editingPlaybookId = pb.id;
      render();
    });

    const list = body.querySelector<HTMLDivElement>("#playbooks-list")!;
    list.querySelectorAll<HTMLButtonElement>("[data-pb-start]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const pb = playbooks.find((p) => p.id === btn.dataset.pbStart);
        if (!pb) return;
        const hunt = huntFromPlaybook(pb);
        hunts.push(hunt);
        saveHunts(hunts);
        openTicket(hunt.id);
        ctx.flashStatus(`Started hunt from playbook: ${pb.title}`);
        render();
      });
    });
    list.querySelectorAll<HTMLButtonElement>("[data-pb-edit]").forEach((btn) => {
      btn.addEventListener("click", () => {
        editingPlaybookId = btn.dataset.pbEdit!;
        render();
      });
    });
    list.querySelectorAll<HTMLButtonElement>("[data-pb-cancel]").forEach((btn) => {
      btn.addEventListener("click", () => {
        editingPlaybookId = null;
        render();
      });
    });
    list.querySelectorAll<HTMLButtonElement>("[data-pb-delete]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const pb = playbooks.find((p) => p.id === btn.dataset.pbDelete);
        if (!pb) return;
        if (!confirm(`Delete playbook "${pb.title}"?`)) return;
        playbooks = playbooks.filter((p) => p.id !== pb.id);
        savePlaybooks(playbooks);
        render();
      });
    });
    list.querySelectorAll<HTMLButtonElement>("[data-pb-save]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const id = btn.dataset.pbSave!;
        const pb = playbooks.find((p) => p.id === id);
        if (!pb) return;
        pb.title = (document.getElementById(`pbe-title-${id}`) as HTMLInputElement).value.trim() || "Untitled Playbook";
        pb.description = (document.getElementById(`pbe-desc-${id}`) as HTMLTextAreaElement).value;
        const parsed = (document.getElementById(`pbe-techniques-${id}`) as HTMLInputElement).value
          .split(",")
          .map((s) => s.trim().toUpperCase())
          .filter(Boolean);
        const valid = parsed.filter((tid) => mitreEntryById(tid));
        if (valid.length !== parsed.length) ctx.flashStatus("Some technique IDs weren't recognized and were dropped");
        pb.techniques = valid;
        pb.suggestedQuery = (document.getElementById(`pbe-query-${id}`) as HTMLTextAreaElement).value;
        savePlaybooks(playbooks);
        editingPlaybookId = null;
        ctx.flashStatus(`Saved playbook: ${pb.title}`);
        render();
      });
    });
  }

  render();
}

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
  HUNT_STATUS_LABELS,
  huntFromPlaybook,
  isDueForReview,
  loadHunts,
  loadPlaybooks,
  mergeById,
  newPlaybookId,
  parseBackup,
  saveHunts,
  savePlaybooks,
  type Hunt,
  type HuntPriority,
  type HuntStatus,
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

type HuntsTab = "hunts" | "coverage" | "playbooks";

export function initHuntsView(container: HTMLElement, ctx: HuntsViewContext): void {
  let hunts: Hunt[] = loadHunts();
  let playbooks: Playbook[] = loadPlaybooks();
  let activeTab: HuntsTab = "hunts";
  let statusFilter: "all" | HuntStatus = "all";
  let priorityFilter: "all" | HuntPriority = "all";
  let dueOnlyFilter = false;
  let keywordFilter = "";
  let draftHunt: Hunt | null = null;
  let editingPlaybookId: string | null = null;

  // All MITRE technique/sub-technique ids+names in one place, for chip
  // labels, the add-technique lookup, and the autocomplete datalist.
  const MITRE_ALL = [
    ...MITRE_TECHNIQUES.map((t) => ({ id: t.id, name: t.name })),
    ...MITRE_SUBTECHNIQUES.map((t) => ({ id: t.id, name: t.name })),
  ];

  function cloneHunt(h: Hunt): Hunt {
    return { ...h, techniques: [...h.techniques], dataSources: [...h.dataSources], iocs: [...h.iocs] };
  }

  function selectHunt(hunt: Hunt) {
    draftHunt = cloneHunt(hunt);
    activeTab = "hunts";
  }

  // -------------------------------------------------------------------------
  // Top-level render
  // -------------------------------------------------------------------------
  function render() {
    container.innerHTML = `
      <div class="hunts-toolbar">
        <div class="hunts-tabs">
          <button data-htab="hunts" class="${activeTab === "hunts" ? "active" : ""}">🎯 Hunts</button>
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
    if (activeTab === "hunts") renderHuntsTab(body);
    else if (activeTab === "coverage") renderCoverageTab(body);
    else renderPlaybooksTab(body);
  }

  // -------------------------------------------------------------------------
  // Hunts tab: list + detail
  // -------------------------------------------------------------------------
  function matchesKeyword(h: Hunt, needle: string): boolean {
    const haystack = [h.title, h.hypothesis, h.findings, h.queries, ...h.dataSources, ...h.techniques]
      .join("\n")
      .toLowerCase();
    return haystack.includes(needle);
  }

  function renderHuntsList(): string {
    const needle = keywordFilter.trim().toLowerCase();
    const filtered = hunts
      .filter((h) => statusFilter === "all" || h.status === statusFilter)
      .filter((h) => priorityFilter === "all" || h.priority === priorityFilter)
      .filter((h) => !dueOnlyFilter || isDueForReview(h))
      .filter((h) => !needle || matchesKeyword(h, needle))
      .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
    if (filtered.length === 0) {
      return hunts.length === 0
        ? `<p class="ioc-empty">No hunts yet. Click "+ New Hunt" to start one, or pick a playbook.</p>`
        : `<p class="ioc-empty">No hunts match the current filters.</p>`;
    }
    return filtered
      .map((h) => {
        const chips = h.techniques
          .slice(0, 3)
          .map((id) => `<span class="tag-chip-mini">${escapeHtml(id)}</span>`)
          .join("");
        const more = h.techniques.length > 3 ? `<span class="tag-chip-mini">+${h.techniques.length - 3}</span>` : "";
        const due = isDueForReview(h) ? `<span class="due-badge" title="Recurring hunt — due for another look">⏰ Due</span>` : "";
        return `
        <div class="hunt-row ${h.id === draftHunt?.id ? "active" : ""}" data-hunt-id="${h.id}">
          <div class="hunt-row-top">
            <span class="status-badge status-${h.status}">${HUNT_STATUS_LABELS[h.status]}</span>
            <span class="priority-badge priority-${h.priority}">${HUNT_PRIORITY_LABELS[h.priority]}</span>
            <span class="hunt-row-title">${escapeHtml(h.title)}</span>
          </div>
          <div class="hunt-row-meta">${chips}${more}${due}</div>
          <div class="hunt-row-updated">Updated ${relTime(h.updatedAt)}</div>
        </div>`;
      })
      .join("");
  }

  function renderHuntsTab(body: HTMLDivElement) {
    body.innerHTML = `
      <div class="hunts-layout">
        <div class="hunts-list-pane">
          <div class="hunts-list-toolbar">
            <input type="text" class="text-input" id="hunt-search" placeholder="Search hunts…" value="${escapeAttr(keywordFilter)}" />
            <button class="primary" id="btn-new-hunt">+ New Hunt</button>
          </div>
          <div class="hunts-list-toolbar">
            <select id="hunt-status-filter">
              <option value="all">All statuses</option>
              <option value="open">Open</option>
              <option value="in_progress">In Progress</option>
              <option value="closed">Closed</option>
            </select>
            <select id="hunt-priority-filter">
              <option value="all">All priorities</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
          <label class="hunt-due-filter"><input type="checkbox" id="hunt-due-filter" ${dueOnlyFilter ? "checked" : ""} /> Due for review only</label>
          <div class="hunts-list" id="hunts-list">${renderHuntsList()}</div>
        </div>
        <div class="hunt-detail-pane" id="hunt-detail-pane">
          ${draftHunt ? "" : `<div class="hunts-empty-state">Select a hunt from the list, or start a new one.</div>`}
        </div>
      </div>
    `;
    const searchEl = body.querySelector<HTMLInputElement>("#hunt-search")!;
    searchEl.addEventListener("input", () => {
      keywordFilter = searchEl.value;
      const list = body.querySelector<HTMLDivElement>("#hunts-list")!;
      list.innerHTML = renderHuntsList();
      wireHuntRows(list);
    });
    const filterEl = body.querySelector<HTMLSelectElement>("#hunt-status-filter")!;
    filterEl.value = statusFilter;
    filterEl.addEventListener("change", () => {
      statusFilter = filterEl.value as typeof statusFilter;
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
      draftHunt = emptyHunt();
      render();
    });
    wireHuntRows(body.querySelector<HTMLDivElement>("#hunts-list")!);

    if (draftHunt) {
      const pane = body.querySelector<HTMLDivElement>("#hunt-detail-pane")!;
      pane.innerHTML = renderHuntDetail(draftHunt);
      wireHuntDetail(pane);
    }
  }

  function wireHuntRows(list: HTMLDivElement) {
    list.querySelectorAll<HTMLDivElement>(".hunt-row").forEach((row) => {
      row.addEventListener("click", () => {
        const hunt = hunts.find((h) => h.id === row.dataset.huntId);
        if (!hunt) return;
        selectHunt(hunt);
        render();
      });
    });
  }

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

  function renderHuntDetail(hunt: Hunt): string {
    const isNew = !hunts.some((h) => h.id === hunt.id);
    const kqlNames = Object.keys(ctx.getKqlSnippets()).sort();
    const due = isDueForReview(hunt);
    return `
      <div class="hunt-detail">
        <div class="hunt-detail-header">
          <input class="text-input hunt-title-input" id="hd-title" value="${escapeAttr(hunt.title)}" placeholder="Hunt title" />
          <select id="hd-priority" title="Triage priority">
            <option value="high">🔺 High</option>
            <option value="medium">▪ Medium</option>
            <option value="low">▫ Low</option>
          </select>
          <select id="hd-status">
            <option value="open">Open</option>
            <option value="in_progress">In Progress</option>
            <option value="closed">Closed</option>
          </select>
        </div>
        <div class="hunt-meta-line">
          ${isNew ? "Not saved yet" : `Created ${relTime(hunt.createdAt)} · Updated ${relTime(hunt.updatedAt)}${hunt.closedAt ? ` · Closed ${relTime(hunt.closedAt)}` : ""}`}
          ${due ? `<span class="due-badge" title="Recurring hunt — due for another look">⏰ Due for review</span>` : ""}
        </div>

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

        <label class="hunt-field-label">Recurring</label>
        <div class="recurring-row">
          Revisit every
          <input type="number" min="1" class="text-input recurring-input" id="hd-recurring" value="${hunt.recurringDays ?? ""}" placeholder="—" />
          day(s) (blank = one-off hunt)
        </div>

        <div class="modal-actions hunt-actions">
          <button id="hd-delete">🗑 Delete</button>
          <button id="hd-copy-report">📋 Copy Report</button>
          <button id="hd-download-report">⬇ Download</button>
          <button class="primary" id="hd-save">💾 Save Hunt</button>
        </div>
      </div>
    `;
  }

  // Any button inside the detail pane that mutates draftHunt and re-renders
  // must first pull the live (possibly unsaved) field values out of the DOM —
  // otherwise the re-render rebuilds the form from the stale draftHunt object
  // and silently discards whatever the user had typed but not yet saved.
  function syncFormFieldsToDraft(pane: HTMLDivElement) {
    if (!draftHunt) return;
    const title = pane.querySelector<HTMLInputElement>("#hd-title");
    if (title) draftHunt.title = title.value;
    const priority = pane.querySelector<HTMLSelectElement>("#hd-priority");
    if (priority) draftHunt.priority = priority.value as HuntPriority;
    const status = pane.querySelector<HTMLSelectElement>("#hd-status");
    if (status) draftHunt.status = status.value as HuntStatus;
    const hypothesis = pane.querySelector<HTMLTextAreaElement>("#hd-hypothesis");
    if (hypothesis) draftHunt.hypothesis = hypothesis.value;
    const dataSources = pane.querySelector<HTMLTextAreaElement>("#hd-datasources");
    if (dataSources) draftHunt.dataSources = dataSources.value.split("\n").map((s) => s.trim()).filter(Boolean);
    const queries = pane.querySelector<HTMLTextAreaElement>("#hd-queries");
    if (queries) draftHunt.queries = queries.value;
    const findings = pane.querySelector<HTMLTextAreaElement>("#hd-findings");
    if (findings) draftHunt.findings = findings.value;
    const recurring = pane.querySelector<HTMLInputElement>("#hd-recurring");
    if (recurring) {
      const n = parseInt(recurring.value, 10);
      draftHunt.recurringDays = Number.isFinite(n) && n > 0 ? n : undefined;
    }
  }

  function wireHuntDetail(pane: HTMLDivElement) {
    if (!draftHunt) return;
    const statusEl = pane.querySelector<HTMLSelectElement>("#hd-status")!;
    statusEl.value = draftHunt.status;
    const priorityEl = pane.querySelector<HTMLSelectElement>("#hd-priority")!;
    priorityEl.value = draftHunt.priority;

    pane.querySelector("#hd-add-technique")!.addEventListener("click", () => {
      const input = pane.querySelector<HTMLInputElement>("#hd-technique-input")!;
      const raw = input.value.trim();
      if (!raw) return;
      const idToken = raw.split(/\s+/)[0].toUpperCase();
      const technique = mitreEntryById(idToken);
      if (!technique) {
        ctx.flashStatus(`Unknown technique: ${raw}`);
        return;
      }
      syncFormFieldsToDraft(pane);
      if (!draftHunt!.techniques.includes(technique.id)) draftHunt!.techniques.push(technique.id);
      render();
    });
    pane.querySelectorAll<HTMLSpanElement>("[data-remove-technique]").forEach((btn) => {
      btn.addEventListener("click", () => {
        syncFormFieldsToDraft(pane);
        draftHunt!.techniques = draftHunt!.techniques.filter((t) => t !== btn.dataset.removeTechnique);
        render();
      });
    });

    pane.querySelector("#hd-kql-picker")!.addEventListener("change", (e) => {
      const select = e.target as HTMLSelectElement;
      const name = select.value;
      if (!name) return;
      const text = ctx.getKqlSnippets()[name] ?? "";
      const queriesEl = pane.querySelector<HTMLTextAreaElement>("#hd-queries")!;
      queriesEl.value = queriesEl.value.trim() ? `${queriesEl.value.trim()}\n\n${text}` : text;
      select.value = "";
      ctx.flashStatus(`Inserted KQL: ${name}`);
    });

    pane.querySelector("#hd-extract-iocs")!.addEventListener("click", () => {
      syncFormFieldsToDraft(pane);
      draftHunt!.iocs = extractHuntIocs(draftHunt!);
      ctx.flashStatus(`Extracted ${draftHunt!.iocs.length} IOC(s)`);
      render();
    });

    pane.querySelectorAll<HTMLDivElement>(".ioc-value[data-copy]").forEach((el) => {
      el.addEventListener("click", () => {
        navigator.clipboard.writeText(el.dataset.copy ?? "");
        ctx.flashStatus(`Copied ${el.dataset.copy}`);
      });
    });
    pane.querySelector("#hd-ioc-csv")?.addEventListener("click", () => exportIocsCsv(draftHunt!.iocs));
    pane.querySelector("#hd-ioc-json")?.addEventListener("click", () => exportIocsJson(draftHunt!.iocs));
    pane.querySelector("#hd-ioc-txt")?.addEventListener("click", () =>
      exportIocsText(
        Object.fromEntries(Object.entries(groupIocs(draftHunt!.iocs)).map(([k, v]) => [IOC_LABELS[k as IocType], v])),
      ),
    );

    pane.querySelector("#hd-copy-report")!.addEventListener("click", () => {
      syncFormFieldsToDraft(pane);
      navigator.clipboard.writeText(buildHuntReport(draftHunt!));
      ctx.flashStatus("Hunt report copied");
    });
    pane.querySelector("#hd-download-report")!.addEventListener("click", () => {
      syncFormFieldsToDraft(pane);
      const slug = draftHunt!.title.replace(/[^a-z0-9]+/gi, "-").toLowerCase() || "hunt";
      downloadTextFile(`hunt-${slug}.txt`, buildHuntReport(draftHunt!));
    });

    pane.querySelector("#hd-delete")!.addEventListener("click", () => {
      const existed = hunts.some((h) => h.id === draftHunt!.id);
      if (existed && !confirm(`Delete hunt "${draftHunt!.title}"? This cannot be undone.`)) return;
      hunts = hunts.filter((h) => h.id !== draftHunt!.id);
      saveHunts(hunts);
      draftHunt = null;
      ctx.flashStatus("Hunt deleted");
      render();
    });

    pane.querySelector("#hd-save")!.addEventListener("click", () => {
      const wasClosed = draftHunt!.status === "closed";
      syncFormFieldsToDraft(pane);
      const hunt = draftHunt!;
      hunt.title = hunt.title.trim() || "Untitled Hunt";
      if (hunt.status === "closed" && !wasClosed) hunt.closedAt = new Date().toISOString();
      if (hunt.status !== "closed") hunt.closedAt = undefined;
      hunt.updatedAt = new Date().toISOString();

      const idx = hunts.findIndex((h) => h.id === hunt.id);
      if (idx === -1) hunts.push(hunt);
      else hunts[idx] = hunt;
      saveHunts(hunts);
      ctx.flashStatus(`Saved hunt: ${hunt.title}`);
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
        <div><b>${stats.total}</b> hunts total (${stats.open} open, ${stats.inProgress} in progress, ${stats.closed} closed)</div>
        <div><b>${neverCount}</b> never hunted</div>
        ${stats.dueForReview > 0 ? `<div><b>${stats.dueForReview}</b> due for review</div>` : ""}
      </div>
      <p class="coverage-note">A curated subset of top-level MITRE ATT&amp;CK Enterprise techniques (plus a smaller
      set of sub-techniques, rolled up into their parent here), tracked locally — click a technique to jump to its
      hunts, or start a new one. Closed coverage fades as it ages: solid green under 30 days, dimmer past 30, faint
      past 90 — a hunt from months ago isn't the same as one from yesterday.</p>
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
          selectHunt(hunt);
        } else {
          const technique = MITRE_TECHNIQUE_BY_ID[id];
          draftHunt = emptyHunt();
          draftHunt.title = `${technique.name} hunt`;
          draftHunt.techniques = [id];
          activeTab = "hunts";
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
        draftHunt = huntFromPlaybook(pb);
        activeTab = "hunts";
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

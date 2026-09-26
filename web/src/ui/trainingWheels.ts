import { INCIDENT_TYPES, TRAINING_CHECKLISTS } from "../core/checklists";

type Mode = "checklist" | "form";

export interface TrainingWheelsHandlers {
  onInsertNote: (note: string) => void;
  onCopyNote: (note: string) => void;
  onStatus: (message: string) => void;
}

export class TrainingWheelsPanel {
  private container: HTMLElement;
  private handlers: TrainingWheelsHandlers;
  private incidentType = INCIDENT_TYPES[0];
  private mode: Mode = "checklist";
  // checklist mode: Set of "section::item" that are checked
  private checked = new Set<string>();
  // form mode: "incidentType::section::item" -> typed value
  private formValues = new Map<string, string>();

  constructor(container: HTMLElement, handlers: TrainingWheelsHandlers) {
    this.container = container;
    this.handlers = handlers;
    this.render();
  }

  private formKey(section: string, item: string): string {
    return `${this.incidentType}::${section}::${item}`;
  }

  private sections() {
    return TRAINING_CHECKLISTS[this.incidentType] ?? [];
  }

  private render(): void {
    const sections = this.sections();
    const total = sections.reduce((n, [, items]) => n + items.length, 0);
    let done = 0;
    if (this.mode === "checklist") {
      done = this.checked.size;
    } else {
      done = sections.reduce(
        (n, [section, items]) =>
          n + items.filter((item) => (this.formValues.get(this.formKey(section, item)) ?? "").trim()).length,
        0,
      );
    }
    const pct = total > 0 ? Math.round((done / total) * 100) : 0;

    this.container.innerHTML = `
      <div class="tw-header">
        <strong>🎓 Training Wheels — Incident Checklist</strong>
        <select id="tw-incident-type">
          ${INCIDENT_TYPES.map((t) => `<option value="${escapeAttr(t)}" ${t === this.incidentType ? "selected" : ""}>${escapeHtml(t)}</option>`).join("")}
        </select>
        <span class="tw-progress-label">${done} / ${total} ${this.mode === "checklist" ? "completed" : "fields filled"}</span>
        <div class="tw-progress-bar"><div class="tw-progress-fill" style="width:${pct}%"></div></div>
        <span style="flex:1"></span>
        <button id="tw-copy" ${this.mode === "form" ? "" : "disabled"}>📄 Copy Note</button>
        <button id="tw-insert" ${this.mode === "form" ? "" : "disabled"}>⬇ Insert Note</button>
        <button id="tw-mode">${this.mode === "checklist" ? "📋 Form Mode" : "☑ Checklist Mode"}</button>
        <button id="tw-reset">↺ Reset</button>
        <button id="tw-close">✕</button>
      </div>
      <div class="tw-body"></div>
    `;

    const body = this.container.querySelector<HTMLDivElement>(".tw-body")!;
    for (const [section, items] of sections) {
      const sectionEl = document.createElement("div");
      sectionEl.className = "tw-section";
      sectionEl.innerHTML = `<h4>${escapeHtml(section)}</h4>`;
      for (const item of items) {
        const row = document.createElement("div");
        row.className = "tw-item";
        if (this.mode === "checklist") {
          const key = `${section}::${item}`;
          row.innerHTML = `<label><input type="checkbox" ${this.checked.has(key) ? "checked" : ""} /> ${escapeHtml(item)}</label>`;
          row.querySelector("input")!.addEventListener("change", (e) => {
            const checked = (e.target as HTMLInputElement).checked;
            if (checked) this.checked.add(key);
            else this.checked.delete(key);
            this.render();
          });
        } else {
          const key = this.formKey(section, item);
          row.innerHTML = `
            <label class="tw-form-label">${escapeHtml(item)}</label>
            <input type="text" class="text-input" value="${escapeAttr(this.formValues.get(key) ?? "")}" />
          `;
          row.querySelector("input")!.addEventListener("input", (e) => {
            this.formValues.set(key, (e.target as HTMLInputElement).value);
            this.updateProgressOnly();
          });
        }
        sectionEl.appendChild(row);
      }
      body.appendChild(sectionEl);
    }

    this.container.querySelector("#tw-incident-type")!.addEventListener("change", (e) => {
      this.incidentType = (e.target as HTMLSelectElement).value;
      this.render();
    });
    this.container.querySelector("#tw-mode")!.addEventListener("click", () => {
      this.mode = this.mode === "checklist" ? "form" : "checklist";
      this.render();
    });
    this.container.querySelector("#tw-reset")!.addEventListener("click", () => {
      if (this.mode === "checklist") {
        this.checked.clear();
      } else {
        for (const [section, items] of sections) {
          for (const item of items) this.formValues.delete(this.formKey(section, item));
        }
      }
      this.render();
    });
    this.container.querySelector("#tw-copy")!.addEventListener("click", () => {
      const note = this.buildNote();
      if (!note) return this.handlers.onStatus("Nothing to copy — fill in some fields in Form Mode first");
      navigator.clipboard.writeText(note);
      this.handlers.onCopyNote(note);
    });
    this.container.querySelector("#tw-insert")!.addEventListener("click", () => {
      const note = this.buildNote();
      if (!note) return this.handlers.onStatus("Nothing to insert — fill in some fields in Form Mode first");
      this.handlers.onInsertNote(note);
    });
    this.container.querySelector("#tw-close")!.addEventListener("click", () => {
      this.container.classList.add("hidden");
    });
  }

  private updateProgressOnly(): void {
    const label = this.container.querySelector(".tw-progress-label");
    const fill = this.container.querySelector<HTMLDivElement>(".tw-progress-fill");
    if (!label || !fill) return;
    const sections = this.sections();
    const total = sections.reduce((n, [, items]) => n + items.length, 0);
    const done = sections.reduce(
      (n, [section, items]) =>
        n + items.filter((item) => (this.formValues.get(this.formKey(section, item)) ?? "").trim()).length,
      0,
    );
    label.textContent = `${done} / ${total} fields filled`;
    fill.style.width = `${total > 0 ? Math.round((done / total) * 100) : 0}%`;
  }

  /** Ported from _tw_build_note(): plain-text note from form-mode fields only; null if nothing filled. */
  private buildNote(): string | null {
    const sections = this.sections();
    const now = new Date();
    const stamp = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}`;
    const lines: string[] = [
      "=".repeat(60),
      `  INCIDENT NOTE -- ${this.incidentType.toUpperCase()}`,
      `  Generated: ${stamp}`,
      "=".repeat(60),
      "",
    ];
    let anyFilled = false;
    for (const [section, items] of sections) {
      const filled = items
        .map((item) => [item, (this.formValues.get(this.formKey(section, item)) ?? "").trim()] as const)
        .filter(([, value]) => value);
      if (filled.length === 0) continue;
      anyFilled = true;
      const dashes = "─".repeat(Math.max(3, 60 - section.length - 4));
      lines.push(`── ${section} ${dashes}`);
      for (const [item, value] of filled) {
        lines.push(`  [${item}]`);
        lines.push(`  ${value}`);
      }
      lines.push("");
    }
    lines.push("=".repeat(60));
    return anyFilled ? lines.join("\n") : null;
  }

  setVisible(visible: boolean): void {
    this.container.classList.toggle("hidden", !visible);
  }
  isVisible(): boolean {
    return !this.container.classList.contains("hidden");
  }
}

function pad(n: number): string {
  return String(n).padStart(2, "0");
}
function escapeHtml(s: string): string {
  const div = document.createElement("div");
  div.textContent = s;
  return div.innerHTML;
}
function escapeAttr(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/"/g, "&quot;");
}

import "./style.css";
import { TabManager } from "./editor/tabs";
import { defangText, refangText } from "./core/defang";
import { extractIocs, groupIocs, IOC_LABELS, type IocMatch } from "./core/iocPatterns";
import { base64Decode, base64Encode, generateHash, identifyHashTypes } from "./core/hashes";
import { downloadTextFile, exportIocsCsv, exportIocsJson, exportIocsText } from "./core/exportIocs";
import {
  hasFileSystemAccess,
  openFromDataTransferItem,
  openFromInputFile,
  pickAndOpenFile,
  pickAndSaveFile,
  writeToHandle,
} from "./core/fileSystem";
import {
  DEFAULT_SETTINGS,
  fillPlaceholders,
  loadKqlSnippets,
  loadSession,
  loadSettings,
  loadSnippets,
  loadTemplates,
  saveKqlSnippets,
  saveSession,
  saveSettings,
  saveSnippets,
  saveTemplates,
  type Settings,
} from "./core/storage";
import { initPhase3, type Phase3Hooks } from "./ui/phase3";
import { initHuntsView } from "./ui/hunts";

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
let settings: Settings = loadSettings();
let templates = loadTemplates();
let snippets = loadSnippets();
let kqlSnippets = loadKqlSnippets();
let lastIocMatches: IocMatch[] = [];
let phase3Hooks: Phase3Hooks;

document.documentElement.setAttribute("data-theme", settings.darkMode ? "dark" : "light");

// ---------------------------------------------------------------------------
// Shell
// ---------------------------------------------------------------------------
const app = document.querySelector<HTMLDivElement>("#app")!;
app.innerHTML = `
  <div class="toolbar">
    <div class="toolbar-left">
      <span class="app-title">ThreatPad</span>
      <button id="btn-view-hunts" class="view-toggle-btn">🎯 Hunts</button>

      <div class="menu">
        <button class="menu-trigger">File ▾</button>
        <div class="menu-list">
          <button id="btn-new">New Tab</button>
          <button id="btn-open">Open…</button>
          <button id="btn-save">Save</button>
          <button id="btn-save-as">Save As…</button>
        </div>
      </div>

      <div class="menu">
        <button class="menu-trigger">IOC Tools ▾</button>
        <div class="menu-list">
          <button id="btn-extract" title="Ctrl+I">Extract IOCs</button>
        </div>
      </div>

      <div class="menu">
        <button class="menu-trigger">Hash ▾</button>
        <div class="menu-list">
          <button id="btn-md5">MD5</button>
          <button id="btn-sha1">SHA1</button>
          <button id="btn-sha256">SHA256</button>
          <button id="btn-identify">Identify Hash</button>
        </div>
      </div>

      <div class="menu">
        <button class="menu-trigger">Encode ▾</button>
        <div class="menu-list">
          <button id="btn-b64enc">Base64 Encode</button>
          <button id="btn-b64dec">Base64 Decode</button>
        </div>
      </div>
    </div>

    <div class="toolbar-center">
      <button id="btn-defang" class="center-action center-action-solid" title="Ctrl+D">🛡 Defang</button>
      <button id="btn-refang" class="center-action center-action-outline" title="Ctrl+R">♻ Refang</button>
      <div class="menu kql-menu" id="kql-menu">
        <button class="menu-trigger center-action center-action-outline" title="Saved KQL snippets">📊 KQL ▾</button>
        <div class="menu-list" id="kql-menu-list"></div>
      </div>
    </div>

    <div class="toolbar-right">
      <select id="client-select" title="Active client"></select>

      <div class="menu menu-align-right">
        <button class="menu-trigger">Client ▾</button>
        <div class="menu-list">
          <button id="btn-manage-clients">Manage Clients…</button>
          <button id="btn-contamination-check">⚠ Contamination Check</button>
        </div>
      </div>

      <div class="menu menu-align-right">
        <button class="menu-trigger">SOC ▾</button>
        <div class="menu-list">
          <button id="btn-training-wheels">🎓 Checklist</button>
          <button id="btn-breakglass">🚨 Mistake?</button>
          <button id="btn-mileage">📊 Mileage</button>
        </div>
      </div>

      <button id="btn-toggle-sidebar" title="Show/Hide IOC pane"></button>
      <button id="btn-theme"></button>
      <button id="btn-settings" title="Settings">⚙</button>
    </div>
  </div>
  <div class="tab-bar" id="tab-bar"></div>
  <div class="tw-panel hidden" id="tw-panel"></div>
  <div class="main" id="main-view">
    <div class="editor-container" id="editor"></div>
    <div class="sidebar" id="sidebar">
      <div class="sidebar-tabs">
        <button data-panel="iocs" class="active">IOCs</button>
        <button data-panel="templates">Templates</button>
        <button data-panel="snippets">Snippets</button>
      </div>
      <div class="sidebar-panel active" id="panel-iocs"></div>
      <div class="sidebar-panel" id="panel-templates"></div>
      <div class="sidebar-panel" id="panel-snippets"></div>
    </div>
  </div>
  <div class="hunts-view hidden" id="hunts-view"></div>
  <div class="status-bar">
    <span id="status-left">Ready</span>
    <span class="status-right-group">
      <span id="traffic-light" class="traffic-dot" title="Content safety indicator"></span>
      <span id="timer-display">⏱ --:--</span>
      <span id="status-right"></span>
    </span>
  </div>
  <div class="fab-group">
    <button id="btn-clear-note" class="fab-circle" title="Clear the current note">✕</button>
    <button id="btn-safe-copy" class="fab" title="Blocks copy on cross-client contamination">🔒 Safe Copy</button>
  </div>
  <button id="btn-help" class="fab fab-help" title="Help / quick reference">?</button>
  <input type="file" id="file-input" accept=".txt,.log,.md,.csv,.json" style="display:none" />
`;

const editorContainer = document.querySelector<HTMLDivElement>("#editor")!;
const tabBar = document.querySelector<HTMLDivElement>("#tab-bar")!;
const statusLeft = document.querySelector<HTMLSpanElement>("#status-left")!;
const statusRight = document.querySelector<HTMLSpanElement>("#status-right")!;
const themeBtn = document.querySelector<HTMLButtonElement>("#btn-theme")!;
const fileInput = document.querySelector<HTMLInputElement>("#file-input")!;

// ---------------------------------------------------------------------------
// Toolbar dropdown menus
// ---------------------------------------------------------------------------
function closeAllMenus() {
  document.querySelectorAll(".menu.open").forEach((m) => m.classList.remove("open"));
}
document.querySelectorAll<HTMLDivElement>(".toolbar .menu").forEach((menu) => {
  const trigger = menu.querySelector<HTMLButtonElement>(".menu-trigger")!;
  trigger.addEventListener("click", (e) => {
    e.stopPropagation();
    const wasOpen = menu.classList.contains("open");
    closeAllMenus();
    if (!wasOpen) menu.classList.add("open");
  });
});
document.addEventListener("click", closeAllMenus);
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeAllMenus();
});

// ---------------------------------------------------------------------------
// Editor / tabs
// ---------------------------------------------------------------------------
const tabs = new TabManager(editorContainer, settings, {
  onChange: () => {
    scheduleAutosave();
    updateStatus();
    phase3Hooks?.onTextChanged();
  },
  onTabsUpdated: () => {
    renderTabBar();
    persistSession();
  },
});

const session = loadSession();
if (session && session.tabs.length > 0) {
  tabs.restore(session.tabs, session.activeTabId);
} else {
  tabs.createTab("Untitled", "");
}

function renderTabBar() {
  const activeId = tabs.activeTabId();
  tabBar.innerHTML = "";
  for (const t of tabs.list()) {
    const el = document.createElement("div");
    el.className = "tab" + (t.id === activeId ? " active" : "");
    el.innerHTML = `<span class="tab-title">${escapeHtml(t.title)}</span><span class="tab-close" data-id="${t.id}">✕</span>`;
    el.addEventListener("click", (e) => {
      if ((e.target as HTMLElement).classList.contains("tab-close")) return;
      tabs.switchTab(t.id);
      updateStatus();
    });
    el.querySelector(".tab-close")!.addEventListener("click", (e) => {
      e.stopPropagation();
      tabs.closeTab(t.id);
      phase3Hooks?.onTabClosed(t.id);
    });
    el.addEventListener("dblclick", (e) => {
      if ((e.target as HTMLElement).classList.contains("tab-close")) return;
      startRenameTab(el, t.id, t.title);
    });
    tabBar.appendChild(el);
  }
  const newBtn = document.createElement("div");
  newBtn.className = "tab-new";
  newBtn.textContent = "+";
  newBtn.title = "New tab (Ctrl+N)";
  newBtn.addEventListener("click", () => tabs.createTab("Untitled", ""));
  tabBar.appendChild(newBtn);
}

function startRenameTab(tabEl: HTMLDivElement, id: string, currentTitle: string) {
  const titleSpan = tabEl.querySelector<HTMLSpanElement>(".tab-title");
  if (!titleSpan) return;

  const input = document.createElement("input");
  input.type = "text";
  input.className = "tab-rename-input";
  input.value = currentTitle;
  titleSpan.replaceWith(input);
  input.focus();
  input.select();

  let settled = false;
  const commit = () => {
    if (settled) return;
    settled = true;
    const value = input.value.trim();
    tabs.renameTab(id, value || currentTitle);
  };
  input.addEventListener("click", (e) => e.stopPropagation());
  input.addEventListener("keydown", (e) => {
    e.stopPropagation();
    if (e.key === "Enter") input.blur();
    else if (e.key === "Escape") {
      settled = true;
      input.blur();
      renderTabBar();
    }
  });
  input.addEventListener("blur", commit, { once: true });
}

let autosaveHandle: number | undefined;
function scheduleAutosave() {
  window.clearTimeout(autosaveHandle);
  autosaveHandle = window.setTimeout(persistSession, 400);
}
function persistSession() {
  saveSession({ tabs: tabs.serialize(), activeTabId: tabs.activeTabId() });
  const now = new Date();
  statusRight.textContent = `Saved ${now.toLocaleTimeString()}`;
}

function updateStatus() {
  const content = tabs.getContent();
  const words = content.trim() ? content.trim().split(/\s+/).length : 0;
  statusLeft.textContent = `${content.length} chars · ${words} words`;
}

function escapeHtml(s: string): string {
  const div = document.createElement("div");
  div.textContent = s;
  return div.innerHTML;
}

// ---------------------------------------------------------------------------
// Toolbar actions
// ---------------------------------------------------------------------------
document.querySelector("#btn-new")!.addEventListener("click", () => tabs.createTab("Untitled", ""));

document.querySelector("#btn-open")!.addEventListener("click", async () => {
  if (hasFileSystemAccess) {
    try {
      const opened = await pickAndOpenFile();
      if (!opened) return; // user cancelled
      const id = tabs.createTab(opened.name, opened.content);
      if (opened.handle) tabs.attachFileHandle(id, opened.handle);
      flashStatus(`Opened ${opened.name}`);
    } catch (e) {
      alert((e as Error).message ?? "Could not open file");
    }
    return;
  }
  fileInput.click();
});
fileInput.addEventListener("change", async () => {
  const file = fileInput.files?.[0];
  fileInput.value = "";
  if (!file) return;
  try {
    const opened = await openFromInputFile(file);
    tabs.createTab(opened.name, opened.content);
    flashStatus(`Opened ${opened.name}`);
  } catch (e) {
    alert((e as Error).message ?? "Could not open file");
  }
});

async function saveActiveTab(forcePicker: boolean) {
  const activeId = tabs.activeTabId();
  const active = tabs.list().find((t) => t.id === activeId);
  const content = tabs.getContent();
  const existingHandle = activeId ? tabs.getFileHandle(activeId) : undefined;

  if (!forcePicker && existingHandle) {
    try {
      await writeToHandle(existingHandle, content);
      flashStatus(`Saved ${active?.title ?? ""}`);
      return;
    } catch (e) {
      alert(`Could not save file: ${(e as Error).message}`);
      return;
    }
  }

  if (hasFileSystemAccess) {
    try {
      const suggested = active ? active.title : "note.txt";
      const handle = await pickAndSaveFile(suggested, content);
      if (!handle) return; // user cancelled
      if (activeId) {
        tabs.attachFileHandle(activeId, handle);
        tabs.renameTab(activeId, handle.name);
      }
      flashStatus(`Saved ${handle.name}`);
    } catch (e) {
      alert(`Could not save file: ${(e as Error).message}`);
    }
    return;
  }

  const filename = active ? `${active.title}.txt` : "note.txt";
  downloadTextFile(filename, content);
  flashStatus("Saved to downloads");
}

document.querySelector("#btn-save")!.addEventListener("click", () => saveActiveTab(false));
document.querySelector("#btn-save-as")!.addEventListener("click", () => saveActiveTab(true));

// Drag & drop files onto the editor open them as new tabs.
editorContainer.addEventListener("dragover", (e) => {
  e.preventDefault();
  if (e.dataTransfer) e.dataTransfer.dropEffect = "copy";
  editorContainer.classList.add("drag-over");
});
editorContainer.addEventListener("dragleave", () => editorContainer.classList.remove("drag-over"));
editorContainer.addEventListener("drop", async (e) => {
  e.preventDefault();
  editorContainer.classList.remove("drag-over");
  const items = e.dataTransfer?.items;
  const files = e.dataTransfer?.files;
  try {
    if (items && items.length > 0) {
      for (const item of Array.from(items)) {
        if (item.kind !== "file") continue;
        const opened = await openFromDataTransferItem(item);
        if (!opened) continue;
        const id = tabs.createTab(opened.name, opened.content);
        if (opened.handle) tabs.attachFileHandle(id, opened.handle);
      }
    } else if (files) {
      for (const file of Array.from(files)) {
        const opened = await openFromInputFile(file);
        tabs.createTab(opened.name, opened.content);
      }
    }
    flashStatus("Opened dropped file(s)");
  } catch (e) {
    alert((e as Error).message ?? "Could not open dropped file");
  }
});

document.querySelector("#btn-defang")!.addEventListener("click", doDefang);
document.querySelector("#btn-refang")!.addEventListener("click", doRefang);
document.querySelector("#btn-extract")!.addEventListener("click", doExtract);

function doDefang() {
  tabs.setContent(defangText(tabs.getContent()));
  flashStatus("Defanged IOCs");
  phase3Hooks?.onDefang();
}
function doRefang() {
  tabs.setContent(refangText(tabs.getContent()));
  flashStatus("Refanged IOCs");
}
function doExtract() {
  lastIocMatches = extractIocs(tabs.getContent());
  renderIocPanel();
  switchSidebar("iocs");
  flashStatus(`Extracted ${lastIocMatches.length} IOC(s)`);
  phase3Hooks?.onExtractIocs(lastIocMatches.length);
}

document.querySelector("#btn-md5")!.addEventListener("click", () => showHash("md5"));
document.querySelector("#btn-sha1")!.addEventListener("click", () => showHash("sha1"));
document.querySelector("#btn-sha256")!.addEventListener("click", () => showHash("sha256"));

function showHash(algo: "md5" | "sha1" | "sha256") {
  const text = tabs.getSelectionOrAll();
  if (!text.trim()) return flashStatus("No text to hash");
  const hash = generateHash(algo, text);
  openModal(`${algo.toUpperCase()} Hash`, `
    <label style="display:block;margin-bottom:4px;">Result</label>
    <input class="text-input" readonly value="${escapeHtml(hash)}" id="hash-output" />
    <div class="modal-actions">
      <button class="primary" id="hash-copy">Copy</button>
    </div>
  `);
  document.querySelector("#hash-copy")!.addEventListener("click", () => {
    navigator.clipboard.writeText(hash);
    flashStatus(`${algo.toUpperCase()} hash copied`);
    closeModal();
  });
}

document.querySelector("#btn-identify")!.addEventListener("click", () => {
  const selected = tabs.getSelectionOrAll().trim();
  const input = selected.length > 0 && selected.length <= 200 ? selected : prompt("Enter hash to identify:") ?? "";
  if (!input.trim()) return;
  const types = identifyHashTypes(input.trim());
  const result = types.length ? `Possible hash type(s): ${types.join(", ")}` : "Unknown hash type or invalid format";
  openModal("Hash Type Identification", `<p style="font-size:13px;">${escapeHtml(result)}</p>`);
});

document.querySelector("#btn-b64enc")!.addEventListener("click", () => {
  const text = tabs.getSelectionOrAll();
  if (!text.trim()) return flashStatus("No text to encode");
  try {
    tabs.insertAtCursor(base64Encode(text));
    flashStatus("Base64 encoded");
  } catch {
    flashStatus("Could not encode text");
  }
});
document.querySelector("#btn-b64dec")!.addEventListener("click", () => {
  const text = tabs.getSelectionOrAll();
  if (!text.trim()) return flashStatus("No text to decode");
  try {
    tabs.insertAtCursor(base64Decode(text));
    flashStatus("Base64 decoded");
  } catch {
    flashStatus("Could not decode Base64 — invalid input");
  }
});

function flashStatus(msg: string) {
  statusLeft.textContent = msg;
  window.setTimeout(updateStatus, 1800);
}

// ---------------------------------------------------------------------------
// KQL snippets: saved-query dropdown (copies to clipboard) + Manage KQL modal
// ---------------------------------------------------------------------------
function renderKqlMenu() {
  const list = document.querySelector<HTMLDivElement>("#kql-menu-list")!;
  const names = Object.keys(kqlSnippets).sort();
  list.innerHTML =
    (names.length > 0
      ? names.map((n) => `<button class="kql-item" data-name="${escapeHtml(n)}">${escapeHtml(n)}</button>`).join("")
      : `<div class="kql-empty">No saved KQL yet</div>`) +
    `<div class="menu-divider"></div><button id="btn-manage-kql">Manage KQL…</button>`;

  list.querySelectorAll<HTMLButtonElement>(".kql-item").forEach((btn) => {
    btn.addEventListener("click", () => {
      const name = btn.dataset.name!;
      navigator.clipboard.writeText(kqlSnippets[name] ?? "");
      flashStatus(`Copied KQL: ${name}`);
      closeAllMenus();
    });
  });
  document.querySelector("#btn-manage-kql")!.addEventListener("click", () => {
    closeAllMenus();
    openKqlManager();
  });
}
renderKqlMenu();

function openKqlManager() {
  const names = Object.keys(kqlSnippets).sort();
  openModal(
    "Manage KQL",
    `
    <div style="display:flex;gap:10px;">
      <div style="width:160px;">
        <select id="km-list" size="8" style="width:100%;">
          ${names.map((n) => `<option value="${escapeHtml(n)}">${escapeHtml(n)}</option>`).join("")}
        </select>
        <button id="km-add" style="width:100%;margin-top:6px;">+ Add</button>
        <button id="km-delete" style="width:100%;margin-top:4px;">Delete</button>
      </div>
      <div style="flex:1;">
        <label style="display:block;font-size:12px;margin-bottom:2px;">KQL query</label>
        <textarea class="snippet-editor" id="km-text" style="min-height:220px;"></textarea>
      </div>
    </div>
    <div class="modal-actions">
      <button class="primary" id="km-save">Save</button>
      <button id="km-close">Close</button>
    </div>
  `,
    { wide: true },
  );

  const listEl = document.querySelector<HTMLSelectElement>("#km-list")!;
  const textEl = document.querySelector<HTMLTextAreaElement>("#km-text")!;

  function loadIntoForm(name: string) {
    textEl.value = kqlSnippets[name] ?? "";
  }
  if (names.length > 0) {
    listEl.selectedIndex = 0;
    loadIntoForm(names[0]);
  }
  listEl.addEventListener("change", () => loadIntoForm(listEl.value));

  document.querySelector("#km-add")!.addEventListener("click", () => {
    const name = prompt("Snippet name:");
    if (!name || !name.trim()) return;
    if (kqlSnippets[name]) return alert("A KQL snippet with that name already exists.");
    kqlSnippets[name] = "";
    saveKqlSnippets(kqlSnippets);
    renderKqlMenu();
    openKqlManager();
  });
  document.querySelector("#km-delete")!.addEventListener("click", () => {
    const name = listEl.value;
    if (!name) return;
    if (!confirm(`Delete KQL snippet "${name}"? This cannot be undone.`)) return;
    delete kqlSnippets[name];
    saveKqlSnippets(kqlSnippets);
    renderKqlMenu();
    openKqlManager();
  });
  document.querySelector("#km-save")!.addEventListener("click", () => {
    const name = listEl.value;
    if (!name) return alert("Select or add a snippet first.");
    kqlSnippets[name] = textEl.value;
    saveKqlSnippets(kqlSnippets);
    renderKqlMenu();
    flashStatus(`Saved KQL snippet: ${name}`);
  });
  document.querySelector("#km-close")!.addEventListener("click", closeModal);
}

// ---------------------------------------------------------------------------
// Sidebar: IOCs / Templates / Snippets
// ---------------------------------------------------------------------------
const sidebarTabButtons = document.querySelectorAll<HTMLButtonElement>(".sidebar-tabs button");
sidebarTabButtons.forEach((btn) => {
  btn.addEventListener("click", () => switchSidebar(btn.dataset.panel!));
});
function switchSidebar(panel: string) {
  sidebarTabButtons.forEach((b) => b.classList.toggle("active", b.dataset.panel === panel));
  document.querySelectorAll(".sidebar-panel").forEach((p) => p.classList.toggle("active", p.id === `panel-${panel}`));
}

function renderIocPanel() {
  const container = document.querySelector<HTMLDivElement>("#panel-iocs")!;
  const grouped = groupIocs(lastIocMatches);
  const hasAny = lastIocMatches.length > 0;

  container.innerHTML = `
    <div class="export-row">
      <button id="ioc-csv" ${hasAny ? "" : "disabled"}>CSV</button>
      <button id="ioc-json" ${hasAny ? "" : "disabled"}>JSON</button>
      <button id="ioc-txt" ${hasAny ? "" : "disabled"}>TXT</button>
    </div>
  `;

  if (!hasAny) {
    container.innerHTML += `<p class="ioc-empty">Run "Extract IOCs" to list indicators found in the active tab.</p>`;
    return;
  }

  for (const [type, values] of Object.entries(grouped)) {
    if (values.length === 0) continue;
    const group = document.createElement("div");
    group.className = "ioc-group";
    group.innerHTML = `<h4>${IOC_LABELS[type as keyof typeof IOC_LABELS]} (${values.length})</h4>`;
    for (const v of values) {
      const item = document.createElement("div");
      item.className = "ioc-value";
      item.textContent = v;
      item.title = "Click to copy";
      item.addEventListener("click", () => {
        navigator.clipboard.writeText(v);
        flashStatus(`Copied ${v}`);
      });
      group.appendChild(item);
    }
    container.appendChild(group);
  }

  document.querySelector("#ioc-csv")!.addEventListener("click", () => exportIocsCsv(lastIocMatches));
  document.querySelector("#ioc-json")!.addEventListener("click", () => exportIocsJson(lastIocMatches));
  document.querySelector("#ioc-txt")!.addEventListener("click", () =>
    exportIocsText(Object.fromEntries(Object.entries(grouped).map(([k, v]) => [IOC_LABELS[k as keyof typeof IOC_LABELS], v]))),
  );
}
renderIocPanel();

function renderNamedPanel(
  panelId: string,
  data: Record<string, string>,
  onSave: (data: Record<string, string>) => void,
  onUse: (content: string, name: string) => void,
) {
  const container = document.querySelector<HTMLDivElement>(panelId)!;
  container.innerHTML = `<button id="${panelId.slice(1)}-add" style="width:100%;margin-bottom:8px;">+ New</button>`;

  for (const name of Object.keys(data).sort()) {
    const row = document.createElement("div");
    row.className = "list-item";
    row.style.display = "flex";
    row.style.justifyContent = "space-between";
    row.style.alignItems = "center";
    row.innerHTML = `<span>${escapeHtml(name)}</span>`;
    const del = document.createElement("span");
    del.textContent = "✕";
    del.style.opacity = "0.6";
    del.addEventListener("click", (e) => {
      e.stopPropagation();
      delete data[name];
      onSave(data);
      renderNamedPanel(panelId, data, onSave, onUse);
    });
    row.appendChild(del);
    row.addEventListener("click", () => onUse(fillPlaceholders(data[name]), name));
    container.appendChild(row);
  }

  document.querySelector(`#${panelId.slice(1)}-add`)!.addEventListener("click", () => {
    const name = prompt("Name:");
    if (!name) return;
    const content = prompt("Content:") ?? "";
    data[name] = content;
    onSave(data);
    renderNamedPanel(panelId, data, onSave, onUse);
  });
}

function renderTemplatesPanel() {
  renderNamedPanel(
    "#panel-templates",
    templates,
    (data) => {
      templates = data;
      saveTemplates(templates);
    },
    (content, name) => {
      tabs.createTab(name, content);
      flashStatus(`Opened template: ${name}`);
    },
  );
}
function renderSnippetsPanel() {
  renderNamedPanel(
    "#panel-snippets",
    snippets,
    (data) => {
      snippets = data;
      saveSnippets(snippets);
    },
    (content, name) => {
      tabs.insertAtCursor(content);
      flashStatus(`Inserted snippet: ${name}`);
    },
  );
}
renderTemplatesPanel();
renderSnippetsPanel();

// ---------------------------------------------------------------------------
// Settings + theme
// ---------------------------------------------------------------------------
function updateThemeButton() {
  themeBtn.textContent = settings.darkMode ? "☀️ Light" : "🌙 Dark";
}
updateThemeButton();

const sidebarEl = document.querySelector<HTMLDivElement>("#sidebar")!;
const sidebarToggleBtn = document.querySelector<HTMLButtonElement>("#btn-toggle-sidebar")!;
function updateSidebarToggleButton() {
  sidebarToggleBtn.textContent = settings.sidebarHidden ? "🗂 Show Pane" : "🗂 Hide Pane";
}
function applySidebarVisibility() {
  sidebarEl.classList.toggle("hidden", settings.sidebarHidden);
  updateSidebarToggleButton();
}
applySidebarVisibility();
sidebarToggleBtn.addEventListener("click", () => {
  settings = { ...settings, sidebarHidden: !settings.sidebarHidden };
  saveSettings(settings);
  applySidebarVisibility();
  flashStatus(settings.sidebarHidden ? "IOC pane hidden" : "IOC pane shown");
});

document.querySelector("#btn-clear-note")!.addEventListener("click", () => {
  if (!tabs.getContent().trim()) return flashStatus("Nothing to clear");
  if (!confirm("Clear the current note? This cannot be undone.")) return;
  tabs.setContent("");
  flashStatus("Note cleared");
});

// ---------------------------------------------------------------------------
// Hunts view: full-screen threat-hunt tracker (toggle away from the editor)
// ---------------------------------------------------------------------------
const mainViewEl = document.querySelector<HTMLDivElement>("#main-view")!;
const huntsViewEl = document.querySelector<HTMLDivElement>("#hunts-view")!;
const viewToggleBtn = document.querySelector<HTMLButtonElement>("#btn-view-hunts")!;
let currentView: "editor" | "hunts" = "editor";

function updateViewToggleButton() {
  viewToggleBtn.textContent = currentView === "editor" ? "🎯 Hunts" : "📝 Editor";
}
function showEditorView() {
  currentView = "editor";
  mainViewEl.classList.remove("hidden");
  tabBar.classList.remove("hidden");
  huntsViewEl.classList.add("hidden");
  updateViewToggleButton();
}
function showHuntsView() {
  currentView = "hunts";
  mainViewEl.classList.add("hidden");
  tabBar.classList.add("hidden");
  huntsViewEl.classList.remove("hidden");
  updateViewToggleButton();
}
viewToggleBtn.addEventListener("click", () => (currentView === "editor" ? showHuntsView() : showEditorView()));
updateViewToggleButton();

initHuntsView(huntsViewEl, {
  flashStatus,
  getKqlSnippets: () => kqlSnippets,
});

function applySettings() {
  document.documentElement.setAttribute("data-theme", settings.darkMode ? "dark" : "light");
  tabs.applySettings(settings);
  saveSettings(settings);
  updateThemeButton();
}

function patchSettings(patch: Partial<Settings>) {
  settings = { ...settings, ...patch };
  applySettings();
}

document.querySelector("#btn-theme")!.addEventListener("click", () => {
  settings = { ...settings, darkMode: !settings.darkMode };
  applySettings();
});

document.querySelector("#btn-settings")!.addEventListener("click", () => {
  openModal(
    "Settings",
    `
    <label>Dark mode <input type="checkbox" id="s-dark" ${settings.darkMode ? "checked" : ""} /></label>
    <label>Line numbers <input type="checkbox" id="s-lines" ${settings.lineNumbers ? "checked" : ""} /></label>
    <label>Word wrap <input type="checkbox" id="s-wrap" ${settings.wordWrap ? "checked" : ""} /></label>
    <label>IOC highlighting <input type="checkbox" id="s-ioc" ${settings.iocHighlighting ? "checked" : ""} /></label>
    <label>Font size <input type="range" min="10" max="22" id="s-font" value="${settings.fontSize}" /></label>
    <div class="modal-actions">
      <button id="s-reset">Reset to defaults</button>
      <button class="primary" id="s-close">Done</button>
    </div>
  `,
  );

  const read = () => ({
    darkMode: (document.querySelector("#s-dark") as HTMLInputElement).checked,
    lineNumbers: (document.querySelector("#s-lines") as HTMLInputElement).checked,
    wordWrap: (document.querySelector("#s-wrap") as HTMLInputElement).checked,
    iocHighlighting: (document.querySelector("#s-ioc") as HTMLInputElement).checked,
    fontSize: Number((document.querySelector("#s-font") as HTMLInputElement).value),
  });
  ["#s-dark", "#s-lines", "#s-wrap", "#s-ioc", "#s-font"].forEach((sel) => {
    document.querySelector(sel)!.addEventListener("input", () => {
      settings = { ...settings, ...read() };
      applySettings();
    });
  });
  document.querySelector("#s-reset")!.addEventListener("click", () => {
    settings = { ...DEFAULT_SETTINGS };
    applySettings();
    closeModal();
  });
  document.querySelector("#s-close")!.addEventListener("click", closeModal);
});

document.querySelector("#btn-help")!.addEventListener("click", () => {
  openModal(
    "ThreatPad — Quick Reference",
    `
    <div class="help-content">
      <p>A CyberChef-style SOC notes app. Everything runs in your browser and is
      saved to this device's local storage only — no accounts, no backend, no
      network calls, nothing leaves your machine.</p>

      <h4>Threat Hunting</h4>
      <ul>
        <li><b>🎯 Hunts</b> (top-left) — switch to the full hunt tracker: log hunts with a
        hypothesis, MITRE ATT&amp;CK tags, data sources, queries, and findings; a
        <b>Coverage</b> view showing which techniques you've actually hunted; and a
        <b>Playbooks</b> library of reusable hunt starting points</li>
      </ul>

      <h4>Menus</h4>
      <ul>
        <li><b>File</b> — New Tab, Open, Save, Save As (uses your OS file picker where supported)</li>
        <li><b>IOC Tools</b> — Extract IOCs into the sidebar (CSV/JSON/TXT export, click-to-copy)</li>
        <li><b>Hash</b> — MD5 / SHA1 / SHA256 generation, and hash-type identification</li>
        <li><b>Encode</b> — Base64 encode/decode</li>
        <li><b>Client ▾</b> — manage per-client identifiers and pick the active client</li>
        <li><b>SOC ▾</b> — incident Checklist, Breakglass ("I Think I've Made a Mistake"), and Mileage stats</li>
      </ul>

      <h4>Center stage</h4>
      <ul>
        <li><b>Defang / Refang</b> — safely neutralize or restore IOCs (<code>hxxp[://]</code>, <code>[.]</code>, <code>[@]</code>, <code>[:]</code>)</li>
        <li><b>📊 KQL</b> — pick a saved KQL query to copy to your clipboard (paste it into your log
        platform yourself — nothing is ever run or sent from here); manage your saved queries via
        "Manage KQL…" at the bottom of the dropdown</li>
      </ul>

      <h4>Floating buttons</h4>
      <ul>
        <li><b>🔒 Safe Copy</b> (bottom-right) — blocks the clipboard copy if the active tab contains
        another client's identifiers, and warns before copying undefanged live IOCs</li>
        <li><b>✕</b> (next to Safe Copy) — clears the active note (asks to confirm)</li>
        <li><b>?</b> (bottom-left) — this panel</li>
      </ul>

      <h4>IOC pane</h4>
      <ul>
        <li>Use <b>🗂 Hide Pane / Show Pane</b> in the toolbar to collapse or restore the sidebar
        (IOCs / Templates / Snippets)</li>
      </ul>

      <h4>Keyboard shortcuts</h4>
      <ul>
        <li><code>Ctrl/Cmd+D</code> — Defang</li>
        <li><code>Ctrl/Cmd+R</code> — Refang</li>
        <li><code>Ctrl/Cmd+I</code> — Extract IOCs</li>
        <li><code>Ctrl/Cmd+N</code> — New tab</li>
        <li><code>Ctrl/Cmd+W</code> — Close tab</li>
        <li><code>Ctrl/Cmd+S</code> — Save</li>
        <li><b>Double-click a tab name</b> to rename it (Enter to confirm, Esc to cancel)</li>
      </ul>

      <p class="help-footnote">The traffic-light dot and timer in the status bar reflect the active
      tab: grey = empty, green = clean, amber = undefanged IOCs present, red = cross-client
      contamination detected.</p>
    </div>
    <div class="modal-actions">
      <button class="primary" id="help-close">Close</button>
    </div>
  `,
    { wide: true },
  );
  document.querySelector("#help-close")!.addEventListener("click", closeModal);
});

// ---------------------------------------------------------------------------
// Modal helper
// ---------------------------------------------------------------------------
function openModal(title: string, bodyHtml: string, opts?: { wide?: boolean }) {
  closeModal();
  const backdrop = document.createElement("div");
  backdrop.className = "modal-backdrop";
  backdrop.id = "modal-backdrop";
  backdrop.innerHTML = `<div class="modal${opts?.wide ? " modal-wide" : ""}"><h3>${escapeHtml(title)}</h3>${bodyHtml}</div>`;
  backdrop.addEventListener("click", (e) => {
    if (e.target === backdrop) closeModal();
  });
  document.body.appendChild(backdrop);
}
function closeModal() {
  document.querySelector("#modal-backdrop")?.remove();
}

// ---------------------------------------------------------------------------
// Keyboard shortcuts
// ---------------------------------------------------------------------------
document.addEventListener("keydown", (e) => {
  const mod = e.ctrlKey || e.metaKey;
  if (!mod) return;
  switch (e.key.toLowerCase()) {
    case "d":
      e.preventDefault();
      doDefang();
      break;
    case "r":
      e.preventDefault();
      doRefang();
      break;
    case "i":
      e.preventDefault();
      doExtract();
      break;
    case "n":
      e.preventDefault();
      tabs.createTab("Untitled", "");
      break;
    case "w": {
      e.preventDefault();
      const id = tabs.activeTabId();
      if (id) tabs.closeTab(id);
      break;
    }
    case "s": {
      e.preventDefault();
      (document.querySelector("#btn-save") as HTMLButtonElement).click();
      break;
    }
  }
});

// ---------------------------------------------------------------------------
// Phase 3: client contamination checks, training wheels, breakglass, mileage
// ---------------------------------------------------------------------------
phase3Hooks = initPhase3({
  tabs,
  flashStatus,
  openModal,
  closeModal,
  escapeHtml,
  getSettings: () => settings,
  patchSettings,
});

updateStatus();

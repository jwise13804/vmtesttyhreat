import { EditorState, type Extension } from "@codemirror/state";
import {
  crosshairCursor,
  drawSelection,
  dropCursor,
  EditorView,
  highlightActiveLine,
  highlightActiveLineGutter,
  keymap,
  lineNumbers,
  rectangularSelection,
} from "@codemirror/view";
import { defaultKeymap, history, historyKeymap } from "@codemirror/commands";
import { highlightSelectionMatches, search, searchKeymap } from "@codemirror/search";
import { bracketMatching, indentOnInput } from "@codemirror/language";
import { iocHighlighter } from "./highlight";
import { darkTheme, lightTheme } from "./theme";
import type { IncidentSeverity, Settings, TabState } from "../core/storage";

let tabCounter = 0;
export function newTabId(): string {
  tabCounter += 1;
  return `tab-${Date.now()}-${tabCounter}`;
}

interface OpenTab {
  id: string;
  title: string;
  state: EditorState;
  fileHandle?: FileSystemFileHandle;
  severity: IncidentSeverity;
}

export class TabManager {
  private view: EditorView;
  private tabs: OpenTab[] = [];
  private activeId: string | null = null;
  private settings: Settings;
  readonly onChange: () => void;
  readonly onTabsUpdated: () => void;

  constructor(
    container: HTMLElement,
    settings: Settings,
    handlers: { onChange: () => void; onTabsUpdated: () => void },
  ) {
    this.settings = settings;
    this.onChange = handlers.onChange;
    this.onTabsUpdated = handlers.onTabsUpdated;
    this.view = new EditorView({ parent: container });
  }

  private buildExtensions(): Extension[] {
    const ext: Extension[] = [
      history(),
      drawSelection(),
      dropCursor(),
      EditorState.allowMultipleSelections.of(true),
      indentOnInput(),
      bracketMatching(),
      highlightActiveLine(),
      highlightSelectionMatches(),
      rectangularSelection(),
      crosshairCursor(),
      search(),
      keymap.of([...defaultKeymap, ...historyKeymap, ...searchKeymap]),
      EditorView.updateListener.of((u) => {
        if (u.docChanged) this.onChange();
      }),
      this.settings.darkMode ? darkTheme : lightTheme,
    ];
    if (this.settings.lineNumbers) ext.push(lineNumbers(), highlightActiveLineGutter());
    if (this.settings.wordWrap) ext.push(EditorView.lineWrapping);
    if (this.settings.iocHighlighting) ext.push(iocHighlighter);
    ext.push(EditorView.theme({ "&": { fontSize: `${this.settings.fontSize}px` } }));
    return ext;
  }

  private createState(content: string): EditorState {
    return EditorState.create({ doc: content, extensions: this.buildExtensions() });
  }

  createTab(title: string, content = "", fileHandle?: FileSystemFileHandle): string {
    const id = newTabId();
    this.tabs.push({ id, title, state: this.createState(content), fileHandle, severity: "none" });
    this.switchTab(id);
    this.onTabsUpdated();
    return id;
  }

  getSeverity(id?: string): IncidentSeverity {
    const targetId = id ?? this.activeId;
    return this.tabs.find((t) => t.id === targetId)?.severity ?? "none";
  }

  setSeverity(id: string, severity: IncidentSeverity): void {
    const tab = this.tabs.find((t) => t.id === id);
    if (tab) tab.severity = severity;
  }

  attachFileHandle(id: string, handle: FileSystemFileHandle): void {
    const tab = this.tabs.find((t) => t.id === id);
    if (tab) tab.fileHandle = handle;
  }

  getFileHandle(id: string): FileSystemFileHandle | undefined {
    return this.tabs.find((t) => t.id === id)?.fileHandle;
  }

  closeTab(id: string): void {
    const idx = this.tabs.findIndex((t) => t.id === id);
    if (idx === -1) return;
    this.tabs.splice(idx, 1);
    if (this.activeId === id) {
      const next = this.tabs[idx] ?? this.tabs[idx - 1];
      this.activeId = null;
      if (next) this.switchTab(next.id);
    }
    if (this.tabs.length === 0) this.createTab("Untitled");
    this.onTabsUpdated();
  }

  switchTab(id: string): void {
    if (this.activeId === id) return;
    const current = this.tabs.find((t) => t.id === this.activeId);
    if (current) current.state = this.view.state;

    const next = this.tabs.find((t) => t.id === id);
    if (!next) return;
    this.activeId = id;
    this.view.setState(next.state);
    this.view.focus();
    this.onTabsUpdated();
  }

  renameTab(id: string, title: string): void {
    const tab = this.tabs.find((t) => t.id === id);
    if (tab) {
      tab.title = title;
      this.onTabsUpdated();
    }
  }

  list(): Array<{ id: string; title: string }> {
    return this.tabs.map(({ id, title }) => ({ id, title }));
  }

  activeTabId(): string | null {
    return this.activeId;
  }

  getContent(id?: string): string {
    if (!id || id === this.activeId) return this.view.state.doc.toString();
    return this.tabs.find((t) => t.id === id)?.state.doc.toString() ?? "";
  }

  setContent(text: string): void {
    this.view.dispatch({
      changes: { from: 0, to: this.view.state.doc.length, insert: text },
    });
  }

  getSelectionOrAll(): string {
    const sel = this.view.state.selection.main;
    if (!sel.empty) return this.view.state.sliceDoc(sel.from, sel.to);
    return this.view.state.doc.toString();
  }

  insertAtCursor(text: string): void {
    const sel = this.view.state.selection.main;
    this.view.dispatch({
      changes: { from: sel.from, to: sel.to, insert: text },
      selection: { anchor: sel.from + text.length },
    });
    this.view.focus();
  }

  applySettings(settings: Settings): void {
    this.settings = settings;
    // The active tab's OpenTab.state is only synced with the live view on
    // switchTab/serialize — resync first so doc and selection can't diverge
    // (a stale doc + a live selection past its end throws in EditorState.create).
    const current = this.tabs.find((t) => t.id === this.activeId);
    if (current) current.state = this.view.state;

    for (const tab of this.tabs) {
      const doc = tab.state.doc.toString();
      const selection = tab.id === this.activeId ? tab.state.selection : undefined;
      tab.state = EditorState.create({ doc, extensions: this.buildExtensions(), selection });
    }
    if (this.activeId) {
      const active = this.tabs.find((t) => t.id === this.activeId);
      if (active) this.view.setState(active.state);
    }
  }

  serialize(): TabState[] {
    if (this.activeId) {
      const current = this.tabs.find((t) => t.id === this.activeId);
      if (current) current.state = this.view.state;
    }
    return this.tabs.map((t) => ({ id: t.id, title: t.title, content: t.state.doc.toString(), severity: t.severity }));
  }

  restore(tabs: TabState[], activeId: string | null): void {
    this.tabs = tabs.map((t) => ({
      id: t.id,
      title: t.title,
      state: this.createState(t.content),
      severity: t.severity ?? "none",
    }));
    this.activeId = null;
    const target = tabs.find((t) => t.id === activeId) ?? tabs[0];
    if (target) this.switchTab(target.id);
    this.onTabsUpdated();
  }
}

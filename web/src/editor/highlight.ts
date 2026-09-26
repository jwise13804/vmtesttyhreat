import { RangeSetBuilder } from "@codemirror/state";
import { Decoration, type DecorationSet, EditorView, ViewPlugin, type ViewUpdate } from "@codemirror/view";
import { extractIocs } from "../core/iocPatterns";

// Colors mirror threatpad.py's apply_syntax_highlighting() tag colors, roughly.
const decorations: Record<string, Decoration> = {
  ipv4: Decoration.mark({ class: "ioc-ipv4" }),
  ipv6: Decoration.mark({ class: "ioc-ipv6" }),
  domain: Decoration.mark({ class: "ioc-domain" }),
  url: Decoration.mark({ class: "ioc-url" }),
  email: Decoration.mark({ class: "ioc-email" }),
  hash_md5: Decoration.mark({ class: "ioc-hash" }),
  hash_sha1: Decoration.mark({ class: "ioc-hash" }),
  hash_sha256: Decoration.mark({ class: "ioc-hash" }),
};

function buildDecorations(view: EditorView): DecorationSet {
  const builder = new RangeSetBuilder<Decoration>();
  const text = view.state.doc.toString();
  for (const match of extractIocs(text)) {
    builder.add(match.start, match.end, decorations[match.type]);
  }
  return builder.finish();
}

export const iocHighlighter = ViewPlugin.fromClass(
  class {
    decorations: DecorationSet;
    constructor(view: EditorView) {
      this.decorations = buildDecorations(view);
    }
    update(update: ViewUpdate) {
      if (update.docChanged || update.viewportChanged) {
        this.decorations = buildDecorations(update.view);
      }
    }
  },
  { decorations: (v) => v.decorations },
);

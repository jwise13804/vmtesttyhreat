import { EditorView } from "@codemirror/view";

export const lightTheme = EditorView.theme({
  "&": { color: "#0b1120", backgroundColor: "#f5f7fb" },
  ".cm-content": { caretColor: "#0b6ecb" },
  ".cm-gutters": { backgroundColor: "#e8ecf5", color: "#7183a3", border: "none" },
  ".cm-activeLine": { backgroundColor: "#e2e8f6" },
  ".cm-activeLineGutter": { backgroundColor: "#e2e8f6" },
});

// Dark navy / cyan "hacker terminal" palette, matching the CSS custom
// properties in style.css ([data-theme="dark"]).
export const darkTheme = EditorView.theme(
  {
    "&": { color: "#cfe3ff", backgroundColor: "#050a14" },
    ".cm-content": { caretColor: "#22d3ee" },
    ".cm-gutters": { backgroundColor: "#0a1120", color: "#3f5c82", border: "none" },
    ".cm-activeLine": { backgroundColor: "rgba(34, 211, 238, 0.06)" },
    ".cm-activeLineGutter": { backgroundColor: "rgba(34, 211, 238, 0.08)", color: "#7dd3fc" },
    ".cm-selectionBackground, &.cm-focused .cm-selectionBackground": {
      backgroundColor: "rgba(34, 211, 238, 0.25) !important",
    },
    ".cm-cursor": { borderLeftColor: "#22d3ee" },
    ".cm-searchMatch": { backgroundColor: "rgba(125, 211, 252, 0.3)" },
    ".cm-searchMatch.cm-searchMatch-selected": { backgroundColor: "rgba(255, 77, 109, 0.45)" },
  },
  { dark: true },
);

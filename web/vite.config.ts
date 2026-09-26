import { defineConfig } from "vite";

// GitHub Pages serves this repo from the kql-hunt-range branch with
// ThreatPad living at the /threatpad/ subfolder alongside KQL Sandbox and a
// landing page, i.e. https://spackyjacky.github.io/vmtesttyhreat/threatpad/.
// Local dev keeps serving from root.
export default defineConfig(({ command }) => ({
  base: command === "build" ? "/vmtesttyhreat/threatpad/" : "/",
}));

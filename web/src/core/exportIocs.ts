import { IOC_LABELS, type IocMatch } from "./iocPatterns";

function download(filename: string, mimeType: string, content: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function exportIocsCsv(matches: IocMatch[]): void {
  const rows = ["Type,Value"];
  for (const m of matches) {
    const value = m.value.includes(",") ? `"${m.value}"` : m.value;
    rows.push(`${IOC_LABELS[m.type]},${value}`);
  }
  download("iocs.csv", "text/csv", rows.join("\n"));
}

export function exportIocsJson(matches: IocMatch[]): void {
  const payload = matches.map((m) => ({ type: IOC_LABELS[m.type], value: m.value }));
  download("iocs.json", "application/json", JSON.stringify(payload, null, 2));
}

export function exportIocsText(grouped: Record<string, string[]>): void {
  const lines: string[] = [];
  for (const [type, values] of Object.entries(grouped)) {
    if (values.length === 0) continue;
    lines.push(`--- ${type} ---`);
    lines.push(...values, "");
  }
  download("iocs.txt", "text/plain", lines.join("\n"));
}

export function downloadTextFile(filename: string, content: string): void {
  download(filename, "text/plain", content);
}

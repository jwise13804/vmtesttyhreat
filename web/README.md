# ThreatPad Web

**Live: https://spackyjacky.github.io/vmtesttyhreat/**

A CyberChef-style port of ThreatPad: a static, fully client-side SOC notes
app. No backend, no accounts — everything runs in the browser and is
persisted to `localStorage` on the machine you're using. Single-user/local-only
by design.

## Features

**Core editor & IOC toolkit**
- Multi-tab note editor (CodeMirror 6) with autosave to `localStorage`
- IOC detection for IPv4/IPv6, domains, URLs, emails, and MD5/SHA1/SHA256
  hashes, with inline highlighting in the editor
- Defang / Refang (`hxxp[://]`, `[.]`, `[@]`, `[:]`, `[#]`)
- Extract IOCs panel with CSV/JSON/text export and click-to-copy
- Hash generation (MD5/SHA1/SHA256) and hash-type identification
- Base64 encode/decode
- Templates and snippets (editable, stored locally)
- Dark/light mode, line numbers, word wrap, font size — all persisted

**Files**
- Native Open/Save via the File System Access API where the browser supports
  it (true in-place "Save" back to the same file, plus "Save As…"), falling
  back to the classic file-input/Blob-download flow elsewhere
- Drag & drop files onto the editor to open them as new tabs

**SOC workflow (ported from the desktop app's Training Wheels / client /
breakglass / mileage subsystems)**
- Training Wheels: a per-incident-type checklist (15 incident types, ported
  verbatim) with Checklist Mode and a free-text Form Mode that builds a
  formatted incident note you can copy or insert into the active tab
- Client management: per-client identifiers (email domains, hostname
  prefixes, IP ranges, keywords) and an active-client selector
- Contamination check: scans the active tab against every *other* client's
  identifiers and reports matches; Safe Copy blocks the clipboard copy
  outright if contamination is found, and warns (cancellable) on undefanged
  live IOCs otherwise
- A traffic-light indicator (grey/green/amber/red) reflecting the active
  tab's content-safety state, and a per-tab elapsed-time timer
- Breakglass ("I Think I've Made a Mistake"): contextual prompts built from
  the session's action log, plus the full log and a general containment
  checklist
- Mileage: session stats (defangs, copies, contamination checks, near-misses,
  etc.) and "mistake memory" pattern detection, with a reset

## Not in this port

IOC enrichment (VirusTotal/AbuseIPDB) needs a server-side proxy to hold API
keys and isn't part of this static, backend-free build — see the scoping
discussion for why.

## Develop

```bash
npm install
npm run dev      # http://localhost:5173
npm run build    # static output in dist/, deployable anywhere (GitHub Pages, S3, nginx, or opened as a local file)
```

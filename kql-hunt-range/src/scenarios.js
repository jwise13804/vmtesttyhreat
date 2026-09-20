

// Curated scenario bank for the KQL Hunt Range. Every solutionQuery below was run against the
// generated Fabrikam dataset and its output verified (see verify-scenarios.js) — facts[] are the
// literal values from that verified output, not guesses. answer/answerLabel/answerAliases are drawn
// from that same verified output — not new claims, just a single headline fact from facts[] chosen
// as the "state your answer" flag for the answer-box step.
//
// domain / discipline / cyberSkills (added this round) are a curriculum-mapping layer, not a factual
// claim about KQL or MITRE — they're this tool's own categorization of which cyber-analyst domain and
// career-track discipline each mission exercises, used to power the Learning Matrix and skill filters.
// teaches[] (existing) captures the KQL-language side of that same mapping.
//
// hints[] (replacing the old single 'hint' field this round) is a 3-tier progressive breadcrumb: a
// conceptual nudge, then a structural pointer naming the right column/operator, then a near-solution —
// so "Ask a teammate" teaches instead of just handing over the answer on the first click.
(function (root) {
  'use strict';

  const SCENARIOS = [
  {
    "id": "s1",
    "level": "Beginner",
    "table": "DeviceLogonEvents",
    "title": "Get your bearings",
    "domain": "Identity & Access",
    "discipline": "Fundamentals",
    "prompt": "Before hunting anything, get a feel for the environment. How many distinct devices show up in DeviceLogonEvents?",
    "cyberSkills": [
      "environment / asset scoping"
    ],
    "hints": [
      "Before you can spot what's abnormal, you need to know what \"normal\" looks like — how many unique endpoints does this environment even have, based on their sign-in activity?",
      "DeviceLogonEvents has one row per logon event, so the same device shows up many times. You need the operator that collapses a column down to its unique values before you count them.",
      "Use `distinct` on DeviceName to collapse to unique devices, then pipe the result into `count`."
    ],
    "solutionQuery": "DeviceLogonEvents\n| distinct DeviceName\n| count",
    "facts": [
      "12"
    ],
    "teaches": [
      "distinct",
      "count"
    ],
    "maxExpectedRows": 1,
    "answer": "12",
    "answerLabel": "How many distinct devices?"
  },
  {
    "id": "s2",
    "level": "Beginner",
    "table": "EmailEvents",
    "title": "Something phishy",
    "domain": "Email Security",
    "discipline": "SOC Triage",
    "prompt": "Security awareness training mentioned a phishing email got through filtering this week. Find the email that Microsoft's filter tagged as a phishing threat. Who sent it, and who received it?",
    "cyberSkills": [
      "phishing triage"
    ],
    "hints": [
      "Microsoft Defender for Office 365 doesn't just deliver mail — it classifies it. Somewhere in EmailEvents is a column that records what threat category, if any, Defender assigned to a message.",
      "Look for a `ThreatTypes` column on EmailEvents and filter for the value that means \"phishing\".",
      "EmailEvents has a ThreatTypes column — filter where it equals \"Phish\"."
    ],
    "solutionQuery": "EmailEvents\n| where ThreatTypes == \"Phish\"\n| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject",
    "facts": [
      "billing@invoice-alerts-secure.example",
      "kwalters@fabrikam.example"
    ],
    "teaches": [
      "where",
      "project",
      "=="
    ],
    "mitre": "T1566.001 · Phishing: Spearphishing Attachment",
    "maxExpectedRows": 1,
    "answer": "billing@invoice-alerts-secure.example",
    "answerLabel": "What address sent the phishing email?",
    "disposition": "TP",
    "dispositionWhy": "Sender domain isn't Fabrikam's, and Defender's own filter already tagged it Phish — a real phishing delivery, not noise.",
    "alertId": "alert-a0",
    "severity": "Medium"
  },
  {
    "id": "s3",
    "level": "Beginner",
    "table": "DeviceProcessEvents",
    "title": "Reconnaissance command",
    "domain": "Endpoint Security",
    "discipline": "SOC Triage",
    "prompt": "Attackers often run `whoami /all` right after gaining a foothold to check what privileges they have. Find every process on FAB-IT-01 whose command line contains \"whoami\".",
    "cyberSkills": [
      "recon / discovery command spotting"
    ],
    "hints": [
      "You're not looking for a specific process name here — you're looking for a specific string inside whatever command line was run. Think about which operator searches free text instead of matching it exactly.",
      "`contains` does a case-insensitive substring match on ProcessCommandLine — scope it to FAB-IT-01 first, then add the substring check.",
      "DeviceProcessEvents | where DeviceName == \"FAB-IT-01\" and ProcessCommandLine contains \"whoami\""
    ],
    "solutionQuery": "DeviceProcessEvents\n| where DeviceName == \"FAB-IT-01\" and ProcessCommandLine contains \"whoami\"\n| project Timestamp, AccountName, ProcessCommandLine",
    "facts": [
      "svc_backup",
      "whoami /all"
    ],
    "teaches": [
      "where",
      "contains",
      "and"
    ],
    "mitre": "T1033 · System Owner/User Discovery",
    "maxExpectedRows": 1,
    "answer": "svc_backup",
    "answerLabel": "Which account ran the whoami command?",
    "disposition": "TP",
    "dispositionWhy": "whoami /all fired immediately after a brute-forced logon, on the same box, same account — textbook post-compromise recon."
  },
  {
    "id": "s4",
    "level": "Beginner",
    "table": "DeviceLogonEvents",
    "title": "Knocking on the door",
    "domain": "Identity & Access",
    "discipline": "SOC Triage",
    "prompt": "The account \"svc_backup\" was targeted before it was compromised. How many LogonFailed events happened against it before the first LogonSuccess, and from what IP address did they all come?",
    "cyberSkills": [
      "brute-force / password-spray detection"
    ],
    "hints": [
      "A brute-force attempt leaves a very specific shape in logon data: lots of failures, from one source, right before a success. Start by isolating just the failed attempts against this one account.",
      "Filter DeviceLogonEvents to AccountName == \"svc_backup\" and ActionType == \"LogonFailed\", then group and count by the source IP.",
      "DeviceLogonEvents | where AccountName == \"svc_backup\" and ActionType == \"LogonFailed\" | summarize Attempts = count() by RemoteIP"
    ],
    "solutionQuery": "DeviceLogonEvents\n| where AccountName == \"svc_backup\" and ActionType == \"LogonFailed\"\n| summarize Attempts = count() by RemoteIP",
    "facts": [
      "7",
      "198.51.100.23"
    ],
    "teaches": [
      "where",
      "summarize",
      "count()"
    ],
    "mitre": "T1110.001 · Brute Force: Password Guessing",
    "maxExpectedRows": 1,
    "answer": "198.51.100.23",
    "answerLabel": "What IP did the failed logons come from?",
    "disposition": "TP",
    "dispositionWhy": "Seven failed attempts from one external IP followed immediately by a success is the brute-force signature, not a mistyped password.",
    "alertId": "alert-b1",
    "severity": "High"
  },
  {
    "id": "s5",
    "level": "Intermediate",
    "table": "DeviceLogonEvents",
    "title": "Privilege check",
    "domain": "Identity & Access",
    "discipline": "SOC Triage",
    "prompt": "Find the successful logon where the account ended up with local admin rights AND the logon came from a remote IP (not an empty/local value). What account, device, and IP were involved?",
    "cyberSkills": [
      "privilege & remote-logon anomaly spotting"
    ],
    "hints": [
      "You need three things to be true on the same row at once: a successful logon, admin rights, and a remote (not blank) source IP. That's a job for combining predicates with `and`.",
      "ActionType == \"LogonSuccess\", IsLocalAdmin == true, and a function that checks a field isn't empty.",
      "ActionType == \"LogonSuccess\" and IsLocalAdmin == true and isnotempty(RemoteIP)."
    ],
    "solutionQuery": "DeviceLogonEvents\n| where ActionType == \"LogonSuccess\" and IsLocalAdmin == true and isnotempty(RemoteIP)\n| project Timestamp, DeviceName, AccountName, RemoteIP",
    "facts": [
      "svc_backup",
      "fab-it-01",
      "198.51.100.23"
    ],
    "teaches": [
      "where",
      "isnotempty",
      "multiple predicates"
    ],
    "mitre": "T1078 · Valid Accounts",
    "maxExpectedRows": 2,
    "answer": "FAB-IT-01",
    "answerAliases": [
      "fab-it-01"
    ],
    "answerLabel": "Which device did the admin logon land on?",
    "disposition": "TP",
    "dispositionWhy": "The account picked up local admin rights from a remote logon minutes after being brute-forced — privilege gained by the attacker, not routine admin access."
  },
  {
    "id": "s6",
    "level": "Intermediate",
    "table": "DeviceProcessEvents",
    "title": "Office spawning a shell",
    "domain": "Endpoint Security",
    "discipline": "SOC Triage",
    "prompt": "A classic macro-malware pattern: an Office app (EXCEL.EXE or WINWORD.EXE) launches powershell.exe. Hunt for that pattern across the whole fleet. What device and account does it point to?",
    "cyberSkills": [
      "spawned-shell (LOLBin) detection"
    ],
    "hints": [
      "This is one of the oldest malware-delivery patterns there is: a document-editing app that has no business launching a shell, doing exactly that. Which two columns on DeviceProcessEvents describe a parent process and its child?",
      "Check where InitiatingProcessFileName is an Office app and FileName is powershell.exe — `in (...)` lets you match a list of values in one predicate.",
      "InitiatingProcessFileName in (\"EXCEL.EXE\", \"WINWORD.EXE\") and FileName == \"powershell.exe\"."
    ],
    "solutionQuery": "DeviceProcessEvents\n| where InitiatingProcessFileName in (\"EXCEL.EXE\", \"WINWORD.EXE\") and FileName == \"powershell.exe\"\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine",
    "facts": [
      "fab-fin-07",
      "kwalters"
    ],
    "teaches": [
      "where",
      "in",
      "project"
    ],
    "mitre": "T1059.001 · Command and Scripting Interpreter: PowerShell",
    "maxExpectedRows": 1,
    "answer": "FAB-FIN-07",
    "answerAliases": [
      "fab-fin-07"
    ],
    "answerLabel": "Which device shows Office spawning PowerShell?",
    "disposition": "TP",
    "dispositionWhy": "An Office macro spawning PowerShell is not a legitimate workflow on any of these machines.",
    "alertId": "alert-a1",
    "severity": "High"
  },
  {
    "id": "s7",
    "level": "Intermediate",
    "table": "DeviceProcessEvents",
    "title": "Living off Temp",
    "domain": "Endpoint Security",
    "discipline": "SOC Triage",
    "prompt": "Processes launching from a user's Temp folder are a common red flag. Find the one on FAB-ENG-03. What is the file name and full command line?",
    "cyberSkills": [
      "suspicious execution path triage"
    ],
    "hints": [
      "Where a process runs from matters as much as what it's called — a folder no legitimate installed software uses for its executables is a red flag on its own.",
      "Scope to FAB-ENG-03, then look for a folder path containing a directory name attackers love: Temp.",
      "`FolderPath contains \"Temp\"` narrows it down fast."
    ],
    "solutionQuery": "DeviceProcessEvents\n| where DeviceName == \"FAB-ENG-03\" and FolderPath contains \"Temp\"\n| project Timestamp, FileName, ProcessCommandLine",
    "facts": [
      "svchost32.exe",
      "--encrypt-mode"
    ],
    "teaches": [
      "where",
      "contains"
    ],
    "maxExpectedRows": 1,
    "answer": "svchost32.exe",
    "answerLabel": "What file name launched from Temp?",
    "disposition": "TP",
    "dispositionWhy": "A renamed system binary running from a user's Temp folder, moments before a mass file-rename spike, is not routine."
  },
  {
    "id": "s8",
    "level": "Intermediate",
    "table": "DeviceFileEvents",
    "title": "The mass-rename spike",
    "domain": "Endpoint Security",
    "discipline": "Incident Response",
    "prompt": "Ransomware-style file renames tend to cluster tightly in time. Bucket FileRenamed events on FAB-ENG-03 into 5-minute windows with `bin()` and count them per window. How many renames landed in the busiest window?",
    "cyberSkills": [
      "ransomware file-activity indicator spotting"
    ],
    "hints": [
      "Ransomware doesn't rename files one at a time with pauses in between — it does hundreds in a tight burst. You need to group events into small time windows to see that burst shape.",
      "`bin()` rounds a datetime down into fixed-size buckets — group FileRenamed events by DeviceName and `bin(Timestamp, 5m)`, then sort to find the busiest bucket.",
      "`summarize count() by DeviceName, bin(Timestamp, 5m)`, then sort by the count column."
    ],
    "solutionQuery": "DeviceFileEvents\n| where ActionType == \"FileRenamed\"\n| summarize Renames = count() by DeviceName, bin(Timestamp, 5m)\n| sort by Renames",
    "facts": [
      "fab-eng-03",
      "15"
    ],
    "teaches": [
      "summarize",
      "bin()",
      "sort by"
    ],
    "mitre": "T1486 · Data Encrypted for Impact",
    "maxExpectedRows": 1,
    "answer": "15",
    "answerLabel": "Renames in the busiest 5-minute window?",
    "disposition": "TP",
    "dispositionWhy": "Fifteen renames to \".locked\" inside one 5-minute window on one device is the ransomware signature, not normal user activity.",
    "alertId": "alert-c1",
    "severity": "High"
  },
  {
    "id": "s9",
    "level": "Intermediate",
    "table": "DeviceProcessEvents",
    "title": "Busiest machine",
    "domain": "Endpoint Security",
    "discipline": "Fundamentals",
    "prompt": "Which single device generated the most process-creation events in the whole dataset, and how many?",
    "cyberSkills": [
      "baseline / asset-activity profiling"
    ],
    "hints": [
      "This is a baselining question, not a threat-hunting one — which device is simply the most active, full stop?",
      "Count process events grouped by device, then keep only the single highest row.",
      "`summarize count() by DeviceName`, then `top 1 by` the count column."
    ],
    "solutionQuery": "DeviceProcessEvents\n| summarize Events = count() by DeviceName\n| top 1 by Events",
    "facts": [
      "fab-fin-04",
      "57"
    ],
    "teaches": [
      "summarize",
      "top"
    ],
    "maxExpectedRows": 1,
    "answer": "FAB-FIN-04",
    "answerAliases": [
      "fab-fin-04"
    ],
    "answerLabel": "Which device has the most process-creation events?"
  },
  {
    "id": "s10",
    "level": "Advanced",
    "table": "DeviceNetworkEvents",
    "title": "Follow the beacon",
    "domain": "Network Security",
    "discipline": "Threat Hunting",
    "prompt": "The malicious PowerShell process from FAB-FIN-07 reached out to the internet repeatedly. Find every connection it made — what domain, and how many connections?",
    "cyberSkills": [
      "C2 beacon pivoting"
    ],
    "hints": [
      "You already know which process is malicious from an earlier case. Now pivot from that process onto the network table to see where it phoned home.",
      "Filter DeviceNetworkEvents to that device and InitiatingProcessFileName == \"powershell.exe\", then group by the destination to see the pattern.",
      "DeviceNetworkEvents | where InitiatingProcessFileName == \"powershell.exe\" and DeviceName == \"FAB-FIN-07\", then summarize by RemoteUrl."
    ],
    "solutionQuery": "DeviceNetworkEvents\n| where DeviceName == \"FAB-FIN-07\" and InitiatingProcessFileName == \"powershell.exe\"\n| summarize Connections = count() by RemoteUrl",
    "facts": [
      "cdn-update-delivery.net",
      "6"
    ],
    "teaches": [
      "where",
      "summarize",
      "pivoting between tables"
    ],
    "mitre": "T1071.001 · Application Layer Protocol: Web Protocols",
    "maxExpectedRows": 1,
    "answer": "cdn-update-delivery.net",
    "answerLabel": "What domain did the beacon call out to?",
    "disposition": "TP",
    "dispositionWhy": "Repeated outbound connections to the same domain from a PowerShell process, right after the macro fired, is C2 beaconing."
  },
  {
    "id": "s11",
    "level": "Advanced",
    "table": "DeviceNetworkEvents",
    "title": "Scope the blast radius",
    "domain": "Network Security",
    "discipline": "Threat Hunting",
    "prompt": "You have an indicator of compromise: the domain cdn-update-delivery.net. Pivot on it across DeviceNetworkEvents — which devices, across the ENTIRE fleet, ever contacted it? (This tells you whether the infection spread beyond patient zero.)",
    "cyberSkills": [
      "IOC-driven blast-radius scoping"
    ],
    "hints": [
      "Now flip the question around — instead of \"what did this device talk to\", ask \"who else talked to this thing\". That's the essence of IOC pivoting.",
      "Filter DeviceNetworkEvents for the known-bad domain across every device — no DeviceName scope this time — then collapse to unique hostnames.",
      "`where RemoteUrl == \"cdn-update-delivery.net\" | distinct DeviceName`."
    ],
    "solutionQuery": "DeviceNetworkEvents\n| where RemoteUrl == \"cdn-update-delivery.net\"\n| distinct DeviceName",
    "facts": [
      "fab-fin-07"
    ],
    "teaches": [
      "IOC pivoting",
      "distinct"
    ],
    "mitre": "T1071.001 · Application Layer Protocol: Web Protocols",
    "maxExpectedRows": 1,
    "answer": "FAB-FIN-07",
    "answerAliases": [
      "fab-fin-07"
    ],
    "answerLabel": "Which device(s) contacted the IOC domain?",
    "disposition": "TP",
    "dispositionWhy": "Confirms the beacon reached out to that IOC on a device the query independently identified — evidence, not coincidence."
  },
  {
    "id": "s12",
    "level": "Advanced",
    "table": "DeviceProcessEvents / DeviceNetworkEvents",
    "title": "Join the dots",
    "domain": "Network Security",
    "discipline": "Threat Hunting",
    "prompt": "Prove the connection between the malicious PowerShell process on FAB-FIN-07 and its network beacon in a single query, by joining DeviceProcessEvents to DeviceNetworkEvents on DeviceName. Project the process command line next to the remote URL it talked to.",
    "cyberSkills": [
      "multi-source correlation / lateral-movement mapping"
    ],
    "hints": [
      "You've proven the process and the network activity separately in earlier cases. Real correlation means tying them together in one query, on a shared key both tables have.",
      "`join kind=inner` combines two tabular expressions on a matching column — here that's DeviceName between the process and network events.",
      "`| join kind=inner (DeviceNetworkEvents | where DeviceName == \"FAB-FIN-07\") on DeviceName`"
    ],
    "solutionQuery": "DeviceProcessEvents\n| where DeviceName == \"FAB-FIN-07\" and FileName == \"powershell.exe\"\n| join kind=inner (\n    DeviceNetworkEvents\n    | where DeviceName == \"FAB-FIN-07\" and RemoteUrl == \"cdn-update-delivery.net\"\n  ) on DeviceName\n| project Timestamp, DeviceName, ProcessCommandLine, RemoteUrl",
    "facts": [
      "cdn-update-delivery.net"
    ],
    "teaches": [
      "join",
      "kind=inner",
      "multi-table correlation"
    ],
    "mitre": "T1071.001 · Application Layer Protocol: Web Protocols",
    "maxExpectedRows": 6,
    "answer": "6",
    "answerLabel": "How many rows does the join return?",
    "disposition": "TP",
    "dispositionWhy": "The join is the proof: same device, same time window, process and network evidence line up."
  },
  {
    "id": "s13",
    "level": "Advanced",
    "table": "DeviceFileEvents",
    "title": "Root cause of the dropped payload",
    "domain": "Endpoint Security",
    "discipline": "Threat Hunting",
    "prompt": "A suspicious DLL was dropped in a user's AppData\\Roaming folder. Find it — what's the file name, and what process created it?",
    "cyberSkills": [
      "file-provenance / ingress-tool-transfer tracing"
    ],
    "hints": [
      "A dropped file has a parent — the process that wrote it to disk. DeviceFileEvents keeps that link. First, find the file by its unusual drop location.",
      "Search FolderPath for a folder real installers rarely use for user-visible files: Roaming. You don't need to escape the backslash if you just search for the folder name itself.",
      "`FolderPath contains \"Roaming\"` — remember backslashes need escaping in a string literal, or just search for \"Roaming\"."
    ],
    "solutionQuery": "DeviceFileEvents\n| where FolderPath contains \"Roaming\"\n| project Timestamp, DeviceName, FileName, InitiatingProcessFileName",
    "facts": [
      "svchost32_update.dll",
      "powershell.exe"
    ],
    "teaches": [
      "where",
      "contains",
      "file provenance"
    ],
    "mitre": "T1105 · Ingress Tool Transfer",
    "maxExpectedRows": 1,
    "answer": "svchost32_update.dll",
    "answerLabel": "What is the dropped file called?",
    "disposition": "TP",
    "dispositionWhy": "A DLL dropped into AppData\\Roaming by the same PowerShell process that beaconed out — the payload, not a stray file."
  },
  {
    "id": "s14",
    "level": "Advanced",
    "table": "DeviceProcessEvents",
    "title": "Flag it yourself",
    "domain": "Endpoint Security",
    "discipline": "Fundamentals",
    "prompt": "Practice `extend`: add a computed boolean column called IsSuspiciousPath that is true when FolderPath contains \"Temp\" or \"Roaming\", then keep only the rows where it's true.",
    "cyberSkills": [
      "custom detection-logic authoring"
    ],
    "hints": [
      "This one's about building your own detection logic instead of just filtering — you need a new column that doesn't exist in the raw data, computed from ones that do.",
      "`extend` adds a computed column. Make a boolean one that's true when FolderPath contains either of two suspicious substrings, then filter on it.",
      "`extend IsSuspiciousPath = FolderPath contains \"Temp\" or FolderPath contains \"Roaming\"` then `where IsSuspiciousPath`."
    ],
    "solutionQuery": "DeviceProcessEvents\n| extend IsSuspiciousPath = FolderPath contains \"Temp\" or FolderPath contains \"Roaming\"\n| where IsSuspiciousPath\n| project Timestamp, DeviceName, FileName, FolderPath",
    "facts": [
      "svchost32.exe"
    ],
    "teaches": [
      "extend",
      "computed columns",
      "boolean expressions"
    ],
    "maxExpectedRows": 1,
    "answer": "FAB-ENG-03",
    "answerAliases": [
      "fab-eng-03"
    ],
    "answerLabel": "Which device has the suspicious path?"
  },
  {
    "id": "s15",
    "level": "Advanced",
    "table": "DeviceProcessEvents",
    "title": "Grabbing the crown jewels",
    "domain": "Endpoint Security",
    "discipline": "Threat Hunting",
    "prompt": "Cisco Talos's Q1 2026 incident-response trends report named OS credential dumping from the SAM and NTDS databases as a top credential-access technique — usually via built-in Windows tools rather than custom malware. Hunt for reg.exe being used to dump a registry hive on FAB-IT-01. Heads up: there's also a legitimate nightly backup job on that box that runs reg.exe too — narrow your filter until only the real credential dump is left. What hive(s), and which account?",
    "cyberSkills": [
      "credential-dumping detection & noise filtering"
    ],
    "hints": [
      "reg.exe is a legitimate Windows tool that's also a classic LOLBin for credential theft — the difference is what it's being asked to save. There's also a legitimate backup job on this box doing the exact same thing, so you'll need to filter on command-line content, not just the process name.",
      "`has` matches whole terms inside a command line. Filter FileName == \"reg.exe\" and look for command lines that `has` \"SAM\" or \"SYSTEM\" — the two hives credential dumpers target.",
      "FileName == \"reg.exe\" and (ProcessCommandLine has \"SAM\" or ProcessCommandLine has \"SYSTEM\") — this leaves the backup job's unrelated hive out."
    ],
    "solutionQuery": "DeviceProcessEvents\n| where DeviceName == \"FAB-IT-01\" and FileName == \"reg.exe\" and (ProcessCommandLine has \"SAM\" or ProcessCommandLine has \"SYSTEM\")\n| project Timestamp, AccountName, ProcessCommandLine",
    "facts": [
      "svc_backup",
      "reg.exe save HKLM\\SAM",
      "reg.exe save HKLM\\SYSTEM"
    ],
    "maxExpectedRows": 2,
    "mitre": "T1003.002 · OS Credential Dumping: Security Account Manager",
    "teaches": [
      "where",
      "has",
      "credential-dumping LOLBins",
      "filtering out look-alike noise"
    ],
    "answer": "svc_backup",
    "answerLabel": "Which account ran the registry hive dump?",
    "disposition": "TP",
    "dispositionWhy": "SAM and SYSTEM hive saves from a compromised service account, using the exact LOLBin pattern Talos flags as the top credential-access technique — real."
  },
  {
    "id": "s16",
    "level": "Advanced",
    "table": "DeviceNetworkEvents / DeviceLogonEvents",
    "title": "Jumping to the corner office",
    "domain": "Network Security",
    "discipline": "Threat Hunting",
    "prompt": "Same report: SMB / Windows admin shares were the #1 lateral-movement technique observed, ahead of WMI and RDP — attackers just reuse the credentials they already have over a built-in protocol. After dumping credentials on FAB-IT-01, svc_backup pivoted somewhere over port 445. Which device did it reach, and does DeviceLogonEvents confirm a successful logon there?",
    "cyberSkills": [
      "lateral-movement (SMB) hunting"
    ],
    "hints": [
      "Attackers rarely bring their own remote-access tools when stolen admin credentials and a built-in Windows protocol will do. Think about which network port that built-in protocol uses.",
      "Port 445 is SMB / Windows admin shares. Filter DeviceNetworkEvents for that device and RemotePort == 445 to find the hop, then check DeviceLogonEvents on the destination.",
      "DeviceNetworkEvents | where DeviceName == \"FAB-IT-01\" and RemotePort == 445, then check DeviceLogonEvents for that destination device."
    ],
    "solutionQuery": "DeviceNetworkEvents\n| where DeviceName == \"FAB-IT-01\" and RemotePort == 445\n| project Timestamp, DeviceName, RemoteUrl, RemotePort, InitiatingProcessFileName, InitiatingProcessAccountName",
    "facts": [
      "fab-exec-01",
      "445",
      "net.exe",
      "svc_backup"
    ],
    "teaches": [
      "where",
      "port-based pivoting",
      "SMB admin-share lateral movement"
    ],
    "mitre": "T1021.002 · Remote Services: SMB/Windows Admin Shares",
    "maxExpectedRows": 1,
    "answer": "FAB-EXEC-01",
    "answerAliases": [
      "fab-exec-01"
    ],
    "answerLabel": "Which device did svc_backup pivot to?",
    "disposition": "TP",
    "dispositionWhy": "svc_backup reused its stolen admin rights to reach a second host over SMB within minutes of the credential dump — real lateral movement, not scheduled IT work.",
    "alertId": "alert-d1",
    "severity": "High"
  },
  {
    "id": "s17",
    "level": "Intermediate",
    "table": "AlertInfo",
    "title": "Incident intake",
    "domain": "Incident Response & Triage",
    "discipline": "Incident Response",
    "prompt": "This is how real investigations actually start: not a paragraph of narration, but an alert in the queue. A new high-severity alert just fired: \"Credential dumping via registry hive save\". Pull it up in AlertInfo — what's its AlertId, and which MITRE ATT&CK technique is it tagged with?",
    "cyberSkills": [
      "alert-driven investigation intake"
    ],
    "hints": [
      "Real investigations usually start from a fired alert, not a hunch. AlertInfo has exactly one row per alert — you just need to find it by its title.",
      "Filter AlertInfo where Title matches the alert name exactly, then project the fields that matter: AlertId, Severity, AttackTechniques.",
      "AlertInfo | where Title == \"Credential dumping via registry hive save\" | project AlertId, Severity, AttackTechniques."
    ],
    "solutionQuery": "AlertInfo\n| where Title == \"Credential dumping via registry hive save\"\n| project AlertId, Severity, AttackTechniques",
    "facts": [
      "alert-b2",
      "high",
      "t1003.002"
    ],
    "maxExpectedRows": 1,
    "mitre": "T1003.002 · OS Credential Dumping: Security Account Manager",
    "teaches": [
      "AlertInfo",
      "where",
      "alert-driven investigation"
    ],
    "answer": "alert-b2",
    "answerLabel": "What is the AlertId?",
    "disposition": "TP",
    "dispositionWhy": "High-severity EDR alert on the credential-access technique matches the incident timeline exactly — real.",
    "alertId": "alert-b2",
    "severity": "High"
  },
  {
    "id": "s18",
    "level": "Advanced",
    "table": "AlertEvidence",
    "title": "Work the evidence",
    "domain": "Incident Response & Triage",
    "discipline": "Incident Response",
    "prompt": "You have the AlertId from alert-b2. Now pivot into AlertEvidence — the real Defender XDR table that lists every entity linked to an alert, joined on AlertId — to see exactly what triggered it. Which device, account, and command line come back?",
    "cyberSkills": [
      "evidence triage from an alert"
    ],
    "hints": [
      "Once you have an AlertId, the real Defender XDR workflow is to pivot into the evidence table that lists every entity tied to that alert — no need to reconstruct it yourself from raw device tables.",
      "AlertEvidence has one row per linked entity and already carries DeviceName, AccountName, and ProcessCommandLine — just filter it by AlertId.",
      "AlertEvidence | where AlertId == \"alert-b2\". No join needed once you have the AlertId."
    ],
    "solutionQuery": "AlertEvidence\n| where AlertId == \"alert-b2\"\n| project EntityType, DeviceName, AccountName, ProcessCommandLine",
    "facts": [
      "fab-it-01",
      "svc_backup",
      "reg.exe save hklm\\sam"
    ],
    "maxExpectedRows": 1,
    "mitre": "T1003.002 · OS Credential Dumping: Security Account Manager",
    "teaches": [
      "AlertEvidence",
      "AlertId pivot",
      "evidence triage"
    ],
    "answer": "FAB-IT-01",
    "answerAliases": [
      "fab-it-01"
    ],
    "answerLabel": "Which device is named in the evidence?",
    "disposition": "TP",
    "dispositionWhy": "The evidence entity confirms the same device, account, and command line as the alert — nothing points to a benign explanation."
  },
  {
    "id": "s19",
    "level": "Expert",
    "table": "DeviceNetworkEvents",
    "title": "Find the beacon by its rhythm",
    "domain": "Network Security",
    "discipline": "Threat Hunting",
    "prompt": "Filtering found the C2 beacon earlier by already knowing the domain — real detection often works the other way: no IOC yet, just a hunch that something is calling home on a schedule. Build an hourly time series of FAB-FIN-07's connection count from 2026-08-27 to 2026-09-01 with `make-series`, then run `series_decompose_anomalies()` over it. Which hour(s) light up as an anomaly?",
    "cyberSkills": [
      "statistical beaconing / anomaly-based hunting"
    ],
    "hints": [
      "This time you don't get to start from a known-bad domain — the whole point is finding the anomaly without an IOC first. That means looking at volume over time, not content.",
      "`make-series` buckets a metric into a time series; `series_decompose_anomalies()` then flags which buckets don't fit the pattern. Build an hourly connection-count series for the device first.",
      "`make-series Connections=count() on Timestamp from datetime(2026-08-27) to datetime(2026-09-01) step 1h | extend Anomalies = series_decompose_anomalies(Connections)` — then find where Anomalies is 1."
    ],
    "solutionQuery": "DeviceNetworkEvents\n| where DeviceName == \"FAB-FIN-07\"\n| make-series Connections=count() on Timestamp from datetime(2026-08-27) to datetime(2026-09-01) step 1h\n| extend Anomalies = series_decompose_anomalies(Connections)",
    "facts": [
      "2026-08-31T13:00:00.000Z",
      "2026-08-31T15:00:00.000Z"
    ],
    "mitre": "T1071.001 · Application Layer Protocol: Web Protocols",
    "teaches": [
      "make-series",
      "series_decompose_anomalies",
      "statistical beacon detection"
    ],
    "answer": "13:00",
    "answerAliases": [
      "2026-08-31t13:00:00.000z",
      "2026-08-31 13:00",
      "2026-08-31t13:00",
      "1pm",
      "1:00pm",
      "13:00 utc",
      "13:00:00"
    ],
    "answerLabel": "First anomalous hour (UTC, e.g. 13:00)?",
    "disposition": "TP",
    "dispositionWhy": "Two consecutive hourly windows spike well above this account's normal beacon cadence, right when the rest of the incident timeline says it should."
  },
  {
    "id": "s20",
    "level": "Advanced",
    "table": "DeviceFileEvents",
    "title": "Prove containment",
    "domain": "Endpoint Security",
    "discipline": "Incident Response",
    "prompt": "Not every good query finds something — sometimes the job is proving a negative. Before this incident gets closed, confirm the ransomware-style renames were scoped to FAB-ENG-03 only: query for any \".locked\" file rename on any OTHER device. A truly contained incident means this comes back empty.",
    "cyberSkills": [
      "negative-result verification (proving containment)"
    ],
    "hints": [
      "You're not hunting for evidence this time — you're trying to confirm its absence somewhere specific. Build the same red-flag query as before, but scoped to exclude the one device you already know is affected.",
      "Filter DeviceFileEvents for FileRenamed events ending in \".locked\", on any device that ISN'T the patient-zero machine.",
      "`where ActionType == \"FileRenamed\" and FileName endswith \".locked\" and DeviceName != \"FAB-ENG-03\"`. Zero rows = containment holds."
    ],
    "solutionQuery": "DeviceFileEvents\n| where ActionType == \"FileRenamed\" and FileName endswith \".locked\" and DeviceName != \"FAB-ENG-03\"",
    "expectEmpty": true,
    "mitre": "T1486 · Data Encrypted for Impact",
    "teaches": [
      "where",
      "endswith",
      "proving a negative result"
    ]
  },
  {
    "id": "s21",
    "level": "Intermediate",
    "table": "DeviceLogonEvents",
    "title": "Clean sweep: HR",
    "domain": "Identity & Access",
    "discipline": "Incident Response",
    "prompt": "HR's two machines (FAB-HR-02, FAB-HR-05) haven't come up in any incident so far — good, but \"hasn't come up yet\" and \"clean\" aren't the same thing. Run the same red flag from earlier (a local-admin logon from a non-empty remote IP) against just those two devices and confirm there's nothing there.",
    "cyberSkills": [
      "scoped hygiene sweep"
    ],
    "hints": [
      "Same red flag as the privilege-check case earlier, just scoped down to a specific set of machines that haven't shown up in this incident so far.",
      "Filter DeviceLogonEvents to just the two HR devices using `in`, then apply the same admin+remote-IP predicate as before.",
      "`where DeviceName in (\"FAB-HR-02\", \"FAB-HR-05\") and IsLocalAdmin == true and isnotempty(RemoteIP)`. Empty result = clean."
    ],
    "solutionQuery": "DeviceLogonEvents\n| where DeviceName in (\"FAB-HR-02\", \"FAB-HR-05\") and IsLocalAdmin == true and isnotempty(RemoteIP)",
    "expectEmpty": true,
    "teaches": [
      "where",
      "in",
      "scoped negative-result sweep"
    ]
  },
  {
    "id": "s22",
    "level": "Intermediate",
    "table": "AlertInfo / DeviceProcessEvents",
    "title": "Alert: registry hive export (Low)",
    "domain": "Incident Response & Triage",
    "discipline": "Incident Response",
    "prompt": "A low-confidence alert fired: \"Registry hive export outside change window\" on FAB-IT-01 — the detection is a blunt heuristic that fires on ANY reg.exe save, any hive. Pull up its evidence in DeviceProcessEvents (search for reg.exe activity on FAB-IT-01 around the alert's timestamp) and decide: is this the same credential-dumping pattern from alert-b2, or something else wearing the same shirt?",
    "cyberSkills": [
      "look-alike evidence comparison & FP disposition"
    ],
    "hints": [
      "A low-confidence heuristic fired on the same tool (reg.exe) used in a real incident elsewhere. Your job is to pull every reg.exe event on this device and compare it against what you already know about the confirmed credential dump — same hive? Same account? Same parent process?",
      "Project Timestamp, AccountName, ProcessCommandLine, and InitiatingProcessFileName for every reg.exe save on FAB-IT-01, then compare each row against alert-b2's evidence.",
      "DeviceProcessEvents | where DeviceName == \"FAB-IT-01\" and FileName == \"reg.exe\" | project Timestamp, AccountName, ProcessCommandLine, InitiatingProcessFileName."
    ],
    "solutionQuery": "DeviceProcessEvents\n| where DeviceName == \"FAB-IT-01\" and FileName == \"reg.exe\"\n| project Timestamp, AccountName, ProcessCommandLine, InitiatingProcessFileName",
    "facts": [
      "svc_veeam",
      "svc_backup",
      "hklm\\software\\veeam",
      "veeamagent.exe"
    ],
    "maxExpectedRows": 6,
    "mitre": "T1003.002 · OS Credential Dumping: Security Account Manager",
    "teaches": [
      "where",
      "comparing look-alike evidence",
      "disposition judgment"
    ],
    "answer": "svc_veeam",
    "answerLabel": "Which account is behind the benign reg.exe activity?",
    "disposition": "FP",
    "dispositionWhy": "Same tool (reg.exe save) and the same alert technique tag, but a different hive (SOFTWARE\\Veeam, not SAM/SYSTEM), a dedicated backup service account, and a VeeamAgent.exe parent process running on a schedule — the nightly backup job, not credential theft. The heuristic that raised this alert can't tell the difference on its own; that's your job.",
    "alertId": "alert-e1",
    "severity": "Low"
  },
  {
    "id": "s23",
    "level": "Intermediate",
    "table": "SigninLogs",
    "title": "Credential stuffing",
    "domain": "Identity & Access",
    "discipline": "SOC Triage",
    "prompt": "Entra ID Protection is showing unusual sign-in activity for a Marketing account. Find the user/IP pair with a burst of failed sign-ins (five or more) — that's your credential-stuffing candidate.",
    "cyberSkills": [
      "brute-force / credential-stuffing detection"
    ],
    "hints": [
      "A single failed sign-in is normal — a typo happens. What you're hunting for is a burst: the same source hammering the same account over and over in a short window, that THEN gets in — a burst alone isn't enough, since this range also has an account that got hammered and never got in at all (that's a different pattern entirely, password guessing, not stuffing). Think about what you'd group by to spot the burst, and what you'd check afterward to confirm it actually succeeded.",
      "Filter SigninLogs to the failed-sign-in result code, then summarize a count grouped by both the user and the source IP so a burst from one IP stands out from ordinary scattered typos, keeping the timestamp of the last failure too. Then join that against successful sign-ins (ResultType \"0\") on the same user and IP, and keep only cases where the success came AFTER the failure burst — that's what actually makes it stuffing instead of just an unsuccessful guessing attempt.",
      "SigninLogs | where ResultType == \"50126\" | summarize Failures = count(), LastFailure = max(TimeGenerated) by UserPrincipalName, IPAddress | where Failures >= 5 | join kind=inner (SigninLogs | where ResultType == \"0\" | project UserPrincipalName, IPAddress, SuccessTime = TimeGenerated) on UserPrincipalName, IPAddress | where SuccessTime > LastFailure."
    ],
    "solutionQuery": "SigninLogs\n| where ResultType == \"50126\"\n| summarize Failures = count(), LastFailure = max(TimeGenerated) by UserPrincipalName, IPAddress\n| where Failures >= 5\n| join kind=inner (\n    SigninLogs\n    | where ResultType == \"0\"\n    | project UserPrincipalName, IPAddress, SuccessTime = TimeGenerated\n  ) on UserPrincipalName, IPAddress\n| where SuccessTime > LastFailure",
    "facts": [
      "ohansen@fabrikam.example",
      "192.0.2.187",
      "9"
    ],
    "teaches": [
      "where",
      "summarize by multiple columns",
      "post-aggregation where",
      "join"
    ],
    "mitre": "T1110.004 · Brute Force: Credential Stuffing",
    "maxExpectedRows": 1,
    "answer": "ohansen@fabrikam.example",
    "answerAliases": [
      "ohansen"
    ],
    "answerLabel": "Which account was hit with the credential-stuffing burst?",
    "disposition": "TP",
    "dispositionWhy": "Nine failed sign-ins from the same external IP in under six minutes, immediately followed by a success from that same IP, is the credential-stuffing pattern — not a user who forgot their password once.",
    "alertId": "alert-p1",
    "severity": "High"
  },
  {
    "id": "s24",
    "level": "Advanced",
    "table": "SigninLogs",
    "title": "Impossible travel",
    "domain": "Identity & Access",
    "discipline": "Threat Hunting",
    "prompt": "That account's story isn't over — the burst of failures was followed by a real successful sign-in. Check every account's successful sign-ins: does any single user have successful sign-ins from more than one country? That's the impossible-travel signal.",
    "cyberSkills": [
      "impossible-travel / account-takeover hunting"
    ],
    "hints": [
      "You're not looking at one row anymore — you're looking at a pattern across ALL of one user's successful sign-ins. What operator lets you collapse a column down to the unique values seen per user?",
      "summarize by UserPrincipalName with make_set() over Location gives you every distinct country each user signed in from. A function that counts array elements can then flag anyone with more than one.",
      "SigninLogs | where ResultType == \"0\" | summarize Countries = make_set(Location) by UserPrincipalName | extend NumCountries = array_length(Countries) | where NumCountries > 1."
    ],
    "solutionQuery": "SigninLogs\n| where ResultType == \"0\"\n| summarize Countries = make_set(Location) by UserPrincipalName\n| extend NumCountries = array_length(Countries)\n| where NumCountries > 1",
    "facts": [
      "ohansen@fabrikam.example",
      "RO",
      "US",
      "2"
    ],
    "teaches": [
      "summarize",
      "make_set",
      "array_length",
      "extend after summarize"
    ],
    "mitre": "T1078.004 · Valid Accounts: Cloud Accounts",
    "maxExpectedRows": 1,
    "answer": "RO",
    "answerLabel": "Besides US, what other country did this account successfully sign in from?",
    "disposition": "TP",
    "dispositionWhy": "A successful sign-in from Romania followed six minutes later by a successful sign-in from the US isn't a traveling employee — it's the attacker's session and the real user's session, minutes apart, from the same compromised account.",
    "alertId": "alert-p2",
    "severity": "Medium"
  },
  {
    "id": "s25",
    "level": "Advanced",
    "table": "AuditLogs",
    "title": "The consent grant",
    "domain": "Identity & Access",
    "discipline": "Incident Response",
    "prompt": "Minutes after that risky sign-in, an OAuth application was granted access — without any admin involved. Find the AuditLogs entry recording a user consenting to an application. Who consented?",
    "cyberSkills": [
      "illicit consent grant / OAuth persistence investigation"
    ],
    "hints": [
      "Admins aren't the only identities that show up in AuditLogs — an ordinary user consenting to an app they were prompted to authorize leaves its own trail. What activity name would that leave behind?",
      "Filter AuditLogs on the ActivityDisplayName that Microsoft's own incident-response playbooks search for when hunting illicit consent grants, then look at who the Identity column says did it.",
      "AuditLogs | where ActivityDisplayName == \"Consent to application\" | project TimeGenerated, Identity, Location, ActivityDisplayName."
    ],
    "solutionQuery": "AuditLogs\n| where ActivityDisplayName == \"Consent to application\"\n| project TimeGenerated, Identity, Location, ActivityDisplayName",
    "facts": [
      "ohansen@fabrikam.example",
      "consent to application",
      "ro"
    ],
    "teaches": [
      "where",
      "project",
      "pivoting from a compromised identity to admin-log activity"
    ],
    "mitre": "T1528 · Steal Application Access Token",
    "maxExpectedRows": 1,
    "answer": "ohansen@fabrikam.example",
    "answerAliases": [
      "ohansen"
    ],
    "answerLabel": "Which identity consented to the application?",
    "disposition": "TP",
    "dispositionWhy": "The compromised user, not an admin, granted an OAuth app access — from the same session, minutes after the attacker's own risky sign-in. That's the illicit-consent-grant pattern attackers use to keep access even after a password reset.",
    "alertId": "alert-p3",
    "severity": "High"
  },
  {
    "id": "s26",
    "level": "Intermediate",
    "table": "NetworkAccessTraffic",
    "title": "Flagged by threat intel",
    "domain": "Network Security",
    "discipline": "Threat Hunting",
    "prompt": "Global Secure Access logs every flow through it, but the ThreatType column is only populated when Microsoft's own threat intelligence recognizes the destination. Find the one flow where that happened. What destination was it, and what threat type was it flagged as?",
    "cyberSkills": [
      "threat-intel-matched network traffic triage"
    ],
    "hints": [
      "Most rows in this table have nothing in ThreatType — it's empty for ordinary traffic. You want the rare row where it isn't.",
      "There's a function that checks whether a column holds any value at all, as opposed to being blank. Use it on ThreatType.",
      "NetworkAccessTraffic | where isnotempty(ThreatType)."
    ],
    "solutionQuery": "NetworkAccessTraffic\n| where isnotempty(ThreatType)",
    "facts": [
      "telemetry-sync-api.net",
      "c2",
      "203.0.113.91"
    ],
    "teaches": [
      "where",
      "isnotempty"
    ],
    "mitre": "T1071 · Application Layer Protocol",
    "maxExpectedRows": 1,
    "answer": "telemetry-sync-api.net",
    "answerLabel": "What destination did Global Secure Access flag?",
    "disposition": "TP",
    "dispositionWhy": "GSA's own threat-intelligence feed matched this destination to a known C2 indicator and blocked it, from the same account that was just compromised — about as confirmed as a network detection gets.",
    "alertId": "alert-p4",
    "severity": "High"
  },
  {
    "id": "s27",
    "level": "Advanced",
    "multiStep": true,
    "table": "SigninLogs / AuditLogs / NetworkAccessTraffic",
    "title": "Full investigation: the ohansen compromise",
    "domain": "Identity & Access",
    "discipline": "Incident Response",
    "cyberSkills": [
      "end-to-end incident investigation (scope → confirm → root cause → impact)"
    ],
    "intro": "A risky sign-in alert just fired for ohansen (Marketing). Real investigations don't stop at the first query that finds something — work this one start to finish: scope what happened, confirm it's actually a takeover and not a traveling employee, find how the attacker kept their foothold, then find out whether they got anywhere with it. Each step unlocks once you've got the one before it right.",
    "prompt": "A risky sign-in alert just fired for ohansen (Marketing). Real investigations don't stop at the first query that finds something — work this one start to finish: scope what happened, confirm it's actually a takeover and not a traveling employee, find how the attacker kept their foothold, then find out whether they got anywhere with it. Each step unlocks once you've got the one before it right.",
    "steps": [
      {
        "key": "scope",
        "label": "Scope",
        "table": "SigninLogs",
        "prompt": "Step 1 — Scope the alert. Entra ID Protection flagged unusual sign-in activity. Find the user/IP pair with a burst of failed sign-ins (five or more) — that's your starting point.",
        "hints": [
          "A single failed sign-in is normal — a typo happens. What you're hunting for is a burst: the same source hammering the same account over and over in a short window, that THEN gets in — a burst alone isn't enough on its own, since a completely separate incident elsewhere in this range is an account that got hammered and never got in at all. Think about what you'd group by to spot the burst, and what you'd check afterward to confirm it actually succeeded.",
          "Filter SigninLogs to the failed-sign-in result code, then summarize a count grouped by both the user and the source IP (keeping the timestamp of the last failure too) so a burst from one IP stands out from ordinary scattered typos. Then join that against successful sign-ins (ResultType \"0\") on the same user and IP, keeping only cases where the success came AFTER the failure burst.",
          "SigninLogs | where ResultType == \"50126\" | summarize Failures = count(), LastFailure = max(TimeGenerated) by UserPrincipalName, IPAddress | where Failures >= 5 | join kind=inner (SigninLogs | where ResultType == \"0\" | project UserPrincipalName, IPAddress, SuccessTime = TimeGenerated) on UserPrincipalName, IPAddress | where SuccessTime > LastFailure."
        ],
        "solutionQuery": "SigninLogs\n| where ResultType == \"50126\"\n| summarize Failures = count(), LastFailure = max(TimeGenerated) by UserPrincipalName, IPAddress\n| where Failures >= 5\n| join kind=inner (\n    SigninLogs\n    | where ResultType == \"0\"\n    | project UserPrincipalName, IPAddress, SuccessTime = TimeGenerated\n  ) on UserPrincipalName, IPAddress\n| where SuccessTime > LastFailure",
        "facts": [
          "ohansen@fabrikam.example",
          "192.0.2.187",
          "9"
        ],
        "teaches": [
          "where",
          "summarize by multiple columns",
          "post-aggregation where",
          "join"
        ],
        "answer": "ohansen@fabrikam.example",
        "answerAliases": [
          "ohansen"
        ],
        "answerLabel": "Which account was hit with the credential-stuffing burst?"
      },
      {
        "key": "confirm",
        "label": "Confirm takeover",
        "table": "SigninLogs",
        "prompt": "Step 2 — Confirm it's actually a takeover. The burst of failures was followed by a real successful sign-in — but that alone doesn't prove compromise; the real user might just be traveling. Check every account's successful sign-ins: does this one have successes from more than one country?",
        "hints": [
          "You're not looking at one row anymore — you're looking at a pattern across ALL of this user's successful sign-ins. What operator lets you collapse a column down to the unique values seen per user?",
          "summarize by UserPrincipalName with make_set() over Location gives you every distinct country each user signed in from. A function that counts array elements can then flag anyone with more than one.",
          "SigninLogs | where ResultType == \"0\" | summarize Countries = make_set(Location) by UserPrincipalName | extend NumCountries = array_length(Countries) | where NumCountries > 1."
        ],
        "solutionQuery": "SigninLogs\n| where ResultType == \"0\"\n| summarize Countries = make_set(Location) by UserPrincipalName\n| extend NumCountries = array_length(Countries)\n| where NumCountries > 1",
        "facts": [
          "ohansen@fabrikam.example",
          "RO",
          "US",
          "2"
        ],
        "teaches": [
          "summarize",
          "make_set",
          "array_length",
          "extend after summarize"
        ],
        "answer": "RO",
        "answerLabel": "Besides US, what other country did this account successfully sign in from?"
      },
      {
        "key": "rootCause",
        "label": "Root cause",
        "table": "AuditLogs",
        "prompt": "Step 3 — Find the root cause of persistence. Account takeover is confirmed. Now find how the attacker made sure they'd keep access even after a password reset: search AuditLogs for a user (not an admin) consenting to an application. Who consented?",
        "hints": [
          "Admins aren't the only identities that show up in AuditLogs — an ordinary user consenting to an app they were prompted to authorize leaves its own trail. What activity name would that leave behind?",
          "Filter AuditLogs on the ActivityDisplayName that Microsoft's own incident-response playbooks search for when hunting illicit consent grants, then look at who the Identity column says did it.",
          "AuditLogs | where ActivityDisplayName == \"Consent to application\" | project TimeGenerated, Identity, Location, ActivityDisplayName."
        ],
        "solutionQuery": "AuditLogs\n| where ActivityDisplayName == \"Consent to application\"\n| project TimeGenerated, Identity, Location, ActivityDisplayName",
        "facts": [
          "ohansen@fabrikam.example",
          "consent to application",
          "ro"
        ],
        "teaches": [
          "where",
          "project",
          "pivoting from a compromised identity to admin-log activity"
        ],
        "answer": "ohansen@fabrikam.example",
        "answerAliases": [
          "ohansen"
        ],
        "answerLabel": "Which identity consented to the application?"
      },
      {
        "key": "impact",
        "label": "Impact",
        "table": "NetworkAccessTraffic",
        "prompt": "Step 4 — Assess the impact. Persistence is in place — but did the attacker actually get anywhere with it? Check NetworkAccessTraffic for the one flow Microsoft's own threat intelligence recognized as malicious. What destination was it, and what threat type?",
        "hints": [
          "Most rows in this table have nothing in ThreatType — it's empty for ordinary traffic. You want the rare row where it isn't.",
          "There's a function that checks whether a column holds any value at all, as opposed to being blank. Use it on ThreatType.",
          "NetworkAccessTraffic | where isnotempty(ThreatType)."
        ],
        "solutionQuery": "NetworkAccessTraffic\n| where isnotempty(ThreatType)",
        "facts": [
          "telemetry-sync-api.net",
          "c2",
          "203.0.113.91"
        ],
        "teaches": [
          "where",
          "isnotempty"
        ],
        "answer": "telemetry-sync-api.net",
        "answerLabel": "What destination did Global Secure Access flag?"
      }
    ],
    "teaches": [
      "where",
      "summarize",
      "summarize by multiple columns",
      "post-aggregation where",
      "make_set",
      "array_length",
      "extend after summarize",
      "project",
      "isnotempty",
      "chaining queries across a live investigation"
    ],
    "mitre": "T1078.004 · Valid Accounts: Cloud Accounts",
    "answer": "telemetry-sync-api.net",
    "answerLabel": "What destination did Global Secure Access flag?",
    "disposition": "TP",
    "dispositionWhy": "Nine failed sign-ins then a success from a foreign IP, a same-account sign-in from two countries six minutes apart, a non-admin OAuth consent grant from that session, and a follow-up beacon flagged by threat intel — every stage of this chain points the same direction, end to end. This is a real, ongoing compromise, not noise.",
    "alertId": "alert-p5",
    "severity": "High"
  },
  {
    "id": "s28",
    "level": "Intermediate",
    "table": "DeviceProcessEvents",
    "title": "Cryptomining after the AI-orchestrator breach",
    "domain": "Endpoint Security",
    "discipline": "Threat Hunting",
    "prompt": "CISA's September 2026 Known Exploited Vulnerabilities update flagged a wave of actively-exploited flaws in self-hosted AI/workflow-orchestration tools, with attackers deploying reverse shells and XMRig cryptominers after breaking in. Fabrikam Engineering self-hosts one of the affected orchestrator types on FAB-ENG-08. Find the cryptominer process: which account did it run under, and what mining pool is it connecting to?",
    "cyberSkills": [
      "cryptomining / resource-hijacking detection",
      "post-exploitation payload hunting"
    ],
    "hints": [
      "A cryptominer has to tell the mining-pool software where to connect — that means its command line carries a distinctive connection string, not just a suspicious file name.",
      "Mining-pool connections are addressed with a specific URL scheme in the command line. Filter DeviceProcessEvents' ProcessCommandLine for that scheme rather than for a generic flag like \"-o\" alone — a legitimate backup tool uses \"-o\" too, and you don't want that false positive.",
      "DeviceProcessEvents | where ProcessCommandLine contains \"stratum+tcp\" | project Timestamp, DeviceName, AccountName, ProcessCommandLine."
    ],
    "solutionQuery": "DeviceProcessEvents\n| where ProcessCommandLine contains \"stratum+tcp\"\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine",
    "facts": [
      "ssingh",
      "relay-pool-sync.net"
    ],
    "teaches": [
      "where",
      "contains",
      "project"
    ],
    "mitre": "T1496 · Resource Hijacking",
    "maxExpectedRows": 1,
    "answer": "ssingh",
    "answerLabel": "Which account did the cryptominer run under?",
    "disposition": "TP",
    "dispositionWhy": "A live stratum mining-pool connection string in a process launched minutes after a reverse-shell-style child process from the same host's AI-orchestrator service is the exact reverse-shell-then-XMRig pattern CISA and multiple vendors reported this week after attackers exploited self-hosted AI/orchestration tooling.",
    "alertId": "alert-p6",
    "severity": "High"
  },
  {
    "id": "s29",
    "level": "Advanced",
    "table": "EmailEvents",
    "title": "The word that isn't really there",
    "domain": "Email Security",
    "discipline": "Threat Hunting",
    "prompt": "Microsoft Security disclosed this week that a phishing-style scam campaign peaked at 2.37 million messages in a single week by hiding finance lure words — like \"funding\" — inside invisible Unicode Tag-block characters (U+E0000-U+E007F). A message reading \"funding\" to a human can literally NOT contain that substring, because an invisible codepoint sits inside the word. A teammate swept the mailbox with `EmailEvents | where Subject contains \"funding\"` and found almost nothing. Don't trust that. Find the real footprint of this campaign a different way: how many distinct sender domains delivered scam email carrying this lure, going by what Defender itself already flagged rather than by searching the visible subject text?",
    "cyberSkills": [
      "recognizing keyword-filter evasion via invisible Unicode",
      "phishing-campaign infrastructure clustering"
    ],
    "hints": [
      "The visible word isn't a reliable filter here — Microsoft's own filtering stack still caught these messages even though a literal substring search on the word a human reads wouldn't. What other column on EmailEvents already carries a verdict, independent of the subject text?",
      "Filter EmailEvents on its threat-verdict column for the bulk-scam classification this campaign actually got (not the same verdict as the unrelated invoice-phishing email elsewhere in this mailbox), then count how many distinct values `SenderFromDomain` takes across what's left.",
      "EmailEvents | where ThreatTypes == \"Spam\" | summarize DomainCount = dcount(SenderFromDomain)"
    ],
    "solutionQuery": "EmailEvents\n| where ThreatTypes == \"Spam\"\n| summarize DomainCount = dcount(SenderFromDomain)",
    "facts": [
      "5"
    ],
    "teaches": [
      "where",
      "summarize",
      "dcount"
    ],
    "mitre": "T1027.018 · Obfuscated Files or Information: Invisible Unicode",
    "maxExpectedRows": 1,
    "answer": "5",
    "answerLabel": "How many distinct sender domains delivered this campaign's scam email?",
    "disposition": "TP",
    "dispositionWhy": "Every one of these messages already carries Defender's own Spam verdict, and the pattern — an invisible Unicode codepoint splitting a common finance lure word, spread across several disposable lookalike lender domains — matches a real, currently-active campaign, not a one-off false alarm.",
    "alertId": "alert-p7",
    "severity": "Medium"
  },
  {
    "id": "s30",
    "level": "Intermediate",
    "table": "SigninLogs",
    "title": "MFA fatigue",
    "domain": "Identity & Access",
    "discipline": "SOC Triage",
    "prompt": "tnowak has a valid password this whole time — there's no credential-stuffing burst to find. Instead, SigninLogs is full of the same account failing sign-in over and over with a strong-authentication error, from the same IP, in a tight window, before one finally succeeds. Find the user/IP pair with five or more MFA prompts that didn't complete.",
    "cyberSkills": [
      "MFA-fatigue / push-bombing detection"
    ],
    "hints": [
      "This isn't a wrong-password pattern — the account already has the right password. What's failing here is the SECOND factor, over and over. Entra ID has its own distinct result code for \"the user didn't complete the MFA prompt,\" separate from the wrong-password code you'd use for credential stuffing.",
      "Filter SigninLogs to that MFA-not-completed result code (500121, not 50126), then summarize a count grouped by user and source IP the same way you would for a brute-force burst.",
      "SigninLogs | where ResultType == \"500121\" | summarize Denials = count() by UserPrincipalName, IPAddress | where Denials >= 5."
    ],
    "solutionQuery": "SigninLogs\n| where ResultType == \"500121\"\n| summarize Denials = count() by UserPrincipalName, IPAddress\n| where Denials >= 5",
    "facts": [
      "tnowak@fabrikam.example",
      "198.51.100.201",
      "11"
    ],
    "teaches": [
      "where",
      "summarize by multiple columns",
      "post-aggregation where",
      "distinguishing sign-in error codes"
    ],
    "mitre": "T1621 · Multi-Factor Authentication Request Generation",
    "maxExpectedRows": 1,
    "answer": "tnowak@fabrikam.example",
    "answerAliases": [
      "tnowak"
    ],
    "answerLabel": "Which account was hit with the MFA-fatigue burst?",
    "disposition": "TP",
    "dispositionWhy": "Eleven MFA prompts denied inside twenty minutes from the same account and IP, immediately followed by one acceptance, isn't a user fat-fingering a notification once — it's push-bombing: sending prompts until the target taps Approve just to make them stop. This is the technique Uber's own September 2022 breach disclosure described; it doesn't need a stolen password to work, only patience and a valid credential from somewhere else.",
    "alertId": "alert-u1",
    "severity": "High"
  },
  {
    "id": "s31",
    "level": "Advanced",
    "multiStep": true,
    "table": "SigninLogs / AuditLogs",
    "title": "Full investigation: the forgotten test account",
    "domain": "Identity & Access",
    "discipline": "Incident Response",
    "cyberSkills": [
      "password-spray detection",
      "legacy/no-MFA account risk investigation",
      "OAuth persistence hunting"
    ],
    "intro": "Entra ID Protection flagged a wave of failed sign-ins, but not the pattern you've seen before — no single account is getting hammered. Real password spraying works the opposite way: a few guesses against a lot of accounts, hoping one has a weak or reused password. Scope it, find out which account actually fell, then find how the attacker made sure they'd keep access.",
    "prompt": "Entra ID Protection flagged a wave of failed sign-ins, but not the pattern you've seen before — no single account is getting hammered. Real password spraying works the opposite way: a few guesses against a lot of accounts, hoping one has a weak or reused password. Scope it, find out which account actually fell, then find how the attacker made sure they'd keep access.",
    "steps": [
      {
        "key": "scope",
        "label": "Scope",
        "table": "SigninLogs",
        "prompt": "Step 1 — Scope the spray. Password spraying spreads its guesses across many accounts from one source instead of hammering one account, so counting failures per account won't find it. Find the IP address that failed sign-ins against five or more DIFFERENT accounts.",
        "hints": [
          "Counting total failures per IP would work too, but the real tell of a SPRAY specifically is the number of distinct accounts targeted, not the raw failure count. What function counts unique values instead of just counting rows?",
          "summarize with dcount() over UserPrincipalName, grouped by IPAddress, tells you how many different accounts each source IP tried — a spray shows up as one IP with a high distinct-account count, even though each individual account only failed a couple of times.",
          "SigninLogs | where ResultType == \"50126\" | summarize DistinctAccounts = dcount(UserPrincipalName) by IPAddress | where DistinctAccounts >= 5."
        ],
        "solutionQuery": "SigninLogs\n| where ResultType == \"50126\"\n| summarize DistinctAccounts = dcount(UserPrincipalName) by IPAddress\n| where DistinctAccounts >= 5",
        "facts": [
          "198.51.100.44",
          "6"
        ],
        "teaches": [
          "where",
          "summarize",
          "dcount",
          "post-aggregation where"
        ],
        "answer": "198.51.100.44",
        "answerLabel": "Which IP failed sign-ins against five or more different accounts?"
      },
      {
        "key": "confirm",
        "label": "Confirm compromise",
        "table": "SigninLogs",
        "prompt": "Step 2 — Confirm the fall. That IP tried a small number of guesses against a wide spread of accounts and mostly failed — but at least one of those attempts didn't. Find the successful sign-in that came from that same IP. Which account did the attacker actually get into?",
        "hints": [
          "You already know the one IP worth looking at. Now you just need the one row from that IP where the result was different from all the others.",
          "Filter SigninLogs to that exact IP address, and add a second condition on the result code for success rather than failure.",
          "SigninLogs | where IPAddress == \"198.51.100.44\" and ResultType == \"0\"."
        ],
        "solutionQuery": "SigninLogs\n| where IPAddress == \"198.51.100.44\"\n| where ResultType == \"0\"",
        "facts": [
          "qatest01@fabrikam.example"
        ],
        "teaches": [
          "where with a known indicator",
          "pivoting from an indicator to the successful outcome"
        ],
        "answer": "qatest01@fabrikam.example",
        "answerAliases": [
          "qatest01"
        ],
        "answerLabel": "Which account signed in successfully from the spray IP?"
      },
      {
        "key": "rootCause",
        "label": "Root cause",
        "table": "AuditLogs",
        "prompt": "Step 3 — Find how they kept access. qatest01 turns out to be a legacy test account nobody remembered to decommission — no MFA, minimal oversight. That's exactly the kind of foothold Microsoft's own January 2024 disclosure described a nation-state actor using to get into a corporate environment: not a zero-day, an old test account with no MFA. Once in, the goal is access that survives a password reset. Search AuditLogs for a service principal being handed brand-new credentials. Whose session did it happen in?",
        "hints": [
          "Adding credentials to an app or service principal is a specific, named action in the audit log — distinct from consenting to an app (which is what you'd look for if the attacker had instead tricked a user into authorizing an OAuth app).",
          "There's a real Microsoft Entra audit activity literally named for handing a service principal new credentials. Filter ActivityDisplayName to it.",
          "AuditLogs | where ActivityDisplayName == \"Add service principal credentials\"."
        ],
        "solutionQuery": "AuditLogs\n| where ActivityDisplayName == \"Add service principal credentials\"",
        "facts": [
          "qatest01@fabrikam.example",
          "add service principal credentials"
        ],
        "teaches": [
          "where",
          "recognizing persistence activity in an audit log"
        ],
        "answer": "qatest01@fabrikam.example",
        "answerAliases": [
          "qatest01"
        ],
        "answerLabel": "Whose session added credentials to a service principal?"
      }
    ],
    "teaches": [
      "where",
      "summarize",
      "dcount",
      "post-aggregation where",
      "where with a known indicator",
      "pivoting from an indicator to the successful outcome",
      "recognizing persistence activity in an audit log",
      "chaining queries across a live investigation"
    ],
    "mitre": "T1110.003 · Password Spraying; T1098.001 · Account Manipulation: Additional Cloud Credentials",
    "answer": "qatest01@fabrikam.example",
    "answerAliases": [
      "qatest01"
    ],
    "answerLabel": "Whose session added credentials to a service principal?",
    "disposition": "TP",
    "dispositionWhy": "One external IP failing a couple of guesses against six different accounts, a single success against a forgotten test account with no MFA, and new credentials added to a service principal from that same account's session minutes later — that's initial access and persistence, back to back. This is the pattern Microsoft's own January 2024 blog described for the Midnight Blizzard nation-state intrusion: not a sophisticated exploit, a stale test account and an OAuth credential used to stay in.",
    "alertId": "alert-m1",
    "severity": "High"
  },
  {
    "id": "s32",
    "level": "Intermediate",
    "table": "AuditLogs / SigninLogs",
    "title": "The helpdesk call",
    "domain": "Identity & Access",
    "discipline": "SOC Triage",
    "prompt": "lchen's account just signed in successfully — flagged by Entra ID as a high-risk sign-in — ninety seconds after someone reset lchen's password. There's no column in this schema that says WHO a password reset was performed for, so you can't just join your way there. What you CAN see is who performed the reset. Find the \"Reset user password\" event that wasn't done by the routine admin account. Who performed it?",
    "cyberSkills": [
      "help-desk social-engineering / impersonation detection"
    ],
    "hints": [
      "Most \"Reset user password\" events in this log are routine — they all come from the same admin identity. You're hunting for the one that doesn't.",
      "Filter AuditLogs to the reset activity, then add a second condition that excludes the routine admin identity by name.",
      "AuditLogs | where ActivityDisplayName == \"Reset user password\" and Identity != \"admin@fabrikam.example\"."
    ],
    "solutionQuery": "AuditLogs\n| where ActivityDisplayName == \"Reset user password\"\n| where Identity != \"admin@fabrikam.example\"",
    "facts": [
      "helpdesk-admin@fabrikam.example"
    ],
    "teaches": [
      "where",
      "excluding a known-good value with !=",
      "correlating across tables by time when there's no join key"
    ],
    "mitre": "T1656 · Impersonation; T1566.004 · Phishing: Spearphishing Voice",
    "maxExpectedRows": 1,
    "answer": "helpdesk-admin@fabrikam.example",
    "answerAliases": [
      "helpdesk-admin"
    ],
    "answerLabel": "Which identity performed the password reset?",
    "disposition": "TP",
    "dispositionWhy": "A password reset performed by an identity other than the routine admin account, immediately followed by a high-risk-flagged successful sign-in on lchen's account just ninety seconds later, is the workflow the joint CISA/FBI advisory on Scattered Spider (AA23-320A) documents for this actor: call the help desk, impersonate the employee, and talk a technician into a reset — bypassing every technical control because the human at the help desk was the target, not the login page.",
    "alertId": "alert-v1",
    "severity": "High"
  },
  {
    "id": "s33",
    "level": "Intermediate",
    "table": "DeviceProcessEvents",
    "title": "The print server that started acting like a person",
    "domain": "Endpoint Security",
    "discipline": "Threat Hunting",
    "prompt": "CISA added two chained PaperCut NG/MF vulnerabilities to its Known Exploited Vulnerabilities catalog on August 31, 2026 — CVE-2026-81578 (missing authentication for a critical function, CVSS 8.8) and CVE-2026-82078 (unsafe dynamic Java class-loading, CVSS 9.4) — which an unauthenticated attacker can chain together for full remote code execution against an internet-facing PaperCut server, no login required. Fabrikam's print-management server (FAB-IT-01) runs PaperCut's application server process, pc-app.exe. A server process like that has no legitimate reason to launch anything a human would run from a keyboard. Find what pc-app.exe spawned. What process was it, and what account did it run as?",
    "cyberSkills": [
      "living-off-the-land / anomalous parent-child process detection",
      "pre-auth RCE exploitation hunting on an internet-facing application"
    ],
    "hints": [
      "pc-app.exe is a Windows service — the PaperCut Application Server. Legitimate server processes don't spawn interactive utilities on their own; if it launched ANYTHING at all, that launch itself is the anomaly, whatever the child process happens to be named.",
      "Filter on the PARENT, not the child. InitiatingProcessFileName is the column that names what launched a given process — that's the pivot here, not FileName.",
      "DeviceProcessEvents | where InitiatingProcessFileName == \"pc-app.exe\" | project Timestamp, DeviceName, FileName, AccountDomain, AccountName, ProcessCommandLine"
    ],
    "solutionQuery": "DeviceProcessEvents\n| where InitiatingProcessFileName == \"pc-app.exe\"\n| project Timestamp, DeviceName, FileName, AccountDomain, AccountName, ProcessCommandLine",
    "facts": [
      "charmap.exe",
      "SYSTEM"
    ],
    "teaches": [
      "where",
      "InitiatingProcessFileName (parent-process pivot)",
      "project"
    ],
    "mitre": "T1190 · Exploit Public-Facing Application",
    "maxExpectedRows": 1,
    "answer": "charmap.exe",
    "answerLabel": "What unexpected process did the print server spawn?",
    "disposition": "TP",
    "dispositionWhy": "A print-management server's own application process spawning a GUI character-map utility under a SYSTEM account is the exact post-exploitation signature Huntress documented in the wild after chaining these two PaperCut bugs — a server process has no legitimate path to launching that, whatever it's named. This isn't a print job gone sideways.",
    "alertId": "alert-p8",
    "severity": "High"
  },
  {
    "id": "s34",
    "level": "Intermediate",
    "table": "DeviceProcessEvents",
    "title": "The antivirus that started running things",
    "domain": "Endpoint Security",
    "discipline": "Threat Hunting",
    "prompt": "A researcher published a public proof-of-concept on August 12, 2026 for a local privilege-escalation zero-day in Windows Defender itself — dubbed \"ShieldBreak\" — that abuses the Cloud Filter API (the mechanism behind OneDrive-style cloud file hydration) to trick Defender's own scanning engine, MsMpEng.exe, into executing attacker-controlled code as NT AUTHORITY\\SYSTEM. As of this writing there is still no official patch. Vendor guidance agrees on the behavioral tell even though no one has published an exact captured payload: MsMpEng.exe, which always runs as SYSTEM, has no ordinary reason to launch anything else at all. Find what MsMpEng.exe spawned on Fabrikam's fleet, and what account it ran as.",
    "cyberSkills": [
      "anomalous parent-child process detection on a security-tooling process",
      "hunting an actively-exploited zero-day with no vendor-published IOC"
    ],
    "hints": [
      "MsMpEng.exe is Defender's own antimalware engine — it always runs as NT AUTHORITY\\SYSTEM, and it doesn't spawn child processes as part of normal scanning. If it launched ANYTHING, that launch is the anomaly, regardless of what the child process is named.",
      "Same pivot as the print-server mission: filter on the PARENT, not the child. InitiatingProcessFileName is where you look for what launched a given process.",
      "DeviceProcessEvents | where InitiatingProcessFileName == \"MsMpEng.exe\" | project Timestamp, DeviceName, FileName, AccountDomain, AccountName, ProcessCommandLine"
    ],
    "solutionQuery": "DeviceProcessEvents\n| where InitiatingProcessFileName == \"MsMpEng.exe\"\n| project Timestamp, DeviceName, FileName, AccountDomain, AccountName, ProcessCommandLine",
    "facts": [
      "calc.exe",
      "SYSTEM"
    ],
    "teaches": [
      "where",
      "InitiatingProcessFileName (parent-process pivot)",
      "project"
    ],
    "mitre": "T1068 · Exploitation for Privilege Escalation",
    "maxExpectedRows": 1,
    "answer": "calc.exe",
    "answerLabel": "What process did MsMpEng.exe spawn?",
    "disposition": "TP",
    "dispositionWhy": "Defender's own scanning engine has no legitimate path to launching another process on its own — vendor bulletins (Arctic Wolf, Qualys) specifically call out child-process creation from MsMpEng.exe as the behavioral tell for this unpatched zero-day. No vendor has published the actual payload attackers are using in the wild; this mission illustrates the detection principle rather than a captured real-world artifact, and says so in its own text.",
    "alertId": "alert-p9",
    "severity": "High"
  },
  {
    "id": "s35",
    "level": "Intermediate",
    "table": "DeviceProcessEvents",
    "title": "The DNS tool that lived in the wrong folder",
    "domain": "Endpoint Security",
    "discipline": "Threat Hunting",
    "prompt": "A newly reported commercial infostealer, REVSTEALER, leaves behind a persistence module its own authors named \"LockAppHost\" — the same name as a real, legitimate Windows Lock Screen process. Elastic Security Labs' analysis (via TheHackerNews, Sept 6 2026) reports that after disabling Windows Update and adding Microsoft Defender exclusions, the module \"hides [its] miner in legitimate processes (nslookup.exe or svchost.exe)\". Genuine System-owned utilities like nslookup.exe only ever run from C:\\Windows\\System32. Find the nslookup.exe process on Fabrikam's fleet that ISN'T running from there — what folder is it actually running from, and under which account?",
    "cyberSkills": [
      "masquerading detection via file-path validation, not filename trust",
      "hunting a newly reported infostealer's persistence module with no published pool/C2 command line"
    ],
    "hints": [
      "The filename here is completely real and ordinary — nslookup.exe ships with every copy of Windows. The lie isn't the name, it's the location. A genuine System32 utility never executes from a user's AppData folder.",
      "Filter on the FileName, then add a second condition on FolderPath that excludes the real, legitimate System32 path — that's the pivot, not the process name itself.",
      "DeviceProcessEvents | where FileName == \"nslookup.exe\" and FolderPath != \"C:\\\\Windows\\\\System32\" | project Timestamp, DeviceName, FolderPath, AccountDomain, AccountName, ProcessCommandLine"
    ],
    "solutionQuery": "DeviceProcessEvents\n| where FileName == \"nslookup.exe\" and FolderPath != \"C:\\\\Windows\\\\System32\"\n| project Timestamp, DeviceName, FolderPath, AccountDomain, AccountName, ProcessCommandLine",
    "facts": [
      "C:\\Users\\kwalters\\AppData\\Local\\LockAppHost",
      "kwalters",
      "FAB-FIN-07"
    ],
    "teaches": [
      "where",
      "compound where (FileName + FolderPath)",
      "masquerading via folder-path mismatch",
      "project"
    ],
    "mitre": "T1036.005 · Masquerading: Match Legitimate Resource Name or Location",
    "maxExpectedRows": 1,
    "answer": "C:\\Users\\kwalters\\AppData\\Local\\LockAppHost",
    "answerAliases": [
      "Users\\kwalters\\AppData\\Local\\LockAppHost",
      "AppData\\Local\\LockAppHost",
      "C:\\Users\\kwalters\\AppData\\Local\\LockAppHost\\"
    ],
    "answerLabel": "What folder was the disguised nslookup.exe actually running from?",
    "disposition": "TP",
    "dispositionWhy": "A process using the name of a legitimate Windows DNS utility, launched by a parent process ALSO named after — and not running from the real location of — the genuine Windows Lock Screen host, both executing from a user's AppData folder instead of System32, matches exactly what Elastic Security Labs and TheHackerNews reported for REVSTEALER's \"LockAppHost\" persistence module: disable Defender and Windows Update, then hide a cryptocurrency miner behind a legitimate-sounding process name rather than an obviously malicious one.",
    "alertId": "alert-p10",
    "severity": "High"
  },
  {
    "id": "s36",
    "level": "Intermediate",
    "table": "DeviceProcessEvents",
    "title": "The remote-support tool that started scripting",
    "domain": "Endpoint Security",
    "discipline": "Threat Hunting",
    "prompt": "Huntress reported this week that attackers who already control an organization's ScreenConnect remote-support sessions are using them to push a four-stage VBScript chain onto every newly-connected host — turning a trusted IT support channel into a self-propagating delivery pipeline. ScreenConnect's own legitimate client process, ScreenConnect.ClientService.exe, has no ordinary reason to hand off to a scripting interpreter — a normal remote-support session is graphical, not script-driven. Find what it spawned on Fabrikam's fleet. What process was it, and what account did it run as?",
    "cyberSkills": [
      "living-off-trusted-tooling (RMM/remote-support) abuse detection",
      "recognizing a legitimate remote-access tool used as a delivery/C2 channel"
    ],
    "hints": [
      "IT support tools like ScreenConnect exist so a technician can remotely control a machine — they don't hand off to a scripting engine on their own. If this legitimate client process launched anything at all, that launch itself is the anomaly, whatever it's named.",
      "Same pivot as the print-server and Defender-engine cases: filter on the PARENT process, not what it launched. InitiatingProcessFileName is where you check what launched a given process.",
      "DeviceProcessEvents | where InitiatingProcessFileName == \"ScreenConnect.ClientService.exe\" | project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName"
    ],
    "solutionQuery": "DeviceProcessEvents\n| where InitiatingProcessFileName == \"ScreenConnect.ClientService.exe\"\n| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName",
    "facts": [
      "wscript.exe",
      "1.vbs"
    ],
    "teaches": [
      "where",
      "InitiatingProcessFileName (parent-process pivot)",
      "project"
    ],
    "mitre": "T1219 · Remote Access Tools",
    "maxExpectedRows": 1,
    "answer": "wscript.exe",
    "answerLabel": "What process did the ScreenConnect client spawn?",
    "disposition": "TP",
    "dispositionWhy": "ScreenConnect's own client service has no legitimate reason to launch a scripting interpreter. Huntress's write-up on this active campaign describes exactly this pattern: an already-compromised ScreenConnect session pushing a four-stage VBScript chain (1.vbs through 4.vbs, each pulling the next stage from Dropbox) onto every host it connects to next — a trusted remote-support channel turned into a self-propagating delivery pipeline, not a technician's normal workflow.",
    "alertId": "alert-p11",
    "severity": "High"
  },
  {
    "id": "s37",
    "level": "Intermediate",
    "table": "SigninLogs",
    "title": "The proxy behind the risky sign-in",
    "domain": "Identity & Access",
    "discipline": "Threat Hunting",
    "prompt": "Entra ID Protection flagged two sign-ins today as high risk. Both look the same at a glance — same risk level, both interactive, both technically successful with MFA satisfied. \"High risk\" isn't one signal, though: Entra tracks the SPECIFIC reason each sign-in got flagged, not just how risky it judged the sign-in overall. Find the one flagged specifically for coming through anonymizing-proxy infrastructure — a VPN, Tor, or similar service built to hide who's really connecting. Which account was it?",
    "cyberSkills": [
      "distinguishing Entra ID Protection risk-detection TYPE from risk LEVEL",
      "recognizing AitM-stolen-session replay via anonymizing/residential-proxy infrastructure"
    ],
    "hints": [
      "IsRisky and RiskLevelDuringSignIn only tell you THAT a sign-in was flagged and HOW risky Entra judged it — not WHY. Entra ID Protection fires a specific, named risk detection for every risky sign-in, and this schema has a column for exactly that.",
      "Look for RiskEventTypes_V2 — the column naming which risk detection actually fired. The real Entra ID Protection detection type for anonymizing network traffic (Tor, anonymous VPN, and similar) is named \"anonymizedIPAddress,\" not a generic \"proxy\" label.",
      "SigninLogs | where RiskEventTypes_V2 == \"anonymizedIPAddress\" | project TimeGenerated, UserPrincipalName, IPAddress, RiskLevelDuringSignIn."
    ],
    "solutionQuery": "SigninLogs\n| where RiskEventTypes_V2 == \"anonymizedIPAddress\"\n| project TimeGenerated, UserPrincipalName, IPAddress, RiskLevelDuringSignIn",
    "facts": [
      "cwoo@fabrikam.example",
      "anonymizedIPAddress"
    ],
    "teaches": [
      "where",
      "distinguishing risk-detection TYPE (RiskEventTypes_V2) from risk LEVEL",
      "project"
    ],
    "mitre": "T1090.002 · External Proxy",
    "maxExpectedRows": 1,
    "answer": "cwoo@fabrikam.example",
    "answerAliases": [
      "cwoo"
    ],
    "answerLabel": "Which account's sign-in was flagged specifically for anonymizing-proxy network use?",
    "disposition": "TP",
    "dispositionWhy": "Arctic Wolf's \"PREY-0058\" reporting (Sept 8, 2026) describes callers impersonating IT/help-desk staff steering executives to lookalike authentication portals that harvest a live, MFA-satisfied session via adversary-in-the-middle, then replaying that stolen session from residential-proxy/anonymizer infrastructure specifically to evade device- and location-based detection. Entra ID Protection's real-time \"Anonymous IP address\" detection exists exactly to catch that network pattern. The other high-risk sign-in today is a real risk detection too (unfamiliar sign-in features) but an unrelated one — a reminder that \"flagged as high risk\" isn't a single signal, and this range's own older incidents (E/I/J) each left a high-risk sign-in behind too, which is exactly why risk LEVEL alone isn't precise enough to isolate today's incident.",
    "alertId": "alert-p12",
    "severity": "High"
  },
  {
    "id": "s38",
    "level": "Intermediate",
    "table": "DeviceProcessEvents",
    "title": "The backup tool that turned destructive",
    "domain": "Endpoint Security",
    "discipline": "Threat Hunting",
    "prompt": "A process alert fired for vssadmin.exe — Windows' own Volume Shadow Copy admin tool. That's not unusual on its own; backup jobs query shadow copies all the time. What matters is what it was actually TOLD to do. Find the invocation that isn't just checking shadow copies, but destroying them — the classic step ransomware takes right before encrypting a victim, so there's nothing left to roll back to. Which account ran it?",
    "cyberSkills": [
      "recognizing MITRE T1490 (Inhibit System Recovery) — the pre-encryption step in almost every modern ransomware chain",
      "separating a destructive command-line invocation of a legitimate admin tool from routine, benign use of the same binary"
    ],
    "hints": [
      "Ransomware operators almost always delete Windows' Volume Shadow Copies right before encrypting files, so victims can't just restore from a snapshot. The tool that does this is a completely normal Windows admin binary — the giveaway isn't its name, it's what command it was given.",
      "Filter DeviceProcessEvents for FileName == \"vssadmin.exe\", then look at ProcessCommandLine. A legitimate backup job might just list or resize shadow storage; a destructive one issues a delete.",
      "DeviceProcessEvents | where FileName == \"vssadmin.exe\" and ProcessCommandLine has \"delete\" | project Timestamp, DeviceName, AccountName, ProcessCommandLine."
    ],
    "solutionQuery": "DeviceProcessEvents\n| where FileName == \"vssadmin.exe\" and ProcessCommandLine has \"delete\"\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName",
    "facts": [
      "tnowak",
      "vssadmin.exe Delete Shadows /all /quiet"
    ],
    "teaches": [
      "where",
      "has (whole-term matching, case-insensitive)",
      "reading command-line intent rather than filtering on a binary's name alone"
    ],
    "mitre": "T1490 · Inhibit System Recovery",
    "maxExpectedRows": 1,
    "answer": "tnowak",
    "answerAliases": [
      "tnowak@fabrikam.example"
    ],
    "answerLabel": "Which account ran the destructive shadow-copy deletion?",
    "disposition": "TP",
    "dispositionWhy": "CISA and the FBI's own #StopRansomware Medusa Ransomware advisory (AA25-071A) quotes the exact real command observed in a Medusa incident — \"vssadmin.exe Delete Shadows /all /quiet\" — used verbatim here. MITRE ATT&CK's own T1490 page independently documents the same class of command from BlackCat/ALPHV, Conti, and WannaCry, so this is one of the most consistently-attested ransomware TTPs across multiple ransomware families, not a one-off. It matters this week specifically: INC Ransom posted 11 new victims in 5 days (manufacturing and healthcare hit hardest) and a new RaaS operation, \"Panzer,\" has already claimed 16 victims across 11 countries since its leak site went live in August — this mission isn't claiming either group ran this exact command, but this is the generic step almost any of their affiliates would take right before encryption. A benign vssadmin.exe invocation exists in this same dataset (a routine backup job listing shadow copies) — a bare FileName == \"vssadmin.exe\" sweep catches both; only the command line tells you which one is the incident.",
    "alertId": "alert-p13",
    "severity": "High"
  },
  {
    "id": "s39",
    "level": "Intermediate",
    "table": "DeviceProcessEvents",
    "title": "The task that re-runs itself every five minutes",
    "domain": "Endpoint Security",
    "discipline": "Threat Hunting",
    "prompt": "Volexity reported this week that multiple Chinese threat actors chained THREE zero-days — two in Chrome, one in the Windows kernel — for full browser-to-kernel compromise. One of them, UTA0560, survives a reboot the ordinary way: it drops a DLL that creates a Windows scheduled task. schtasks.exe creating something isn't inherently suspicious — IT automation does that constantly. Find the one task on the fleet that re-runs its own loader every five minutes rather than doing routine IT work. Which account is it running under?",
    "cyberSkills": [
      "recognizing scheduled-task-based persistence (T1053.005) following a browser/kernel exploit chain",
      "separating a malicious scheduled task from routine IT automation by task name + cadence, not the tool's name alone"
    ],
    "hints": [
      "schtasks.exe firing isn't the anomaly by itself — plenty of legitimate IT automation creates scheduled tasks. What you're really hunting for is a task with an unusual NAME and an unusually tight recurrence, not the mere presence of schtasks.exe.",
      "Filter DeviceProcessEvents for FileName == \"schtasks.exe\", then look at ProcessCommandLine for the specific task name reported in the wild — a routine nightly job will have a completely different, boring name.",
      "DeviceProcessEvents | where FileName == \"schtasks.exe\" and ProcessCommandLine contains \"Windows Scheduled System\" | project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName"
    ],
    "solutionQuery": "DeviceProcessEvents\n| where FileName == \"schtasks.exe\" and ProcessCommandLine contains \"Windows Scheduled System\"\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName",
    "facts": [
      "cwoo",
      "Windows Scheduled System"
    ],
    "teaches": [
      "where",
      "contains",
      "project"
    ],
    "mitre": "T1053.005 · Scheduled Task/Job: Scheduled Task",
    "maxExpectedRows": 1,
    "answer": "cwoo",
    "answerAliases": [
      "cwoo@fabrikam.example"
    ],
    "answerLabel": "Which account is the malicious scheduled task running under?",
    "disposition": "TP",
    "dispositionWhy": "This isn't a claim that UTA0560 specifically targeted this fictional company — it's built directly from Volexity's own reporting on this actor's real post-exploitation chain: a dropper (msgbox.exe) sideloads a malicious DLL (wsc.dll), which establishes persistence by creating a scheduled task literally named \"Windows Scheduled System\" that re-runs the whole sideloading chain every five minutes. That's the generic persistence step any actor running this exact playbook would leave behind, running under the compromised user's own account rather than SYSTEM, since this follows a browser-launched exploit chain rather than a SYSTEM-level payload. A legitimate, differently-named IT scheduled task exists in this same dataset — proof that schtasks.exe activity alone isn't the signal; the specific task name and its five-minute cadence are.",
    "alertId": "alert-p14",
    "severity": "High"
  },
  {
    "id": "s40",
    "level": "Intermediate",
    "table": "DeviceProcessEvents",
    "title": "The archive tool that wasn't where it belonged",
    "domain": "Endpoint Security",
    "discipline": "Threat Hunting",
    "prompt": "Gen Digital reported this week that the threat actor UNC3569 exploited a flaw in Sogou Input Method (CVE-2026-51990) to run a downloader that stages a REAL 7-Zip executable and a malicious 7z.dll together in the same folder — 7-Zip loads any DLL sitting next to it at startup, so that's enough to get the malicious code running and ultimately load the GRAYRABBIT backdoor. 7z.exe itself is completely legitimate and installed on plenty of machines. Find the one running from somewhere it should never be. What folder is it actually running from?",
    "cyberSkills": [
      "recognizing DLL search-order hijacking (T1574.001) abusing a trusted, commonly-installed utility",
      "validating a known-legitimate binary's folder path rather than trusting its filename alone"
    ],
    "hints": [
      "7z.exe isn't malware — it's the real 7-Zip archiver, and plenty of legitimate rows in this fleet's data involve it. The tell isn't the filename, it's WHERE it's running from. The real install location is C:\\Program Files\\7-Zip.",
      "Filter DeviceProcessEvents for FileName == \"7z.exe\", then add a second condition on FolderPath that excludes the real install path — that isolates anything running from somewhere 7-Zip was never installed.",
      "DeviceProcessEvents | where FileName == \"7z.exe\" and FolderPath != \"C:\\\\Program Files\\\\7-Zip\" | project Timestamp, DeviceName, FolderPath, AccountDomain, AccountName, ProcessCommandLine"
    ],
    "solutionQuery": "DeviceProcessEvents\n| where FileName == \"7z.exe\" and FolderPath != \"C:\\\\Program Files\\\\7-Zip\"\n| project Timestamp, DeviceName, FolderPath, AccountDomain, AccountName, ProcessCommandLine",
    "facts": [
      "C:\\Users\\Public\\Documents",
      "mrivera",
      "FAB-MKT-02"
    ],
    "teaches": [
      "where",
      "compound where (FileName + FolderPath)",
      "DLL search-order hijacking via folder-path validation",
      "project"
    ],
    "mitre": "T1574.001 · Hijack Execution Flow: DLL",
    "maxExpectedRows": 1,
    "answer": "C:\\Users\\Public\\Documents",
    "answerAliases": [
      "Users\\Public\\Documents",
      "C:\\Users\\Public\\Documents\\"
    ],
    "answerLabel": "What folder was the disguised 7z.exe actually running from?",
    "disposition": "TP",
    "dispositionWhy": "This isn't a claim that UNC3569 targeted this fictional company — it's built from Gen Digital's own reporting on a real intrusion: a Sogou Input Method flaw (CVE-2026-51990) drives a downloader that drops a genuine 7-Zip executable next to a malicious 7z.dll in a non-standard, user-writable folder, so 7-Zip's own normal DLL-loading behavior gets hijacked into running the attacker's code on the way to the GRAYRABBIT backdoor. This exact archiving-tool sideload pattern has independent precedent on MITRE's own T1574.001 page (Storm-1811 doing the same thing with a modified 7zG.exe). The report doesn't name the specific process that executes the dropped 7z.exe — only SGMyInput.exe, the process the crafted link itself targets, is explicitly named at that point in the chain, so that's what's modeled here rather than an invented intermediary. A legitimate 7z.exe row already exists elsewhere in this dataset, running from its real install path — proof that the filename alone was never the signal.",
    "alertId": "alert-p15",
    "severity": "High"
  },
  {
    "id": "s41",
    "level": "Intermediate",
    "table": "DeviceFileEvents",
    "title": "The task manager that went looking for secrets",
    "domain": "Endpoint Security",
    "discipline": "Threat Hunting",
    "prompt": "Prophet Security's quarterly threat report (via BleepingComputer, published this week) analyzed 4.7 million alert-investigation questions and found that on the least-monitored endpoints in customer environments, attackers reached for ordinary Windows tools — accessibility utilities, Task Manager, and error-reporting services — to get at LSASS, the process that holds Windows credentials in memory. One well-documented way Task Manager does this: right-click lsass.exe, \"Create dump file.\" That writes the entire process's memory to disk as a .DMP file — no child process, no PowerShell, just a file appearing where lsass.exe's memory shouldn't be. Task Manager also gets used the ordinary way on this fleet, to dump a crashed application for support tickets, so don't just look for the tool — look for what it dumped. Which account ran Task Manager to create the real credential-dump file?",
    "cyberSkills": [
      "recognizing LSASS memory-dumping via a living-off-the-land GUI tool (T1003.001), not just a scripted one",
      "pivoting on a file-creation event's target file rather than the trusted tool's name alone"
    ],
    "hints": [
      "Task Manager creating a file isn't news by itself — IT support does that on this fleet too, dumping crashed apps for troubleshooting. The tell isn't that taskmgr.exe made a file, it's WHICH file.",
      "This is a DeviceFileEvents question, not DeviceProcessEvents — Task Manager writes the dump straight to disk, it doesn't spawn a child process to do it. Filter InitiatingProcessFileName for taskmgr.exe, then narrow by what the created file is actually named.",
      "DeviceFileEvents | where InitiatingProcessFileName == \"taskmgr.exe\" and FileName contains \"lsass\" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName"
    ],
    "solutionQuery": "DeviceFileEvents\n| where InitiatingProcessFileName == \"taskmgr.exe\" and FileName contains \"lsass\"\n| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName",
    "facts": [
      "lsass.DMP",
      "FAB-HR-02",
      "agomez"
    ],
    "teaches": [
      "where",
      "contains",
      "compound where (InitiatingProcessFileName + FileName)",
      "project"
    ],
    "mitre": "T1003.001 · OS Credential Dumping: LSASS Memory",
    "maxExpectedRows": 1,
    "answer": "agomez",
    "answerAliases": [
      "agomez@fabrikam.example"
    ],
    "answerLabel": "Which account ran Task Manager to create the real credential-dump file?",
    "disposition": "TP",
    "dispositionWhy": "Grounded in Prophet Security's Sept 10, 2026 quarterly report (via BleepingComputer), which names Task Manager — alongside accessibility utilities and error-reporting services — as one of the legitimate Windows tools attackers used to reach LSASS on organizations' least-monitored endpoints. That report doesn't publish an exact file path or command line for the Task Manager sub-case specifically — the mechanism modeled here (right-click lsass.exe, \"Create dump file,\" writing a .DMP under ...\\AppData\\Local\\Temp) comes from two independently-documented sources instead: MITRE's own CAR-2019-08-001 analytic, and the SigmaHQ community detection rule for this exact technique. MITRE ATT&CK T1003.001 (OS Credential Dumping: LSASS Memory) independently cross-confirms Task Manager as a real-world LSASS-dumping method in its own procedure examples — the Cutting Edge campaign, the Iranian group Magic Hound, and the Play ransomware group have all been documented using it this way. This isn't a claim that any of those three specifically targeted this fictional company; it's the same generic, tool-agnostic technique any of them (or Prophet's unmonitored-asset intruders) would leave behind. A legitimate Task Manager crash-dump exists elsewhere in this same dataset — proof that Task Manager writing a .DMP file is never the signal by itself; what it dumped is.",
    "alertId": "alert-p16",
    "severity": "High"
  },
  {
    "id": "s42",
    "level": "Intermediate",
    "table": "DeviceProcessEvents",
    "title": "The AI installer that told Defender to look away",
    "domain": "Endpoint Security",
    "discipline": "Threat Hunting",
    "prompt": "Microsoft's own security team flagged malvertising for a fake AI Windows plugin that delivered the Vidar credential stealer as one of the AI-branded lures it's actively catching right now. A separately reported campaign matching that exact shape used a fake AI-tool installer whose own setup instructions told victims to add it to their antivirus exclusion list before running it — and PowerShell has a real, one-line cmdlet for exactly that. IT runs that same cmdlet legitimately too, for real software installs. Find the exclusion that was added for a suspicious, user-writable folder rather than a real Program Files install. Which account added it?",
    "cyberSkills": [
      "recognizing Impair Defenses / T1562.001 via a Defender-exclusion PowerShell command",
      "separating a malicious defense-tampering command from routine IT software-rollout activity"
    ],
    "hints": [
      "Windows Defender exclusions get added constantly by legitimate IT tooling during real software installs — the cmdlet itself isn't the tell. What matters is WHERE the exclusion points: a real installed program lives under Program Files, not a user's own AppData folder.",
      "Filter ProcessCommandLine for the real PowerShell cmdlet that adds a Defender scan exclusion, then narrow to the invocation whose path argument points somewhere no legitimate installer would ever put itself.",
      "DeviceProcessEvents | where ProcessCommandLine contains \"Add-MpPreference\" and ProcessCommandLine contains \"AppData\" | project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName"
    ],
    "solutionQuery": "DeviceProcessEvents\n| where ProcessCommandLine contains \"Add-MpPreference\" and ProcessCommandLine contains \"AppData\"\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName",
    "facts": [
      "ohansen",
      "GoogleAppInstaller.exe"
    ],
    "teaches": [
      "where",
      "contains",
      "compound where (command-line content, not just process name)",
      "project"
    ],
    "mitre": "T1562.001 · Impair Defenses: Disable or Modify Tools",
    "maxExpectedRows": 1,
    "answer": "ohansen",
    "answerAliases": [
      "ohansen@fabrikam.example"
    ],
    "answerLabel": "Which account added the exclusion for the suspicious folder?",
    "disposition": "TP",
    "dispositionWhy": "A fake AI-tool installer, running from a non-standard folder under the user's own AppData, telling PowerShell to add that exact folder to Windows Defender's scan-exclusion list before it runs — that's textbook T1562.001, and the shape matches what Microsoft's own security team says it's actively catching right now in AI-branded malvertising (delivering the Vidar stealer). The same cmdlet also has a completely routine use — IT adding an exclusion for a real, Program-Files-installed backup tool during a scheduled rollout — which is exactly why the cmdlet's presence alone isn't the signal; where it points is.",
    "alertId": "alert-p17",
    "severity": "High"
  },
  {
    "id": "s43",
    "level": "Intermediate",
    "table": "DeviceProcessEvents",
    "title": "The Run dialog that fixed nothing",
    "domain": "Endpoint Security",
    "discipline": "Threat Hunting",
    "prompt": "Attackers hijacked HBO Max's own verified Reddit account and ran 108 malicious ads over about 48 hours, using \"ClickFix\": ads that tell the victim they need to fix an error or pass a CAPTCHA by pressing Win+R and pasting a command. That command line runs straight from the Run dialog, so the process tree looks wrong from the very first hop — explorer.exe launching PowerShell directly, not the ordinary path a real script shortcut would take through cmd.exe. The Run dialog also gets used the ordinary way on this fleet, for ordinary personal scripts, so the parent-child pattern alone won't isolate it — you need the obfuscated payload itself. Which account ran the obfuscated command?",
    "cyberSkills": [
      "recognizing ClickFix-style user-execution (T1204.004) via the anomalous explorer.exe-directly-spawns-powershell.exe parent-child pattern",
      "separating an obfuscated iwr/irm/iex download-and-execute chain from an ordinary, non-malicious Run-dialog PowerShell launch"
    ],
    "hints": [
      "explorer.exe launching powershell.exe by itself isn't news — that's exactly what the Run dialog (Win+R) does for any ordinary script, too. The tell isn't that the parent is explorer.exe, it's what the launched command line actually says.",
      "Filter DeviceProcessEvents for InitiatingProcessFileName == \"explorer.exe\" and FileName == \"powershell.exe\", then narrow to the one whose ProcessCommandLine actually chains a download-and-run cmdlet (iwr/irm piped into iex) rather than just running a local script file.",
      "DeviceProcessEvents | where InitiatingProcessFileName == \"explorer.exe\" and FileName == \"powershell.exe\" and ProcessCommandLine has \"iex\" | project Timestamp, DeviceName, AccountName, ProcessCommandLine"
    ],
    "solutionQuery": "DeviceProcessEvents\n| where InitiatingProcessFileName == \"explorer.exe\" and FileName == \"powershell.exe\" and ProcessCommandLine has \"iex\"\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine",
    "facts": [
      "lchen",
      "FAB-HR-05",
      "secure-captcha-verify.example"
    ],
    "teaches": [
      "where",
      "has",
      "compound where (parent-child pattern + command-line content)",
      "project"
    ],
    "mitre": "T1204.004 · User Execution: Malicious Copy and Paste",
    "maxExpectedRows": 1,
    "answer": "lchen",
    "answerAliases": [
      "lchen@fabrikam.example"
    ],
    "answerLabel": "Which account ran the obfuscated command?",
    "disposition": "TP",
    "dispositionWhy": "Grounded in BleepingComputer's Sept 14, 2026 report that attackers hijacked HBO Max's own verified Reddit account and ran 108 malicious ClickFix ads over roughly 48 hours (researchers at Hudson Rock and ADAMnetworks track this as Operation \"PasteSwitch\"), tricking victims into pasting a malicious command into the Windows Run dialog while believing they're fixing an error or passing a CAPTCHA. That article quotes an exact macOS ClickFix command verbatim but does NOT publish a captured Windows command line for the campaign's reported \"Amatera Stealer\" PowerShell delivery — only that it happens \"via obfuscated PowerShell.\" This mission's exact obfuscated iwr/irm/iex syntax is therefore NOT a literal quote from the HBO Max incident — it's built from Microsoft's own generically-documented ClickFix command shape (Microsoft Security Blog, \"Think before you ClickFix,\" Aug 21 2025), which independently confirms explorer.exe (the Run dialog) spawning a LOLBin like powershell.exe directly — never the ordinary cmd.exe-then-powershell.exe chain a legitimate script launch takes — as the real, documented anomaly, with obfuscated iwr/irm/iex-chained PowerShell as the common payload shape. The same Run-dialog PowerShell launch also happens for a completely ordinary reason elsewhere on this fleet, which is exactly why the parent-child pattern by itself was never the signal — the obfuscated download-and-execute content is.",
    "alertId": "alert-p18",
    "severity": "High"
  },
  {
    "id": "s44",
    "level": "Intermediate",
    "table": "DeviceNetworkEvents",
    "title": "The scan that knew exactly what it wanted",
    "domain": "Network Security",
    "discipline": "Threat Hunting",
    "prompt": "Hunt.io reported this week on a Chinese-speaking operator (tracked only by the infrastructure handle \"Nie\") running an AI-orchestration framework called SecFlow — Claude, Qwen, and DeepSeek agents chained together to automate reconnaissance-through-exploitation against government, education, and telecom targets. The report names a set of known CVEs the operator's tooling exploits, each living on its own distinctive port: Grafana (3000), Nexus Repository Manager (8081), Tomcat's AJP connector / \"Ghostcat\" (8009), and Nacos (8848). FAB-IT-01 shows a burst of connections to a single downstream address hitting several distinct ports in a matter of seconds — but this fleet also runs its own authorized internal vulnerability scanner, which produces the exact same shape (many distinct ports, one source, tight time window) every time it runs. Raw port fan-out alone won't tell them apart. Find the burst that's specifically hitting this campaign's own reported exploited-service ports. What address did it target?",
    "cyberSkills": [
      "active-scanning / port-sweep detection via aggregation",
      "distinguishing malicious reconnaissance from an authorized vulnerability scanner producing the same shape"
    ],
    "hints": [
      "A burst of connections to many different ports from one source in a tight window is the classic shape of active service scanning — but that shape by itself also matches a perfectly legitimate vulnerability scanner doing its job. Counting distinct ports alone won't separate the two; you need to know WHICH ports.",
      "Aggregate DeviceNetworkEvents with `summarize dcount(RemotePort) by RemoteIP` to find any source with a wide port fan-out on FAB-IT-01 — then filter to just the small, specific set of ports this campaign's own reported exploited services use, not ports in general.",
      "DeviceNetworkEvents | where DeviceName == \"FAB-IT-01\" and RemotePort in (3000, 8009, 8081, 8848) | summarize PortsHit = dcount(RemotePort) by RemoteIP | where PortsHit >= 3"
    ],
    "solutionQuery": "DeviceNetworkEvents\n| where DeviceName == \"FAB-IT-01\" and RemotePort in (3000, 8009, 8081, 8848)\n| summarize PortsHit = dcount(RemotePort) by RemoteIP\n| where PortsHit >= 3",
    "facts": [
      "203.0.113.87",
      "4"
    ],
    "teaches": [
      "where",
      "summarize",
      "dcount",
      "post-aggregation where"
    ],
    "mitre": "T1595 · Active Scanning",
    "maxExpectedRows": 1,
    "answer": "203.0.113.87",
    "answerLabel": "What downstream address did the scanning burst hit across all four of the campaign's exploited-service ports?",
    "disposition": "TP",
    "dispositionWhy": "Hunt.io's Sept 3, 2026 report (resurfaced in TheHackerNews' Sept 16 \"ThreatsDay\" roundup) documents a Chinese-speaking operator, tracked only by the infrastructure handle \"Nie,\" running an AI-orchestration framework (\"SecFlow\") that automates reconnaissance-through-exploitation using Claude/Qwen/DeepSeek agents against government, education, and telecom targets — and the report's own MITRE ATT&CK mapping lists T1595 (Active Scanning) among the techniques used, alongside a named set of exploited CVEs across specific services (Grafana, Nexus, Ghostcat/Tomcat AJP, Nacos, and others). Hunt.io does NOT publish a literal scan-burst telemetry table for this campaign — no captured list of exact ports, timing, or source for a specific incident — so this mission's four ports (the real, verified default ports of the exploited services the report names) and its timing are a disclosed, illustrative modeling choice grounded in T1595's own definition (probing for open ports/services) and the campaign's documented target-service list, not a captured IOC. What makes this a true positive rather than routine scanning noise: raw port fan-out alone isn't the signal — this same fleet's own authorized vulnerability scanner also sweeps a broad range of common ports against internal hosts from time to time, producing the identical many-distinct-ports-from-one-source shape — but this burst hits specifically, and only, the small set of ports tied to this campaign's own reported exploited services, which the authorized scanner's much broader, generic port range never touches.",
    "alertId": "alert-p19",
    "severity": "High"
  },
  {
    "id": "s45",
    "level": "Intermediate",
    "table": "DeviceProcessEvents",
    "title": "The Python runtime that built its own tunnel",
    "domain": "Endpoint Security",
    "discipline": "Threat Hunting",
    "prompt": "Microsoft's own \"TerminalFix\" write-up (Aug 28, 2026) documents a ClickFix-variant campaign: a fake Cloudflare CAPTCHA overlay talks a victim into pasting a command into their own terminal, kicking off a multistage intrusion that ends with a real, unmodified Python runtime (downloaded straight from python.org) opening a persistent reverse tunnel back out over port 443. Microsoft's own advanced-hunting query for this exact stage checks two things together: is the process pythonw.exe OR python.exe, AND does its command line carry every one of the tunnel client's required arguments at once. Run that same check against Fabrikam's fleet — which account launched it?",
    "cyberSkills": [
      "reverse-tunnel / custom C2-tooling detection via required-argument matching",
      "recognizing a legitimate scripting runtime (Python) repurposed as a tunnel client"
    ],
    "hints": [
      "python.exe and pythonw.exe are both completely legitimate — Python ships on plenty of machines for completely ordinary reasons, and this fleet has a benign automation script using it too. A reverse-tunnel client built on top of Python doesn't announce itself by binary name; it announces itself by the SPECIFIC set of connection arguments it needs, all present together on the same command line.",
      "Match the file name against BOTH possible Python launchers case-insensitively with `in~`, then require the command line to contain every one of the tunnel client's required flags at once — chain several `contains` checks together with `and` rather than trusting the binary name alone.",
      "DeviceProcessEvents | where FileName in~ (\"pythonw.exe\", \"python.exe\") | where ProcessCommandLine contains \"client.py\" and ProcessCommandLine contains \"--server\" and ProcessCommandLine contains \"--uuid\" and ProcessCommandLine contains \"cert.pem\""
    ],
    "solutionQuery": "DeviceProcessEvents\n| where FileName in~ (\"pythonw.exe\", \"python.exe\")\n| where ProcessCommandLine contains \"client.py\" and ProcessCommandLine contains \"--server\" and ProcessCommandLine contains \"--uuid\" and ProcessCommandLine contains \"cert.pem\"\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine",
    "facts": [
      "rpatel",
      "fab-fin-11",
      "gitsync-relay.example"
    ],
    "teaches": [
      "where",
      "in~ (case-insensitive list match)",
      "compound where (multiple chained contains)",
      "project"
    ],
    "mitre": "T1572 · Protocol Tunneling",
    "maxExpectedRows": 1,
    "answer": "rpatel",
    "answerAliases": [
      "rpatel@fabrikam.example"
    ],
    "answerLabel": "Which account launched the reverse-tunnel process?",
    "disposition": "TP",
    "dispositionWhy": "Grounded in Microsoft Security Blog's Aug 28, 2026 post \"TerminalFix campaign deploys a reverse tunnel through multistage intrusion,\" resurfaced this week via a German BSI warning and press coverage after it hit a German state institution and the Berlin Senate. This mission is built directly around the third of Microsoft's own four published hunting queries for this campaign, adapted only where this range's engine requires it — verbatim `in~` file-name check, and `contains` in place of Microsoft's `has_all` for the punctuation-bearing arguments (this range's simplified `has`/`has_all` only matches whole alphanumeric terms, so needles like \"--server\" or \"cert.pem\" never match here — a disclosed engine limitation, not a weaker detection) — plus the fictional .example domain standing in for the real reported one. Two things are worth disclosing plainly: (1) Microsoft's own post does NOT attribute TerminalFix to a named threat actor — a SEPARATE tracker, CrowdStrike, links this activity cluster to what it calls Vice Spider (aka Rhysida/Vanilla Tempest/InterLock), a financially-motivated ransomware operator — that's a different source's attribution, not Microsoft's own claim, and the two are kept distinct here. (2) Microsoft's second hunting query targets DeviceImageLoadEvents (detecting the campaign's dui70.dll sideload) — a table this range doesn't implement, the same class of documented gap as s43's missing DeviceRegistryEvents table — so the fake-CAPTCHA lure and the ProgramData/1.bat/LockScreenContentServer.exe launch chain that precede this stage are real, Microsoft-documented background, not encoded as queryable rows here. What IS fully modeled and graded: the one stage that maps cleanly onto a table this range supports end to end — a real, unmodified Python interpreter, not a custom binary, used as the tunnel client, distinguishable from this fleet's own completely legitimate Python automation script only by the exact combination of required connection arguments on its command line, exactly as Microsoft's own query checks for.",
    "alertId": "alert-p20",
    "severity": "High"
  },
  {
    "id": "s46",
    "level": "Intermediate",
    "table": "DeviceProcessEvents",
    "title": "The updater that unpacked itself somewhere else",
    "domain": "Endpoint Security",
    "discipline": "Threat Hunting",
    "prompt": "ESET researchers reported this week that FamousSparrow — a China-aligned espionage group — is deploying a new backdoor, \"SparroWocky,\" against government targets across Latin America via DLL side-loading: a legitimate executable launches a loader DLL that decrypts and runs the real payload. The article doesn't name which legitimate executable or DLL are used — only the mechanism. A genuine copy of this fleet's own updater utility only ever runs from its real Program Files install. Find the one running somewhere it was never installed. What folder is it actually running from?",
    "cyberSkills": [
      "recognizing DLL side-loading (T1574.001) via folder-path validation on a trusted utility",
      "hunting a newly reported nation-state backdoor with no published process/DLL filenames"
    ],
    "hints": [
      "The executable's name here is completely ordinary — it's a real, harmless updater tool that plenty of machines run. The lie isn't the name, it's WHERE it's running from. The real install location is C:\\Program Files\\AppUpdater.",
      "Filter on the FileName, then add a second condition on FolderPath that excludes the real install path — same pivot as the 7-Zip/GRAYRABBIT case, applied to a different utility.",
      "DeviceProcessEvents | where FileName == \"AppUpdater.exe\" and FolderPath != \"C:\\\\Program Files\\\\AppUpdater\" | project Timestamp, DeviceName, FolderPath, AccountDomain, AccountName, ProcessCommandLine"
    ],
    "solutionQuery": "DeviceProcessEvents\n| where FileName == \"AppUpdater.exe\" and FolderPath != \"C:\\\\Program Files\\\\AppUpdater\"\n| project Timestamp, DeviceName, FolderPath, AccountDomain, AccountName, ProcessCommandLine",
    "facts": [
      "c:\\users\\agomez\\appdata\\local\\appupdatercache",
      "agomez",
      "fab-hr-02"
    ],
    "teaches": [
      "where",
      "compound where (FileName + FolderPath)",
      "masquerading/side-loading via folder-path mismatch",
      "project"
    ],
    "mitre": "T1574.001 · Hijack Execution Flow: DLL",
    "maxExpectedRows": 1,
    "answer": "C:\\Users\\agomez\\AppData\\Local\\AppUpdaterCache",
    "answerAliases": [
      "Users\\agomez\\AppData\\Local\\AppUpdaterCache",
      "C:\\Users\\agomez\\AppData\\Local\\AppUpdaterCache\\",
      "appdata\\local\\appupdatercache"
    ],
    "answerLabel": "What folder was the disguised AppUpdater.exe actually running from?",
    "disposition": "TP",
    "dispositionWhy": "Grounded in TheHackerNews' Sept 17, 2026 report on ESET's research into FamousSparrow (a China-aligned espionage group) deploying a new C++ backdoor, \"SparroWocky,\" against government entities across Argentina, Ecuador, Guatemala, Honduras, Panama, Peru, Puerto Rico, and Venezuela, via DLL side-loading — a legitimate executable launching a loader DLL that decrypts and runs the real payload. Three things are disclosed plainly rather than glossed over: (1) MITRE ATT&CK's \"T1574.002 (DLL Side-Loading)\" no longer exists as a standalone sub-technique — fetching attack.mitre.org/techniques/T1574/002/ directly redirects to T1574.001, whose own page folds DLL side-loading in as one of its own named behaviors; this mission uses the correct, current ID, T1574.001, the same one s40's GRAYRABBIT mission already used — a real correction caught by verifying independently rather than trusting an un-checked technique ID. (2) The article names neither the specific legitimate executable nor the loader DLL involved — only the mechanism — so \"AppUpdater.exe\" and its cache folder are a disclosed illustrative stand-in, not a captured IOC. (3) The article also reports a real C2 IP (216.238.110.120, TLS-encrypted via Mbed TLS) — this range's standing convention fictionalizes every malicious external address with an RFC 5737 documentation-range value instead, so this incident's paired network connection (also in this dataset, alongside this graded process evidence) uses 198.51.100.130 in its place, not the real reported IP. A genuine copy of this same updater exists elsewhere on the fleet, running from its real Program Files location — proof the filename alone was never the signal.",
    "alertId": "alert-p21",
    "severity": "High"
  },
  {
    "id": "s47",
    "level": "Intermediate",
    "table": "DeviceProcessEvents",
    "title": "The Windows-sounding app that ran from \"All Users\"",
    "domain": "Endpoint Security",
    "discipline": "Threat Hunting",
    "prompt": "Group-IB's research (via TheHackerNews) ties the Iran-linked \"Handala\" hacktivist persona (operated by Void Manticore) to a Telegram-based backdoor, HEAVYGRAM — a joint UK NCSC / US FBI / Dutch advisory tracks the same underlying malware family under a different name, CHOSEN BRICK. Both sources agree on the persistence mechanism: a Windows Run key that launches a dropped file named winappx.exe, disguised to sound like a legitimate Windows component. This fleet has no table for reading the registry directly, but every time a user logs on, whatever that Run key points to gets launched by the shell itself — explorer.exe. Find the winappx.exe that explorer.exe launched from somewhere it was never installed. What folder is it actually running from?",
    "cyberSkills": [
      "recognizing Run-key persistence (T1547.001) via its downstream execution signal when no registry telemetry exists",
      "validating a Windows-branded process's folder path rather than trusting its name"
    ],
    "hints": [
      "There's no registry table here to catch the Run-key write itself — but a Run key doesn't do anything on its own. It has to actually launch something, every time the user logs on, and the process that does that launching is the ordinary Windows shell itself.",
      "Filter DeviceProcessEvents for FileName == \"winappx.exe\", then add a second condition on FolderPath that excludes wherever a real, legitimately-installed copy of that tool would run from (Program Files) — same pivot as the 7-Zip/AppUpdater cases.",
      "DeviceProcessEvents | where FileName == \"winappx.exe\" and FolderPath != \"C:\\\\Program Files\\\\WinAppX\" | project Timestamp, DeviceName, FolderPath, AccountDomain, AccountName, ProcessCommandLine"
    ],
    "solutionQuery": "DeviceProcessEvents\n| where FileName == \"winappx.exe\" and FolderPath != \"C:\\\\Program Files\\\\WinAppX\"\n| project Timestamp, DeviceName, FolderPath, AccountDomain, AccountName, ProcessCommandLine",
    "facts": [
      "c:\\users\\all users\\microsoftdistribution\\sysmain",
      "mrivera",
      "fab-mkt-02"
    ],
    "teaches": [
      "where",
      "compound where (FileName + FolderPath)",
      "hunting a persistence technique's downstream signal when the underlying table doesn't exist",
      "project"
    ],
    "mitre": "T1547.001 · Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
    "maxExpectedRows": 1,
    "answer": "C:\\Users\\All Users\\MicrosoftDistribution\\sysmain",
    "answerAliases": [
      "Users\\All Users\\MicrosoftDistribution\\sysmain",
      "C:\\Users\\All Users\\MicrosoftDistribution\\sysmain\\",
      "c:\\users\\all users\\microsoftdistribution\\sysmain",
      "all users\\microsoftdistribution\\sysmain"
    ],
    "answerLabel": "What folder was the disguised winappx.exe actually running from?",
    "disposition": "TP",
    "dispositionWhy": "Grounded in Group-IB's research (via TheHackerNews, Sept 17, 2026) on the Iran-linked \"Handala\" hacktivist persona, operated by Void Manticore (assessed Iran MOIS-affiliated), deploying the HEAVYGRAM Telegram-based backdoor alongside a Delphi defense-evasion utility, CRUDEEXCLUDE — corroborated by a joint UK NCSC / US FBI / Dutch advisory (~Sept 15-16, 2026) that tracks the same underlying malware family under a different name, CHOSEN BRICK. Both names are cited here as the same campaign, not two — the same treatment this range gave the ShieldBreak CVE-numbering disagreement. Both sources report persistence via the real, standard HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run key, and two named registry-value-to-dropped-file pairs — \"SMQDService\" and \"winappx\", the one modeled here, pointing at C:\\Users\\All Users\\MicrosoftDistribution\\sysmain\\winappx.exe, a real reported path, not invented for this mission. This range has no DeviceRegistryEvents table (a known, disclosed gap), so the registry write itself can't be queried directly — what IS modeled and graded is the one signal that gap still leaves visible: a Run-key entry has to actually execute on every logon, and that execution shows up as the shell process (explorer.exe) launching the dropped file, from the exact non-standard folder both sources report, never from any real Windows or third-party install path. The delivery method (fake app installers pushed over WhatsApp/Telegram), the Defender-exclusion evasion step (the same T1562.001 family s42 already covers), and the Telegram-bot-API C2/legitimate-cloud-service exfil channel are all real, reported parts of this campaign but aren't encoded as queryable rows here — the C2/exfil channel specifically rides abused LEGITIMATE third-party services (VultrObjects, StorjShare, iproyal.com, lightningproxies.net) that this range has no clean way to distinguish from their own ordinary legitimate traffic, so rather than invent a row that can't honestly tell the two apart, it's left as prompt-only background, the same conservative choice this range has made whenever a real mechanism doesn't map cleanly onto a table it implements.",
    "alertId": "alert-p22",
    "severity": "High"
  },
  {
    "id": "s48",
    "level": "Beginner",
    "table": "EmailEvents",
    "title": "The email that wanted your password",
    "domain": "Email Security",
    "discipline": "Fundamentals",
    "prompt": "A Tier 1 alert just landed in your queue: Microsoft Defender for Office 365 flagged a message sent to dkoval, an engineer here at Fabrikam, with the display name \"IT Service Desk\" and the subject \"Action required: verify your account password.\" At a glance it looks exactly like the routine IT notices Fabrikam employees get every week — same friendly display name, same mildly urgent subject line. But a display name is just a label the sender typed in when they composed the message; nothing on the receiving end checks it against anything. The field that actually tells you who sent a message is the sending DOMAIN — the part after the @ that the mail server delivered it from. Real Fabrikam IT mail always comes from fabrikam.example. This one claims to be IT, but don't take that at face value — look at what domain it actually came from. This is a good one to slow down on (budget yourself 30–45 minutes even though the KQL is short — the whole point of this mission is careful reading, not fast querying). The query itself is about as simple as it gets: one `where` clause. Somewhere in EmailEvents there are two messages sharing the exact same display name, \"IT Service Desk\" — one sent to dkoval, one sent to a different Fabrikam employee. Only one of them genuinely came from Fabrikam's real domain. Find the impostor message and answer with the domain it actually came from — not the one it's pretending to be.",
    "cyberSkills": [
      "recognizing display-name spoofing vs. verifying the real sending domain",
      "reading EmailEvents header fields instead of trusting what's visually prominent"
    ],
    "hints": [
      "Start with the concept, not the query. A display name (\"IT Service Desk\") is text the SENDER chose when composing the email — it lives on their end, and nothing on the receiving side verifies it against who they really are. Anyone who registers a brand-new domain can set their display name to whatever they like, including the name of your own IT team. That's exactly why security teams are trained never to trust a display name alone. What you CAN rely on is the domain the mail actually originated from — that's tied to real DNS infrastructure an attacker has to separately register and control, which is a much higher bar. So before writing anything: what field in EmailEvents captures where a message really came from, regardless of what name it's dressed up in?",
      "You're working in EmailEvents. Filtering for SenderDisplayName == \"IT Service Desk\" will pull back BOTH messages that use that display name — the real one and the fake one. To tell them apart, add exactly one more condition on SenderFromDomain: Fabrikam's real domain is fabrikam.example, so excluding that exact domain (SenderFromDomain != \"fabrikam.example\") should leave you with only the impostor. Project SenderFromDomain, RecipientEmailAddress, and Subject on the result so you can confirm the one row left over is the message sent to dkoval.",
      "EmailEvents | where SenderDisplayName == \"IT Service Desk\" and SenderFromDomain != \"fabrikam.example\" | project Timestamp, SenderFromDomain, RecipientEmailAddress, Subject — run that and read the SenderFromDomain value on the single row that comes back. That domain, not fabrikam.example, is your answer."
    ],
    "solutionQuery": "EmailEvents\n| where SenderDisplayName == \"IT Service Desk\" and SenderFromDomain != \"fabrikam.example\"\n| project Timestamp, SenderFromDomain, RecipientEmailAddress, Subject",
    "facts": [
      "fabrikan-support.example",
      "dkoval@fabrikam.example",
      "192.0.2.77"
    ],
    "teaches": [
      "where",
      "compound where (multiple and conditions)",
      "project",
      "domain vs. display-name verification"
    ],
    "mitre": "T1566.002 · Phishing: Spearphishing Link",
    "maxExpectedRows": 1,
    "answer": "fabrikan-support.example",
    "answerAliases": [
      "fabrikan-support"
    ],
    "answerLabel": "What is the real sending domain behind the spoofed \"IT Service Desk\" display name?",
    "disposition": "TP",
    "dispositionWhy": "Grounded in MITRE ATT&CK T1566.002, Phishing: Spearphishing Link (attack.mitre.org/techniques/T1566/002/) — a sub-technique of Phishing (T1566), which sits under the Initial Access tactic: this is how an attacker gets a first foothold, not something that happens after they're already in. In plain language, T1566.002 covers exactly this pattern — an email built to look trustworthy, carrying a link the attacker wants clicked — as opposed to T1566.001, phishing via a malicious attachment (already modeled elsewhere in this range, Incident A). The display-name-vs-domain trick here (fabrikan-support.example impersonating fabrikam.example with a single swapped letter, a classic typosquat) is one of the oldest phishing techniques there is, and still one of the most effective, precisely because most mail clients show the display name prominently and tuck the real domain away where it's easy to skip past. As a Tier 1 analyst, once you've confirmed the sending domain doesn't match, your next steps are: block or quarantine the sender domain at the mail gateway, search EmailEvents for every other recipient who received mail from that same domain (there may be more than one target), and flag dkoval's account for a precautionary password reset plus a quick check of whether the link was actually clicked.",
    "alertId": "alert-p23",
    "severity": "Medium"
  },
  {
    "id": "s49",
    "level": "Beginner",
    "table": "SigninLogs",
    "title": "The account that got locked out overnight",
    "domain": "Identity & Access",
    "discipline": "Fundamentals",
    "prompt": "Overnight, Entra ID Protection generated a pile of failed sign-in alerts for rpatel, a Finance analyst, all from the same external IP address. Nobody on the Finance team was working overnight, and rpatel says they didn't try to log in either. Your job this morning is simple but important: figure out exactly how many failed attempts actually happened, so you can size the incident correctly before you escalate it. This is deliberately a slow, careful mission rather than a fast one — take your time, maybe 30–45 minutes, and think about WHY the number matters, not just how to get it. A couple of failed sign-ins is completely normal; everyone fat-fingers a password sometimes. A sustained double-digit run of failures against one account from one source overnight, with zero successes anywhere in the burst, is a different story entirely — that's someone (or something) systematically trying password after password against a single target, the textbook definition of password guessing. It's worth being precise about what this ISN'T, too: this isn't password SPRAYING, where an attacker tries a few passwords across MANY different accounts to avoid tripping any one account's lockout threshold, and it isn't credential STUFFING, where the attacker already has a real, previously-leaked password and the failed attempts are quickly followed by a successful login. Here, there's no success at all — just failure after failure against rpatel specifically. Filter SigninLogs down to the failed attempts against this account and count them. How many failed sign-ins hit rpatel's account overnight?",
    "cyberSkills": [
      "recognizing single-account password guessing (T1110.001) as distinct from spraying and stuffing",
      "using summarize to size an incident with a single aggregate number"
    ],
    "hints": [
      "Think about what a failed Entra ID sign-in actually looks like in the logs before you write anything. Every failed attempt gets its own row with a specific result code — Microsoft Learn's own AADSTS error-code reference lists 50126 as \"invalid username or password.\" A normal person might generate one or two of those rows in a week. An automated guessing attempt generates a lot of them, in a tight window, from one source. So conceptually: you need to isolate rows from THAT ONE SOURCE IP with THAT failure code, and then just count how many there are. (The source IP is the more reliable pivot here — rpatel's account also shows up with a handful of its own, completely unrelated ordinary sign-ins elsewhere in the log, so filtering on the account alone would mix those in.)",
      "You're working in SigninLogs. Filter IPAddress to the attacker's source IP (203.0.113.66 — the alert already told you it was one IP) and ResultType to \"50126\" (the invalid-credentials code). Once you've narrowed it down to just those rows, use summarize count() to collapse them into a single number instead of scrolling through every row by hand.",
      "SigninLogs | where IPAddress == \"203.0.113.66\" and ResultType == \"50126\" | summarize Failures = count() — run that and read the Failures value. That number is your answer."
    ],
    "solutionQuery": "SigninLogs\n| where IPAddress == \"203.0.113.66\" and ResultType == \"50126\"\n| summarize Failures = count()",
    "facts": [
      "rpatel@fabrikam.example",
      "203.0.113.66",
      "13"
    ],
    "teaches": [
      "where",
      "compound where (multiple and conditions)",
      "summarize count()"
    ],
    "mitre": "T1110.001 · Brute Force: Password Guessing",
    "maxExpectedRows": 1,
    "answer": "13",
    "answerLabel": "How many failed sign-in attempts hit rpatel's account overnight?",
    "disposition": "TP",
    "dispositionWhy": "Grounded in MITRE ATT&CK T1110.001, Brute Force: Password Guessing (attack.mitre.org/techniques/T1110/001/) — a sub-technique of Brute Force (T1110), under the Credential Access tactic: the attacker doesn't have a working password yet, they're trying to obtain one by guessing. The discriminator that matters here is the SHAPE of the failure pattern, and it's worth being explicit about the two look-alikes this range already models elsewhere: T1110.003, Password Spraying, spreads a small number of guesses across MANY different accounts from one source specifically to stay under any single account's lockout threshold (modeled in this range as Incident I); T1110.004, Credential Stuffing, uses already-valid leaked credentials, so the failure burst is quickly followed by a SUCCESS from the same source (modeled as this range's own credential-stuffing mission). This incident is the plain case: one account, one source IP, a double-digit run of failures, and no success anywhere — the attacker genuinely didn't have the right password. As a Tier 1 analyst, your next steps: confirm in Entra ID that the account never actually authenticated successfully during the burst, block or rate-limit the source IP at the identity layer, verify whether MFA is enabled on rpatel's account (it should be, going forward, regardless of outcome), and check whether any other Fabrikam accounts saw failed attempts from that same IP.",
    "alertId": "alert-p24",
    "severity": "Medium"
  },
  {
    "id": "s50",
    "level": "Beginner",
    "table": "DeviceProcessEvents",
    "title": "The invoice that opened a command prompt",
    "domain": "Endpoint Security",
    "discipline": "Fundamentals",
    "prompt": "Microsoft Defender for Endpoint fired a High-severity alert: a command prompt (cmd.exe) was launched by Microsoft Excel on an Engineering laptop. That sentence alone should feel wrong once you sit with it — Excel's whole job is opening spreadsheets and running formulas; it has no legitimate reason to ever launch a command-line interpreter. When that DOES happen, it's almost always because a spreadsheet contained a macro, the user was prompted to \"Enable Content\" to see the real invoice, and the macro used that permission to run something Excel would never run on its own. This mission asks you to slow down and actually trace that relationship in the data rather than just pattern-matching on cmd.exe by itself — plenty of employees open a normal command prompt every day for entirely ordinary reasons, so the filename alone tells you nothing. What matters is WHO launched cmd.exe — Excel, or a person. In DeviceProcessEvents, every process row records not just what ran, but what process started it (the \"initiating process\"). A command prompt a user opened themselves gets started by explorer.exe, the Windows shell. A command prompt a malicious macro launched gets started by EXCEL.EXE instead — and that's the tell. Take your time with this one (30–45 minutes is reasonable) and really look at the InitiatingProcessFileName column before you filter anything. Once you've found the row where Excel, not a person, is the parent process, answer with the account it happened under.",
    "cyberSkills": [
      "recognizing an Office application spawning a command interpreter as user-execution malware (T1204.002)",
      "reading InitiatingProcessFileName to establish a real parent-child process relationship"
    ],
    "hints": [
      "Before touching KQL, think about the concept of a \"parent process.\" Every process on Windows was started BY something — DeviceProcessEvents records that relationship in InitiatingProcessFileName. A user manually opening a command prompt from the Start Menu will always show explorer.exe (the Windows shell) as the parent. A malicious Office macro launching a command prompt behind the scenes will show the Office application itself — EXCEL.EXE — as the parent instead. The filename cmd.exe by itself tells you nothing; who launched it tells you everything.",
      "You're working in DeviceProcessEvents. Filter FileName to \"cmd.exe\" so you're only looking at command-prompt launches, then add one more condition on InitiatingProcessFileName equal to \"EXCEL.EXE\" — that isolates the case where Excel, not a person, did the launching. Project Timestamp, DeviceName, AccountName, and ProcessCommandLine so you can see exactly what happened and under whose account.",
      "DeviceProcessEvents | where FileName == \"cmd.exe\" and InitiatingProcessFileName == \"EXCEL.EXE\" | project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine — run that. The AccountName on the single row that comes back is your answer."
    ],
    "solutionQuery": "DeviceProcessEvents\n| where FileName == \"cmd.exe\" and InitiatingProcessFileName == \"EXCEL.EXE\"\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine",
    "facts": [
      "ssingh",
      "FAB-ENG-08",
      "Invoice_9873.xlsm"
    ],
    "teaches": [
      "where",
      "compound where (multiple and conditions)",
      "project",
      "parent-process (InitiatingProcessFileName) reasoning"
    ],
    "mitre": "T1204.002 · User Execution: Malicious File",
    "maxExpectedRows": 1,
    "answer": "ssingh",
    "answerAliases": [
      "ssingh@fabrikam.example"
    ],
    "answerLabel": "Which account's Excel session spawned a command prompt?",
    "disposition": "TP",
    "dispositionWhy": "Grounded in MITRE ATT&CK T1204.002, User Execution: Malicious File (attack.mitre.org/techniques/T1204/002/), under the Execution tactic: the attacker doesn't need an exploit at all here, only a user willing to open a file and click \"Enable Content.\" A macro-enabled spreadsheet (.xlsm) is a completely normal file type at most companies, which is exactly what makes it an effective lure — the malicious part isn't the file format, it's the macro code embedded inside, which ran with Excel's own permissions the moment content was enabled and used them to launch cmd.exe. This mission is deliberately built on a different device and timestamp than this range's Detection Lab officeToPowerShell ground truth (a separate, earlier incident on a different machine), so don't confuse the two if you go looking at the Detection Lab later — same general pattern (Office spawning a shell it shouldn't), different incident. As a Tier 1 analyst, your next steps once you've confirmed this: isolate the affected device from the network, capture the cmd.exe command line and anything it spawned afterward (a lone `cmd.exe /c whoami` here suggests early-stage reconnaissance, not yet full compromise), pull the original .xlsm attachment for analysis, and check EmailEvents/other endpoints for anyone else who received the same invoice filename.",
    "alertId": "alert-p25",
    "severity": "High"
  },
  {
    "id": "s51",
    "level": "Beginner",
    "table": "DeviceProcessEvents",
    "title": "The pop-up that said the browser was out of date",
    "domain": "Endpoint Security",
    "discipline": "Fundamentals",
    "prompt": "cwoo, one of Fabrikam's executives, mentioned in passing that they saw a pop-up while browsing yesterday claiming their browser was out of date, and clicked through to update it. No email was involved anywhere in this story — cwoo was just browsing an ordinary web page, the same as any other day. That detail matters: this is a real, well-documented attack pattern called a \"drive-by compromise,\" where the entry point is the web page itself, not a phishing email. A legitimate site can get compromised or served a malicious ad, and inject a fake browser-update pop-up designed to talk the visitor into downloading and running an installer themselves — no exploit required, just persuasion. Your job is to find what cwoo actually ran, because a REAL browser updater and a FAKE one look almost identical by filename, and the filename alone won't tell you which is which. Fabrikam's Chrome installations do update themselves automatically and legitimately from time to time — that's normal background activity you should expect to see elsewhere in the data. What separates the real one from what cwoo describes is WHERE it ran from: a legitimate, already-installed updater runs from Chrome's real installation folder under Program Files. Something a user just downloaded and double-clicked themselves runs from their own Downloads folder instead. Take this one slowly (30–45 minutes is reasonable) — the query is short, but the reasoning about install paths versus download paths is the whole point. Find the update-related process that ran from a Downloads folder rather than a real install location, and answer with the account it ran under.",
    "cyberSkills": [
      "recognizing drive-by compromise (T1189) as a web-browsing-only initial access vector",
      "distinguishing a legitimate installed updater from a user-run downloaded impostor by folder path"
    ],
    "hints": [
      "Before writing KQL, think about the difference between software that's ALREADY installed updating itself, and software a user just downloaded and ran for the first time. A real Chrome update runs quietly from wherever Chrome is actually installed — Program Files, in a real Windows environment. Something a user downloaded because a pop-up told them to runs from wherever their browser saved the download — almost always their own Downloads folder. The filename can look exactly the same either way; the folder it's running FROM is the tell.",
      "You're working in DeviceProcessEvents. Filter FileName to contain \"update\" (`has \"update\"` catches update-related filenames without needing the exact name) so you're only looking at updater-style processes, then add one more condition on FolderPath containing \"Downloads\" — that isolates the case where the file ran from a user's download folder instead of a real install path. Project Timestamp, DeviceName, AccountName, FileName, and FolderPath so you can see exactly where it ran from.",
      "DeviceProcessEvents | where FileName has \"update\" and FolderPath has \"Downloads\" | project Timestamp, DeviceName, AccountName, FileName, FolderPath — run that. The AccountName on the single row that comes back is your answer."
    ],
    "solutionQuery": "DeviceProcessEvents\n| where FileName has \"update\" and FolderPath has \"Downloads\"\n| project Timestamp, DeviceName, AccountName, FileName, FolderPath",
    "facts": [
      "cwoo",
      "FAB-EXEC-01",
      "Chrome_Update_Setup.exe"
    ],
    "teaches": [
      "where",
      "has (whole-term text matching)",
      "compound where (multiple and conditions)",
      "project"
    ],
    "mitre": "T1189 · Drive-by Compromise",
    "maxExpectedRows": 1,
    "answer": "cwoo",
    "answerAliases": [
      "cwoo@fabrikam.example"
    ],
    "answerLabel": "Which account ran the fake browser updater downloaded from the pop-up?",
    "disposition": "TP",
    "dispositionWhy": "Grounded in MITRE ATT&CK T1189, Drive-by Compromise (attack.mitre.org/techniques/T1189/), under the Initial Access tactic — and specifically in the real, MITRE-documented SocGholish pattern (Software S1124, attack.mitre.org/software/S1124/, verified directly against MITRE's page): a fake \"your browser is out of date\" pop-up served on an otherwise ordinary web page, which convinces the visitor to download and run a fake updater themselves. No email is involved at any point, which is exactly why this technique sits under Initial Access on its own rather than alongside phishing — the web page itself is the delivery mechanism. This range has no way to distinguish an ordinary web visit from a visit to a page that happened to be serving injected fake-update content at the network-log level, so that part is left as background story rather than an invented, unverifiable row; what IS modeled and graded is the one signal actually left behind afterward — the file cwoo downloaded and ran, sitting in a Downloads folder rather than any real install path. As a Tier 1 analyst on a case involving an executive account, your next steps: treat this as elevated priority given the target, isolate the device, submit the downloaded file for sandbox analysis, check for any process or network activity AFTER the installer ran (none is present in this specific incident, but that's exactly what you'd check for in a real one), and remind cwoo that legitimate browsers update themselves silently — a pop-up demanding action is itself the red flag.",
    "alertId": "alert-p26",
    "severity": "High"
  },
  {
    "id": "s52",
    "level": "Beginner",
    "table": "SigninLogs",
    "title": "The login from an account nobody uses anymore",
    "domain": "Identity & Access",
    "discipline": "Fundamentals",
    "prompt": "HR flagged something odd to the SOC this morning: bsanders, a former Fabrikam Finance employee, left the company months ago — offboarded, badge deactivated, the works. Except this morning, Entra ID shows a completely normal, completely successful sign-in on that account. No failed attempts before it, no risk flags, no MFA challenge that failed, nothing an automated system would ever flag on its own. That's exactly what makes this mission important to sit with slowly: this ISN'T a case of breaking in through some flashy exploit. It's a case of a login that, from a computer's point of view, looks perfectly fine — because the credentials genuinely still work. Somewhere in the offboarding process, this account never actually got disabled, and now something (an old saved session, a forgotten integration, or genuinely someone who shouldn't have access) is using it like nothing happened. This is the simplest query in this entire mission set — you'll find it in well under 30 minutes technically — but don't let that fool you into rushing past the concept. The hard part of this mission isn't the KQL, it's recognizing that hundreds of completely ordinary, successful sign-ins from Fabrikam's actual current employees are sitting in this same table, and none of them are the problem. The one row that matters here doesn't look different from any of the others on paper. It's only wrong because of something the data itself can't tell you: this person doesn't work here anymore. Find the sign-in on bsanders' account and confirm it actually happened.",
    "cyberSkills": [
      "recognizing valid-account misuse (T1078) as a context problem, not a technical anomaly",
      "understanding why offboarding gaps are a real, common root cause of unauthorized access"
    ],
    "hints": [
      "This one starts entirely with context, not KQL. Every automated defense — failed-login detection, impossible-travel alerts, risky-sign-in scoring — is built to catch something that LOOKS wrong technically: a bad password, a weird location, an unusual device. A valid username and password used successfully, from an ordinary-looking location, on an ordinary-looking app, doesn't trip any of those wires, because nothing about the LOGIN ITSELF is wrong. What's wrong is something no sign-in log can know on its own: whether the person behind that account is even supposed to have one anymore. That's why HR telling you bsanders left months ago is the entire alert here — the data will never flag this for you by itself.",
      "You're working in SigninLogs, and this is about as direct as it gets: filter UserPrincipalName to bsanders' address. You don't need ResultType, a threshold, or a summarize — there's exactly one sign-in for this account in the whole dataset, and finding it is the whole task.",
      "SigninLogs | where UserPrincipalName == \"bsanders@fabrikam.example\" | project TimeGenerated, IPAddress, ResultType, ConditionalAccessStatus — run that. The single row that comes back is your answer; note the IP address and the fact that ResultType is \"0\" (success)."
    ],
    "solutionQuery": "SigninLogs\n| where UserPrincipalName == \"bsanders@fabrikam.example\"\n| project TimeGenerated, IPAddress, ResultType, ConditionalAccessStatus",
    "facts": [
      "bsanders@fabrikam.example",
      "20.118.44.201",
      "success"
    ],
    "teaches": [
      "where",
      "project",
      "context-dependent judgment (why 'looks clean' isn't the same as 'is fine')"
    ],
    "mitre": "T1078 · Valid Accounts",
    "maxExpectedRows": 1,
    "answer": "bsanders@fabrikam.example",
    "answerAliases": [
      "bsanders"
    ],
    "answerLabel": "Which departed employee's account signed in successfully?",
    "disposition": "TP",
    "dispositionWhy": "Grounded in MITRE ATT&CK T1078, Valid Accounts (attack.mitre.org/techniques/T1078/) — this is the first mission in this range to teach T1078 on its own, as a first-principles concept, rather than bundled into a larger multi-step chain the way this range's earlier spray-and-persist investigation used T1078.004. It's worth knowing T1078 is ATT&CK's broadest technique by tactic coverage: MITRE maps it to FOUR tactics simultaneously — Initial Access, Persistence, Privilege Escalation, and Stealth (the April 2026-renamed former Defense Evasion) — because one working credential can be used to get in, to stay in, to act with more privilege than intended, and to blend in as completely ordinary traffic, all at once. In plain language: this is exactly why \"valid accounts\" is considered one of the hardest technique categories to detect automatically — there's no malformed request, no failed anything, no signature to match, just a login that authenticates correctly. In this specific case the likely root cause isn't even necessarily an attacker — offboarding gaps (an account that should have been disabled but wasn't) are a genuinely common, well-documented real-world failure mode, and the fix is the same either way. As a Tier 1 analyst, your next steps: immediately disable the account in Entra ID regardless of intent, pull AuditLogs/mailbox-access logs to see what the session actually did, find out why offboarding didn't disable it (a process gap to fix, not just an incident to close), and check whether any other departed employees' accounts are still active.",
    "alertId": "alert-p27",
    "severity": "Medium"
  }
];

  root.KQL_SCENARIOS = SCENARIOS;
})(typeof window !== 'undefined' ? window : (typeof module !== 'undefined' ? module.exports : this));

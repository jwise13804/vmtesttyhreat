// A curated, local-only subset of MITRE ATT&CK Enterprise (top-level
// techniques only, no sub-techniques) for offline coverage tracking. This is
// NOT the full framework and is not synced against attack.mitre.org — it's
// meant to give hunts a consistent, recognizable set of tags without any
// network call. Verify technique IDs against Microsoft/MITRE's own
// documentation before citing them externally.

export interface MitreTactic {
  id: string;
  name: string;
}

export const MITRE_TACTICS: MitreTactic[] = [
  { id: "TA0043", name: "Reconnaissance" },
  { id: "TA0042", name: "Resource Development" },
  { id: "TA0001", name: "Initial Access" },
  { id: "TA0002", name: "Execution" },
  { id: "TA0003", name: "Persistence" },
  { id: "TA0004", name: "Privilege Escalation" },
  { id: "TA0005", name: "Defense Evasion" },
  { id: "TA0006", name: "Credential Access" },
  { id: "TA0007", name: "Discovery" },
  { id: "TA0008", name: "Lateral Movement" },
  { id: "TA0009", name: "Collection" },
  { id: "TA0011", name: "Command and Control" },
  { id: "TA0010", name: "Exfiltration" },
  { id: "TA0040", name: "Impact" },
];

export interface MitreTechnique {
  id: string;
  name: string;
  tactics: string[]; // tactic names, from MITRE_TACTICS
}

interface RawEntry {
  id: string;
  name: string;
  tactic: string;
}

// One row per (technique, tactic) pairing, the way ATT&CK itself maps
// techniques to multiple tactics — merged into MITRE_TECHNIQUES below.
const RAW: RawEntry[] = [
  // Reconnaissance
  { id: "T1595", name: "Active Scanning", tactic: "Reconnaissance" },
  { id: "T1592", name: "Gather Victim Host Information", tactic: "Reconnaissance" },
  { id: "T1589", name: "Gather Victim Identity Information", tactic: "Reconnaissance" },
  { id: "T1590", name: "Gather Victim Network Information", tactic: "Reconnaissance" },
  { id: "T1591", name: "Gather Victim Org Information", tactic: "Reconnaissance" },
  { id: "T1598", name: "Phishing for Information", tactic: "Reconnaissance" },
  { id: "T1597", name: "Search Closed Sources", tactic: "Reconnaissance" },
  { id: "T1596", name: "Search Open Technical Databases", tactic: "Reconnaissance" },
  { id: "T1593", name: "Search Open Websites/Domains", tactic: "Reconnaissance" },
  { id: "T1594", name: "Search Victim-Owned Websites", tactic: "Reconnaissance" },

  // Resource Development
  { id: "T1583", name: "Acquire Infrastructure", tactic: "Resource Development" },
  { id: "T1586", name: "Compromise Accounts", tactic: "Resource Development" },
  { id: "T1584", name: "Compromise Infrastructure", tactic: "Resource Development" },
  { id: "T1587", name: "Develop Capabilities", tactic: "Resource Development" },
  { id: "T1585", name: "Establish Accounts", tactic: "Resource Development" },
  { id: "T1588", name: "Obtain Capabilities", tactic: "Resource Development" },
  { id: "T1608", name: "Stage Capabilities", tactic: "Resource Development" },

  // Initial Access
  { id: "T1189", name: "Drive-by Compromise", tactic: "Initial Access" },
  { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
  { id: "T1133", name: "External Remote Services", tactic: "Initial Access" },
  { id: "T1200", name: "Hardware Additions", tactic: "Initial Access" },
  { id: "T1566", name: "Phishing", tactic: "Initial Access" },
  { id: "T1091", name: "Replication Through Removable Media", tactic: "Initial Access" },
  { id: "T1195", name: "Supply Chain Compromise", tactic: "Initial Access" },
  { id: "T1199", name: "Trusted Relationship", tactic: "Initial Access" },
  { id: "T1078", name: "Valid Accounts", tactic: "Initial Access" },

  // Execution
  { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" },
  { id: "T1609", name: "Container Administration Command", tactic: "Execution" },
  { id: "T1610", name: "Deploy Container", tactic: "Execution" },
  { id: "T1203", name: "Exploitation for Client Execution", tactic: "Execution" },
  { id: "T1559", name: "Inter-Process Communication", tactic: "Execution" },
  { id: "T1106", name: "Native API", tactic: "Execution" },
  { id: "T1053", name: "Scheduled Task/Job", tactic: "Execution" },
  { id: "T1129", name: "Shared Modules", tactic: "Execution" },
  { id: "T1072", name: "Software Deployment Tools", tactic: "Execution" },
  { id: "T1569", name: "System Services", tactic: "Execution" },
  { id: "T1204", name: "User Execution", tactic: "Execution" },
  { id: "T1047", name: "Windows Management Instrumentation", tactic: "Execution" },

  // Persistence
  { id: "T1098", name: "Account Manipulation", tactic: "Persistence" },
  { id: "T1547", name: "Boot or Logon Autostart Execution", tactic: "Persistence" },
  { id: "T1037", name: "Boot or Logon Initialization Scripts", tactic: "Persistence" },
  { id: "T1176", name: "Browser Extensions", tactic: "Persistence" },
  { id: "T1554", name: "Compromise Client Software Binary", tactic: "Persistence" },
  { id: "T1136", name: "Create Account", tactic: "Persistence" },
  { id: "T1543", name: "Create or Modify System Process", tactic: "Persistence" },
  { id: "T1546", name: "Event Triggered Execution", tactic: "Persistence" },
  { id: "T1133", name: "External Remote Services", tactic: "Persistence" },
  { id: "T1574", name: "Hijack Execution Flow", tactic: "Persistence" },
  { id: "T1525", name: "Implant Internal Image", tactic: "Persistence" },
  { id: "T1556", name: "Modify Authentication Process", tactic: "Persistence" },
  { id: "T1137", name: "Office Application Startup", tactic: "Persistence" },
  { id: "T1542", name: "Pre-OS Boot", tactic: "Persistence" },
  { id: "T1053", name: "Scheduled Task/Job", tactic: "Persistence" },
  { id: "T1505", name: "Server Software Component", tactic: "Persistence" },
  { id: "T1205", name: "Traffic Signaling", tactic: "Persistence" },
  { id: "T1078", name: "Valid Accounts", tactic: "Persistence" },

  // Privilege Escalation
  { id: "T1548", name: "Abuse Elevation Control Mechanism", tactic: "Privilege Escalation" },
  { id: "T1134", name: "Access Token Manipulation", tactic: "Privilege Escalation" },
  { id: "T1098", name: "Account Manipulation", tactic: "Privilege Escalation" },
  { id: "T1547", name: "Boot or Logon Autostart Execution", tactic: "Privilege Escalation" },
  { id: "T1037", name: "Boot or Logon Initialization Scripts", tactic: "Privilege Escalation" },
  { id: "T1543", name: "Create or Modify System Process", tactic: "Privilege Escalation" },
  { id: "T1484", name: "Domain Policy Modification", tactic: "Privilege Escalation" },
  { id: "T1611", name: "Escape to Host", tactic: "Privilege Escalation" },
  { id: "T1546", name: "Event Triggered Execution", tactic: "Privilege Escalation" },
  { id: "T1068", name: "Exploitation for Privilege Escalation", tactic: "Privilege Escalation" },
  { id: "T1574", name: "Hijack Execution Flow", tactic: "Privilege Escalation" },
  { id: "T1055", name: "Process Injection", tactic: "Privilege Escalation" },
  { id: "T1053", name: "Scheduled Task/Job", tactic: "Privilege Escalation" },
  { id: "T1078", name: "Valid Accounts", tactic: "Privilege Escalation" },

  // Defense Evasion
  { id: "T1548", name: "Abuse Elevation Control Mechanism", tactic: "Defense Evasion" },
  { id: "T1134", name: "Access Token Manipulation", tactic: "Defense Evasion" },
  { id: "T1197", name: "BITS Jobs", tactic: "Defense Evasion" },
  { id: "T1610", name: "Deploy Container", tactic: "Defense Evasion" },
  { id: "T1140", name: "Deobfuscate/Decode Files or Information", tactic: "Defense Evasion" },
  { id: "T1006", name: "Direct Volume Access", tactic: "Defense Evasion" },
  { id: "T1484", name: "Domain Policy Modification", tactic: "Defense Evasion" },
  { id: "T1480", name: "Execution Guardrails", tactic: "Defense Evasion" },
  { id: "T1211", name: "Exploitation for Defense Evasion", tactic: "Defense Evasion" },
  { id: "T1222", name: "File and Directory Permissions Modification", tactic: "Defense Evasion" },
  { id: "T1564", name: "Hide Artifacts", tactic: "Defense Evasion" },
  { id: "T1574", name: "Hijack Execution Flow", tactic: "Defense Evasion" },
  { id: "T1562", name: "Impair Defenses", tactic: "Defense Evasion" },
  { id: "T1070", name: "Indicator Removal", tactic: "Defense Evasion" },
  { id: "T1202", name: "Indirect Command Execution", tactic: "Defense Evasion" },
  { id: "T1036", name: "Masquerading", tactic: "Defense Evasion" },
  { id: "T1556", name: "Modify Authentication Process", tactic: "Defense Evasion" },
  { id: "T1578", name: "Modify Cloud Compute Infrastructure", tactic: "Defense Evasion" },
  { id: "T1112", name: "Modify Registry", tactic: "Defense Evasion" },
  { id: "T1601", name: "Modify System Image", tactic: "Defense Evasion" },
  { id: "T1599", name: "Network Boundary Bridging", tactic: "Defense Evasion" },
  { id: "T1027", name: "Obfuscated Files or Information", tactic: "Defense Evasion" },
  { id: "T1542", name: "Pre-OS Boot", tactic: "Defense Evasion" },
  { id: "T1055", name: "Process Injection", tactic: "Defense Evasion" },
  { id: "T1620", name: "Reflective Code Loading", tactic: "Defense Evasion" },
  { id: "T1207", name: "Rogue Domain Controller", tactic: "Defense Evasion" },
  { id: "T1014", name: "Rootkit", tactic: "Defense Evasion" },
  { id: "T1218", name: "System Binary Proxy Execution", tactic: "Defense Evasion" },
  { id: "T1216", name: "System Script Proxy Execution", tactic: "Defense Evasion" },
  { id: "T1221", name: "Template Injection", tactic: "Defense Evasion" },
  { id: "T1205", name: "Traffic Signaling", tactic: "Defense Evasion" },
  { id: "T1127", name: "Trusted Developer Utilities Proxy Execution", tactic: "Defense Evasion" },
  { id: "T1550", name: "Use Alternate Authentication Material", tactic: "Defense Evasion" },
  { id: "T1078", name: "Valid Accounts", tactic: "Defense Evasion" },
  { id: "T1497", name: "Virtualization/Sandbox Evasion", tactic: "Defense Evasion" },
  { id: "T1600", name: "Weaken Encryption", tactic: "Defense Evasion" },
  { id: "T1220", name: "XSL Script Processing", tactic: "Defense Evasion" },

  // Credential Access
  { id: "T1557", name: "Adversary-in-the-Middle", tactic: "Credential Access" },
  { id: "T1110", name: "Brute Force", tactic: "Credential Access" },
  { id: "T1555", name: "Credentials from Password Stores", tactic: "Credential Access" },
  { id: "T1212", name: "Exploitation for Credential Access", tactic: "Credential Access" },
  { id: "T1187", name: "Forced Authentication", tactic: "Credential Access" },
  { id: "T1606", name: "Forge Web Credentials", tactic: "Credential Access" },
  { id: "T1056", name: "Input Capture", tactic: "Credential Access" },
  { id: "T1556", name: "Modify Authentication Process", tactic: "Credential Access" },
  { id: "T1111", name: "Multi-Factor Authentication Interception", tactic: "Credential Access" },
  { id: "T1621", name: "Multi-Factor Authentication Request Generation", tactic: "Credential Access" },
  { id: "T1040", name: "Network Sniffing", tactic: "Credential Access" },
  { id: "T1003", name: "OS Credential Dumping", tactic: "Credential Access" },
  { id: "T1528", name: "Steal Application Access Token", tactic: "Credential Access" },
  { id: "T1558", name: "Steal or Forge Kerberos Tickets", tactic: "Credential Access" },
  { id: "T1539", name: "Steal Web Session Cookie", tactic: "Credential Access" },
  { id: "T1552", name: "Unsecured Credentials", tactic: "Credential Access" },

  // Discovery
  { id: "T1087", name: "Account Discovery", tactic: "Discovery" },
  { id: "T1010", name: "Application Window Discovery", tactic: "Discovery" },
  { id: "T1217", name: "Browser Information Discovery", tactic: "Discovery" },
  { id: "T1580", name: "Cloud Infrastructure Discovery", tactic: "Discovery" },
  { id: "T1538", name: "Cloud Service Dashboard", tactic: "Discovery" },
  { id: "T1526", name: "Cloud Service Discovery", tactic: "Discovery" },
  { id: "T1619", name: "Cloud Storage Object Discovery", tactic: "Discovery" },
  { id: "T1482", name: "Domain Trust Discovery", tactic: "Discovery" },
  { id: "T1083", name: "File and Directory Discovery", tactic: "Discovery" },
  { id: "T1046", name: "Network Service Discovery", tactic: "Discovery" },
  { id: "T1135", name: "Network Share Discovery", tactic: "Discovery" },
  { id: "T1040", name: "Network Sniffing", tactic: "Discovery" },
  { id: "T1201", name: "Password Policy Discovery", tactic: "Discovery" },
  { id: "T1120", name: "Peripheral Device Discovery", tactic: "Discovery" },
  { id: "T1069", name: "Permission Groups Discovery", tactic: "Discovery" },
  { id: "T1057", name: "Process Discovery", tactic: "Discovery" },
  { id: "T1012", name: "Query Registry", tactic: "Discovery" },
  { id: "T1018", name: "Remote System Discovery", tactic: "Discovery" },
  { id: "T1518", name: "Software Discovery", tactic: "Discovery" },
  { id: "T1082", name: "System Information Discovery", tactic: "Discovery" },
  { id: "T1614", name: "System Location Discovery", tactic: "Discovery" },
  { id: "T1016", name: "System Network Configuration Discovery", tactic: "Discovery" },
  { id: "T1049", name: "System Network Connections Discovery", tactic: "Discovery" },
  { id: "T1033", name: "System Owner/User Discovery", tactic: "Discovery" },
  { id: "T1007", name: "System Service Discovery", tactic: "Discovery" },
  { id: "T1124", name: "System Time Discovery", tactic: "Discovery" },
  { id: "T1497", name: "Virtualization/Sandbox Evasion", tactic: "Discovery" },

  // Lateral Movement
  { id: "T1210", name: "Exploitation of Remote Services", tactic: "Lateral Movement" },
  { id: "T1534", name: "Internal Spearphishing", tactic: "Lateral Movement" },
  { id: "T1570", name: "Lateral Tool Transfer", tactic: "Lateral Movement" },
  { id: "T1563", name: "Remote Service Session Hijacking", tactic: "Lateral Movement" },
  { id: "T1021", name: "Remote Services", tactic: "Lateral Movement" },
  { id: "T1091", name: "Replication Through Removable Media", tactic: "Lateral Movement" },
  { id: "T1072", name: "Software Deployment Tools", tactic: "Lateral Movement" },
  { id: "T1080", name: "Taint Shared Content", tactic: "Lateral Movement" },
  { id: "T1550", name: "Use Alternate Authentication Material", tactic: "Lateral Movement" },

  // Collection
  { id: "T1557", name: "Adversary-in-the-Middle", tactic: "Collection" },
  { id: "T1560", name: "Archive Collected Data", tactic: "Collection" },
  { id: "T1123", name: "Audio Capture", tactic: "Collection" },
  { id: "T1119", name: "Automated Collection", tactic: "Collection" },
  { id: "T1185", name: "Browser Session Hijacking", tactic: "Collection" },
  { id: "T1115", name: "Clipboard Data", tactic: "Collection" },
  { id: "T1530", name: "Data from Cloud Storage", tactic: "Collection" },
  { id: "T1602", name: "Data from Configuration Repository", tactic: "Collection" },
  { id: "T1213", name: "Data from Information Repositories", tactic: "Collection" },
  { id: "T1005", name: "Data from Local System", tactic: "Collection" },
  { id: "T1039", name: "Data from Network Shared Drive", tactic: "Collection" },
  { id: "T1025", name: "Data from Removable Media", tactic: "Collection" },
  { id: "T1074", name: "Data Staged", tactic: "Collection" },
  { id: "T1114", name: "Email Collection", tactic: "Collection" },
  { id: "T1056", name: "Input Capture", tactic: "Collection" },
  { id: "T1113", name: "Screen Capture", tactic: "Collection" },
  { id: "T1125", name: "Video Capture", tactic: "Collection" },

  // Command and Control
  { id: "T1071", name: "Application Layer Protocol", tactic: "Command and Control" },
  { id: "T1092", name: "Communication Through Removable Media", tactic: "Command and Control" },
  { id: "T1132", name: "Data Encoding", tactic: "Command and Control" },
  { id: "T1001", name: "Data Obfuscation", tactic: "Command and Control" },
  { id: "T1568", name: "Dynamic Resolution", tactic: "Command and Control" },
  { id: "T1573", name: "Encrypted Channel", tactic: "Command and Control" },
  { id: "T1008", name: "Fallback Channels", tactic: "Command and Control" },
  { id: "T1105", name: "Ingress Tool Transfer", tactic: "Command and Control" },
  { id: "T1104", name: "Multi-Stage Channels", tactic: "Command and Control" },
  { id: "T1095", name: "Non-Application Layer Protocol", tactic: "Command and Control" },
  { id: "T1571", name: "Non-Standard Port", tactic: "Command and Control" },
  { id: "T1572", name: "Protocol Tunneling", tactic: "Command and Control" },
  { id: "T1090", name: "Proxy", tactic: "Command and Control" },
  { id: "T1219", name: "Remote Access Software", tactic: "Command and Control" },
  { id: "T1205", name: "Traffic Signaling", tactic: "Command and Control" },
  { id: "T1102", name: "Web Service", tactic: "Command and Control" },

  // Exfiltration
  { id: "T1020", name: "Automated Exfiltration", tactic: "Exfiltration" },
  { id: "T1030", name: "Data Transfer Size Limits", tactic: "Exfiltration" },
  { id: "T1048", name: "Exfiltration Over Alternative Protocol", tactic: "Exfiltration" },
  { id: "T1041", name: "Exfiltration Over C2 Channel", tactic: "Exfiltration" },
  { id: "T1011", name: "Exfiltration Over Other Network Medium", tactic: "Exfiltration" },
  { id: "T1052", name: "Exfiltration Over Physical Medium", tactic: "Exfiltration" },
  { id: "T1567", name: "Exfiltration Over Web Service", tactic: "Exfiltration" },
  { id: "T1029", name: "Scheduled Transfer", tactic: "Exfiltration" },
  { id: "T1537", name: "Transfer Data to Cloud Account", tactic: "Exfiltration" },

  // Impact
  { id: "T1531", name: "Account Access Removal", tactic: "Impact" },
  { id: "T1485", name: "Data Destruction", tactic: "Impact" },
  { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact" },
  { id: "T1565", name: "Data Manipulation", tactic: "Impact" },
  { id: "T1491", name: "Defacement", tactic: "Impact" },
  { id: "T1561", name: "Disk Wipe", tactic: "Impact" },
  { id: "T1499", name: "Endpoint Denial of Service", tactic: "Impact" },
  { id: "T1495", name: "Firmware Corruption", tactic: "Impact" },
  { id: "T1490", name: "Inhibit System Recovery", tactic: "Impact" },
  { id: "T1498", name: "Network Denial of Service", tactic: "Impact" },
  { id: "T1496", name: "Resource Hijacking", tactic: "Impact" },
  { id: "T1489", name: "Service Stop", tactic: "Impact" },
  { id: "T1529", name: "System Shutdown/Reboot", tactic: "Impact" },
];

function buildTechniques(): MitreTechnique[] {
  const byId = new Map<string, MitreTechnique>();
  for (const row of RAW) {
    const existing = byId.get(row.id);
    if (existing) {
      if (!existing.tactics.includes(row.tactic)) existing.tactics.push(row.tactic);
    } else {
      byId.set(row.id, { id: row.id, name: row.name, tactics: [row.tactic] });
    }
  }
  return Array.from(byId.values()).sort((a, b) => a.id.localeCompare(b.id));
}

export const MITRE_TECHNIQUES: MitreTechnique[] = buildTechniques();

export const MITRE_TECHNIQUE_BY_ID: Record<string, MitreTechnique> = Object.fromEntries(
  MITRE_TECHNIQUES.map((t) => [t.id, t]),
);

export function techniquesForTactic(tacticName: string): MitreTechnique[] {
  return MITRE_TECHNIQUES.filter((t) => t.tactics.includes(tacticName));
}

// -----------------------------------------------------------------------
// Sub-techniques — a much smaller curated set (only the parents most likely
// to come up in practice, generally the ones the default playbooks already
// reference), not full coverage of every parent technique's children.
// -----------------------------------------------------------------------
export interface MitreSubTechnique {
  id: string; // e.g. "T1059.001"
  name: string;
  parentId: string; // e.g. "T1059"
}

export const MITRE_SUBTECHNIQUES: MitreSubTechnique[] = [
  // T1059 Command and Scripting Interpreter
  { id: "T1059.001", name: "PowerShell", parentId: "T1059" },
  { id: "T1059.003", name: "Windows Command Shell", parentId: "T1059" },
  { id: "T1059.004", name: "Unix Shell", parentId: "T1059" },
  { id: "T1059.006", name: "Python", parentId: "T1059" },
  { id: "T1059.007", name: "JavaScript", parentId: "T1059" },

  // T1053 Scheduled Task/Job
  { id: "T1053.003", name: "Cron", parentId: "T1053" },
  { id: "T1053.005", name: "Scheduled Task", parentId: "T1053" },

  // T1003 OS Credential Dumping
  { id: "T1003.001", name: "LSASS Memory", parentId: "T1003" },
  { id: "T1003.002", name: "Security Account Manager", parentId: "T1003" },
  { id: "T1003.003", name: "NTDS", parentId: "T1003" },
  { id: "T1003.004", name: "LSA Secrets", parentId: "T1003" },
  { id: "T1003.006", name: "DCSync", parentId: "T1003" },

  // T1078 Valid Accounts
  { id: "T1078.001", name: "Default Accounts", parentId: "T1078" },
  { id: "T1078.002", name: "Domain Accounts", parentId: "T1078" },
  { id: "T1078.003", name: "Local Accounts", parentId: "T1078" },
  { id: "T1078.004", name: "Cloud Accounts", parentId: "T1078" },

  // T1021 Remote Services
  { id: "T1021.001", name: "Remote Desktop Protocol", parentId: "T1021" },
  { id: "T1021.002", name: "SMB/Windows Admin Shares", parentId: "T1021" },
  { id: "T1021.004", name: "SSH", parentId: "T1021" },
  { id: "T1021.006", name: "Windows Remote Management", parentId: "T1021" },

  // T1071 Application Layer Protocol
  { id: "T1071.001", name: "Web Protocols", parentId: "T1071" },
  { id: "T1071.002", name: "File Transfer Protocols", parentId: "T1071" },
  { id: "T1071.004", name: "DNS", parentId: "T1071" },

  // T1027 Obfuscated Files or Information
  { id: "T1027.001", name: "Binary Padding", parentId: "T1027" },
  { id: "T1027.002", name: "Software Packing", parentId: "T1027" },
  { id: "T1027.003", name: "Steganography", parentId: "T1027" },

  // T1036 Masquerading
  { id: "T1036.003", name: "Rename System Utilities", parentId: "T1036" },
  { id: "T1036.005", name: "Match Legitimate Name or Location", parentId: "T1036" },

  // T1055 Process Injection
  { id: "T1055.001", name: "Dynamic-link Library Injection", parentId: "T1055" },
  { id: "T1055.002", name: "Portable Executable Injection", parentId: "T1055" },

  // T1547 Boot or Logon Autostart Execution
  { id: "T1547.001", name: "Registry Run Keys / Startup Folder", parentId: "T1547" },

  // T1562 Impair Defenses
  { id: "T1562.001", name: "Disable or Modify Tools", parentId: "T1562" },
  { id: "T1562.004", name: "Disable or Modify System Firewall", parentId: "T1562" },

  // T1070 Indicator Removal
  { id: "T1070.001", name: "Clear Windows Event Logs", parentId: "T1070" },
  { id: "T1070.004", name: "File Deletion", parentId: "T1070" },

  // T1204 User Execution
  { id: "T1204.001", name: "Malicious Link", parentId: "T1204" },
  { id: "T1204.002", name: "Malicious File", parentId: "T1204" },
];

export const MITRE_SUBTECHNIQUE_BY_ID: Record<string, MitreSubTechnique> = Object.fromEntries(
  MITRE_SUBTECHNIQUES.map((t) => [t.id, t]),
);

export function subTechniquesForParent(parentId: string): MitreSubTechnique[] {
  return MITRE_SUBTECHNIQUES.filter((t) => t.parentId === parentId);
}

/** Looks up either a top-level technique or a sub-technique by id. */
export function mitreEntryById(id: string): { id: string; name: string } | undefined {
  return MITRE_TECHNIQUE_BY_ID[id] ?? MITRE_SUBTECHNIQUE_BY_ID[id];
}

/** True if `tag` is `parentId` itself, or one of its sub-technique ids (e.g. "T1059.001" for parent "T1059"). */
export function tagCoversTechnique(tag: string, parentId: string): boolean {
  return tag === parentId || tag.startsWith(`${parentId}.`);
}

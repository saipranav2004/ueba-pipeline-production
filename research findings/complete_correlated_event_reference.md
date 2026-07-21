Looking at what I provided, I missed several important correlations. Let me do a thorough audit.  
  
---  
  
# What I Missed — Honest Gap Analysis  
  
## Gaps in My Previous Response  
  
```  
WHAT I MISSED:  
─────────────────────────────────────────────────────────────  
1. Cross-event correlations (how events chain together)  
2. Windows Security Event IDs paired with Sysmon Events  
3. Several attack techniques that span multiple event IDs  
4. Field-level correlations across events (ProcessGuid linking)  
5. Specific attack chains that require 3+ events together  
6. Several MITRE techniques I did not map  
7. Behavioral baselines that need multiple event types combined  
```  
  
---  
  
# Complete Correlated Event Reference  
  
---  
  
## Correlation 1: Full Credential Dumping Chain  
  
### Events Involved: Sysmon 1 + 10 + 11 + 9 + Windows 4656 + 4663  
  
```  
COMPLETE ATTACK CHAIN — LSASS Credential Dumping:  
  
STEP 1: Tool arrives on disk  
────────────────────────────────────────────────────────────────  
Sysmon Event 29 (FileExecutableDetected):  
  Image          = powershell.exe          ← downloader  
  TargetFilename = C:\Temp\procdump.exe   ← tool dropped  
  Hashes         = SHA256:<hash>  
  
Sysmon Event 11 (FileCreate):  
  Image          = powershell.exe  
  TargetFilename = C:\Temp\procdump.exe  
  
STEP 2: Tool executes  
────────────────────────────────────────────────────────────────  
Sysmon Event 1 (Process Create):  
  Image          = C:\Temp\procdump.exe  
  CommandLine    = procdump.exe -ma lsass.exe lsass.dmp  
  ParentImage    = C:\Windows\System32\cmd.exe  
  User           = CORP\attacker  
  IntegrityLevel = High                   ← needs elevation  
  
STEP 3: Process opens LSASS handle  
────────────────────────────────────────────────────────────────  
Sysmon Event 10 (ProcessAccess):  
  SourceImage    = C:\Temp\procdump.exe  
  TargetImage    = C:\Windows\System32\lsass.exe  
  GrantedAccess  = 0x1FFFFF               ← full access  
  CallTrace      = dbghelp.dll|...        ← dump library  
  
Windows Security Event 4656 (Handle requested):  
  ObjectName     = \Device\HarddiskVolume\Windows\System32\lsass.exe  
  AccessMask     = 0x1FFFFF  
  SubjectUserName = attacker  
  
Windows Security Event 4663 (Handle used):  
  ObjectName     = lsass.exe  
  AccessMask     = READ_CONTROL  
  
STEP 4: Dump file written to disk  
────────────────────────────────────────────────────────────────  
Sysmon Event 11 (FileCreate):  
  Image          = C:\Temp\procdump.exe  
  TargetFilename = C:\Temp\lsass.dmp      ← dump file created  
  User           = CORP\attacker  
  
STEP 5: Raw disk access (alternative method — comsvcs)  
────────────────────────────────────────────────────────────────  
Sysmon Event 9 (RawAccessRead):  
  Image          = C:\Windows\System32\rundll32.exe  
  Device         = \\.\PhysicalDrive0  
  
CORRELATION KEY:  
  ProcessGuid links Event 1 → Event 10 → Event 11  
  Same ProcessGuid = same process across all three events  
  Timeline: Event 1 (birth) → Event 10 (LSASS access) → Event 11 (dump written)  
```  
  
### Fields That Must Be Correlated  
  
```  
┌───────────────────────────────────────────────────────────────────────┐  
│  Field          │  Event 1        │  Event 10       │  Event 11       │  
├───────────────────────────────────────────────────────────────────────┤  
│  ProcessGuid    │  Created here   │  Same GUID      │  Same GUID      │  
│                 │  (the link)     │  (same process) │  (same process) │  
├───────────────────────────────────────────────────────────────────────┤  
│  Image          │  procdump.exe   │  SourceImage    │  Image          │  
│                 │  (who it is)    │  (who opens)    │  (who writes)   │  
├───────────────────────────────────────────────────────────────────────┤  
│  User           │  CORP\attacker  │  SourceUser     │  User           │  
│                 │  (identity)     │  (same account) │  (same account) │  
├───────────────────────────────────────────────────────────────────────┤  
│  UtcTime        │  14:01:00       │  14:01:02       │  14:01:05       │  
│                 │  (timeline)     │  (2s after)     │  (5s after)     │  
└───────────────────────────────────────────────────────────────────────┘  
```  
  
### What I Missed Previously  
  
```  
MISSED:  
- Windows Security Event 4656 (object handle request) correlation  
- Windows Security Event 4663 (object handle use) correlation    
- The ProcessGuid chain linking all three Sysmon events  
- Event 9 (RawAccessRead) as alternative LSASS dump method  
- Event 29 (FileExecutableDetected) as the precursor event  
- IntegrityLevel field in Event 1 as indicator (needs High to dump LSASS)  
- CallTrace field analysis in Event 10  
- The dump file creation via Event 11 as post-dump confirmation  
```  
  
---  
  
## Correlation 2: Full Lateral Movement Chain  
  
### Events Involved: Sysmon 1 + 3 + 8 + Windows 4624 + 4648 + 4672 + 7045  
  
```  
COMPLETE ATTACK CHAIN — PsExec Lateral Movement:  
  
STEP 1: Attacker initiates connection  
────────────────────────────────────────────────────────────────  
Sysmon Event 1 on SOURCE host:  
  Image       = C:\Tools\PsExec.exe  
  CommandLine = psexec \\TARGET01 -u admin -p pass cmd.exe  
  User        = CORP\attacker  
  ParentImage = cmd.exe  
  
Sysmon Event 3 on SOURCE host:  
  Image            = C:\Tools\PsExec.exe  
  DestinationIp    = 10.0.0.50          ← TARGET01  
  DestinationPort  = 445                ← SMB  
  Initiated        = true  
  
Windows Security Event 4648 on SOURCE host (explicit creds used):  
  SubjectUserName  = attacker  
  TargetUserName   = admin  
  TargetServerName = TARGET01  
  ProcessName      = PsExec.exe  
  ← explicit credential use detected here  
  
STEP 2: Service installed on target  
────────────────────────────────────────────────────────────────  
Windows Security Event 7045 on TARGET host (new service):  
  ServiceName    = PSEXESVC  
  ServiceFileName = %SystemRoot%\PSEXESVC.exe  
  ServiceType    = User Mode Service  
  StartType      = Demand Start  
  AccountName    = LocalSystem  
  
Sysmon Event 11 on TARGET host:  
  Image          = services.exe  
  TargetFilename = C:\Windows\PSEXESVC.exe   ← binary dropped  
  
STEP 3: Named pipe created  
────────────────────────────────────────────────────────────────  
Sysmon Event 17 on TARGET host:  
  PipeName = \PSEXESVC                ← known PsExec pipe  
  Image    = C:\Windows\PSEXESVC.exe  
  
STEP 4: Authentication on target  
────────────────────────────────────────────────────────────────  
Windows Security Event 4624 on TARGET host:  
  LogonType       = 3                 ← network logon  
  TargetUserName  = admin  
  IpAddress       = 10.0.0.40         ← source (attacker's machine)  
  AuthPackage     = NTLM or Kerberos  
  LogonProcessName = NtLmSsp  
  
Windows Security Event 4672 on TARGET host (special privileges):  
  SubjectUserName = admin  
  PrivilegeList   = SeDebugPrivilege, SeTcbPrivilege, SeBackupPrivilege  
  ← privileged logon happened here  
  
STEP 5: Command executes on target  
────────────────────────────────────────────────────────────────  
Sysmon Event 1 on TARGET host:  
  Image       = C:\Windows\System32\cmd.exe  
  ParentImage = C:\Windows\PSEXESVC.exe    ← spawned by PsExec service  
  User        = NT AUTHORITY\SYSTEM        ← running as SYSTEM!  
  CommandLine = cmd.exe  
  
STEP 6: Pipe connected  
────────────────────────────────────────────────────────────────  
Sysmon Event 18 on TARGET host:  
  PipeName = \PSEXESVC  
  Image    = cmd.exe  
  User     = NT AUTHORITY\SYSTEM  
```  
  
### The Full Correlation Map  
  
```  
SOURCE HOST                              TARGET HOST  
────────────────                         ────────────────  
Sysmon 1: PsExec launch                   
  ProcessGuid: {A}                         
                │                          
Sysmon 3: SMB connection ──────────────→ Windows 4624: Network logon  
  DestPort: 445                            LogonType: 3  
  DestIp: TARGET01                         IpAddress: SOURCE  
                │                          │  
Windows 4648: Explicit cred              Windows 4672: Special privs  
  TargetUser: admin                        PrivilegeList: SeDebug...  
                                           │  
                                         Windows 7045: Service installed  
                                           ServiceName: PSEXESVC  
                                           │  
                                         Sysmon 11: File dropped  
                                           PSEXESVC.exe  
                                           │  
                                         Sysmon 17: Pipe created  
                                           PipeName: \PSEXESVC  
                                           │  
                                         Sysmon 1: cmd.exe spawned  
                                           ParentImage: PSEXESVC.exe  
                                           User: SYSTEM  
                                           │  
                                         Sysmon 18: Pipe connected  
                                           cmd.exe → \PSEXESVC  
```  
  
### What I Missed Previously  
  
```  
MISSED:  
- Windows 4648 (explicit credential logon) — key field for lateral movement  
- Windows 4672 (special privilege logon) — confirms privileged access  
- Windows 7045 (new service installed) — PsExec service installation  
- The cross-host correlation requirement (source AND target events together)  
- PSEXESVC.exe ParentImage relationship in Sysmon Event 1 on target  
- The pipe chain: Event 17 (create) → Event 18 (connect) → Event 1 (cmd spawned)  
- LogonProcessName field in Event 4624 distinguishing NTLM vs Kerberos  
```  
  
---  
  
## Correlation 3: Full Process Injection Chain  
  
### Events Involved: Sysmon 1 + 8 + 10 + 7 + 3 + Windows 4688  
  
```  
COMPLETE ATTACK CHAIN — Process Injection:  
  
STEP 1: Injector process created  
────────────────────────────────────────────────────────────────  
Sysmon Event 1:  
  Image          = C:\Temp\injector.exe  
  ParentImage    = C:\Windows\System32\cmd.exe  
  CommandLine    = injector.exe svchost  
  User           = CORP\attacker  
  IntegrityLevel = High  
  
Windows 4688 (Process Create — if Sysmon not deployed):  
  NewProcessName  = C:\Temp\injector.exe  
  ParentProcess   = cmd.exe  
  TokenElevationType = TokenElevationTypeFull  ← elevated token  
  
STEP 2: Injector opens handle to target process  
────────────────────────────────────────────────────────────────  
Sysmon Event 10:  
  SourceImage    = C:\Temp\injector.exe  
  TargetImage    = C:\Windows\System32\svchost.exe  
  GrantedAccess  = 0x1FFFFF  
  SourceUser     = CORP\attacker  
  TargetUser     = NT AUTHORITY\SYSTEM  
  
STEP 3: Remote thread created in target  
────────────────────────────────────────────────────────────────  
Sysmon Event 8:  
  SourceImage    = C:\Temp\injector.exe  
  TargetImage    = C:\Windows\System32\svchost.exe  
  StartModule    = (empty)              ← shellcode, not a DLL  
  StartFunction  = (empty)  
  SourceUser     = CORP\attacker  
  TargetUser     = NT AUTHORITY\SYSTEM  
  
STEP 4: Malicious DLL loaded into target (DLL injection variant)  
────────────────────────────────────────────────────────────────  
Sysmon Event 7:  
  Image          = C:\Windows\System32\svchost.exe  ← victim process  
  ImageLoaded    = C:\Temp\evil.dll                 ← injected DLL  
  Signed         = false  
  ProcessGuid    = {svchost's GUID}  
  
STEP 5: Injected code makes network connection  
────────────────────────────────────────────────────────────────  
Sysmon Event 3:  
  Image          = C:\Windows\System32\svchost.exe  ← but it's injected!  
  DestinationIp  = 185.220.100.5         ← C2 server  
  DestinationPort = 443  
  User           = NT AUTHORITY\SYSTEM   ← running as SYSTEM  
  
CRITICAL CORRELATION:  
  svchost.exe (ProcessGuid: {B}) → Event 7 (DLL loaded)  
                                 → Event 3 (network connection to C2)  
    
  The ProcessGuid of svchost LINKS:  
    Event 7: which DLL was injected INTO svchost  
    Event 3: which network connections svchost made AFTER injection  
      
  Without this link: Event 3 looks like legitimate svchost traffic  
  With this link: svchost loaded evil.dll 2 seconds before the C2 connection  
```  
  
### What I Missed Previously  
  
```  
MISSED:  
- Event 7 (DLL load) as post-injection evidence linked via ProcessGuid  
- Event 3 (network) from the INJECTED process as C2 indicator  
- The ProcessGuid chain linking injection events to subsequent behavior  
- Windows 4688 TokenElevationType field correlation  
- SourceUser vs TargetUser cross-account mismatch significance  
- The timeline correlation (Event 8 → Event 7 → Event 3 within seconds)  
- Event 10 as precursor to Event 8 (handle opened BEFORE thread created)  
```  
  
---  
  
## Correlation 4: Full WMI Attack Chain  
  
### Events Involved: Sysmon 1 + 3 + 19 + 20 + 21 + Windows 4688 + 4624 + 4648  
  
```  
COMPLETE ATTACK CHAIN — WMI Remote Execution + Persistence:  
  
PHASE A: Remote WMI Execution (Lateral Movement)  
────────────────────────────────────────────────────────────────  
  
STEP 1: WMI command sent from attacker  
Sysmon Event 1 on SOURCE:  
  Image       = C:\Windows\System32\wmic.exe  
  CommandLine = wmic /node:TARGET01 process call create "powershell -enc <payload>"  
  User        = CORP\attacker  
  
Sysmon Event 3 on SOURCE:  
  Image           = C:\Windows\System32\wmic.exe  
  DestinationIp   = 10.0.0.50  
  DestinationPort = 135           ← WMI uses RPC/DCOM on 135  
  Initiated       = true  
  
Windows 4648 on SOURCE (explicit credential use):  
  SubjectUserName  = attacker  
  TargetUserName   = admin  
  TargetServerName = TARGET01  
  
STEP 2: WMI execution on target  
Windows 4624 on TARGET:  
  LogonType       = 3  
  TargetUserName  = admin  
  IpAddress       = SOURCE_IP  
  LogonProcessName = NtLmSsp  
  
Sysmon Event 1 on TARGET:  
  Image       = C:\Windows\System32\WmiPrvSE.exe  ← WMI provider host  
  ParentImage = C:\Windows\System32\svchost.exe  
  
Sysmon Event 1 on TARGET (the payload):  
  Image       = C:\Windows\System32\powershell.exe  
  ParentImage = C:\Windows\System32\WmiPrvSE.exe  ← WMI spawned this!  
  CommandLine = powershell -enc <payload>  
  User        = NT AUTHORITY\NETWORK SERVICE  
  
KEY INDICATOR:  
  WmiPrvSE.exe as ParentImage = WMI-spawned process  
  Anything spawned by WmiPrvSE.exe is WMI execution  
  Especially: cmd.exe, powershell.exe, cscript.exe  
  
PHASE B: WMI Persistence Installation  
────────────────────────────────────────────────────────────────  
  
Sysmon Event 19 (Filter):  
  Name  = "WindowsUpdateCheck"  
  Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60  
           WHERE TargetInstance ISA 'Win32_LocalTime'  
           AND TargetInstance.Minutes = 0"  
  User  = CORP\attacker  
  
Sysmon Event 20 (Consumer):  
  Name        = "WindowsUpdater"  
  Type        = CommandLine  
  Destination = "powershell.exe -NoP -W Hidden -Enc <c2_payload>"  
  User        = CORP\attacker  
  
Sysmon Event 21 (Binding):  
  Consumer = "WindowsUpdater"  
  Filter   = "WindowsUpdateCheck"  
  User     = CORP\attacker  
  
PHASE C: WMI Persistence Triggers (1 hour later)  
────────────────────────────────────────────────────────────────  
  
Sysmon Event 1 (Subscription fires):  
  Image       = C:\Windows\System32\powershell.exe  
  ParentImage = C:\Windows\System32\WmiPrvSE.exe  ← WMI subscription triggered  
  CommandLine = powershell.exe -NoP -W Hidden -Enc <c2_payload>  
  User        = NT AUTHORITY\SYSTEM               ← subscription runs as SYSTEM  
  
Sysmon Event 3 (C2 connection from subscription):  
  Image           = powershell.exe  
  DestinationIp   = 185.220.100.5  
  DestinationPort = 443  
  User            = NT AUTHORITY\SYSTEM  
  
CORRELATION:  
  Events 19+20+21 (installation) → Event 1 (WmiPrvSE spawns payload) → Event 3 (C2)  
  The installation and execution are linked by:  
    - Same Consumer name in Event 21 and the triggered Event 1  
    - WmiPrvSE.exe as parent in triggered Event 1  
    - Same payload command in Event 20 Destination field and Event 1 CommandLine  
```  
  
### What I Missed Previously  
  
```  
MISSED:  
- WmiPrvSE.exe as ParentImage = the key WMI execution indicator in Event 1  
- RPC port 135 in Event 3 as WMI lateral movement via network  
- Windows 4648 correlation for WMI explicit credential use  
- The Phase C: how the persistence TRIGGERS and what events it generates  
- Linking Event 20 Destination field to Event 1 CommandLine (same payload)  
- NETWORK SERVICE vs SYSTEM account difference for WMI execution types  
- Event 3 from the WMI-triggered process as C2 confirmation  
```  
  
---  
  
## Correlation 5: Full Golden/Silver Ticket Chain  
  
### Events Involved: Sysmon 1 + 3 + Windows 4624 + 4625 + 4768 + 4769 + 4770 + 4776 + 4672  
  
```  
COMPLETE ATTACK CHAIN — Mimikatz + Golden Ticket:  
  
STEP 1: Mimikatz runs (DCSync to get KRBTGT)  
────────────────────────────────────────────────────────────────  
Sysmon Event 1:  
  Image            = C:\Temp\mimikatz.exe  
  OriginalFileName = mimikatz.exe          ← even if renamed  
  CommandLine      = mimikatz.exe "lsadump::dcsync /user:krbtgt" exit  
  User             = CORP\da_admin  
  Hashes           = SHA256:<mimikatz_hash>  
  
Windows 4662 (Directory Service Access):  
  SubjectUserName  = da_admin             ← the actor (NOT machine account)  
  ObjectType       = domainDNS  
  Properties       = {1131f6aa-...}       ← replication GUID  
  AccessMask       = 0x100  
  
STEP 2: Golden ticket forged (offline — no events)  
────────────────────────────────────────────────────────────────  
  [No Windows events during offline forgery]  
  [Attacker uses KRBTGT hash to sign fake TGT]  
  
STEP 3: Ticket injected into session  
────────────────────────────────────────────────────────────────  
Sysmon Event 1:  
  Image       = C:\Temp\mimikatz.exe  
  CommandLine = mimikatz.exe "kerberos::ptt ticket.kirbi" exit  
  
  [No Windows auth events for injection itself]  
  
STEP 4: Golden ticket used — access DC  
────────────────────────────────────────────────────────────────  
Windows 4624 on DC:  
  TargetUserName   = Administrator        ← impersonated account  
  LogonType        = 3  
  AuthPackage      = Kerberos  
  IpAddress        = 10.0.0.99            ← attacker's machine (novel source!)  
  LogonGuid        = {GUID}  
  
Windows 4672 on DC (Special Privilege Logon):  
  SubjectUserName  = Administrator  
  PrivilegeList    = SeDebugPrivilege, SeTcbPrivilege...  
  
CRITICAL ABSENCE — What's MISSING for Golden Ticket:  
  Windows 4768: ABSENT                    ← No TGT request (ticket was forged)  
    
  Normal flow:  4768 (TGT) → 4769 (TGS) → 4624 (logon)  
  Golden Ticket: [nothing] → 4769 (TGS requested with forged TGT) → 4624 (logon)  
    
  The 4769 (TGS request) IS present because attacker uses forged TGT to get TGS  
  But no preceding 4768 = Golden Ticket indicator  
  
Windows 4769 on DC (Service Ticket Request):  
  TargetUserName   = Administrator@CORP.LOCAL  
  ServiceName      = krbtgt              ← requesting service ticket using forged TGT  
  TicketEncType    = 0x17 (RC4)          ← forged tickets often use RC4  
  
STEP 5: Accessing file server with golden ticket  
────────────────────────────────────────────────────────────────  
Windows 4769 on DC (TGS for file server):  
  TargetUserName   = Administrator@CORP.LOCAL  
  ServiceName      = CIFS/fileserver01  
  IpAddress        = 10.0.0.99           ← attacker machine  
  
Sysmon Event 3 on ATTACKER machine:  
  Image            = C:\Windows\System32\cmd.exe  
  DestinationIp    = 192.168.1.20        ← file server  
  DestinationPort  = 445  
  
Windows 4624 on FILE SERVER:  
  TargetUserName   = Administrator  
  LogonType        = 3  
  AuthPackage      = Kerberos  
  IpAddress        = 10.0.0.99           ← same novel source throughout  
  
SILVER TICKET — DIFFERENCE:  
  Windows 4624 on TARGET SERVICE:  
    TargetUserName = Administrator  
    IpAddress      = attacker_IP  
    AuthPackage    = Kerberos  
    
  ABSENT on DC: No 4769 for this service (ticket was forged directly)  
  Silver Ticket skips DC entirely for service ticket  
  Only the 4624 on the service exists  
```  
  
### What I Missed Previously  
  
```  
MISSED:  
- Windows 4662 (Directory Access) linking to Sysmon Event 1 (Mimikatz)  
- Windows 4672 (Special Privilege) as post-Golden-Ticket confirmation  
- Windows 4769 presence WITH absence of 4768 as Golden Ticket pattern  
- The TicketEncType=0x17 in 4769 for forged tickets  
- Windows 4770 (TGT renewal) — abnormal renewal patterns  
- Sysmon Event 3 from attacker machine linking network to auth events  
- LogonGuid field in 4624 for session correlation  
- The Silver Ticket absence pattern — no 4769 on DC at all  
- Cross-host correlation requirement for complete picture  
```  
  
---  
  
## Correlation 6: Full Pass-the-Hash Chain  
  
### Events Involved: Sysmon 1 + 3 + 10 + Windows 4624 + 4625 + 4648 + 4672 + 4776  
  
```  
COMPLETE ATTACK CHAIN — Pass-the-Hash:  
  
STEP 1: Hash obtained via LSASS dump  
────────────────────────────────────────────────────────────────  
[See Correlation 1 — LSASS dump chain]  
Result: attacker has NTLM hash of da_admin  
  
STEP 2: PtH tool runs  
────────────────────────────────────────────────────────────────  
Sysmon Event 1:  
  Image       = C:\Temp\mimikatz.exe  
  CommandLine = sekurlsa::pth /user:da_admin /ntlm:<hash> /run:cmd.exe  
  User        = CORP\lowpriv            ← started as low-priv  
    
Sysmon Event 1 (spawned cmd.exe with stolen identity):  
  Image        = C:\Windows\System32\cmd.exe  
  ParentImage  = C:\Temp\mimikatz.exe  
  User         = CORP\da_admin          ← now running as da_admin!  
  LogonId      = 0x3e7                  ← new logon session  
  
STEP 3: NTLM authentication attempt  
────────────────────────────────────────────────────────────────  
Windows 4776 on DC (NTLM credential validation):  
  TargetUserName   = da_admin  
  Workstation      = ATTACKER-PC        ← attacking machine name  
  Status           = 0x0                ← success  
  
Windows 4624 on TARGET:  
  TargetUserName   = da_admin  
  LogonType        = 3                  ← network logon  
  AuthPackage      = NTLM              ← NOT Kerberos — this is PtH  
  WorkstationName  = ATTACKER-PC  
  IpAddress        = 10.0.0.99  
  KeyLength        = 0                  ← PtH indicator (no session key)  
  
Windows 4672 on TARGET:  
  SubjectUserName  = da_admin  
  PrivilegeList    = SeDebugPrivilege...  ← privileged logon  
  
STEP 4: Network activity from stolen identity  
────────────────────────────────────────────────────────────────  
Sysmon Event 3:  
  Image           = C:\Windows\System32\cmd.exe  
  DestinationIp   = 10.0.0.10          ← DC  
  DestinationPort = 445  
  User            = CORP\da_admin      ← stolen identity  
  
KEY CORRELATION FIELDS:  
  LogonId in Sysmon Event 1 → links to Windows 4624 LogonId  
  Same LogonId = same logon session = same stolen identity  
    
PtH-SPECIFIC INDICATORS IN 4624:  
  AuthPackage    = NTLM                 ← not Kerberos (unusual for DA)  
  KeyLength      = 0                    ← no encryption key negotiated  
  WorkstationName ≠ normal workstation  ← coming from wrong machine  
```  
  
### What I Missed Previously  
  
```  
MISSED:  
- Windows 4776 (NTLM validation) as direct PtH indicator  
- KeyLength=0 in Windows 4624 as PtH-specific field  
- AuthPackage=NTLM for Domain Admin accounts as anomaly  
  (DA accounts should use Kerberos in a healthy environment)  
- LogonId field linking Sysmon Event 1 (spawned process) to Windows 4624  
- WorkstationName field in 4776 for source identification  
- Windows 4648 (explicit credential use) when PtH uses explicit creds  
- The User field change in Sysmon Event 1 (low-priv → da_admin) as indicator  
```  
  
---  
  
## Correlation 7: Full Kerberoasting Chain  
  
### Events Involved: Sysmon 1 + 3 + Windows 4769 + 4770 + 4768  
  
```  
COMPLETE ATTACK CHAIN — Kerberoasting:  
  
STEP 1: SPN enumeration  
────────────────────────────────────────────────────────────────  
Sysmon Event 1:  
  Image       = C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe  
  CommandLine = Get-DomainSPN | Get-DomainObject    ← PowerView  
              OR  
              setspn -T corp.local -Q /*            ← built-in tool  
  
Sysmon Event 3:  
  Image           = powershell.exe  
  DestinationIp   = DC01_IP  
  DestinationPort = 389               ← LDAP query for SPN enumeration  
              OR  
  DestinationPort = 636               ← LDAPS  
  
Windows 5156 (Windows Filtering Platform — network connection):  
  Application     = powershell.exe  
  DestPort        = 389  
  
STEP 2: TGT obtained (if not already present)  
────────────────────────────────────────────────────────────────  
Windows 4768 on DC:  
  TargetUserName   = attacker_user  
  EncryptionType   = 0x12 (AES256)   ← normal TGT  
  PreAuthType      = 2                ← normal  
  IpAddress        = attacker_IP  
  
STEP 3: Burst of RC4 TGS requests  
────────────────────────────────────────────────────────────────  
Windows 4769 on DC × 47 (one per SPN):  
  TargetUserName       = attacker_user  
  ServiceName          = MSSQLSvc/sql01.corp.local:1433  
  TicketEncryptionType = 0x17          ← RC4! deliberately requested  
  IpAddress            = attacker_IP  
  Status               = 0x0          ← all succeed  
  
Windows 4769 on DC:  
  ServiceName          = HTTP/webserver.corp.local  
  TicketEncryptionType = 0x17          ← RC4 again  
  
[× 47 more events, all RC4, all within 30 seconds]  
  
STEP 4: Tickets saved for offline cracking  
────────────────────────────────────────────────────────────────  
Sysmon Event 11:  
  Image          = powershell.exe  
  TargetFilename = C:\Temp\tickets.kirbi    ← tickets saved to disk  
  
STEP 5: Offline cracking (no events — attacker's own machine)  
  hashcat --mode 13100 tickets.kirbi wordlist.txt  
  
STEP 6: Compromised service account used  
────────────────────────────────────────────────────────────────  
Windows 4624:  
  TargetUserName  = svc_sql              ← cracked service account  
  LogonType       = 3  
  IpAddress       = attacker_IP          ← novel source for svc_sql!  
  AuthPackage     = NTLM or Kerberos  
  
BEHAVIORAL CORRELATION:  
  4769 burst (TicketEncType=0x17) + LDAP query (port 389) + ticket file creation  
  = complete Kerberoasting signature via correlated events  
  
TIMING CORRELATION:  
  Event 3 (LDAP port 389)     = 14:00:00  ← SPN enumeration  
  4769 burst (RC4 × 47)       = 14:00:30  ← all within 30 seconds  
  Event 11 (tickets.kirbi)    = 14:01:00  ← saved to disk  
    
  The 30-second window of 47 RC4 TGS requests is the MIDAS burst signal  
```  
  
### What I Missed Previously  
  
```  
MISSED:  
- Windows 5156 (WFP connection) for LDAP SPN enumeration detection  
- Event 3 on port 389/636 as LDAP enumeration precursor  
- Windows 4768 (normal TGT) as precursor establishing session  
- Event 11 (tickets saved to disk) as post-Kerberoasting artifact  
- The timing correlation between LDAP query and TGS burst  
- Windows 4769 Status=0x0 (all succeed) as part of pattern  
  (failed TGS requests would have non-zero status)  
- The link between 4769 ServiceName and subsequent 4624 with cracked account  
- Windows 4770 (TGT renewal) abnormalities during the attack window  
```  
  
---  
  
## Correlation 8: Full DCSync Chain  
  
### Events Involved: Sysmon 1 + 3 + Windows 4662 + 4624 + 4672 + 4738 + 5136  
  
```  
COMPLETE ATTACK CHAIN — DCSync:  
  
STEP 1: Attacker authenticates to DC  
────────────────────────────────────────────────────────────────  
Windows 4624 on DC:  
  TargetUserName  = da_admin            ← compromised DA account  
  LogonType       = 3  
  IpAddress       = 10.0.0.99           ← attacker's machine (novel source!)  
  AuthPackage     = Kerberos  
  
Windows 4672 on DC:  
  SubjectUserName = da_admin  
  PrivilegeList   = SeDebugPrivilege, SeImpersonatePrivilege...  
  
STEP 2: Mimikatz runs DCSync  
────────────────────────────────────────────────────────────────  
Sysmon Event 1:  
  Image       = C:\Tools\mimikatz.exe  
  CommandLine = lsadump::dcsync /domain:corp.local /user:krbtgt  
  User        = CORP\da_admin  
  
Sysmon Event 3:  
  Image           = mimikatz.exe OR the process hosting it  
  DestinationIp   = DC01_IP  
  DestinationPort = 135               ← RPC endpoint mapper  
  DestinationPort = 49XXX             ← dynamic RPC port (MS-DRSR)  
  
STEP 3: Directory replication events on DC  
────────────────────────────────────────────────────────────────  
Windows 4662 on DC (Directory Service Access):  
  SubjectUserName  = da_admin          ← human account (NOT machine$)  
  SubjectDomainName = CORP  
  ObjectType       = domainDNS  
  Properties       = {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  
                   ← "Replicating Directory Changes"  
                   AND/OR  
                   {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}  
                   ← "Replicating Directory Changes All"  
  AccessMask       = 0x100  
  
Windows 4662 repeats multiple times:  
  Once for each account being synchronized  
  Many 4662s in quick succession = full domain dump  
  
STEP 4: Specific account data retrieved  
────────────────────────────────────────────────────────────────  
Windows 4662 on DC (for krbtgt specifically):  
  SubjectUserName  = da_admin  
  ObjectType       = user  
  ObjectName       = CN=krbtgt,CN=Users,DC=corp,DC=local  
  Properties       = {bf967a86-...}    ← unicodePwd attribute access  
                   AND  
                   {00fbf30c-...}      ← supplementalCredentials  
  
Windows 5136 on DC (Directory Service Object Modified):  
  SubjectUserName  = da_admin  
  ObjectDN         = CN=krbtgt,...  
  AttributeLdapDisplayName = unicodePwd  
  OperationType    = Value Added or Value Read  
  
STEP 5: If ACL was modified first (stealthier DCSync)  
────────────────────────────────────────────────────────────────  
Windows 5136 (ACL modified to grant replication rights):  
  ObjectDN        = DC=corp,DC=local  
  AttributeLdapDisplayName = nTSecurityDescriptor  
  SubjectUserName = attacker_lowpriv   ← low-priv account adding rights to itself!  
  
Then 4662 follows from the same lowpriv account  
→ Lowpriv account doing replication = stealthy DCSync via ACL abuse  
  
CORRELATION:  
  4624 (novel source logon) → 4672 (privileged) → 4662 (replication GUIDs)  
  = DCSync with 3-event confirmation  
  
  5136 (nTSecurityDescriptor changed) → 4662 (replication) by same non-$ account  
  = ACL-based DCSync preparation and execution  
```  
  
### What I Missed Previously  
  
```  
MISSED:  
- Windows 5136 (DS Object Modified) for ACL-based DCSync preparation  
- Windows 5136 for unicodePwd and supplementalCredentials attribute access  
- The specific replication GUIDs in 4662 Properties field  
  {1131f6aa} = Replicating Directory Changes  
  {1131f6ad} = Replicating Directory Changes All  
  {89e95b76} = Replicating Directory Changes in Filtered Set  
- Sysmon Event 3 on RPC ports (135 + dynamic) as MS-DRSR communication  
- Windows 4672 as precursor confirming privileged session  
- The ACL abuse path: 5136 (nTSecurityDescriptor) → 4662 (replication)  
- Multiple rapid 4662 events = full domain dump vs single account pull  
- ObjectName field in 4662 to identify WHICH account's data was pulled  
```  
  
---  
  
## Correlation 9: Full Persistence Chain  
  
### Events Involved: Sysmon 1 + 11 + 12 + 13 + 19 + 20 + 21 + Windows 4697 + 4698 + 7045 + 4702  
  
```  
PERSISTENCE METHODS — ALL EVENT CORRELATIONS:  
  
METHOD 1: Scheduled Task Persistence  
────────────────────────────────────────────────────────────────  
Windows 4698 (Scheduled Task Created):  
  TaskName        = \Microsoft\Windows\UpdateCheck   ← disguised name  
  TaskContent     = <Actions><Exec><Command>powershell.exe</Command>  
                    <Arguments>-enc <payload></Arguments></Exec></Actions>  
  SubjectUserName = attacker  
  
Sysmon Event 1 (schtasks.exe):  
  Image       = C:\Windows\System32\schtasks.exe  
  CommandLine = schtasks /create /tn "UpdateCheck" /tr "powershell..." /sc daily  
  User        = CORP\attacker  
  
When task triggers:  
Sysmon Event 1:  
  Image       = C:\Windows\System32\taskeng.exe  
             OR C:\Windows\System32\svchost.exe  ← Task Scheduler host  
  ParentImage = taskeng.exe or svchost.exe       ← task scheduler spawned this  
  
Windows 4702 (Scheduled Task Updated):  
  TaskName    = \Microsoft\Windows\UpdateCheck  
  ← modification events also tracked  
  
METHOD 2: Service-Based Persistence  
────────────────────────────────────────────────────────────────  
Windows 4697 (Service Installed):  
  ServiceName    = MaliciousService  
  ServiceFileName = C:\Temp\malware.exe  
  ServiceType    = 0x10 (Win32_Own_Process)  
  StartType      = 0x2  (Auto Start)             ← survives reboots  
  SubjectUserName = attacker  
  
Windows 7045 (New Service Installed — Security log):  
  ServiceName    = MaliciousService  
  ServiceFileName = C:\Temp\malware.exe  
  AccountName    = LocalSystem                   ← SYSTEM level persistence  
  
Sysmon Event 1:  
  Image       = C:\Windows\System32\sc.exe  
  CommandLine = sc create MaliciousService binPath= "C:\Temp\malware.exe" start= auto  
  User        = CORP\attacker  
  
When service starts:  
Sysmon Event 1:  
  Image       = C:\Temp\malware.exe  
  ParentImage = C:\Windows\System32\services.exe  ← service control manager  
  User        = NT AUTHORITY\SYSTEM  
  
METHOD 3: Registry Run Key (already covered in Event 13)  
+ Windows 4657 (Registry Value Modified):  
  ObjectName      = \REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run  
  ObjectValueName = MalwareKey  
  OldValue        = (empty)  
  NewValue        = C:\Temp\malware.exe  
  SubjectUserName = attacker  
  
METHOD 4: Startup Folder  
Sysmon Event 11:  
  Image          = powershell.exe  
  TargetFilename = C:\Users\alice\AppData\Roaming\Microsoft\Windows\  
                   Start Menu\Programs\Startup\malware.lnk  
  
METHOD 5: WMI Persistence (Events 19+20+21 — already covered)  
+ Windows 4662 for WMI subscription repository access  
  
CORRELATION ACROSS ALL PERSISTENCE METHODS:  
  Any persistence installation generates:  
  - Event 1 (the installer process)  
  - Method-specific event (4698/7045/4697/5136/19-21)  
  - File creation (Event 11 for the payload)  
  - Network connection (Event 3 when persistence calls home)  
  
  When persistence triggers:  
  - Event 1 with UNUSUAL ParentImage:  
    taskeng.exe/svchost.exe → scheduled task  
    services.exe → service  
    WmiPrvSE.exe → WMI subscription  
    explorer.exe startup → startup folder  
```  
  
### What I Missed Previously  
  
```  
MISSED:  
- Windows 4698 (Scheduled Task Created) — completely missed  
- Windows 4702 (Scheduled Task Modified) — completely missed  
- Windows 4697 (Service Installed) — completely missed  
- Windows 7045 (New Service — Security log) — missed the Security log version  
- Windows 4657 (Registry Modified) — missed, pairs with Sysmon 13  
- taskeng.exe/svchost.exe as ParentImage = scheduled task execution indicator  
- services.exe as ParentImage = service execution indicator  
- The startup folder path in Event 11 as persistence indicator  
- The complete "installation → trigger" correlation chain for each method  
```  
  
---  
  
## Correlation 10: Full Ransomware Chain  
  
### Events Involved: Sysmon 1 + 3 + 11 + 23 + 26 + Windows 4663 + 4660 + 5145  
  
```  
COMPLETE ATTACK CHAIN — Ransomware:  
  
STEP 1: Initial Access and Download  
────────────────────────────────────────────────────────────────  
Sysmon Event 1:  
  Image       = C:\Windows\System32\cmd.exe  
  CommandLine = cmd /c powershell -enc <downloader_payload>  
  ParentImage = C:\Program Files\Microsoft Office\Office16\WINWORD.EXE  
                ← macro in Word document  
  
Sysmon Event 3:  
  Image           = powershell.exe  
  DestinationIp   = malicious_cdn  
  DestinationPort = 443              ← downloading ransomware  
  
Sysmon Event 29 (FileExecutableDetected):  
  Image          = powershell.exe  
  TargetFilename = C:\Users\alice\AppData\Local\Temp\ransomware.exe  
  Hashes         = SHA256:<unknown_hash>  
  
STEP 2: Ransomware executes and calls home  
────────────────────────────────────────────────────────────────  
Sysmon Event 1:  
  Image       = C:\Users\alice\AppData\Local\Temp\ransomware.exe  
  ParentImage = powershell.exe  
  User        = CORP\alice  
  
Sysmon Event 3 (C2 check-in):  
  Image           = ransomware.exe  
  DestinationIp   = C2_server  
  DestinationPort = 443  
  
STEP 3: Shadow copy deletion (defense evasion)  
────────────────────────────────────────────────────────────────  
Sysmon Event 1:  
  Image       = C:\Windows\System32\vssadmin.exe  
  CommandLine = vssadmin delete shadows /all /quiet  
  ParentImage = C:\Temp\ransomware.exe    ← ransomware deleting backups!  
  User        = CORP\alice  
  
Sysmon Event 1:  
  Image       = C:\Windows\System32\wmic.exe  
  CommandLine = wmic shadowcopy delete  
  
STEP 4: Mass file encryption  
────────────────────────────────────────────────────────────────  
Sysmon Event 11 × thousands:  
  Image          = C:\Temp\ransomware.exe  
  TargetFilename = C:\Users\alice\Documents\Q4_Report.docx.LOCKED  
  ← new encrypted file created  
  
Sysmon Event 26 × thousands (FileDeleteDetected):  
  Image          = C:\Temp\ransomware.exe  
  TargetFilename = C:\Users\alice\Documents\Q4_Report.docx  
  ← original deleted after encryption  
  
Windows 4663 × thousands (File access):  
  SubjectUserName  = alice  
  ObjectName       = C:\Users\alice\Documents\Q4_Report.docx  
  AccessMask       = WRITE_DATA, DELETE  
  
Windows 4660 × thousands (Object deleted):  
  ObjectName       = C:\Users\alice\Documents\Q4_Report.docx  
  
STEP 5: Network share encryption  
────────────────────────────────────────────────────────────────  
Sysmon Event 3:  
  Image           = ransomware.exe  
  DestinationIp   = fileserver  
  DestinationPort = 445            ← encrypting network shares via SMB  
  
Windows 5145 on FILE SERVER (Network Share access):  
  SubjectUserName  = alice  
  ShareName        = \\*\Documents  
  RelativeTargetName = Q4_Report.docx  
  AccessMask       = WRITE | DELETE  ← writing encrypted + deleting original  
  
VOLUMETRIC SIGNALS (ECOD):  
  alice's normal file operations per hour: ~20  
  Ransomware hour: 5,000+ file creates + 5,000+ file deletes  
  Z-score: extreme → ECOD fires  
  
STEP 6: Ransom note dropped  
────────────────────────────────────────────────────────────────  
Sysmon Event 11:  
  Image          = ransomware.exe  
  TargetFilename = C:\Users\alice\Desktop\HOW_TO_DECRYPT.txt  
  ← ransom note in every directory  
```  
  
### What I Missed Previously  
  
```  
MISSED:  
- Windows 4663 (file access) mass event correlation for ransomware  
- Windows 4660 (object deleted) mass event for ransomware  
- Windows 5145 (network share access) for ransomware hitting file servers  
- vssadmin/wmic shadowcopy delete as ransomware precursor (Event 1)  
- ParentImage = ransomware.exe spawning vssadmin = behavioral chain  
- The create-then-delete pattern (Event 11 then Event 26) per file  
- Word.exe → cmd.exe → powershell.exe → ransomware.exe full chain  
- The network share encryption via Event 3 port 445 + 5145 correlation  
- ECOD volumetric: thousands of file operations in one hour  
```  
  
---  
  
## Correlation 11: Full Password Spray Chain  
  
### Events Involved: Sysmon 3 + Windows 4625 + 4648 + 4771 + 4776 + 4624  
  
```  
COMPLETE ATTACK CHAIN — Password Spray:  
  
STEP 1: Spray begins  
────────────────────────────────────────────────────────────────  
Windows 4625 × many (Failed Logon):  
  TargetUserName   = alice             ← different user each time  
  FailureReason    = %%2313            ← Wrong password  
  SubStatus        = 0xC000006A        ← Wrong password subcode  
  LogonType        = 3  
  IpAddress        = 185.220.100.5    ← same external IP always  
  WorkstationName  = ATTACKER-PC  
  
Windows 4625:  
  TargetUserName   = bob  
  SubStatus        = 0xC000006A        ← same wrong password  
  IpAddress        = 185.220.100.5    ← same source  
  
[× 498 more accounts]  
  
IMPORTANT SubStatus codes:  
  0xC000006A = Wrong password (the spray case)  
  0xC0000064 = Account doesn't exist (enumeration)  
  0xC000006D = Generic failure (could be either)  
  0xC000006F = Outside logon hours (spray during off-hours)  
  0xC0000234 = Account locked out (spray was too fast!)  
  
Windows 4771 (Kerberos Pre-Auth Failed — Kerberos version of 4625):  
  TargetUserName  = charlie  
  FailureCode     = 0x18              ← Wrong password (Kerberos)  
  IpAddress       = 185.220.100.5  
    
Windows 4776 (NTLM Credential Validation):  
  TargetUserName  = diana  
  Status          = 0xC000006A        ← Wrong password  
  Workstation     = ATTACKER-PC  
  
STEP 2: Successful hit  
────────────────────────────────────────────────────────────────  
Windows 4624 (Successful Logon):  
  TargetUserName  = emma              ← found valid credentials  
  LogonType       = 3  
  IpAddress       = 185.220.100.5    ← same attacker IP  
  AuthPackage     = NTLM or Kerberos  
  
Windows 4768 (TGT Requested — Kerberos):  
  TargetUserName  = emma  
  IpAddress       = 185.220.100.5    ← novel source for emma  
  EncryptionType  = 0x12             ← normal AES (legitimate TGT after spray)  
  
STEP 3: Attacker uses compromised account  
────────────────────────────────────────────────────────────────  
Windows 4672 (Special Privilege — if emma has admin rights):  
  SubjectUserName = emma  
  PrivilegeList   = SeDebugPrivilege...  
  
Sysmon Event 3:  
  Image   = (any process)  
  User    = CORP\emma                 ← compromised account making connections  
  DestinationIp = internal_server  
  
CORRELATION:  
  Same IpAddress (185.220.100.5) in:  
    - 4625 × 498 (failed) = SubStatus 0xC000006A  
    - 4624 × 1 (success) = for emma  
    - 4768 (TGT for emma from same IP)  
    
  This IP pattern across 499 events is the spray signature  
    
SPRAY vs BRUTE FORCE DISTINCTION:  
  Brute Force:  same TargetUserName, different passwords (triggers lockout)  
  Spray:        different TargetUserName, same attempt (stays under lockout)  
    
  Detection in events:  
    Brute Force: many 4625 for alice, then lockout (SubStatus 0xC0000234)  
    Spray: one 4625 per user, 498 different users, same IpAddress  
```  
  
### What I Missed Previously  
  
```  
MISSED:  
- Windows 4771 (Kerberos Pre-Auth Failure) — the Kerberos version of 4625  
- Windows 4776 (NTLM validation failure) — NTLM version  
- SubStatus codes in 4625 for distinguishing spray vs brute force vs enumeration  
  0xC000006A = wrong password  
  0xC0000064 = user doesn't exist (enumeration)  
  0xC000006F = outside logon hours  
  0xC0000234 = account locked (spray too fast)  
- Windows 4768 from same IP after successful spray = TGT acquisition  
- Windows 4672 post-spray to confirm privileged compromise  
- The distinction between 4625 (Security) and 4771 (Kerberos) events  
- FailureReason vs SubStatus fields and their different codes  
- Sysmon Event 3 post-spray showing the attacker using the account  
```  
  
---  
  
## Correlation 12: Defense Evasion Full Chain  
  
### Events Involved: Sysmon 1 + 4 + 16 + Windows 4719 + 4907 + 1102 + 4688  
  
```  
COMPLETE ATTACK CHAIN — Defense Evasion:  
  
METHOD 1: Disabling/Stopping Sysmon  
────────────────────────────────────────────────────────────────  
Sysmon Event 1:  
  Image       = C:\Windows\System32\sc.exe  
  CommandLine = sc stop Sysmon  
  User        = CORP\attacker  
  
Sysmon Event 4:  
  State = Stopped              ← LAST EVENT BEFORE BLIND SPOT  
  ← This is the last thing Sysmon logs before going blind  
  
METHOD 2: Modifying Sysmon Config  
────────────────────────────────────────────────────────────────  
Sysmon Event 1:  
  Image       = C:\Windows\System32\sysmon.exe  
  CommandLine = sysmon.exe -c minimal_config.xml   ← load stripped config  
  
Sysmon Event 16:  
  ConfigurationFileHash = <new_hash>    ← config changed  
  Configuration         = C:\Temp\minimal_config.xml  ← attacker's config  
  
METHOD 3: Clearing Event Logs  
────────────────────────────────────────────────────────────────  
Sysmon Event 1:  
  Image       = C:\Windows\System32\wevtutil.exe  
  CommandLine = wevtutil cl Security        ← clear Security log  
             OR wevtutil cl System  
             OR wevtutil cl "Microsoft-Windows-Sysmon/Operational"  
  
Windows 1102 (Audit Log Cleared):  
  SubjectUserName = attacker  
  SubjectLogonId  = 0x3e7  
  Channel         = Security               ← which log was cleared  
  
Windows 4616 (System time changed — to disrupt log correlation):  
  SubjectUserName = attacker  
  PreviousTime    = 2024-01-15 14:00:00  
  NewTime         = 2024-01-14 08:00:00   ← backdated! disrupts timeline  
  
METHOD 4: Disabling Audit Policy  
────────────────────────────────────────────────────────────────  
Windows 4719 (System Audit Policy Changed):  
  SubjectUserName  = attacker  
  AuditPolicyChanges = Removed: Logon/Logoff Success  
  ← removing logon auditing before credential attacks  
  
Sysmon Event 13:  
  TargetObject = HKLM\SYSTEM\CurrentControlSet\Control\Lsa\AuditBaseObjects  
  Details      = 0                      ← audit disabled via registry  
  
METHOD 5: AMSI Bypass (Anti-Malware Scan Interface)  
────────────────────────────────────────────────────────────────  
Sysmon Event 13:  
  TargetObject = HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings\Enabled  
  Details      = 0                      ← disabling script host security  
  
Sysmon Event 8 (CreateRemoteThread into amsi.dll):  
  SourceImage  = powershell.exe  
  TargetImage  = powershell.exe         ← same process  
  StartModule  = C:\Windows\System32\amsi.dll  
  ← patching AMSI in PowerShell's own process  
  
METHOD 6: ETW (Event Tracing for Windows) Tampering  
────────────────────────────────────────────────────────────────  
Sysmon Event 10:  
  SourceImage  = powershell.exe  
  TargetImage  = powershell.exe         ← self-targeting  
  GrantedAccess = 0x1FFFFF  
  ← patching ETW in own process to stop logging  
  
CORRELATION CHAIN:  
  Event 1 (sc stop Sysmon) → Event 4 (Sysmon stops) = [GAP BEGINS]  
  ...  
  Event 1 (sc start Sysmon) → Event 4 (Sysmon restarts) = [GAP ENDS]  
    
  The GAP between Event 4 Stopped and Event 4 Started = blind spot  
  Everything in that gap is unlogged  
  Duration of gap × expected event rate = estimated missed events  
```  
  
### What I Missed Previously  
  
```  
MISSED:  
- Windows 1102 (Audit Log Cleared) — completely missed  
- Windows 4719 (Audit Policy Changed) — completely missed    
- Windows 4616 (System Time Changed) — timestamp manipulation missed  
- Sysmon Event 4 paired with Event 1 (sc.exe) for stop context  
- The GAP analysis: Sysmon Event 4 Stopped → Started = blind spot  
- AMSI bypass via Sysmon Event 8 (self-injection into amsi.dll)  
- ETW tampering via Sysmon Event 10 (self-targeting for GrantedAccess)  
- Windows 4907 (Audit Policy changed on object) for per-object audit changes  
- Registry-based audit disable via Sysmon Event 13  
```  
  
---  
  
## Complete Field Cross-Reference — What Links Events Together  
  
```  
┌─────────────────────────────────────────────────────────────────────────────┐  
│  LINKING FIELD        │  Events It Connects           │  What It Enables    │  
├─────────────────────────────────────────────────────────────────────────────┤  
│  ProcessGuid          │  1 ↔ 5 ↔ 8 ↔ 10 ↔ 3 ↔ 7    │  Full process       │  
│                       │                               │  lifecycle tracking  │  
├─────────────────────────────────────────────────────────────────────────────┤  
│  LogonId / LogonGuid  │  Sysmon 1 ↔ Win 4624         │  Process → identity  │  
│                       │                               │  attribution        │  
├─────────────────────────────────────────────────────────────────────────────┤  
│  User (account name)  │  All Sysmon events ↔          │  Identity-centric   │  
│                       │  Win 4624/4625/4672           │  behavioral model   │  
├─────────────────────────────────────────────────────────────────────────────┤  
│  IpAddress            │  Win 4624 ↔ 4625 ↔ 4768 ↔   │  Source attribution │  
│                       │  4769 ↔ Sysmon 3             │  across protocols   │  
├─────────────────────────────────────────────────────────────────────────────┤  
│  TargetUserName       │  Win 4624 ↔ 4625 ↔ 4768 ↔   │  Victim account     │  
│                       │  4769 ↔ 4662                 │  tracking           │  
├─────────────────────────────────────────────────────────────────────────────┤  
│  SubjectUserName      │  Win 4662 ↔ 5136 ↔ 4698 ↔   │  Actor attribution  │  
│                       │  4697 ↔ 4719                 │  in AD events       │  
├─────────────────────────────────────────────────────────────────────────────┤  
│  UtcTime (timestamp)  │  All events                   │  Timeline           │  
│                       │                               │  reconstruction     │  
├─────────────────────────────────────────────────────────────────────────────┤  
│  ParentProcessGuid    │  Sysmon 1 (child) ↔           │  Process tree       │  
│                       │  Sysmon 1 (parent)            │  reconstruction     │  
├─────────────────────────────────────────────────────────────────────────────┤  
│  Hashes               │  Sysmon 1 ↔ 6 ↔ 7 ↔ 11 ↔   │  File identity      │  
│                       │  23 ↔ 26 ↔ 29               │  across events      │  
├─────────────────────────────────────────────────────────────────────────────┤  
│  PipeName             │  Sysmon 17 ↔ 18              │  Pipe interaction   │  
│                       │                               │  pairing           │  
├─────────────────────────────────────────────────────────────────────────────┤  
│  TaskName             │  Win 4698 ↔ 4702 ↔           │  Scheduled task     │  
│                       │  Sysmon 1 (taskeng parent)   │  lifecycle          │  
├─────────────────────────────────────────────────────────────────────────────┤  
│  ServiceName          │  Win 4697 ↔ 7045 ↔           │  Service lifecycle  │  
│                       │  Sysmon 1 (services parent)  │  tracking           │  
├─────────────────────────────────────────────────────────────────────────────┤  
│  TargetObject         │  Sysmon 12 ↔ 13 ↔ 14        │  Registry key       │  
│  (registry path)      │  ↔ Win 4657                  │  change chain       │  
├─────────────────────────────────────────────────────────────────────────────┤  
│  Consumer + Filter    │  Sysmon 19 ↔ 20 ↔ 21        │  WMI subscription   │  
│  names                │                               │  complete picture   │  
└─────────────────────────────────────────────────────────────────────────────┘  
```  
  
---  
  
## Windows Security Events I Missed Pairing With Sysmon  
  
```  
┌──────────┬─────────────────────────────────┬──────────────────────────────┐  
│  Event   │  Name                           │  Pairs With Sysmon           │  
├──────────┼─────────────────────────────────┼──────────────────────────────┤  
│  1102    │  Audit Log Cleared              │  Event 1 (wevtutil)          │  
│  4616    │  System Time Changed            │  Event 1 (time change tool)  │  
│  4648    │  Explicit Credential Logon      │  Event 1 (PsExec, runas)     │  
│          │                                 │  Event 3 (network)           │  
│  4656    │  Handle to Object Requested     │  Event 10 (ProcessAccess)    │  
│  4657    │  Registry Value Modified        │  Event 13 (Registry Set)     │  
│  4660    │  Object Deleted                 │  Event 26 (FileDelete)       │  
│  4663    │  Object Access Attempt          │  Event 10, 11 (file/process) │  
│  4672    │  Special Privileges Assigned    │  Event 1, 3 (privileged exec)│  
│  4697    │  Service Installed              │  Event 1 (sc.exe)            │  
│  4698    │  Scheduled Task Created         │  Event 1 (schtasks.exe)      │  
│  4702    │  Scheduled Task Modified        │  Event 1 (schtasks.exe)      │  
│  4719    │  Audit Policy Changed           │  Event 13 (registry)         │  
│  4738    │  User Account Changed           │  Event 1 (net.exe, ADUC)     │  
│  4768    │  TGT Requested                  │  Event 3 (port 88)           │  
│  4769    │  Service Ticket Requested       │  Event 3 (port 88)           │  
│  4770    │  TGT Renewed                    │  Event 3 (port 88)           │  
│  4771    │  Kerberos Pre-Auth Failed       │  Event 3 (spray source)      │  
│  4776    │  NTLM Credential Validation     │  Event 3, Event 1 (PtH tool) │  
│  4907    │  Audit Settings Changed         │  Event 13 (registry)         │  
│  5136    │  Directory Object Modified      │  Event 1 (AD tools)          │  
│  5145    │  Network Share Object Access    │  Event 3 (port 445)          │  
│  5156    │  WFP Connection Allowed         │  Event 3 (lower-level)       │  
│  7045    │  New Service Installed          │  Event 1 (sc.exe, PsExec)    │  
└──────────┴─────────────────────────────────┴──────────────────────────────┘  
```
"""
daily_simulation.py — Orchestrates one calendar day of enterprise activity.

Integrates ALL event generators covering Security, Sysmon, DNS, PowerShell,
Task Scheduler, WMI, and Windows Defender channels.

Company: Nexovate Solutions Pvt. Ltd., Bangalore, India
Timezone: IST (UTC+5:30) — NO Daylight Saving Time ever
"""

from __future__ import annotations

import os
import random
import sys
from datetime import date, datetime, timedelta
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from config.company import (
    DEPARTMENTS,
    DOMAIN_CONTROLLERS,
    DOMAIN_FQDN,
    DOMAIN_NETBIOS,
    NETWORK_RANGES,
    SECURITY_GROUPS,
    SERVERS,
)

# Other generators
from generators.other_generators import (
    build_task_content_xml,
    gen_dns_256,
    gen_dns_257,
    gen_ps_4103,
    gen_ps_4104,
    gen_task_106,
    gen_task_200,
    gen_task_201,
    gen_task_4698,
)

# Core security generators
from generators.security_generator import (
    gen_4624,
    gen_4625,
    gen_4634,
    gen_4672,
    gen_4720,
    gen_4740,
    gen_4768,
    gen_4769,
    gen_4771,
    gen_4776,
    gen_group_change,
)

# Extended security generators
from generators.security_generator_extended import (
    gen_4647,
    gen_4656,
    gen_4658,
    gen_4663,
    gen_4689,
    gen_4697,
    gen_4719,
    gen_4722,
    gen_4724,
    gen_4725,
    gen_4726,
    gen_4729,
    gen_4738,
    gen_4741,
    gen_4742,
    gen_4743,
    gen_4907,
    gen_5140,
    gen_5145,
    gen_6416,
    gen_7036,
    gen_7045,
)

# Sysmon generators
from generators.sysmon_generator import (
    gen_eid1,
    gen_eid3,
    gen_eid10,
    gen_eid11,
    gen_eid22,
)
from generators.sysmon_generator_extended import (
    gen_eid6,
    gen_eid12,
    gen_eid13,
    gen_eid15,
    gen_eid17,
    gen_eid18,
)
from generators.wmi_defender_generators import (
    gen_defender_1116,
    gen_defender_1117,
    gen_wmi_5857,
    gen_wmi_5858,
)

from core.employees import Employee, ServiceAccount, stable_seed
from core.event_bus import EventBus, LogonSession
from core.time_engine import (
    AbsenceCalendar,
    DailySchedule,
    _float_hour_to_datetime,
    is_business_day,
    local_to_utc,
    random_ts_in_session,
    service_account_ts,
    week_drift,
)

# Deterministic SID per security group (position-based, stable across runs), so
# routine group-management traffic references consistent group identities.
_GROUP_SID = {
    g: f"S-1-5-21-1484628597-1684816888-3125425894-{1300 + i}"
    for i, g in enumerate(sorted(SECURITY_GROUPS))
}
# Regular groups that receive routine, benign membership churn. The privileged
# Tier-0 / Domain-Admin groups are deliberately excluded: routine helpdesk work
# never touches them, which is precisely what makes an add to Domain Admins a
# novel, rare directory edge the graph track can flag (account_manipulation).
_ROUTINE_GROUPS = [g for g in sorted(SECURITY_GROUPS)
                   if "Tier0" not in g and "DomainAdmins" not in g and "Tier1" not in g]

DC01     = DOMAIN_CONTROLLERS[0]
DNS_IP   = DC01["ip"]
DNS_FQDN = DC01["fqdn"]

_SERVER_BY_HOSTNAME: dict[str, dict] = {
    s["hostname"]: s for s in SERVERS + DOMAIN_CONTROLLERS
}

# Standard Kerberos SPNs for internal servers
_CIFS_SPNS: dict[str, tuple[str, str]] = {
    "FS01":       ("cifs/FS01.nexovate.local",          "S-1-5-21-1484628597-1684816888-3125425894-1050"),
    "FS02":       ("cifs/FS02.nexovate.local",          "S-1-5-21-1484628597-1684816888-3125425894-1051"),
    "SQL01":      ("MSSQLSvc/SQL01.nexovate.local:1433","S-1-5-21-1484628597-1684816888-3125425894-1060"),
    "SQL02":      ("MSSQLSvc/SQL02.nexovate.local:1433","S-1-5-21-1484628597-1684816888-3125425894-1061"),
    "APP01":      ("http/APP01.nexovate.local",         "S-1-5-21-1484628597-1684816888-3125425894-1070"),
    "DC01":       ("ldap/DC01.nexovate.local",          "S-1-5-21-1484628597-1684816888-3125425894-1000"),
    "EXCHANGE01": ("exchangeMDB/EXCHANGE01.nexovate.local","S-1-5-21-1484628597-1684816888-3125425894-1080"),
    "PRINT01":    ("cifs/PRINT01.nexovate.local",       "S-1-5-21-1484628597-1684816888-3125425894-1090"),
}

# Dept -> (share UNC, local path, server hostname)
_DEPT_SHARES: dict[str, tuple[str, str, str]] = {
    "Engineering": (r"\\FS01\Engineering$", r"D:\Shares\Engineering", "FS01"),
    "Finance":     (r"\\FS01\Finance$",     r"D:\Shares\Finance",     "FS01"),
    "HR":          (r"\\FS01\HR$",          r"D:\Shares\HR",          "FS01"),
    "Sales":       (r"\\FS01\Sales$",       r"D:\Shares\Sales",       "FS01"),
    "Marketing":   (r"\\FS01\Marketing$",   r"D:\Shares\Marketing",   "FS01"),
    "Operations":  (r"\\FS01\Operations$",  r"D:\Shares\Operations",  "FS01"),
    "IT":          (r"\\FS02\IT$",          r"E:\Shares\IT",          "FS02"),
    "Legal":       (r"\\FS01\Legal$",       r"D:\Shares\Legal",       "FS01"),
    "Executive":   (r"\\FS01\Executive$",   r"D:\Shares\Executive",   "FS01"),
}

# Files per department for realistic share access
_DEPT_FILES: dict[str, list[str]] = {
    "Engineering": ["architecture.md", "api_spec.yaml", "deployment_notes.txt",
                    "test_results.json", "config.yaml", "README.md"],
    "Finance":     ["Q1_Budget.xlsx", "Annual_Report_2024.xlsx", "Expenses_Jan.xlsx",
                    "Payroll_2025.xlsx", "Invoice_001.pdf"],
    "HR":          ["Employee_Handbook.docx", "Offer_Letter_Template.docx",
                    "Performance_Review_Q4.xlsx", "Headcount_2025.xlsx"],
    "Sales":       ["Q4_Pipeline.xlsx", "Client_List.xlsx",
                    "Contract_Template.docx", "Proposal_Draft.pptx"],
    "Marketing":   ["Brand_Guide.pdf", "Campaign_Q1.pptx",
                    "Social_Calendar.xlsx", "Press_Release_Jan.docx"],
    "Legal":       ["NDA_Template.docx", "Contract_Review_Jan.docx",
                    "IP_Agreement.pdf", "Compliance_Report.docx"],
    "IT":          ["Server_Inventory.xlsx", "Patch_Schedule.xlsx",
                    "DR_Runbook.docx", "Network_Diagram.vsd"],
    "Operations":  ["Vendor_Contracts.xlsx", "Project_Status.xlsx",
                    "SLA_Report.pdf", "Process_Flow.docx"],
    "Executive":   ["Board_Deck_Q4.pptx", "Strategy_2025.pptx",
                    "Revenue_Forecast.xlsx", "Org_Chart.pptx"],
}

# ── Registry and named-pipe behaviour ────────────────────────────────────────
#
# Both of these used to be a uniform `rng.choice` over one short global list, so
# every identity eventually touched every value: measured on a 20-day estate, an
# account reached 3.98 of the 4 registry locations and 3.79 of the 7 pipe names
# that existed. A behavioural model cannot learn anything from that -- there is no
# per-identity baseline to deviate FROM -- and the two views built on this
# telemetry were unusable as a direct result.
#
# Real estates have the opposite shape: diversity is high ACROSS identities and
# low WITHIN one. A given person's machine runs a particular set of applications,
# and those applications touch a particular, stable set of pipes and registry
# locations, day after day. So the vocabulary below is realistic in size, and
# `software_profile()` gives each employee a stable subset of it.

# Windows built-in pipes, present on essentially every host. Names verified
# against the documented RPC/SMB endpoint list (svcctl, lsarpc, samr, netlogon,
# wkssvc, srvsvc, epmapper, eventlog, atsvc, spoolss are the classic set).
_OS_PIPES: list[str] = [
    "svcctl", "lsarpc", "samr", "netlogon", "wkssvc", "eventlog", "srvsvc",
    "epmapper", "atsvc", "spoolss", "ntsvcs", "InitShutdown", "scerpc",
    "LSM_API_service", "trkwks", "plugplay", "winreg", "browser",
]
# Every session touches a few of these; they are the shared floor, not the signal.
_UNIVERSAL_PIPES: list[str] = ["svcctl", "lsarpc", "wkssvc", "srvsvc", "eventlog"]

# Application pipes, keyed by the software a role actually runs. Deliberately
# STABLE names: Chromium's `mojo.<pid>.<n>.<random>` and similar per-launch
# pipes are excluded, because a production Sysmon configuration filters them for
# exactly the reason they would break this view -- every instance is novel, so
# they carry no per-identity information, only noise.
_APP_PIPES: dict[str, list[str]] = {
    "Engineering": ["docker_engine", "vscode-git", "dotnet-diagnostic", "openssh-agent"],
    "IT":          ["PSHost.Admin", "sqlquery", "wcf-remoting", "RemoteRegistry"],
    "Finance":     ["MsFteWds", "OfficeC2R", "SAPgui"],
    "HR":          ["MsFteWds", "OfficeC2R", "WorkdaySync"],
    "Sales":       ["MsFteWds", "OfficeC2R", "CrmSync"],
    "Marketing":   ["MsFteWds", "OfficeC2R", "AdobeIPC"],
    "Operations":  ["MsFteWds", "OfficeC2R", "SAPgui"],
    "Legal":       ["MsFteWds", "OfficeC2R", "DocuSignIPC"],
    "Executive":   ["MsFteWds", "OfficeC2R", "TeamsIPC"],
}

# Registry locations, as (key, value, data). Breadth matters more than depth:
# the `reg` view keys on hive + three path components, so what it needs is many
# distinct LOCATIONS, not many values in one location.
_OS_REGISTRY_WRITES: list[tuple[str, str, str]] = [
    (r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "HideFileExt", "0"),
    (r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs", "MRUListEx", "0100000"),
    (r"HKCU\Control Panel\Desktop", "ScreenSaveTimeOut", "900"),
    (r"HKCU\SOFTWARE\Microsoft\Internet Explorer\Main", "Start Page", "https://intranet.nexovate.local"),
    (r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "Domain", "nexovate.local"),
    (r"HKLM\SOFTWARE\Microsoft\Windows Defender\Signature Updates", "SignatureLastUpdated", "1"),
]
_APP_REGISTRY_WRITES: dict[str, list[tuple[str, str, str]]] = {
    "Engineering": [
        (r"HKCU\SOFTWARE\Microsoft\VisualStudio\Telemetry", "LastPing", "1"),
        (r"HKCU\SOFTWARE\GitForWindows", "InstallPath", r"C:\Program Files\Git"),
        (r"HKLM\SOFTWARE\Docker Inc\Docker", "AppPath", r"C:\Program Files\Docker"),
    ],
    "IT": [
        (r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoRestartShell", "1"),
        (r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections", "0"),
        (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", "1"),
    ],
    "Finance":   [(r"HKCU\SOFTWARE\Microsoft\Office\16.0\Excel\Options", "DefaultPath", r"D:\Shares\Finance")],
    "HR":        [(r"HKCU\SOFTWARE\Microsoft\Office\16.0\Word\Options", "DefaultPath", r"D:\Shares\HR")],
    "Sales":     [(r"HKCU\SOFTWARE\Salesforce\Client", "LastSync", "1")],
    "Marketing": [(r"HKCU\SOFTWARE\Adobe\CommonFiles", "LastLaunch", "1")],
    "Operations":[(r"HKCU\SOFTWARE\SAP\SAPGUI Front", "LastServer", "sap.nexovate.local")],
    "Legal":     [(r"HKCU\SOFTWARE\DocuSign\Client", "LastSession", "1")],
    "Executive": [(r"HKCU\SOFTWARE\Microsoft\Office\16.0\PowerPoint\Options", "DefaultPath", r"D:\Shares\Executive")],
}


def software_profile(emp) -> tuple[list[str], list[tuple[str, str, str]]]:
    """The pipes and registry locations THIS employee's machine touches.

    Derived from the account name by a stable hash rather than drawn per session,
    so an identity's baseline is the same every day and a departure from it is
    genuinely a departure. That property -- not the size of the vocabulary -- is
    what makes per-identity novelty measurable; the `share` view works precisely
    because department-keyed access already had it.
    """
    import hashlib
    seed = int(hashlib.sha256(emp.samaccountname.encode()).hexdigest()[:8], 16)
    picker = random.Random(seed)

    pipes = list(_UNIVERSAL_PIPES)
    pipes += _APP_PIPES.get(emp.department, [])
    # One or two OS pipes beyond the universal floor, stable per person: real
    # machines differ by installed drivers, printers and management agents.
    pipes += picker.sample([p for p in _OS_PIPES if p not in pipes],
                           k=min(2, max(0, len(_OS_PIPES) - len(pipes))))

    writes = list(_OS_REGISTRY_WRITES[:3])
    writes += _APP_REGISTRY_WRITES.get(emp.department, [])
    writes += picker.sample(_OS_REGISTRY_WRITES[3:],
                            k=min(2, len(_OS_REGISTRY_WRITES[3:])))
    return pipes, writes

# Normal WMI queries (administrative monitoring)
_WMI_QUERIES: list[str] = [
    "SELECT * FROM Win32_Service WHERE Name = 'Spooler'",
    "SELECT * FROM Win32_Process WHERE Name = 'svchost.exe'",
    "SELECT * FROM Win32_OperatingSystem",
    "SELECT * FROM Win32_DiskDrive",
    "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True",
    "SELECT * FROM Win32_LogicalDisk WHERE DriveType = 3",
]

# WMI provider paths (normal activity)
_WMI_PROVIDERS: list[tuple[str, str]] = [
    ("CIMWin32",    r"%SystemRoot%\system32\wbem\CIMWin32.dll"),
    ("WmiApRpl",    r"%SystemRoot%\system32\wbem\WmiApRpl.dll"),
    ("MSIProv",     r"%SystemRoot%\system32\wbem\msiprov.dll"),
    ("ntevt",       r"%SystemRoot%\system32\wbem\ntevt.dll"),
]

# USB devices — realistic Indian corporate hardware
_USB_DEVICES: list[tuple[str, str, str, str]] = [
    ("USB\\VID_0781&PID_5583\\0401234567AB", "SanDisk Cruzer Blade 32GB",
     "{36FC9E60-C465-11CF-8056-444553540000}", "USB"),
    ("USB\\VID_058F&PID_6387\\0987654321CD", "Transcend JetFlash 16GB",
     "{36FC9E60-C465-11CF-8056-444553540000}", "USB"),
    ("USB\\VID_13FE&PID_4300\\ABCDEF123456", "HP v150w 64GB USB Flash Drive",
     "{36FC9E60-C465-11CF-8056-444553540000}", "USB"),
]

# Rare Windows Defender threat samples
_DEFENDER_THREATS: list[tuple[str, str, str, str]] = [
    ("Trojan:Win32/Meterpreter.A!MTB", "Severe",   "Trojan",
     r"C:\Temp\update.exe"),
    ("HackTool:Win32/Mimikatz.A",      "Severe",   "HackTool",
     r"C:\Users\Default\AppData\Local\Temp\mimi.exe"),
    ("Ransom:Win32/WannaCrypt.A",      "Critical", "Ransomware",
     r"C:\Downloads\invoice.exe"),
    ("TrojanDownloader:Win32/Agent.F", "High",     "Trojan",
     r"C:\Temp\svchost32.exe"),
]

# PowerShell scripts per department
_PS_SCRIPTS: dict[str, list[tuple[str, str]]] = {
    "IT": [
        ("Get-ADUser -Filter * -Properties LastLogonDate | Where-Object {$_.LastLogonDate -lt (Get-Date).AddDays(-90)} | Select Name,LastLogonDate",
         r"C:\Scripts\stale-accounts.ps1"),
        ("Get-Service | Where-Object {$_.Status -eq 'Stopped'} | Format-Table Name,DisplayName", ""),
        ("Get-EventLog -LogName Security -Newest 100 | Where-Object {$_.EventID -eq 4625}",
         r"C:\Scripts\failed-logons.ps1"),
        ("Test-NetConnection -ComputerName SQL01 -Port 1433", ""),
        ("Get-ADGroupMember -Identity 'Domain Admins' | Select Name,SamAccountName", ""),
        ("Restart-Service -Name 'wuauserv' -Force", ""),
        ("Get-WinEvent -LogName Security -FilterXPath '*[System[EventID=4624]]' -MaxEvents 50",
         r"C:\Scripts\audit-logons.ps1"),
        ("Get-ADComputer -Filter * -Properties LastLogonDate | Where-Object {$_.LastLogonDate -lt (Get-Date).AddDays(-60)}", ""),
        ("Get-WmiObject Win32_OperatingSystem | Select CSName,Caption,LastBootUpTime", ""),
        ("Set-GPLink -Name 'Default Domain Policy' -Target 'DC=NEXOVATE,DC=local' -Enforced Yes",
         r"C:\Scripts\gpo-enforce.ps1"),
        ("New-ADUser -Name 'Ravi Sharma' -SamAccountName rsharma -Enabled $true",
         r"C:\Scripts\new-user.ps1"),
        ("Get-DnsServerStatistics -ComputerName DC01", ""),
    ],
    "Engineering": [
        ("python -m pytest tests/ --tb=short", ""),
        ("git log --oneline -20", ""),
        ("Get-Content C:\\Logs\\app.log -Tail 50", ""),
        ("Test-NetConnection -ComputerName SQL01.nexovate.local -Port 1433", ""),
        ("Invoke-WebRequest -Uri http://APP01.nexovate.local/api/health -UseBasicParsing | Select StatusCode", ""),
        ("Set-Location C:\\Dev\\nexovate-api; dotnet build", ""),
        ("Get-ChildItem -Path C:\\Dev -Recurse -Filter *.log | Remove-Item -Force",
         r"C:\Scripts\cleanup-logs.ps1"),
    ],
    "Finance": [
        ("Import-Csv C:\\Finance\\Q4_2024.csv | ConvertTo-Json | Out-File report.json", ""),
        ("Get-Date | Select-Object -ExpandProperty Month", ""),
    ],
    "HR": [
        ("Get-ADUser -Filter {Department -eq 'Engineering'} | Measure-Object", ""),
    ],
}

# Process paths (Windows)
_PROCESS_PATHS: dict[str, str] = {
    "cmd.exe":            r"C:\Windows\System32\cmd.exe",
    "powershell.exe":     r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "powershell_ise.exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe",
    "mstsc.exe":          r"C:\Windows\System32\mstsc.exe",
    "mmc.exe":            r"C:\Windows\System32\mmc.exe",
    "chrome.exe":         r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    "EXCEL.EXE":          r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
    "WINWORD.EXE":        r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
    "OUTLOOK.EXE":        r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
    "POWERPNT.EXE":       r"C:\Program Files\Microsoft Office\root\Office16\POWERPNT.EXE",
    "Teams.exe":          r"C:\Users\Default\AppData\Local\Microsoft\Teams\current\Teams.exe",
    "devenv.exe":         r"C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\devenv.exe",
    "code.exe":           r"C:\Program Files\Microsoft VS Code\Code.exe",
    "python.exe":         r"C:\Python311\python.exe",
    "node.exe":           r"C:\Program Files\nodejs\node.exe",
    "git.exe":            r"C:\Program Files\Git\cmd\git.exe",
    "putty.exe":          r"C:\Program Files\PuTTY\putty.exe",
    "Zoom.exe":           r"C:\Users\Default\AppData\Roaming\Zoom\bin\Zoom.exe",
    "Slack.exe":          r"C:\Users\Default\AppData\Local\slack\Slack.exe",
    "slack.exe":          r"C:\Users\Default\AppData\Local\slack\Slack.exe",
    "AcroRd32.exe":       r"C:\Program Files\Adobe\Acrobat DC\Acrobat\AcroRd32.exe",
    "WinSCP.exe":         r"C:\Program Files (x86)\WinSCP\WinSCP.exe",
    "procexp.exe":        r"C:\Tools\Sysinternals\procexp.exe",
    "procmon.exe":        r"C:\Tools\Sysinternals\procmon.exe",
    "nmap.exe":           r"C:\Program Files (x86)\Nmap\nmap.exe",
    "Wireshark.exe":      r"C:\Program Files\Wireshark\Wireshark.exe",
    "eventvwr.exe":       r"C:\Windows\System32\eventvwr.exe",
    "services.msc":       r"C:\Windows\System32\services.msc",
    "veeam.exe":          r"C:\Program Files\Veeam\Backup and Replication\Console\veeam.exe",
    "postman.exe":        r"C:\Users\Default\AppData\Local\Postman\Postman.exe",
    "dbeaver.exe":        r"C:\Program Files\DBeaver\dbeaver.exe",
    "docker.exe":         r"C:\Program Files\Docker\Docker\resources\bin\docker.exe",
    "QuickBooks.exe":     r"C:\Program Files\Intuit\QuickBooks 2024\QBW32.exe",
    "Photoshop.exe":      r"C:\Program Files\Adobe\Adobe Photoshop 2024\Photoshop.exe",
    "Figma.exe":          r"C:\Users\Default\AppData\Local\Figma\Figma.exe",
    "Canva.exe":          r"C:\Users\Default\AppData\Local\Programs\Canva\Canva.exe",
    "iManage.exe":        r"C:\Program Files\iManage\Work\iManage.Work.exe",
    "Salesforce.exe":     r"C:\Program Files\Salesforce\Salesforce.exe",
    "explorer.exe":       r"C:\Windows\explorer.exe",
    "bginfo.exe":         r"C:\Tools\Sysinternals\bginfo.exe",
    "psexec.exe":         r"C:\Tools\Sysinternals\psexec.exe",
    "mshta.exe":          r"C:\Windows\System32\mshta.exe",
    "regsvr32.exe":       r"C:\Windows\System32\regsvr32.exe",
    "rundll32.exe":       r"C:\Windows\System32\rundll32.exe",
    "certutil.exe":       r"C:\Windows\System32\certutil.exe",
    "bitsadmin.exe":      r"C:\Windows\System32\bitsadmin.exe",
    "wmic.exe":           r"C:\Windows\System32\wbem\wmic.exe",
}

_EXPLORER  = r"C:\Windows\explorer.exe"
_SVCHOST   = r"C:\Windows\System32\svchost.exe"


def _full_path(exe: str) -> str:
    return _PROCESS_PATHS.get(exe, fr"C:\Program Files\{exe}")


def _user_sid(sam: str) -> str:
    import hashlib
    rid = int(hashlib.md5(sam.encode()).hexdigest()[:4], 16) % 9000 + 1100
    return f"S-1-5-21-1484628597-1684816888-3125425894-{rid}"


def _build_cmdline(exe: str, rng: random.Random) -> str:
    commands: dict[str, str] = {
        "chrome.exe":    r"C:\Program Files\Google\Chrome\Application\chrome.exe --profile-directory=Default",
        "OUTLOOK.EXE":   r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE /recycle",
        "powershell.exe":r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonInteractive -ExecutionPolicy Bypass",
        "cmd.exe":       r"C:\Windows\System32\cmd.exe /c dir",
        "python.exe":    r"C:\Python311\python.exe C:\Dev\nexovate-api\main.py",
        "node.exe":      r"C:\Program Files\nodejs\node.exe C:\Dev\frontend\server.js",
        "git.exe":       fr"C:\Program Files\Git\cmd\git.exe {rng.choice(['pull','push','status','log --oneline'])}",
        "code.exe":      r"C:\Program Files\Microsoft VS Code\Code.exe C:\Dev\nexovate-api",
        "devenv.exe":    r"C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\devenv.exe /nosplash",
        "mstsc.exe":     fr"C:\Windows\System32\mstsc.exe /v:10.10.1.{rng.randint(10,80)}",
    }
    return commands.get(exe, _full_path(exe))


def _select_processes(emp: Employee, rng: random.Random) -> list[str]:
    dept_procs = DEPARTMENTS[emp.department].typical_processes
    n = rng.randint(3, min(len(dept_procs), 9))
    return rng.sample(dept_procs, n)


def _fake_ext_ip(domain: str) -> str:
    """
    Deterministic fake external IP from domain.
    Uses realistic Indian CDN/cloud IP ranges for Indian companies.
    AWS Mumbai: 13.126.0.0/15, 52.66.0.0/15
    Google India: 74.125.0.0/16, 142.250.0.0/15
    Cloudflare: 104.16.0.0/13, 103.21.244.0/22
    Akamai: 2.16.0.0/13, 23.32.0.0/11
    """
    import hashlib
    h = int(hashlib.md5(domain.encode()).hexdigest()[:6], 16)
    # Rotate between realistic public CDN/cloud prefixes
    prefixes = [
        (13, 126),   # AWS Mumbai ap-south-1
        (52, 66),    # AWS Mumbai
        (74, 125),   # Google
        (104, 16),   # Cloudflare
        (103, 21),   # Cloudflare India
        (23, 32),    # Akamai
        (142, 250),  # Google
    ]
    a, b = prefixes[h % len(prefixes)]
    c = (h >> 8) % 256
    d = (h >> 16) % 256
    return f"{a}.{b}.{c}.{d}"


# ── Event container ────────────────────────────────────────────────────────────
class LogEvent:
    """Single log event with routing tag."""
    __slots__ = ("data", "source", "ts")
    def __init__(self, source: str, ts: datetime, data: dict[str, Any]):
        self.source = source
        self.ts     = ts
        self.data   = data


class DayResult:
    """All events generated for one employee on one day."""
    def __init__(self):
        self.events: list[LogEvent] = []

    def add(self, source: str, ts: datetime, data: dict[str, Any]) -> None:
        self.events.append(LogEvent(source, ts, data))

    def sorted_events(self) -> list[LogEvent]:
        return sorted(self.events, key=lambda e: e.ts)


# ════════════════════════════════════════════════════════════════════════════
# MAIN EMPLOYEE DAY
# ════════════════════════════════════════════════════════════════════════════

def simulate_employee_day(
    emp:         Employee,
    sim_date:    date,
    bus:         EventBus,
    absence_cal: AbsenceCalendar,
    rng:         random.Random,
    sim_start:   date,
) -> DayResult:
    """Simulate one full workday for a single employee."""
    result = DayResult()

    # Absence / weekend check
    if absence_cal.is_absent(sim_date):
        return result
    if not is_business_day(sim_date):
        # Weekend — only IT/Eng with <5% chance
        if emp.department not in ("IT", "Engineering") or rng.random() > 0.05:
            return result

    # Remote vs on-site
    is_remote   = rng.random() < emp.remote_fraction
    src_ip      = _session_source_ip(emp, sim_date, rng, is_remote)
    workstation = emp.workstation
    dept        = DEPARTMENTS[emp.department]
    is_it       = emp.department == "IT"
    is_mgr      = emp.is_manager
    user_sid    = _user_sid(emp.samaccountname)

    # Daily schedule
    drift   = week_drift(sim_start, sim_date, rng)
    partial = absence_cal.is_partial_day(sim_date)
    sched   = DailySchedule(
        rng, emp.login_start_mean, emp.login_start_std,
        emp.work_duration_mean, emp.work_duration_std, is_remote=is_remote,
    )
    logon_utc, logoff_utc = sched.to_datetimes(sim_date, drift, partial)
    span_secs = max(3600.0, (logoff_utc - logon_utc).total_seconds())

    # ── Kerberos TGT (4768) — seconds before logon ────────────────────────────
    # LogonGuid is shared across 4768 → 4769 → 4624 for the same authentication.
    # Create the GUID here and pass it explicitly to all three events.
    tgt_guid = bus.new_guid()
    tgt_ts   = logon_utc - timedelta(seconds=rng.randint(2, 5))
    result.add("security", tgt_ts,
               gen_4768(emp.samaccountname, src_ip, tgt_ts, bus, logon_guid=tgt_guid))

    # ── Kerberos TGS (4769) for a server this person actually uses ────────────
    tgs_server = _pick_server(emp, dept, rng)
    spn, spn_sid = _CIFS_SPNS.get(
        tgs_server,
        (f"cifs/{tgs_server}.nexovate.local", "S-1-5-21-1484628597-1684816888-3125425894-1099")
    )
    tgs_ts = tgt_ts + timedelta(seconds=rng.randint(1, 3))
    result.add("security", tgs_ts,
               gen_4769(emp.samaccountname, spn, spn_sid, src_ip, tgs_ts, bus,
                        logon_guid=tgt_guid))

    # ── Main logon session ────────────────────────────────────────────────────
    logon_type = 10 if is_remote else (7 if rng.random() < 0.08 else 2)
    session = bus.open_session(
        samaccountname=emp.samaccountname,
        domain=DOMAIN_NETBIOS,
        logon_type=logon_type,
        auth_package="Kerberos",
        src_ip=src_ip,
        src_port=bus.new_src_port(),
        workstation=workstation,
        computer=f"{workstation}.{DOMAIN_FQDN}",
        logon_time_utc=logon_utc,
        is_elevated=False,  # Standard daily-use session; admin sessions use admin_sam
        is_remote=is_remote,
        logon_guid=tgt_guid,   # match 4624 LogonGuid to the preceding 4768 TGT
    )
    result.add("security", logon_utc,
               gen_4624(session, logon_utc, bus, user_sid))
    # 4672 (Special Logon) is NOT emitted here — daily logons use standard tokens.
    # 4672 fires only for admin sessions (simulate_it_admin_day) and service accounts.

    # ── Explorer process (parent for all user-space processes) ────────────────
    exp_proc = bus.spawn_process(
        image=_EXPLORER,
        command_line=r"C:\Windows\Explorer.EXE",
        user=emp.samaccountname,
        logon_id=session.target_logon_id,
        parent_image=r"C:\Windows\System32\userinit.exe",
        parent_guid=bus.new_guid(),
        computer=session.computer,
        start_time_utc=logon_utc + timedelta(seconds=2),
        integrity_level="Medium",  # Standard user session
    )
    result.add("sysmon", logon_utc + timedelta(seconds=2),
               gen_eid1(exp_proc, DOMAIN_NETBIOS, logon_utc + timedelta(seconds=2), bus))

    # ── Benign LSASS access (Sysmon 10) ──────────────────────────────────────
    # Windows Defender / EDR queries lsass with a benign mask on every host, so
    # a real baseline exists for the LSASS-access detector. Credential dumping
    # is distinguished by an unusual *source* process and a dump-class mask,
    # not by the mere fact of touching lsass.
    for _i in range(rng.randint(1, 3)):
        acc_ts = logon_utc + timedelta(seconds=rng.randint(30, max(60, int(span_secs * 0.8))))
        if acc_ts >= logoff_utc:
            break
        defender = bus.spawn_process(
            image=r"C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe",
            command_line=r"MsMpEng.exe", user="SYSTEM",
            logon_id="0x3e7", parent_image=r"C:\Windows\System32\services.exe",
            parent_guid=bus.new_guid(), computer=session.computer,
            start_time_utc=acc_ts, integrity_level="System",
        )
        lsass_tgt = bus.spawn_process(
            image=r"C:\Windows\System32\lsass.exe",
            command_line=r"C:\Windows\system32\lsass.exe", user="SYSTEM",
            logon_id="0x3e7", parent_image=r"C:\Windows\System32\wininit.exe",
            parent_guid=bus.new_guid(), computer=session.computer,
            start_time_utc=acc_ts, integrity_level="System",
        )
        result.add("sysmon", acc_ts,
                   gen_eid10(defender, lsass_tgt, DOMAIN_NETBIOS, acc_ts, bus,
                             granted_access="0x1400"))

    # ── Occasional benign admin-tool usage (IT staff only) ───────────────────
    # Legit backup / maintenance runs vssadmin/ntdsutil/procdump so the
    # rare-process detector faces a non-empty benign baseline for these tools.
    if is_it and rng.random() < 0.10:
        tool_ts = logon_utc + timedelta(seconds=rng.randint(60, max(120, int(span_secs * 0.6))))
        if tool_ts < logoff_utc:
            tool = rng.choice([
                r"C:\Windows\System32\vssadmin.exe",
                r"C:\Windows\System32\procdump.exe",
                r"C:\Windows\System32\reg.exe",
            ])
            admin_proc = bus.spawn_process(
                image=tool, command_line=f"{_full_path(tool)} (maintenance)",
                user=emp.samaccountname, logon_id=session.target_logon_id,
                parent_image=_full_path("cmd.exe"), parent_guid=exp_proc.process_guid,
                computer=session.computer, start_time_utc=tool_ts, integrity_level="High",
            )
            result.add("sysmon", tool_ts, gen_eid1(admin_proc, DOMAIN_NETBIOS, tool_ts, bus))

    # ── Background system drivers (once per session, IT more often) ───────────
    if rng.random() < (0.6 if is_it else 0.15):
        drv_ts = logon_utc + timedelta(seconds=rng.randint(3, 15))
        drv = rng.choice([
            r"C:\Windows\System32\drivers\http.sys",
            r"C:\Windows\System32\drivers\tcpip.sys",
            r"C:\Windows\System32\drivers\storport.sys",
        ])
        result.add("sysmon", drv_ts, gen_eid6(drv, session.computer, drv_ts, bus))

    # ── WMI activity ──────────────────────────────────────────────────────────
    if rng.random() < (0.9 if is_it else 0.3):
        wmi_ts = logon_utc + timedelta(seconds=rng.randint(10, 120))
        prov_name, prov_path = rng.choice(_WMI_PROVIDERS)
        result.add("wmi", wmi_ts,
                   gen_wmi_5857(prov_name, "wmiprvse.exe",
                                rng.randint(800, 2000), prov_path,
                                session.computer, wmi_ts, bus))
        # Occasional WMI error
        if rng.random() < 0.08:
            err_ts = wmi_ts + timedelta(seconds=1)
            result.add("wmi", err_ts,
                       gen_wmi_5858(
                           f"ExecQuery - root\\cimv2 : {rng.choice(_WMI_QUERIES)}",
                           f"{DOMAIN_NETBIOS}\\{emp.samaccountname}",
                           session.computer, rng.randint(1000, 9000),
                           "0x80041032", session.computer, err_ts, bus,
                       ))

    # ── Named pipes (background OS traffic) ───────────────────────────────────
    # The machine's logon sequence touches the SAME pipes every day -- the same
    # services start, the same agents connect -- so an account's pipe set is
    # established within its first sessions and is then stable. Drawing a random
    # subset per session instead would trickle first-contact edges across the
    # whole training window, and a view whose benign edges are perpetually novel
    # carries no information (the lesson `user_src` already learned: keyed on IP
    # its benign novelty was ~92% and it was pure noise).
    #
    # So: the core set every session, plus an occasional extra for the genuinely
    # intermittent things (a printer, a VPN client, an update agent).
    emp_pipes, emp_writes = software_profile(emp)
    todays_pipes = list(emp_pipes[:5])
    if rng.random() < 0.15 and len(emp_pipes) > 5:
        todays_pipes.append(rng.choice(emp_pipes[5:]))
    for pipe_leaf in todays_pipes:
        pipe_ts   = logon_utc + timedelta(seconds=rng.randint(5, 900))
        pipe_name = rf"\\.\pipe\{pipe_leaf}"
        result.add("sysmon", pipe_ts,
                   gen_eid17(exp_proc, pipe_name, pipe_ts, bus))
        result.add("sysmon", pipe_ts + timedelta(milliseconds=rng.randint(5, 50)),
                   gen_eid18(exp_proc, pipe_name,
                             pipe_ts + timedelta(milliseconds=rng.randint(5, 50)), bus))

    # ── Process launch loop ───────────────────────────────────────────────────
    for proc_idx, exe in enumerate(_select_processes(emp, rng)):
        offset  = rng.uniform(120, max(121.0, span_secs - 60))
        proc_ts = logon_utc + timedelta(seconds=offset)
        if proc_ts >= logoff_utc:
            continue

        full_exe = _full_path(exe)
        proc = bus.spawn_process(
            image=full_exe,
            command_line=_build_cmdline(exe, rng),
            user=emp.samaccountname,
            logon_id=session.target_logon_id,
            parent_image=_EXPLORER,
            parent_guid=exp_proc.process_guid,
            computer=session.computer,
            start_time_utc=proc_ts,
            integrity_level="High" if (is_it and is_mgr) else "Medium",
        )
        result.add("sysmon", proc_ts,
                   gen_eid1(proc, DOMAIN_NETBIOS, proc_ts, bus))

        # Process termination (4689) — 30% chance
        if rng.random() < 0.3:
            term_off = rng.randint(60, int(span_secs * 0.4))
            term_ts  = proc_ts + timedelta(seconds=term_off)
            if term_ts < logoff_utc:
                result.add("security", term_ts,
                           gen_4689(session, full_exe,
                                    hex(proc.process_id), "0x0", term_ts, bus))

        # MOTW (Zone.Identifier) for downloads via browser / mail
        if exe in ("chrome.exe", "OUTLOOK.EXE") and rng.random() < 0.25:
            dl_ts  = proc_ts + timedelta(seconds=rng.randint(60, 600))
            if dl_ts < logoff_utc:
                dl_file = (fr"C:\Users\{emp.samaccountname}\Downloads"
                           fr"\{rng.choice(['setup','installer','update','report'])}"
                           fr"_{rng.randint(1,99)}.exe")
                result.add("sysmon", dl_ts,
                           gen_eid15(proc, dl_file,
                                     "[ZoneTransfer]\r\nZoneId=3\r\n"
                                     "ReferrerUrl=https://drive.google.com\r\n",
                                     dl_ts, bus))
                result.add("sysmon", dl_ts + timedelta(milliseconds=10),
                           gen_eid11(proc, dl_file, DOMAIN_NETBIOS,
                                     dl_ts + timedelta(milliseconds=10), bus))

        # Registry reads/writes (normal application activity)
        if rng.random() < 0.35:
            reg_ts  = proc_ts + timedelta(seconds=rng.randint(1, 20))
            # Cycle deterministically through this machine's own settings keys
            # rather than sampling: an application rewrites the same values on
            # each launch, so the account's registry footprint is established
            # early and stable. Sampling produced a 14.5% benign novelty rate --
            # a view whose ordinary traffic is perpetually novel cannot rank.
            reg_key, reg_val, reg_data = emp_writes[proc_idx % len(emp_writes)]
            result.add("sysmon", reg_ts,
                       gen_eid12(proc, f"{reg_key}\\{reg_val}",
                                 "CreateKey", reg_ts, bus))
            if rng.random() < 0.5:
                result.add("sysmon", reg_ts + timedelta(seconds=1),
                           gen_eid13(proc, f"{reg_key}\\{reg_val}",
                                     reg_data, reg_ts + timedelta(seconds=1), bus))

        # DNS + network for internet-facing apps
        if exe in ("chrome.exe", "Teams.exe", "Zoom.exe", "Slack.exe", "slack.exe"):
            for domain in rng.sample(dept.dns_domains, min(3, len(dept.dns_domains))):
                dns_ts = proc_ts + timedelta(seconds=rng.randint(5, 120))
                if dns_ts >= logoff_utc:
                    break
                resolved = _fake_ext_ip(domain)
                # Sysmon EID 22 (per-process DNS)
                result.add("sysmon", dns_ts,
                           gen_eid22(proc, domain, resolved, DOMAIN_NETBIOS, dns_ts, bus))
                # DNS server analytical logs (EID 256 + 257 pair)
                # QTYPE diversity: most queries are A (85%), but real environments
                # also have AAAA (8%), MX (3%), TXT (2%), CNAME (1%), NS (1%)
                # per NXLog capture format
                qtype_roll = rng.random()
                if qtype_roll < 0.85:
                    qtype_name = "A"
                elif qtype_roll < 0.93:
                    qtype_name = "AAAA"
                elif qtype_roll < 0.96:
                    qtype_name = "MX"
                elif qtype_roll < 0.98:
                    qtype_name = "TXT"
                elif qtype_roll < 0.99:
                    qtype_name = "CNAME"
                else:
                    qtype_name = "NS"
                result.add("dns", dns_ts,
                           gen_dns_256(src_ip, domain, DNS_FQDN, DNS_IP, dns_ts, bus,
                                       qtype=qtype_name))
                resp_ts = dns_ts + timedelta(milliseconds=rng.randint(5, 50))
                result.add("dns", resp_ts,
                           gen_dns_257(src_ip, domain, DNS_FQDN, DNS_IP,
                                       resolved, resp_ts, bus, qtype=qtype_name))
                # Network connection (EID 3) after DNS resolution
                conn_ts = dns_ts + timedelta(seconds=rng.randint(1, 5))
                if conn_ts < logoff_utc:
                    result.add("sysmon", conn_ts,
                               gen_eid3(proc, DOMAIN_NETBIOS, resolved, 443,
                                        domain, conn_ts, bus, src_ip=src_ip))

    # ── File share access (5140 + 5145 + 4656 → 4663 → 4658) ────────────────
    if emp.department in _DEPT_SHARES and rng.random() < 0.65:
        share_name, share_path, share_server = _DEPT_SHARES[emp.department]
        srv_fqdn = f"{share_server}.{DOMAIN_FQDN}"
        fs_ts    = random_ts_in_session(rng, logon_utc, logoff_utc, "morning")

        # DNS for file server
        result.add("dns", fs_ts - timedelta(seconds=2),
                   gen_dns_256(src_ip, f"{share_server}.nexovate.local",
                               DNS_FQDN, DNS_IP,
                               fs_ts - timedelta(seconds=2), bus))

        # 4769 TGS for the share server (Kerberos auth to file server)
        if share_server in _CIFS_SPNS:
            fspn, fspn_sid = _CIFS_SPNS[share_server]
            result.add("security", fs_ts - timedelta(seconds=1),
                       gen_4769(emp.samaccountname, fspn, fspn_sid,
                                src_ip, fs_ts - timedelta(seconds=1), bus))

        result.add("security", fs_ts,
                   gen_5140(session, share_name, share_path,
                             src_ip, fs_ts, bus, share_server=srv_fqdn))

        files = _DEPT_FILES.get(emp.department, ["data.xlsx"])
        for fname in rng.sample(files, min(rng.randint(1, 3), len(files))):
            f_ts = fs_ts + timedelta(seconds=rng.randint(5, 120))
            if f_ts >= logoff_utc:
                break
            result.add("security", f_ts,
                       gen_5145(session, share_name, fname,
                                src_ip, f_ts, bus, share_server=srv_fqdn))
            # Object access sequence: 4656 → 4663 → 4658
            if rng.random() < 0.45:
                handle_id = hex(rng.randint(0x100, 0xFFF))
                obj_path  = f"{share_path}\\{fname}"
                result.add("security", f_ts + timedelta(milliseconds=10),
                           gen_4656(session, obj_path, "File", "0x12019f",
                                    handle_id, f_ts + timedelta(milliseconds=10), bus))
                result.add("security", f_ts + timedelta(milliseconds=20),
                           gen_4663(session, obj_path, "File", "0x1",
                                    handle_id, f_ts + timedelta(milliseconds=20), bus))
                result.add("security", f_ts + timedelta(milliseconds=50),
                           gen_4658(session, obj_path, handle_id,
                                    f_ts + timedelta(milliseconds=50), bus))

    # ── Additional TGS for other servers accessed during day ──────────────────
    if len(dept.server_access) > 1 and rng.random() < 0.5:
        extra = _pick_server(emp, dept, rng)
        if extra in _CIFS_SPNS:
            espn, espn_sid = _CIFS_SPNS[extra]
            srv_ts = random_ts_in_session(rng, logon_utc, logoff_utc, "afternoon")
            result.add("security", srv_ts,
                       gen_4769(emp.samaccountname, espn, espn_sid,
                                src_ip, srv_ts, bus))

    # ── PowerShell activity ───────────────────────────────────────────────────
    ps_per_day = dept.ps_scripts_per_week / 5.0
    n_ps       = max(0, int(rng.gauss(ps_per_day, max(0.3, ps_per_day * 0.5))))
    if n_ps > 0 and dept.uses_powershell:
        ps_scripts = _PS_SCRIPTS.get(emp.department, _PS_SCRIPTS["Engineering"])
        ps_pid     = rng.randint(2000, 9000)
        runspace   = bus.new_guid()
        ps_path    = _full_path("powershell.exe")
        for _ in range(min(n_ps, len(ps_scripts))):
            script_text, script_path = rng.choice(ps_scripts)
            ps_ts = random_ts_in_session(rng, logon_utc, logoff_utc)
            if ps_ts >= logoff_utc:
                continue
            sb_id = bus.new_guid()
            result.add("powershell", ps_ts,
                       gen_ps_4104(session.computer, emp.samaccountname, user_sid,
                                   script_text, sb_id, ps_ts, bus,
                                   path=script_path, process_id=ps_pid,
                                   activity_id=runspace))
            result.add("powershell", ps_ts + timedelta(seconds=rng.randint(1, 30)),
                       gen_ps_4103(session.computer, emp.samaccountname, user_sid,
                                   script_text.split()[0],
                                   f"Command completed: {script_text[:80]}",
                                   runspace,
                                   ps_ts + timedelta(seconds=rng.randint(1, 30)),
                                   bus, process_id=ps_pid, activity_id=runspace))
            # PS process in Sysmon (correlated to same logon session)
            ps_proc = bus.spawn_process(
                image=ps_path,
                command_line=f"{ps_path} -NonInteractive -ExecutionPolicy Bypass",
                user=emp.samaccountname,
                logon_id=session.target_logon_id,
                parent_image=_EXPLORER,
                parent_guid=exp_proc.process_guid,
                computer=session.computer,
                start_time_utc=ps_ts,
                integrity_level="High" if (is_it and is_mgr) else "Medium",
            )
            result.add("sysmon", ps_ts,
                       gen_eid1(ps_proc, DOMAIN_NETBIOS, ps_ts, bus))

    # ── Scheduled tasks (IT only) ─────────────────────────────────────────────
    if is_it and rng.random() < 0.15:
        _emit_scheduled_task(emp, session, bus, result, rng, logon_utc, logoff_utc)

    # ── USB device (rare — ~2% of days) ──────────────────────────────────────
    if rng.random() < 0.02:
        usb_ts = random_ts_in_session(rng, logon_utc, logoff_utc)
        dev_id, dev_desc, class_id, class_name = rng.choice(_USB_DEVICES)
        result.add("security", usb_ts,
                   gen_6416(session, dev_id, dev_desc, class_id, class_name,
                             usb_ts, bus))

    # ── Service state noise (background OS) ───────────────────────────────────
    if rng.random() < 0.25:
        svc_ts = logon_utc + timedelta(seconds=rng.randint(30, 300))
        svc    = rng.choice(["Spooler", "wuauserv", "Schedule", "EventLog"])
        result.add("security", svc_ts,
                   gen_7036(svc, "running", session.computer, svc_ts, bus))

    # ── Account lockout (rare — ~0.5% of days) ────────────────────────────────
    if rng.random() < 0.005:
        lock_ts = random_ts_in_session(rng, logon_utc, logoff_utc)
        # Use 4771 (Kerberos pre-auth failure) for Kerberos logons,
        # 4625 + 4776 (NTLM) for NTLM logons — realistic protocol split
        use_ntlm = rng.random() < 0.3  # 30% of lockouts via NTLM spray
        for i in range(rng.randint(3, 7)):
            ts_i = lock_ts + timedelta(seconds=i * 2)
            if use_ntlm:
                # NTLM path: 4625 + 4776 on DC
                result.add("security", ts_i,
                           gen_4625(emp.samaccountname, src_ip,
                                    f"{workstation}.{DOMAIN_FQDN}", 3,
                                    ts_i, bus, sub_status="0xc000006a",
                                    auth_package="NTLM"))
                result.add("security", ts_i + timedelta(milliseconds=50),
                           gen_4776(emp.samaccountname, workstation,
                                    ts_i + timedelta(milliseconds=50), bus,
                                    status="0xc000006a"))
            else:
                # Kerberos path: 4771 (pre-auth failure) on DC
                result.add("security", ts_i,
                           gen_4771(emp.samaccountname, src_ip, ts_i, bus,
                                    status="0x18"))  # 0x18 = wrong password
        result.add("security", lock_ts + timedelta(seconds=20),
                   gen_4740(emp.samaccountname, workstation,
                             lock_ts + timedelta(seconds=20), bus))

    # ── Logoff: 4647 (interactive) then 4634 ─────────────────────────────────
    if logon_type in (2, 10):
        result.add("security", logoff_utc - timedelta(seconds=2),
                   gen_4647(session, logoff_utc - timedelta(seconds=2), bus))
    result.add("security", logoff_utc, gen_4634(session, logoff_utc, bus))
    bus.close_session(session.target_logon_id)
    return result


# ════════════════════════════════════════════════════════════════════════════
# IT ADMIN DAY — elevated administrative operations
# ════════════════════════════════════════════════════════════════════════════

def simulate_it_admin_day(
    emp:       Employee,
    sim_date:  date,
    bus:       EventBus,
    rng:       random.Random,
    sim_start: date,
    roster:    list[Employee] | None = None,
) -> DayResult:
    """Elevated admin operations using named tiered admin account (emp.admin_sam).
    Targets real roster employees for password resets and account ops so that
    entity resolution graphs remain internally consistent."""
    result = DayResult()
    if not is_business_day(sim_date):
        return result

    admin_sam = emp.admin_sam or emp.samaccountname
    logon_ts  = local_to_utc(
        _float_hour_to_datetime(sim_date, rng.gauss(9.0, 0.5)), sim_date
    )
    logoff_ts = logon_ts + timedelta(hours=max(1.0, rng.gauss(2.0, 0.5)))

    # Kerberos TGT (4768) before admin logon — same LogonGuid chain as employee sessions
    adm_tgt_guid = bus.new_guid()
    tgt_ts       = logon_ts - timedelta(seconds=rng.randint(2, 5))
    result.add("security", tgt_ts,
               gen_4768(admin_sam, emp.workstation_ip, tgt_ts, bus, logon_guid=adm_tgt_guid))
    tgs_ts = tgt_ts + timedelta(seconds=rng.randint(1, 3))
    result.add("security", tgs_ts,
               gen_4769(admin_sam, f"TERMSRV/JUMP01.{DOMAIN_FQDN}",
                        "S-1-5-21-1484628597-1684816888-3125425894-1104",
                        emp.workstation_ip, tgs_ts, bus, logon_guid=adm_tgt_guid))

    session = bus.open_session(
        samaccountname=admin_sam, domain=DOMAIN_NETBIOS,
        logon_type=10, auth_package="Kerberos",
        src_ip=emp.workstation_ip, src_port=bus.new_src_port(),
        workstation=emp.workstation,
        computer=f"JUMP01.{DOMAIN_FQDN}",
        logon_time_utc=logon_ts, is_elevated=True,
        logon_guid=adm_tgt_guid,   # match 4624 LogonGuid to the preceding 4768 TGT
    )
    result.add("security", logon_ts, gen_4624(session, logon_ts, bus, _user_sid(admin_sam)))
    result.add("security", logon_ts + timedelta(milliseconds=50),
               gen_4672(session, logon_ts + timedelta(milliseconds=50), bus))

    # Password reset for a user (15% chance each admin day)
    if rng.random() < 0.15 and roster:
        target_emp = rng.choice(roster)
        target     = target_emp.samaccountname
        op_ts      = logon_ts + timedelta(minutes=rng.randint(5, 40))
        result.add("security", op_ts, gen_4724(session, target, op_ts, bus))
        result.add("security", op_ts + timedelta(seconds=1),
                   gen_4738(session, target, "%%2050", op_ts + timedelta(seconds=1), bus))

    # Enable/disable account (8% chance)
    if rng.random() < 0.08 and roster:
        target_emp = rng.choice(roster)
        target     = target_emp.samaccountname
        op_ts      = logon_ts + timedelta(minutes=rng.randint(10, 50))
        result.add("security", op_ts,
                   gen_4722(session, target, op_ts, bus)
                   if rng.random() < 0.5 else
                   gen_4725(session, target, op_ts, bus))

    # Service installation (4% chance — SCCM/patch deployment)
    if rng.random() < 0.04:
        svc_ts = logon_ts + timedelta(minutes=rng.randint(20, 60))
        result.add("security", svc_ts,
                   gen_4697(session, "NexoPatchAgent",
                             r"C:\Windows\NexoPatch\agent.exe",
                             "0x10", "2", "LocalSystem", svc_ts, bus))
        result.add("security", svc_ts + timedelta(seconds=1),
                   gen_7045("NexoPatchAgent",
                             r"C:\Windows\NexoPatch\agent.exe",
                             "own process", "auto start", "LocalSystem",
                             f"JUMP01.{DOMAIN_FQDN}", svc_ts + timedelta(seconds=1), bus))
        result.add("security", svc_ts + timedelta(seconds=5),
                   gen_7036("NexoPatchAgent", "running",
                             f"JUMP01.{DOMAIN_FQDN}", svc_ts + timedelta(seconds=5), bus))

    # Audit policy change (2% — IT compliance)
    if rng.random() < 0.02:
        pol_ts = logon_ts + timedelta(minutes=rng.randint(30, 80))
        result.add("security", pol_ts,
                   gen_4719(session, "%%8272", "%%13312",
                             "%%8449 %%8451", pol_ts, bus))

    # SACL update on a sensitive path (2%)
    if rng.random() < 0.02:
        sacl_ts = logon_ts + timedelta(minutes=rng.randint(40, 90))
        result.add("security", sacl_ts,
                   gen_4907(session,
                             r"C:\Windows\System32\winevt\Logs\Security.evtx",
                             "D:(D;;FA;;;S-1-1-0)", "D:(A;;FA;;;WD)(A;;FA;;;BA)",
                             sacl_ts, bus))

    result.add("security", logoff_ts - timedelta(seconds=2),
               gen_4647(session, logoff_ts - timedelta(seconds=2), bus))
    result.add("security", logoff_ts, gen_4634(session, logoff_ts, bus))
    bus.close_session(session.target_logon_id)
    return result


# ════════════════════════════════════════════════════════════════════════════
# SERVICE ACCOUNT DAY
# ════════════════════════════════════════════════════════════════════════════

def simulate_service_account_day(
    svc:      ServiceAccount,
    sim_date: date,
    bus:      EventBus,
    rng:      random.Random,
) -> DayResult:
    """Service accounts: Type-5 logons at scheduled maintenance windows."""
    result = DayResult()
    _SCHEDULES: dict[str, tuple[str, str]] = {
        "svc_sql_engine":  ("backup",          r"C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Binn\sqlservr.exe"),
        "svc_sql_agent":   ("sql_maintenance",  r"C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Binn\SQLAGENT.EXE"),
        "svc_backup":      ("backup",           r"C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Service.exe"),
        "svc_sccm_client": ("sccm",             r"C:\Windows\CCM\CcmExec.exe"),
        "svc_monitor":     ("monitoring",       r"C:\Program Files\Monitoring\agent.exe"),
        "svc_iis_apppool": ("monitoring",       r"C:\Windows\System32\inetsrv\w3wp.exe"),
        "svc_exchange":    ("monitoring",       r"C:\Program Files\Microsoft\Exchange Server\V15\Bin\MSExchangeServiceHost.exe"),
    }
    sched_type, _ = _SCHEDULES.get(svc.samaccountname, ("backup", ""))

    for _ in range(rng.randint(1, 3)):
        logon_ts  = service_account_ts(rng, sim_date, sched_type)
        logoff_ts = logon_ts + timedelta(minutes=rng.randint(5, 60))
        session   = bus.open_session(
            samaccountname=svc.samaccountname, domain=DOMAIN_NETBIOS,
            logon_type=5, auth_package="Kerberos",
            src_ip=svc.server_ip, src_port=0,
            workstation=svc.server_hostname,
            computer=f"{svc.server_hostname}.{DOMAIN_FQDN}",
            logon_time_utc=logon_ts, is_elevated=True,
        )
        result.add("security", logon_ts,
                   gen_4624(session, logon_ts, bus, _user_sid(svc.samaccountname)))
        result.add("security", logon_ts + timedelta(milliseconds=20),
                   gen_4672(session, logon_ts + timedelta(milliseconds=20), bus,
                             "SeBackupPrivilege\nSeRestorePrivilege\nSeDebugPrivilege"))
        result.add("security", logon_ts + timedelta(seconds=2),
                   gen_7036(svc.samaccountname.replace("svc_", "").title(),
                             "running", f"{svc.server_hostname}.{DOMAIN_FQDN}",
                             logon_ts + timedelta(seconds=2), bus))
        # Kerberos service tickets for the resource this account exists to drive.
        # A service account that touches a SQL instance, a share or a mailbox
        # requests a TGS for it exactly as a person would; omitting this left
        # service accounts with no ticketing history at all, which is both
        # unrealistic and misleading for evaluation -- it made *any* service-ticket
        # request by a service account a novel relationship, so a compromised
        # credential doing ordinary work looked anomalous for the wrong reason.
        spn, spn_sid = _CIFS_SPNS.get(
            svc.server_hostname,
            (f"cifs/{svc.server_hostname}.{DOMAIN_FQDN}",
             "S-1-5-21-1484628597-1684816888-3125425894-1099"))
        for _ in range(rng.randint(2, 6)):
            tgs_ts = logon_ts + timedelta(seconds=rng.randint(3, 240))
            result.add("security", tgs_ts,
                       gen_4769(svc.samaccountname, spn, spn_sid,
                                svc.server_ip, tgs_ts, bus))
        # WMI from service (monitoring agents query system state)
        if rng.random() < 0.5:
            wmi_ts = logon_ts + timedelta(seconds=rng.randint(10, 60))
            prov_name, prov_path = rng.choice(_WMI_PROVIDERS)
            result.add("wmi", wmi_ts,
                       gen_wmi_5857(prov_name, "wmiprvse.exe",
                                    rng.randint(800, 2000), prov_path,
                                    f"{svc.server_hostname}.{DOMAIN_FQDN}", wmi_ts, bus))
        result.add("security", logoff_ts, gen_4634(session, logoff_ts, bus))
        bus.close_session(session.target_logon_id)
    return result


# ════════════════════════════════════════════════════════════════════════════
# LIFECYCLE EVENTS — onboarding, offboarding, transfers
# ════════════════════════════════════════════════════════════════════════════

# Share of server accesses that fall outside a person's usual working set: a new
# project share, covering for a colleague, a one-off request. Real access follows
# a stable per-person working set with a long tail rather than a department-wide
# constant, and that tail is the benign novelty a detector must tolerate.
_SERVER_EXPLORE_RATE = 0.06


def _personal_servers(emp, dept) -> list[str]:
    """The stable subset of departmental servers this person actually uses.

    Derived deterministically from the account name, so it is the same every day
    for the same person without needing to be stored. Giving every member of a
    department an identical server list makes host-to-host edges deterministic by
    construction, which is not how an estate behaves and which distorts any
    measurement of relationship views (see docs/evaluation.md).
    """
    servers = list(dept.server_access)
    if len(servers) <= 1:
        return servers
    personal = random.Random(f"servers:{emp.samaccountname}")
    # Most people work against a small, stable handful even when their department
    # is entitled to more.
    size = min(len(servers), personal.randint(1, max(2, (len(servers) + 1) // 2)))
    return personal.sample(servers, size)


def _pick_server(emp, dept, rng: random.Random) -> str:
    """Choose a destination server for one access."""
    servers = list(dept.server_access)
    if not servers:
        return "DC01"
    usual = _personal_servers(emp, dept)
    outside = [s for s in servers if s not in usual]
    if outside and rng.random() < _SERVER_EXPLORE_RATE:
        return rng.choice(outside)
    return rng.choice(usual) if usual else rng.choice(servers)


_DHCP_LEASE_DAYS = 4          # how long a device keeps its address
_WIFI_FRACTION = 0.25         # share of on-site days spent on corporate Wi-Fi


def _session_source_ip(emp, sim_date: date, rng: random.Random, is_remote: bool) -> str:
    """The address a session originates from, with realistic churn.

    A fixed address per employee for the life of a run is the single most
    unrealistic thing a synthetic estate can do to an authentication-graph
    detector: it makes a novel (account, source) edge almost impossible in benign
    traffic, which silently flatters any novelty-based detection and turns the
    reported false-positive rate into a floor. Real estates churn constantly:

      * VPN concentrators hand out whatever address is free, so a user's remote
        address differs session to session;
      * DHCP leases expire, so an on-site device's address changes every few days;
      * the same laptop appears on wired and Wi-Fi ranges.

    Addresses therefore churn while the *device* identity stays stable -- which is
    why the detector keys its source edges on the workstation name and falls back
    to the address only when no device name is present.
    """
    if is_remote and emp.vpn_ip:
        # Pool assignment: a different address each remote session.
        return f"{NETWORK_RANGES['vpn']}{rng.randint(10, 200)}"
    if rng.random() < _WIFI_FRACTION:
        return f"{NETWORK_RANGES['wifi']}{rng.randint(1, 100)}"
    # Wired: a DHCP lease that is stable within a lease window and rotates
    # between them. Deterministic in (employee, lease epoch) so a run reproduces.
    epoch = sim_date.toordinal() // _DHCP_LEASE_DAYS
    h = stable_seed(0xD4CB, f"{emp.samaccountname}:{epoch}")
    return f"{NETWORK_RANGES['workstations']}{2 + (h % 250)}"


def simulate_routine_group_management(
    it_admins: list[Employee],
    roster:    list[Employee],
    sim_date:  date,
    bus:       EventBus,
    rng:       random.Random,
) -> DayResult:
    """Benign, high-frequency directory access management.

    Real estates generate a steady stream of security-group membership changes
    every business day -- access requests, project onboarding, resource
    grants -- performed by helpdesk/Tier-2 admins against ordinary department
    and file-share groups. The original simulator emitted almost none (only a
    weekly onboarding add), which left the authentication graph's directory view
    with no baseline: the FIRST group change it ever saw was an attacker adding
    themselves to Domain Admins, and with no baseline a novelty scorer stays
    silent (cold start scores ~0).

    Modelling this routine churn is both more faithful and what lets
    account-manipulation detection generalise: once the graph has learned that
    admins routinely add members to GG-Dept-* / DL-FileShare-* groups, an add to
    a Tier-0 group nobody has ever touched is a novel edge to a rare destination
    and scores high -- with no group allow/deny list anywhere in the detector.
    """
    result = DayResult()
    if not is_business_day(sim_date) or not it_admins or not roster or not _ROUTINE_GROUPS:
        return result

    admin = rng.choice(it_admins)
    if not admin.admin_sam:
        from config.company import ADMIN_ACCOUNTS as _ADMIN_ACCOUNTS
        idx = it_admins.index(admin) if admin in it_admins else 0
        admin.admin_sam = _ADMIN_ACCOUNTS[idx % len(_ADMIN_ACCOUNTS)]["samaccountname"]
    admin_sam = admin.admin_sam

    op_ts = local_to_utc(_float_hour_to_datetime(sim_date, rng.gauss(11.0, 2.0)), sim_date)
    tgt_guid = bus.new_guid()
    tgt_ts = op_ts - timedelta(seconds=rng.randint(2, 5))
    result.add("security", tgt_ts,
               gen_4768(admin_sam, admin.workstation_ip, tgt_ts, bus, logon_guid=tgt_guid))
    session = bus.open_session(
        samaccountname=admin_sam, domain=DOMAIN_NETBIOS,
        logon_type=2, auth_package="Kerberos",
        src_ip=admin.workstation_ip, src_port=bus.new_src_port(),
        workstation=admin.workstation, computer=f"{admin.workstation}.{DOMAIN_FQDN}",
        logon_time_utc=op_ts, is_elevated=True, logon_guid=tgt_guid,
    )
    result.add("security", op_ts, gen_4624(session, op_ts, bus, _user_sid(admin_sam)))
    result.add("security", op_ts + timedelta(milliseconds=30),
               gen_4672(session, op_ts + timedelta(milliseconds=30), bus))

    for _ in range(rng.randint(3, 9)):
        t = op_ts + timedelta(minutes=rng.uniform(1, 360))
        emp = rng.choice(roster)
        grp = rng.choice(_ROUTINE_GROUPS)
        result.add("security", t, gen_group_change(
            session, emp.samaccountname,
            f"CN={emp.samaccountname},OU=Users,DC=NEXOVATE,DC=local",
            grp, _GROUP_SID[grp], t, bus, "4728"))
    return result


def simulate_lifecycle_events(
    it_admins: list[Employee],
    roster:    list[Employee],
    sim_date:  date,
    bus:       EventBus,
    rng:       random.Random,
) -> DayResult:
    """
    Realistic identity lifecycle: onboarding, offboarding, password resets,
    department transfers, computer account rotations.
    Runs once per simulation week.
    """
    result = DayResult()
    if not is_business_day(sim_date) or not it_admins:
        return result

    admin     = rng.choice(it_admins)
    # Lifecycle operations (account creation, password resets, group changes)
    # are privileged AD actions and must always run under a named tiered admin
    # account — never under the employee's personal daily-use SAM. If this
    # employee hasn't been assigned an admin_sam yet (no admin-day has fired
    # for them this run), assign one deterministically from ADMIN_ACCOUNTS so
    # the SID/identity stays consistent with what later admin-days will use.
    if not admin.admin_sam:
        from config.company import ADMIN_ACCOUNTS as _ADMIN_ACCOUNTS
        idx = it_admins.index(admin) if admin in it_admins else 0
        admin.admin_sam = _ADMIN_ACCOUNTS[idx % len(_ADMIN_ACCOUNTS)]["samaccountname"]
    admin_sam = admin.admin_sam
    op_ts     = local_to_utc(
        _float_hour_to_datetime(sim_date, rng.gauss(9.5, 0.5)), sim_date
    )

    # Kerberos TGT (4768) before the privileged logon — same LogonGuid chain
    # used by simulate_it_admin_day, so every admin-tier interactive session
    # is traceable back to its AS-REQ regardless of which function emitted it.
    lc_tgt_guid = bus.new_guid()
    lc_tgt_ts   = op_ts - timedelta(seconds=rng.randint(2, 5))
    result.add("security", lc_tgt_ts,
               gen_4768(admin_sam, admin.workstation_ip, lc_tgt_ts, bus, logon_guid=lc_tgt_guid))
    lc_tgs_ts = lc_tgt_ts + timedelta(seconds=rng.randint(1, 3))
    result.add("security", lc_tgs_ts,
               gen_4769(admin_sam, f"cifs/{admin.workstation}.{DOMAIN_FQDN}",
                        "S-1-5-21-1484628597-1684816888-3125425894-1101",
                        admin.workstation_ip, lc_tgs_ts, bus, logon_guid=lc_tgt_guid))

    session = bus.open_session(
        samaccountname=admin_sam, domain=DOMAIN_NETBIOS,
        logon_type=2, auth_package="Kerberos",
        src_ip=admin.workstation_ip, src_port=bus.new_src_port(),
        workstation=admin.workstation,
        computer=f"{admin.workstation}.{DOMAIN_FQDN}",
        logon_time_utc=op_ts, is_elevated=True,
        logon_guid=lc_tgt_guid,
    )
    result.add("security", op_ts, gen_4624(session, op_ts, bus, _user_sid(admin_sam)))
    result.add("security", op_ts + timedelta(milliseconds=30),
               gen_4672(session, op_ts + timedelta(milliseconds=30), bus))

    t = op_ts + timedelta(minutes=2)

    # Onboarding: new employee (15% weekly chance)
    if rng.random() < 0.15:
        fn = rng.choice(["Rahul", "Priya", "Amit", "Sunita", "Arjun",
                          "Meena", "Vikram", "Deepa", "Kiran", "Sneha"])
        ln = rng.choice(["Sharma", "Verma", "Singh", "Gupta", "Patel",
                          "Nair", "Reddy", "Joshi", "Kumar", "Rao"])
        new_sam = (fn[0] + ln).lower()[:18]
        new_dn  = f"CN={fn} {ln},OU=Engineering,OU=Users,DC=NEXOVATE,DC=local"
        result.add("security", t, gen_4720(session, new_sam, f"{fn} {ln}", t, bus))
        t += timedelta(seconds=2)
        result.add("security", t, gen_4722(session, new_sam, t, bus))
        t += timedelta(seconds=2)
        result.add("security", t, gen_4724(session, new_sam, t, bus))
        t += timedelta(seconds=2)
        result.add("security", t,
                   gen_group_change(session, new_sam, new_dn,
                                    "GG-Dept-Engineering",
                                    "S-1-5-21-1484628597-1684816888-3125425894-1201",
                                    t, bus, "4728"))
        t += timedelta(minutes=3)
        # Provision new computer
        comp_sam = f"WSENG{rng.randint(51, 80):02d}$"
        comp_dns = f"{comp_sam[:-1].lower()}.nexovate.local"
        result.add("security", t, gen_4741(session, comp_sam, comp_dns, t, bus))
        result.add("security", t + timedelta(seconds=5),
                   gen_4742(session, comp_sam, t + timedelta(seconds=5), bus))

    # Offboarding: employee exits (7% weekly)
    if rng.random() < 0.07 and roster:
        target_emp = rng.choice(roster)
        t2 = op_ts + timedelta(minutes=rng.randint(15, 45))
        result.add("security", t2, gen_4725(session, target_emp.samaccountname, t2, bus))
        t2 += timedelta(seconds=5)
        result.add("security", t2,
                   gen_4729(session, target_emp.samaccountname,
                             f"CN={target_emp.display_name},{target_emp.ou_path}",
                             f"GG-Dept-{target_emp.department}", t2, bus))
        t2 += timedelta(minutes=2)
        result.add("security", t2, gen_4726(session, target_emp.samaccountname, t2, bus))
        t2 += timedelta(minutes=3)
        result.add("security", t2, gen_4743(session, target_emp.workstation + "$", t2, bus))

    # Department transfer (4% weekly)
    if rng.random() < 0.04 and roster:
        target_emp = rng.choice(roster)
        t3         = op_ts + timedelta(minutes=rng.randint(30, 70))
        result.add("security", t3,
                   gen_4738(session, target_emp.samaccountname,
                             "%%2050\n\t\t\t\tDepartment changed", t3, bus))
        result.add("security", t3 + timedelta(seconds=5),
                   gen_4729(session, target_emp.samaccountname,
                             f"CN={target_emp.display_name},{target_emp.ou_path}",
                             f"GG-Dept-{target_emp.department}",
                             t3 + timedelta(seconds=5), bus))
        new_dept = rng.choice([d for d in DEPARTMENTS if d != target_emp.department])
        result.add("security", t3 + timedelta(seconds=10),
                   gen_group_change(session, target_emp.samaccountname,
                                    f"CN={target_emp.display_name},{target_emp.ou_path}",
                                    f"GG-Dept-{new_dept}",
                                    "S-1-5-21-1484628597-1684816888-3125425894-1250",
                                    t3 + timedelta(seconds=10), bus, "4728"))

    # Password resets (20% weekly — helpdesk requests)
    if rng.random() < 0.20 and roster:
        target_emp = rng.choice(roster)
        t4         = op_ts + timedelta(minutes=rng.randint(10, 60))
        result.add("security", t4, gen_4724(session, target_emp.samaccountname, t4, bus))
        result.add("security", t4 + timedelta(seconds=2),
                   gen_4738(session, target_emp.samaccountname,
                             "%%2050", t4 + timedelta(seconds=2), bus))

    # Computer account machine-password rotations (every ~30 days, automated)
    for _ in range(rng.randint(2, 5)):
        dept_prefix = rng.choice(["WSENG", "WSFIN", "WSHR", "WSSLS", "WSIT"])
        cname  = f"{dept_prefix}{rng.randint(1, 50):02d}$"
        t5     = op_ts + timedelta(minutes=rng.randint(1, 100))
        result.add("security", t5,
                   gen_4742(session, cname, t5, bus,
                             change_desc="%%2050\n\t\t\t\tMachine password rotated automatically"))

    result.add("security", op_ts + timedelta(hours=2),
               gen_4634(session, op_ts + timedelta(hours=2), bus))
    bus.close_session(session.target_logon_id)
    return result


# ════════════════════════════════════════════════════════════════════════════
# DEFENDER EVENTS (very rare)
# ════════════════════════════════════════════════════════════════════════════

def simulate_defender_event(
    emp:      Employee,
    sim_date: date,
    bus:      EventBus,
    rng:      random.Random,
) -> DayResult:
    """Rare Defender detection: 1116 (detected) then 1117 (quarantined)."""
    result   = DayResult()
    computer = f"{emp.workstation}.{DOMAIN_FQDN}"
    ts       = local_to_utc(
        _float_hour_to_datetime(sim_date, rng.gauss(11, 2)), sim_date
    )
    threat_name, severity, category, path = rng.choice(_DEFENDER_THREATS)
    user_ctx  = f"{DOMAIN_NETBIOS}\\{emp.samaccountname}"
    threat_id = str(rng.randint(2000, 9999))
    result.add("defender", ts,
               gen_defender_1116(threat_name, severity, category, path,
                                  user_ctx, r"C:\Windows\explorer.exe",
                                  computer, ts, bus, threat_id=threat_id))
    action_ts = ts + timedelta(seconds=rng.randint(2, 10))
    result.add("defender", action_ts,
               gen_defender_1117(threat_name, severity, category, path,
                                  "2", computer, action_ts, bus,
                                  threat_id=threat_id))
    return result


# ════════════════════════════════════════════════════════════════════════════
# SCHEDULED TASK HELPER
# ════════════════════════════════════════════════════════════════════════════

def _emit_scheduled_task(
    emp:       Employee,
    session:   LogonSession,
    bus:       EventBus,
    result:    DayResult,
    rng:       random.Random,
    logon_utc: datetime,
    logoff_utc:datetime,
) -> None:
    _IT_TASKS: list[tuple[str, str, str]] = [
        (r"\NEXOVATE\IT\DiskReport",
         r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         r"-NonInteractive -File C:\Scripts\disk-report.ps1"),
        (r"\NEXOVATE\IT\StaleAccounts",
         r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         r"-NonInteractive -File C:\Scripts\stale-accounts.ps1"),
        (r"\NEXOVATE\IT\EventLogBackup",
         r"C:\Windows\System32\wevtutil.exe",
         r"epl Security C:\Backups\Security.evtx"),
        (r"\NEXOVATE\IT\PatchReport",
         r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         r"-NonInteractive -File C:\Scripts\wsus-report.ps1"),
    ]
    task_name, command, args = rng.choice(_IT_TASKS)
    task_ts     = logon_utc + timedelta(seconds=rng.randint(30, 1800))
    if task_ts >= logoff_utc:
        task_ts = logon_utc + timedelta(seconds=30)
    instance_id = bus.new_guid()
    xml         = build_task_content_xml(task_name, command, args,
                                          run_as_user=emp.samaccountname)
    result.add("task_scheduler", task_ts,
               gen_task_106(task_name, f"{DOMAIN_NETBIOS}\\{emp.samaccountname}",
                             session.computer, task_ts, bus))
    result.add("security", task_ts + timedelta(seconds=1),
               gen_task_4698(session, task_name, xml,
                              task_ts + timedelta(seconds=1), bus))
    result.add("task_scheduler", task_ts + timedelta(seconds=5),
               gen_task_200(task_name, f"{command} {args}", instance_id,
                             session.computer, task_ts + timedelta(seconds=5), bus))
    result.add("task_scheduler", task_ts + timedelta(seconds=rng.randint(30, 180)),
               gen_task_201(task_name, f"{command} {args}", instance_id, "0",
                             session.computer,
                             task_ts + timedelta(seconds=rng.randint(30, 180)), bus))

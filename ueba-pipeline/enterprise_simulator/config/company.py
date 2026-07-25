"""
company.py — Single source of truth for the synthetic enterprise.

Company:    Nexovate Solutions Pvt. Ltd.
Location:   Bangalore, Karnataka, India
Industry:   B2B Enterprise Software (SaaS + On-premise)
Size:       253 employees (9 departments)
Domain:     nexovate.local (internal AD) / nexovatetech.in (external)

Network:    10.10.0.0/16 — Bangalore HQ, per-VLAN /24 segmentation.
  Workstation VLAN uses cumulative department offsets so no two employees
  share an IP across departments.

Timezone:   IST = UTC+5:30 (fixed, NO Daylight Saving Time ever)
  Source: timeanddate.com — "India and Sri Lanka do not use DST"
  Business hours: 09:00–18:30 IST = 03:30–13:00 UTC

Public egress IPs use realistic Indian ISP / cloud ranges:
  Tata Communications (AS4755): 203.101.224.0/19
  BSNL Broadband (AS9829):      125.16.0.0/13
  Jio Corporate Leased Line:    49.44.0.0/14 (approximate allocation)
  (Safe for simulation — real ASN ranges but not real assigned IPs)
"""

from __future__ import annotations

from dataclasses import dataclass

# ── Company identity ──────────────────────────────────────────────────────────
COMPANY_NAME      = "Nexovate Solutions Pvt. Ltd."
COMPANY_SHORT     = "NEXOVATE"
DOMAIN_FQDN       = "nexovate.local"
DOMAIN_NETBIOS    = "NEXOVATE"
DOMAIN_DNS_SUFFIX = "nexovate.local"
EXTERNAL_DOMAIN   = "nexovatetech.in"

# ── Simulation window ─────────────────────────────────────────────────────────
SIM_START_DATE = "2025-01-06"   # Monday
SIM_END_DATE   = "2025-03-28"   # 12 weeks

# ── Timezone — IST = UTC+5:30, NO DST ever ───────────────────────────────────
# Source: timeanddate.com — "India Standard Time is fixed at UTC+5:30."
TIMEZONE          = "Asia/Kolkata"
UTC_OFFSET_HOURS  = 5
UTC_OFFSET_MINUTES= 30
UTC_OFFSET_TOTAL_MINUTES = 330     # 5*60 + 30 = 330 minutes ahead of UTC
DST_OBSERVED      = False          # India never observes DST

# ── Business hours in IST (local) ─────────────────────────────────────────────
# Typical Indian IT company: 9:00–18:30 IST
# UTC equivalents: 03:30–13:00 UTC
BUSINESS_HOURS_START_IST = 9     # 09:00 IST = 03:30 UTC
BUSINESS_HOURS_END_IST   = 18    # 18:00 IST = 12:30 UTC
# NOTE: End is 18:00 (6 PM), half-hour flex to 18:30 comes from work_duration jitter.
CORE_HOURS_START_IST     = 10    # 10:00 IST = 04:30 UTC
CORE_HOURS_END_IST       = 17    # 17:00 IST = 11:30 UTC

# Indian national holidays 2025 within the simulation window (Jan 6 – Mar 28).
# Sources:
#   Republic Day:     Government of India Official Gazette (Jan 26 every year)
#   Maha Shivaratri:  Drik Panchang 2025 — Feb 26
#   Holi:             Drik Panchang 2025 — Mar 14 (near-universal Indian corporate holiday)
# Makar Sankranti (Jan 14) is a major Karnataka/Bangalore holiday; included.
IN_HOLIDAYS_2025 = [
    "2025-01-14",   # Makar Sankranti — major Karnataka / Bangalore holiday
    "2025-01-26",   # Republic Day — National holiday
    "2025-02-26",   # Maha Shivaratri
    "2025-03-14",   # Holi — near-universal Indian corporate holiday
]

# ── Network addressing — Bangalore HQ ────────────────────────────────────────
# Design: 10.10.VLAN.0/24 per VLAN
NETWORK_RANGES = {
    "dc":           "10.10.0.",    # 10.10.0.1–10  Domain Controllers
    "servers":      "10.10.1.",    # 10.10.1.1–80  Server VLAN
    "workstations": "10.10.2.",    # 10.10.2.10–252 Workstation VLAN (253 employees fit in /24)
    "management":   "10.10.3.",    # 10.10.3.1–20  Out-of-band management
    "dmz":          "10.10.6.",    # 10.10.6.1–20  DMZ
    "vpn":          "172.16.10.",  # 172.16.10.10–200 VPN pool (RFC 1918)
    "wifi":         "10.10.4.",    # 10.10.4.1–100 Corporate Wi-Fi
    "printers":     "10.10.5.",    # 10.10.5.1–30  Printers / IoT
}

# ── Public egress / internet IPs (Indian ISP ranges) ─────────────────────────
PUBLIC_EGRESS_IPS = [
    "203.101.224.10",   # Tata Communications leased line (AS4755)
    "49.44.128.15",     # Jio Enterprise leased line (approximate AS55836)
    "125.16.8.22",      # BSNL Broadband Bangalore (AS9829)
]

VPN_PUBLIC_IP   = "203.101.224.10"
VPN_POOL_START  = "172.16.10.10"
VPN_POOL_END    = "172.16.10.200"

# ── Domain Controllers ────────────────────────────────────────────────────────
DOMAIN_CONTROLLERS = [
    {"hostname": "DC01",  "fqdn": "DC01.nexovate.local",  "ip": "10.10.0.1",  "role": "PDC Emulator"},
    {"hostname": "DC02",  "fqdn": "DC02.nexovate.local",  "ip": "10.10.0.2",  "role": "Additional DC"},
]

# ── Servers ───────────────────────────────────────────────────────────────────
SERVERS = [
    {"hostname": "FS01",      "fqdn": "FS01.nexovate.local",      "ip": "10.10.1.10", "role": "FileServer",   "os": "Windows Server 2022"},
    {"hostname": "FS02",      "fqdn": "FS02.nexovate.local",      "ip": "10.10.1.11", "role": "FileServer",   "os": "Windows Server 2022"},
    {"hostname": "SQL01",     "fqdn": "SQL01.nexovate.local",     "ip": "10.10.1.20", "role": "SQLServer",    "os": "Windows Server 2022"},
    {"hostname": "SQL02",     "fqdn": "SQL02.nexovate.local",     "ip": "10.10.1.21", "role": "SQLServer",    "os": "Windows Server 2022"},
    {"hostname": "APP01",     "fqdn": "APP01.nexovate.local",     "ip": "10.10.1.30", "role": "AppServer",    "os": "Windows Server 2022"},
    {"hostname": "APP02",     "fqdn": "APP02.nexovate.local",     "ip": "10.10.1.31", "role": "AppServer",    "os": "Windows Server 2022"},
    {"hostname": "WEB01",     "fqdn": "WEB01.nexovate.local",     "ip": "10.10.1.40", "role": "WebServer",    "os": "Windows Server 2022"},
    {"hostname": "PRINT01",   "fqdn": "PRINT01.nexovate.local",   "ip": "10.10.1.50", "role": "PrintServer",  "os": "Windows Server 2019"},
    {"hostname": "BACKUP01",  "fqdn": "BACKUP01.nexovate.local",  "ip": "10.10.1.55", "role": "BackupServer", "os": "Windows Server 2022"},
    {"hostname": "SCCM01",    "fqdn": "SCCM01.nexovate.local",    "ip": "10.10.1.60", "role": "SCCM",         "os": "Windows Server 2022"},
    {"hostname": "WSUS01",    "fqdn": "WSUS01.nexovate.local",    "ip": "10.10.1.61", "role": "WSUS",         "os": "Windows Server 2022"},
    {"hostname": "EXCHANGE01","fqdn": "EXCHANGE01.nexovate.local", "ip": "10.10.1.70", "role": "Exchange",     "os": "Windows Server 2022"},
    {"hostname": "RDS01",     "fqdn": "RDS01.nexovate.local",     "ip": "10.10.1.80", "role": "RDSBroker",    "os": "Windows Server 2022"},
    {"hostname": "JUMP01",    "fqdn": "JUMP01.nexovate.local",    "ip": "10.10.3.10", "role": "JumpServer",   "os": "Windows Server 2022"},
]

# ── OU Structure ──────────────────────────────────────────────────────────────
OU_STRUCTURE = {
    "users": {
        "Engineering":    "OU=Engineering,OU=Users,DC=NEXOVATE,DC=local",
        "Finance":        "OU=Finance,OU=Users,DC=NEXOVATE,DC=local",
        "HR":             "OU=HR,OU=Users,DC=NEXOVATE,DC=local",
        "Sales":          "OU=Sales,OU=Users,DC=NEXOVATE,DC=local",
        "Marketing":      "OU=Marketing,OU=Users,DC=NEXOVATE,DC=local",
        "Operations":     "OU=Operations,OU=Users,DC=NEXOVATE,DC=local",
        "IT":             "OU=IT,OU=Users,DC=NEXOVATE,DC=local",
        "Legal":          "OU=Legal,OU=Users,DC=NEXOVATE,DC=local",
        "Executive":      "OU=Executive,OU=Users,DC=NEXOVATE,DC=local",
        "ServiceAccounts":"OU=ServiceAccounts,OU=Users,DC=NEXOVATE,DC=local",
    },
    "computers": {
        "Workstations": "OU=Workstations,OU=Computers,DC=NEXOVATE,DC=local",
        "Servers":      "OU=Servers,OU=Computers,DC=NEXOVATE,DC=local",
    },
}

# ── Department profiles ───────────────────────────────────────────────────────
@dataclass
class DepartmentProfile:
    name:                str
    headcount:           int
    login_start_mean:    float   # mean first-logon hour, IST local
    login_start_std:     float
    work_duration_mean:  float   # mean hours worked per day
    work_duration_std:   float
    remote_fraction:     float
    server_access:       list[str]
    uses_powershell:     bool
    ps_scripts_per_week: float
    task_scheduler_use:  bool
    typical_processes:   list[str]
    dns_domains:         list[str]
    ou_path:             str = ""


DEPARTMENTS: dict[str, DepartmentProfile] = {
    "Engineering": DepartmentProfile(
        name="Engineering", headcount=80,
        login_start_mean=9.5, login_start_std=1.0,
        work_duration_mean=9.5, work_duration_std=1.2,
        remote_fraction=0.40,
        server_access=["SQL01", "SQL02", "APP01", "APP02", "FS01"],
        uses_powershell=True, ps_scripts_per_week=10.0,
        task_scheduler_use=True,
        typical_processes=[
            "devenv.exe", "code.exe", "node.exe", "python.exe",
            "git.exe", "docker.exe", "chrome.exe", "Teams.exe",
            "powershell.exe", "cmd.exe", "postman.exe", "dbeaver.exe",
            "slack.exe",
        ],
        dns_domains=[
            "github.com", "stackoverflow.com", "npmjs.com", "pypi.org",
            "docs.microsoft.com", "hub.docker.com", "registry.npmjs.org",
            "raw.githubusercontent.com", "api.github.com", "azure.microsoft.com",
            "s3.amazonaws.com",
        ],
    ),
    "Finance": DepartmentProfile(
        name="Finance", headcount=30,
        login_start_mean=9.0, login_start_std=0.5,
        work_duration_mean=8.5, work_duration_std=0.7,
        remote_fraction=0.15,
        server_access=["SQL01", "FS01", "APP01"],
        uses_powershell=False, ps_scripts_per_week=0.2,
        task_scheduler_use=False,
        typical_processes=[
            "EXCEL.EXE", "WINWORD.EXE", "OUTLOOK.EXE", "chrome.exe",
            "Teams.exe", "QuickBooks.exe", "AcroRd32.exe", "POWERPNT.EXE",
        ],
        dns_domains=[
            "incometax.gov.in", "gst.gov.in", "rbi.org.in",
            "hdfcbank.com", "icicibank.com", "sbi.co.in",
            "quickbooks.intuit.com", "microsoftonline.com", "sharepoint.com",
            "zoho.com",
        ],
    ),
    "HR": DepartmentProfile(
        name="HR", headcount=15,
        login_start_mean=9.5, login_start_std=0.5,
        work_duration_mean=8.0, work_duration_std=0.6,
        remote_fraction=0.20,
        server_access=["FS01", "SQL01"],
        uses_powershell=False, ps_scripts_per_week=0.1,
        task_scheduler_use=False,
        typical_processes=[
            "EXCEL.EXE", "WINWORD.EXE", "OUTLOOK.EXE", "chrome.exe",
            "Teams.exe", "AcroRd32.exe", "POWERPNT.EXE",
        ],
        dns_domains=[
            "linkedin.com", "naukri.com", "greythr.com", "darwinbox.com",
            "workday.com", "bamboohr.com", "microsoftonline.com",
            "indeed.com", "shine.com",
        ],
    ),
    "Sales": DepartmentProfile(
        name="Sales", headcount=50,
        login_start_mean=9.0, login_start_std=1.0,
        work_duration_mean=9.0, work_duration_std=1.2,
        remote_fraction=0.50,
        server_access=["APP01", "FS01"],
        uses_powershell=False, ps_scripts_per_week=0.2,
        task_scheduler_use=False,
        typical_processes=[
            "OUTLOOK.EXE", "chrome.exe", "Teams.exe", "EXCEL.EXE",
            "WINWORD.EXE", "Zoom.exe", "AcroRd32.exe", "Salesforce.exe",
        ],
        dns_domains=[
            "salesforce.com", "hubspot.com", "linkedin.com", "zoom.us",
            "calendly.com", "docusign.com", "gong.io", "indiamart.com",
            "microsoftonline.com", "sharepoint.com",
        ],
    ),
    "Marketing": DepartmentProfile(
        name="Marketing", headcount=20,
        login_start_mean=9.5, login_start_std=0.8,
        work_duration_mean=8.5, work_duration_std=1.0,
        remote_fraction=0.35,
        server_access=["APP01", "FS01", "WEB01"],
        uses_powershell=False, ps_scripts_per_week=0.1,
        task_scheduler_use=False,
        typical_processes=[
            "OUTLOOK.EXE", "chrome.exe", "Teams.exe", "POWERPNT.EXE",
            "EXCEL.EXE", "Canva.exe", "Photoshop.exe", "Figma.exe",
            "Slack.exe", "AcroRd32.exe",
        ],
        dns_domains=[
            "google.com", "analytics.google.com", "hootsuite.com",
            "mailchimp.com", "canva.com", "figma.com", "semrush.com",
            "linkedin.com", "twitter.com", "youtube.com",
        ],
    ),
    "Operations": DepartmentProfile(
        name="Operations", headcount=25,
        login_start_mean=9.0, login_start_std=0.7,
        work_duration_mean=8.5, work_duration_std=0.8,
        remote_fraction=0.10,
        server_access=["FS01", "FS02", "APP01", "PRINT01"],
        uses_powershell=False, ps_scripts_per_week=0.3,
        task_scheduler_use=False,
        typical_processes=[
            "OUTLOOK.EXE", "chrome.exe", "Teams.exe", "EXCEL.EXE",
            "WINWORD.EXE", "AcroRd32.exe",
        ],
        dns_domains=[
            "fedex.com", "dtdc.com", "bluedart.com", "amazon.in",
            "flipkart.com", "sharepoint.com", "microsoftonline.com",
        ],
    ),
    "IT": DepartmentProfile(
        name="IT", headcount=18,
        login_start_mean=8.5, login_start_std=0.8,
        work_duration_mean=9.5, work_duration_std=1.5,
        remote_fraction=0.30,
        server_access=["DC01", "DC02", "FS01", "FS02", "SQL01", "SQL02",
                       "APP01", "APP02", "BACKUP01", "SCCM01", "WSUS01",
                       "JUMP01", "PRINT01", "RDS01"],
        uses_powershell=True, ps_scripts_per_week=40.0,
        task_scheduler_use=True,
        typical_processes=[
            "powershell.exe", "powershell_ise.exe", "mstsc.exe", "cmd.exe",
            "mmc.exe", "eventvwr.exe", "services.msc",
            "OUTLOOK.EXE", "chrome.exe", "Teams.exe", "putty.exe",
            "WinSCP.exe", "nmap.exe", "Wireshark.exe", "procexp.exe",
            "procmon.exe", "psexec.exe", "bginfo.exe", "veeam.exe",
        ],
        dns_domains=[
            "docs.microsoft.com", "technet.microsoft.com", "support.microsoft.com",
            "portal.azure.com", "download.microsoft.com",
            "windowsupdate.microsoft.com", "github.com",
            "community.spiceworks.com",
        ],
    ),
    "Legal": DepartmentProfile(
        name="Legal", headcount=8,
        login_start_mean=9.5, login_start_std=0.6,
        work_duration_mean=9.0, work_duration_std=1.0,
        remote_fraction=0.15,
        server_access=["FS01", "SQL01"],
        uses_powershell=False, ps_scripts_per_week=0.0,
        task_scheduler_use=False,
        typical_processes=[
            "WINWORD.EXE", "OUTLOOK.EXE", "chrome.exe", "Teams.exe",
            "AcroRd32.exe", "EXCEL.EXE", "iManage.exe",
        ],
        dns_domains=[
            "manupatra.com", "indiankanoon.org", "legalcrystal.com",
            "mca.gov.in", "docusign.com", "microsoftonline.com",
        ],
    ),
    "Executive": DepartmentProfile(
        name="Executive", headcount=7,
        login_start_mean=8.5, login_start_std=1.5,
        work_duration_mean=10.0, work_duration_std=2.0,
        remote_fraction=0.45,
        server_access=["APP01", "FS01", "SQL01"],
        uses_powershell=False, ps_scripts_per_week=0.0,
        task_scheduler_use=False,
        typical_processes=[
            "OUTLOOK.EXE", "chrome.exe", "Teams.exe", "POWERPNT.EXE",
            "EXCEL.EXE", "Zoom.exe", "AcroRd32.exe", "WINWORD.EXE",
        ],
        dns_domains=[
            "google.com", "linkedin.com", "economictimes.indiatimes.com",
            "moneycontrol.com", "zoom.us", "salesforce.com",
            "sharepoint.com", "microsoftonline.com",
        ],
    ),
}

# ── Service accounts ──────────────────────────────────────────────────────────
SERVICE_ACCOUNTS = [
    {"samaccountname": "svc_sql_engine",  "display": "SQL Server Engine",       "server": "SQL01",      "password_never_expires": True},
    {"samaccountname": "svc_sql_agent",   "display": "SQL Server Agent",        "server": "SQL01",      "password_never_expires": True},
    {"samaccountname": "svc_sql2_engine", "display": "SQL Server 2 Engine",     "server": "SQL02",      "password_never_expires": True},
    {"samaccountname": "svc_iis_apppool", "display": "IIS Application Pool",    "server": "APP01",      "password_never_expires": True},
    {"samaccountname": "svc_webapp_api",  "display": "Web App API Service",     "server": "APP02",      "password_never_expires": True},
    {"samaccountname": "svc_exchange",    "display": "Exchange Service",         "server": "EXCHANGE01", "password_never_expires": True},
    {"samaccountname": "svc_backup",      "display": "Veeam Backup Agent",      "server": "BACKUP01",   "password_never_expires": True},
    {"samaccountname": "svc_sccm_client", "display": "SCCM Client Push",        "server": "SCCM01",     "password_never_expires": True},
    {"samaccountname": "svc_monitor",     "display": "System Monitoring Agent", "server": "DC01",       "password_never_expires": True},
    {"samaccountname": "svc_fileshare",   "display": "File Share Service",      "server": "FS01",       "password_never_expires": True},
    {"samaccountname": "svc_rds",         "display": "RDS Session Host",        "server": "RDS01",      "password_never_expires": True},
    {"samaccountname": "svc_wsus",        "display": "WSUS Update Service",     "server": "WSUS01",     "password_never_expires": True},
]

# ── Tiered admin accounts ─────────────────────────────────────────────────────
ADMIN_ACCOUNTS = [
    {"samaccountname": "adm_t0_rverma",   "display": "IT Admin T0 - Rohit Verma",    "tier": 0, "real_user": "rverma"},
    {"samaccountname": "adm_t0_asharma",  "display": "IT Admin T0 - Amit Sharma",    "tier": 0, "real_user": "asharma"},
    {"samaccountname": "adm_t1_rverma",   "display": "IT Admin T1 - Rohit Verma",    "tier": 1, "real_user": "rverma"},
    {"samaccountname": "adm_t1_asharma",  "display": "IT Admin T1 - Amit Sharma",    "tier": 1, "real_user": "asharma"},
    {"samaccountname": "adm_t1_psingh",   "display": "IT Admin T1 - Priya Singh",    "tier": 1, "real_user": "psingh"},
    {"samaccountname": "adm_t2_vgupta",   "display": "IT Admin T2 - Vivek Gupta",    "tier": 2, "real_user": "vgupta"},
    {"samaccountname": "adm_t2_snair",    "display": "IT Admin T2 - Sunita Nair",    "tier": 2, "real_user": "snair"},
]

# ── Security groups ────────────────────────────────────────────────────────────
SECURITY_GROUPS = {
    "GG-Dept-Engineering":          "Engineering department members",
    "GG-Dept-Finance":              "Finance department members",
    "GG-Dept-HR":                   "HR department members",
    "GG-Dept-Sales":                "Sales department members",
    "GG-Dept-Marketing":            "Marketing department members",
    "GG-Dept-Operations":           "Operations department members",
    "GG-Dept-IT":                   "IT department members",
    "GG-Dept-Legal":                "Legal department members",
    "GG-Dept-Executive":            "Executive leadership",
    "DL-FileShare-Finance-RW":      "Finance file share read-write",
    "DL-FileShare-HR-RW":           "HR file share read-write",
    "DL-FileShare-Engineering-RW":  "Engineering file share read-write",
    "DL-FileShare-AllStaff-RO":     "All staff file share read-only",
    "DL-SQL-Finance-Access":        "SQL access for Finance users",
    "DL-SQL-Engineering-Access":    "SQL access for Engineering users",
    "GG-Admins-Tier0-DomainAdmins": "Domain Administrator accounts (Tier 0)",
    "GG-Admins-Tier1-ServerAdmins": "Server Administrator accounts (Tier 1)",
    "GG-Admins-Tier2-Helpdesk":     "Helpdesk Administrator accounts (Tier 2)",
    "GG-GPO-PSLogging-All":         "PowerShell script block logging targets",
    "GG-GPO-BitLocker-Workstations":"BitLocker policy targets",
}

# ── Workstation naming: WS<DEPT_CODE><NN> ─────────────────────────────────────
DEPT_WS_PREFIX = {
    "Engineering": "WSENG",
    "Finance":     "WSFIN",
    "HR":          "WSHR",
    "Sales":       "WSSLS",
    "Marketing":   "WSMKT",
    "Operations":  "WSOPS",
    "IT":          "WSIT",
    "Legal":       "WSLGL",
    "Executive":   "WSEXC",
}

# ── Internal DNS names ────────────────────────────────────────────────────────
INTERNAL_DNS_NAMES = [
    "nexovate.local", "DC01.nexovate.local", "DC02.nexovate.local",
    "FS01.nexovate.local", "FS02.nexovate.local",
    "SQL01.nexovate.local", "SQL02.nexovate.local",
    "APP01.nexovate.local", "APP02.nexovate.local",
    "WEB01.nexovate.local", "EXCHANGE01.nexovate.local",
    "intranet.nexovate.local", "mail.nexovate.local",
    "files.nexovate.local",
]

# ── Simulation controls ────────────────────────────────────────────────────────
RANDOM_SEED = 20250106

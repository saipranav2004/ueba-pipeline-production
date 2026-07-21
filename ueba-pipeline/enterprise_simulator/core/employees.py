"""
employees.py — Generates the full employee roster for the simulation.

Produces a deterministic list of Employee objects with realistic Indian names,
SAM account names, email addresses, assigned workstations, and manager
relationships. Seeded for full reproducibility.

Total headcount: 253 employees (matches DEPARTMENTS sum in company.py).

Key design decisions:
  - Manager assignment: per-department manager is the FIRST person whose
    samaccountname matches one of the named ADMIN_ACCOUNTS real_user values.
    If no admin maps to a department, the first employee is manager (same
    as before) but the job title is correctly the LAST (most senior) entry
    in the department's title list, not titles[0].
  - IP collision fix: workstation IPs use cumulative cross-department offsets
    rather than fixed per-dept offsets, so no two employees share an IP.
  - VPN pool: sized to actual remote-eligible headcount (no modulo wrap).
  - Reproducibility: per-entity seeds derived via hashlib.md5 (not Python's
    hash() which is process-salted by default).
  - Service account OU: OU=ServiceAccounts,OU=Users,DC=NEXOVATE,DC=local
    (was incorrectly APEXION in the original build_service_accounts()).
"""

from __future__ import annotations
import random
import hashlib
from dataclasses import dataclass, field
from typing import List, Optional, Dict
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config.company import (
    DEPARTMENTS, DOMAIN_NETBIOS, EXTERNAL_DOMAIN, DOMAIN_FQDN,
    NETWORK_RANGES, DEPT_WS_PREFIX, SERVICE_ACCOUNTS, ADMIN_ACCOUNTS,
    RANDOM_SEED,
)

# ── First / last name pools — realistic Indian corporate demographics ─────────
FIRST_NAMES_M = [
    "Rahul","Amit","Vikram","Arjun","Rohit","Rajesh","Suresh","Anil",
    "Manoj","Sanjay","Deepak","Rajan","Vivek","Nitin","Pankaj","Ajay",
    "Pradeep","Santosh","Dinesh","Ramesh","Girish","Naveen","Kiran","Tarun",
    "Gaurav","Ankit","Varun","Shubham","Harsh","Neeraj","Sachin","Vinay",
    "Alok","Ashish","Vikas","Hemant","Manish","Devesh","Ravi","Sunil",
    "Chetan","Pranav","Akash","Rohan","Nikhil","Kartik","Yash","Mohit",
    "Aman","Vishal","Tejas","Rishabh","Aakash","Siddharth","Dev","Jay",
    "Shyam","Mohan","Gopal","Krishnan","Lakshman","Balaji","Venkatesan","Muthu",
    "Selvam","Arumugam","Senthil","Vijay","Harish","Subramaniam","Murali",
    "Pratik","Sumit","Abhishek","Souvik","Arnab","Debashis","Partha","Subrata",
    "Indrajit","Avinash","Shailesh","Nagesh","Prashant","Kuldeep","Bhavesh","Jigar",
    "Dhruv","Ishaan","Parth","Lakshya","Aditya","Shivam","Utkarsh","Kushal",
]
FIRST_NAMES_F = [
    "Priya","Sunita","Pooja","Anita","Kavitha","Meena","Lakshmi","Geeta",
    "Rekha","Sushma","Deepa","Asha","Usha","Nisha","Lata","Saroja",
    "Radha","Sita","Parvati","Kamala","Vimala","Mangala","Pushpa","Leela",
    "Divya","Sneha","Neha","Ritu","Simran","Komal","Swati","Preeti",
    "Shweta","Ankita","Pallavi","Smita","Madhuri","Vandana","Sudha","Nandita",
    "Archana","Bharati","Meenakshi","Nalini","Vasantha","Sumathi","Gayathri","Vijaya",
    "Anjali","Rima","Sonal","Avni","Tanvi","Shruti","Ishita","Arushi",
    "Aishwarya","Deeksha","Sakshi","Aditi","Riya","Tanya","Muskan","Harsha",
    "Kirti","Shital","Bindiya","Hema","Amita","Beena","Jyoti","Seema",
    "Savita","Sangeeta","Bharathi","Janaki","Rukmini","Saraswathi","Yamuna","Ganga",
    "Madhavi","Sarita","Manorama","Bhavna","Chitra","Nandini","Lalitha","Shobha",
    "Kalyani","Revathi","Padma","Gomathi","Mythili","Vijayalakshmi","Rani",
]
LAST_NAMES = [
    "Sharma","Verma","Singh","Gupta","Kumar","Patel","Shah","Mehta",
    "Joshi","Mishra","Tiwari","Dubey","Pandey","Yadav","Chauhan","Rajput",
    "Nair","Menon","Pillai","Iyer","Iyengar","Krishnan","Rajan","Subramanian",
    "Reddy","Naidu","Rao","Murthy","Gowda","Hegde","Pai","Kamath",
    "Mukherjee","Chatterjee","Banerjee","Ghosh","Das","Sen","Roy","Bose",
    "Agarwal","Jain","Khandelwal","Goel","Arora","Khanna","Malhotra","Kapoor",
    "Bhatia","Chopra","Sood","Bajaj","Sethi","Narang","Dhillon","Sandhu",
    "Ranganathan","Venkataraman","Balasubramanian","Srinivasan","Parthasarathy",
    "Sundaram","Natarajan","Annamalai",
    "Desai","Bhatt","Trivedi","Pandya","Modi","Solanki","Parmar","Makwana",
    "Kulkarni","Patil","Deshmukh","Shinde","Jadhav","More","Gaikwad","Bhosale",
    "Nayak","Shetty","Bhat","Alva","Bangera","Prabhu",
    "Choudhury","Sahu","Mohapatra","Panda","Misra","Dash","Pradhan","Behera",
]


@dataclass
class Employee:
    """Full employee record used throughout the simulation."""
    employee_id:     str          # APXN-0001 etc.
    first_name:      str
    last_name:       str
    gender:          str          # 'M' or 'F'
    samaccountname:  str
    display_name:    str
    email:           str          # rsharma@nexovatetech.in
    upn:             str          # rsharma@nexovate.local
    department:      str
    job_title:       str
    is_manager:      bool
    manager_sam:     Optional[str]
    workstation:     str          # e.g. WSENG07
    workstation_ip:  str
    ou_path:         str
    hire_date:       str          # YYYY-MM-DD
    is_contractor:   bool
    is_active:       bool = True
    termination_date: Optional[str] = None
    login_start_mean: float = 8.5
    login_start_std:  float = 1.0
    work_duration_mean: float = 8.5
    work_duration_std:  float = 1.0
    remote_fraction:    float = 0.3
    vpn_ip:          Optional[str] = None
    # Privileged admin account SAM (if this employee has a named admin account)
    admin_sam:       Optional[str] = None


@dataclass
class ServiceAccount:
    """Service account record."""
    samaccountname:  str
    display_name:    str
    upn:             str
    server_hostname: str
    server_ip:       str
    password_never_expires: bool
    ou_path:         str
    logon_hours:     str = "any"


def _sam_from_name(first: str, last: str, existing: set) -> str:
    """
    Generates SAM account name: first initial + last name (max 20 chars).
    Appends digit to resolve collisions — mirrors real AD helpdesk behaviour.
    """
    base = (first[0] + last).lower()
    base = base.replace(" ", "").replace("-", "").replace("'", "")[:18]
    sam  = base
    counter = 2
    while sam in existing:
        sam = f"{base}{counter}"
        counter += 1
    existing.add(sam)
    return sam


def stable_seed(base_seed: int, identifier: str) -> int:
    """
    Derives a per-entity seed via hashlib.md5 — NOT Python's hash().
    Python's hash() is process-salted (PYTHONHASHSEED) so hash('x') differs
    across runs. hashlib.md5 is deterministic across all processes.
    """
    digest = hashlib.md5(identifier.encode()).hexdigest()
    return base_seed ^ (int(digest[:8], 16))


def user_sid(sam: str) -> str:
    """
    Stable, per-user SID derived from SAM account name via MD5.
    RID range 1100–10099 avoids well-known RIDs.
    This is the canonical SID generator — used everywhere a user SID
    is needed (4624, 4634, 4768, 4771, 4740, and all extended events).
    """
    rid = int(hashlib.md5(sam.encode()).hexdigest()[:4], 16) % 9000 + 1100
    return f"S-1-5-21-1484628597-1684816888-3125425894-{rid}"


def _workstation_ip(cumulative_index: int) -> str:
    """
    Assigns a unique workstation IP in the 10.10.2.x VLAN using a global
    running counter across all departments. Starting from .2 gives 253 unique
    addresses (10.10.2.2 – 10.10.2.254) for 253 employees — exactly zero
    collisions, no wrapping required.
    """
    base = NETWORK_RANGES["workstations"]   # "10.10.2."
    last_octet = 2 + cumulative_index       # .2 → .254 for 253 employees
    return f"{base}{last_octet}"


def _vpn_ip(index: int, pool_size: int) -> str:
    """
    Assigns a VPN pool IP. Pool is 172.16.10.10 – 172.16.10.200 (191 IPs).
    We size the pool to the actual remote-eligible headcount rather than
    wrapping with %; if headcount exceeds pool, spill into .201+.
    """
    return f"172.16.10.{10 + index}"


def _server_ip(hostname: str) -> str:
    """Look up server IP from config."""
    from config.company import SERVERS, DOMAIN_CONTROLLERS
    for s in SERVERS + DOMAIN_CONTROLLERS:
        if s["hostname"] == hostname:
            return s["ip"]
    return "10.10.1.1"


def _hire_date(rng: random.Random) -> str:
    """Most employees are pre-hired. ~5% are new hires during the sim window."""
    if rng.random() < 0.05:
        m = rng.randint(1, 2)
        d = rng.randint(2, 28)
        return f"2025-{m:02d}-{d:02d}"
    year  = rng.randint(2020, 2024)
    month = rng.randint(1, 12)
    day   = rng.randint(1, 28)
    return f"{year}-{month:02d}-{day:02d}"


# Job titles per department — ordered junior → senior
# Manager gets the LAST (most senior) title; others get sequential indices.
JOB_TITLES: Dict[str, List[str]] = {
    "Engineering":  [
        "Software Engineer I", "Software Engineer II", "Senior Software Engineer",
        "Staff Software Engineer", "Principal Engineer",
        "DevOps Engineer", "QA Engineer", "Security Engineer",
        "Data Engineer", "ML Engineer", "Site Reliability Engineer",
        "Engineering Manager",
    ],
    "Finance":      [
        "Staff Accountant", "Accounts Payable Specialist", "Accounts Receivable Specialist",
        "Financial Analyst", "Senior Financial Analyst",
        "Accounting Manager", "Controller", "VP of Finance",
    ],
    "HR":           [
        "HR Generalist", "Recruiter", "Benefits Administrator", "HRIS Analyst",
        "Learning and Development Specialist", "Senior Recruiter",
        "HR Business Partner", "HR Manager",
    ],
    "Sales":        [
        "Sales Development Rep", "Account Executive", "Senior Account Executive",
        "Account Manager", "Customer Success Manager", "Sales Engineer",
        "Regional Sales Manager", "VP of Sales",
    ],
    "Marketing":    [
        "Marketing Coordinator", "Content Writer", "SEO Specialist",
        "Brand Designer", "Digital Marketing Manager",
        "Demand Generation Manager", "Product Marketing Manager", "Marketing Manager",
    ],
    "Operations":   [
        "Administrative Assistant", "Executive Assistant", "Operations Analyst",
        "Supply Chain Analyst", "Business Analyst",
        "Project Manager", "Facilities Manager", "Operations Manager",
    ],
    "IT":           [
        "Help Desk Technician", "Systems Administrator", "Network Administrator",
        "Database Administrator", "Cloud Engineer", "Security Analyst",
        "Identity & Access Management Admin", "IT Manager", "IT Director",
    ],
    "Legal":        [
        "Paralegal", "Legal Counsel", "Compliance Officer",
        "Contracts Manager", "Senior Legal Counsel", "General Counsel",
    ],
    "Executive":    [
        "Chief Executive Officer", "Chief Technology Officer",
        "Chief Financial Officer", "Chief People Officer",
        "Chief Marketing Officer", "Chief Revenue Officer", "Chief Operating Officer",
    ],
}


def roster_to_peer_group_map(roster: List["Employee"]) -> Dict[str, str]:
    """
    Projects a roster into the flat {username: peer_group} shape
    ueba_pipeline.cli.main._load_peer_groups expects (a bare `json.load`
    result handed straight to ThresholdRegistry as user_to_peer_group).

    Key shape MUST match ueba_pipeline.parsing.normalize.normalize_username's
    output exactly (lowercased SAM name, no domain/NetBIOS prefix) or peer-
    group lookups silently miss for every user -- Employee.samaccountname is
    already a bare SAM name, so `.lower()` alone is sufficient here, but
    this is asserted in the regression test rather than left implicit, since
    a future Employee field change could quietly break that assumption.

    A richer per-employee export (title, manager, IP, etc.) was considered
    and rejected for this purpose: the consumer only ever reads a flat
    username->peer_group map, and shipping more than that gives the two
    subsystems two different implicit contracts to keep in sync instead of
    one explicit one.

    Non-human identities (service accounts) are included under dedicated
    NHI peer groups rather than a human department. Service accounts have
    fundamentally more regular, scripted behavior than humans, so pooling
    them with a department baseline would both mis-score them and pollute
    that department's human baseline. They are grouped by function
    ("nhi_<role>") so a service account with no individual model yet falls
    back to other service accounts of the same kind, never to humans.
    """
    mapping = {e.samaccountname.lower(): e.department for e in roster}
    for sa in SERVICE_ACCOUNTS:
        sam = sa.get("samaccountname", "").lower()
        if not sam:
            continue
        # Derive a coarse NHI function from the account name (svc_sql_engine
        # -> nhi_sql) so like service accounts share a fallback cohort.
        stem = sam[4:] if sam.startswith("svc_") else sam
        role = stem.split("_")[0] if stem else "generic"
        mapping[sam] = f"nhi_{role}"
    return mapping


def build_employee_roster() -> List[Employee]:
    """
    Deterministically generates the complete 253-employee roster.
    Returns a list of Employee objects sorted by department then index.

    Key fixes vs original:
      1. Manager title: manager gets titles[-1] (most senior), not titles[0]
      2. Manager identity: first employee in IT whose sam maps to an
         ADMIN_ACCOUNTS real_user gets is_manager=True; for other depts
         the first employee with an admin mapping is manager; fallback is
         index==0 as before.
      3. IP allocation: cumulative global counter, no per-dept fixed offsets.
      4. VPN pool: non-wrapping sequential index, properly sized.
      5. Per-entity RNG seed: uses stable_seed() not hash().
    """
    rng = random.Random(RANDOM_SEED)
    employees: List[Employee] = []
    used_sams: set = set()
    emp_id_counter = 1
    ws_counter_global = 0   # cumulative across all departments
    vpn_counter = 0

    # Build set of real_user sams that have admin accounts
    admin_real_users: set = {adm["real_user"] for adm in ADMIN_ACCOUNTS}
    # Map real_user -> highest-tier admin sam (tier 0 > 1 > 2)
    admin_sam_by_user: Dict[str, str] = {}
    for adm in sorted(ADMIN_ACCOUNTS, key=lambda a: a["tier"]):
        # lower tier number = more privileged; keep the first (lowest tier)
        if adm["real_user"] not in admin_sam_by_user:
            admin_sam_by_user[adm["real_user"]] = adm["samaccountname"]

    for dept_name, profile in DEPARTMENTS.items():
        ws_prefix = DEPT_WS_PREFIX[dept_name]
        titles    = JOB_TITLES[dept_name]
        ou_path   = f"OU={dept_name},OU=Users,DC=NEXOVATE,DC=local"
        ws_local_counter = 1   # local within-dept workstation number
        dept_manager_assigned = False

        for i in range(profile.headcount):
            gender = rng.choice(["M", "F"])
            first  = rng.choice(FIRST_NAMES_M if gender == "M" else FIRST_NAMES_F)
            last   = rng.choice(LAST_NAMES)
            sam    = _sam_from_name(first, last, used_sams)
            display   = f"{first} {last}"
            emp_id    = f"APXN-{emp_id_counter:04d}"
            email     = f"{sam}@{EXTERNAL_DOMAIN}"
            upn       = f"{sam}@{DOMAIN_FQDN}"
            workstation = f"{ws_prefix}{ws_local_counter:02d}"
            ws_ip     = _workstation_ip(ws_counter_global)
            hire_dt   = _hire_date(rng)
            is_contractor = (rng.random() < 0.08)

            # Manager assignment logic:
            # A person is manager if:
            #   (a) they have a named admin account in ADMIN_ACCOUNTS and
            #       no manager has been assigned yet in this dept, OR
            #   (b) i == 0 and no admin-account holder appeared yet
            has_admin = sam in admin_real_users
            is_mgr = False
            if not dept_manager_assigned:
                if has_admin or i == profile.headcount - 1:
                    # Either this person has an admin account, or we've
                    # reached the last employee and still need a manager
                    is_mgr = True
                    dept_manager_assigned = True
                elif i == 0:
                    # Tentatively mark as manager; will be overridden if
                    # an admin-holder appears later in the dept.
                    # We handle this in a second pass below.
                    pass

            # Job title
            # Non-managers get sequential titles; managers get the senior title
            if is_mgr:
                title = titles[-1]
            else:
                title_idx = min(i, len(titles) - 2)   # -2 to reserve last for manager
                title = titles[title_idx]
            if is_contractor:
                title = f"Contractor - {title}"

            # Behavioural jitter
            jitter = lambda mu, sig: max(0.5, rng.gauss(mu, sig * 0.15))
            login_start_mean  = jitter(profile.login_start_mean, profile.login_start_std)
            login_start_std   = max(0.3, rng.gauss(profile.login_start_std, 0.1))
            work_dur_mean     = jitter(profile.work_duration_mean, profile.work_duration_std)
            work_dur_std      = max(0.3, rng.gauss(profile.work_duration_std, 0.1))
            remote_frac       = max(0.0, min(1.0, rng.gauss(profile.remote_fraction, 0.1)))

            vpn_ip = None
            if remote_frac > 0:
                vpn_ip = _vpn_ip(vpn_counter, 191)
                vpn_counter += 1

            admin_sam = admin_sam_by_user.get(sam)

            emp = Employee(
                employee_id       = emp_id,
                first_name        = first,
                last_name         = last,
                gender            = gender,
                samaccountname    = sam,
                display_name      = display,
                email             = email,
                upn               = upn,
                department        = dept_name,
                job_title         = title,
                is_manager        = is_mgr,
                manager_sam       = None,   # filled in second pass
                workstation       = workstation,
                workstation_ip    = ws_ip,
                ou_path           = ou_path,
                hire_date         = hire_dt,
                is_contractor     = is_contractor,
                login_start_mean  = login_start_mean,
                login_start_std   = login_start_std,
                work_duration_mean= work_dur_mean,
                work_duration_std = work_dur_std,
                remote_fraction   = remote_frac,
                vpn_ip            = vpn_ip,
                admin_sam         = admin_sam,
            )
            employees.append(emp)
            emp_id_counter   += 1
            ws_local_counter += 1
            ws_counter_global += 1

        # If no admin-holder was in this dept, ensure the first employee is manager
        dept_emps = [e for e in employees if e.department == dept_name]
        if not any(e.is_manager for e in dept_emps):
            dept_emps[0].is_manager = True
            dept_emps[0].job_title  = titles[-1]

    # Second pass: assign manager_sam
    manager_by_dept: Dict[str, str] = {}
    for emp in employees:
        if emp.is_manager:
            manager_by_dept[emp.department] = emp.samaccountname
    for emp in employees:
        if not emp.is_manager:
            emp.manager_sam = manager_by_dept.get(emp.department)

    return employees


def build_service_accounts() -> List[ServiceAccount]:
    """Builds service account records. OU path uses NEXOVATE (not APEXION)."""
    records: List[ServiceAccount] = []
    for sa in SERVICE_ACCOUNTS:
        server_ip = _server_ip(sa["server"])
        records.append(ServiceAccount(
            samaccountname        = sa["samaccountname"],
            display_name          = sa["display"],
            upn                   = f"{sa['samaccountname']}@{DOMAIN_FQDN}",
            server_hostname       = sa["server"],
            server_ip             = server_ip,
            password_never_expires= sa["password_never_expires"],
            ou_path               = "OU=ServiceAccounts,OU=Users,DC=NEXOVATE,DC=local",
            logon_hours           = sa.get("logon_hours", "any"),
        ))
    return records


if __name__ == "__main__":
    roster = build_employee_roster()
    sas    = build_service_accounts()
    print(f"Generated {len(roster)} employees across {len(DEPARTMENTS)} departments")
    for dept in DEPARTMENTS:
        mgr = next((e for e in roster if e.department == dept and e.is_manager), None)
        count = sum(1 for e in roster if e.department == dept)
        mgr_title = mgr.job_title if mgr else "NONE"
        mgr_sam   = mgr.samaccountname if mgr else "NONE"
        print(f"  {dept:15s}: {count:3d} employees  manager={mgr_sam} ({mgr_title})")
    print(f"Generated {len(sas)} service accounts")
    # Verify no IP collisions
    ips = [e.workstation_ip for e in roster]
    dupes = [ip for ip in set(ips) if ips.count(ip) > 1]
    print(f"Workstation IP duplicates: {dupes if dupes else 'none'}")
    vpn_ips = [e.vpn_ip for e in roster if e.vpn_ip]
    vpn_dupes = [ip for ip in set(vpn_ips) if vpn_ips.count(ip) > 1]
    print(f"VPN IP duplicates: {vpn_dupes if vpn_dupes else 'none'}")

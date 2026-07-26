"""
attacks.py -- labelled attack injection for evaluation.

Every function generates a small, realistic set of events for one attack instance
and returns a ground-truth label alongside them, so detection rate can be measured
against the ueba_pipeline scorer. Field details follow MITRE ATT&CK and public
detection guidance, e.g.:

- Pass-the-Hash (T1550.002): NTLM / Type-3 logon with no preceding Kerberos
  exchange, from a workstation the victim has never used.
- Kerberoasting (T1558.003): TGS requests for service SPNs with RC4 ticket
  encryption, at a volume/timing pattern outside the account's normal use.
- Password Spray (T1110.003): failed-authentication bursts (4771/4625) against
  many distinct accounts from a single source IP in a short window, with
  wrong-password sub-status codes (0xc000006a / 0x18).

Off by default. Enabled via run_simulation.py's --inject-attacks flag. Ground
truth is written to output/attack_labels.jsonl -- one line per injected instance,
never mixed into the regular log streams, so a consumer can ignore it entirely
(train purely unsupervised) or use it for evaluation.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Any

from config.company import DOMAIN_FQDN
from core.daily_simulation import _CIFS_SPNS
from core.employees import Employee
from core.employees import user_sid as _user_sid
from core.event_bus import EventBus, ProcessRecord
from core.time_engine import _float_hour_to_datetime, local_to_utc, utc_now_str
from generators.security_generator import (
    gen_4624,
    gen_4625,
    gen_4662,
    gen_4768,
    gen_4769,
    gen_4771,
    gen_4776,
    gen_group_change,
)
from generators.security_generator_extended import gen_5140, gen_5145
from generators.sysmon_generator import gen_eid1, gen_eid10
from generators.sysmon_generator_extended import gen_eid17, gen_eid18

InjectedEvents = list[tuple[str, datetime, dict[str, Any]]]


@dataclass
class AttackLabel:
    attack_type: str
    mitre_technique: str
    start_time: str
    end_time: str
    target_users: list[str]
    source_ip: str
    details: dict[str, Any]


def inject_pass_the_hash(
    roster: list[Employee],
    bus: EventBus,
    sim_date: date,
    rng: random.Random,
) -> tuple[InjectedEvents, AttackLabel]:
    """
    Simulates lateral movement via a stolen NTLM hash: the victim's
    credentials authenticate from a workstation they have never used,
    over NTLM (not Kerberos), with no preceding ticket-granting exchange.
    That absence is the point -- every legitimate domain-joined logon in
    this generator's normal traffic goes through gen_4768/gen_4769 first
    (see daily_simulation.py); a bare 4624+4776 pair with nothing before
    it is exactly the anomaly a real Pass-the-Hash attempt would produce.
    """
    victim = rng.choice(roster)
    # Attacker pivots from a foothold on a DIFFERENT employee's workstation
    # -- modeling "already compromised host A, now moving to host B's
    # credentials," not an attack against the victim's own machine.
    foothold_pool = [e for e in roster if e.samaccountname != victim.samaccountname]
    foothold = rng.choice(foothold_pool)

    attack_hour = rng.uniform(9.0, 18.0)
    attack_ts = local_to_utc(_float_hour_to_datetime(sim_date, attack_hour))

    events: InjectedEvents = []
    session = bus.open_session(
        samaccountname=victim.samaccountname,
        domain="NEXOVATE",
        logon_type=3,
        auth_package="NTLM",
        src_ip=foothold.workstation_ip,
        src_port=bus.new_src_port(),
        workstation=foothold.workstation,
        computer=foothold.workstation + ".nexovate.local",
        logon_time_utc=attack_ts,
        is_elevated=victim.is_manager,
        is_remote=False,
    )
    logon_event = gen_4624(session, attack_ts, bus, target_user_sid=_user_sid(victim.samaccountname))
    events.append(("security", attack_ts, logon_event))

    ntlm_ts = attack_ts + timedelta(seconds=1)
    ntlm_event = gen_4776(victim.samaccountname, foothold.workstation, ntlm_ts, bus, status="0x0")
    events.append(("security", ntlm_ts, ntlm_event))

    label = AttackLabel(
        attack_type="pass_the_hash",
        mitre_technique="T1550.002",
        start_time=utc_now_str(attack_ts),
        end_time=utc_now_str(ntlm_ts),
        target_users=[victim.samaccountname],
        source_ip=foothold.workstation_ip,
        details={
            "source_workstation": foothold.workstation,
            "victim_normal_workstation": victim.workstation,
            "signature": "LogonType=3, AuthenticationPackageName=NTLM, "
                         "LogonProcessName=NtLmSsp, no preceding 4768/4769",
        },
    )
    return events, label


def inject_kerberoasting(
    roster: list[Employee],
    bus: EventBus,
    sim_date: date,
    rng: random.Random,
) -> tuple[InjectedEvents, AttackLabel]:
    """
    Simulates requesting service tickets for every SPN in the domain to
    harvest RC4-encrypted tickets for offline cracking. Targets a real SPN and forces enc_type
    ="0x17" (RC4) explicitly via gen_4769's override parameter, which
    exists specifically for this purpose (see that function's docstring).
    Volume (distinct SPNs requested in a short window) is itself part of
    the signal.
    """
    attacker = rng.choice(roster)
    attack_hour = rng.uniform(9.0, 18.0)
    start_ts = local_to_utc(_float_hour_to_datetime(sim_date, attack_hour))

    all_spns = list(_CIFS_SPNS.items())
    n_requests = min(len(all_spns), rng.randint(6, len(all_spns)))
    targets = rng.sample(all_spns, n_requests)

    events: InjectedEvents = []
    ts = start_ts
    requested_spns = []
    for _hostname, (spn, spn_sid) in targets:
        ts = ts + timedelta(seconds=rng.randint(2, 8))  # rapid, not human-paced
        event = gen_4769(
            attacker.samaccountname, spn, spn_sid, attacker.workstation_ip,
            ts, bus, enc_type="0x17",  # force RC4 -- the crackable ticket type
        )
        events.append(("security", ts, event))
        requested_spns.append(spn)

    label = AttackLabel(
        attack_type="kerberoasting",
        mitre_technique="T1558.003",
        start_time=utc_now_str(start_ts),
        end_time=utc_now_str(ts),
        target_users=[attacker.samaccountname],
        source_ip=attacker.workstation_ip,
        details={
            "requested_spns": requested_spns,
            "ticket_encryption_forced": "0x17",
            "signature": "TicketEncryptionType=0x17 across "
                         f"{n_requests} distinct SPNs within "
                         f"{(ts - start_ts).total_seconds():.0f}s",
        },
    )
    return events, label


def inject_password_spray(
    roster: list[Employee],
    bus: EventBus,
    sim_date: date,
    rng: random.Random,
) -> tuple[InjectedEvents, AttackLabel]:
    """
    Simulates a low-and-slow password spray: one password guessed against
    many distinct real accounts from a single source IP, relying on
    account-lockout policies not tripping per-account thresholds. Uses the
    SubStatus/Status codes that mark the spray signature (0xc000006a / 0x18 = wrong
    password on an account that exists -- as opposed to
    account-not-found codes, which would indicate enumeration, a
    different technique).
    """
    attack_ip = f"185.220.{rng.randint(100, 254)}.{rng.randint(1, 254)}"  # external, not RFC1918
    attack_hour = rng.uniform(2.0, 5.0)  # off-hours, per real spray campaigns
    start_ts = local_to_utc(_float_hour_to_datetime(sim_date, attack_hour))

    n_targets = rng.randint(15, 40)
    targets = rng.sample(roster, min(n_targets, len(roster)))

    events: InjectedEvents = []
    ts = start_ts
    for emp in targets:
        ts = ts + timedelta(seconds=rng.uniform(3, 20))
        if rng.random() < 0.7:
            event = gen_4771(emp.samaccountname, attack_ip, ts, bus, status="0x18")
        else:
            event = gen_4625(
                emp.samaccountname, attack_ip, "DC01.nexovate.local",
                logon_type=3, utc_dt=ts, bus=bus,
                sub_status="0xc000006a", auth_package="NTLM", workstation="-",
            )
        events.append(("security", ts, event))

    label = AttackLabel(
        attack_type="password_spray",
        mitre_technique="T1110.003",
        start_time=utc_now_str(start_ts),
        end_time=utc_now_str(ts),
        target_users=[e.samaccountname for e in targets],
        source_ip=attack_ip,
        details={
            "distinct_accounts_targeted": len(targets),
            "signature": "wrong-password failures (0xc000006a/0x18) across "
                         f"{len(targets)} accounts from one external IP "
                         f"within {(ts - start_ts).total_seconds():.0f}s",
        },
    )
    return events, label


def inject_dcsync(
    roster: list[Employee],
    bus: EventBus,
    sim_date: date,
    rng: random.Random,
) -> tuple[InjectedEvents, AttackLabel]:
    """
    Simulates a DCSync attack (T1003.006): a non-DC account requests
    directory replication, triggering event 4662 with the Replicating
    Directory Changes All GUID in the Properties field. Detection signature: SubjectUserName NOT ending
    in '$' (not a DC machine account) + replication GUIDs present.
    """
    attacker = rng.choice(roster)
    # Pick a high-value target whose hashes the attacker wants
    target_pool = [e for e in roster if e.samaccountname != attacker.samaccountname]
    target = rng.choice(target_pool)
    attack_hour = rng.uniform(2.0, 5.0)  # off-hours, typical for stealth
    attack_ts = local_to_utc(_float_hour_to_datetime(sim_date, attack_hour))

    events: InjectedEvents = []
    # First, a normal Kerberos logon for the attacker (DCSync requires DA-level access)
    session = bus.open_session(
        samaccountname=attacker.samaccountname,
        domain="NEXOVATE",
        logon_type=3,
        auth_package="Kerberos",
        src_ip=attacker.workstation_ip,
        src_port=bus.new_src_port(),
        workstation=attacker.workstation,
        computer=attacker.workstation + ".nexovate.local",
        logon_time_utc=attack_ts,
        is_elevated=True,  # DCSync requires Domain Admin or equivalent
        is_remote=False,
    )
    logon_event = gen_4624(session, attack_ts, bus, target_user_sid=_user_sid(attacker.samaccountname))
    events.append(("security", attack_ts, logon_event))

    # The DCSync event itself — 4662 with replication GUIDs
    dcsync_ts = attack_ts + timedelta(seconds=2)
    dcsync_event = gen_4662(
        actor_session=session,
        object_dn="DC=nexovate,DC=local",
        utc_dt=dcsync_ts,
        bus=bus,
        is_dcsync=True,
    )
    events.append(("security", dcsync_ts, dcsync_event))

    label = AttackLabel(
        attack_type="dcsync",
        mitre_technique="T1003.006",
        start_time=utc_now_str(attack_ts),
        end_time=utc_now_str(dcsync_ts),
        # target_users is whoever's behavioural vector carries the attack
        # telemetry: the attacker performing the 4662 replication request
        # (SubjectUserName), not the victim whose hash is stolen (who generates
        # no events and cannot be flagged).
        target_users=[attacker.samaccountname],
        source_ip=attacker.workstation_ip,
        details={
            "attacker": attacker.samaccountname,
            "target": target.samaccountname,
            "signature": "4662 with Replicating Directory Changes All GUID "
                         "from non-DC machine account",
        },
    )
    return events, label


def inject_asrep_roasting(
    roster: list[Employee],
    bus: EventBus,
    sim_date: date,
    rng: random.Random,
) -> tuple[InjectedEvents, AttackLabel]:
    """
    Simulates AS-REP Roasting (T1558.004): requests a TGT for a user
    with pre-authentication disabled, generating a 4768 with PreAuthType=0
    and RC4 encryption. Detection signature: PreAuthType='0' + Status='0x0' + EncryptionType='0x17' on a
    non-machine-account.
    """
    attacker = rng.choice(roster)
    # Pick a target with pre-auth disabled (in real env, these are
    # configured in AD; here we just pick a non-attacker user)
    target_pool = [e for e in roster if e.samaccountname != attacker.samaccountname]
    target = rng.choice(target_pool)
    attack_hour = rng.uniform(2.0, 6.0)  # off-hours
    attack_ts = local_to_utc(_float_hour_to_datetime(sim_date, attack_hour))

    events: InjectedEvents = []
    # The 4768 with pre_auth_type=0 and forced RC4
    asrep_event = gen_4768(
        samaccountname=target.samaccountname,
        src_ip=attacker.workstation_ip,
        utc_dt=attack_ts,
        bus=bus,
        pre_auth_type="0",  # pre-auth disabled — the vulnerability
        enc_type="0x17",     # force RC4 — crackable offline
        status="0x0",        # TGT was issued successfully
    )
    events.append(("security", attack_ts, asrep_event))

    label = AttackLabel(
        attack_type="asrep_roasting",
        mitre_technique="T1558.004",
        start_time=utc_now_str(attack_ts),
        end_time=utc_now_str(attack_ts),
        target_users=[target.samaccountname],
        source_ip=attacker.workstation_ip,
        details={
            "attacker": attacker.samaccountname,
            "target": target.samaccountname,
            "signature": "4768 PreAuthType=0 + EncryptionType=0x17 + Status=0x0",
        },
    )
    return events, label


def inject_lsass_dump(
    roster: list[Employee],
    bus: EventBus,
    sim_date: date,
    rng: random.Random,
) -> tuple[InjectedEvents, AttackLabel]:
    """
    Simulates LSASS memory dumping (T1003.001) via comsvcs.dll MiniDump.
    Detection signature: Sysmon EID 10 (ProcessAccess) targeting lsass.exe
    with high GrantedAccess mask (0x1FFFFF = PROCESS_ALL_ACCESS), or the
    comsvcs.dll MiniDump call appearing in Sysmon EID 1 command line.
    Source: Atomic Red Team T1003.001 Atomic Test #3 (comsvcs.dll),
    TrustedSec SysmonCommunityGuide process-access.md GrantedAccess table,
    Splunk LSASS hunting blog (GrantedAccess values for credential dumping).
    """
    attacker = rng.choice(roster)
    attack_hour = rng.uniform(10.0, 17.0)
    attack_ts = local_to_utc(_float_hour_to_datetime(sim_date, attack_hour))

    # Open a normal logon session for the attacker
    session = bus.open_session(
        samaccountname=attacker.samaccountname,
        domain="NEXOVATE",
        logon_type=2,
        auth_package="Kerberos",
        src_ip=attacker.workstation_ip,
        src_port=bus.new_src_port(),
        workstation=attacker.workstation,
        computer=attacker.workstation + ".nexovate.local",
        logon_time_utc=attack_ts,
        is_elevated=True,
        is_remote=False,
    )
    logon_event = gen_4624(session, attack_ts, bus, target_user_sid=_user_sid(attacker.samaccountname))
    events: InjectedEvents = [("security", attack_ts, logon_event)]

    # Sysmon EID 10 — ProcessAccess targeting lsass.exe with credential-dump GrantedAccess
    lsass_guid = bus.new_guid()
    lsass_proc = ProcessRecord(
        process_guid=lsass_guid, process_id=888,
        image="C:\\Windows\\System32\\lsass.exe",
        command_line="C:\\Windows\\system32\\lsass.exe",
        user="NT AUTHORITY\\SYSTEM", integrity_level="System",
        session_id=0, logon_id="0x3e7",
        parent_process_guid=bus.new_guid(),
        parent_image="C:\\Windows\\System32\\wininit.exe",
        start_time_utc=attack_ts, computer=attacker.workstation + ".nexovate.local",
    )
    # Attacker's process performing the dump (rundll32 + comsvcs.dll)
    dump_proc = bus.spawn_process(
        image="C:\\Windows\\System32\\rundll32.exe",
        command_line="C:\\Windows\\System32\\rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump (Get-Process lsass).id $env:TEMP\\lsass.dmp full",
        user=attacker.samaccountname, logon_id=session.target_logon_id,
        parent_image="C:\\Windows\\System32\\cmd.exe",
        parent_guid=session.process_guids[0] if session.process_guids else bus.new_guid(),
        computer=attacker.workstation + ".nexovate.local",
        start_time_utc=attack_ts + timedelta(seconds=2),
        integrity_level="High",
    )
    sysmon10_event = gen_eid10(
        source_proc=dump_proc, target_proc=lsass_proc,
        user_domain="NEXOVATE", utc_dt=attack_ts + timedelta(seconds=3),
        bus=bus, granted_access="0x1fffff",
    )
    events.append(("sysmon", attack_ts + timedelta(seconds=3), sysmon10_event))

    label = AttackLabel(
        attack_type="lsass_dump",
        mitre_technique="T1003.001",
        start_time=utc_now_str(attack_ts),
        end_time=utc_now_str(attack_ts + timedelta(seconds=3)),
        target_users=[attacker.samaccountname],
        source_ip=attacker.workstation_ip,
        details={
            "tool": "rundll32.exe comsvcs.dll MiniDump",
            "signature": "Sysmon EID 10 TargetImage=lsass.exe + GrantedAccess=0x1fffff",
        },
    )
    return events, label


def inject_golden_ticket(
    roster: list[Employee],
    bus: EventBus,
    sim_date: date,
    rng: random.Random,
) -> tuple[InjectedEvents, AttackLabel]:
    """
    Simulates a Golden Ticket (T1558.001): a forged TGT using the krbtgt
    hash, allowing domain-wide impersonation. The key detection signature is
    a Kerberos Type-3 (Network) logon on a target host with NO preceding
    4768 TGT request on any Domain Controller — because the ticket was
    forged offline, the DC never saw the AS-REQ.
    Source: Atomic Red Team T1558.001, Microsoft documentation on forged Kerberos tickets.
    """
    victim = rng.choice(roster)
    attacker_pool = [e for e in roster if e.samaccountname != victim.samaccountname]
    attacker = rng.choice(attacker_pool)
    attack_hour = rng.uniform(10.0, 16.0)
    attack_ts = local_to_utc(_float_hour_to_datetime(sim_date, attack_hour))

    # Golden Ticket: Type-3 Network logon via forged TGT, Kerberos auth
    # package (the forged ticket is still Kerberos-format on the wire, but
    # the DC never saw the AS-REQ that issued it).
    # No 4768 or 4769 is emitted from this src_ip — that IS the detection
    # signal (see aggregate.py cross-group IP-correlated detection).
    session = bus.open_session(
        samaccountname=victim.samaccountname,
        domain="NEXOVATE",
        logon_type=3,
        auth_package="Kerberos",
        src_ip=attacker.workstation_ip,
        src_port=bus.new_src_port(),
        workstation=attacker.workstation,
        computer=attacker.workstation + ".nexovate.local",
        logon_time_utc=attack_ts,
        is_elevated=victim.is_manager,
        is_remote=False,
    )
    logon_event = gen_4624(session, attack_ts, bus, target_user_sid=_user_sid(victim.samaccountname))
    events: InjectedEvents = [("security", attack_ts, logon_event)]

    label = AttackLabel(
        attack_type="golden_ticket",
        mitre_technique="T1558.001",
        start_time=utc_now_str(attack_ts),
        end_time=utc_now_str(attack_ts),
        target_users=[victim.samaccountname],
        source_ip=attacker.workstation_ip,
        details={
            "attacker": attacker.samaccountname,
            "signature": "4624 LogonType=3 Kerberos without preceding 4768/4769",
        },
    )
    return events, label


def inject_silver_ticket(
    roster: list[Employee],
    bus: EventBus,
    sim_date: date,
    rng: random.Random,
) -> tuple[InjectedEvents, AttackLabel]:
    """
    Simulates a Silver Ticket (T1558.002): a forged TGS for a specific
    service (e.g. CIFS/SQL), using a service account's hash. The detection
    signature is a Kerberos Type-3 logon to a target server with NO
    corresponding 4769 TGS request on any DC — because the TGS was forged
    offline without contacting the DC.
    Source: Atomic Red Team T1558.002.
    """
    victim = rng.choice(roster)
    attacker_pool = [e for e in roster if e.samaccountname != victim.samaccountname]
    attacker = rng.choice(attacker_pool)
    attack_hour = rng.uniform(10.0, 16.0)
    attack_ts = local_to_utc(_float_hour_to_datetime(sim_date, attack_hour))

    # Silver Ticket: Type-3 logon to a specific service host.
    # No 4769 is emitted on any DC — that IS the detection signal.
    session = bus.open_session(
        samaccountname=victim.samaccountname,
        domain="NEXOVATE",
        logon_type=3,
        auth_package="Kerberos",
        src_ip=attacker.workstation_ip,
        src_port=bus.new_src_port(),
        workstation=attacker.workstation,
        computer="SQL01.nexovate.local",
        logon_time_utc=attack_ts,
        is_elevated=False,
        is_remote=False,
    )
    logon_event = gen_4624(session, attack_ts, bus, target_user_sid=_user_sid(victim.samaccountname))
    events: InjectedEvents = [("security", attack_ts, logon_event)]

    label = AttackLabel(
        attack_type="silver_ticket",
        mitre_technique="T1558.002",
        start_time=utc_now_str(attack_ts),
        end_time=utc_now_str(attack_ts),
        target_users=[victim.samaccountname],
        source_ip=attacker.workstation_ip,
        details={
            "attacker": attacker.samaccountname,
            "target_service": "MSSQLSvc/SQL01.nexovate.local",
            "signature": "4624 LogonType=3 Kerberos to SQL01 without preceding 4769 on DC",
        },
    )
    return events, label


def inject_ntds_dump(
    roster: list[Employee],
    bus: EventBus,
    sim_date: date,
    rng: random.Random,
) -> tuple[InjectedEvents, AttackLabel]:
    """
    Simulates NTDS.dit extraction (T1003.003) via volume shadow copy +
    ntdsutil. Detection signature: process creation (4688/Sysmon EID 1)
    of vssadmin.exe or ntdsutil.exe with suspicious command-line arguments,
    followed by a file creation event (Sysmon EID 11) targeting NTDS.dit.
    Source: Atomic Red Team T1003.003 Atomic Tests #1–#3, AD_BEHAVIORAL_
    BASELINE_FIELDS.md §3.14 (4688 CommandLine detection).
    """
    attacker = rng.choice(roster)
    attack_hour = rng.uniform(2.0, 5.0)
    attack_ts = local_to_utc(_float_hour_to_datetime(sim_date, attack_hour))

    # Logon session for the attacker (requires DA-level access)
    session = bus.open_session(
        samaccountname=attacker.samaccountname,
        domain="NEXOVATE",
        logon_type=2,
        auth_package="Kerberos",
        src_ip=attacker.workstation_ip,
        src_port=bus.new_src_port(),
        workstation=attacker.workstation,
        computer="DC01.nexovate.local",
        logon_time_utc=attack_ts,
        is_elevated=True,
        is_remote=False,
    )
    logon_event = gen_4624(session, attack_ts, bus, target_user_sid=_user_sid(attacker.samaccountname))
    events: InjectedEvents = [("security", attack_ts, logon_event)]

    # Sysmon EID 1 — vssadmin.exe creating shadow copy
    vssadmin_proc = bus.spawn_process(
        image="C:\\Windows\\System32\\vssadmin.exe",
        command_line="vssadmin.exe create shadow /for=C:",
        user=attacker.samaccountname, logon_id=session.target_logon_id,
        parent_image="C:\\Windows\\System32\\cmd.exe",
        parent_guid=session.process_guids[0] if session.process_guids else bus.new_guid(),
        computer="DC01.nexovate.local",
        start_time_utc=attack_ts + timedelta(seconds=2),
        integrity_level="High",
    )
    sysmon1_vss = gen_eid1(vssadmin_proc, "NEXOVATE", attack_ts + timedelta(seconds=2), bus)
    events.append(("sysmon", attack_ts + timedelta(seconds=2), sysmon1_vss))

    # Sysmon EID 1 — ntdsutil.exe dumping the database
    ntdsutil_proc = bus.spawn_process(
        image="C:\\Windows\\System32\\ntdsutil.exe",
        command_line='ntdsutil.exe "ac i ntds" "ifm" "create full C:\\Temp\\dump" q q',
        user=attacker.samaccountname, logon_id=session.target_logon_id,
        parent_image="C:\\Windows\\System32\\cmd.exe",
        parent_guid=session.process_guids[0] if session.process_guids else bus.new_guid(),
        computer="DC01.nexovate.local",
        start_time_utc=attack_ts + timedelta(seconds=5),
        integrity_level="High",
    )
    sysmon1_ntds = gen_eid1(ntdsutil_proc, "NEXOVATE", attack_ts + timedelta(seconds=5), bus)
    events.append(("sysmon", attack_ts + timedelta(seconds=5), sysmon1_ntds))

    label = AttackLabel(
        attack_type="ntds_dump",
        mitre_technique="T1003.003",
        start_time=utc_now_str(attack_ts),
        end_time=utc_now_str(attack_ts + timedelta(seconds=5)),
        target_users=[attacker.samaccountname],
        source_ip=attacker.workstation_ip,
        details={
            "tools": ["vssadmin.exe create shadow", "ntdsutil.exe ifm create full"],
            "signature": "Sysmon EID 1 vssadmin+ntdsutil on DC, "
                         "followed by NTDS.dit extraction",
        },
    )
    return events, label


def inject_account_manipulation(
    roster: list[Employee],
    bus: EventBus,
    sim_date: date,
    rng: random.Random,
) -> tuple[InjectedEvents, AttackLabel]:
    """
    Simulates Account Manipulation (T1098) — adding a compromised user to
    a privileged security group (Domain Admins). Detection signature:
    Event 4728 (member added to global group) where TargetUserName is a
    privileged group (Domain Admins SID ending in -512, Enterprise Admins
    -519, Schema Admins -518).
    Source: Atomic Red Team T1098 Atomic Test #1, Microsoft Learn Event 4728.
    """
    actor = rng.choice([e for e in roster if e.department == "IT"])
    target_pool = [e for e in roster if e.samaccountname != actor.samaccountname
                   and e.department != "IT"]
    target = rng.choice(target_pool)
    attack_hour = rng.uniform(9.0, 17.0)
    attack_ts = local_to_utc(_float_hour_to_datetime(sim_date, attack_hour))

    # Actor's logon session (must be elevated to modify DA membership)
    session = bus.open_session(
        samaccountname=actor.samaccountname,
        domain="NEXOVATE",
        logon_type=2,
        auth_package="Kerberos",
        src_ip=actor.workstation_ip,
        src_port=bus.new_src_port(),
        workstation=actor.workstation,
        computer="DC01.nexovate.local",
        logon_time_utc=attack_ts,
        is_elevated=True,
        is_remote=False,
    )
    logon_event = gen_4624(session, attack_ts, bus, target_user_sid=_user_sid(actor.samaccountname))
    events: InjectedEvents = [("security", attack_ts, logon_event)]

    # 4728 — Member added to security-enabled global group (Domain Admins)
    DA_GROUP_SID = "S-1-5-21-1484628597-1684816888-3125425894-512"
    group_change_ts = attack_ts + timedelta(seconds=3)
    group_event = gen_group_change(
        actor_session=session,
        member_sam=target.samaccountname,
        member_dn=f"CN={target.samaccountname},OU=Users,DC=NEXOVATE,DC=local",
        group_name="Domain Admins",
        group_sid=DA_GROUP_SID,
        utc_dt=group_change_ts,
        bus=bus,
        event_id="4728",
    )
    events.append(("security", group_change_ts, group_event))

    label = AttackLabel(
        attack_type="account_manipulation",
        mitre_technique="T1098",
        start_time=utc_now_str(attack_ts),
        end_time=utc_now_str(group_change_ts),
        # Labelled to the actor (SubjectUserName) who performed the 4728
        # group-add -- the identity whose behavioural vector carries it -- not
        # the member who was added.
        target_users=[actor.samaccountname],
        source_ip=actor.workstation_ip,
        details={
            "actor": actor.samaccountname,
            "added_member": target.samaccountname,
            "group": "Domain Admins",
            "group_sid": DA_GROUP_SID,
            "signature": "4728 member added to Domain Admins (SID -512)",
        },
    )
    return events, label


def inject_insider_data_staging(
    roster: list[Employee],
    bus: EventBus,
    sim_date: date,
    rng: random.Random,
) -> tuple[InjectedEvents, AttackLabel]:
    """An authorised user collecting data at far above their normal rate.

    This is the threat class the credential-theft techniques do not cover:
    insider abuse, credential misuse and privilege abuse all look like a
    legitimate identity using a legitimate path. Nothing here is novel -- the
    account, the workstation and the file server are the ones this person uses
    every day, and every ticket request succeeds. What is abnormal is only the
    *rate*: a burst of service-ticket requests against their own file server,
    far above the one or two a normal session produces.

    A detector that recognises this cannot be relying on relationship novelty,
    because there is no new relationship to see. That is precisely why the
    scenario belongs in the benchmark: without it, nothing measures whether the
    engine can separate abuse-of-access from theft-of-access.
    """
    actor = rng.choice(roster)
    # Their own file server, over their own established path.
    server = "FS01"
    spn, spn_sid = _CIFS_SPNS.get(
        server, (f"cifs/{server}.nexovate.local",
                 "S-1-5-21-1484628597-1684816888-3125425894-1099"))

    # During working hours: an insider does this while their access is expected.
    start_hour = rng.uniform(10.0, 16.0)
    start_ts = local_to_utc(_float_hour_to_datetime(sim_date, start_hour))
    src_ip = actor.workstation_ip

    events: InjectedEvents = []
    ts = start_ts
    n_requests = rng.randint(60, 140)
    for _ in range(n_requests):
        ts = ts + timedelta(seconds=rng.uniform(1.0, 8.0))
        events.append(("security", ts,
                        gen_4769(actor.samaccountname, spn, spn_sid, src_ip, ts, bus)))

    label = AttackLabel(
        attack_type="insider_data_staging",
        mitre_technique="T1005",
        start_time=utc_now_str(start_ts),
        end_time=utc_now_str(ts),
        target_users=[actor.samaccountname],
        source_ip=src_ip,
        details={
            "actor": actor.samaccountname,
            "service_ticket_requests": n_requests,
            "signature": f"{n_requests} service-ticket requests for {server} from "
                         f"{actor.samaccountname}'s own workstation within "
                         f"{(ts - start_ts).total_seconds() / 60:.0f} minutes; every "
                         "relationship involved is one the account already had",
        },
    )
    return events, label


def inject_psexec_lateral_movement(
    roster: list[Employee],
    bus: EventBus,
    sim_date: date,
    rng: random.Random,
) -> tuple[InjectedEvents, AttackLabel]:
    """Remote execution over SMB, leaving a service-control named pipe behind.

    PsExec-class tooling (Sysinternals PsExec, Impacket psexec.py/smbexec) copies
    a service binary to ADMIN$, starts it through the Service Control Manager and
    talks to it over a named pipe. Published detections are lists of pipe names --
    `psexesvc`, `remcom_communication`, anything ending `-stdin`/`-stdout` -- and
    OPSEC-aware variants exist precisely to defeat that: SharpNoPSExec and patched
    Impacket let the operator rename the pipe to something ordinary like `atsvc`
    (Task Scheduler) or `winspool` (Print Spooler).

    Half the injections here use a tool-shaped name and half use the evasive
    rename, on purpose. A name list catches the first half only. A model of which
    pipes THIS ACCOUNT has ever used catches both, because an account that has
    never done service-control work has never touched either pipe -- which is the
    claim this engine makes about signatures, made falsifiable.
    """
    from core.daily_simulation import software_profile

    attacker = rng.choice([e for e in roster if e.is_manager] or roster)
    target = rng.choice([e for e in roster if e.workstation != attacker.workstation])

    # Evasive half: a pipe that exists on every host, so the NAME is unremarkable
    # and only its use by this account is not. The tool-shaped half is the
    # baseline case a name list would also catch.
    evasive = rng.random() < 0.5
    if evasive:
        pipe = rng.choice(["atsvc", "winspool", "spoolss"])
    else:
        pipe = rng.choice([f"psexesvc-{target.workstation}-{rng.randint(1000, 9999)}",
                           "RemCom_communication", "paexec"])
    # Never a pipe the attacker's own account routinely uses, or the injection
    # would be labelled as an attack while being, correctly, unremarkable.
    own_pipes, _ = software_profile(attacker)
    if pipe in own_pipes:
        pipe = f"{pipe}-svc"

    attack_ts = local_to_utc(_float_hour_to_datetime(sim_date, rng.uniform(9.0, 18.0)))
    src_ip = attacker.workstation_ip
    events: InjectedEvents = []

    session = bus.open_session(
        samaccountname=attacker.samaccountname,
        domain="NEXOVATE",
        logon_type=3,
        auth_package="NTLM",
        src_ip=src_ip,
        src_port=bus.new_src_port(),
        workstation=attacker.workstation,
        computer=target.workstation + ".nexovate.local",
        logon_time_utc=attack_ts,
        is_elevated=True,
        is_remote=True,
    )
    events.append(("security", attack_ts,
                   gen_4624(session, attack_ts, bus,
                            target_user_sid=_user_sid(attacker.samaccountname))))

    # The service host process, then the pipe it serves and the client connect.
    svc_proc = bus.spawn_process(
        image=rf"C:\Windows\{pipe.split('-')[0]}.exe",
        command_line=rf"C:\Windows\{pipe.split('-')[0]}.exe -service",
        user=attacker.samaccountname, logon_id=session.target_logon_id,
        parent_image=r"C:\Windows\System32\services.exe",
        parent_guid=bus.new_guid(),
        computer=target.workstation + ".nexovate.local",
        start_time_utc=attack_ts + timedelta(seconds=2),
        integrity_level="System",
    )
    events.append(("sysmon", attack_ts + timedelta(seconds=2),
                   gen_eid1(svc_proc, "NEXOVATE", attack_ts + timedelta(seconds=2), bus)))

    for i, offset in enumerate((3, 4)):
        ts = attack_ts + timedelta(seconds=offset)
        gen = gen_eid17 if i == 0 else gen_eid18
        events.append(("sysmon", ts, gen(svc_proc, rf"\\.\pipe\{pipe}", ts, bus)))

    # Redirection pipes, the artifact the "-stdin/-stdout" detections key on.
    if not evasive:
        for suffix, offset in (("stdin", 5), ("stdout", 5), ("stderr", 6)):
            ts = attack_ts + timedelta(seconds=offset)
            events.append(("sysmon", ts,
                           gen_eid17(svc_proc, rf"\\.\pipe\{pipe}-{suffix}", ts, bus)))

    end_ts = attack_ts + timedelta(seconds=8)
    label = AttackLabel(
        attack_type="psexec_lateral_movement",
        mitre_technique="T1021.002",     # SMB/Windows Admin Shares
        start_time=utc_now_str(attack_ts),
        end_time=utc_now_str(end_ts),
        target_users=[attacker.samaccountname],
        source_ip=src_ip,
        details={
            "actor": attacker.samaccountname,
            "target_host": target.workstation,
            "pipe": pipe,
            "evasive_rename": evasive,
            "signature": (f"{attacker.samaccountname} executed remotely on "
                          f"{target.workstation} over \\\\.\\pipe\\{pipe}"
                          + (" -- an ordinary Windows pipe name chosen to defeat a "
                             "name-list detection; only novelty for this account "
                             "distinguishes it" if evasive else
                             " -- a tool-shaped pipe name a name list would also catch")),
        },
    )
    return events, label


def inject_insider_share_exfiltration(
    roster: list[Employee],
    bus: EventBus,
    sim_date: date,
    rng: random.Random,
) -> tuple[InjectedEvents, AttackLabel]:
    """An authorised user reading a department share that is not theirs.

    The second insider sub-class, and deliberately NOT a variant of
    ``insider_data_staging``: that one is a pure RATE anomaly over the account's
    own path and is kept novelty-free on purpose, because it is what proves the
    volume instrument works. Collapsing the two would destroy that measurement.

    This is SCOPE abuse instead. Every employee's routine share access is
    department-keyed -- one share, every day, for their whole tenure -- so an
    account reading another department's share is a relationship it has never
    had. That is the shape real insider data theft takes when the actor already
    holds broad file permissions: the access is authorised, the authentication is
    ordinary, and only the *reach* is wrong.

    Telemetry is what a real file server writes for it: one 5140 share connect,
    then a 5145 per file touched (Audit Detailed File Share), from the actor's own
    workstation over their own logon. No new host, no new credential, no failure,
    no privileged operation -- so the credential-theft views see nothing, and only
    an (account -> share) relationship model can distinguish it from a normal day.
    """
    from core.daily_simulation import _DEPT_FILES, _DEPT_SHARES

    # Someone whose own department has a share to deviate FROM: without a
    # baseline there is no deviation to measure, only a cold-start.
    candidates = [e for e in roster if e.department in _DEPT_SHARES]
    actor = rng.choice(candidates)
    foreign = [d for d in _DEPT_SHARES if d != actor.department]
    target_dept = rng.choice(foreign)
    share_name, _share_path, share_server = _DEPT_SHARES[target_dept]
    srv_fqdn = f"{share_server}.{DOMAIN_FQDN}"

    # Working hours: an insider acts while their presence is unremarkable.
    start_ts = local_to_utc(_float_hour_to_datetime(sim_date, rng.uniform(10.0, 16.0)))
    src_ip = actor.workstation_ip

    events: InjectedEvents = []
    session = bus.open_session(
        samaccountname=actor.samaccountname,
        domain="NEXOVATE",
        logon_type=3,
        auth_package="Kerberos",
        src_ip=src_ip,
        src_port=bus.new_src_port(),
        workstation=actor.workstation,
        computer=actor.workstation + ".nexovate.local",
        logon_time_utc=start_ts,
        is_elevated=False,
        is_remote=False,
    )

    # A ticket for the file server carrying the share, as Kerberos requires.
    if share_server in _CIFS_SPNS:
        fspn, fspn_sid = _CIFS_SPNS[share_server]
        events.append(("security", start_ts,
                       gen_4769(actor.samaccountname, fspn, fspn_sid, src_ip, start_ts, bus)))

    events.append(("security", start_ts,
                   gen_5140(session, share_name, _share_path, src_ip, start_ts, bus,
                            share_server=srv_fqdn)))

    # Then a sustained read of that department's documents. Volume is well above a
    # normal browse but not absurd -- the signal this exists to test is the share
    # itself, not the count.
    pool = _DEPT_FILES.get(target_dept) or ["report.docx"]
    ts = start_ts
    n_files = rng.randint(40, 90)
    for i in range(n_files):
        ts = ts + timedelta(seconds=rng.uniform(2.0, 15.0))
        fname = f"{rng.choice(pool)}" if i % 3 else f"archive/{rng.choice(pool)}"
        events.append(("security", ts,
                       gen_5145(session, share_name, fname, src_ip, ts, bus,
                                share_server=srv_fqdn, access_mask="0x1")))

    label = AttackLabel(
        attack_type="insider_share_exfiltration",
        mitre_technique="T1039",       # Data from Network Shared Drive
        start_time=utc_now_str(start_ts),
        end_time=utc_now_str(ts),
        target_users=[actor.samaccountname],
        source_ip=src_ip,
        details={
            "actor": actor.samaccountname,
            "actor_department": actor.department,
            "target_share": share_name,
            "files_read": n_files,
            "signature": f"{actor.samaccountname} ({actor.department}) read {n_files} "
                         f"files from {share_name}, a {target_dept} share their "
                         f"account has never touched; own workstation, own logon, "
                         f"every access authorised",
        },
    )
    return events, label


def inject_nhi_schedule_hijack(
    roster: list[Employee],
    bus: EventBus,
    sim_date: date,
    rng: random.Random,
) -> tuple[InjectedEvents, AttackLabel]:
    """A compromised service-account credential used outside its schedule.

    The non-human-identity equivalent of insider abuse, and the class the
    relational engine structurally cannot see. A service account's credential is
    stolen (Kerberoasting makes service accounts the standard target) and the
    attacker rides it: the account authenticates to *its own* server and requests
    tickets for *its own* service, exactly as it always does.

    The only thing wrong is *when*. A backup job that has only ever run in its
    small hours maintenance window is suddenly active in the middle of the
    afternoon. Deliberately:

      * no new host, no new SPN, no new relationship of any kind -- so every
        relationship view scores this as routine and the shipped detector is
        blind to it by construction, exactly as it is to insider volume abuse;
      * no RC4 downgrade, no failure burst, no privileged-group change -- there is
        no signature to key on;
      * a session-sized volume, not a flood -- so detecting it requires modelling
        *time*, and a volume detector cannot take the credit.

    That makes it the honest test of whether an NHI temporal baseline adds a
    capability the estate did not already have. Sources: service accounts are
    documented as the identities that "operate 24/7 and do not follow patterns
    like working hours", so a human-shaped behavioural model raises nothing on
    them; off-hours use of a machine credential is the corresponding signal.
    """
    from core.employees import build_service_accounts

    svc = rng.choice(build_service_accounts())
    server = svc.server_hostname
    spn, spn_sid = _CIFS_SPNS.get(
        server, (f"cifs/{server.lower()}.nexovate.local",
                 "S-1-5-21-1484628597-1684816888-3125425894-1099"))

    # Mid-afternoon: squarely inside the business day and far outside every
    # maintenance window the service accounts run in (backup 02:30, SQL 04:00,
    # WSUS 03:00, SCCM 22:00, log rotation 23:30 IST). The attacker works when
    # people work, which is precisely when this identity never does.
    start_hour = rng.uniform(13.0, 16.0)
    start_ts = local_to_utc(_float_hour_to_datetime(sim_date, start_hour))
    src_ip = svc.server_ip

    events: InjectedEvents = []
    # Its own logon, from its own server: a relationship it already has.
    session = bus.open_session(
        samaccountname=svc.samaccountname, domain="NEXOVATE",
        logon_type=5, auth_package="Kerberos",
        src_ip=src_ip, src_port=0,
        workstation=svc.server_hostname,
        computer=f"{svc.server_hostname}.nexovate.local",
        logon_time_utc=start_ts, is_elevated=True,
    )
    events.append(("security", start_ts,
                   gen_4624(session, start_ts, bus, _user_sid(svc.samaccountname))))

    # A session's worth of ordinary work, at the wrong time of day.
    ts = start_ts
    n_requests = rng.randint(12, 25)
    for _ in range(n_requests):
        ts = ts + timedelta(seconds=rng.uniform(5.0, 45.0))
        events.append(("security", ts,
                       gen_4769(svc.samaccountname, spn, spn_sid, src_ip, ts, bus)))
    bus.close_session(session.target_logon_id)

    label = AttackLabel(
        attack_type="nhi_schedule_hijack",
        mitre_technique="T1078.003",   # Valid Accounts: Local/Service Accounts
        start_time=utc_now_str(start_ts),
        end_time=utc_now_str(ts),
        target_users=[svc.samaccountname],
        source_ip=src_ip,
        details={
            "actor": svc.samaccountname,
            "service_ticket_requests": n_requests,
            "signature": f"service account {svc.samaccountname} active at "
                         f"{start_hour:04.1f}h local, outside every window it has "
                         f"ever run in; {n_requests} service-ticket requests for "
                         f"{server}, its own server. No new relationship, no "
                         "downgrade, no failure -- only the time is wrong",
        },
    )
    return events, label


ATTACK_REGISTRY = {
    "pass_the_hash": inject_pass_the_hash,
    "kerberoasting": inject_kerberoasting,
    "password_spray": inject_password_spray,
    "dcsync": inject_dcsync,
    "asrep_roasting": inject_asrep_roasting,
    "lsass_dump": inject_lsass_dump,
    "golden_ticket": inject_golden_ticket,
    "silver_ticket": inject_silver_ticket,
    "ntds_dump": inject_ntds_dump,
    "account_manipulation": inject_account_manipulation,
    "insider_data_staging": inject_insider_data_staging,
    "insider_share_exfiltration": inject_insider_share_exfiltration,
    "psexec_lateral_movement": inject_psexec_lateral_movement,
    "nhi_schedule_hijack": inject_nhi_schedule_hijack,
}

# Two corpora are DIFFERENT attack classes from the credential-theft /
# lateral-movement techniques above, and each is measured on its own rather than
# folded into the headline recall:
#
#   * insider data staging (T1005) creates no new relationship, only an abnormal
#     *rate* over an existing one (docs/evaluation.md, "Open capability: volume
#     abuse over an established relationship");
#   * NHI schedule hijack (T1078.003) creates no new relationship either, only
#     activity at a *time* the identity never operates (docs/identities.md).
#
# Both are invisible to a purely relational detector by construction, so scoring
# them inside the headline would understate a figure that measures a different
# capability. They stay in ATTACK_REGISTRY so `--inject-attacks all` can generate
# them, and are excluded from the headline preset below.
#
# This split exists because `all` silently changed meaning once these corpora were
# added: the documented headline (53/60 over ten techniques) is reproduced by
# `--inject-attacks headline`, NOT by `--inject-attacks all`. Keeping the headline
# set named and explicit is what keeps the figure reproducible as the registry
# grows.
INSIDER_CORPUS_ATTACKS = ("insider_data_staging", "insider_share_exfiltration")
NHI_CORPUS_ATTACKS = ("nhi_schedule_hijack",)
# Remote execution over SMB, kept out of the headline for the same reason as the
# other corpora: it exists to exercise the `pipe` view, which is implemented and
# NOT shipped. Folding it into the headline would change that figure's
# denominator -- making it incomparable with every number already published --
# to measure a capability the engine does not currently claim. If `pipe` ever
# earns its place, promoting this is a deliberate, documented re-baseline.
PIPE_CORPUS_ATTACKS = ("psexec_lateral_movement",)
NON_HEADLINE_ATTACKS = INSIDER_CORPUS_ATTACKS + NHI_CORPUS_ATTACKS + PIPE_CORPUS_ATTACKS
HEADLINE_ATTACKS = tuple(k for k in ATTACK_REGISTRY if k not in NON_HEADLINE_ATTACKS)

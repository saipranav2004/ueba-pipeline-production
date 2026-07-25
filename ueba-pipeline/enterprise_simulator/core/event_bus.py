"""
event_bus.py — Central event correlation and session state tracker.

This is the heart of cross-source consistency. When a user logs on, a
session is registered here. All subsequent events in that session
(Sysmon process creation, DNS queries, PowerShell execution, file access)
reference the same TargetLogonId, ProcessGuid, and timestamps.

Without this, events across log sources would be internally inconsistent.
With it, a Sysmon EID 1 ProcessGuid can be traced to a Security 4624
TargetLogonId, which can be traced to a Kerberos 4768/4769 on the DC —
exactly as real Windows produces.
"""

from __future__ import annotations

import hashlib
import os
import random
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


def _new_guid() -> str:
    """
    Produces a Windows-style GUID string using OS entropy.
    WARNING: This function is intentionally non-deterministic.
    Use bus.new_guid() everywhere inside generators for reproducibility.
    This function is kept only for legacy call sites that receive an explicit guid param.
    """
    return "{" + str(uuid.uuid4()).upper() + "}"


def _seeded_guid(rng: random.Random) -> str:
    """
    Produces a deterministic Windows-style GUID from a seeded RNG.
    RFC4122 v4 compliant: version=4, variant=10xx.
    Use this inside all generators via bus.new_guid() for reproducible output.
    """
    raw = bytearray(rng.getrandbits(8) for _ in range(16))
    raw[6] = (raw[6] & 0x0F) | 0x40   # version = 4
    raw[8] = (raw[8] & 0x3F) | 0x80   # variant = 10xx
    h = raw.hex()
    guid = f"{{{h[0:8].upper()}-{h[8:12].upper()}-{h[12:16].upper()}-{h[16:20].upper()}-{h[20:32].upper()}}}"
    return guid


def _new_logon_id(rng: random.Random) -> str:
    """Produces a hex logon session ID like 0x3A2C0E1."""
    return hex(rng.randint(0x10000, 0xFFFFFFF))


def _new_pid(rng: random.Random) -> int:
    """Random process PID in Windows typical range 4–32760."""
    return rng.choice(range(4, 32760, 4))   # PIDs are multiples of 4


def _new_pid_hex(rng: random.Random) -> str:
    return hex(_new_pid(rng))


def _record_id(counter_dict: dict, key: str) -> int:
    """Monotonically increasing record ID per log channel / host."""
    counter_dict[key] = counter_dict.get(key, 1000) + 1
    return counter_dict[key]


def _rfc4122_v4_from_sha256(namespace_key: str) -> str:
    """
    Generate an RFC4122 version-4-shaped UUID from a deterministic SHA-256 digest.
    Approach verified from EvidenceForge utils/rng.py stable_uuid():
      digest[6] = (digest[6] & 0x0F) | 0x40  → forces version nibble to '4'
      digest[8] = (digest[8] & 0x3F) | 0x80  → forces variant bits to '10xx'
    Source: https://github.com/Cisco-Talos/EvidenceForge/blob/main/src/evidenceforge/utils/rng.py
    """
    import uuid as _uuid
    raw = hashlib.sha256(namespace_key.encode()).digest()[:16]
    ba  = bytearray(raw)
    ba[6] = (ba[6] & 0x0F) | 0x40   # version = 4
    ba[8] = (ba[8] & 0x3F) | 0x80   # variant = 10xx (RFC4122)
    return str(_uuid.UUID(bytes=bytes(ba)))


def stable_agent_id(hostname: str) -> str:
    """
    Stable RFC4122 v4 Winlogbeat agent.id derived from hostname.
    Real Winlogbeat writes its agent.id to disk and reuses it across events and days.
    UUID v4 compliance verified: version nibble=4, variant=10xx.
    """
    return _rfc4122_v4_from_sha256(f"winlogbeat_agent:{hostname}")


def stable_ephemeral_id(hostname: str, seed: int) -> str:
    """
    Stable RFC4122 v4 ephemeral_id per (host, seed).
    Changes per Winlogbeat process restart but constant within a simulation run.
    """
    return _rfc4122_v4_from_sha256(f"winlogbeat_ephemeral:{hostname}:{seed}")


def sha256_hash(path: str) -> str:
    """Deterministic fake SHA256 from a file path — stable across runs."""
    return hashlib.sha256(path.encode()).hexdigest().upper()


def md5_hash(path: str) -> str:
    return hashlib.md5(path.encode()).hexdigest().upper()


def imphash(path: str) -> str:
    """Fake IMPHASH derived from file path — good enough for logs."""
    return hashlib.md5((path + "_imphash").encode()).hexdigest().upper()


# ── WindowsRecordIdCounter ────────────────────────────────────────────────────
class WindowsRecordIdCounter:
    """
    Per-host, per-channel monotonic EventRecordID counter with realistic starting
    values and background-event gaps.

    Starting values are sized to host type (EvidenceForge windows_record_ids.py):
      DC Security:        6,000,000 – 35,000,000
      Server channels:      180,000 –  4,500,000
      Workstation:           25,000 –    950,000
    Between logged events, background activity (Sysmon filter drops, unlogged
    subcategories) increments the counter by a rate proportional to elapsed time.

    Source: github.com/Cisco-Talos/EvidenceForge/blob/main/
            src/evidenceforge/generation/emitters/windows_record_ids.py
    """

    def __init__(self, channel: str, hostname: str, seed: int):
        self._rng = random.Random(
            int(hashlib.md5(f"record_id:{channel}:{hostname}:{seed}".encode()).hexdigest()[:8], 16)
        )
        host_lower = hostname.lower()
        is_dc     = "dc" in host_lower or "dc01" in host_lower or "dc02" in host_lower
        is_server = any(t in host_lower for t in (
            "sql", "app", "web", "fs", "exch", "backup", "sccm", "wsus", "rds", "print", "jump"
        ))

        if channel.lower() == "security":
            if is_dc:
                self._current  = self._rng.randint(6_000_000, 35_000_000)
                self._bg_rate  = self._rng.uniform(0.06, 0.42)
            elif is_server:
                self._current  = self._rng.randint(180_000, 4_500_000)
                self._bg_rate  = self._rng.uniform(0.015, 0.16)
            else:
                self._current  = self._rng.randint(25_000, 950_000)
                self._bg_rate  = self._rng.uniform(0.004, 0.055)
        else:
            if is_dc:
                self._current  = self._rng.randint(350_000, 5_500_000)
                self._bg_rate  = self._rng.uniform(0.01, 0.095)
            elif is_server:
                self._current  = self._rng.randint(80_000, 1_800_000)
                self._bg_rate  = self._rng.uniform(0.005, 0.06)
            else:
                self._current  = self._rng.randint(15_000, 750_000)
                self._bg_rate  = self._rng.uniform(0.0015, 0.035)

        self._last_ts: float = 0.0

    def next(self, utc_epoch: float = 0.0) -> int:
        """Return next EventRecordID with a gap for background events."""
        hidden = 0
        if utc_epoch and self._last_ts:
            elapsed  = max(0.0, utc_epoch - self._last_ts)
            expected = elapsed * self._bg_rate
            hidden   = int(expected)
            if self._rng.random() < (expected - hidden):
                hidden += 1
        self._current += 1 + hidden
        if utc_epoch:
            self._last_ts = utc_epoch
        return self._current


# ── Session state ─────────────────────────────────────────────────────────────
@dataclass
class LogonSession:
    """
    Represents one authenticated session for a user.
    Created when a 4624 is generated; closed when a 4634 is generated.
    Sysmon events in this session reference session_guid for correlation.
    """
    samaccountname:  str
    domain:          str
    target_logon_id: str          # hex, e.g. "0x3a2c0e1"
    logon_type:      int          # 2=Interactive, 3=Network, 10=RDP
    auth_package:    str          # "Kerberos", "NTLM", "Negotiate"
    src_ip:          str
    src_port:        int
    workstation:     str
    computer:        str          # machine the logon landed on
    logon_time_utc:  datetime
    is_elevated:     bool = False
    is_remote:       bool = False
    # Kerberos correlation
    logon_guid:      str = ""   # set explicitly by open_session() via seeded RNG
    # Linked processes spawned during this session
    process_guids:   list[str] = field(default_factory=list)
    active:          bool = True


@dataclass
class ProcessRecord:
    """
    Represents a running process — created by Sysmon EID 1 / Security 4688.
    Child processes reference parent_process_guid.
    """
    process_guid:       str
    process_id:         int
    image:              str          # full exe path
    command_line:       str
    user:               str
    integrity_level:    str
    session_id:         int
    logon_id:           str          # links to LogonSession.target_logon_id
    parent_process_guid: str
    parent_image:       str
    start_time_utc:     datetime
    computer:           str
    hashes:             dict[str, str] = field(default_factory=dict)


@dataclass
class KerberosTicket:
    """
    Tracks TGT and TGS issuances for cross-event correlation (4768→4769→4624).
    """
    user:            str
    service_name:    str
    ticket_id:       str          # LogonGuid value
    issued_utc:      datetime
    encryption_type: str          # "0x12"=AES256, "0x17"=RC4, "0x11"=AES128
    is_tgt:          bool         # True=4768, False=4769


# ── Central correlation bus ───────────────────────────────────────────────────
class EventBus:
    """
    Maintains shared state for the simulation run.
    Generators register and look up sessions/processes here so that
    cross-source events reference consistent identifiers.
    """

    def __init__(self, rng: random.Random, sim_seed: int = 20250106):
        self._rng               = rng
        self._sim_seed          = sim_seed  # for stable_ephemeral_id per host
        self._record_counters: dict[tuple[str,str], WindowsRecordIdCounter] = {}
        self._sessions:  dict[str, LogonSession]  = {}  # logon_id → session
        self._processes: dict[str, ProcessRecord] = {}  # process_guid → record
        self._tickets:   list[KerberosTicket]     = []
        self._record_counters: dict[tuple[str,str], WindowsRecordIdCounter] = {}  # (channel, host) → counter

        # Cache: user → [active session logon_ids]
        self._user_sessions: dict[str, list[str]] = {}

    # ── Session management ────────────────────────────────────────────────────

    def open_session(
        self,
        samaccountname: str,
        domain: str,
        logon_type: int,
        auth_package: str,
        src_ip: str,
        src_port: int,
        workstation: str,
        computer: str,
        logon_time_utc: datetime,
        is_elevated: bool = False,
        is_remote: bool = False,
        logon_guid: str = "",
    ) -> LogonSession:
        """
        Creates and registers a new logon session.
        logon_guid: if not supplied, generated deterministically from the seeded
        bus RNG (never from uuid.uuid4(), which would break reproducibility).
        Callers that already have a Kerberos TGT guid (4768/4769 chain) should
        pass it explicitly so 4624.LogonGuid matches the TGT.
        """
        logon_id = _new_logon_id(self._rng)
        if not logon_guid:
            logon_guid = self.new_guid()
        session  = LogonSession(
            samaccountname  = samaccountname,
            domain          = domain,
            target_logon_id = logon_id,
            logon_type      = logon_type,
            auth_package    = auth_package,
            src_ip          = src_ip,
            src_port        = src_port,
            workstation     = workstation,
            computer        = computer,
            logon_time_utc  = logon_time_utc,
            is_elevated     = is_elevated,
            is_remote       = is_remote,
            logon_guid      = logon_guid,
        )
        self._sessions[logon_id] = session
        self._user_sessions.setdefault(samaccountname, []).append(logon_id)
        return session

    def close_session(self, logon_id: str) -> LogonSession | None:
        """Marks a session as closed (triggers a 4634 logoff event)."""
        session = self._sessions.get(logon_id)
        if session:
            session.active = False
        return session

    def get_session(self, logon_id: str) -> LogonSession | None:
        return self._sessions.get(logon_id)

    def active_sessions_for_user(self, samaccountname: str) -> list[LogonSession]:
        ids = self._user_sessions.get(samaccountname, [])
        return [self._sessions[i] for i in ids if i in self._sessions and self._sessions[i].active]

    # ── Process management ────────────────────────────────────────────────────

    def spawn_process(
        self,
        image:              str,
        command_line:       str,
        user:               str,
        logon_id:           str,
        parent_image:       str,
        parent_guid:        str,
        computer:           str,
        start_time_utc:     datetime,
        integrity_level:    str = "Medium",
        session_id:         int = 1,
    ) -> ProcessRecord:
        """Creates and registers a new process record."""
        guid = self.new_guid()
        pid  = _new_pid(self._rng)
        proc = ProcessRecord(
            process_guid       = guid,
            process_id         = pid,
            image              = image,
            command_line       = command_line,
            user               = user,
            integrity_level    = integrity_level,
            session_id         = session_id,
            logon_id           = logon_id,
            parent_process_guid= parent_guid,
            parent_image       = parent_image,
            start_time_utc     = start_time_utc,
            computer           = computer,
            hashes             = {
                "SHA256":  sha256_hash(image),
                "MD5":     md5_hash(image),
                "IMPHASH": imphash(image),
            },
        )
        self._processes[guid] = proc

        # Link to session
        session = self._sessions.get(logon_id)
        if session:
            session.process_guids.append(guid)

        return proc

    def get_process(self, guid: str) -> ProcessRecord | None:
        return self._processes.get(guid)

    # ── Kerberos ticket tracking ──────────────────────────────────────────────

    def issue_ticket(
        self,
        user:            str,
        service_name:    str,
        issued_utc:      datetime,
        encryption_type: str = "0x12",
        is_tgt:          bool = True,
    ) -> KerberosTicket:
        ticket = KerberosTicket(
            user            = user,
            service_name    = service_name,
            ticket_id       = self.new_guid(),
            issued_utc      = issued_utc,
            encryption_type = encryption_type,
            is_tgt          = is_tgt,
        )
        self._tickets.append(ticket)
        return ticket

    def latest_tgt(self, user: str) -> KerberosTicket | None:
        """Returns the most recent TGT for a user (for LogonGuid correlation)."""
        for t in reversed(self._tickets):
            if t.user == user and t.is_tgt:
                return t
        return None

    # ── Record ID management ─────────────────────────────────────────────────



    # ── Utility ──────────────────────────────────────────────────────────────

    def new_guid(self) -> str:
        """Seeded, deterministic GUID for reproducible output. RFC4122 v4."""
        return _seeded_guid(self._rng)

    def next_record_id(self, channel_or_key: str, hostname: str = "", utc_epoch: float | None = None) -> int:
        """Return the next EventRecordID for a channel+hostname pair.

        Accepts two calling conventions:
          bus.next_record_id("Security:DC01.nexovate.local")  # legacy key
          bus.next_record_id("Security", "DC01.nexovate.local", ts)  # explicit
        """
        if hostname:
            channel = channel_or_key
        else:
            # Parse legacy "channel:hostname" key
            parts = channel_or_key.split(":", 1)
            channel  = parts[0]
            hostname = parts[1] if len(parts) > 1 else channel_or_key
        key = (channel.lower(), hostname.lower())
        if key not in self._record_counters:
            self._record_counters[key] = WindowsRecordIdCounter(channel, hostname, self._sim_seed)
        return self._record_counters[key].next(utc_epoch)

    def new_pid(self) -> int:
        return _new_pid(self._rng)

    def new_logon_id(self) -> str:
        return _new_logon_id(self._rng)

    def new_src_port(self) -> int:
        """Random ephemeral source port — real Windows uses 49152–65535."""
        return self._rng.randint(49152, 65535)

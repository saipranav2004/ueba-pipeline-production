"""LANL 2015 Comprehensive Cyber Security Events adapter.

Maps the LANL authentication log (`auth.txt`) and red-team labels (`redteam.txt`)
into `NormalizedEvent`s so the production engine can be evaluated on the canonical
public AD lateral-movement benchmark with no engine change.

`auth.txt` columns (comma-separated):
    time, src_user@domain, dst_user@domain, src_computer, dst_computer,
    auth_type, logon_type, auth_orientation, success/failure

`redteam.txt` columns:
    time, user@domain, src_computer, dst_computer
Each red-team row is a known-malicious authentication; an auth event is malicious
if it matches on (time, computer pair, user) where the user is either the source
or destination user of that auth (the compromised credential appears as one or
both).

The construction — host->host authentication edges typed by logon type, scored
online — follows Bowman et al. (RAID 2020) and Kent (LANL, 2015). The files sit
behind a data-use agreement and are not downloadable without accepting it; place
them locally and point the `lanl-eval` CLI at them.
"""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from ueba_pipeline.parsing.normalize import NormalizedEvent

# LANL times are integer seconds from an arbitrary epoch (t=1 is the first
# second). Anchor to a fixed reference so event_time is a real datetime.
_LANL_EPOCH = datetime(2015, 1, 1, tzinfo=UTC)

# LANL logon_type -> the numeric LogonType the graph track's edge projection
# reads. Unknown/"?" values default to Network (3), the dominant LANL type and
# the one that forms host->host lateral-movement edges.
_LOGON_TYPE_MAP = {
    "Network": "3", "Interactive": "2", "RemoteInteractive": "10",
    "Service": "5", "Batch": "4", "NetworkCleartext": "8",
}


def _u(user: str) -> str:
    return (user or "").split("@")[0].strip().lower()


def lanl_time(t: str) -> datetime:
    return _LANL_EPOCH + timedelta(seconds=int(t))


def _to_event(row: list[str]) -> NormalizedEvent | None:
    if len(row) < 9:
        return None
    t, su, du, sc, dc, auth_type, logon_type, orientation, result = row[:9]
    # Only logon events (not logoff) form authentication-graph edges.
    if "logon" not in orientation.strip().lower():
        return None
    success = result.strip().lower().startswith("succ")
    src_l, dst_l = sc.strip().lower(), dc.strip().lower()
    return NormalizedEvent(
        event_time=lanl_time(t),
        ingest_time=None,
        channel="lanl",
        # Exact event_type so the full engine (is_graph_event) routes these, not
        # only the bare detector.
        event_id="4624" if success else "4625",
        event_type="4624" if success else "4625",
        group="auth",
        computer_name=dst_l,
        outcome="success" if success else "failure",
        keywords=[],
        fields={
            "target_user_name": _u(du),
            "src_user_name": _u(su),                 # retained for red-team matching
            "src_ip": src_l,                          # LANL has computers, not IPs
            "workstation": src_l,
            "computer_name": dst_l,
            "logon_type": _LOGON_TYPE_MAP.get(logon_type.strip(), "3"),
            "auth_package": auth_type.strip(),
        },
    )


def iter_lanl_events(auth_path: str, max_rows: int | None = None) -> Iterator[NormalizedEvent]:
    """Stream `auth.txt` (or a decompressed prefix of it) as NormalizedEvents."""
    with open(auth_path) as f:
        for i, line in enumerate(f):
            if max_rows is not None and i >= max_rows:
                break
            ev = _to_event(line.rstrip("\n").split(","))
            if ev is not None:
                yield ev


def load_redteam_labels(redteam_path: str) -> set[tuple[int, str, str, str]]:
    """Return the set of (time, user, src_computer, dst_computer) marked malicious."""
    labels: set[tuple[int, str, str, str]] = set()
    with open(redteam_path) as f:
        for line in f:
            parts = line.rstrip("\n").split(",")
            if len(parts) >= 4:
                labels.add((int(parts[0]), _u(parts[1]),
                            parts[2].strip().lower(), parts[3].strip().lower()))
    return labels


@dataclass
class LanlDataset:
    events: list[NormalizedEvent]
    malicious: set[tuple[int, str, str, str]]
    # (time, src, dst) index of red-team events, so an auth matches if either its
    # source or destination user is the compromised credential.
    _by_conn: dict[tuple[int, str, str], set[str]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for t, u, s, d in self.malicious:
            self._by_conn.setdefault((t, s, d), set()).add(u)

    def is_malicious(self, e: NormalizedEvent) -> bool:
        t = int((e.event_time - _LANL_EPOCH).total_seconds())
        users = self._by_conn.get((t, e.fields.get("src_ip"), e.fields.get("computer_name")))
        if not users:
            return False
        return (_u(e.fields.get("target_user_name")) in users
                or _u(e.fields.get("src_user_name")) in users)


def load_lanl(auth_path: str, redteam_path: str, max_rows: int | None = None) -> LanlDataset:
    events = list(iter_lanl_events(auth_path, max_rows=max_rows))
    events.sort(key=lambda e: e.event_time)
    return LanlDataset(events=events, malicious=load_redteam_labels(redteam_path))

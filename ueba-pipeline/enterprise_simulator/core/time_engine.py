"""
time_engine.py — Realistic timestamp generation for Indian enterprise.

Timezone: IST = UTC+5:30, fixed offset, NO Daylight Saving Time ever.
Source: timeanddate.com — "India Standard Time is fixed at UTC+5:30.
        India and Sri Lanka do not use Daylight Saving Time."

Business hours in IST: 09:00–18:30 local
UTC equivalents:       03:30–13:00 UTC

Key fact: IST offset is +330 minutes (5 hours 30 minutes) ahead of UTC.
To convert local IST → UTC: subtract 330 minutes.
To convert UTC → IST: add 330 minutes.
"""

from __future__ import annotations
import random
import math
from datetime import datetime, timedelta, date
from typing import List, Optional, Tuple, Dict
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from config.company import (
    SIM_START_DATE, SIM_END_DATE,
    UTC_OFFSET_TOTAL_MINUTES,  # 330 minutes = +5:30
    IN_HOLIDAYS_2025,
    BUSINESS_HOURS_START_IST, BUSINESS_HOURS_END_IST,
)

# IST is always UTC+5:30 — no DST, no variation.
# IST_OFFSET_MINUTES == UTC_OFFSET_TOTAL_MINUTES from config (both = 330).
# Using a local constant here avoids circular imports in low-level modules.
IST_OFFSET_MINUTES = UTC_OFFSET_TOTAL_MINUTES  # 330 minutes = +5h30m


# ── Date helpers ──────────────────────────────────────────────────────────────
def parse_date(s: str) -> date:
    return datetime.strptime(s, "%Y-%m-%d").date()


def all_sim_dates() -> List[date]:
    start = parse_date(SIM_START_DATE)
    end   = parse_date(SIM_END_DATE)
    out, cur = [], start
    while cur <= end:
        out.append(cur)
        cur += timedelta(days=1)
    return out


def is_business_day(d: date) -> bool:
    """True if weekday (Mon–Fri) and not an Indian national holiday."""
    holidays = {parse_date(h) for h in IN_HOLIDAYS_2025}
    return d.weekday() < 5 and d not in holidays


def local_to_utc(local_dt: datetime, _: date = None) -> datetime:
    """
    Convert a naive IST local datetime to UTC.
    IST = UTC+5:30, so UTC = IST - 5h30m = IST - 330 minutes.
    The second argument is unused (kept for API compatibility) because
    India has NO Daylight Saving Time — offset is always 330 minutes.
    """
    return local_dt - timedelta(minutes=IST_OFFSET_MINUTES)


def utc_to_local(utc_dt: datetime) -> datetime:
    """Convert UTC datetime to IST (for display/verification only)."""
    return utc_dt + timedelta(minutes=IST_OFFSET_MINUTES)


def utc_now_str(utc_dt: datetime) -> str:
    """
    ISO 8601 UTC string with 7-digit fractional precision (100-nanosecond units).
    
    Real Windows EventLog timestamps have 7 fractional digits:
      "2025-01-06T04:15:22.1234567Z"
    The 7th digit (100ns unit) is deterministic based on the microsecond value
    to avoid all-zero timestamps that expose synthetic origin.
    
    Verified from EvidenceForge utils/windows_event/time.py:
      format_windows_system_time adds a 0-9 digit for the sub-microsecond unit.
    """
    # 6-digit microsecond string (standard Python %f)
    us_str   = f"{utc_dt.microsecond:06d}"
    # 7th digit: deterministic sub-microsecond (avoids .0000000 artifact)
    seventh  = (utc_dt.microsecond * 7 + utc_dt.second * 13) % 10
    return utc_dt.strftime("%Y-%m-%dT%H:%M:%S.") + us_str + str(seventh) + "Z"


def _float_hour_to_datetime(d: date, fhour: float) -> datetime:
    """
    Convert fractional hour (e.g. 9.5 = 09:30 IST) to a datetime on date d,
    preserving microsecond precision from the input float.

    Sub-second resolution is retained deliberately: `fhour` comes from a
    continuous rng.gauss() draw, and truncating to whole seconds would collapse
    the timestamp space to 86,400 values per day, producing spurious exact
    cross-employee timestamp collisions a UEBA model could misread as two users
    acting in lockstep.
    """
    total_seconds = fhour * 3600.0
    hour = int(total_seconds // 3600) % 24
    remainder = total_seconds - (int(total_seconds // 3600) * 3600)
    minute = int(remainder // 60)
    remainder -= minute * 60
    second = int(remainder)
    microsecond = int(round((remainder - second) * 1_000_000))
    if microsecond >= 1_000_000:  # rounding at the boundary
        microsecond -= 1_000_000
        second += 1
        if second >= 60:
            second -= 60
            minute += 1
    return datetime(d.year, d.month, d.day,
                    min(hour, 23), min(minute, 59), min(second, 59), microsecond)


# ── Absence calendar ──────────────────────────────────────────────────────────
class AbsenceCalendar:
    """
    Per-employee absence patterns.
    Annual leave: ~18 days in India (EL + CL) → ~5 days in 12-week window
    Sick leave: ~8 days/year → ~2% per business day
    """

    def __init__(self, rng: random.Random, samaccountname: str):
        self.rng  = rng
        self.sam  = samaccountname
        self._absent: set = self._generate()

    def _generate(self) -> set:
        absent   = set()
        biz_days = [d for d in all_sim_dates() if is_business_day(d)]
        n_biz    = len(biz_days)

        # Annual leave block (70% of employees take ≥1 block in 12 weeks)
        if self.rng.random() < 0.70:
            block_len = self.rng.randint(2, 5)
            max_start = max(0, n_biz - block_len - 1)
            if max_start > 0:
                start_idx = self.rng.randint(0, max_start)
                for i in range(start_idx, min(start_idx + block_len, n_biz)):
                    absent.add(biz_days[i])

        # Sick days (~2% per business day)
        for d in biz_days:
            if d not in absent and self.rng.random() < 0.02:
                absent.add(d)

        return absent

    def is_absent(self, d: date) -> bool:
        return d in self._absent

    def is_partial_day(self, d: date) -> bool:
        """8% of workdays: employee leaves early (doctor, personal errand)."""
        return self.rng.random() < 0.08


# ── Daily schedule ────────────────────────────────────────────────────────────
class DailySchedule:
    """
    Computes logon/logoff times for one employee on one day.
    All hours are in IST local; converted to UTC before returning.
    """

    def __init__(
        self,
        rng:                 random.Random,
        login_start_mean:    float,    # IST hour, e.g. 9.5 = 09:30 IST
        login_start_std:     float,
        work_duration_mean:  float,    # hours
        work_duration_std:   float,
        is_remote:           bool = False,
    ):
        self.rng           = rng
        self.login_mean    = login_start_mean
        self.login_std     = login_start_std
        self.dur_mean      = work_duration_mean
        self.dur_std       = work_duration_std
        self.is_remote     = is_remote

    def logon_hour_ist(self, drift: float = 0.0) -> float:
        """Returns IST logon hour with Gaussian variation and weekly drift.

        Uses rejection sampling instead of hard clamp to avoid an artificial
        probability spike at the boundary hour (which occurs when all Gaussian
        tail values below min are collapsed to exactly min).
        Early arrival allowed from 07:30 IST; latest from 19:00 IST.
        """
        mu    = self.login_mean + drift
        sigma = self.login_std
        if self.is_remote:
            mu += 0.25   # remote workers start ~15min later on average
        lo, hi = BUSINESS_HOURS_START_IST - 1.5, BUSINESS_HOURS_END_IST + 1.0
        for _ in range(10):
            h = self.rng.gauss(mu, sigma)
            if lo <= h <= hi:
                return h
        # Fallback: truncate only after 10 failed draws (very rare)
        return max(lo, min(hi, h))

    def logoff_hour_ist(self, logon_h: float, partial: bool = False) -> float:
        """Returns IST logoff hour."""
        dur = max(4.0, self.rng.gauss(self.dur_mean, self.dur_std))
        if partial:
            dur = max(3.0, dur - self.rng.uniform(1.0, 2.5))
        off = logon_h + dur
        return max(logon_h + 3.0, min(23.5, off))

    def to_datetimes(
        self,
        d:       date,
        drift:   float = 0.0,
        partial: bool  = False,
    ) -> Tuple[datetime, datetime]:
        """Returns (logon_utc, logoff_utc) for this employee on date d."""
        logon_h  = self.logon_hour_ist(drift)
        logoff_h = self.logoff_hour_ist(logon_h, partial)

        logon_ist  = _float_hour_to_datetime(d, logon_h)
        logoff_ist = _float_hour_to_datetime(d, logoff_h)

        logon_utc  = local_to_utc(logon_ist)
        logoff_utc = local_to_utc(logoff_ist)
        return logon_utc, logoff_utc


# ── Random timestamp within a session ────────────────────────────────────────
def random_ts_in_session(
    rng:                random.Random,
    session_start_utc:  datetime,
    session_end_utc:    datetime,
    bias:               str = "uniform",
) -> datetime:
    """
    Returns a random UTC timestamp within the session window.
    bias: 'uniform' | 'morning' | 'afternoon' | 'burst'
    """
    total_secs = max(1, (session_end_utc - session_start_utc).total_seconds())
    if bias == "morning":
        offset = rng.betavariate(2, 5) * total_secs
    elif bias == "afternoon":
        offset = rng.betavariate(5, 2) * total_secs
    elif bias == "burst":
        centre = rng.uniform(0.2, 0.8) * total_secs
        offset = max(0.0, min(total_secs, rng.gauss(centre, total_secs * 0.05)))
    else:
        offset = rng.uniform(0, total_secs)
    return session_start_utc + timedelta(seconds=offset)


# ── Service account timestamps ────────────────────────────────────────────────
def service_account_ts(
    rng:          random.Random,
    d:            date,
    service_type: str = "backup",
) -> datetime:
    """
    Returns a UTC timestamp for a scheduled service-account operation.
    All maintenance windows given in IST, then converted to UTC.
    """
    # (IST_hour, IST_minute, spread_minutes)
    schedules: Dict[str, Tuple[int, int, int]] = {
        "backup":           (2,  30, 30),   # 02:30 IST = 21:00 UTC prev day
        "wsus":             (3,  0,  30),   # 03:00 IST = 21:30 UTC prev day
        "sql_maintenance":  (4,  0,  30),   # 04:00 IST = 22:30 UTC prev day
        "sccm":             (22, 0,  30),   # 22:00 IST = 16:30 UTC
        "log_rotation":     (23, 30, 15),   # 23:30 IST = 18:00 UTC
        "antivirus":        (1,  30, 20),   # 01:30 IST = 20:00 UTC prev day
        "monitoring":       (0,  0,  0),    # any time — uses random hour
    }
    h, m, spread = schedules.get(service_type, schedules["backup"])
    if service_type == "monitoring":
        h = rng.randint(0, 23)
        m = rng.randint(0, 59)
    base_ist  = _float_hour_to_datetime(d, h + m / 60.0)
    jitter    = rng.randint(-spread * 60, spread * 60) if spread > 0 else 0
    local_ist = base_ist + timedelta(seconds=jitter)
    return local_to_utc(local_ist)


# ── Weekly behavioral drift ───────────────────────────────────────────────────
def week_drift(
    sim_start:    date,
    current_date: date,
    rng:          random.Random,
    drift_rate:   float = 0.04,
) -> float:
    """
    Returns cumulative login-time drift for long-term behavioral shift.
    Max ±0.5h over 12 weeks. Models natural habit change (new project,
    new manager, changed commute route, etc.).
    """
    weeks = (current_date - sim_start).days / 7.0
    total = 0.0
    for _ in range(int(weeks) + 1):
        total += rng.gauss(0, drift_rate)
    return max(-0.5, min(0.5, total))


def jitter_ts(rng: random.Random, base_utc: datetime, max_seconds: int = 5) -> datetime:
    """Adds ±max_seconds of random jitter to a timestamp."""
    return base_utc + timedelta(seconds=rng.randint(-max_seconds, max_seconds))

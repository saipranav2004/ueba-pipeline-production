# Enterprise Log Simulator

A synthetic enterprise Active Directory telemetry generator. It produces
realistic, multi-channel security logs for a modeled organization — including
normal business-hours behavior and, optionally, injected attacks with ground-truth
labels — so the UEBA pipeline can be trained and evaluated end to end without
access to production data.

## What it models

A mid-size company ("Nexovate Solutions") with a realistic identity structure:

- **Employees** across departments (Engineering, Finance, HR, Sales, Marketing,
  Operations, IT, Legal, Executive), each with department-specific working hours,
  remote-work fraction, application/process mix, and PowerShell/scheduled-task
  usage.
- **Tiered administration** following the AD Administrative Tier Model: separate
  Tier 0 / 1 / 2 admin accounts tied to their real users, with distinct
  credentials per tier.
- **Service accounts** bound to the servers they run on, with non-expiring
  passwords.
- **Infrastructure**: domain controllers, file/SQL/app/web servers, backup, SCCM,
  WSUS, Exchange, RDS, and a jump server, with an OU structure and AGDLP-style
  security groups.

The identity structure is defined in `config/company.py` and is configurable —
department profiles, headcount, servers, admin tiers, and service accounts can be
overridden without changing generator code.

## Output

Events are written as per-channel JSONL under `output/`:

| Directory | Contents |
|-----------|----------|
| `security_logs/` | Windows Security channel (logon, Kerberos, account/group management) |
| `sysmon_logs/` | Sysmon process, network, image-load, and access events |
| `dns_logs/` | DNS query activity |
| `powershell_logs/` | PowerShell script-block and module logging |
| `task_scheduler_logs/` | Scheduled-task registration and execution |
| `wmi_logs/` | WMI activity |
| `defender_logs/` | Endpoint-protection events |
| `kafka_json/` | A merged JSON mirror of all channels for streaming-ingestion testing |
| `csv_exports/` | Tabular exports for inspection |

A peer-group roster (`{username: department}`) is written for the pipeline's
training and scoring steps, and, when attacks are injected, a
`attack_labels.jsonl` with ground-truth technique, timing, and target for each
injected attack.

The pipeline's file ingestion reads the per-channel directories and excludes the
merged `kafka_json/` and `csv_exports/` mirrors so events are not double-counted.

## Injected attacks

With `--inject-attacks`, the simulator injects labeled attack scenarios into the
normal activity stream, each mapped to its MITRE ATT&CK technique:

| Scenario | Technique |
|----------|-----------|
| Pass-the-Hash | T1550.002 |
| Kerberoasting | T1558.003 |
| Password spray | T1110.003 |
| Golden ticket | T1558.001 |
| Silver ticket | T1558.002 |
| AS-REP roasting | T1558.004 |
| DCSync | T1003.006 |
| LSASS dump | T1003.001 |
| NTDS dump | T1003.003 |
| Account manipulation | T1098 |

Each injected attack is written into the same channels a real attack would touch
and recorded in `attack_labels.jsonl`, so evaluation can measure detection against
ground truth.

## Benign baselines for endpoint detection

To avoid trivially "detecting" telemetry that only ever appears during attacks,
the simulator emits realistic benign versions of the same activity a detector
must discriminate against:

- **Benign LSASS access (Sysmon 10):** Windows Defender (`MsMpEng.exe`) queries
  `lsass.exe` with a benign access mask on every host, several times per session,
  so credential-dumping detection must key on the *unusual accessing process*,
  not on the mere fact of touching lsass.
- **Benign admin-tool use:** IT staff occasionally run `vssadmin` / `procdump` /
  `reg` for legitimate maintenance, so rare-process detection faces a non-empty
  benign baseline for these tools.
- **Routine directory management:** help-desk admins process access requests
  against ordinary department and file-share groups every business day, so a
  privileged-group escalation (an add to Domain Admins) must stand out against a
  real baseline of group changes rather than being the first one ever seen.
- **Address churn:** VPN concentrators hand out a different pool address each
  remote session, DHCP leases rotate every few days, and the same laptop appears
  on wired and Wi-Fi ranges — around ten distinct source addresses per user over
  twenty days, while the device identity stays stable. A fixed address per
  employee is the single most unrealistic thing a synthetic estate can do to an
  authentication-graph detector: it makes a novel `(account, source)` edge almost
  impossible in benign traffic and so flatters any novelty-based detection.

This makes the process-, directory- and authentication-based detectors validate
against a real baseline rather than "the attack is the only such event."

## Usage

```bash
# Evaluation estate: the ten headline techniques, balanced across the timeline.
# Use `headline` (not `all`) to reproduce the 53/60 figure — `all` also injects
# the separately-measured insider corpus. See docs/evaluation.md.
python run_simulation.py --days 20 --seed 20250106 \
    --inject-attacks headline --attack-count 30 --attack-placement spread

# Normal activity only (no attacks)
python run_simulation.py --days 20

# A short run for smoke testing
python run_simulation.py --days 5 --inject-attacks all --quiet
```

Options:

- `--days N` — simulate the first N business days.
- `--seed N` — random seed for reproducible runs.
- `--inject-attacks LIST` — comma-separated scenarios, or a preset: `headline`
  (the ten credential/lateral-movement techniques the recall figure is measured
  over) or `all` (every registered attack, incl. the separate insider corpus).
- `--attack-count N` — number of attack instances to inject.
- `--attack-placement MODE` — `spread` (balanced, seed-varied coverage of every
  technique across the timeline; use for evaluation), `tail` (all attacks in the
  held-out tail), or `uniform`.
- `--dump-roster PATH` — where to write the peer-group roster.
- `--config PATH` — YAML overriding department/company definitions.
- `--quiet` — suppress per-day progress output.

## Structure

```
enterprise_simulator/
  run_simulation.py      entry point and CLI
  config/company.py      organization model: departments, servers, admins, service accounts, groups
  core/                  time engine, employee behavior, event bus, daily simulation loop
  generators/            per-channel event generators (security, sysmon, dns, powershell, wmi, defender, tasks)
  attacks.py             injected attack scenarios and label emission
```

## Design notes

Timestamps are emitted in UTC with a configurable local business-hours offset, so
the generated telemetry exhibits realistic diurnal and weekly patterns.
Organization-specific values are held in configuration rather than hard-coded in
the generators, so the modeled enterprise can be reshaped without touching
generator logic.

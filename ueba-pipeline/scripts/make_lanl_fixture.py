"""Generate a small SYNTHETIC LANL-format fixture (auth.txt + redteam.txt).

This is NOT the real LANL 2015 dataset. It reproduces the LANL file *format* and
the structural signal — stable per-user host access with a small amount of
red-team lateral movement embedded — so the `lanl-eval` harness and adapter can
be exercised end to end and smoke-tested without the 7 GB gated download. Results
on this fixture validate the plumbing and methodology, never real-world
performance.

Usage:
    python scripts/make_lanl_fixture.py <out_dir> [--users 300] [--days 4] [--seed 7]
Then:
    python -m ueba_pipeline.cli.main lanl-eval \
        --auth <out_dir>/auth.txt --redteam <out_dir>/redteam.txt
"""
from __future__ import annotations

import argparse
import os
import random


def generate(out_dir: str, n_users: int = 300, n_servers: int = 12,
             days: int = 4, seed: int = 7) -> tuple[int, int]:
    rng = random.Random(seed)
    os.makedirs(out_dir, exist_ok=True)
    users = [f"U{i}" for i in range(n_users)]
    home = {u: f"C{1000 + i}" for i, u in enumerate(users)}
    servers = [f"C{i}" for i in range(1, n_servers + 1)]
    # Each user routinely reaches a small, stable set of servers (department-like).
    reaches = {u: rng.sample(servers, rng.randint(2, 4)) for u in users}

    horizon = days * 86400
    # (time, srcU, dstU, srcC, dstC, type, logon, orient, result)
    auth_rows: list[tuple] = []
    redteam_rows: list[tuple] = []       # (time, user, srcC, dstC)

    # -- benign traffic ---------------------------------------------------
    for u in users:
        hc = home[u]
        for day in range(days):
            base = day * 86400 + rng.randint(8 * 3600, 10 * 3600)
            # interactive logon to own workstation
            auth_rows.append((base, u, u, hc, hc, "Negotiate", "Interactive", "LogOn", "Success"))
            # network logons to the user's routine servers, a few times a day
            for _ in range(rng.randint(3, 8)):
                t = base + rng.randint(0, 8 * 3600)
                s = rng.choice(reaches[u])
                auth_rows.append((t, u, u, hc, s, "Kerberos", "Network", "LogOn", "Success"))

    # -- red-team lateral movement (in the second half = test window) -----
    compromised = rng.sample(users, 5)
    for u in compromised:
        # attacker pivots across a chain of hosts this user never normally touches
        start = int(horizon * 0.6) + rng.randint(0, int(horizon * 0.3))
        # a foothold host the victim never uses, then hops to several new hosts
        foothold = f"C{5000 + rng.randint(0, 400)}"
        chain = [foothold, *rng.sample([c for c in servers if c not in reaches[u]],
                                       k=min(3, max(1, n_servers - len(reaches[u]))))]
        t = start
        for i in range(len(chain) - 1):
            t += rng.randint(30, 600)
            src, dst = chain[i], chain[i + 1]
            auth_rows.append((t, u, u, src, dst, "NTLM", "Network", "LogOn", "Success"))
            redteam_rows.append((t, u, src, dst))

    auth_rows.sort(key=lambda r: r[0])
    with open(os.path.join(out_dir, "auth.txt"), "w") as f:
        for r in auth_rows:
            f.write(",".join(str(x) for x in r) + "\n")
    with open(os.path.join(out_dir, "redteam.txt"), "w") as f:
        for r in sorted(redteam_rows):
            f.write(",".join(str(x) for x in r) + "\n")
    return len(auth_rows), len(redteam_rows)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("out_dir")
    ap.add_argument("--users", type=int, default=300)
    ap.add_argument("--servers", type=int, default=12)
    ap.add_argument("--days", type=int, default=4)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    n_auth, n_red = generate(args.out_dir, args.users, args.servers, args.days, args.seed)
    print(f"[make_lanl_fixture] wrote {n_auth} auth rows, {n_red} red-team rows to {args.out_dir}")
    print("  NOTE: synthetic LANL-format fixture — not the real LANL dataset.")


if __name__ == "__main__":
    main()

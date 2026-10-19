"""Synthetic auth.log + ground-truth labels. Seeded, so results are reproducible.

Benign background: normal users with fixed home IPs, typos, a shared NAT office IP,
a legitimate night-shift user, occasional VPN source changes.
Attacks: fast/slow brute force, fast/slow spraying, brute force that succeeds, off-hours
use of stolen credentials, privileged group add. 'slow' variants deliberately sit below the
rule thresholds to measure what the rules miss (reported honestly as evasions).
"""
import argparse
import json
import os
import random
from datetime import datetime, timedelta

HOST = "srv01"
USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi"]
NIGHT_USER = "ops_night"
NAT_IP = "10.0.5.20"
START = datetime(2026, 10, 1, 0, 0, 0)


def fmt(ts, line):
    return f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} {HOST} sshd[{random.randint(1000, 9999)}]: {line}"


def login(ts, ok, user, ip, method="password"):
    if ok:
        return ts, fmt(ts, f"Accepted {method} for {user} from {ip} port {random.randint(30000, 60000)} ssh2")
    return ts, fmt(ts, f"Failed password for {'invalid user ' if user not in USERS + [NIGHT_USER] else ''}{user} from {ip} port {random.randint(30000, 60000)} ssh2")


def generate(seed, days=7, noise=1.0, hard=False):
    random.seed(seed)
    rows, labels = [], []
    home = {u: f"192.168.1.{10 + i}" for i, u in enumerate(USERS)}
    home[NIGHT_USER] = "192.168.1.60"

    for d in range(days):
        day = START + timedelta(days=d)
        for u in USERS:
            for _ in range(random.randint(1, 3)):
                t = day + timedelta(hours=random.randint(7, 18), minutes=random.randint(0, 59), seconds=random.randint(0, 59))
                ip = NAT_IP if random.random() < 0.3 else home[u]
                # typos: 0-2 failures just before a success
                for k in range(random.choice([0, 0, 0, 1, 2]) if random.random() < noise else 0):
                    rows.append(login(t - timedelta(seconds=20 * (k + 1)), False, u, ip))
                rows.append(login(t, True, u, ip))
        # shared NAT: several users mistype within minutes (spray-like but benign)
        if random.random() < 0.5 * noise:
            t = day + timedelta(hours=9, minutes=random.randint(0, 50))
            for i, u in enumerate(random.sample(USERS, 3)):
                rows.append(login(t + timedelta(seconds=40 * i), False, u, NAT_IP))
                rows.append(login(t + timedelta(seconds=40 * i + 15), True, u, NAT_IP))
        # legitimate night shift
        rows.append(login(day + timedelta(hours=22, minutes=random.randint(0, 30)), True, NIGHT_USER, home[NIGHT_USER]))
        # benign VPN source change (once or twice a week)
        if d >= 2 and random.random() < 0.3 * noise:
            u = random.choice(USERS)
            rows.append(login(day + timedelta(hours=11, minutes=random.randint(0, 59)), True, u, f"172.16.0.{random.randint(2, 200)}"))
        # background internet noise: scattered single failures, below thresholds
        for _ in range(random.randint(2, 6)):
            t = day + timedelta(seconds=random.randint(0, 86399))
            rows.append(login(t, False, random.choice(["root", "admin", "test"]), f"203.0.113.{random.randint(1, 250)}"))

    def label(i, typ, ip, t0, t1, rules):
        labels.append({"id": i, "type": typ, "src_ip": ip, "start": t0.isoformat(), "end": t1.isoformat(),
                       "expected_rules": rules})

    aid = 0

    def when(d, h):
        return START + timedelta(days=d, hours=h, minutes=random.randint(0, 59))

    # 1. fast brute force (10 tries, 4s apart)
    t0 = when(1, 3); ip = "198.51.100.10"
    for i in range(10):
        rows.append(login(t0 + timedelta(seconds=4 * i), False, "root", ip))
    aid += 1; label(aid, "brute_force_fast", ip, t0, t0 + timedelta(seconds=40), ["R001", "R007", "R011"])

    # 2. slow brute force: 1 try / 40s -> 3 per 120s window, below threshold 5
    t0 = when(2, 4); ip = "198.51.100.11"
    for i in range(12):
        rows.append(login(t0 + timedelta(seconds=40 * i), False, "admin", ip))
    aid += 1; label(aid, "brute_force_slow", ip, t0, t0 + timedelta(seconds=480), ["R001", "R007", "R011"])

    # 3. fast spray: 6 users, 20s apart
    t0 = when(3, 2); ip = "198.51.100.12"
    for i, u in enumerate(["alice", "bob", "carol", "dave", "erin", "frank"]):
        rows.append(login(t0 + timedelta(seconds=20 * i), False, u, ip))
    aid += 1; label(aid, "spray_fast", ip, t0, t0 + timedelta(seconds=120), ["R002", "R008"])

    # 4. low-and-slow spray: 1 user / 10 min
    t0 = when(4, 1); ip = "198.51.100.13"
    for i, u in enumerate(["alice", "bob", "carol", "dave", "erin"]):
        rows.append(login(t0 + timedelta(minutes=10 * i), False, u, ip))
    aid += 1; label(aid, "spray_slow", ip, t0, t0 + timedelta(minutes=40), ["R002", "R008"])

    # 5. brute force that succeeds, then off-hours session
    t0 = when(5, 2); ip = "198.51.100.14"
    for i in range(7):
        rows.append(login(t0 + timedelta(seconds=5 * i), False, "heidi", ip))
    rows.append(login(t0 + timedelta(seconds=40), True, "heidi", ip))
    aid += 1; label(aid, "brute_force_success", ip, t0, t0 + timedelta(seconds=40), ["R001", "R004", "R007", "R003", "R005"])

    # 6. stolen credentials used at night from a new IP (single success: only R003/R005 can see it)
    t0 = when(5, 0) + timedelta(hours=3); ip = "198.51.100.15"
    rows.append(login(t0, True, "carol", ip))
    aid += 1; label(aid, "stolen_creds_offhours", ip, t0, t0, ["R003", "R005"])

    # 7. privileged group add after compromise
    t0 = when(5, 3)
    ts = t0
    rows.append((ts, fmt(ts, "add 'backdoor' to group 'sudo'")))
    aid += 1; label(aid, "privilege_escalation", "-", t0, t0, ["R006"])

    # 8. second fast brute force against a different account (multiple attackers)
    t0 = when(6, 14); ip = "198.51.100.16"
    for i in range(6):
        rows.append(login(t0 + timedelta(seconds=10 * i), False, "bob", ip))
    aid += 1; label(aid, "brute_force_fast", ip, t0, t0 + timedelta(seconds=60), ["R001", "R007", "R011"])

    if hard:
        # distributed brute force: 12 failures on one account from 6 IPs (2 each, under per-IP thresholds)
        t0 = when(2, 15)
        for i in range(12):
            rows.append(login(t0 + timedelta(seconds=40 * i), False, "alice", f"203.0.113.{100 + i % 6}"))
        aid += 1; label(aid, "distributed_brute_force", "*", t0, t0 + timedelta(seconds=480), ["R010"])
        # very slow brute force: 1 try / 10 min for ~2 h (below even the 1 h slow rule)
        t0 = when(3, 5); ip = "198.51.100.30"
        for i in range(12):
            rows.append(login(t0 + timedelta(minutes=10 * i), False, "root", ip))
        aid += 1; label(aid, "brute_force_very_slow", ip, t0, t0 + timedelta(minutes=120), ["R001", "R007", "R011"])
        # insider with valid credentials, normal hours, known IP: no rule can see this
        t0 = START + timedelta(days=4, hours=13)
        rows.append(login(t0, True, "dave", home["dave"]))
        aid += 1; label(aid, "valid_credentials_insider", home["dave"], t0, t0, [])

    rows.sort(key=lambda r: r[0])
    return [r[1] for r in rows], labels


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="sample_data")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--noise", type=float, default=1.0)
    ap.add_argument("--hard", action="store_true", help="add evasion attacks (distributed, very slow, insider)")
    a = ap.parse_args()
    lines, labels = generate(a.seed, noise=a.noise, hard=a.hard)
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "auth.log"), "w") as f:
        f.write("\n".join(lines) + "\n")
    with open(os.path.join(a.out, "labels.json"), "w") as f:
        json.dump(labels, f, indent=2)
    print(f"wrote {len(lines)} lines, {len(labels)} labelled attacks to {a.out}")


if __name__ == "__main__":
    main()

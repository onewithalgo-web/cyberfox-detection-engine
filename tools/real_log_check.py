"""Check the engine against an independent real-world sshd log (e.g. LogHub OpenSSH_2k.log).

Real logs have no labels, so ground truth is derived separately from the engine: this script
counts 'Failed password' lines per source IP straight from the raw text (expanding syslog
"message repeated N times" lines) and treats any IP with >= MIN_FAILS failed logins as an attacker.
It then reports which of those IPs the engine alerted on, and any alerted IP outside that set.

Usage: python tools/real_log_check.py OpenSSH_2k.log --year 2015 [--min-fails 5]
Data source for the reported results: https://github.com/logpai/loghub (OpenSSH_2k.log, not redistributed here).
"""
import argparse
import collections
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detector.cli import analyse  # noqa: E402

FAIL = re.compile(r"Failed password for .*? from (\d+\.\d+\.\d+\.\d+) port")
REPEAT = re.compile(r"message repeated (\d+) times")


def raw_truth(path):
    counts = collections.Counter()
    for line in open(path, encoding="utf-8", errors="replace"):
        m = FAIL.search(line)
        if m:
            r = REPEAT.search(line)
            counts[m.group(1)] += int(r.group(1)) if r else 1
    return counts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--year", type=int, default=2015)
    ap.add_argument("--min-fails", type=int, default=5)
    ap.add_argument("--set", action="append")
    a = ap.parse_args()
    from detector.cli import parse_set
    events, alerts = analyse(a.log, a.year, None, parse_set(a.set))
    truth = raw_truth(a.log)
    attackers = {ip: n for ip, n in truth.items() if n >= a.min_fails}
    by_ip = collections.defaultdict(set)
    for al in alerts:
        by_ip[al.src_ip].add(al.rule_id)

    print(f"raw failed logins (expanded): {sum(truth.values())} | parsed failed events: {sum(not e.success for e in events)}"
          f" | accepted logins: {sum(e.success for e in events)}")
    print(f"alerts: {len(alerts)} | per rule: {dict(sorted(collections.Counter(x.rule_id for x in alerts).items()))}")
    print(f"\nattacker IPs (>= {a.min_fails} failed logins, independent count): {len(attackers)}")
    hit = 0
    for ip, n in sorted(attackers.items(), key=lambda kv: -kv[1]):
        rules = sorted(by_ip.get(ip, []))
        hit += bool(rules)
        print(f"  {ip:16} {n:4} failures  {'DETECTED by ' + ', '.join(rules) if rules else 'MISSED'}")
    fp = sorted(set(by_ip) - set(attackers))
    print(f"\ndetected {hit}/{len(attackers)} attacker IPs | alerted IPs outside attacker set: {fp or 'none'}")
    ok = [e for e in events if e.success]
    for e in ok:
        print(f"accepted login: {e.user} from {e.src_ip} at {e.ts} -> alerts on that IP: {sorted(by_ip.get(e.src_ip, [])) or 'none'}")


if __name__ == "__main__":
    main()

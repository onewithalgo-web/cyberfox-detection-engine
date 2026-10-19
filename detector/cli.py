import argparse
import json
import os
from .parser import parse_file as parse_linux
from .parser_windows import parse_file as parse_windows
from .engine import load_rules, run_all

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def parse_set(items):
    """--set R001.threshold=3  ->  {'R001': {'threshold': 3}}"""
    out = {}
    for s in items or []:
        key, val = s.split("=", 1)
        rid, fld = key.split(".", 1)
        out.setdefault(rid, {})[fld] = int(val) if val.lstrip("-").isdigit() else val
    return out


def load_events(log, year=2026, fmt="auto"):
    if fmt == "auto":
        fmt = "windows" if log.lower().endswith(".csv") else "linux"
    return parse_windows(log) if fmt == "windows" else parse_linux(log, year)


def analyse(log, year=2026, rules_dir=None, overrides=None, trusted=(), fmt="auto"):
    events = load_events(log, year, fmt)
    rules = load_rules(rules_dir or os.path.join(HERE, "rules"), overrides)
    return events, run_all(rules, events, set(trusted))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="detector", description="Explainable auth-log detection engine (read-only)")
    ap.add_argument("log")
    ap.add_argument("--year", type=int, default=2026)
    ap.add_argument("--format", choices=["auto", "linux", "windows"], default="auto",
                    help="linux = sshd auth.log; windows = Security event CSV export (auto picks by extension)")
    ap.add_argument("--rules", default=None)
    ap.add_argument("--set", action="append", metavar="RULE.FIELD=VALUE", help="override a rule threshold")
    ap.add_argument("--trusted-ip", action="append", default=[], help="ignore events from this IP")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--html", metavar="FILE", help="write a self-contained HTML dashboard")
    a = ap.parse_args(argv)
    events, alerts = analyse(a.log, a.year, a.rules, parse_set(a.set), a.trusted_ip, a.format)
    if a.html:
        from .dashboard import render
        with open(a.html, "w", encoding="utf-8") as f:
            f.write(render(alerts, len(events), os.path.basename(a.log)))
        print(f"dashboard written to {a.html}")
    if a.json:
        print(json.dumps([x.to_dict() for x in alerts], indent=2))
        return
    print(f"{len(events)} events, {len(alerts)} alerts")
    for x in alerts:
        print(f"[{x.severity.upper():8}] {x.ts:%Y-%m-%d %H:%M:%S} {x.rule_id} {x.name} ({x.mitre})\n    {x.reason}")


if __name__ == "__main__":
    main()

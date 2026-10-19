"""Score alerts against ground truth.

Alert = true positive if it matches a labelled attack: same src_ip (or '-' for host-level
events), rule in the attack's expected_rules, timestamp within [start, end + 10 min].
Otherwise it is a false positive. An attack is detected if >= 1 expected rule fired on it.
Run across many seeds with --seeds N to get mean / spread.
"""
import argparse
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detector.cli import analyse, parse_set  # noqa: E402
from tools.generate_logs import generate  # noqa: E402

SLACK = timedelta(minutes=10)


def score(alerts, labels):
    tp, fp = [], []
    hit = {l["id"]: set() for l in labels}
    for a in alerts:
        match = None
        for l in labels:
            if (l["src_ip"] in ("*", a.src_ip) and a.rule_id in l["expected_rules"]
                    and datetime.fromisoformat(l["start"]) <= a.ts <= datetime.fromisoformat(l["end"]) + SLACK):
                match = l
                break
        if match:
            tp.append(a); hit[match["id"]].add(a.rule_id)
        else:
            fp.append(a)
    detected = [l for l in labels if hit[l["id"]]]
    missed = [l for l in labels if not hit[l["id"]]]
    return tp, fp, detected, missed


def run_once(log, labels, overrides, trusted=()):
    _, alerts = analyse(log, 2026, None, overrides, trusted)
    tp, fp, det, missed = score(alerts, labels)
    return dict(alerts=len(alerts), tp=len(tp), fp=len(fp), attacks=len(labels), detected=len(det),
                missed=[m["type"] for m in missed], fp_rules=sorted({a.rule_id for a in fp}),
                fp_by_rule={r: sum(1 for a in fp if a.rule_id == r) for r in sorted({a.rule_id for a in fp})})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log", nargs="?")
    ap.add_argument("labels", nargs="?")
    ap.add_argument("--seeds", type=int, default=0, help="generate + score N seeds instead of a single file")
    ap.add_argument("--noise", type=float, default=1.0)
    ap.add_argument("--hard", action="store_true", help="include evasion attacks")
    ap.add_argument("--set", action="append")
    ap.add_argument("--trusted-ip", action="append", default=[])
    a = ap.parse_args()
    ov = parse_set(a.set)

    if a.seeds:
        rows = []
        for s in range(1, a.seeds + 1):
            lines, labels = generate(s, noise=a.noise, hard=a.hard)
            with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
                f.write("\n".join(lines) + "\n")
            rows.append(run_once(f.name, labels, ov, a.trusted_ip)); os.unlink(f.name)
        tp = sum(r["tp"] for r in rows); fp = sum(r["fp"] for r in rows)
        det = sum(r["detected"] for r in rows); att = sum(r["attacks"] for r in rows)
        print(f"seeds={a.seeds} noise={a.noise} overrides={ov or '-'}")
        print(f"attack detection (recall): {det}/{att} = {det / att:.2%}")
        print(f"alert precision: {tp}/{tp + fp} = {tp / max(tp + fp, 1):.2%}   false positives/log: {fp / a.seeds:.1f}")
        print(f"incident precision (stricter, one credit per detected attack): {det}/{det + fp} = {det / max(det + fp, 1):.2%}")
        from collections import Counter
        print("false positives by rule:", dict(Counter(k for r in rows for k, v in r["fp_by_rule"].items() for _ in range(v))))
        print("missed attack types:", dict(Counter(m for r in rows for m in r["missed"])))
        return

    with open(a.labels) as f:
        labels = json.load(f)
    r = run_once(a.log, labels, ov, a.trusted_ip)
    print(json.dumps(r, indent=2))


if __name__ == "__main__":
    main()

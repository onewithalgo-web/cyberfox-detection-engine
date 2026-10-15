# Explainable Auth-Log Detection Engine

CyberFox Society internship project (Security Operations & Detection Engineering).
A lightweight, rule-based engine that reads SSH authentication logs and raises **explainable** alerts
(every alert states why it fired and carries the raw log lines as evidence). Read-only; synthetic data only.

## Problem
Credential attacks (brute force, password spraying, stolen-credential use) are common, but small teams
often lack a SIEM. This tool detects them from a raw `auth.log` with transparent, tunable YAML rules.

## Rules
| ID | Detects | MITRE | Default |
|---|---|---|---|
| R001 | Brute force: N failures, same IP + user | T1110.001 | 5 / 120 s |
| R002 | Password spraying: one IP, many users | T1110.003 | 4 users / 300 s |
| R003 | Successful login outside business hours | T1078 | outside 06:00-20:00; `allow_users` |
| R004 | Success after repeated failures (likely compromise, critical) | T1110 | 3 fails / 600 s |
| R005 | Login from a never-seen source IP (ignores shared NAT IPs) | T1078 | 3-day learning window |
| R006 | Account added to sudo/wheel/admin | T1136.001 | any |
| R007 | Slow brute force | T1110.001 | 8 / 3600 s |
| R008 | Low-and-slow password spraying | T1110.003 | 5 users / 3600 s |

## Quick start
```
pip install -r requirements.txt
python tools/generate_logs.py --out sample_data --seed 42
python -m detector.cli sample_data/auth.log --set R003.allow_users=ops_night --html sample_data/dashboard.html
python -m unittest discover -s tests -v
python tools/evaluate.py --seeds 50 --set R003.allow_users=ops_night
```
Options: `--json`, `--rules DIR`, `--trusted-ip IP`, `--set RULE.FIELD=VALUE` (override any threshold).
The dashboard is a single self-contained HTML file (alerts by rule / IP / day, click a row for evidence).

## Evaluation
`tools/generate_logs.py` builds 7 days of seeded logs: normal users, typos, a shared NAT office IP,
a legitimate night-shift user, benign VPN source changes, internet background noise, plus 8 labelled
attacks (fast/slow brute force, fast/slow spraying, brute force that succeeds, stolen credentials at night,
privilege escalation). `tools/evaluate.py` scores alerts against the labels. Results (20 seeds unless stated; 8 attacks per seed):

| Config | Attack detection | Alert precision | False positives / log |
|---|---|---|---|
| Rules R001-R006 only, default thresholds (baseline) | 75% (slow attacks missed) | ~35% | ~15 |
| + R007/R008 slow rules, default thresholds | 100% | ~63% | ~8 |
| + `allow_users=ops_night` (tuned; 50 seeds: 91.3%, 1.3 FP/log) | 100% | ~91% | ~1.4 |
| Tuned, noise x2 | 100% | ~84% | ~2.7 |

Remaining false positives are mostly R005 (benign VPN source changes) and occasional NAT typo bursts.

## Limitations (be honest in the report)
- The data is synthetic and the rules were tuned on the same generator, so the figures show the method works,
  not real-world performance. Next step would be a public dataset or authorised lab logs.
- Detection assumes attacks stay in one source IP; distributed attacks from many IPs are not correlated.
- Only sshd/group-change syslog lines are parsed. Windows events (4625/4624) are future work.
- Thresholds are static; a per-user baseline would reduce R005 noise.

## Layout
```
detector/   models, parser, engine (rule types), cli, dashboard
rules/      one YAML file per rule
tools/      generate_logs.py, evaluate.py
tests/      17 unit and end-to-end tests
```

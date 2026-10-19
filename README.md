# Explainable Auth-Log Detection Engine

CyberFox Society internship project (Security Operations & Detection Engineering).
A lightweight, rule-based engine that reads authentication logs (Linux sshd `auth.log` and Windows Security
event CSV exports) and raises **explainable** alerts: every alert states why it fired, maps to a MITRE ATT&CK
technique, and carries the raw log lines as evidence. Read-only; synthetic or authorised data only.

## Problem
Credential attacks (brute force, password spraying, stolen-credential use) are common, but small teams often
lack a SIEM. This tool detects them from raw logs with transparent, tunable YAML rules.

## Rules
| ID | Detects | MITRE | Default |
|---|---|---|---|
| R001 | Brute force: repeated failures, same IP + user | T1110.001 | 5 / 120 s |
| R002 | Password spraying: one IP, many users | T1110.003 | 4 users / 300 s |
| R003 | Successful login outside business hours (`allow_users`) | T1078 | outside 06:00-20:00 |
| R004 | Login succeeded after repeated failures (critical) | T1110 | 3 fails / 600 s |
| R005 | Login from a never-seen source IP (ignores shared NAT IPs; `ignore_cidrs`) | T1078 | 3-day learning |
| R006 | Account added to sudo / wheel / Administrators | T1136.001 | any |
| R007 | Slow brute force | T1110.001 | 8 / 1 h |
| R008 | Low-and-slow password spraying | T1110.003 | 5 users / 1 h |
| R009 | New user account created | T1136.001 | any |
| R010 | **Distributed** brute force: one account, many IPs, each below the per-IP threshold | T1110.001 | 10 fails from 4+ IPs / 15 min |
| R011 | Very slow brute force | T1110.001 | 10 / 24 h |
| R012 | Probing of non-existent accounts (sshd "invalid user" / Windows SubStatus 0xC0000064), per IP | T1110.001 | 5 / 24 h |

## Quick start
```
pip install -r requirements.txt
python tools/generate_logs.py --out sample_data --seed 42 --hard
python -m detector.cli sample_data/auth.log --set R003.allow_users=ops_night --set R005.ignore_cidrs=172.16.0.0/16 --html sample_data/dashboard.html
python -m unittest discover -s tests -v
python tools/evaluate.py --seeds 30 --hard --set R003.allow_users=ops_night --set R005.ignore_cidrs=172.16.0.0/16
```
Options: `--format linux|windows|auto`, `--json`, `--html FILE`, `--rules DIR`, `--trusted-ip IP`,
`--set RULE.FIELD=VALUE` (override any threshold). Windows input is a CSV export of Security events
4624/4625/4720/4732 (columns documented in `detector/parser_windows.py`).

Dashboard documentation (panels, severity scheme, how to read an alert): [docs/DASHBOARD.md](docs/DASHBOARD.md).

![Dashboard](docs/dashboard.jpg)

## Testing methodology
`tools/generate_logs.py` builds 7 days of seeded logs: normal users, typos, a shared NAT office IP, a legitimate
night-shift user, benign VPN source changes and internet background noise, plus labelled attacks. With `--hard`
it adds three evasion attacks (distributed brute force, very slow brute force, an insider using valid credentials).
`tools/evaluate.py` scores every alert against the labels: an alert is a true positive if it has the attack's
source IP, an expected rule, and falls in the attack window; otherwise it is a false positive. An attack is
detected if at least one expected rule fires. 28 unit and end-to-end tests pass, including a check that the
same events as a Linux log and as a Windows CSV produce identical alerts.

## Results (30 seeds, 11 attacks per seed = 330 labelled attacks, evasion attacks included)

| Step | Attack detection | Alert precision | False positives / log |
|---|---|---|---|
| A. Week 2 rules (R001-R008, night-shift allow-list) | 72.7% | 91.7% | 1.3 |
| B. + R010 distributed brute force | 81.8% | 92.2% | 1.3 |
| C. + R011 very slow brute force (all rules) | 90.9% | 93.4% | 1.3 |
| D. + R012 invalid-user probing, R005 `ignore_cidrs` (known VPN pool) | 90.9% | 99.2% | 0.2 |
| E. D with 2x benign noise | 90.9% | 97.5% | 0.5 |
| F. D with 3x benign noise | 90.9% | 97.7% | 0.4 |

On the original 8-attack set (no evasion attacks, 50 seeds) the Week 2 rules reached 100% detection at 91.3% precision.

## Independent real-world test (LogHub OpenSSH, real sshd logs)
Tested on 1,999 lines of public real-world sshd logs (12 attacker IPs, 528 failed logins, 1 legitimate login). First run:
9/12 attacker IPs detected, 0 alerts on non-attacker IPs. The misses exposed a syslog "message repeated N times" parsing gap and
an ultra-slow scanner, fixed by a parser change and rule R012: now 12/12 with 0 false positives (R012 was designed after seeing
the miss, so 9/12 is the clean number). Full method, ground-truth definition and caveats: [docs/REAL_DATA_TEST.md](docs/REAL_DATA_TEST.md).
Reproduce with `python tools/real_log_check.py OpenSSH_2k.log --year 2015`.

## Missed attacks (analysis on synthetic data)
| Attack | Detected? | Why / fix |
|---|---|---|
| Distributed brute force (12 failures, one account, 6 IPs) | Missed by R001-R008, caught by **R010** | Per-IP rules never see more than 2 failures per source; correlating by account fixes it |
| Very slow brute force (1 try / 10 min for 2 h) | Missed by R001/R007, caught by **R011** | Longer window; costs little because the key is IP + account |
| Insider with valid credentials, normal hours, usual IP | **Never detected** (0/30) | Indistinguishable from legitimate use in auth logs alone; needs endpoint/data-access telemetry |

Remaining false positives (about 0.2-0.5 per log) are R002/R004/R008 firing on benign NAT typo bursts.

## Limitations
- Data is synthetic and the rules and tuning options were chosen on the same generator (including the VPN range
  in step D), so these figures show the method works, not production performance. Real-world results are in the section above and are small-scale.
- Attacks are correlated per source IP or per account; slow multi-account, multi-IP campaigns can still slip through.
- Only sshd/group-change lines and a documented Windows CSV subset are parsed.
- Thresholds are static; per-user baselines would further reduce noise.

## Layout
```
detector/   models, parsers (linux, windows), engine (rule types), cli, dashboard
rules/      one YAML file per rule (R001-R012)
tools/      generate_logs.py, evaluate.py, real_log_check.py, to_windows_csv.py
tests/      28 unit and end-to-end tests
docs/       dashboard guide, screenshot, real-data test write-up
```

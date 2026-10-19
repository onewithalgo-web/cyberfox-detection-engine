# Independent real-world log test

## Data
`OpenSSH_2k.log` from the public **LogHub** collection (https://github.com/logpai/loghub): 2,000 lines of real sshd logs from an internet-facing Linux lab server, 10 Dec 2015 06:55-11:04. Downloaded for this test and **not redistributed** in this repo. It is independent of my synthetic generator: the engine's rules were not written against it (with the one exception noted below).

Reproduce:
```
python tools/real_log_check.py OpenSSH_2k.log --year 2015
```

## Ground truth (no labels exist, so it is derived independently)
`tools/real_log_check.py` counts `Failed password` lines per source IP straight from the raw text, **without using the engine's parser or rules**, expanding syslog "message repeated N times" lines. Any IP with 5 or more failed logins is treated as an attacker. This is a coarse volumetric criterion (it is the best available without human labels), so treat "precision" below as "alerts fell on IPs that clearly behaved as attackers".

Facts about the log: 528 failed logins (after expanding compressed lines) from 12 attacker IPs, one successful login (`fztu` from 119.137.62.142), **assumed legitimate**: no failed attempts from that IP and the session closed normally after about 13 minutes. This is my judgement, not a label from the dataset. There is no successful compromise in this sample, so R003/R004/R005/R006 had nothing to detect.

## Results
| Version | Attacker IPs detected | Alerts | Alerts on non-attacker IPs |
|---|---|---|---|
| First run (rules R001-R011, as pushed in commit b6a98a1) | 9 / 12 | 30 | 0 |
| After fixes below | **12 / 12** | 39 | 0 |

The successful login produced no alert.

## What the real data exposed (missed-attack analysis)
| Finding | Effect | Fix |
|---|---|---|
| syslog compresses repeats: `message repeated 5 times: [ Failed password ... ]` | The parser read 1 failure instead of 6 for two attacker IPs (5.36.59.76, 106.5.5.195), so they stayed under every threshold | Parser expands the repeat count |
| Odd spacing: `Failed password for invalid user  0101 from ...` | One failed login silently dropped | Regex tolerates extra whitespace |
| 52.80.34.196: 5 attempts against 3 distinct non-existent accounts (test9, test, matlab) over about 3 h 13 min (one every ~48 min) | Below every rate rule, including the 24 h one (needs 10 per IP+user) | New rule **R012**: 5+ failures against accounts sshd reports as "invalid user", per source IP, 24 h window |

**Honesty note:** R012 was designed after seeing this miss, so 12/12 is not a clean held-out result; the 9/12 first-run figure is the clean one. R012 was then re-checked on the synthetic data with no loss in recall and no new false positives (precision 99.2%), and has unit tests.

## Other observations
- **Alert volume:** 39 alerts for 12 attackers (about 3 per attacker), because several rules corroborate the same activity (e.g. R001 + R007 + R011 for one burst). Useful as evidence, but a production version should group alerts by source IP.
- **Not counted:** the log has 113 `Invalid user X from IP` lines with no password attempt and 4 `Failed none` lines; the engine ignores these, so probing that never reaches a password prompt is invisible to it.
- **Scale and scope:** 2k lines, one server, 4 hours, one attack style (password guessing). It shows the engine copes with real syslog quirks and real attacker behaviour, not that it is production-ready.

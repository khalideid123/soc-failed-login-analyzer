# SOC Failed Login Analyzer

A beginner-friendly cybersecurity portfolio project that simulates a common SOC analyst task: reviewing authentication logs, identifying repeated failed login attempts, and escalating suspicious activity.

## What this project demonstrates

- Security log analysis
- Brute-force / password-spraying detection concepts
- Python scripting
- CSV/JSON data handling
- Alert triage
- Basic incident documentation
- SOC-style investigation workflow

## Scenario

A security operations center receives authentication events from a company login system. Most activity is normal, but one or more IP addresses may repeatedly fail authentication attempts.

The analyst's job is to:

1. Parse authentication logs.
2. Count failed attempts by source IP.
3. Identify IPs that exceed an alert threshold.
4. Review successful logins after repeated failures.
5. Generate a simple SOC alert report.

> The included data is fictional and intended only for defensive cybersecurity learning.

## Project structure

```text
soc-failed-login-analyzer/
├── README.md
├── requirements.txt
├── .gitignore
├── data/
│   └── auth_logs.csv
├── src/
│   └── analyzer.py
├── tests/
│   └── test_analyzer.py
├── docs/
│   └── investigation.md
└── output/
    └── .gitkeep
```

## Detection logic

An IP is flagged when it reaches **5 or more failed login attempts**.

The analyzer also marks a finding as higher priority when a successful login occurs from the same IP after repeated failures. That pattern can indicate a compromised account, although additional investigation would always be required in a real SOC.

## Run the project

Requires Python 3.10+.

```bash
python src/analyzer.py
```

The script reads `data/auth_logs.csv` and writes:

```text
output/alerts.json
```

## Run tests

```bash
python -m unittest discover tests
```

## Example finding

The sample dataset contains repeated failures from the same source IP followed by a successful login. The analyzer groups those events and raises an alert once the configured threshold is reached.

## Skills demonstrated

`Python` · `Log Analysis` · `SOC Operations` · `Incident Triage` · `Authentication Security` · `Threat Detection`

## Future improvements

Possible extensions include:

- GeoIP enrichment
- MITRE ATT&CK mapping
- Windows Event Log support
- Splunk/SIEM query examples
- Time-window based detections
- Account lockout detection
- Alert severity scoring
- Visualization dashboard

## Disclaimer

This project uses fictional sample logs and is designed for defensive cybersecurity education only.

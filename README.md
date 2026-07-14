# SOC Alert Triage

## Overview

SOC Alert Triage is a beginner-friendly cybersecurity project developed in Python to simulate common tasks performed by a Security Operations Center (SOC) Level 1 analyst.

The project analyzes Windows Security Event logs stored in CSV format and helps identify suspicious activity through simple detection scripts.

This project was created as part of my cybersecurity learning path and portfolio.

---

## Objectives

- Analyze Windows Security Event logs.
- Classify security alerts by severity.
- Detect possible brute-force attacks.
- Identify suspicious IP addresses.
- Practice log analysis using Python.

---

## Technologies

- Python 3
- Pandas
- Git
- GitHub
- Kali Linux

---

## Project Structure

```
soc-alert-triage/
│
├── data/
│   └── windows_security.csv
│
├── scripts/
│   ├── alert_classifier.py
│   ├── brute_force_detector.py
│   └── suspicious_ips.py
│
├── reports/
│   └── classified_events.csv (generated after execution)
├── requirements.txt
└── README.md
```

---
## Output

After running the script, a classified report is generated automatically:

```text
reports/classified_events.csv
```

The report includes:

- Timestamp
- Event ID
- Severity
- Username
- Source IP
- Description

## Scripts

### alert_classifier.py

Classifies Windows Security Events according to their severity level.

Example:

| Event ID | Severity |
|----------|----------|
|4624|Low|
|4625|Medium|
|4672|High|
|4720|Critical|

---

### brute_force_detector.py

Detects repeated failed logon attempts (Event ID 4625) that could indicate a brute-force attack.

---

### suspicious_ips.py

Displays the IP addresses that generate the highest number of security events.

---

## Installation

Clone the repository.

```bash
git clone https://github.com/miltonquinterog/soc-alert-triage.git
```

Move into the project.

```bash
cd soc-alert-triage
```

Install the dependencies.

```bash
pip install -r requirements.txt
```

---

## Usage

Run any script individually.

Example:

```bash
python scripts/alert_classifier.py
```

---

## Skills Demonstrated

- Log Analysis
- Security Event Classification
- Basic Threat Detection
- Python Programming
- Data Analysis with Pandas
- Git Version Control

---

## Author

Milton Quintero

Cybersecurity Student

GitHub:

https://github.com/miltonquinterog

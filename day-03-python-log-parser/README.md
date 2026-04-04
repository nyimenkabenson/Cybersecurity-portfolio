# Day 3 — Python Log Parser: Extract IPs & Status Codes

**Portfolio:** 30 Days of Cybersecurity | Blue Team Track
**Date:** April 3, 2026
**Tools:** Python 3, Kali Linux
**Difficulty:** Intermediate
**Format:** Security Automation / Log Analysis

---

## Objective

Build a Python script that parses an Apache web server access log, extracts key fields using regex, and outputs a structured analyst report — including top source IPs, HTTP status code breakdown, HTTP methods, suspicious IPs, and flagged malicious URL requests. This project simulates a core SOC automation task: processing large log files programmatically to surface threats quickly.

---

## Lab Environment

| Component | Detail |
|-----------|--------|
| OS | Kali Linux (VirtualBox VM) |
| Language | Python 3 |
| Log Format | Apache Combined Log Format |
| Input File | sample_access.log (15 entries) |
| Script | log_parser.py |

---

## Script Overview

The parser uses Python's `re` module to match each log line against the Apache Combined Log Format pattern, extracting:

- Source IP address
- HTTP method (GET, POST)
- Requested URL
- HTTP status code
- Response size

It then uses `collections.Counter` to aggregate and rank results, and flags suspicious activity based on 4xx error codes and known malicious URL patterns.

---

## Regex Pattern Used

```python
pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)'   # IP address
    r'.+\[(?P<datetime>[^\]]+)\]'     # Datetime
    r'\s"(?P<method>\w+)\s'           # HTTP method
    r'(?P<url>\S+)\s[^"]+"\s'         # URL
    r'(?P<status>\d{3})\s'            # Status code
    r'(?P<size>\d+)'                  # Response size
)
```

Named capture groups make each field directly accessible by name, keeping the code readable and maintainable.

---

## Script Output

```
=======================================================
       WEB SERVER ACCESS LOG — PARSER REPORT
=======================================================

 Total log entries parsed : 15
 Unique IP addresses      : 7

--- Top 5 Source IPs ---
  185.220.101.45       4 requests
  103.75.190.12        3 requests
  192.168.1.10         2 requests
  10.0.0.5             2 requests
  45.33.32.156         2 requests

--- Status Code Breakdown ---
  200 OK                5 occurrences
  304 Not Modified      1 occurrences
  400 Bad Request       1 occurrences
  401 Unauthorized      3 occurrences
  404 Not Found         5 occurrences

--- HTTP Methods ---
  GET        11 requests
  POST        4 requests

--- Suspicious IPs (4xx errors) ---
  185.220.101.45       4 error responses
  103.75.190.12        3 error responses
  45.33.32.156         2 error responses

--- Suspicious URL Requests ---
  185.220.101.45       requested /admin
  103.75.190.12        requested /wp-admin
  103.75.190.12        requested /phpmyadmin
  103.75.190.12        requested /.env
  45.33.32.156         requested /etc/passwd
  45.33.32.156         requested /shell.php

=======================================================
 Analysis complete.
=======================================================
```

---

## Findings

### Top Threat Actors

| IP Address | Requests | Error Responses | Suspicious URLs | Assessment |
|------------|----------|----------------|-----------------|------------|
| 185.220.101.45 | 4 | 4 | /admin | Brute-force / admin scanner |
| 103.75.190.12 | 3 | 3 | /wp-admin, /phpmyadmin, /.env | Automated vulnerability scanner |
| 45.33.32.156 | 2 | 2 | /etc/passwd, /shell.php | Active exploitation attempt |

### Status Code Analysis

| Code | Count | Meaning | Significance |
|------|-------|---------|-------------|
| 200 OK | 5 | Success | Legitimate traffic |
| 304 Not Modified | 1 | Cached | Normal browser behaviour |
| 400 Bad Request | 1 | Malformed request | Possible fuzzing |
| 401 Unauthorized | 3 | Auth failed | Brute-force login attempts |
| 404 Not Found | 5 | Resource missing | Scanning for vulnerabilities |

### Suspicious URL Analysis

- **`/admin`, `/wp-admin`, `/phpmyadmin`** — common admin panel scanning, often automated
- **`/.env`** — attackers probing for exposed environment files containing credentials and API keys
- **`/etc/passwd`** — path traversal attempt targeting Linux password file
- **`/shell.php`** — probing for web shell upload — indicates prior or attempted compromise

---

## Key Security Insight

> A single log file with 15 entries revealed **3 actively malicious IPs**, **9 error responses**, and **5 suspicious URL requests** — including a path traversal attempt and a web shell probe. Automated log parsing makes it possible to surface these threats in seconds, even across millions of log lines.

---

## Defensive Recommendations

1. **Block all three attacker IPs** at the firewall immediately
2. **Alert on 401 bursts** — 3+ failed auth attempts from one IP in 60 seconds should trigger a SOC alert
3. **Alert on sensitive URL patterns** — `/etc/passwd`, `/.env`, `/shell.php` should never appear in access logs
4. **Restrict admin panels by IP** — `/admin`, `/wp-admin`, `/phpmyadmin` should be whitelisted to known IPs only
5. **Automate this parser** — run it on a cron job every hour and pipe output to your SIEM

---

## Skills Demonstrated

- Python regex (`re` module) for structured log parsing
- `collections.Counter` for frequency analysis
- Threat detection logic (4xx flagging, suspicious URL matching)
- Log analysis and pattern recognition
- Security automation mindset

---

## Files in This Repository

```
day-03-python-log-parser/
├── README.md            ← This file
├── log_parser.py        ← Python parser script
├── sample_access.log    ← Sample Apache access log
└── report.pdf           ← Full analyst report
```

---

*Part of the [30 Days of Cybersecurity](../README.md) portfolio project.*

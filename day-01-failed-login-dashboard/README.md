# Day 1 — Splunk SPL Dashboard: Top 10 Failed Logins

**Portfolio:** 30 Days of Cybersecurity | Blue Team Track  
**Date:** April 1, 2026  
**Tools:** Splunk Enterprise (Free), SPL, Linux auth logs  
**Difficulty:** Intermediate  
**Format:** SIEM / Log Analysis

---

## Objective

Build a Splunk dashboard to detect brute-force login activity by identifying the top 10 source IPs with the highest number of failed SSH authentication attempts. This project simulates a real SOC analyst task: surfacing attack patterns from raw authentication logs.

---

## Dataset

A synthetic `auth.log` file was generated containing **500 log events** spanning a 24-hour period (April 1, 2026). The dataset includes:

- **400 failed login attempts** from 5 external attacker IPs targeting common usernames (`admin`, `root`, `test`, etc.)
- **100 legitimate events** from internal IPs — mix of successful and failed authentications
- Log format: standard Linux `sshd` via `/var/log/auth.log`

**Sample log line:**
```
Apr 01 03:22:11 web-server-01 sshd[4821]: Failed password for invalid user admin from 185.220.101.45 port 52341 ssh2
```

---

## SPL Queries

### Query 1 — Top 10 Source IPs by Failed Logins
```spl
index=main sourcetype=linux_secure "Failed password"
| rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as failed_attempts by src_ip
| sort -failed_attempts
| head 10
```
**What it does:** Extracts source IPs from failed password events using regex, counts occurrences per IP, and returns the top 10.

---

### Query 2 — Top Targeted Usernames
```spl
index=main sourcetype=linux_secure "Failed password"
| rex field=_raw "for (invalid user )?(?<username>\w[\w.]*) from"
| stats count as attempts by username
| sort -attempts
| head 10
```
**What it does:** Extracts the targeted username from each failed login event and ranks them by frequency. High counts on `admin`, `root`, or `test` indicate automated credential stuffing.

---

### Query 3 — Failed Logins Over Time
```spl
index=main sourcetype=linux_secure "Failed password"
| timechart span=1h count as failed_logins
```
**What it does:** Buckets failed logins into 1-hour intervals to reveal attack timing patterns (e.g., spikes at 3am suggest automated scanning).

---

### Query 4 — Success vs Failure Ratio
```spl
index=main sourcetype=linux_secure ("Failed password" OR "Accepted password")
| eval status=if(match(_raw,"Failed"),"Failed","Accepted")
| stats count by status
```
**What it does:** Computes the overall authentication success/failure ratio. A ratio heavily skewed toward failures is a strong indicator of brute-force activity.

---

## Dashboard

A 4-panel Splunk dashboard was built using XML, containing:

| Panel | Visualization | Query |
|-------|--------------|-------|
| Top 10 Source IPs | Bar chart | Query 1 |
| Top Targeted Usernames | Bar chart | Query 2 |
| Failed Logins Over Time | Line chart | Query 3 |
| Success vs Failure | Pie chart | Query 4 |

**Dashboard XML:** See `dashboard.xml` in this repository.

---

## Findings

| Source IP | Failed Attempts | Classification |
|-----------|----------------|----------------|
| 91.240.118.172 | 89 | Likely Tor exit node |
| 45.33.32.156 | 84 | Known scanner (Shodan) |
| 185.220.101.45 | 80 | Tor exit node |
| 103.75.190.12 | 75 | Suspicious cloud IP |
| 194.165.16.99 | 72 | VPN/proxy infrastructure |

**Top targeted usernames:** `admin`, `root`, `administrator`, `test`, `guest`  
**Attack pattern:** Distributed brute-force across multiple IPs, targeting default credentials

---

## Detection Logic

This dashboard supports detection of:

- **Brute-force attacks** — high failed login count from a single IP
- **Credential stuffing** — many usernames attempted from the same IP
- **Distributed attacks** — coordinated attempts spread across multiple IPs to evade per-IP thresholds

---

## Defensive Recommendations

1. **Block attacker IPs** at the firewall or via `hosts.deny`
2. **Implement fail2ban** to auto-ban IPs after N failed attempts
3. **Disable password authentication** for SSH — enforce key-based auth only
4. **Rename or disable default accounts** (`admin`, `root` login)
5. **Alert threshold:** Trigger SOC alert when any single IP exceeds 20 failed logins in 10 minutes

---

## Skills Demonstrated

- SPL query writing (regex extraction, stats, timechart, eval)
- Splunk dashboard creation via XML
- Log analysis and threat pattern identification
- Authentication log forensics
- Defensive recommendation writing

---

## Files in This Repository

```
day-01-failed-login-dashboard/
├── README.md              ← This file
├── auth.log               ← Sample dataset (500 events)
├── dashboard.xml          ← Splunk dashboard source
└── report.pdf             ← Full project report
```

---

*Part of the [30 Days of Cybersecurity](../README.md) portfolio project.*

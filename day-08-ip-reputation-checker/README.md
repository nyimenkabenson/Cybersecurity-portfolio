# Day 8: Python Automated IP Reputation Checker with VirusTotal API

**Portfolio:** 30 Days of Cybersecurity | Blue Team Track  
**Date:** April 8, 2026  
**Tools:** Python 3, VirusTotal API, Kali Linux  
**Difficulty:** Intermediate  
**Format:** Security Automation / Threat Intelligence  

---

## Objective

Build a Python script that automatically queries the VirusTotal API for a list of suspicious IP addresses and produces a reputation report with verdicts, engine counts, and country information. This project simulates a core SOC automation task: enriching IOCs (Indicators of Compromise) with threat intelligence data during alert triage and threat hunting workflows.

---

## Lab Environment

| Component | Detail |
|-----------|--------|
| OS | Kali Linux (VirtualBox VM) |
| Language | Python 3 |
| API | VirusTotal v3 (free tier) |
| Library | requests |
| Output | Terminal report and results.json |

---

## Script Design

The script takes a predefined list of IP addresses, queries the VirusTotal v3 API for each one, extracts reputation data from the response, applies a verdict logic, and outputs a structured summary report. A 16-second delay between requests keeps usage within the free tier rate limit of 4 requests per minute.

### Verdict Logic

| Condition | Verdict |
|-----------|---------|
| Malicious engine count greater than 2 | MALICIOUS |
| Malicious or suspicious count greater than 0 | SUSPICIOUS |
| No malicious or suspicious flags | CLEAN |

### API Endpoint

```
GET https://www.virustotal.com/api/v3/ip_addresses/{ip}
```

Fields extracted from each response: country, reputation score, malicious engine count, suspicious engine count, harmless engine count.

---

## IPs Checked

| IP Address | Category | Reason for Inclusion |
|------------|---------|---------------------|
| 185.220.101.45 | Known attacker | Appeared in Day 1 and Day 6 brute-force logs |
| 103.75.190.12 | Known attacker | Appeared in Day 3 web server log analysis |
| 45.33.32.156 | Known attacker | Flagged in multiple previous days |
| 91.240.118.172 | Known attacker | Appeared in Day 1 brute-force dataset |
| 194.165.16.99 | Known attacker | Appeared in Day 1 brute-force dataset |
| 8.8.8.8 | Control (clean) | Google DNS — known legitimate IP |
| 1.1.1.1 | Control (clean) | Cloudflare DNS — known legitimate IP |

The two clean control IPs were included to validate that the script correctly identifies legitimate infrastructure.

---

## Results

### Full IP Reputation Report

| IP Address | Country | Reputation | Malicious | Suspicious | Harmless | Verdict |
|------------|---------|-----------|-----------|-----------|---------|---------|
| 185.220.101.45 | DE (Germany) | -22 | 17 | 3 | 45 | MALICIOUS |
| 103.75.190.12 | MY (Malaysia) | 0 | 0 | 0 | 0 | CLEAN |
| 45.33.32.156 | US (United States) | 0 | 4 | 1 | 56 | MALICIOUS |
| 91.240.118.172 | HK (Hong Kong) | -1 | 11 | 1 | 50 | MALICIOUS |
| 194.165.16.99 | MC (Monaco) | 0 | 8 | 0 | 53 | MALICIOUS |
| 8.8.8.8 | US (United States) | 534 | 0 | 0 | — | CLEAN |
| 1.1.1.1 | Unknown | 83 | 0 | 0 | 63 | CLEAN |

### Summary

| Metric | Count |
|--------|-------|
| Total IPs checked | 7 |
| Malicious | 4 |
| Suspicious | 0 |
| Clean | 3 |

### IPs to Block Immediately

| IP | Country | Engines Flagged |
|----|---------|----------------|
| 185.220.101.45 | Germany | 17 |
| 91.240.118.172 | Hong Kong | 11 |
| 194.165.16.99 | Monaco | 8 |
| 45.33.32.156 | United States | 4 |

---

## Key Findings and Insights

### Finding 1: 185.220.101.45 is the highest-confidence threat
With 17 malicious engine detections and a reputation score of -22, this IP is confirmed malicious infrastructure. It appeared in brute-force logs on Day 1 and Day 6 — the VirusTotal data now provides independent corroboration from 17 separate threat intelligence engines.

### Finding 2: 103.75.190.12 came back clean
This IP appeared in the Day 3 web server attack log but returned zero detections on VirusTotal. This is an important real-world lesson — IP reputation scores change over time. An IP can be used in an attack, cleaned up, and eventually removed from blacklists. Absence of a VirusTotal flag does not mean an IP is safe in context.

### Finding 3: Control IPs validated correctly
8.8.8.8 (reputation 534) and 1.1.1.1 (reputation 83) both returned clean verdicts, confirming the script correctly distinguishes between malicious and legitimate infrastructure.

### Finding 4: Geographic distribution of threats
The malicious IPs span Germany, Hong Kong, Monaco, and the United States — consistent with anonymisation infrastructure (VPNs, Tor exit nodes, bulletproof hosting) spread across multiple jurisdictions to complicate attribution and takedown efforts.

---

## Real-World SOC Application

This script can be extended for production SOC use in several ways:

1. Feed it IPs extracted automatically from SIEM alerts instead of a static list
2. Add WHOIS lookup to enrich results with ASN and hosting provider information
3. Write results to a CSV or push them directly into a ticketing system
4. Schedule it to run automatically when new IOCs are identified
5. Add domain and file hash checking using additional VirusTotal API endpoints

---

## Defensive Recommendations

1. Block all four confirmed malicious IPs at the firewall immediately
2. Cross-reference these IPs against your SIEM logs to check for prior connections from internal hosts
3. Never rely on VirusTotal alone — a clean result does not mean an IP is safe. Always use context from your own logs
4. Automate IOC enrichment as part of your alert triage workflow to reduce manual lookup time
5. Set up a VirusTotal livehunt or retrohunt to be notified if these IPs appear in new malware samples

---

## Skills Demonstrated

- VirusTotal API v3 integration with Python
- REST API authentication using API key headers
- JSON response parsing and field extraction
- Rate limiting implementation for API compliance
- IOC enrichment and verdict logic
- Threat intelligence reporting and analysis

---

## Files in This Repository

```
day-08-ip-reputation-checker/
├── README.md                  
├── ip_reputation_checker.py   
├── results.json               
└── report.pdf                 
```

---

*Part of the 30 Days of Cybersecurity portfolio project.*

# Day 17: Python IOC Extractor — Hashes, IPs, Domains from Threat Reports

**Portfolio:** 30 Days of Cybersecurity | Blue Team Track  
**Date:** April 17, 2026  
**Tools:** Python 3, re module, Kali Linux  
**Difficulty:** Intermediate  
**Format:** Security Automation / Threat Intelligence  

---

## Objective

Build a Python script that automatically extracts Indicators of Compromise from unstructured threat report text using regular expressions, covering 10 IOC categories including IP addresses, domains, file hashes, emails, URLs, CVEs, registry keys, and file paths. This tool eliminates manual IOC extraction — a repetitive but critical SOC task during threat intelligence processing.

---

## Lab Environment

| Component | Detail |
|-----------|--------|
| OS | Kali Linux (VirtualBox VM) |
| Language | Python 3 |
| Library | re (built-in), json (built-in) |
| Input | Simulated threat intelligence report |
| Output | Terminal report and extracted_iocs.json |

---

## IOC Categories Supported

| Category | Regex Pattern Type | Example |
|----------|-------------------|---------|
| IPv4 | Octet-validated IP address | 185.220.101.45 |
| Domain | Multi-TLD domain matching | default.exp-tas.com |
| MD5 | 32-character hex string | 5f4dcc3b5aa765d61d8327deb882cf99 |
| SHA1 | 40-character hex string | da39a3ee5e6b4b0d3255bfef95601890afd80709 |
| SHA256 | 64-character hex string | 2cf24dba5fb0a30e26e83b2ac5b9e29e... |
| Email | RFC-style email address | recover@darkmail.xyz |
| URL | HTTP and HTTPS URLs | http://185.220.101.45/stage2.exe |
| CVE | CVE identifier format | CVE-2022-30190 |
| Registry | Windows registry key paths | HKEY_CURRENT_USER\...\Run\WindowsUpdate |
| Filepath | Windows file system paths | C:\Users\Public\svchost32.exe |

---

## Script Features

### False Positive Filtering

Known benign IPs and domains are excluded from results to reduce noise:

```python
EXCLUDE_IPS = {"127.0.0.1", "0.0.0.0", "255.255.255.255", "8.8.8.8", "1.1.1.1"}
EXCLUDE_DOMAINS = {"example.com", "test.com", "localhost.com"}
```

### JSON Output

All extracted IOCs are saved to `extracted_iocs.json` for downstream processing — feeding into SIEM rules, firewall blocklists, or threat intelligence platforms.

### Deduplication

The script uses Python sets to automatically remove duplicate IOC entries before displaying results.

---

## Extraction Results

The script was run against a simulated threat intelligence report covering the ongoing campaign identified throughout this portfolio.

### Full Results

| IOC Type | Count | Values Extracted |
|----------|-------|-----------------|
| IPv4 | 5 | 103.75.190.12, 185.220.101.45, 194.165.16.99, 45.33.32.156, 91.240.118.172 |
| Domain | 4 | darkmail.xyz, default.exp-tas.com, hr-portal-secure.com, objects.githubusercontent.com |
| MD5 | 1 | 5f4dcc3b5aa765d61d8327deb882cf99 |
| SHA1 | 1 | da39a3ee5e6b4b0d3255bfef95601890afd80709 |
| SHA256 | 1 | 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824 |
| Email | 2 | payroll-update@hr-portal-secure.com, recover@darkmail.xyz |
| URL | 2 | http://185.220.101.45/stage2.exe, https://objects.githubusercontent.com/payload.ps1 |
| CVE | 2 | CVE-2021-40444, CVE-2022-30190 |
| Registry | 1 | HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate |
| Filepath | 2 | C:\Users\Public\svchost32.exe, C:\Windows\System32\Tasks\WindowsUpdateHelper |
| **Total** | **21** | |

### Analyst Note: Bitcoin Wallet

The Bitcoin wallet address `1A2B3C4D5E6F7G8H9I0J` from the threat report was not extracted. This is correct behaviour — the wallet address in the sample used characters outside the valid Base58 Bitcoin encoding set (which excludes 0, O, I, and l to avoid visual confusion). A real Bitcoin wallet address would be correctly identified by the regex pattern.

---

## Real-World SOC Application

Manual IOC extraction from a threat report typically takes 15 to 20 minutes per report. This script processes the same report in under one second and outputs structured JSON ready for immediate use.

### Downstream Uses for Extracted IOCs

| Use Case | How |
|----------|-----|
| Firewall blocking | Feed extracted IPs directly to firewall blocklist via API |
| DNS sinkholing | Add extracted domains to DNS resolver blocklist |
| SIEM correlation | Import extracted IOCs as lookup tables for alert enrichment |
| VirusTotal lookup | Feed extracted hashes to Day 8 IP reputation checker (extended for hashes) |
| Threat intel sharing | Export JSON to MISP or OpenCTI threat intelligence platform |

---

## Portfolio Connection

Every IOC extracted in this script appeared in a previous day of this portfolio:

| IOC | First Seen |
|-----|-----------|
| 185.220.101.45 | Day 1 — SSH brute-force logs |
| 91.240.118.172 | Day 9 — Malware C2 PCAP |
| default.exp-tas.com | Day 9 — Malware C2 PCAP |
| recover@darkmail.xyz | Day 15 — Ransomware IR report |
| CVE-2022-30190 | Day 15 — Ransomware attack vector |

The IOC extractor closes the loop on the campaign narrative — all threat intelligence from the past 17 days can now be automatically extracted and operationalised.

---

## Skills Demonstrated

- Python regex (re module) for multi-pattern IOC extraction
- False positive filtering with exclusion lists
- JSON structured output for downstream processing
- Deduplication using Python sets
- IOC category coverage across 10 types
- Threat intelligence automation mindset

---

## Files in This Repository

```
day-17-ioc-extractor/
├── README.md              
├── ioc_extractor.py       
├── extracted_iocs.json    
└── report.pdf             
```

---

*Part of the 30 Days of Cybersecurity portfolio project.*

# Day 27: Python Automated Alert Enrichment Tool — WHOIS and VirusTotal

**Portfolio:** 30 Days of Cybersecurity | Blue Team Track  
**Date:** April 27, 2026  
**Tools:** Python 3, VirusTotal API v3, python-whois, Kali Linux  
**Difficulty:** Intermediate  
**Format:** Security Automation / Threat Intelligence  

---

## Objective

Build a Python script that automatically enriches IOCs (IP addresses and domains) by querying both VirusTotal and WHOIS simultaneously, producing a structured analyst report with verdicts. This combines API integration from Day 8 with new WHOIS lookup capability into a single multi-source enrichment tool — the kind of automation that saves SOC analysts significant time during alert triage.

---

## Lab Environment

| Component | Detail |
|-----------|--------|
| OS | Kali Linux (VirtualBox VM) |
| Language | Python 3 |
| Libraries | requests, python-whois |
| APIs | VirusTotal v3, WHOIS |
| IOCs enriched | 4 (2 IPs, 2 domains) |

---

## IOCs Enriched

All four IOCs were selected from the campaign tracked across this portfolio:

| IOC | Type | Source |
|-----|------|--------|
| 185.220.101.45 | IP | Days 1, 6, 8, 11, 15, 23, 25 |
| 91.240.118.172 | IP | Days 9, 11, 15, 23, 25 |
| exp-tas.com | Domain | Days 9, 11, 25 |
| hr-payroll-verify.xyz | Domain | Day 25 |

---

## Enrichment Results

### 185.220.101.45 — MALICIOUS

| Field | Value |
|-------|-------|
| VT Malicious engines | 17 |
| VT Suspicious engines | 3 |
| Country | Germany (DE) |
| ASN Owner | Stiftung Erneuerbare Freiheit |
| Registrar | easyDNS Technologies Inc. |
| Registration date | 2019-02-28 |
| Verdict | MALICIOUS |

**Analysis:** Stiftung Erneuerbare Freiheit is a known Tor infrastructure organisation — confirming this IP is a Tor exit node used to anonymise attacker traffic. The 2019 registration date indicates long-standing infrastructure rather than a newly spun-up attack server. 17 engine detections is among the highest confidence malicious ratings possible.

---

### 91.240.118.172 — MALICIOUS

| Field | Value |
|-------|-------|
| VT Malicious engines | 11 |
| VT Suspicious engines | 1 |
| Country | Hong Kong (HK) |
| ASN Owner | Unknown |
| Registrar | Unknown |
| Registration date | Unknown |
| Verdict | MALICIOUS |

**Analysis:** The anonymised WHOIS data — unknown registrar, unknown creation date — is itself a red flag. Legitimate infrastructure always has traceable registration data. Combined with 11 malicious engine detections, this confirms a deliberately anonymised C2 server. Hong Kong jurisdiction complicates takedown requests.

---

### exp-tas.com — CLEAN (Context: Malicious)

| Field | Value |
|-------|-------|
| VT Malicious engines | 0 |
| VT Suspicious engines | 0 |
| Registrar | NOM-IQ Ltd dba Com Laude |
| Registration date | 2019-02-06 |
| Verdict | CLEAN (VirusTotal) |

**Analysis:** Zero VirusTotal detections confirms why domain fronting works — the domain appears completely clean to automated reputation systems. The attacker deliberately chose a legitimate-looking domain registered through a reputable registrar. Despite the clean VT score, this domain is confirmed malicious C2 infrastructure from network forensics analysis in Days 9 and 11. Context from your own environment always overrides reputation scores.

---

### hr-payroll-verify.xyz — CLEAN / No Data

| Field | Value |
|-------|-------|
| VT Malicious engines | N/A |
| VT Suspicious engines | N/A |
| Registrar | Unknown |
| Registration date | Unknown |
| Verdict | CLEAN (insufficient data) |

**Analysis:** No WHOIS data and no VirusTotal results indicates either a very recently registered domain or one that has already been taken down. The .xyz TLD combined with the payroll-themed name and complete absence of registration data are strong contextual red flags regardless of the clean VT verdict. This domain was the phishing delivery URL from Day 25.

---

## Key Analyst Insight

The enrichment results demonstrate a critical lesson: **VirusTotal scores are context-dependent.** Two confirmed malicious domains (exp-tas.com and hr-payroll-verify.xyz) returned clean or no-data results on VirusTotal, while being confirmed malicious through network forensics. A clean reputation score is not a clearance — always cross-reference with your own environment's logs.

---

## WHOIS vs VirusTotal — Complementary Data Sources

| Data Source | What It Tells You | Limitation |
|-------------|------------------|-----------|
| VirusTotal | Community-verified threat reputation | Domain fronting evades it — clean scores possible for malicious domains |
| WHOIS | Registration history, ownership, ASN | Anonymisation services hide ownership — unknown data is itself suspicious |
| Combined | Full enrichment picture | Neither alone is sufficient — both required for confident verdict |

---

## Real-World SOC Application

This script can be extended for production use:

| Extension | Implementation |
|-----------|---------------|
| SIEM integration | Auto-enrich IPs from Splunk alerts via API trigger |
| Slack alerting | Post enrichment summary to SOC Slack channel automatically |
| Blocklist automation | Push MALICIOUS IPs directly to firewall API |
| MISP feed | Export enriched IOCs to threat intelligence sharing platform |
| Batch processing | Process hundreds of IOCs from a CSV file |

---

## Skills Demonstrated

- VirusTotal API v3 for IP and domain reputation checking
- python-whois library for registration data extraction
- Multi-source IOC enrichment combining two data sources
- Verdict logic based on combined signal strength
- JSON output for downstream processing
- Context-aware analysis beyond automated verdict scores

---

## Files in This Repository

```
day-27-alert-enrichment/
├── README.md                  
├── alert_enrichment.py        
├── enrichment_results.json    
└── report.pdf                 
```

---

*Part of the 30 Days of Cybersecurity portfolio project.*

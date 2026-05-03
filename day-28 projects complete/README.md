# 🛡️ Cybersecurity Portfolio — 30 Days of Blue Team

**Analyst:** Nyimenka  
**Focus:** Blue Team · SOC Analysis · DFIR · Network Forensics · Security Automation  
**Status:** Active — April/May 2026

\---

## About This Portfolio

This repository documents a structured 30-day cybersecurity challenge covering the full blue team analyst skillset — from SIEM detection engineering and network forensics through Python automation, memory forensics, incident response, and threat intelligence. Every project uses real tools, real malware samples, and real attacker infrastructure tracked across a simulated 25-day campaign.

The portfolio is designed to demonstrate job-ready skills for **SOC Analyst**, **Junior DFIR**, and **Security Operations** roles.

\---

## Skills Demonstrated

|Category|Skills|
|-|-|
|**SIEM / Splunk**|SPL queries, dashboards, detection rules, threat hunting, API automation|
|**Network Forensics**|Wireshark, PCAP analysis, protocol analysis, file extraction, malware C2|
|**DFIR**|Volatility 3, memory forensics, incident response, ransomware analysis|
|**Python Automation**|Log parsing, IP reputation, port scanning, IOC extraction, alert enrichment|
|**Threat Intelligence**|VirusTotal API, WHOIS, IOC classification, campaign attribution|
|**SOC Operations**|Alert triage, phishing investigation, detection use cases, playbook authoring|
|**CTF / Labs**|TryHackMe, Blue Team Labs Online, CyberDefenders|

\---

## 30-Day Project Index

### 🔵 Splunk / SIEM Track

|Day|Project|Key Skills|
|-|-|-|
|[Day 01](./day-01-failed-login-dashboard)|Failed Login Dashboard|SPL · timechart · stats · visualisation|
|[Day 06](./day-06-splunk-brute-force-detection)|Brute-Force Detection Rule|Alert scheduling · threshold tuning · cron|
|[Day 10](./day-10-splunk-port-scan-detection)|Port Scan Detection|Firewall log analysis · rate-based detection|
|[Day 16](./day-16-splunk-threat-hunting-powershell)|PowerShell Threat Hunting|T1059.001 · encoded commands · download cradles|
|[Day 22](./day-22-splunk-soc-dashboard)|Full SOC Operations Dashboard|Multi-source · 6 panels · auth/network/endpoint|
|[Day 23](./day-23-splunk-api-automation)|Splunk API Automation|Python · REST API · async job polling|

\---

### 🟢 Wireshark / Network Forensics Track

|Day|Project|Key Skills|
|-|-|-|
|[Day 02](./day-02-wireshark-http-analysis)|HTTP Traffic Capture|Live capture · TCP streams · HTTP analysis|
|[Day 07](./day-07-wireshark-dns-analysis)|DNS Analysis|NXDOMAIN · DGA domains · DNS filtering|
|[Day 09](./day-09-wireshark-malware-c2-analysis)|Malware C2 PCAP Analysis|Domain fronting · C2 traffic · IOC extraction|
|[Day 14](./day-14-wireshark-arp-analysis)|ARP Storm Analysis|ARP protocol · storm vs poisoning · Cisco|
|[Day 19](./day-19-wireshark-file-extraction)|File Extraction from PCAP|Export Objects · HTTP/FTP · DFIR recovery|
|[Day 28](./day-28-warmcookie-analysis)|WARMCOOKIE Intrusion Analysis|BITS abuse · C2 beaconing · SMB2 recon|

\---

### 🟡 Python Automation Track

|Day|Project|Key Skills|
|-|-|-|
|[Day 03](./day-03-python-log-parser)|Apache Log Parser|Regex · suspicious pattern detection · reporting|
|[Day 08](./day-08-ip-reputation-checker)|IP Reputation Checker|VirusTotal API · threat scoring · JSON output|
|[Day 13](./day-13-python-port-scanner)|Multi-threaded Port Scanner|Socket · threading · service identification|
|[Day 17](./day-17-ioc-extractor)|IOC Extractor|10-category regex · false positive filtering · JSON|
|[Day 27](./day-27-alert-enrichment)|Alert Enrichment Tool|WHOIS + VirusTotal · multi-source · verdicts|

\---

### 🔴 DFIR Track

|Day|Project|Key Skills|
|-|-|-|
|[Day 12](./day-12-windows-event-log-analysis)|Windows Event Log Analysis|Event IDs · MITRE mapping · BTL1-style|
|[Day 15](./day-15-ransomware-ir-report)|Ransomware IR Report|Full IR report · T1490 · do-not-pay analysis|
|[Day 21](./day-21-volatility-memory-forensics)|Memory Forensics with Volatility|Volatility 3 · pslist · filescan · envars|
|[Day 25](./day-25-dfir-capstone)|DFIR Capstone Investigation|47-min attack chain · 14 MITRE techniques · double extortion|

\---

### 🟠 SOC Operations Track

|Day|Project|Key Skills|
|-|-|-|
|[Day 04](./day-04-soc-alert-triage)|SOC Alert Triage|10 alerts · FP/FN · prioritisation|
|[Day 11](./day-11-phishing-investigation)|Phishing Investigation|Email forensics · IOC extraction · MITRE|
|[Day 20](./day-20-credential-stuffing-detection)|Credential Stuffing Detection Use Case|T1110.004 · detection logic · triage steps|
|[Day 26](./day-26-ransomware-playbook)|Ransomware SOC Playbook|7-phase IR · SPL integration · MTTD/MTTR|

\---

### 🟣 CTF / Lab Track

|Day|Project|Key Skills|
|-|-|-|
|[Day 05](./day-05-tryhackme-siem-intro)|TryHackMe — Intro to SIEM|THM{000\_SIEM\_INTRO} · Splunk fundamentals|
|[Day 18](./day-18-tryhackme-dfir-introduction)|TryHackMe — DFIR Introduction|THM{DFIR\_REPORT\_DONE} · IR lifecycle · SANS vs NIST|
|[Day 24](./day-24-btlo-phishing-analysis)|BTLO — Phishing Analysis|10/10 score · nested .eml evasion · Blogspot abuse|

\---

## Campaign Narrative

A consistent attacker campaign runs as a thread across 25 days of this portfolio. The same threat actor infrastructure was tracked from initial reconnaissance through to ransomware deployment and data exfiltration:

```
Day 01 ──── SSH brute-force scanning (185.220.101.45)
Day 06 ──── Brute-force detection rule built
Day 08 ──── VirusTotal confirms 185.220.101.45 — 17 engine detections
Day 09 ──── C2 PCAP analysis — 91.240.118.172, domain fronting via exp-tas.com
Day 11 ──── Phishing compromise of WS-SARAH-01
Day 12 ──── Windows event log forensics post-compromise
Day 15 ──── Ransomware incident response — INC-2026-0415
Day 16 ──── Threat hunting confirms svchost32.exe on all 5 hosts
Day 21 ──── Memory forensics — svchost32.exe still running
Day 23 ──── Splunk API confirms attacker IPs across environment
Day 25 ──── DFIR Capstone — full 47-minute attack chain reconstructed
           14 MITRE techniques · 45 MB exfiltrated · double extortion
```

The portfolio demonstrates how a threat actor can persist across an environment when incidents are incompletely remediated — a real-world scenario that makes this portfolio uniquely coherent compared to disconnected individual projects.

\---

## Tools and Platforms

|Tool|Projects Used In|
|-|-|
|Splunk Enterprise|Days 1, 6, 10, 16, 22, 23|
|Wireshark|Days 2, 7, 9, 14, 19, 28|
|Volatility 3|Day 21|
|Python 3|Days 3, 8, 13, 17, 23, 27|
|VirusTotal API|Days 8, 27|
|TryHackMe|Days 5, 18|
|Blue Team Labs Online|Day 24|
|Kali Linux|All practical days|

\---

## Certifications in Progress

* **BTL1** — Blue Team Level 1 (Security Blue Team)
* **CompTIA Security+**

\---

## Background

Banking and Finance graduate (Rivers State University) transitioning into cybersecurity with a focus on the defensive blue team path. Building this portfolio to demonstrate practical, job-ready skills ahead of applications for SOC Analyst and Junior DFIR roles.

\---

## Connect

* 📺 YouTube: https://www.youtube.com/@thecyberstudysessions
* 💼 LinkedIn: http://www.linkedin.com/in/elizabethnyimenka
* 🐙 GitHub: https://github.com/nyimenkabenson
* 📧 Email: nyimenkabenson@gmail.com

\---

*Built across April–May 2026 · 30 days · 28 projects · 1 campaign narrative*


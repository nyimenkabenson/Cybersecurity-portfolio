# Day 5: TryHackMe Intro to SIEM Room Write-Up

**Portfolio:** 30 Days of Cybersecurity | Blue Team Track  
**Date:** April 5, 2026  
**Platform:** TryHackMe  
**Room:** Intro to SIEM  
**Tools:** TryHackMe browser-based lab  
**Difficulty:** Easy  
**Format:** CTF Write-Up / SIEM Theory and Practical  

---

## Room Overview

The Intro to SIEM room on TryHackMe covers the fundamentals of Security Information and Event Management systems. It explores what a SIEM is, what data it collects, how alerts are generated, and how a SOC analyst triages findings inside a SIEM interface. The room concludes with a hands-on practical where a real suspicious process is detected and investigated.

---

## Theory Notes

### What is a SIEM?

A Security Information and Event Management (SIEM) system is a centralised platform that collects, aggregates, and analyses log data from across an organisation's entire IT environment. It correlates events from multiple sources in real time to detect threats, generate alerts, and support incident response. Rather than logging into individual servers and devices manually, a SIEM gives a SOC analyst a single pane of glass across the entire network.

### Two Types of Log Sources

| Type | Description | Examples |
|------|-------------|---------|
| Host-Centric | Activity happening on an endpoint or server | Registry changes, file access, process execution, Windows Event Logs |
| Network-Centric | Traffic and activity between devices | VPN connections, firewall logs, DNS queries, proxy logs |

Registry activity is host-centric. VPN activity is network-centric. Knowing which log source to check first is a core SOC efficiency skill that saves time during investigations.

### Linux Log Locations

Linux systems store logs in /var/log/. Key paths every analyst should know:

| Log Path | Contents |
|----------|---------|
| /var/log/httpd | Apache HTTP server access and error logs |
| /var/log/auth.log | SSH logins, sudo usage, authentication events |
| /var/log/syslog | General system events |
| /var/log/kern.log | Kernel-level events |

### Critical Windows Event IDs

| Event ID | Meaning | Significance |
|----------|---------|-------------|
| 4624 | Successful logon | Baseline, monitor for anomalies |
| 4625 | Failed logon | Brute-force indicator |
| 4688 | Process created | Detect malicious process execution |
| 4698 | Scheduled task created | Persistence mechanism |
| 104 | Event log cleared | Critical: attacker covering tracks |

Event ID 104 is one of the most important alerts in Windows environments. Attackers routinely clear event logs after a compromise to destroy forensic evidence. Any occurrence of 104 should be treated as a serious finding requiring immediate investigation.

### Alert Types and Tuning

| Alert Type | Meaning | Action |
|-----------|---------|--------|
| True Positive | Real threat confirmed | Investigate and escalate |
| False Positive | Alert fired but activity is benign | Close ticket and tune the rule |

False Positive alerts require rule tuning — adjusting thresholds, adding exceptions, or refining keyword lists to reduce noise without missing real threats. Excessive false positives cause alert fatigue, which is one of the biggest challenges in real SOC environments.

---

## Practical: Suspicious Activity Investigation

### Scenario

A SIEM alert fired after suspicious process activity was detected on the network. The task was to investigate the alert inside the SIEM interface, identify the process and the responsible user, locate the affected host, and classify the finding correctly.

### Investigation Steps

1. Clicked Start Suspicious Activity in the SIEM interface
2. Reviewed the triggered alert and identified the suspicious process
3. Traced the process back to the responsible user account
4. Identified the hostname of the affected machine
5. Examined the detection rule to find the matched keyword
6. Classified the alert and selected the appropriate response action

### Findings

| Field | Value |
|-------|-------|
| Suspicious process | cudominer.exe |
| Responsible user | chris |
| Affected hostname | HR_02 |
| Rule match keyword | miner |
| Alert classification | True Positive |
| Room flag | THM{000_SIEM_INTRO} |

### Analysis

cudominer.exe is a cryptocurrency mining application. Its presence on an HR workstation (HR_02) is highly suspicious — HR machines have no legitimate reason to run mining software. This is consistent with either a malware infection where the endpoint was compromised and a crypto miner silently installed, or an insider threat where user chris intentionally installed mining software to exploit company resources.

The SIEM detection rule matched on the keyword "miner" in the process name, demonstrating how simple but well-crafted detection rules can surface real threats quickly.

### Recommended Response Actions

1. Isolate HR_02 from the network immediately to prevent lateral movement
2. Disable chris's account pending full investigation
3. Preserve the endpoint and do not reimage before forensic analysis
4. Check for persistence mechanisms including scheduled tasks, registry run keys, and startup entries
5. Scan all other endpoints for cudominer.exe or similar processes
6. Escalate to Tier 2 for a full DFIR investigation

---

## Room Questions and Answers

| Question | Answer |
|----------|--------|
| What does SIEM stand for? | Security Information and Event Management |
| Is Registry activity host-centric or network-centric? | Host-centric |
| Is VPN activity host-centric or network-centric? | Network-centric |
| Where are HTTP logs stored on Linux? | /var/log/httpd |
| Which Event ID is generated when logs are cleared? | 104 |
| What alert type may require tuning? | False Positive |
| Which process caused the alert? | cudominer.exe |
| Who was responsible for the process? | chris |
| What was the hostname? | HR_02 |
| Which keyword matched the detection rule? | miner |
| True Positive or False Positive? | True Positive |
| What was the room flag? | THM{000_SIEM_INTRO} |

---

## Key Takeaways

1. A SIEM aggregates logs from all sources into one platform, which is essential for SOC visibility at scale
2. Knowing your log source type (host-centric vs network-centric) determines where you look first during an investigation
3. Event ID 104 (log clearing) is a critical red flag and should always be investigated immediately
4. False Positives require rule tuning since alert fatigue is a real and serious SOC problem
5. Process name keyword matching is a simple but highly effective detection technique
6. A crypto miner running on an HR machine is an automatic True Positive and automatic escalation

---

## Skills Demonstrated

- TryHackMe room navigation and browser-based lab usage
- SIEM fundamentals including data sources, log types, and alert lifecycle
- Windows and Linux log knowledge
- SIEM alert investigation covering process, user, and host identification
- Alert classification (True Positive vs False Positive)
- Incident response recommendation writing

---

## Files in This Repository

```
day-05-tryhackme-intro-to-siem/
├── README.md     
└── report.pdf    
```

---

*Part of the 30 Days of Cybersecurity portfolio project.*

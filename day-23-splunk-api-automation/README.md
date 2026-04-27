# Day 23: Python Splunk API Automation Script

**Portfolio:** 30 Days of Cybersecurity | Blue Team Track  
**Date:** April 23, 2026  
**Tools:** Python 3, Splunk REST API, requests library, Kali Linux  
**Difficulty:** Intermediate  
**Format:** Security Automation / SIEM Integration  

---

## Objective

Build a Python script that connects to Splunk's REST API, programmatically submits SPL search jobs, polls for completion, and retrieves structured results — without touching the Splunk web interface. This demonstrates how real SOC automation pipelines integrate with SIEM platforms to run scheduled queries, feed results into ticketing systems, or trigger automated responses.

---

## Lab Environment

| Component | Detail |
|-----------|--------|
| Script OS | Kali Linux (VirtualBox VM) |
| Splunk host | Windows 11 (host machine) |
| API endpoint | https://10.0.2.2:8089 (Splunk REST API port) |
| Authentication | Basic auth via requests.Session |
| Language | Python 3 |
| Library | requests |

---

## API Architecture

The Splunk REST API uses a three-step search workflow:

1. **Submit** — POST to `/services/search/jobs` with the SPL query to create a search job and receive a job ID (SID)
2. **Poll** — GET `/services/search/jobs/{sid}` repeatedly until `dispatchState` returns DONE
3. **Retrieve** — GET `/services/search/jobs/{sid}/results` to fetch the completed results as JSON

This asynchronous pattern allows Splunk to handle long-running searches without blocking the client.

---

## Searches Automated

### Search 1: Failed Login Summary

```spl
search index=main sourcetype=linux_secure "Failed password"
| rex field=_raw "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as attempts by src_ip
| sort -attempts
| head 5
```

### Search 2: Malicious Process Executions

```spl
search index=main "EventID=4688" "Category=malicious"
| rex field=_raw "(?P<hostname>\S+)\sEventID"
| rex field=_raw "Process=(?P<process>[^\s]+)"
| stats count by hostname, process
| sort -count
| head 5
```

### Search 3: Suspicious Network Connections

```spl
search index=main "EventID=5156"
| rex field=_raw "dst=(?P<dst_ip>\d+\.\d+\.\d+\.\d+)"
| rex field=_raw "dport=(?P<port>\d+)"
| stats count by dst_ip, port
| sort -count
| head 5
```

---

## Results

### Search 1: Failed Login Summary

| Source IP | Attempts |
|-----------|---------|
| 91.240.118.172 | 178 |
| 45.33.32.156 | 168 |
| 185.220.101.45 | 160 |
| 103.75.190.12 | 150 |
| 194.165.16.99 | 144 |

All five known attacker IPs from the campaign tracked throughout this portfolio were automatically identified and ranked by attempt count.

### Search 2: Malicious Process Executions

| Hostname | Process | Count |
|----------|---------|-------|
| FS-PROD-01 | svchost32.exe | 16 |
| WS-DANIEL-01 | svchost32.exe | 15 |
| WS-OPS-01 | svchost32.exe | 13 |
| WS-FINANCE-01 | svchost32.exe | 12 |
| WS-SARAH-01 | svchost32.exe | 9 |

The persistent ransomware malware svchost32.exe was confirmed running across all five hosts — consistent with the environment-wide compromise identified on Day 16.

### Search 3: Suspicious Network Connections

| Destination IP | Port | Count | Assessment |
|----------------|------|-------|-----------|
| 10.0.0.5 | 22 | 8 | Internal SSH — review |
| 10.0.0.5 | 443 | 8 | Internal HTTPS — normal |
| 192.168.1.22 | 445 | 8 | SMB — potential lateral movement |
| 91.240.118.172 | 3389 | 8 | Known attacker IP on RDP — Critical |
| 45.33.32.156 | 22 | 7 | Known attacker IP on SSH — Critical |

The attacker IP 91.240.118.172 connecting on port 3389 (RDP) is a critical finding — the attacker has established remote desktop access to the environment.

---

## Key Findings

### Finding 1: Environment-Wide svchost32.exe Infection

The automated search confirmed the ransomware persistence binary is running on all five hosts — not just the originally compromised workstations. This confirms the attacker achieved full environment compromise before deploying ransomware, consistent with the Day 15 incident response findings.

### Finding 2: Active RDP Access from Attacker IP

91.240.118.172 is making connections on port 3389 — the Windows Remote Desktop Protocol port. This means the attacker has live graphical access to at least one machine in the environment, significantly escalating the severity of the ongoing incident.

### Finding 3: SMB Lateral Movement Indicator

192.168.1.22 connecting on port 445 (SMB) appears in the suspicious connections list — consistent with file share access during lateral movement across the internal network.

---

## Real-World SOC Applications

This automation pattern can be extended for production use:

| Extension | Implementation |
|-----------|---------------|
| Scheduled execution | Run via cron every 15 minutes for continuous monitoring |
| Alert threshold | Add logic to send email or Slack alert when results exceed threshold |
| Ticketing integration | POST results to Jira or ServiceNow via their APIs automatically |
| IOC blocklist | Extract malicious IPs and push to firewall API for automatic blocking |
| MISP integration | Feed extracted IOCs into a threat intelligence platform |

---

## Skills Demonstrated

- Splunk REST API integration with Python
- Three-step async search workflow (submit, poll, retrieve)
- requests.Session for authenticated API communication
- SSL warning suppression for self-signed certificates
- JSON result parsing and structured output
- Cross-host API connectivity (Kali to Windows Splunk instance)
- SOC automation design and production extension planning

---

## Files in This Repository

```
day-23-splunk-api-automation/
├── README.md              
├── splunk_api.py          
├── splunk_results.json    
└── report.pdf             
```

---

*Part of the 30 Days of Cybersecurity portfolio project.*

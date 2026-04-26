# Day 22: Splunk Full SOC Dashboard — Auth, Network, Endpoint

**Portfolio:** 30 Days of Cybersecurity | Blue Team Track  
**Date:** April 22, 2026  
**Tools:** Splunk Enterprise, SPL  
**Difficulty:** Intermediate  
**Format:** SIEM Dashboard Engineering  

---

## Objective

Build a multi-panel SOC Operations Center dashboard in Splunk that consolidates authentication logs, network traffic data, and endpoint process execution events into a single operational view. This simulates the real-time monitoring interface a Tier 1 SOC analyst uses to detect threats across all three major data sources simultaneously.

---

## Datasets Used

| Source | Events | Content |
|--------|--------|---------|
| linux_secure | 1,000 | SSH authentication logs from Days 1 and 6 |
| syslog | 1,824 | Firewall and system logs from Day 10 |
| endpoint_logs | 350 | Process creation and network connection events |
| Total | 3,174 | Across three sourcetypes |

---

## Dashboard Overview

The SOC Operations Center dashboard contains 6 panels organised into 3 rows covering the three core SOC monitoring tracks.

| Row | Panel | Visualisation | Data Source |
|-----|-------|--------------|------------|
| 1 | Failed Logins Over Time | Line chart | linux_secure |
| 1 | Top 10 Attacker IPs | Bar chart | linux_secure |
| 2 | Network Connections to Suspicious IPs | Bar chart | endpoint_logs |
| 2 | Malicious Process Executions by Host | Bar chart | endpoint_logs |
| 3 | Process Execution Timeline | Column chart | endpoint_logs |
| 3 | Event Volume by Category | Pie chart | All sources |

---

## SPL Queries

### Panel 1: Failed Logins Over Time

```spl
index=main sourcetype=linux_secure "Failed password"
| timechart span=1h count as failed_logins
```

Buckets failed SSH login events into 1-hour windows to reveal attack timing patterns and sustained brute-force campaigns. Spikes indicate automated scanning activity.

---

### Panel 2: Top 10 Attacker IPs

```spl
index=main sourcetype=linux_secure "Failed password"
| rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as attempts by src_ip
| sort -attempts
| head 10
```

Extracts source IPs from failed login events and ranks by frequency. The top IPs represent the most persistent threat actors in the environment — these are immediate firewall block candidates.

---

### Panel 3: Network Connections to Suspicious IPs

```spl
index=main "EventID=5156"
| rex field=_raw "dst=(?<dst_ip>\d+\.\d+\.\d+\.\d+)"
| rex field=_raw "dport=(?<port>\d+)"
| stats count by dst_ip, port
| sort -count
```

Surfaces all outbound network connections grouped by destination IP and port. Connections to known attacker IPs (185.220.101.45, 91.240.118.172) or suspicious ports (4444, 8080) are immediate escalation candidates.

---

### Panel 4: Malicious Process Executions by Host

```spl
index=main "EventID=4688" "Category=malicious"
| rex field=_raw "(?<hostname>\S+)\sEventID"
| rex field=_raw "User=(?<user>\S+)"
| rex field=_raw "Process=(?<process>[^\s]+)"
| stats count by hostname, user, process
| sort -count
```

Filters process creation events to malicious category only and groups by host, user, and process name. This panel immediately shows which machines are actively compromised and which users are involved.

---

### Panel 5: Process Execution Timeline

```spl
index=main "EventID=4688"
| rex field=_raw "Category=(?<category>\S+)"
| timechart span=1h count by category
```

Stacked column chart comparing legitimate versus malicious process execution over time. Periods where malicious activity spikes while legitimate activity remains flat indicate automated attacker tooling rather than user-driven activity.

---

### Panel 6: Event Volume by Category

```spl
index=main
| eval source_type=case(
    like(_raw,"%Failed password%") OR like(_raw,"%Accepted password%"),"Authentication",
    like(_raw,"%EventID=5156%"),"Network",
    like(_raw,"%EventID=4688%"),"Endpoint",
    true(),"Other"
)
| stats count by source_type
```

Pie chart showing the overall split of event types across all data sources. Useful for understanding data coverage and identifying gaps — a well-monitored environment should have balanced representation across all three tracks.

---

## Dashboard Design Principles

### Why Three Data Tracks?

A complete SOC monitoring view requires visibility across three layers:

| Layer | What It Shows | Why It Matters |
|-------|--------------|----------------|
| Authentication | Who is logging in and failing | Detects brute-force, credential stuffing, account takeover |
| Network | What connections are being made | Detects C2 communication, lateral movement, data exfiltration |
| Endpoint | What processes are running | Detects malware execution, persistence, post-exploitation activity |

An attacker who bypasses authentication monitoring can still be caught in network or endpoint data. Covering all three layers closes the detection gaps.

### Single Pane of Glass

The dashboard consolidates data that would otherwise require three separate searches into one view. A Tier 1 analyst opening this dashboard has immediate situational awareness across the entire environment — reducing mean time to detect (MTTD) by eliminating the need to run individual queries.

---

## Portfolio Connection

This dashboard brings together data and techniques from across the portfolio:

| Dashboard Panel | Built On |
|----------------|---------|
| Failed Logins Over Time | Day 1 — Splunk failed login dashboard |
| Top 10 Attacker IPs | Day 6 — Brute-force detection rule |
| Network Connections | Day 10 — Port scan detection |
| Malicious Process Executions | Day 16 — PowerShell threat hunting |
| Process Timeline | Day 12 — Windows event log analysis |
| Event Volume Summary | All previous Splunk days |

---

## Defensive Value

This dashboard would catch the following attacks from this portfolio's campaign:

| Attack | Panel That Catches It |
|--------|----------------------|
| SSH brute-force | Panel 1 and Panel 2 |
| C2 connection to 91.240.118.172:4444 | Panel 3 |
| Encoded PowerShell execution | Panel 4 |
| Lateral movement via svchost32.exe | Panel 4 and Panel 5 |
| Ransomware deployment activity | Panel 5 spike |

---

## Skills Demonstrated

- Multi-source Splunk dashboard architecture
- SPL timechart, stats, eval, and rex across three data tracks
- Dashboard XML creation with six panel types
- SOC monitoring workflow design
- Cross-day data integration and correlation
- Operational dashboard documentation

---

## Files in This Repository

```
day-22-splunk-soc-dashboard/
├── README.md              
├── endpoint_logs.log      
└── report.pdf             
```

---

*Part of the 30 Days of Cybersecurity portfolio project.*

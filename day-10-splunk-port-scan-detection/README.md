# Day 10: Splunk Port Scan Detection with SPL

**Portfolio:** 30 Days of Cybersecurity | Blue Team Track  
**Date:** April 10, 2026  
**Tools:** Splunk Enterprise, SPL  
**Difficulty:** Intermediate  
**Format:** SIEM Detection Engineering  

---

## Objective

Write SPL queries to detect port scanning activity in firewall logs and build a live Splunk alert that triggers automatically when scanning behaviour is identified. Port scanning is one of the most common reconnaissance techniques used by attackers before an intrusion — detecting it early gives defenders the opportunity to block the attacker before they find an exploitable service.

---

## Dataset

A synthetic firewall log was generated containing 1,224 events across a 1-hour window on April 10, 2026.

| Category | Events |
|----------|--------|
| Port scan events (attacker IPs) | 1,024 |
| Legitimate traffic events | 200 |
| Total log lines | 1,224 |

**Log format sample:**
```
2026-04-10T08:00:00 firewall DENY src=185.220.101.45 dst=10.0.0.100 proto=TCP dport=1 sport=52341 flags=SYN
```

---

## SPL Queries

### Query 1: Detect Port Scan Activity

```spl
index=main "firewall"
| rex field=_raw "src=(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex field=_raw "dport=(?<dst_port>\d+)"
| stats dc(dst_port) as ports_scanned, count as total_packets by src_ip
| where ports_scanned > 100
| sort -ports_scanned
```

**Purpose:** Counts the number of unique destination ports each source IP contacted. Any IP reaching more than 100 unique ports is flagged as a scanner. The `dc()` function (distinct count) is key — it counts unique values rather than total events.

**Results:**

| Source IP | Ports Scanned | Total Packets |
|-----------|-------------|--------------|
| 185.220.101.45 | 520 | 520 |
| 45.33.32.156 | 504 | 504 |

Both IPs contacted over 500 unique ports with one packet per port — a textbook port scan signature.

---

### Query 2: Sequential Port Range Analysis

```spl
index=main "firewall"
| rex field=_raw "src=(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex field=_raw "dport=(?<dst_port>\d+)"
| where src_ip="185.220.101.45" OR src_ip="45.33.32.156"
| stats min(dst_port) as first_port, max(dst_port) as last_port, dc(dst_port) as total_ports by src_ip
| sort -total_ports
```

**Purpose:** Identifies the port range covered by each scanner to determine scope and intent.

**Results:**

| Source IP | First Port | Last Port | Total Ports |
|-----------|-----------|----------|------------|
| 185.220.101.45 | 3 | 1024 | 520 |
| 45.33.32.156 | 1 | 1022 | 504 |

Both scanners covered ports 1 through 1024 — the full well-known ports range. This targets critical services including SSH (22), HTTP (80), HTTPS (443), RDP (3389), and database ports.

---

### Query 3: Scan Timeline

```spl
index=main "firewall"
| rex field=_raw "src=(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| where src_ip="185.220.101.45" OR src_ip="45.33.32.156"
| timechart span=1m count as scan_packets by src_ip
```

**Purpose:** Maps the scan activity over time to determine speed and duration.

**Results:**

| Time Window | 185.220.101.45 | 45.33.32.156 |
|-------------|---------------|-------------|
| 08:00:00 | 309 packets | 291 packets |
| 08:01:00 | 211 packets | 213 packets |

The entire scan completed in under 2 minutes — approximately 300 packets per minute per scanner. This speed is consistent with an aggressive nmap SYN scan (`nmap -sS`).

---

### Query 4: Legitimate vs Scan Traffic

```spl
index=main "firewall"
| rex field=_raw "src=(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex field=_raw "dport=(?<dst_port>\d+)"
| eval traffic_type=if(src_ip="185.220.101.45" OR src_ip="45.33.32.156","Port Scan","Legitimate")
| stats count by traffic_type
```

**Purpose:** Provides a clean breakdown of malicious versus legitimate traffic volume.

**Results:**

| Traffic Type | Count |
|-------------|-------|
| Legitimate | 200 |
| Port Scan | 1,024 |

Port scan events represent 83.6% of all traffic in the capture window — a clear signal that the environment was under active reconnaissance.

---

## Detection Alert Configuration

| Field | Value |
|-------|-------|
| Alert name | Port Scan Detection |
| Description | Triggers when any IP scans more than 100 unique destination ports |
| Alert type | Scheduled |
| Schedule | Every 10 minutes (*/10 * * * *) |
| Time range | Last 10 minutes |
| Trigger condition | Number of results greater than 0 |
| Trigger action | Add to Triggered Alerts |

---

## Findings Summary

| Finding | Detail |
|---------|--------|
| Scanner IPs | 185.220.101.45 and 45.33.32.156 |
| Port range scanned | Ports 1 through 1024 (full well-known ports range) |
| Scan speed | Approximately 300 packets per minute — aggressive fast scan |
| Scan duration | Under 2 minutes |
| Total scan packets | 1,024 |
| Traffic composition | 83.6% scan traffic, 16.4% legitimate |

---

## Attack Context

A port scan covering ports 1 through 1024 at 300 packets per minute is consistent with an nmap SYN scan. The attacker is mapping which services are running on the target server before selecting an attack vector. Common targets in this port range include SSH on port 22, HTTP on port 80, HTTPS on port 443, and RDP on port 3389.

A port scan is almost always a precursor to exploitation — it is the attacker's shopping list. Detecting and blocking scanners at this stage prevents them from finding vulnerabilities to exploit.

---

## Key Concepts

**Why use dc() instead of count()?**  
`count()` would return the total number of packets, which could be inflated by retransmissions or repeated connections to the same port. `dc()` counts only unique destination ports, which is the true measure of scanning breadth.

**Why 100 ports as the threshold?**  
A legitimate user or application will never contact 100 unique ports on a single server. Even the most complex enterprise application uses fewer than 20 ports. A threshold of 100 provides a comfortable buffer above legitimate traffic while catching all realistic scanning behaviour.

**Why does one packet per port matter?**  
In the results, ports scanned equals total packets for both scanner IPs. This one-to-one ratio is a definitive port scan signature — each port was contacted exactly once, which is how scanning tools like nmap operate by default.

---

## Defensive Recommendations

1. Block both scanner IPs at the firewall immediately and add them to a threat intelligence feed
2. Deploy this alert in any Splunk environment with firewall or network flow log ingestion
3. Tune the threshold down to 50 unique ports for higher sensitivity environments
4. Combine with a geo-lookup to flag scans from unexpected countries automatically
5. Implement rate limiting on your firewall — drop connections from IPs exceeding 50 SYN packets per second to a single destination
6. Consider deploying a honeypot on unused ports to catch scanners before they reach real services

---

## Skills Demonstrated

- SPL regex field extraction from raw firewall logs
- dc() distinct count function for unique value analysis
- min() and max() functions for range analysis
- timechart for temporal attack pattern visualisation
- eval for traffic classification logic
- Splunk scheduled alert configuration
- Port scan detection methodology and threshold reasoning

---

## Files in This Repository

```
day-10-splunk-port-scan-detection/
├── README.md        
├── firewall.log     
└── report.pdf       
```

---

*Part of the 30 Days of Cybersecurity portfolio project.*

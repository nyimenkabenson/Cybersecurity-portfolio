# Day 6: Splunk Brute-Force Detection Rule

**Portfolio:** 30 Days of Cybersecurity | Blue Team Track  
**Date:** April 6, 2026  
**Tools:** Splunk Enterprise, SPL  
**Difficulty:** Intermediate  
**Format:** SIEM Detection Engineering  

---

## Objective

Build a live Splunk detection rule that automatically triggers an alert when brute-force SSH login activity is detected. This project goes beyond querying and visualising data — it produces a working detection rule that runs on a schedule and fires when the threat condition is met, simulating real SOC detection engineering work.

---

## Dataset

The same `auth.log` dataset from Day 1 was used: 500 SSH authentication log events covering a 24-hour period, with 400 failed login attempts from 5 external attacker IPs and 100 legitimate events from internal IPs.

---

## Detection Rule: Brute-Force SSH Alert

### Rule Logic

If any single IP address generates more than 5 failed SSH login attempts within a 10-minute window, the alert triggers. This threshold catches automated brute-force tools while avoiding false positives from occasional legitimate failures.

### SPL Query

```spl
index=main "Failed password"
| rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| bucket _time span=10m
| stats count as failed_attempts by src_ip, _time
| where failed_attempts > 5
| sort -failed_attempts
```

### Query Breakdown

The query searches for all failed password events, extracts the source IP using regex, groups events into 10-minute time buckets, counts failures per IP per bucket, and filters for IPs exceeding the threshold of 5.

### Alert Configuration

| Field | Value |
|-------|-------|
| Alert name | Brute-Force SSH Detection |
| Alert type | Scheduled |
| Schedule | Every 10 minutes (*/10 * * * *) |
| Time range | Last 10 minutes |
| Trigger condition | Number of results greater than 0 |
| Trigger action | Add to Triggered Alerts |

### Results

The query returned all 5 attacker IPs with their attempt counts per 10-minute window, confirming the rule fires correctly against known brute-force activity.

---

## Supporting Detection Queries

### Query 2: Distributed Brute-Force Detection

A distributed attack spreads login attempts across multiple source IPs to stay below single-IP thresholds. This query surfaces usernames being targeted by more than one IP simultaneously.

```spl
index=main "Failed password"
| rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex field=_raw "for (invalid user )?(?<username>\w[\w.]*) from"
| stats dc(src_ip) as unique_ips, count as total_attempts by username
| where unique_ips > 1
| sort -total_attempts
```

Results showed multiple usernames being targeted by more than one attacker IP, confirming a coordinated distributed brute-force campaign across the dataset.

### Query 3: First-Time Seen IP Detection

New IPs that have never appeared in logs before are high-priority investigation targets. This query shows each source IP alongside its first appearance timestamp and total attempt count.

```spl
index=main "Failed password"
| rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats min(_time) as first_seen, count as attempts by src_ip
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S")
| sort -attempts
```

Results returned all attacker IPs with first-seen timestamps and attempt counts, providing a clear picture of when each threat actor first appeared in the environment.

---

## Detection Rule Summary

| Rule | Threat Detected | Trigger Condition |
|------|----------------|------------------|
| Brute-Force SSH Detection | Single IP burst | More than 5 failures in 10 minutes |
| Distributed Attack Detection | Multi-IP campaign | Same username targeted by more than 1 IP |
| First-Time Seen IP | New threat actor | IP appearing for the first time in logs |

---

## Key Concepts

**Why 5 attempts as the threshold?**  
A legitimate user mistyping their password will typically fail 2 to 3 times before succeeding or resetting. A threshold of 5 catches automated tools (which attempt hundreds per minute) while avoiding false positives from normal user behaviour.

**Why 10-minute buckets?**  
Brute-force tools are designed to work fast. A 10-minute window is wide enough to catch slow-and-low attacks but short enough to trigger before significant damage is done.

**Why monitor distributed attacks separately?**  
Attackers use botnets to spread attempts across thousands of IPs to evade per-IP rate limiting. A rule that only watches individual IPs will miss this pattern entirely.

---

## Defensive Recommendations

1. Deploy this alert in any Splunk environment monitoring SSH-facing servers
2. Tune the threshold of 5 based on your environment — high-traffic servers may need a higher value to reduce false positives
3. Pair this alert with an automated response: feed triggered IPs into a firewall blocklist via Splunk's webhook action
4. Add a geo-enrichment lookup to flag attempts from unexpected countries
5. Combine with the Day 1 dashboard to give responders instant visual context when the alert fires

---

## Skills Demonstrated

- Splunk Saved Search Alert configuration
- Cron-based scheduling in Splunk
- SPL regex extraction and time bucketing
- Multi-layer detection rule design (single IP, distributed, new IP)
- Detection threshold reasoning and tuning logic
- SOC detection engineering documentation

---

## Files in This Repository

```
day-06-splunk-brute-force-detection/
├── README.md     
└── report.pdf    
```

---

*Part of the 30 Days of Cybersecurity portfolio project.*

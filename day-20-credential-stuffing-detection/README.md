# Day 20: SOC Detection Use Case — Credential Stuffing

**Portfolio:** 30 Days of Cybersecurity | Blue Team Track  
**Date:** April 20, 2026  
**Tools:** Analyst documentation, MITRE ATT&CK framework  
**Difficulty:** Intermediate  
**Format:** SOC Detection Engineering  

---

## Threat Overview

Credential stuffing is an automated attack where threat actors obtain large databases of leaked username and password combinations from previous data breaches and systematically test them against login portals. Unlike brute-force attacks which attempt to guess passwords randomly, credential stuffing uses real credentials that genuinely worked somewhere else — making it significantly more likely to succeed and harder to detect.

The attack exploits the reality that most people reuse passwords across multiple services. When a breach exposes credentials from one platform, attackers immediately test those same credentials against banks, email providers, corporate VPNs, and e-commerce sites. Tools like Sentry MBA, SNIPR, and Credential Chief automate the process at scale — testing millions of combinations per hour across distributed infrastructure to avoid rate limiting.

### Credential Stuffing vs Brute-Force

| Feature | Credential Stuffing | Brute-Force |
|---------|-------------------|-------------|
| Credentials used | Real leaked credentials | Guessed or generated |
| Success rate | High (0.1% to 2%) | Very low |
| Volume required | Moderate | Extremely high |
| Detection difficulty | Harder | Easier |
| Source | Breach databases | Wordlists or random |
| Tool examples | Sentry MBA, SNIPR | Hydra, Medusa |

A 0.1% success rate sounds low but against a list of 10 million credentials means 10,000 compromised accounts.

---

## Attack Indicators

The following observable indicators appear in logs during a credential stuffing attack:

1. **High volume of failed logins across many different usernames from one or a small number of IPs** — the defining pattern. Unlike brute-force which hammers one account, stuffing spreads attempts across thousands of accounts.

2. **Login attempts matching known breached credential pairs** — if threat intelligence feeds are integrated, some username/password combinations will match entries in known breach databases.

3. **Successful logins immediately following failed attempts** — a sudden success after a series of failures from the same IP suggests a valid credential was found from the stuffing list.

4. **Login attempts from unusual geographic locations** — an account that always logs in from Lagos suddenly authenticating from Eastern Europe or an AWS data centre is a strong indicator.

5. **High ratio of unique usernames per source IP** — legitimate users connect from one IP and authenticate with one account. An IP hitting 500 different usernames in an hour is never legitimate.

6. **Distributed attempts from many IPs targeting the same accounts** — sophisticated attackers use botnets to distribute attempts across thousands of IPs to evade per-IP rate limiting, while still targeting the same username list.

7. **Unusual User-Agent strings** — credential stuffing tools often use default or fake browser User-Agent headers that do not match normal browser patterns.

8. **Login attempts outside business hours across many accounts** — automated tools run 24/7 while human users follow business hours patterns.

---

## Data Sources Required

| Log Source | What It Provides | Why Needed |
|-----------|-----------------|-----------|
| Authentication logs (Windows Event ID 4625/4624) | Failed and successful logon events with username, source IP, timestamp | Primary detection source — raw login attempt data |
| Web Application Firewall (WAF) logs | HTTP request details including User-Agent, IP, endpoint, response code | Detects stuffing against web login portals |
| VPN authentication logs | Remote access login attempts with source IP and geographic data | Detects stuffing against remote access infrastructure |
| Identity Provider logs (Azure AD, Okta) | Cloud authentication events across all integrated applications | Single source for all SaaS and cloud app login attempts |
| Network firewall logs | Source IP reputation, connection frequency, geographic origin | Enriches authentication events with network context |
| Threat intelligence feeds | Known bad IPs, breached credential lists, Tor exit nodes | Enables matching attempts against known attacker infrastructure |

---

## Detection Logic

### Rule 1: High-Volume Multi-Account Failure (Primary Rule)

**Condition:** Any single source IP generates failed authentication attempts against more than 20 unique usernames within a 10-minute window.

**Rationale:** A legitimate user will fail on their own account — not on 20 different accounts. Any IP hitting 20 unique usernames in 10 minutes is running an automated tool.

### Rule 2: Distributed Stuffing Detection

**Condition:** More than 50 unique source IPs each generate at least 3 failed login attempts against the same set of usernames within a 1-hour window.

**Rationale:** Sophisticated attackers distribute attempts across many IPs to stay below single-IP thresholds. This rule detects the coordinated pattern across the IP space.

### Rule 3: Success After Failure

**Condition:** A source IP that generated 5 or more failed login attempts in the past 30 minutes achieves a successful login on any account.

**Rationale:** A successful login from an IP that was just failing is the highest-confidence indicator that a valid credential was found through stuffing.

### Rule 4: Geographic Anomaly Post-Failure

**Condition:** A user account achieves a successful login from a country or ASN not seen in the past 30 days, within 1 hour of failed login attempts against that same account.

**Rationale:** Stuffing tools use proxies and VPNs in countries the organisation does not normally see traffic from.

---

## Alert Thresholds

| Rule | Threshold | Time Window | Confidence |
|------|-----------|------------|-----------|
| Multi-account failure | 20 unique usernames per IP | 10 minutes | High |
| Distributed stuffing | 50 IPs × 3 failures on same usernames | 1 hour | Medium |
| Success after failure | 1 success after 5 failures from same IP | 30 minutes | Critical |
| Geographic anomaly | New country + prior failures | 1 hour | High |

### Threshold Tuning Notes

Start conservative and tune down based on your environment's baseline. High-traffic login portals with global users may need higher thresholds to avoid false positives. Low-traffic internal systems can use much lower thresholds. Review false positive rates weekly for the first month after deployment.

---

## Triage Steps

When the alert fires, the analyst follows this process:

**Step 1 — Confirm the alert is not a false positive**  
Check whether the source IP is a known legitimate system — internal scanner, load balancer, monitoring tool, or shared corporate NAT. If yes, close as FP and add to exclusion list.

**Step 2 — Enrich the source IP**  
Run the IP through VirusTotal, AbuseIPDB, and Shodan. Check whether it is a Tor exit node, known proxy, VPN provider, or previously flagged attacker IP. Cross-reference against the campaign IPs identified in this portfolio.

**Step 3 — Assess the scope**  
Determine how many unique accounts were targeted, how many attempts were made, and over what time window. Check whether any attempts succeeded.

**Step 4 — Check for successful logins**  
This is the most critical step. Search for any successful authentication events from the same source IP or targeting the same accounts in the same window. A success changes the severity from Medium to Critical immediately.

**Step 5 — Review affected accounts**  
For any accounts that had successful logins, check for post-authentication activity — password changes, MFA device additions, data downloads, email forwarding rules, or privilege escalation.

**Step 6 — Classify the alert**  
Based on steps 1 through 5, classify as True Positive, False Positive, or True Positive requiring escalation.

---

## Response Actions

### If No Successful Logins (Attempted Stuffing — Blocked)

1. Block the source IP at the firewall and WAF
2. Add IP to threat intelligence blocklist
3. Document the attempt in the ticketing system
4. Monitor for repeat attempts from different IPs targeting the same accounts

### If Successful Logins Confirmed (Active Compromise)

1. Immediately lock all accounts that had successful logins from the attacking IP
2. Force password reset on all affected accounts
3. Revoke all active sessions for affected accounts
4. Check and remove any MFA devices added after the compromise time
5. Review post-compromise activity — emails sent, files accessed, settings changed
6. Notify affected users with clear instructions
7. Escalate to Tier 2 for full investigation if sensitive data was accessed
8. Notify management and legal if regulated data (PII, financial) was accessed

---

## SPL Detection Query (Splunk Implementation)

```spl
index=main (EventID=4625 OR EventID=4624)
| rex field=_raw "src_ip=(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex field=_raw "user=(?<username>\S+)"
| rex field=_raw "status=(?<status>\S+)"
| bucket _time span=10m
| stats dc(username) as unique_accounts, count as total_attempts,
    values(status) as statuses by src_ip, _time
| where unique_accounts > 20
| eval alert="Credential Stuffing Detected"
| sort -unique_accounts
```

---

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Technique | T1110 — Brute Force |
| Sub-technique | T1110.004 — Credential Stuffing |
| Related | T1078 — Valid Accounts (post-success) |

### T1110.004 Sub-technique Detail

Credential stuffing is specifically defined under T1110.004 in MITRE ATT&CK. The technique is distinct from password spraying (T1110.003) which uses one password against many accounts, and from password guessing (T1110.001) which uses generated passwords. T1110.004 specifically uses credentials from external breach sources.

---

## Real-World Context

Credential stuffing is one of the most common attack types targeting organisations today. Major incidents include:

- The 2020 Nintendo breach — 160,000 accounts compromised via credential stuffing
- Spotify credential stuffing attacks — thousands of accounts taken over using breached credentials
- Financial sector attacks — automated stuffing against online banking portals using breach data

The attack is particularly dangerous because the credentials are real — multi-factor authentication is the single most effective control, as a valid password alone is not sufficient to complete the login.

---

## Key Takeaways for Study

1. Credential stuffing uses real breached credentials — not guessed passwords. This is why MFA is the most effective defence.
2. The defining detection pattern is many unique usernames from one IP — not many attempts at one username.
3. A success after failures is the highest-severity alert — treat it as an active compromise immediately.
4. Sophisticated attackers distribute attempts across many IPs — single-IP rate limiting alone is insufficient.
5. Geographic anomaly detection is a powerful secondary signal — valid users do not suddenly log in from unusual countries.
6. MITRE ATT&CK T1110.004 is the specific technique — know this for BTL1 and Security+ exams.

---

## Files in This Repository

```
day-20-credential-stuffing-detection/
├── README.md     
└── report.pdf    
```

---

*Part of the 30 Days of Cybersecurity portfolio project.*

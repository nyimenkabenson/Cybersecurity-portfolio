# Day 11: SOC Scenario — Phishing Email Chain Investigation

**Portfolio:** 30 Days of Cybersecurity | Blue Team Track  
**Date:** April 11, 2026  
**Tools:** Analyst judgement, MITRE ATT&CK framework  
**Ticket:** INC-2026-0411  
**Difficulty:** Intermediate  
**Format:** SOC Incident Investigation  

---

## Scenario Overview

HR Manager Sarah Kwame reported receiving a suspicious email at 09:31 AM on April 11, 2026. She clicked a link in the email at 09:47 AM and her workstation (WS-SARAH-01) began exhibiting unusual behaviour. The helpdesk escalated to the SOC for full investigation.

---

## Email Analysis

### Email Details

| Field | Value |
|-------|-------|
| From | payroll-update@hr-portal-secure.com |
| To | sarah.kwame@wiresharkworkshop.online |
| Subject | URGENT: Your April Payroll Details Have Changed |
| Date | April 11, 2026 — 09:31 AM |
| Attachment | Payroll_April2026.pdf (284 KB) |
| Malicious URL | http://hr-payroll-verify.xyz/confirm?token=8f3k2p |

### Email Header Indicators

| Header | Result | Significance |
|--------|--------|-------------|
| SPF | FAIL | Sending server not authorised for this domain |
| DKIM | FAIL | Email integrity cannot be verified |
| DMARC | FAIL | Domain policy violated — email should be rejected |
| Originating IP | 185.220.101.45 | Known malicious IP from previous investigations |

All three email authentication protocols failed simultaneously — a definitive technical confirmation of a spoofed phishing email. The originating IP 185.220.101.45 was previously identified as a known attacker IP in Days 1, 6, and 8 of this portfolio, confirming attribution to a known threat actor.

### Sender Domain Analysis

`hr-portal-secure.com` is a lookalike domain designed to appear legitimate at a quick glance. Legitimate company communications originate from the organisation's own domain (`@wiresharkworkshop.online`). Attackers register convincing-sounding domains specifically to deceive employees who do not examine the full sender address carefully.

### Malicious URL Analysis

The link `http://hr-payroll-verify.xyz/confirm?token=8f3k2p` contains three red flags. First, the `.xyz` TLD is associated with high malware usage and is not used by legitimate HR platforms. Second, `hr-payroll-verify.xyz` is another lookalike domain — not the organisation's real domain. Third, the `?token=8f3k2p` tracking parameter identifies the specific victim who clicked, confirming to the attacker that the target is live and engaged.

---

## Endpoint Timeline Analysis

### WS-SARAH-01 — Event Reconstruction

| Time | Event | Analysis |
|------|-------|---------|
| 09:47:12 | Sarah opened malicious URL | Initial compromise vector activated |
| 09:47:18 | invoice_setup.exe downloaded | Malware dropper disguised as payroll document |
| 09:47:31 | invoice_setup.exe executed (parent: chrome.exe) | User clicked or auto-execution triggered |
| 09:47:33 | powershell.exe with EncodedCommand (parent: invoice_setup.exe) | Malware spawned encoded PowerShell to evade detection |
| 09:47:41 | Registry Run key modified with svchost32.exe | Persistence mechanism established |
| 09:47:55 | Outbound connection to 91.240.118.172:4444 | Initial Metasploit reverse shell C2 check-in |
| 09:48:10 | svchost32.exe written to Temp folder | Persistent malware binary dropped to disk |
| 09:52:44 | DNS query to default.exp-tas.com | Secondary C2 domain resolution |
| 09:53:01 | TLS connection to 13.107.5.93:443 | Encrypted secondary C2 channel established |

### Attack Chain Narrative

Sarah received a urgency-themed phishing email impersonating her company's payroll system. The social engineering pressure of a 24-hour deadline and payment threat prompted her to click the embedded link. The malicious site immediately served `invoice_setup.exe` — a dropper disguised as a legitimate document.

Upon execution, the dropper spawned PowerShell with a base64-encoded payload (`-EncodedCommand`) to evade security tools that scan for suspicious plaintext commands. PowerShell is abused because it is trusted natively by Windows and can execute arbitrary code, download additional payloads, and modify system settings without triggering standard AV signatures.

The malware then established persistence by writing `svchost32.exe` to the Windows Registry Run key — ensuring it restarts automatically every time Sarah logs in. The filename deliberately mimics the legitimate Windows process `svchost.exe` to avoid suspicion during manual inspection.

Within seconds, the malware established an outbound reverse shell to port 4444 — the default Metasploit listener port — giving the attacker live interactive access to Sarah's machine. A secondary encrypted C2 channel was then established to `exp-tas.com` via domain fronting through Microsoft CDN infrastructure, providing a persistent covert channel hidden inside what appears to be legitimate HTTPS traffic.

---

## Key Technical Findings

### Finding 1: Infrastructure Overlap with Previous Incident

The C2 domain `default.exp-tas.com` and the fronting IP `13.107.5.93` are identical to those identified in the Day 9 malware PCAP analysis ("You Dirty RAT"). This infrastructure overlap links both incidents to the same threat actor operating the same C2 framework, suggesting a coordinated campaign targeting the organisation.

### Finding 2: Known Malicious IP as Email Origin

The originating IP 185.220.101.45 was previously identified as a high-confidence malicious IP in the Day 8 VirusTotal analysis (17 malicious engine detections). The same IP was present in brute-force logs on Days 1 and 6. This IP is persistent, active infrastructure used by this threat actor across multiple attack vectors.

### Finding 3: Dual C2 Architecture

The malware established two separate C2 channels — an immediate reverse shell on port 4444 for live operator access and a secondary encrypted TLS channel on port 443 for persistent long-term access. This redundancy ensures the attacker maintains access even if one channel is blocked.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Evidence |
|-------------|------|---------|
| T1566.001 | Phishing: Spearphishing Attachment | Malicious PDF attached to phishing email |
| T1059.001 | PowerShell | Encoded PowerShell execution from invoice_setup.exe |
| T1547.001 | Registry Run Keys: Boot or Logon Autostart | HKCU Run key set to svchost32.exe |
| T1071.001 | Application Layer Protocol: Web | C2 communication over TLS port 443 |
| T1090.004 | Proxy: Domain Fronting | C2 traffic routed through Microsoft CDN |
| T1105 | Ingress Tool Transfer | invoice_setup.exe downloaded from C2 server |
| T1041 | Exfiltration Over C2 Channel | Active reverse shell connection on port 4444 |

---

## Indicators of Compromise

| Type | Value | Classification |
|------|-------|---------------|
| Domain | hr-portal-secure.com | Phishing sender domain |
| Domain | hr-payroll-verify.xyz | Malicious delivery domain |
| Domain | default.exp-tas.com | C2 domain |
| IP | 185.220.101.45 | Phishing email origin and known attacker IP |
| IP | 91.240.118.172 | Metasploit reverse shell listener |
| IP | 13.107.5.93 | C2 fronting IP (Microsoft CDN) |
| File | invoice_setup.exe | Malware dropper |
| File | svchost32.exe | Persistent malware binary |
| Registry | HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate | Persistence key |
| URL | http://hr-payroll-verify.xyz/confirm?token=8f3k2p | Phishing delivery URL |

---

## Immediate Response Actions

Priority-ordered actions for incident containment and remediation:

1. Isolate WS-SARAH-01 from the network immediately to cut active C2 connections
2. Preserve the machine for forensics — do not reimage before memory acquisition and disk imaging
3. Reset Sarah's credentials — username and password may have been captured by a keylogger
4. Block all IOC domains and IPs at the firewall and DNS resolver across the entire environment
5. Search all endpoints for svchost32.exe in Temp folders and the registry Run key modification
6. Pull Sarah's emails and check whether the same phishing email was sent to other employees
7. Escalate to Tier 2 DFIR for full memory and disk forensic investigation
8. Notify HR and management per the organisation's incident response plan

---

## Key Lessons

1. SPF, DKIM, and DMARC failures together are definitive proof of email spoofing — never dismiss them
2. Encoded PowerShell (-EncodedCommand) is never legitimate in a user context — always escalate
3. Registry Run key modifications are a persistence red flag — attackers survive reboots this way
4. Infrastructure overlap between incidents reveals campaign attribution and threat actor continuity
5. Urgency language in phishing emails ("within 24 hours", "payment delays") is a manipulation technique — train users to pause and verify before clicking

---

## Skills Demonstrated

- Phishing email header analysis (SPF, DKIM, DMARC)
- Lookalike domain identification
- Endpoint timeline reconstruction and narrative writing
- Persistence mechanism identification
- Dual C2 architecture analysis
- Infrastructure overlap and threat actor attribution
- MITRE ATT&CK technique mapping
- Incident response priority ordering

---

## Files in This Repository

```
day-11-phishing-investigation/
├── README.md     
└── report.pdf    
```

---

*Part of the 30 Days of Cybersecurity portfolio project.*

# Day 25: DFIR Capstone — Full End-to-End Incident Investigation

**Portfolio:** 30 Days of Cybersecurity | Blue Team Track  
**Date:** April 25, 2026  
**Ticket:** INC-2026-0425  
**Severity:** Critical  
**Format:** DFIR Capstone / Full Incident Investigation  

---

## Scenario Overview

At 08:15 AM on April 25, 2026, the SOC received alerts indicating a serious compromise at wiresharkworkshop.online. Three employees had received phishing emails impersonating IT support. Two clicked the link. Investigation revealed a complete attack chain from initial phishing through data exfiltration and ransomware deployment — all executed within 47 minutes of the first click.

---

## Affected Systems

| Hostname | Role | Impact |
|----------|------|--------|
| WS-JAMES-01 | James Osei workstation | Initial compromise — fully encrypted |
| WS-FINANCE-01 | Finance workstation | Ransomware deployed — encrypted |
| WS-HR-01 | HR workstation | Ransomware deployed — encrypted |
| FS-PROD-01 | File server | Finance and HR data exfiltrated |

---

## Section 1: Initial Access

The attacker gained their first foothold via a spearphishing email impersonating IT support. Three email header indicators confirm this is malicious:

**Indicator 1 — Authentication failures:** SPF, DKIM, and DMARC all failed simultaneously, confirming the email was sent from an unauthorised server spoofing the legitimate domain.

**Indicator 2 — Suspicious sender domain:** `vpn-portal-update.com` is a lookalike domain designed to appear legitimate. Legitimate IT communications would originate from `@wiresharkworkshop.online`.

**Indicator 3 — Known attacker infrastructure:** The originating IP 185.220.101.45 is a confirmed malicious IP that has appeared in 7 previous incidents across this portfolio dating back to April 1, 2026.

**Social engineering technique:** The subject "URGENT: VPN Credentials Expiring Today" creates artificial urgency, suppressing the recipient's critical thinking and prompting immediate action without verification.

---

## Section 2: Execution Chain

Full timeline from first click to C2 establishment:

| Time | Event | Analysis |
|------|-------|---------|
| 07:31:14 | Chrome opened phishing URL | Initial compromise vector activated |
| 07:31:22 | VPN_update.exe downloaded | Malware dropper disguised as VPN tool |
| 07:31:45 | VPN_update.exe executed (parent: chrome.exe) | User ran or auto-execution triggered |
| 07:31:47 | powershell.exe -WindowStyle Hidden -enc | Encoded payload concealed from taskbar |
| 07:31:59 | Registry Run key written | Persistence established immediately |
| 07:32:11 | Outbound connection to 91.240.118.172:4444 | Reverse shell — attacker gains live control |
| 07:32:45 | whoami, net user, nltest executed | Attacker begins reconnaissance |
| 07:33:10 | svch0st.exe created in Temp | Persistent malware binary dropped |
| 07:33:44 | TLS connection to 13.107.5.93:443 | Secondary encrypted C2 via domain fronting |

**Decoded PowerShell payload:** The base64-encoded command `-enc cwB2AGMAaABvAHMAdAAzADIALgBlAHgAZQA=` decodes to `svch0st.exe` — the persistent malware binary name, confirming the encoded command dropped the malware to disk.

---

## Section 3: Persistence

The attacker established persistence via a Windows Registry Run key within 14 seconds of initial execution:

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\VPNHelper
Value: C:\Users\james\AppData\Local\Temp\VPN_update.exe
```

The key name `VPNHelper` is deliberately chosen to appear as a legitimate VPN application helper process during casual inspection, reducing the chance of manual discovery.

---

## Section 4: Discovery (Reconnaissance)

Three reconnaissance commands executed from the attacker's shell within 6 seconds of gaining access:

| Command | Purpose | MITRE Technique |
|---------|---------|----------------|
| whoami.exe | Confirm compromised user identity | T1033 |
| net.exe user /domain | Enumerate all domain user accounts | T1087 |
| nltest.exe /domain_trusts | Map Active Directory trusted domains | T1482 |

The use of `nltest.exe` is particularly significant — it goes beyond basic user enumeration to map the entire Active Directory trust structure. This is an advanced attacker behaviour indicating preparation for broad lateral movement or cross-domain attacks.

---

## Section 5: Lateral Movement

At 07:45:22 — 13 minutes after initial compromise — the attacker connected from WS-JAMES-01 to FS-PROD-01 via SMB (port 445) using James's credentials. These credentials were likely captured either by a keylogger component of the malware or harvested directly from the phishing page before the dropper was delivered.

This SMB lateral movement is MITRE ATT&CK T1021.002 (Remote Services: SMB/Windows Admin Shares).

---

## Section 6: Data Exfiltration

Two high-value files were accessed and exfiltrated from FS-PROD-01:

| File | Location | Content | Risk |
|------|----------|---------|------|
| Q1_Report.xlsx | \Finance\ | Quarterly financial data | Commercial sensitivity |
| Employee_Records.xlsx | \HR\ | Staff personal data | Regulatory — GDPR/data protection |

**Total exfiltrated: 45 MB**  
**Destination: 185.220.101.45:443**

The exfiltration destination is the same IP that sent the original phishing email — confirming the attacker uses the same infrastructure for delivery, C2, and data receipt. This is a critical attribution indicator.

**Double extortion confirmed:** The attacker stole data before encrypting. This is the double extortion ransomware model — victims face two simultaneous threats: pay to decrypt files AND pay to prevent stolen data being published publicly.

---

## Section 7: Impact Timeline

| Time | Action | Technique |
|------|--------|----------|
| 07:46:55 | 45 MB data exfiltrated | T1041 |
| 07:52:10 | vssadmin delete shadows /all /quiet | T1490 |
| 07:58:30 | Ransomware deployed to 3 machines | T1486 |
| 08:01:45 | Encryption complete — ransom note dropped | T1486 |
| 08:15:00 | SOC receives first alert | — |

Shadow copies were deleted before encryption to eliminate the free recovery option. The 47-minute gap between first click and SOC alert demonstrates the danger of detection delays — the entire attack was complete before anyone was aware.

---

## Section 8: Infrastructure Attribution

This attack uses infrastructure that has appeared across the entire 25-day campaign:

| IP / Domain | Previous Incidents | Days |
|-------------|-------------------|------|
| 185.220.101.45 | SSH brute-force, VirusTotal analysis, phishing, ransomware | 1, 6, 8, 11, 15, 16, 23 |
| 91.240.118.172 | C2 PCAP, phishing compromise, port 4444 reverse shell | 9, 11, 15, 16, 23 |
| 13.107.5.93 | Domain fronting via Microsoft CDN | 9, 11 |
| default.exp-tas.com | C2 domain | 9, 11 |

This is not a new attacker. wiresharkworkshop.online has been under continuous targeted attack by the same threat actor since April 1, 2026. The organisation was never fully remediated after previous incidents — each incomplete response left the attacker with residual access that enabled the next attack.

---

## Section 9: MITRE ATT&CK Mapping

| Technique ID | Name | Evidence |
|-------------|------|---------|
| T1566.001 | Phishing: Spearphishing Attachment | Malicious PDF attached to email |
| T1566.002 | Phishing: Spearphishing Link | Malicious URL in email body |
| T1059.001 | PowerShell | Encoded hidden PowerShell execution |
| T1547.001 | Registry Run Keys | VPNHelper persistence key |
| T1071.001 | Application Layer Protocol | C2 over TLS port 443 |
| T1090.004 | Domain Fronting | C2 via Microsoft CDN (13.107.5.93) |
| T1033 | System Owner Discovery | whoami.exe execution |
| T1087 | Account Discovery | net user /domain |
| T1482 | Domain Trust Discovery | nltest /domain_trusts |
| T1021.002 | SMB/Windows Admin Shares | Lateral movement to FS-PROD-01 |
| T1005 | Data from Local System | Finance and HR files accessed |
| T1041 | Exfiltration Over C2 Channel | 45 MB uploaded to attacker IP |
| T1490 | Inhibit System Recovery | vssadmin delete shadows /all /quiet |
| T1486 | Data Encrypted for Impact | Ransomware deployed to 3 machines |

---

## Section 10: Immediate Response Actions

| Priority | Action | Reason |
|----------|--------|--------|
| 1 | Isolate WS-JAMES-01, WS-FINANCE-01, WS-HR-01 | Stop active encryption and C2 |
| 2 | Isolate FS-PROD-01 | Attacker has active SMB access |
| 3 | Block all IOC IPs and domains at firewall | Cut C2 channels across environment |
| 4 | Preserve forensic evidence | Memory and disk images before remediation |
| 5 | Reset all domain credentials | Attacker enumerated all domain accounts |
| 6 | Verify backup integrity | Confirm clean offline backups exist |
| 7 | Notify law enforcement | HR and Finance data exfiltrated — regulatory requirement |
| 8 | Engage DFIR team | Full forensic investigation required |
| 9 | Prepare breach notification | HR Employee_Records.xlsx likely contains PII |
| 10 | Full environment audit | Same attacker active since April 1 — residual access likely elsewhere |

---

## Campaign Summary — 25 Days of Attacks

This capstone investigation reveals that wiresharkworkshop.online has been under continuous targeted attack by the same threat actor for 25 days. Each incident was a building block toward this ransomware and extortion outcome:

| Phase | Days | Activity |
|-------|------|---------|
| Reconnaissance | 1, 6, 10 | SSH brute-force, port scanning, credential gathering |
| Initial access | 11, 15 | Phishing compromises of Sarah and Daniel |
| Persistence | 12, 16 | Malware installed, PowerShell abuse, registry keys |
| Intelligence gathering | 9, 17, 21 | C2 traffic analysis, IOC extraction, memory forensics |
| Ransomware | 15, 25 | Full encryption and double extortion |

---

## Skills Demonstrated

- Full end-to-end incident investigation
- Attack chain reconstruction across 47-minute timeline
- Multi-stage MITRE ATT&CK mapping (14 techniques)
- Double extortion ransomware analysis
- 25-day campaign attribution and infrastructure reuse analysis
- Regulatory data breach identification (HR and Finance records)
- Priority-ordered incident response planning

---

## Files in This Repository

```
day-25-dfir-capstone/
├── README.md     
└── report.pdf    
```

---

*Part of the 30 Days of Cybersecurity portfolio project.*

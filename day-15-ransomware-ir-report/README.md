# Day 15: DFIR — Ransomware Incident Response Report

**Portfolio:** 30 Days of Cybersecurity | Blue Team Track  
**Date:** April 15, 2026  
**Ticket:** INC-2026-0415  
**Severity:** Critical  
**Format:** DFIR / Incident Response  

---

## Scenario Overview

At 06:23 AM on April 15, 2026, employees at wiresharkworkshop.online discovered their files had been encrypted overnight. Desktop wallpapers had been replaced with a ransom note demanding 2.5 Bitcoin. Four systems were affected including the primary file server. The SOC was engaged to lead the incident response investigation.

---

## Affected Systems

| Hostname | Role | OS | Impact |
|----------|------|----|--------|
| FS-PROD-01 | File server | Windows Server 2019 | Shared drives fully encrypted |
| WS-DANIEL-01 | Workstation | Windows 11 | HR documents encrypted |
| WS-FINANCE-01 | Workstation | Windows 11 | Finance spreadsheets encrypted |
| WS-OPS-01 | Workstation | Windows 11 | Operations project files encrypted |

---

## Attack Timeline

| Time | Event |
|------|-------|
| April 14 — 11:47 PM | Phishing email received by daniel.asante@wiresharkworkshop.online |
| April 14 — 11:52 PM | daniel.asante opened Invoice_Q1_2026.docx |
| April 14 — 11:52 PM | winword.exe spawned powershell.exe — macro execution confirmed |
| April 14 — 11:53 PM | PowerShell downloaded stage2.exe from 185.220.101.45 |
| April 14 — 11:53 PM | Cobalt Strike beacon established to 91.240.118.172:443 |
| April 15 — 01:14 AM | Lateral movement to FS-PROD-01 via stolen credentials |
| April 15 — 01:22 AM | Shadow copies deleted: vssadmin delete shadows /all /quiet |
| April 15 — 01:31 AM | Ransomware deployed to WS-FINANCE-01, WS-OPS-01, WS-DANIEL-01 |
| April 15 — 02:47 AM | Encryption complete — ransom note dropped on all systems |
| April 15 — 06:23 AM | Incident discovered by staff arriving for work |

**Total attacker dwell time before encryption: 89 minutes**  
**Total time from initial access to discovery: approximately 6.5 hours**

---

## Initial Infection Vector

The attack began with a phishing email containing a malicious Word document attachment (`Invoice_Q1_2026.docx`). The document contained a macro that executed automatically when Daniel opened it. The macro spawned PowerShell (`winword.exe → powershell.exe`) — a parent-child process relationship that should never occur legitimately — and downloaded the Cobalt Strike beacon payload from the attacker's delivery infrastructure.

The key forensic indicator is `winword.exe spawning powershell.exe`. Microsoft Word has no legitimate reason to launch PowerShell. This single event ID 4688 entry is enough to confirm macro-based malware execution and trigger an immediate escalation.

---

## Critical Finding: Shadow Copy Deletion

At 01:22 AM — before deploying ransomware — the attacker executed:

```
vssadmin delete shadows /all /quiet
```

This command deleted all Windows Volume Shadow Copies — the operating system's built-in backup snapshots. This was a deliberate preparation step to eliminate the free recovery option before encryption began. Without shadow copies, victims cannot use Windows Previous Versions to restore encrypted files without paying the ransom or restoring from external backup.

This technique is MITRE ATT&CK T1490 (Inhibit System Recovery) and is used by virtually every major ransomware group.

---

## Threat Actor Attribution

The delivery IP (185.220.101.45) and C2 IP (91.240.118.172) are identical to infrastructure identified across multiple previous incidents in this environment:

| Prior Incident | IP Involved | Date |
|---------------|-------------|------|
| SSH brute-force campaign | 185.220.101.45 | April 1, 2026 |
| VirusTotal analysis — 17 engine detections | 185.220.101.45 | April 8, 2026 |
| Phishing compromise of WS-SARAH-01 | 91.240.118.172 | April 11, 2026 |
| Malware C2 PCAP analysis | 91.240.118.172 | April 9, 2026 |

This infrastructure reuse confirms this ransomware attack is part of an ongoing targeted campaign against wiresharkworkshop.online by the same threat actor — not an opportunistic or random attack. The organisation has been under active targeting since at least April 1, 2026.

---

## Off-Hours Attack Pattern

The attacker chose to execute their most destructive actions between midnight and 3 AM — a deliberate tactic. SOC staffing is typically reduced overnight, automated alerts are less likely to be actioned quickly, and business hours monitoring tools may generate fewer baseline alerts to mask malicious activity. This is a well-documented ransomware operator technique, not a misconfiguration on the organisation's part. It highlights the need for 24/7 alert escalation coverage or an after-hours managed detection and response service.

---

## Analyst Recommendations

### Should the Organisation Pay the Ransom?

**Recommendation: Do not pay.**

Studies consistently show that a significant proportion of organisations that pay the ransom receive a broken decryptor, never receive the decryption key, or are re-attacked within months — having been identified as willing payers. Payment also directly funds future attacks against this and other organisations, and provides no guarantee of data recovery. The correct recovery path is restoring from clean offline backups combined with a full forensic investigation.

### Should Law Enforcement Be Contacted?

**Recommendation: Yes — immediately.**

Ransomware is a criminal act. Law enforcement must be notified regardless of whether the organisation intends to pay. Benefits include: law enforcement agencies may have decryption keys from previous takedowns of the same group, the Bitcoin wallet can be tracked and potentially frozen, and reporting creates a legal record that may be required for cyber insurance claims and regulatory compliance.

---

## Immediate Containment Actions

Priority ordered response steps:

1. Isolate all four affected systems from the network immediately to stop any active encryption and prevent further spread
2. Verify backup integrity — confirm offline backups exist, are clean, and have not been encrypted or deleted
3. Preserve forensic evidence — acquire memory images and disk images from all affected systems before any remediation
4. Reset all credentials across the environment — the attacker used stolen credentials for lateral movement and may have harvested additional passwords
5. Block all identified IOC IPs and domains at the firewall and DNS resolver: 185.220.101.45, 91.240.118.172, recover@darkmail.xyz
6. Notify law enforcement and engage legal counsel
7. Search all other endpoints for stage2.exe, Cobalt Strike indicators, and the .locked file extension
8. Engage senior management and communications team — staff, customers, and regulators may need to be notified depending on data affected

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Evidence |
|-------------|------|---------|
| T1566.001 | Phishing: Spearphishing Attachment | Malicious Word document via email |
| T1059.001 | PowerShell | winword.exe spawned powershell.exe |
| T1105 | Ingress Tool Transfer | stage2.exe downloaded from C2 |
| T1071.001 | Application Layer Protocol | Cobalt Strike C2 over HTTPS |
| T1078 | Valid Accounts | Lateral movement via stolen credentials |
| T1490 | Inhibit System Recovery | vssadmin delete shadows /all /quiet |
| T1486 | Data Encrypted for Impact | Ransomware encryption of all files |
| T1491.001 | Defacement: Internal Defacement | Desktop wallpaper replaced with ransom note |

---

## Long-Term Defensive Recommendations

1. Disable macro execution in Microsoft Office via Group Policy across all endpoints — the initial infection relied entirely on a Word macro
2. Deploy EDR on all endpoints to detect and block winword.exe spawning PowerShell in real time
3. Implement MFA on all accounts to prevent lateral movement using stolen credentials
4. Enforce the 3-2-1 backup rule: 3 copies, 2 different media types, 1 stored offline — offline backups cannot be encrypted by ransomware
5. Implement network segmentation so compromised workstations cannot directly access file servers without authentication
6. Conduct regular phishing awareness training — the initial vector was social engineering and human error
7. Establish 24/7 alert escalation for critical alerts — the attacker had 89 minutes of undetected access specifically because the attack occurred overnight
8. Implement privileged access management to limit which accounts can access file servers and delete shadow copies

---

## Indicators of Compromise

| Type | Value | Classification |
|------|-------|---------------|
| IP | 185.220.101.45 | Phishing delivery and known attacker IP |
| IP | 91.240.118.172 | Cobalt Strike C2 server |
| File | Invoice_Q1_2026.docx | Malicious Word document dropper |
| File | stage2.exe | Cobalt Strike beacon payload |
| Email | recover@darkmail.xyz | Ransom contact |
| Bitcoin | 1A2B3C4D5E6F7G8H9I0J | Ransom payment wallet |
| Extension | .locked | Encrypted file extension |
| Reference | RNS-2026-0415-WW | Ransomware group reference ID |

---

## Skills Demonstrated

- Full incident response report writing
- Ransomware attack chain reconstruction
- Threat actor attribution through infrastructure reuse
- Shadow copy deletion forensics (T1490)
- Cobalt Strike beacon identification
- Ransom payment analysis and recommendation
- MITRE ATT&CK mapping (8 techniques)
- Long-term defensive improvement planning

---

## Files in This Repository

```
day-15-ransomware-ir-report/
├── README.md     
└── report.pdf    
```

---

*Part of the 30 Days of Cybersecurity portfolio project.*

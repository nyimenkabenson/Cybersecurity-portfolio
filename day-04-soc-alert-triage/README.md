# Day 4 — SOC Alert Triage: Classify 10 Sample Alerts

**Portfolio:** 30 Days of Cybersecurity | Blue Team Track
**Date:** April 4, 2026
**Tools:** Analyst judgement, MITRE ATT&CK framework
**Difficulty:** Intermediate
**Format:** SOC Operations / Alert Triage

---

## Objective

Simulate a real SOC analyst triage workflow by classifying 10 sample security alerts as True Positive (TP), False Positive (FP), or TP — Escalate. This exercise develops the critical thinking skills needed to prioritise threats, reduce alert fatigue, and make fast, accurate decisions under pressure.

---

## Triage Classification Key

| Classification | Meaning |
|---------------|---------|
| **True Positive (TP)** | Real threat confirmed — log and action |
| **True Positive — Escalate** | Real threat requiring immediate escalation |
| **False Positive (FP)** | Alert fired but activity is benign — close ticket |
| **False Negative (FN)** | Real attack that generated NO alert — missed by system |

> **Key distinction:** A False Positive means the alert fired but it is benign. A False Negative means a real attack happened but no alert fired at all — it is a detection gap, not an alert classification.

---

## Alert Triage Results

### Alert 1 — SSH Brute Force
**Alert:** 47 failed SSH login attempts in 60 seconds from IP 185.220.101.45 targeting `root` on prod-server-01.
**Classification:** ✅ TP — Escalate
**Reasoning:** 47 failures in 60 seconds from a known Tor exit node targeting the root account is a textbook brute-force attack. Block IP immediately and escalate to Tier 2.
**MITRE ATT&CK:** T1110.001 — Brute Force: Password Guessing

---

### Alert 2 — Antivirus Detection
**Alert:** AV detected `eicar.com.txt` on workstation WS-042. File quarantined automatically.
**Classification:** ✅ TP (No escalation)
**Reasoning:** EICAR is a harmless antivirus test file used by IT teams to verify AV functionality. Quarantine was automatic. Log the ticket and confirm with IT whether it was a planned test.

---

### Alert 3 — Off-Hours Login
**Alert:** User `jsmith` logged in at 2:14 AM from IP 192.168.1.10 — same IP and user as previous logins.
**Classification:** ⚠️ FP (with follow-up recommended)
**Reasoning:** Same IP, same user — no credential anomaly. However, 2 AM login is outside normal working hours and warrants a quick check with the user to confirm legitimacy.

---

### Alert 4 — Large Data Upload
**Alert:** 500MB upload to `dropbox.com` from finance workstation FIN-003 at 4:45 PM on a Tuesday.
**Classification:** ⚠️ FP (contextually benign)
**Reasoning:** Business hours, finance workstation, cloud storage upload — consistent with end-of-day file backup or report sharing. Log and monitor for repeat behaviour or uploads to unknown destinations.

---

### Alert 5 — Encoded PowerShell Execution
**Alert:** PowerShell execution on EP-017: `powershell.exe -EncodedCommand <base64 string>`
**Classification:** 🔴 TP — Escalate immediately
**Reasoning:** Encoded PowerShell is one of the most common attacker techniques for hiding malicious commands from plain-text log inspection. The `-EncodedCommand` flag base64-encodes the payload to evade detection. Always decode and inspect — never dismiss.
**MITRE ATT&CK:** T1059.001 — Command and Scripting Interpreter: PowerShell

**How to decode:**
```python
import base64
decoded = base64.b64decode("<base64string>").decode("utf-16-le")
print(decoded)
```

---

### Alert 6 — Internal Port Scan
**Alert:** 1,024 ports probed on internal network from IP 10.0.0.99 in 30 seconds.
**Classification:** ✅ TP — Escalate
**Reasoning:** Internal reconnaissance is more alarming than external scanning. A compromised internal machine or malicious insider scanning for open ports indicates active lateral movement or pre-attack enumeration. Isolate 10.0.0.99 immediately.
**MITRE ATT&CK:** T1046 — Network Service Discovery

---

### Alert 7 — Mass DNS Queries to Microsoft
**Alert:** DNS query to `update.microsoft.com` from 14 workstations between 9–10 AM.
**Classification:** ✅ FP
**Reasoning:** Bulk DNS queries to Microsoft update servers during business hours from multiple workstations is normal Windows Update behaviour. No action required.

---

### Alert 8 — Midnight Domain Controller Login
**Alert:** User `admin` logged into domain controller at 11:58 PM from an unrecognised device.
**Classification:** 🔴 TP — Escalate immediately
**Reasoning:** Domain controllers are crown jewels. Any anomalous access — especially at midnight from an unknown device using the admin account — must be treated as a critical incident. Could indicate credential theft or an active intrusion in progress.
**MITRE ATT&CK:** T1078 — Valid Accounts

---

### Alert 9 — Outbound Connection on Port 4444
**Alert:** Outbound connection from EP-023 to IP `91.240.118.172` on port 4444.
**Classification:** 🔴 TP — Escalate immediately
**Reasoning:** Port 4444 is the default listener port for Metasploit reverse shells. An outbound connection to a known suspicious IP on this port is a strong indicator of an active Command and Control (C2) connection. Isolate EP-023 and begin DFIR immediately.
**MITRE ATT&CK:** T1571 — Non-Standard Port / T1095 — Non-Application Layer Protocol

---

### Alert 10 — Malicious PDF Execution
**Alert:** `invoice_april2026.pdf` opened — `cmd.exe` spawned as child process of `AcroRd32.exe`.
**Classification:** 🔴 TP — Escalate immediately
**Reasoning:** cmd.exe spawning as a child process of Adobe Reader is a classic malicious PDF exploit. The document executed code that launched a command shell — indicating the endpoint is actively compromised. Isolate immediately, preserve memory, begin full DFIR investigation.
**MITRE ATT&CK:** T1566.001 — Phishing: Spearphishing Attachment

---

## Triage Summary

| Alert | Classification | Severity |
|-------|---------------|----------|
| 1 — SSH brute force | TP — Escalate | High |
| 2 — EICAR AV detection | TP | Low |
| 3 — Off-hours login | FP (follow-up) | Low |
| 4 — Large data upload | FP (contextual) | Low |
| 5 — Encoded PowerShell | TP — Escalate | Critical |
| 6 — Internal port scan | TP — Escalate | High |
| 7 — Microsoft DNS queries | FP | Info |
| 8 — DC midnight login | TP — Escalate | Critical |
| 9 — Port 4444 C2 connection | TP — Escalate | Critical |
| 10 — Malicious PDF | TP — Escalate | Critical |

**Critical escalations: 4 | High: 2 | Low/Info: 4**

---

## Key Lessons

1. **Encoded PowerShell is never benign** — always decode and inspect before closing
2. **Internal scanning is more dangerous than external** — it suggests a compromised host
3. **Child process anomalies reveal exploitation** — cmd.exe under AcroRd32.exe is never legitimate
4. **Context matters for FP decisions** — time of day, user history, and destination all inform triage
5. **False Positive ≠ False Negative** — FP means alert fired but benign; FN means attack happened but no alert fired

---

## MITRE ATT&CK Techniques Covered

| Technique ID | Name | Alert |
|-------------|------|-------|
| T1110.001 | Brute Force: Password Guessing | Alert 1 |
| T1059.001 | PowerShell Execution | Alert 5 |
| T1046 | Network Service Discovery | Alert 6 |
| T1078 | Valid Accounts | Alert 8 |
| T1571 | Non-Standard Port | Alert 9 |
| T1566.001 | Spearphishing Attachment | Alert 10 |

---

## Files in This Repository

```
day-04-soc-alert-triage/
├── README.md       ← This file
└── report.pdf      ← Full analyst report
```

---

*Part of the [30 Days of Cybersecurity](../README.md) portfolio project.*

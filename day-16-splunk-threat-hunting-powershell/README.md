# Day 16: Splunk Threat Hunting — MITRE ATT&CK T1059 PowerShell

**Portfolio:** 30 Days of Cybersecurity | Blue Team Track  
**Date:** April 16, 2026  
**Tools:** Splunk Enterprise, SPL  
**MITRE Technique:** T1059.001 — Command and Scripting Interpreter: PowerShell  
**Difficulty:** Intermediate  
**Format:** SIEM Threat Hunting  

---

## Objective

Proactively hunt for PowerShell abuse across endpoint logs using Splunk SPL, identifying MITRE ATT&CK T1059.001 patterns including encoded commands, download cradles, policy bypasses, and suspicious parent process relationships. Threat hunting differs from alerting — instead of waiting for a rule to fire, the analyst goes looking for attacker behaviour patterns already present in the environment.

---

## Dataset

A simulated Windows Event ID 4688 (process creation) log was generated containing 100 PowerShell execution events across 5 hosts and a business-hours timeframe.

| Category | Count |
|----------|-------|
| Legitimate PowerShell events | 60 |
| Malicious PowerShell events | 40 |
| Total events | 100 |

Hosts covered: WS-SARAH-01, WS-DANIEL-01, WS-FINANCE-01, WS-OPS-01, FS-PROD-01

---

## Hunt Queries and Results

### Hunt Query 1: Encoded Command Detection (T1059.001)

```spl
index=main "EventID=4688" "powershell.exe"
| rex field=_raw "CommandLine=\"(?<cmdline>[^\"]+)\""
| where like(cmdline, "%-enc%") OR like(cmdline, "%-EncodedCommand%")
| rex field=_raw "User=(?<user>\S+)"
| rex field=_raw "(?<hostname>\S+)\sEventID"
| table _time, hostname, user, cmdline
| sort _time
```

**Results: 20 encoded command events**

Both `daniel.asante` and `sarah.kwame` ran encoded PowerShell commands across WS-SARAH-01 and WS-DANIEL-01. The `-EncodedCommand` and `-enc` flags base64-encode the actual payload to hide malicious commands from security tools scanning for suspicious plaintext strings. This is one of the most reliable T1059.001 indicators in the wild.

---

### Hunt Query 2: All PowerShell Executions by Host and Parent

```spl
index=main "EventID=4688" "powershell.exe"
| rex field=_raw "(?<hostname>\S+)\sEventID"
| rex field=_raw "User=(?<user>\S+)"
| rex field=_raw "ParentProcess=(?<parent>\S+)"
| stats count by hostname, user, parent
| sort -count
```

**Results: 63 unique host/user/parent combinations**

PowerShell activity was found across all 5 hosts including FS-PROD-01 (the file server), confirming lateral movement has occurred. The spread across the entire environment indicates the threat actor has significant foothold across the organisation.

---

### Hunt Query 3: Suspicious Parent Process Detection

```spl
index=main "EventID=4688" "powershell.exe"
| rex field=_raw "ParentProcess=(?<parent>\S+)"
| rex field=_raw "User=(?<user>\S+)"
| rex field=_raw "(?<hostname>\S+)\sEventID"
| where parent="winword.exe" OR parent="excel.exe" OR parent="chrome.exe" 
    OR parent="invoice_setup.exe" OR parent="svchost32.exe"
| stats count by parent, user, hostname
| sort -count
```

**Results: 22 suspicious parent process events**

| Parent Process | Significance |
|---------------|-------------|
| invoice_setup.exe | Known malware dropper from Day 15 ransomware investigation |
| winword.exe | Word spawning PowerShell — macro execution confirmed |
| excel.exe | Excel spawning PowerShell — macro execution confirmed |
| chrome.exe | Browser spawning PowerShell — drive-by or malicious download |
| svchost32.exe | Known persistent malware binary — still active on WS-DANIEL-01 |

None of these parent-child relationships are legitimate. Office applications, browsers, and malware binaries have no legitimate reason to spawn PowerShell.

---

### Hunt Query 4: Download Cradle Detection

```spl
index=main "EventID=4688" "powershell.exe"
| rex field=_raw "CommandLine=\"(?<cmdline>[^\"]+)\""
| where like(cmdline, "%WebClient%") OR like(cmdline, "%DownloadString%") 
    OR like(cmdline, "%DownloadFile%") OR like(cmdline, "%Invoke-WebRequest%") 
    OR like(cmdline, "%IEX%")
| rex field=_raw "User=(?<user>\S+)"
| rex field=_raw "(?<hostname>\S+)\sEventID"
| table _time, hostname, user, cmdline
| sort _time
```

**Results: 14 download cradle events**

Active downloads confirmed to known attacker infrastructure:

| Command | Destination | File |
|---------|-------------|------|
| Invoke-WebRequest | 91.240.118.172 | payload.ps1 → svchost32.exe |
| New-Object WebClient DownloadFile | 185.220.101.45 | rat.exe → C:\Temp\rat.exe |
| -WindowStyle Hidden IEX DownloadString | 185.220.101.45 | stage2.ps1 |

Both 91.240.118.172 and 185.220.101.45 are confirmed attacker IPs from the ongoing campaign identified across Days 1 through 15 of this portfolio.

---

### Hunt Query 5: Full Suspicious PowerShell Classification

```spl
index=main "EventID=4688" "powershell.exe"
| rex field=_raw "CommandLine=\"(?<cmdline>[^\"]+)\""
| rex field=_raw "ParentProcess=(?<parent>\S+)"
| eval suspicious=case(
    like(cmdline,"%-enc%") OR like(cmdline,"%-EncodedCommand%"), "Encoded command",
    like(cmdline,"%WebClient%") OR like(cmdline,"%DownloadString%") OR like(cmdline,"%IEX%") 
        OR like(cmdline,"%Invoke-WebRequest%"), "Download cradle",
    like(cmdline,"%-WindowStyle Hidden%") OR like(cmdline,"%-w hidden%"), "Hidden window",
    like(cmdline,"%-ExecutionPolicy Bypass%") OR like(cmdline,"%-nop%"), "Policy bypass",
    parent="winword.exe" OR parent="excel.exe" OR parent="chrome.exe" 
        OR parent="invoice_setup.exe", "Suspicious parent",
    true(), "Legitimate"
)
| stats count by suspicious
| sort -count
```

**Results: Full classification breakdown**

| Classification | Count | Percentage |
|---------------|-------|-----------|
| Legitimate | 60 | 60% |
| Encoded command | 20 | 20% |
| Download cradle | 14 | 14% |
| Policy bypass | 6 | 6% |

The hunt queries identified 100% of the 40 malicious events across three distinct T1059.001 sub-techniques.

---

## Key Hunt Findings

### Finding 1: Active Download Cradles to Known Attacker IPs
The threat actor is actively pulling payloads from 91.240.118.172 and 185.220.101.45 — the same infrastructure used in every previous incident in this environment. The ransomware delivered on Day 15 did not end the campaign — the attacker still has active footholds.

### Finding 2: svchost32.exe Still Active
The persistent malware binary from the Day 15 ransomware attack is still spawning PowerShell on WS-DANIEL-01, confirming the host was not fully remediated after the ransomware incident.

### Finding 3: Campaign Spread Across All Hosts
PowerShell abuse was found on all 5 hosts including the file server, indicating the threat actor has spread beyond the initially compromised endpoints. Full environment remediation is required.

### Finding 4: Three Distinct Evasion Techniques
The attacker used encoded commands (T1059.001), download cradles (T1105), and execution policy bypass (T1562.001) simultaneously — demonstrating a sophisticated, layered evasion approach.

---

## T1059.001 Sub-Techniques Identified

| Technique | Indicator | Example |
|-----------|-----------|---------|
| Encoded command | -enc or -EncodedCommand flag | powershell.exe -enc UABvAHcA... |
| Download cradle | Invoke-WebRequest, WebClient, IEX | IEX (New-Object Net.WebClient).DownloadString(...) |
| Execution policy bypass | -ExecutionPolicy Bypass or -nop | powershell.exe -nop -noni -w hidden |
| Hidden window | -WindowStyle Hidden or -w hidden | powershell.exe -WindowStyle Hidden |
| Suspicious parent | Office apps or malware spawning PowerShell | winword.exe → powershell.exe |

---

## Defensive Recommendations

1. Enable PowerShell Script Block Logging (Event ID 4104) — this logs the decoded content of encoded commands, removing the evasion benefit of base64 encoding
2. Enable PowerShell Transcription Logging — records every command and output to a text file for forensic analysis
3. Constrained Language Mode — restricts PowerShell capabilities to prevent download cradles and arbitrary code execution
4. Alert on Office applications spawning PowerShell — winword.exe or excel.exe as a parent of powershell.exe is never legitimate
5. Block outbound connections from PowerShell to known malicious IPs at the firewall — the download cradles in this hunt all connected to previously identified attacker IPs

---

## Skills Demonstrated

- Proactive threat hunting methodology in Splunk
- SPL eval classification for multi-category detection
- T1059.001 pattern recognition (encoded, download cradle, policy bypass, hidden window)
- Suspicious parent-child process relationship detection
- Hunt finding correlation with prior incident investigations
- MITRE ATT&CK technique mapping and sub-technique identification

---

## Files in This Repository

```
day-16-splunk-threat-hunting-powershell/
├── README.md              
├── powershell_logs.log    
└── report.pdf             
```

---

*Part of the 30 Days of Cybersecurity portfolio project.*

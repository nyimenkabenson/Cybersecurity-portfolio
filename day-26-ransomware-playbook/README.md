# Day 26: SOC Threat Detection Playbook — Ransomware

**Portfolio:** 30 Days of Cybersecurity | Blue Team Track  
**Date:** April 26, 2026  
**Tools:** Analyst documentation, MITRE ATT&CK framework  
**Difficulty:** Intermediate  
**Format:** SOC Playbook / Incident Response Procedure  

---

## Overview

This playbook defines the step-by-step procedure a SOC analyst follows when a ransomware alert fires. It covers trigger conditions, triage steps, containment, investigation, eradication, recovery, and post-incident review. This playbook was developed from direct experience investigating the ransomware campaign tracked across this portfolio.

---

## Playbook Metadata

| Field | Value |
|-------|-------|
| Playbook name | Ransomware Detection and Response |
| Version | 1.0 |
| Created | April 26, 2026 |
| Review cycle | Quarterly |
| Severity | Critical |
| Target audience | SOC Tier 1 and Tier 2 analysts |
| Escalation | Tier 2 DFIR within 15 minutes of confirmation |

---

## Phase 1: Trigger Conditions

This playbook activates when any of the following alerts fire:

| Alert | Threshold | Source |
|-------|-----------|--------|
| Mass file extension change | More than 50 files with unknown extension in 5 minutes | EDR or file server logs |
| vssadmin delete shadows | Any execution | Windows Event ID 4688 |
| Ransom note file creation | README.txt, DECRYPT.txt, or similar dropped to multiple directories | EDR |
| Encryption process detected | High CPU with sequential file write pattern | EDR behavioural |
| Known ransomware hash | File hash matches threat intelligence feed | AV or EDR |
| C2 connection to known ransomware IP | Outbound connection to flagged IP on non-standard port | Firewall or SIEM |

---

## Phase 2: Initial Triage — First 15 Minutes

### Step 1 — Confirm the alert is not a false positive (2 minutes)

Check whether the triggering activity could be legitimate:

- Mass file renaming could be a legitimate backup or encryption tool run by IT
- vssadmin usage could be a legitimate backup software
- Contact the IT team immediately if there is any doubt

If the activity cannot be explained by a legitimate business process, proceed immediately.

### Step 2 — Identify the scope (5 minutes)

Run these SIEM queries to determine how many systems are affected:

```spl
index=main "vssadmin delete shadows"
| rex field=_raw "(?<hostname>\S+)\s"
| stats count by hostname
```

```spl
index=main EventID=4688
| rex field=_raw "Process=(?<process>\S+)"
| where like(process, "%.locked%") OR like(process, "%encrypt%") OR like(process, "%ransom%")
| stats count by hostname, process
```

### Step 3 — Assess the blast radius (3 minutes)

Determine:
- How many endpoints are showing ransomware indicators
- Is the file server affected
- Are backups accessible and potentially encrypted
- Is the attack still in progress or complete

### Step 4 — Classify severity

| Condition | Severity |
|-----------|---------|
| Single workstation, no server access, backups intact | High |
| Multiple workstations, server access, backups intact | Critical |
| Multiple workstations, server access, backups encrypted | Critical — Major Incident |

---

## Phase 3: Containment — Stop the Spread

**Time target: within 20 minutes of alert**

### Step 1 — Isolate affected endpoints

For each affected machine, immediately remove from the network:
- Apply firewall block rule for all traffic to and from the affected IP
- Disable the machine's network adapter via EDR if available
- Physically disconnect if remote isolation is not possible

Do NOT shut down the machine — memory contains forensic evidence including encryption keys.

### Step 2 — Isolate shared storage

- Take shared drives offline immediately
- Apply read-only access to all network shares
- Block SMB (port 445) from affected endpoints at the firewall

### Step 3 — Block attacker infrastructure

Add the following to firewall blocklist and DNS sinkhole:
- All source IPs identified in the initial triage
- All domains identified in DNS logs from affected machines
- Known ransomware C2 ranges from threat intelligence feeds

### Step 4 — Protect backups

- Verify backup systems are online and unaffected
- Take backup infrastructure offline or into read-only mode
- Confirm the most recent clean backup timestamp

---

## Phase 4: Investigation — Understand the Scope

**Escalate to Tier 2 DFIR — this phase requires advanced forensics**

### Step 1 — Identify patient zero

Find the first affected machine using earliest encryption timestamp:

```spl
index=main "vssadmin delete shadows" OR "ransom" OR ".locked"
| rex field=_raw "(?<hostname>\S+)\s"
| stats min(_time) as first_seen by hostname
| sort first_seen
| head 1
```

### Step 2 — Reconstruct the initial access vector

Check email logs for phishing emails received before the first alert. Look for:
- SPF/DKIM/DMARC failures
- Attachments with executable content
- Links to newly registered domains or unusual TLDs

### Step 3 — Map the execution chain

Pull Event ID 4688 logs from patient zero for the 2 hours before encryption:

```spl
index=main EventID=4688 hostname=PATIENT_ZERO_HOSTNAME
| rex field=_raw "Process=(?<process>\S+)"
| rex field=_raw "ParentProcess=(?<parent>\S+)"
| table _time, process, parent
| sort _time
```

Look for: office apps spawning PowerShell, encoded commands, processes dropped to Temp folder.

### Step 4 — Identify persistence mechanisms

Check for registry Run keys, scheduled tasks, and services created by the malware:

```spl
index=main (EventID=4657 OR EventID=4698 OR EventID=7045)
| rex field=_raw "(?<hostname>\S+)\s"
| table _time, hostname, _raw
| sort _time
```

### Step 5 — Check for data exfiltration

Review outbound traffic volumes in the 2 hours before encryption:

```spl
index=main EventID=5156
| rex field=_raw "dst=(?<dst>\S+)"
| rex field=_raw "bytes=(?<bytes>\d+)"
| stats sum(bytes) as total_bytes by dst
| where total_bytes > 10000000
| sort -total_bytes
```

Any destination receiving more than 10 MB before the encryption event warrants immediate investigation — double extortion must be assumed until ruled out.

---

## Phase 5: Eradication — Remove the Threat

**Do not begin eradication until forensic preservation is complete**

### Step 1 — Preserve forensic evidence

Before touching any affected system:
- Acquire memory image from all affected machines
- Acquire disk image from all affected machines
- Export all relevant SIEM logs for the 48 hours before the incident

### Step 2 — Remove persistence mechanisms

On each affected machine:
- Delete registry Run keys created by the malware
- Remove scheduled tasks created by the malware
- Stop and remove any malicious services
- Delete malware binaries from Temp, AppData, and System32 folders

### Step 3 — Reset credentials

- Reset passwords for all accounts on affected machines
- Reset all service account passwords
- Revoke and reissue any API keys or certificates that were accessible on affected machines
- Enable or enforce MFA on all accounts

### Step 4 — Patch and harden

- Apply all outstanding security patches to affected machines before restoration
- Disable macro execution in Microsoft Office via Group Policy
- Deploy or update EDR signatures with indicators from this incident

---

## Phase 6: Recovery — Restore Operations

**Only begin recovery after eradication is confirmed complete**

### Step 1 — Determine recovery method

| Scenario | Recovery Method |
|----------|----------------|
| Clean backups available | Restore from backup |
| No clean backups, decryptor available | Apply decryptor |
| No clean backups, no decryptor | Rebuild from scratch |

### Step 2 — Restore from backup

- Restore to a clean isolated environment first to verify integrity
- Scan restored files with updated AV signatures before reconnecting to network
- Restore in priority order: critical servers first, then workstations

### Step 3 — Verify restoration

Before reconnecting any restored system:
- Confirm no malware indicators are present
- Verify all persistence mechanisms have been removed
- Test connectivity to critical services
- Confirm backup data integrity

### Step 4 — Reconnect in stages

- Reconnect one system at a time with monitoring active
- Watch for any immediate re-infection indicators
- Keep affected systems under enhanced monitoring for 30 days

---

## Phase 7: Post-Incident — Lessons Learned

**Complete within 5 business days of incident resolution**

### Mandatory review items

1. What was the initial access vector and how can it be prevented?
2. How long did the attacker have undetected access (dwell time)?
3. Which detection gaps allowed the attack to progress undetected?
4. Were backup systems adequate for recovery?
5. Did the response meet time targets defined in this playbook?

### Metrics to capture

| Metric | Definition |
|--------|-----------|
| Mean Time to Detect (MTTD) | Time from first malicious activity to SOC alert |
| Mean Time to Respond (MTTR) | Time from alert to containment |
| Dwell time | Time attacker had undetected access |
| Blast radius | Number of systems affected |
| Data loss | Volume of data exfiltrated or unrecoverable |

### Playbook improvement actions

- Add any new IOCs to detection rules
- Update firewall blocklists with identified attacker infrastructure
- Tune SIEM rules to reduce the dwell time identified
- Update this playbook with any gaps identified during the response

---

## Ransomware-Specific Decision Tree

```
Alert fires
    ↓
Can activity be explained by legitimate IT process?
    YES → False Positive → Close ticket → Tune rule
    NO  ↓
Is encryption actively in progress?
    YES → Immediate network isolation of affected machines
    NO  ↓
Is vssadmin or ransom note the trigger?
    YES → Treat as active ransomware → Begin containment
    NO  ↓
Is this a C2 connection to known ransomware IP?
    YES → Isolate endpoint → Check for lateral movement
    NO  → Escalate to Tier 2 for further investigation
```

---

## Do Not Pay Guidance

The SOC must never recommend ransom payment without senior management and legal approval. Key considerations:

- Payment does not guarantee decryption
- Payment funds future attacks against this and other organisations
- Payment may violate sanctions regulations if attacker is on a government sanctions list
- Law enforcement must be notified regardless of payment decision
- Clean backups are always the preferred recovery path

---

## Key Lessons from the April 2026 Campaign

This playbook was developed from the 25-day ransomware campaign investigated in this portfolio. The following gaps were identified:

1. **47-minute dwell time before SOC alert** — vssadmin execution should have triggered an immediate alert but was not monitored
2. **Incomplete remediation after prior incidents** — the same attacker infrastructure was present across 7 incidents without full eradication
3. **No 24/7 SOC coverage** — attacks consistently occurred overnight and off-hours
4. **Missing MFA** — stolen credentials enabled lateral movement that MFA would have prevented
5. **No offline backups** — shadow copies were deleted as a precursor to ransomware

---

## Skills Demonstrated

- SOC playbook development from first principles
- Phase-based incident response structure (SANS framework)
- SIEM query integration within playbook steps
- Ransomware-specific decision tree design
- Metric definition for incident measurement
- Real-world lessons learned documentation

---

## Files in This Repository

```
day-26-ransomware-playbook/
├── README.md     
└── report.pdf    
```

---

*Part of the 30 Days of Cybersecurity portfolio project.*

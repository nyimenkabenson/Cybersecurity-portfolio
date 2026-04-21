# Day 18: TryHackMe — DFIR: An Introduction Room Write-Up

**Portfolio:** 30 Days of Cybersecurity | Blue Team Track  
**Date:** April 18, 2026  
**Platform:** TryHackMe  
**Room:** DFIR: An Introduction  
**Tools:** TryHackMe browser-based lab  
**Difficulty:** Easy  
**Format:** CTF Write-Up / DFIR Theory  

---

## Room Overview

The DFIR: An Introduction room on TryHackMe covers the foundational concepts of Digital Forensics and Incident Response — what DFIR is, why it matters, how evidence is collected and preserved, and how the incident response lifecycle works. The room concludes with a timeline creation exercise and an overview of industry-standard DFIR tools.

---

## Theory Notes

### What is DFIR?

Digital Forensics and Incident Response (DFIR) is the practice of collecting forensic artefacts from digital devices to investigate security incidents. It combines two complementary disciplines:

- **Digital Forensics** — the science of collecting, preserving, and analysing digital evidence
- **Incident Response** — the structured process of detecting, containing, eradicating, and recovering from security incidents

The two fields are interdependent. Digital forensics relies on incident response to provide context for the investigation, and incident response relies on digital forensics to understand what happened, how far the attacker reached, and what evidence to preserve.

### Forensic Artefacts

Forensic artefacts are the digital footprints left behind by attackers during an intrusion. DFIR analysts collect and analyse these artefacts to reconstruct the attack chain, identify persistence mechanisms, and attribute the activity to a threat actor.

Examples of forensic artefacts include: Windows Event Logs, registry keys, prefetch files, browser history, network connection logs, and memory dumps.

### Evidence Preservation and Chain of Custody

When evidence is collected, two critical principles apply:

**Preservation:** A forensic copy should be made for analysis. The original evidence must remain untouched and unmodified — even a single write operation to the original can invalidate it in a legal context.

**Chain of custody:** Evidence must remain in the possession of authorised individuals throughout the investigation. If someone outside the chain of custody handles the evidence, its integrity can be legally challenged, potentially making the entire investigation inadmissible.

### Data Volatility

Not all digital evidence lasts equally long. Volatility refers to how quickly data disappears if not captured immediately.

| Storage Type | Volatility | Notes |
|-------------|-----------|-------|
| RAM | High | Lost immediately on power off — must be captured while system is live |
| Hard disk | Low | Persists after power off — can be imaged later |

This is why memory acquisition is always the first step in live DFIR — RAM contains running processes, network connections, encryption keys, and attacker tools that will be lost the moment the machine is powered down.

### Timeline Creation

Timeline creation provides chronological perspective to a DFIR investigation. By ordering all artefacts — file creation times, registry modifications, event log entries, network connections — analysts can reconstruct exactly what happened, when, and in what sequence. Without a timeline, it is impossible to understand the full scope of an attack.

---

## DFIR Tools Covered

| Tool | Category | Primary Use |
|------|----------|------------|
| KAPE | Artefact collection | Fast triage — collects forensic artefacts from live or dead systems |
| Autopsy | Disk forensics | Full disk image analysis — file recovery, timeline, keyword search |
| Volatility | Memory forensics | RAM analysis — running processes, network connections, injected code |
| Velociraptor | Enterprise DFIR | Endpoint visibility and remote forensic collection at scale |
| Redline | Memory and triage | FireEye tool for host investigation and IOC scanning |

---

## Incident Response Lifecycle

### SANS Six-Step Process

| Step | Name | Description |
|------|------|-------------|
| 1 | Preparation | Building IR capability before an incident occurs |
| 2 | Identification | Detecting and confirming an incident has occurred |
| 3 | Containment | Isolating affected systems to prevent spread |
| 4 | Eradication | Evicting the threat from the network after forensic analysis |
| 5 | Recovery | Restoring disrupted services to their pre-incident state |
| 6 | Lessons Learned | Post-incident review to improve future response |

### SANS vs NIST Comparison

| SANS Step | NIST Equivalent |
|-----------|----------------|
| Preparation | Preparation |
| Identification | Detection and Analysis |
| Containment | Containment, Eradication, and Recovery |
| Eradication | Containment, Eradication, and Recovery |
| Recovery | Containment, Eradication, and Recovery |
| Lessons Learned | Post-incident Activity |

The key difference is that NIST combines Containment, Eradication, and Recovery into a single phase, while SANS treats them as three distinct steps. In practice, both frameworks guide the same actions — SANS simply provides more granularity.

---

## Room Questions and Answers

| Question | Answer |
|----------|--------|
| What does DFIR stand for? | Digital Forensics and Incident Response |
| DFIR requires expertise in two fields. One is Digital Forensics. What is the other? | Incident Response |
| From RAM and hard disk, which storage is more volatile? | RAM |
| What is the flag after completing the timeline creation exercise? | THM{DFIR_REPORT_DONE} |
| At what stage are disrupted services brought back online? | Recovery |
| At what stage is the threat evicted from the network? | Eradication |
| What is the NIST equivalent of "Lessons Learned"? | Post-incident Activity |

---

## Key Takeaways

1. DFIR combines Digital Forensics and Incident Response — neither field works effectively without the other
2. RAM is more volatile than disk storage — always capture memory first during live incident response
3. Evidence preservation and chain of custody are legal requirements — a tampered original can invalidate an entire investigation
4. Timeline creation is essential — without chronological ordering of artefacts, the attack scope cannot be understood
5. The SANS and NIST IR frameworks cover the same ground — SANS provides more step granularity while NIST consolidates into fewer phases
6. Eradication comes after forensic analysis — you must understand the full scope of compromise before evicting the attacker, otherwise you risk missing persistence mechanisms

---

## Portfolio Connection

The DFIR concepts covered in this room directly underpin several previous days of this portfolio:

| Concept | Applied In |
|---------|-----------|
| Memory volatility | Day 12 — Windows Event Log Analysis (preserve before reimage) |
| Timeline creation | Days 11, 12, 15 — Phishing, Event Log, and Ransomware investigations |
| Evidence preservation | Day 15 — Ransomware IR report (Step 2: preserve before remediation) |
| Eradication vs Recovery | Day 15 — Ransomware response priority ordering |
| Volatility tool | Day 21 — Memory forensics walkthrough (upcoming) |

---

## Skills Demonstrated

- TryHackMe room navigation and browser-based lab completion
- DFIR foundational knowledge — artefacts, volatility, chain of custody
- IR lifecycle understanding — SANS six-step and NIST four-phase frameworks
- DFIR toolset awareness — KAPE, Autopsy, Volatility, Velociraptor, Redline
- Timeline creation exercise completion
- Framework comparison (SANS vs NIST)

---

## Files in This Repository

```
day-18-tryhackme-dfir-introduction/
├── README.md     
└── report.pdf    
```

---

*Part of the 30 Days of Cybersecurity portfolio project.*

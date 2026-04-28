# Day 24: Blue Team Labs Online — Phishing Analysis Challenge Write-Up

**Portfolio:** 30 Days of Cybersecurity | Blue Team Track  
**Date:** April 24, 2026  
**Platform:** Blue Team Labs Online (BTLO)  
**Challenge:** Phishing Analysis  
**Difficulty:** Easy  
**Format:** CTF Write-Up / Email Forensics  

---

## Challenge Overview

The Phishing Analysis challenge on Blue Team Labs Online presents a real-world phishing email for forensic examination. The analyst must extract key artefacts from the email headers, identify the malicious attachment, locate the embedded URL, and investigate the hosted phishing page. This simulates the email triage workflow a SOC analyst performs when a user reports a suspicious email.

---

## Challenge Questions and Answers

| Question | Answer | Points |
|----------|--------|--------|
| Who is the primary recipient? | kinnar1975@yahoo.co.uk | 1 |
| What is the subject? | Undeliverable: Website contact form submission | 1 |
| Date and time sent? | 18 March 2021 04:14 | 1 |
| What is the originating IP? | 103.9.171.10 | 1 |
| Reverse DNS of originating IP? | c5s2-1e-syd.hosting-services.net.au | 1 |
| Name of attached file? | Website contact form submission.eml | 2 |
| URL found inside the attachment? | https://35000usdperwwekpodf.blogspot.sg/?p=9swg | 1 |
| What service hosts the webpage? | Blogspot | 1 |
| Heading text on the page (URL2PNG)? | Blog Has Been Removed | 1 |

**Total score: 10/10**

---

## Investigation Analysis

### Email Header Analysis

The email arrived at `kinnar1975@yahoo.co.uk` on 18 March 2021 at 04:14 with the subject "Undeliverable: Website contact form submission." The subject line is a social engineering technique — impersonating a legitimate website notification to create the impression that something requires the recipient's attention.

**Originating IP: 103.9.171.10**

Reverse DNS resolution via whois.domaintools.com identified the originating host as `c5s2-1e-syd.hosting-services.net.au` — an Australian hosting provider. This indicates the attacker used a rented or compromised hosting account in Australia as a sending relay, distancing the email origin from the actual threat actor and bypassing basic IP reputation filters focused on known bad regions.

### The Attachment Trick

The attachment is named `Website contact form submission.eml` — an email file format. This is a deliberate evasion technique. Rather than attaching a malicious executable or document, the attacker embedded a secondary email file containing the malicious URL. Many email security gateways and antivirus scanners focus on executable attachment types and do not deeply inspect nested .eml files, allowing the payload to pass through undetected.

### URL Analysis

The URL found inside the nested attachment was:
```
https://35000usdperwwekpodf.blogspot.sg/?p=9swg
```

This URL contains several notable indicators:

| Indicator | Value | Significance |
|-----------|-------|-------------|
| Domain name | 35000usdperwwekpodf | Financial lure — "35000 USD per week" |
| Hosting platform | Blogspot (Google) | Trusted domain evades URL reputation filters |
| TLD | .sg (Singapore) | Geographic obfuscation |
| Path parameter | ?p=9swg | Unique tracking token per victim |

**Why Blogspot?** Google's Blogspot is a trusted domain with high reputation scores across all URL filtering systems. By hosting the phishing page on Blogspot rather than a newly registered domain, the attacker significantly increases the chance the URL passes through corporate web filters and email security gateways.

### Page Status

URL2PNG confirmed the page heading reads "Blog Has Been Removed" — indicating Google took down the phishing blog after the campaign was reported. This is a standard outcome for Blogspot-hosted phishing campaigns: they operate briefly, collect credentials or deliver malware, and are then removed either by Google or through abuse reporting.

---

## Attack Chain Reconstruction

```
Step 1: Attacker sends spoofed "Undeliverable" notification email
Step 2: Victim receives email — subject creates urgency and legitimacy
Step 3: Victim opens attachment (nested .eml file — evades AV)
Step 4: Victim sees financial lure — "35000 USD per week" offer
Step 5: Victim clicks Blogspot URL (trusted domain — bypasses filters)
Step 6: Victim lands on phishing page — credential harvest or malware delivery
Step 7: Attacker collects harvested credentials or deploys payload
```

---

## Indicators of Compromise

| Type | Value | Classification |
|------|-------|---------------|
| Email recipient | kinnar1975@yahoo.co.uk | Victim |
| Originating IP | 103.9.171.10 | Sending relay |
| Originating host | c5s2-1e-syd.hosting-services.net.au | Australian hosting infrastructure |
| Attachment | Website contact form submission.eml | Malicious nested email |
| URL | https://35000usdperwwekpodf.blogspot.sg/?p=9swg | Phishing delivery URL |
| Platform | Blogspot | Trusted hosting abused for phishing |

---

## Key Lessons

1. **Nested .eml attachments bypass AV** — email security must be configured to inspect files within email attachments, not just the attachment itself
2. **Trusted domains are weaponised** — Blogspot, Google Drive, OneDrive, and GitHub are all abused by attackers because they carry high reputation scores
3. **Social engineering combines urgency and familiarity** — "Undeliverable form submission" sounds like something the recipient would expect and act on immediately
4. **Reverse DNS enriches IP context** — knowing the originating host is an Australian hosting provider tells investigators where to send abuse reports
5. **URL parameters track victims** — the `?p=9swg` token allows attackers to track which specific victim clicked and correlate with harvested data

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Evidence |
|-------------|------|---------|
| T1566.001 | Phishing: Spearphishing Attachment | Malicious .eml file attached |
| T1566.002 | Phishing: Spearphishing Link | URL embedded in nested attachment |
| T1036 | Masquerading | Email impersonates legitimate form notification |

---

## Skills Demonstrated

- Blue Team Labs Online challenge completion
- Email header forensic analysis
- Originating IP identification and reverse DNS lookup
- Nested attachment evasion technique recognition
- URL analysis and phishing infrastructure identification
- URL2PNG for investigating taken-down phishing pages
- MITRE ATT&CK phishing technique mapping

---

## Files in This Repository

```
day-24-btlo-phishing-analysis/
├── README.md     
└── report.pdf    
```

---

*Part of the 30 Days of Cybersecurity portfolio project.*

# Day 19: Wireshark — Extract Files from a PCAP (FTP/HTTP)

**Portfolio:** 30 Days of Cybersecurity | Blue Team Track  
**Date:** April 19, 2026  
**Tools:** Wireshark, Kali Linux  
**Source:** Wireshark Sample Captures — ftp.pcap  
**Difficulty:** Intermediate  
**Format:** Network Forensics / DFIR  

---

## Objective

Learn and apply Wireshark's file extraction capability to recover files transferred over FTP and HTTP from a packet capture. File extraction from PCAPs is a critical DFIR skill used during malware investigations to recover dropped payloads, stolen documents, and attacker tools directly from network traffic — without needing access to the original endpoints.

---

## PCAP Overview

| Metric | Value |
|--------|-------|
| Source | wiki.wireshark.org Sample Captures |
| Filename | ftp.pcap |
| Total packets | 566 |
| Protocols | TCP, HTTP, FTP, FTP-DATA, DNS, UDP, ICMP, Gnutella, Microsoft Messenger |
| FTP packets | 12 |
| Files extracted | 21 |

---

## How File Extraction Works in Wireshark

Wireshark reassembles TCP streams and can reconstruct files transferred over application-layer protocols. The **Export Objects** feature (File → Export Objects) supports HTTP, FTP, SMB, DICOM, and TFTP — extracting the raw file content from the packet stream and saving it to disk.

This technique works because unencrypted protocols like HTTP and FTP transmit file content as raw bytes inside TCP segments. Wireshark reassembles these segments in order and writes the payload to a file — exactly as the original recipient received it.

---

## FTP Analysis

### FTP Commands Observed

| Command | Meaning |
|---------|---------|
| USER | Authentication — username submitted |
| PASS | Authentication — password submitted |
| OPTS | Transfer options configured |
| SYST | Server OS identification requested |

No RETR (download) or STOR (upload) commands were present, confirming no file was actually transferred over FTP in this capture. The FTP session established a connection and authenticated but did not complete a file transfer during the capture window.

### FTP Export Result

File → Export Objects → FTP returned an empty list, confirming no FTP file transfer data was captured.

---

## HTTP Analysis

### HTTP GET Requests Identified

| File | Server | Notes |
|------|--------|-------|
| windowsxp-sp2-x86fre-usa-2180_056b2b38baf5620be85ddd58141b073bc0b06a1d.psf | au.download.windowsupdate.com | Windows XP SP2 patch — requested twice |
| xampp-win32-1.4.14-installer.exe | keihanna.dl.sourceforge.net | XAMPP web server installer |
| download.html | 65.223.109.8 | Web page download |
| zebralogo.jpg | www.zebra.org | Logo image |
| dotgreen.jpg | www.zebra.org | UI image |
| powered1-blue.jpg | www.zebra.org | UI image |

### Servers That Served Files

| Server | Content Served |
|--------|---------------|
| au.download.windowsupdate.com | Windows XP SP2 patch file (.psf) |
| keihanna.dl.sourceforge.net | XAMPP installer executable |
| www.zebra.org | Website images (.jpg) |

### Files Extracted

21 files were successfully extracted from the HTTP traffic using File → Export Objects → HTTP, including:

- Windows patch files (.psf format)
- Binary executable (XAMPP installer)
- Matlab data file
- JPEG images from www.zebra.org
- HTML page content

### TCP Stream Analysis

Following the TCP stream for the XAMPP download confirmed:

- HTTP request headers were fully readable in plain text
- File content was binary (unreadable as text) — expected for executable files
- This demonstrates why HTTP is insecure: all headers including cookies, user agents, and referrers are visible to anyone capturing the traffic

---

## DFIR Significance

### Why File Extraction Matters

In a real investigation, this technique recovers:

- **Malware payloads** downloaded by infected hosts — the actual executable dropped during an attack
- **Exfiltrated documents** uploaded by insiders or malware to external servers
- **Attacker tools** transferred laterally across the network (SMB file extraction)
- **C2 scripts** pulled by PowerShell download cradles (as seen in Day 16)

The XAMPP installer and Windows patch download in this capture are legitimate. The same workflow applied to a malware PCAP would recover actual malicious payloads for analysis and hashing.

### Connecting to Previous Days

The PowerShell download cradles identified in Day 16 used `Invoke-WebRequest` to pull `payload.ps1` and `rat.exe` from attacker infrastructure. If those connections had been captured in a PCAP, File → Export Objects → HTTP would have extracted those exact files — giving the analyst the malware binary without needing to access the compromised endpoint.

---

## Wireshark Techniques Used

| Technique | Filter or Menu Path | Purpose |
|-----------|-------------------|---------|
| FTP command analysis | ftp | View FTP control channel commands |
| FTP data channel | ftp-data | View file transfer data channel |
| HTTP request filtering | http.request.method == "GET" | Identify all file download requests |
| HTTP export | File → Export Objects → HTTP | Extract all HTTP-transferred files |
| TCP stream follow | Right-click → Follow → TCP Stream | Read raw HTTP conversation |
| HTTP statistics | Statistics → HTTP → Requests | Map all servers that served content |

---

## Defensive Recommendations

1. Enforce HTTPS for all internal and external web traffic — HTTP file transfers are fully visible and extractable by anyone on the network path
2. Deploy TLS inspection at the perimeter to maintain visibility into HTTPS downloads for malware detection
3. Alert on large file downloads from unknown external IPs — the XAMPP installer download would have been flagged in a monitored environment
4. Log all HTTP and FTP file transfers to your SIEM — file names, sizes, source IPs, and destination IPs should be retained for retrospective investigation
5. Block FTP outbound on corporate networks — FTP transmits credentials and file content in plain text with no encryption

---

## Skills Demonstrated

- Wireshark Export Objects for HTTP and FTP file recovery
- FTP protocol command analysis
- HTTP traffic analysis and server enumeration
- TCP stream reconstruction and content inspection
- DFIR file extraction methodology
- Connecting network forensics to endpoint investigation findings

---

## Files in This Repository

```
day-19-wireshark-file-extraction/
├── README.md          
├── ftp.pcap           
└── report.pdf         
```

---

*Part of the 30 Days of Cybersecurity portfolio project.*

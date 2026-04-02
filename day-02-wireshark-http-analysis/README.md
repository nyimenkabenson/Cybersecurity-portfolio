# Day 2 — Wireshark: HTTP Traffic Capture & Analysis

**Portfolio:** 30 Days of Cybersecurity | Blue Team Track
**Date:** April 2, 2026
**Tools:** Wireshark, Kali Linux, VirtualBox
**Difficulty:** Intermediate
**Format:** Network Forensics / Packet Analysis

---

## Objective

Capture live HTTP network traffic using Wireshark on a Kali Linux lab VM, apply display filters to isolate and analyse requests and responses, and follow a TCP stream to inspect plain text data. This project simulates a core SOC analyst skill: network traffic analysis for threat detection and investigation.

---

## Lab Environment

| Component | Detail |
|-----------|--------|
| Host OS | Windows 11 |
| VM Software | VirtualBox |
| Guest OS | Kali Linux |
| Network Adapter | NAT |
| Capture Tool | Wireshark |
| Traffic Generator | Firefox browser + curl |

---

## Methodology

1. Launched Wireshark on Kali Linux and selected the active network interface
2. Generated HTTP traffic by browsing to known HTTP (non-HTTPS) sites
3. Stopped the capture after sufficient packets were collected
4. Applied display filters to isolate HTTP traffic
5. Followed a TCP stream to inspect raw readable content
6. Saved the capture as `day02_http_capture.pcapng`

> **Analyst note:** Always take notes during live capture — recording observations in real time prevents having to re-open the PCAP later and ensures nothing is missed during time-sensitive investigations.

---

## Wireshark Filters Used

### Filter 1 — Isolate all HTTP traffic
```
http
```
Displays only HTTP protocol packets, filtering out all other traffic types.

---

### Filter 2 — Show HTTP GET requests only
```
http.request.method == "GET"
```
Isolates client-side GET requests — useful for seeing what resources were requested from which hosts.

---

### Filter 3 — Show HTTP responses only
```
http.response
```
Shows server responses — used to identify status codes returned for each request.

---

### Filter 4 — Filter by specific host
```
http.host == "example.com"
```
Narrows traffic to a single domain — useful when investigating a specific server or suspicious destination.

---

### Filter 5 — Follow TCP Stream
Right-click any HTTP packet → **Follow → TCP Stream**

Reconstructs the full conversation between client and server, revealing headers, request paths, and any plain text body content.

---

## Findings

### Hosts Identified

| Domain | Protocol | Notes |
|--------|----------|-------|
| example.com | HTTP | Responds with HTML content |
| httpforever.com | HTTP | Plain HTTP test site |

### HTTP Methods Observed

| Method | Count | Description |
|--------|-------|-------------|
| GET | Multiple | Standard page and resource requests |

### HTTP Status Codes Observed

| Code | Meaning | Observed On |
|------|---------|-------------|
| 200 OK | Request succeeded | example.com, httpforever.com |

### TCP Stream Analysis

Following the TCP stream revealed **plain text readable content** — including full HTTP request headers, server response headers, and HTML body content. This demonstrates a critical security finding: all data transmitted over HTTP is unencrypted and fully visible to anyone on the network.

---

## Key Security Insight

> HTTP traffic is transmitted in **plain text** with zero encryption. Any attacker with network access — or a compromised router — can intercept and read all HTTP requests, responses, credentials, and page content using nothing more than Wireshark.

This is why modern websites enforce **HTTPS** (HTTP over TLS), which encrypts the entire conversation. As a SOC analyst, HTTP traffic on a corporate network should be treated as a red flag — especially for internal applications.

---

## Defensive Recommendations

1. **Enforce HTTPS everywhere** — use HSTS (HTTP Strict Transport Security) headers
2. **Block plain HTTP on corporate networks** — proxy or firewall rules should reject unencrypted HTTP
3. **Alert on HTTP to external IPs** — any outbound HTTP traffic from endpoints warrants investigation
4. **Never transmit credentials over HTTP** — they are fully visible in packet captures

---

## Skills Demonstrated

- Wireshark installation and configuration on Kali Linux
- Live packet capture on a virtualized network interface
- HTTP display filter writing
- TCP stream reconstruction and analysis
- Plain text data exposure identification
- Security insight documentation

---

## Files in This Repository

```
day-02-wireshark-http-analysis/
├── README.md                     ← This file
├── day02_http_capture.pcapng     ← Packet capture file
└── report.pdf                    ← Full analyst report
```

---

*Part of the [30 Days of Cybersecurity](../README.md) portfolio project.*

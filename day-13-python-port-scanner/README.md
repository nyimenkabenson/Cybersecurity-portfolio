# Day 13: Python Port Scanner with Socket

**Portfolio:** 30 Days of Cybersecurity | Blue Team Track  
**Date:** April 13, 2026  
**Tools:** Python 3, socket library, Kali Linux  
**Difficulty:** Intermediate  
**Format:** Security Automation / Network Reconnaissance  

---

## Objective

Build a multithreaded TCP port scanner from scratch using Python's built-in socket library — no third-party tools required. This project demonstrates how scanning tools like nmap work under the hood and produces a functional security automation script that can be used in real assessments and SOC workflows.

---

## Lab Environment

| Component | Detail |
|-----------|--------|
| OS | Kali Linux (VirtualBox VM) |
| Language | Python 3 |
| Library | socket (built-in), concurrent.futures |
| Target 1 | scanme.nmap.org (legal public practice target) |
| Target 2 | 127.0.0.1 (localhost) |
| Port range | 1 to 1024 (well-known ports) |
| Threads | 100 concurrent |

---

## Script Design

The scanner uses Python's `socket.connect_ex()` to attempt a TCP connection to each port. A return value of 0 indicates the port is open. `ThreadPoolExecutor` runs 100 concurrent threads to dramatically reduce scan time compared to sequential scanning.

### Key Design Decisions

| Decision | Reasoning |
|----------|-----------|
| socket.connect_ex() over connect() | Returns an error code rather than raising an exception — cleaner flow control |
| 100 concurrent threads | Balances speed against network stability — sequential scanning of 1024 ports would take minutes |
| 1 second timeout per port | Avoids hanging on filtered ports while giving enough time for slow responses |
| socket.getservbyport() | Resolves port numbers to service names automatically from the system service database |

---

## Scan Results

### Target 1: scanme.nmap.org

| Port | Service | Status | Scan Duration |
|------|---------|--------|--------------|
| 22 | ssh | OPEN | 11 seconds |
| 80 | http | OPEN | 11 seconds |

Both services are intentionally exposed — `scanme.nmap.org` is a server maintained by the Nmap project specifically for legal scanning practice. SSH on port 22 provides remote access and HTTP on port 80 serves a basic web page.

### Target 2: 127.0.0.1 (Kali localhost)

| Result | Detail |
|--------|--------|
| Open ports found | 0 |
| Scan duration | 0 seconds |
| Assessment | Clean — no listening services |

No open ports on the local Kali machine confirms a secure default posture. A fresh Kali installation runs no network services by default, meaning there are no exposed attack surfaces on the local machine.

---

## How the Scanner Works

### TCP Connect Scan Explained

The scanner performs a full TCP connect scan. For each port it attempts to complete a three-way handshake:

1. The scanner sends a SYN packet to the target port
2. If the port is open, the target responds with SYN-ACK
3. The scanner completes the handshake with ACK — connection established
4. `connect_ex()` returns 0, the port is recorded as open
5. The scanner immediately closes the connection

If the port is closed the target responds with RST. If the port is filtered a firewall drops the packet and the connection times out after 1 second.

### Threading Impact on Speed

Without threading, scanning 1024 ports with a 1-second timeout would take up to 1024 seconds in the worst case. With 100 concurrent threads, the effective maximum scan time drops to approximately 10 to 11 seconds — a 99% reduction.

---

## Comparison: Python Scanner vs nmap

| Feature | This Scanner | nmap |
|---------|-------------|------|
| Scan type | TCP connect | SYN, UDP, connect and more |
| Speed | Fast (threaded) | Faster (kernel-level) |
| Service detection | Port-to-name mapping | Version and banner grabbing |
| OS detection | No | Yes |
| Output formats | Terminal | XML, JSON, grepable |
| Dependencies | Python built-in only | External install required |

This scanner demonstrates the core principle behind nmap's TCP connect scan. Understanding the fundamentals makes it easier to interpret nmap output during real assessments.

---

## Blue Team Application

From a defensive perspective, this scanner demonstrates exactly what attackers and penetration testers do during reconnaissance. A SOC analyst should:

1. Alert on sequential port connection attempts from a single IP — the pattern produced by this scanner is detectable in firewall logs
2. Recognise that a scan completing in 11 seconds means the attacker already knows which ports are open — response time matters
3. Understand that open ports are attack surface — every open port is a potential entry point that must be justified and hardened

---

## Defensive Recommendations

1. Run this scanner against your own infrastructure regularly to audit your exposed attack surface
2. Deploy firewall rules that drop rather than reject connection attempts on unused ports — rejection responses confirm port status to scanners
3. Alert on any source IP attempting more than 20 unique destination ports in 60 seconds — the detection rule built in Day 10 catches exactly this pattern
4. Use this script as the foundation for an automated weekly port audit — compare results against a baseline and alert on new open ports

---

## Skills Demonstrated

- Python socket programming from first principles
- TCP three-way handshake understanding
- Multithreading with concurrent.futures.ThreadPoolExecutor
- Service name resolution with socket.getservbyport()
- Hostname to IP resolution with socket.gethostbyname()
- Offensive tool fundamentals applied to defensive understanding

---

## Files in This Repository

```
day-13-python-port-scanner/
├── README.md          
├── port_scanner.py    
└── report.pdf         
```

---

*Part of the 30 Days of Cybersecurity portfolio project.*

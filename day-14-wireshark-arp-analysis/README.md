# Day 14: Wireshark ARP Analysis — Storm Detection and Poisoning Theory

**Portfolio:** 30 Days of Cybersecurity | Blue Team Track  
**Date:** April 14, 2026  
**Tools:** Wireshark, Kali Linux  
**Source:** Wireshark Sample Captures — arp-storm.pcap  
**Difficulty:** Intermediate  
**Format:** Network Forensics / Protocol Analysis  

---

## Objective

Analyse a real-world ARP packet capture to identify abnormal ARP behaviour, characterise the traffic pattern, and document both ARP storm detection methodology and ARP poisoning theory, two related but distinct network threats every SOC analyst must recognise.

---

## PCAP Overview

| Metric | Value |
|--------|-------|
| Source | wiki.wireshark.org Sample Captures |
| Filename | arp-storm.pcap |
| Total packets | 622 |
| Protocol | ARP only (100%) |
| Capture duration | 28.97 seconds |
| Unique MAC addresses | 2 |

---

## ARP Protocol Background

Address Resolution Protocol (ARP) maps IP addresses to MAC addresses on a local network. When a device wants to communicate with an IP address it does not have a MAC address for, it broadcasts an ARP request to the entire network. The device with that IP responds with an ARP reply containing its MAC address.

Normal ARP behaviour follows a strict request-reply pattern — one broadcast request followed by one unicast reply. Any deviation from this pattern is a forensic indicator worth investigating.

---

## Analysis Findings

### Finding 1: Single Source ARP Storm

One Cisco device was responsible for all 622 packets in the capture.

| Field | Value |
|-------|-------|
| Sender MAC | 00:07:0d:af:f4:54 (Cisco) |
| Sender IP | 24.166.172.1 |
| Packet count | 622 ARP requests |
| Capture duration | 28.97 seconds |
| Average rate | 21.5 requests per second |
| Traffic pattern | Bursts rather than steady stream |

### Finding 2: Multiple Target IPs

The device sent ARP requests for different target IP addresses each time rather than repeatedly querying the same IP. This is the defining characteristic of ARP scanning — the device is systematically probing the network to discover which hosts are alive and reachable.

### Finding 3: Broadcast Only Traffic

Both MAC addresses present are expected: the Cisco device as the sender and `ff:ff:ff:ff:ff:ff` (broadcast) as the destination. All ARP requests were sent to the broadcast address — no ARP replies were captured, meaning no hosts responded to the requests during the capture window.

### Finding 4: Burst Pattern

The IO graph showed traffic arriving in bursts rather than at a constant rate. This is consistent with either an automated scanning tool cycling through address ranges in batches, or a network device rebuilding its ARP cache in groups after a restart.

---

## ARP Storm vs ARP Poisoning

This capture showed an ARP storm. Understanding the difference between a storm and poisoning is essential for correct incident classification.

| Feature | ARP Storm (this PCAP) | ARP Poisoning |
|---------|----------------------|---------------|
| Traffic direction | One device sends many requests | Attacker sends unsolicited replies |
| Target IPs | Multiple different addresses | Specific victim IP addresses |
| Wireshark indicator | High ARP request volume and bursts | arp.duplicate-address-detected |
| ARP opcode | 1 (request) only | 2 (reply) without prior request |
| Intent | Discovery or misconfiguration | Man-in-the-middle interception |
| Network impact | Bandwidth consumption | Traffic redirection and interception |

---

## ARP Poisoning — Theory and Detection

Although this PCAP did not contain ARP poisoning, documenting the detection methodology is essential for any blue team analyst.

### How ARP Poisoning Works

An attacker sends unsolicited ARP reply packets to two victims — typically a host and the default gateway. Each ARP reply falsely claims the attacker's MAC address corresponds to the other victim's IP address. Both victims update their ARP caches with the false mapping, directing all traffic between them through the attacker's machine.

### ARP Poisoning Indicators in Wireshark

| Indicator | Filter | What to Look For |
|-----------|--------|-----------------|
| Duplicate IP detection | arp.duplicate-address-detected | Same IP claimed by two different MACs |
| Unsolicited replies | arp.opcode == 2 | ARP replies with no preceding request |
| One MAC claiming multiple IPs | Statistics → Endpoints | Single MAC with unusually high packet count |
| Gratuitous ARP | arp.isgratuitous == 1 | Device announcing its own IP-MAC mapping unprompted |

### ARP Poisoning Attack Chain

1. Attacker sends ARP reply to Victim A: "IP of Gateway = Attacker MAC"
2. Attacker sends ARP reply to Victim B (gateway): "IP of Victim A = Attacker MAC"
3. Both victims update their ARP cache with false mappings
4. All traffic from Victim A to the gateway flows through the attacker
5. Attacker forwards traffic to maintain connectivity (avoiding detection)
6. Attacker reads, modifies, or injects data in transit

---

## Possible Explanations for This ARP Storm

Three scenarios could explain the behaviour observed:

**Scenario 1: Network discovery after device restart.** A Cisco router rebuilding its ARP table after a reboot or configuration change will send bursts of ARP requests for all known hosts. This is benign but generates significant broadcast traffic.

**Scenario 2: Misconfigured or faulty device.** A routing loop, software bug, or incorrect network configuration can cause a device to continuously re-probe the network. This degrades performance for all devices on the segment.

**Scenario 3: Compromised device used for reconnaissance.** An attacker who has gained access to a Cisco device may use it to map the network via ARP scanning before attempting lateral movement to other hosts.

---

## Defensive Recommendations

1. Implement Dynamic ARP Inspection (DAI) on managed switches — this validates ARP packets against a trusted DHCP binding table and drops spoofed replies automatically
2. Alert on ARP request rates exceeding 10 requests per second from any single source — the Day 10 port scan detection approach can be adapted for ARP monitoring in a SIEM
3. Use static ARP entries for critical infrastructure such as default gateways and domain controllers to prevent ARP cache poisoning on these key hosts
4. Deploy network monitoring tools that alert on ARP cache changes — tools like XArp or arpwatch detect when a MAC address changes for a known IP
5. Segment networks using VLANs to limit ARP broadcast domains and reduce the blast radius of any ARP-based attack

---

## Wireshark Filters Reference

| Filter | Purpose |
|--------|---------|
| arp | Show all ARP traffic |
| arp.opcode == 1 | ARP requests only |
| arp.opcode == 2 | ARP replies only |
| arp.duplicate-address-detected | Poisoning indicator |
| arp.isgratuitous == 1 | Gratuitous ARP packets |
| arp.src.hw_mac == 00:07:0d:af:f4:54 | Filter by specific MAC |

---

## Skills Demonstrated

- ARP protocol analysis and traffic characterisation
- ARP storm identification and rate calculation
- ARP poisoning theory and detection methodology
- Wireshark Statistics tools (IO Graph, Endpoints, Protocol Hierarchy)
- Incident classification — distinguishing storm from poisoning
- Defensive control recommendations for ARP-based attacks

---

## Files in This Repository

```
day-14-wireshark-arp-analysis/
├── README.md          
├── arp-storm.pcap     
└── report.pdf         
```

---

*Part of the 30 Days of Cybersecurity portfolio project.*

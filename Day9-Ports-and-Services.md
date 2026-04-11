# Day 9: Understanding Ports and Services 🚪

## Introduction
On Day 9 of my cybersecurity journey, I learned about ports and services and how they relate to system security.

---

## What are Ports?
Ports are communication endpoints that allow systems to send and receive data.

---

## What are Services?
Services are programs running on a system that use ports to communicate.

---

## Practical Experiment

I started a simple HTTP server:
python3 -m http.server 8000


Then I scanned my system using Nmap and observed that port 8000 was open.

After stopping the server, I scanned again and noticed the port was no longer open.

---

## Key Observations
- Ports open when services are running
- Ports close when services stop
- Open ports can expose systems to risks if not managed properly

---

## Common Ports
- 22 → SSH
- 80 → HTTP
- 443 → HTTPS

---

## What I Learned
- The relationship between ports and services
- Why open ports matter in cybersecurity
- How to identify open ports using Nmap

---

## Reflection
This exercise helped me understand how systems expose services and why monitoring open ports is important for security.

---

## Conclusion
Managing open ports is essential for maintaining system security and reducing vulnerabilities. 

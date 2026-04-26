# Day 21: DFIR — Memory Forensics with Volatility

**Portfolio:** 30 Days of Cybersecurity | Blue Team Track  
**Date:** April 21, 2026  
**Tools:** Volatility 3 Framework 2.27.0, GIMP, foremost, Kali Linux  
**Memory Image:** MemLabs Lab1 — MemoryDump_Lab1.raw  
**Difficulty:** Advanced  
**Format:** DFIR / Memory Forensics  

---

## Objective

Perform a complete memory forensics investigation on a Windows 7 SP1 memory dump using Volatility 3, extracting forensic artefacts including process lists, command history, network connections, file system artefacts, and environment variables to reconstruct system activity at the time of capture.

---

## Memory Image Profile

| Field | Value |
|-------|-------|
| Source | MemLabs Lab1 — CTF memory forensics challenge |
| OS | Windows 7 SP1 (7601.17514.amd64fre.win7sp1_rtm) |
| Architecture | 32-bit (WindowsIntel32e) |
| System time | 2019-12-11 14:38:00 UTC |
| Computer name | SMARTNET-PC |
| Logged-in user | SmartNet |
| Volatility version | Framework 3 — 2.27.0 |

---

## Commands Executed and Findings

### Command 1: windows.info — OS Identification

```bash
vol -f ~/MemoryDump_Lab1.raw windows.info
```

Confirmed Windows 7 SP1 32-bit. Kernel base at 0xf8000261f000. System time 2019-12-11 14:38:00. This is always the first command in any memory forensics investigation — the profile determines which plugins and structures apply to the rest of the analysis.

---

### Command 2: windows.pslist — Running Processes

```bash
vol -f ~/MemoryDump_Lab1.raw windows.pslist
```

Key processes identified at time of capture:

| Process | PID | Parent PID | Notes |
|---------|-----|-----------|-------|
| System | 4 | 0 | Normal Windows kernel process |
| smss.exe | 248 | 4 | Session Manager — normal |
| csrss.exe | 320, 368 | 248, 312 | Client Server Runtime — normal |
| winlogon.exe | 416 | 368 | Windows logon — normal |
| services.exe | 484 | 424 | Service Control Manager — normal |
| lsass.exe | 492 | 424 | Local Security Authority — normal |
| explorer.exe | 604 | 2016 | Windows shell — user session |
| cmd.exe | 1984 | 604 | Command prompt — launched from desktop |
| mspaint.exe | 2424 | 604 | Paint — suspicious in forensics context |
| WinRAR.exe | 1512 | 604 | Opening Important.rar from Alissa's documents |
| DumpIt.exe | 796 | 604 | Memory dumping tool — confirms intentional capture |
| VBoxTray.exe | 1844 | 604 | VirtualBox guest additions — VM environment |

---

### Command 3: windows.pstree — Process Tree Analysis

```bash
vol -f ~/MemoryDump_Lab1.raw windows.pstree
```

The process tree confirmed all suspicious processes were spawned directly from explorer.exe (PID 604) — the Windows shell. This indicates a user directly launched these applications rather than malware spawning them through exploitation.

**Key parent-child relationships:**
- explorer.exe → cmd.exe (user opened command prompt)
- explorer.exe → mspaint.exe (user opened Paint — likely to display or create an image)
- explorer.exe → WinRAR.exe (user opened Important.rar)
- explorer.exe → DumpIt.exe (user ran memory capture tool)

---

### Command 4: windows.cmdline — Command Line Arguments

```bash
vol -f ~/MemoryDump_Lab1.raw windows.cmdline
```

**Critical finding:** WinRAR.exe was launched with the path:
```
"C:\Program Files\WinRAR\WinRAR.exe" "C:\Users\Alissa Simpson\Documents\Important.rar"
```

This confirms the user Alissa Simpson had an archive called `Important.rar` in her Documents folder — a primary investigation target. The cmd.exe process showed no additional arguments, suggesting it was opened interactively.

---

### Command 5: windows.filescan — File System Artefacts

```bash
vol -f ~/MemoryDump_Lab1.raw windows.filescan | grep -i "alissa"
vol -f ~/MemoryDump_Lab1.raw windows.filescan | grep -iE "\.png|\.jpg|\.rar|\.txt|\.zip"
```

**Key files identified:**

| File Path | Significance |
|-----------|-------------|
| \Users\Alissa Simpson\Documents\Important.rar | Primary evidence — archive of interest |
| \Users\Alissa Simpson\AppData\Roaming\Microsoft\Windows\Themes\TranscodedWallpaper.jpg | Desktop wallpaper image |
| \Windows\Tasks\SCHEDLGU.TXT | Scheduled tasks log |
| \Users\Alissa Simpson\AppData\Roaming\WinRAR\version.dat | WinRAR usage confirmed |

The file `Important.rar` appearing multiple times in the filescan at different memory addresses confirms it was actively open and cached in memory during the dump.

---

### Command 6: windows.memmap — Process Memory Dump

```bash
vol -f ~/MemoryDump_Lab1.raw -o ~/ windows.memmap --pid 2424 --dump
```

The mspaint.exe process memory was successfully dumped. Foremost was used to carve BMP files from the raw dump:

```bash
foremost -t jpg,png,bmp -i ~/memdump_mspaint.data -o ~/foremost_output/
```

One BMP file was extracted. The image contained visual data from the Paint canvas at the time of memory capture, consistent with a user having an image open in Paint during the session.

---

### Command 7: windows.envars — Environment Variables

```bash
vol -f ~/MemoryDump_Lab1.raw windows.envars --pid 2424
```

Key environment variables from mspaint.exe process:

| Variable | Value | Significance |
|----------|-------|-------------|
| USERNAME | SmartNet | Confirms active user account |
| COMPUTERNAME | SMARTNET-PC | Machine hostname |
| HOMEPATH | C:\Users\SmartNet | User home directory |
| APPDATA | C:\Users\SmartNet\AppData\Roaming | Application data path |
| windows_tracing_logfile | C:\BVTBin\Tests\installpackage\csilogfile.log | Suspicious tracing path |
| TEMP | C:\Users\SmartNet\AppData\Local\Temp | Temp directory |

**Note:** The logged-in user is SmartNet while the file of interest belongs to Alissa Simpson — suggesting either multiple user accounts exist on the system or the machine was shared.

---

### Command 8: windows.netstat — Network Connections

```bash
vol -f ~/MemoryDump_Lab1.raw windows.netstat
```

Network state at time of capture:

| Process | Protocol | Local IP | Port | State |
|---------|----------|----------|------|-------|
| TCPSVCS.EXE | TCPv4/v6 | 0.0.0.0 | 7, 9, 13, 17, 19 | LISTENING |
| svchost.exe | TCPv4/v6 | 0.0.0.0 | 135 | LISTENING |
| System | TCPv4 | 10.0.2.15 | 139 | LISTENING |
| wmpnetwk.exe | TCPv4/v6 | 0.0.0.0 | 554 | LISTENING |
| lsass.exe | TCPv4/v6 | 0.0.0.0 | 49154 | LISTENING |

The machine IP was **10.0.2.15** — consistent with VirtualBox NAT networking. TCPSVCS.EXE listening on ports 7, 9, 13, 17, and 19 represents legacy TCP/IP small services (echo, discard, daytime, etc.) — unusual in modern environments.

No active established connections were found at the time of the dump, suggesting no live attacker access at capture time.

---

## Investigation Summary

### What the Memory Dump Tells Us

| Finding | Evidence | Significance |
|---------|----------|-------------|
| Two user accounts | SmartNet (active) and Alissa Simpson (files) | Shared machine or multiple accounts |
| Important.rar open | WinRAR.exe cmdline + filescan | Primary evidence target |
| mspaint.exe active | Process list + memory dump | Canvas content recoverable |
| cmd.exe open | Process list | Interactive shell available |
| DumpIt.exe ran | Process list | Intentional forensic capture |
| No active network connections | Netstat | No live attacker access at capture |

### Volatility 3 Commands Reference

| Command | Purpose |
|---------|---------|
| windows.info | OS identification and profile |
| windows.pslist | Running process enumeration |
| windows.pstree | Parent-child process relationships |
| windows.cmdline | Full command line arguments per process |
| windows.filescan | File system artefacts in memory |
| windows.memmap --dump | Dump process memory to disk |
| windows.envars | Environment variables per process |
| windows.netstat | Network connections at capture time |
| windows.dumpfiles | Extract specific files from memory |

---

## Key DFIR Lessons from This Exercise

1. Always run windows.info first — the OS profile determines everything that follows
2. windows.pstree reveals parent-child relationships that expose malicious process spawning
3. DumpIt.exe in the process list confirms this was a deliberate forensic capture
4. mspaint.exe is commonly used in CTF challenges to hide flags in canvas images
5. filescan locates files that may no longer exist on disk but were cached in memory
6. Environment variables reveal the active user context even for GUI applications
7. Volatility 3 syntax differs from Volatility 2 — no profile flag needed, uses plugin namespacing

---

## Skills Demonstrated

- Volatility 3 installation and configuration on Kali Linux
- Memory image profiling and OS identification
- Process list and process tree forensic analysis
- Command line argument extraction
- Memory-resident file system artefact recovery
- Process memory dumping and BMP carving with foremost
- Environment variable analysis
- Network connection state recovery
- Memory forensics methodology and workflow

---

## Files in This Repository

```
day-21-volatility-memory-forensics/
├── README.md     
└── report.pdf    
```

Note: The memory dump file is not included in this repository. It can be downloaded from the MemLabs Lab1 challenge.

---

*Part of the 30 Days of Cybersecurity portfolio project.*

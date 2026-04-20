import re
import json
from datetime import datetime

# ── IOC Regex Patterns ────────────────────────────────────────────────────
PATTERNS = {
    "ipv4": r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
    "domain": r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|xyz|io|gov|edu|co|uk|de|ru|cn|info|biz|onion)\b',
    "md5": r'\b[a-fA-F0-9]{32}\b',
    "sha1": r'\b[a-fA-F0-9]{40}\b',
    "sha256": r'\b[a-fA-F0-9]{64}\b',
    "email": r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b',
    "url": r'https?://[^\s<>"\']+',
    "cve": r'CVE-\d{4}-\d{4,7}',
    "bitcoin": r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
    "registry": r'HK(?:EY_)?(?:LOCAL_MACHINE|CURRENT_USER|LM|CU)\\[^\s"\']+',
    "filepath": r'[A-Za-z]:\\(?:[^\\\/:*?"<>|\r\n]+\\)*[^\\\/:*?"<>|\r\n]*',
}

# ── False Positive Exclusions ─────────────────────────────────────────────
EXCLUDE_IPS = {"127.0.0.1", "0.0.0.0", "255.255.255.255", "8.8.8.8", "1.1.1.1"}
EXCLUDE_DOMAINS = {"example.com", "test.com", "localhost.com"}

def extract_iocs(text):
    results = {}
    for ioc_type, pattern in PATTERNS.items():
        matches = list(set(re.findall(pattern, text)))
        if ioc_type == "ipv4":
            matches = [m for m in matches if m not in EXCLUDE_IPS]
        if ioc_type == "domain":
            matches = [m for m in matches if m not in EXCLUDE_DOMAINS]
            matches = [m for m in matches if not re.match(r'^\d', m)]
        if matches:
            results[ioc_type] = sorted(matches)
    return results

# ── Sample Threat Report ──────────────────────────────────────────────────
SAMPLE_REPORT = r"""
THREAT INTELLIGENCE REPORT — April 16, 2026

SUMMARY:
A new ransomware campaign has been identified targeting financial organisations.
The threat actor is using spearphishing emails with malicious Word documents.

INFECTION CHAIN:
Initial access via phishing email from payroll-update@hr-portal-secure.com
The attachment Invoice_Q1_2026.docx contains a macro that downloads from:
http://185.220.101.45/stage2.exe

The dropper connects to C2 at 91.240.118.172:443 using domain fronting via
default.exp-tas.com. A secondary payload is pulled from:
https://objects.githubusercontent.com/payload.ps1

MALWARE HASHES:
invoice_setup.exe MD5: 5f4dcc3b5aa765d61d8327deb882cf99
stage2.exe SHA256: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
payload.ps1 SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709

PERSISTENCE:
Registry key: HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate
File dropped: C:\Users\Public\svchost32.exe
Scheduled task: C:\Windows\System32\Tasks\WindowsUpdateHelper

RANSOM CONTACT:
Email: recover@darkmail.xyz
Bitcoin wallet: 1A2B3C4D5E6F7G8H9I0J
Reference: RNS-2026-0415-WW

VULNERABILITIES EXPLOITED:
CVE-2022-30190 (Follina — MSDT RCE)
CVE-2021-40444 (MSHTML RCE)

ADDITIONAL IPs OBSERVED:
103.75.190.12, 45.33.32.156, 194.165.16.99
"""

print("\n" + "="*60)
print("         IOC EXTRACTOR — THREAT REPORT ANALYSIS")
print("="*60)
print(f"\n Report analysed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f" Report length     : {len(SAMPLE_REPORT)} characters\n")

iocs = extract_iocs(SAMPLE_REPORT)

total = 0
for ioc_type, values in iocs.items():
    print(f"\n {'='*50}")
    print(f" {ioc_type.upper()} ({len(values)} found)")
    print(f" {'='*50}")
    for v in values:
        print(f"   {v}")
    total += len(values)

print(f"\n{'='*60}")
print(f" Total IOCs extracted : {total}")
print(f"{'='*60}\n")

with open("extracted_iocs.json", "w") as f:
    json.dump({
        "extracted_at": datetime.now().isoformat(),
        "total_iocs": total,
        "iocs": iocs
    }, f, indent=2)

print(" Results saved to extracted_iocs.json\n")

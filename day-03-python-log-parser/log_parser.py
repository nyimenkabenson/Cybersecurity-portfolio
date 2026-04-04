import re
from collections import Counter

LOG_FILE = "sample_access.log"

# Regex pattern for Apache Combined Log Format
pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)'   # IP address
    r'.+\[(?P<datetime>[^\]]+)\]'     # Datetime
    r'\s"(?P<method>\w+)\s'           # HTTP method
    r'(?P<url>\S+)\s[^"]+"\s'         # URL
    r'(?P<status>\d{3})\s'            # Status code
    r'(?P<size>\d+)'                  # Response size
)

ips      = []
statuses = []
methods  = []
urls     = []
failures = []

print("\n" + "="*55)
print("       WEB SERVER ACCESS LOG — PARSER REPORT")
print("="*55)

with open(LOG_FILE, "r") as f:
    lines = f.readlines()

for line in lines:
    match = pattern.match(line)
    if match:
        ip     = match.group("ip")
        method = match.group("method")
        url    = match.group("url")
        status = match.group("status")

        ips.append(ip)
        statuses.append(status)
        methods.append(method)
        urls.append(url)

        # Flag suspicious activity
        if status in ("401", "403", "404", "400"):
            failures.append(ip)

# ── Summary ──────────────────────────────────────────────────────
print(f"\n Total log entries parsed : {len(lines)}")
print(f" Unique IP addresses      : {len(set(ips))}")

# ── Top IPs ──────────────────────────────────────────────────────
print("\n--- Top 5 Source IPs ---")
for ip, count in Counter(ips).most_common(5):
    print(f"  {ip:<20} {count} requests")

# ── Status Codes ─────────────────────────────────────────────────
print("\n--- Status Code Breakdown ---")
for status, count in sorted(Counter(statuses).items()):
    label = {
        "200": "OK",
        "304": "Not Modified",
        "400": "Bad Request",
        "401": "Unauthorized",
        "403": "Forbidden",
        "404": "Not Found",
    }.get(status, "Other")
    print(f"  {status} {label:<20} {count} occurrences")

# ── HTTP Methods ─────────────────────────────────────────────────
print("\n--- HTTP Methods ---")
for method, count in Counter(methods).most_common():
    print(f"  {method:<10} {count} requests")

# ── Suspicious IPs ───────────────────────────────────────────────
print("\n--- Suspicious IPs (4xx errors) ---")
for ip, count in Counter(failures).most_common():
    print(f"  {ip:<20} {count} error responses")

# ── Suspicious URLs ──────────────────────────────────────────────
suspicious_keywords = ["admin", "passwd", "shell", "env", "phpmyadmin", "wp-admin"]
print("\n--- Suspicious URL Requests ---")
found = False
for line in lines:
    match = pattern.match(line)
    if match:
        url = match.group("url")
        ip  = match.group("ip")
        if any(keyword in url.lower() for keyword in suspicious_keywords):
            print(f"  {ip:<20} requested {url}")
            found = True
if not found:
    print("  None detected.")

print("\n" + "="*55)
print(" Analysis complete.")
print("="*55 + "\n")

import requests
import json
import time

API_KEY ="3c2298caf4b714c95031ae5f244bf2407771096c3438e01068d4ae84e0ead9ef"

SUSPICIOUS_IPS = [
    "185.220.101.45",
    "103.75.190.12",
    "45.33.32.156",
    "91.240.118.172",
    "194.165.16.99",
    "8.8.8.8",
    "1.1.1.1",
]

BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

HEADERS = {
    "x-apikey": API_KEY
}

def check_ip(ip):
    try:
        response = requests.get(BASE_URL + ip, headers=HEADERS)
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            reputation = data["data"]["attributes"].get("reputation", 0)
            country = data["data"]["attributes"].get("country", "Unknown")
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            return {
                "ip": ip,
                "country": country,
                "reputation": reputation,
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "verdict": "MALICIOUS" if malicious > 2 else "SUSPICIOUS" if malicious > 0 or suspicious > 0 else "CLEAN"
            }
        elif response.status_code == 429:
            return {"ip": ip, "error": "Rate limit hit — wait 60 seconds"}
        else:
            return {"ip": ip, "error": f"Status code {response.status_code}"}
    except Exception as e:
        return {"ip": ip, "error": str(e)}

print("\n" + "="*60)
print("        IP REPUTATION CHECKER — VIRUSTOTAL API")
print("="*60)

results = []

for ip in SUSPICIOUS_IPS:
    print(f"\n Checking {ip}...")
    result = check_ip(ip)
    results.append(result)

    if "error" in result:
        print(f"  ERROR: {result['error']}")
    else:
        print(f"  Country    : {result['country']}")
        print(f"  Reputation : {result['reputation']}")
        print(f"  Malicious  : {result['malicious']} engines")
        print(f"  Suspicious : {result['suspicious']} engines")
        print(f"  Harmless   : {result['harmless']} engines")
        print(f"  Verdict    : {result['verdict']}")

    time.sleep(16)

print("\n" + "="*60)
print("                    SUMMARY")
print("="*60)

malicious_ips = [r for r in results if r.get("verdict") == "MALICIOUS"]
suspicious_ips = [r for r in results if r.get("verdict") == "SUSPICIOUS"]
clean_ips = [r for r in results if r.get("verdict") == "CLEAN"]

print(f"\n  Total IPs checked : {len(results)}")
print(f"  Malicious         : {len(malicious_ips)}")
print(f"  Suspicious        : {len(suspicious_ips)}")
print(f"  Clean             : {len(clean_ips)}")

if malicious_ips:
    print("\n  Malicious IPs to block immediately:")
    for r in malicious_ips:
        print(f"    {r['ip']} ({r['country']}) — {r['malicious']} engines flagged")

print("\n" + "="*60)
print("  Analysis complete.")
print("="*60 + "\n")

with open("results.json", "w") as f:
    json.dump(results, f, indent=2)
print("  Results saved to results.json")

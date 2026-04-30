import requests
import whois
import json
import sys
from datetime import datetime

# ── Configuration ──────────────────────────────────────────────────────────
VT_API_KEY = "3c2298caf4b714c95031ae5f244bf2407771096c3438e01068d4ae84e0ead9ef"

# ── IOCs to enrich ─────────────────────────────────────────────────────────
IOCS = [
    {"type": "ip", "value": "185.220.101.45"},
    {"type": "ip", "value": "91.240.118.172"},
    {"type": "domain", "value": "exp-tas.com"},
    {"type": "domain", "value": "hr-payroll-verify.xyz"},
]

VT_HEADERS = {"x-apikey": VT_API_KEY}

def vt_check_ip(ip):
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers=VT_HEADERS, timeout=10)
        if r.status_code == 200:
            d = r.json()["data"]["attributes"]
            stats = d.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "country": d.get("country", "Unknown"),
                "reputation": d.get("reputation", 0),
                "asn": d.get("asn", "Unknown"),
                "as_owner": d.get("as_owner", "Unknown"),
            }
    except Exception as e:
        return {"error": str(e)}
    return {}

def vt_check_domain(domain):
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers=VT_HEADERS, timeout=10)
        if r.status_code == 200:
            d = r.json()["data"]["attributes"]
            stats = d.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "reputation": d.get("reputation", 0),
                "registrar": d.get("registrar", "Unknown"),
                "creation_date": str(d.get("creation_date", "Unknown")),
            }
    except Exception as e:
        return {"error": str(e)}
    return {}

def whois_lookup(ioc):
    try:
        w = whois.whois(ioc)
        return {
            "registrar": str(w.registrar) if w.registrar else "Unknown",
            "creation_date": str(w.creation_date) if w.creation_date else "Unknown",
            "expiration_date": str(w.expiration_date) if w.expiration_date else "Unknown",
            "name_servers": str(w.name_servers) if w.name_servers else "Unknown",
            "country": str(w.country) if w.country else "Unknown",
            "org": str(w.org) if w.org else "Unknown",
        }
    except Exception as e:
        return {"error": str(e)}

def get_verdict(malicious, suspicious):
    if malicious > 5:
        return "MALICIOUS"
    elif malicious > 0 or suspicious > 2:
        return "SUSPICIOUS"
    else:
        return "CLEAN"

print("\n" + "="*65)
print("       AUTOMATED ALERT ENRICHMENT TOOL")
print("       WHOIS + VirusTotal Integration")
print("="*65)
print(f"\n Enriching {len(IOCS)} IOCs at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

results = []

for ioc in IOCS:
    ioc_type = ioc["type"]
    ioc_value = ioc["value"]
    print(f" Checking {ioc_type.upper()}: {ioc_value}")

    result = {"type": ioc_type, "value": ioc_value}

    # VirusTotal check
    if ioc_type == "ip":
        vt_data = vt_check_ip(ioc_value)
    else:
        vt_data = vt_check_domain(ioc_value)

    result["virustotal"] = vt_data

    # WHOIS lookup
    whois_data = whois_lookup(ioc_value)
    result["whois"] = whois_data

    # Verdict
    malicious = vt_data.get("malicious", 0)
    suspicious = vt_data.get("suspicious", 0)
    result["verdict"] = get_verdict(malicious, suspicious)

    results.append(result)

    # Print summary
    print(f"   VT Malicious  : {vt_data.get('malicious', 'N/A')} engines")
    print(f"   VT Suspicious : {vt_data.get('suspicious', 'N/A')} engines")
    if ioc_type == "ip":
        print(f"   Country       : {vt_data.get('country', 'N/A')}")
        print(f"   ASN Owner     : {vt_data.get('as_owner', 'N/A')}")
    print(f"   Registrar     : {whois_data.get('registrar', 'N/A')}")
    print(f"   Created       : {whois_data.get('creation_date', 'N/A')}")
    print(f"   Verdict       : {result['verdict']}")
    print()

    import time
    time.sleep(16)

# Summary
print("="*65)
print(" ENRICHMENT SUMMARY")
print("="*65)
malicious_iocs = [r for r in results if r["verdict"] == "MALICIOUS"]
suspicious_iocs = [r for r in results if r["verdict"] == "SUSPICIOUS"]
clean_iocs = [r for r in results if r["verdict"] == "CLEAN"]

print(f"\n Total IOCs enriched : {len(results)}")
print(f" Malicious           : {len(malicious_iocs)}")
print(f" Suspicious          : {len(suspicious_iocs)}")
print(f" Clean               : {len(clean_iocs)}")

if malicious_iocs:
    print("\n Block immediately:")
    for r in malicious_iocs:
        print(f"   {r['value']} ({r['type'].upper()})")

# Save results
with open("enrichment_results.json", "w") as f:
    json.dump({
        "timestamp": datetime.now().isoformat(),
        "total": len(results),
        "results": results
    }, f, indent=2)

print(f"\n Results saved to: enrichment_results.json")
print("="*65 + "\n")

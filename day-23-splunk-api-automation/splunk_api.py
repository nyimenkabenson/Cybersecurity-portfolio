import requests
import json
import time
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Configuration ──────────────────────────────────────────────────────────
SPLUNK_HOST = "https://10.0.2.2:8089"
USERNAME = "liznyime"
PASSWORD = "Mslizzy30"  # Replace with your Splunk password

SEARCHES = [
    {
        "name": "Failed Login Summary",
        "query": 'search index=main sourcetype=linux_secure "Failed password" | rex field=_raw "from (?P<src_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)" | stats count as attempts by src_ip | sort -attempts | head 5'
    },
    {
        "name": "Malicious Process Executions",
        "query": 'search index=main "EventID=4688" "Category=malicious" | rex field=_raw "(?P<hostname>\\S+)\\sEventID" | rex field=_raw "Process=(?P<process>[^\\s]+)" | stats count by hostname, process | sort -count | head 5'
    },
    {
        "name": "Suspicious Network Connections",
        "query": 'search index=main "EventID=5156" | rex field=_raw "dst=(?P<dst_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)" | rex field=_raw "dport=(?P<port>\\d+)" | stats count by dst_ip, port | sort -count | head 5'
    },
]

def run_search(session, query, name):
    print(f"\n Running: {name}")
    print(f" Query  : {query[:60]}...")

    # Submit search job
    response = session.post(
        f"{SPLUNK_HOST}/services/search/jobs",
        data={
            "search": query,
            "output_mode": "json",
            "exec_mode": "normal"
        },
        verify=False
    )

    if response.status_code != 201:
        print(f" ERROR: {response.status_code} — {response.text[:100]}")
        return None

    sid = response.json()["sid"]
    print(f" Job ID : {sid}")

    # Poll until complete
    while True:
        status = session.get(
            f"{SPLUNK_HOST}/services/search/jobs/{sid}",
            params={"output_mode": "json"},
            verify=False
        )
        state = status.json()["entry"][0]["content"]["dispatchState"]
        if state == "DONE":
            break
        elif state == "FAILED":
            print(" Search FAILED")
            return None
        time.sleep(1)

    # Retrieve results
    results = session.get(
        f"{SPLUNK_HOST}/services/search/jobs/{sid}/results",
        params={"output_mode": "json", "count": 10},
        verify=False
    )

    return results.json().get("results", [])

print("\n" + "="*60)
print("      SPLUNK API AUTOMATION — SOC QUERY RUNNER")
print("="*60)

# Authenticate
session = requests.Session()
session.auth = (USERNAME, PASSWORD)

auth_test = session.get(
    f"{SPLUNK_HOST}/services/authentication/current-context",
    params={"output_mode": "json"},
    verify=False
)

if auth_test.status_code != 200:
    print(f"\n Authentication FAILED: {auth_test.status_code}")
    exit()

print(f"\n Connected to Splunk as: {USERNAME}")
print(f" Host: {SPLUNK_HOST}")

all_results = {}

for search in SEARCHES:
    results = run_search(session, search["query"], search["name"])
    if results is not None:
        all_results[search["name"]] = results
        print(f"\n Results for: {search['name']}")
        print(" " + "-"*40)
        for row in results:
            print(f"   {row}")
    else:
        print(f" No results for {search['name']}")

# Save results
with open("splunk_results.json", "w") as f:
    json.dump({
        "run_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "host": SPLUNK_HOST,
        "results": all_results
    }, f, indent=2)

print("\n" + "="*60)
print(f" Searches completed: {len(SEARCHES)}")
print(f" Results saved to  : splunk_results.json")
print("="*60 + "\n")

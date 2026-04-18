import socket
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

TARGET = TARGET = "127.0.0.1"  # Legal public target for testing
PORTS = range(1, 1025)      # Scan well-known ports 1-1024
TIMEOUT = 1                  # Seconds to wait per port
THREADS = 100                # Concurrent threads

open_ports = []
closed_ports = 0

def scan_port(port):
    global closed_ports
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((TARGET, port))
        sock.close()
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except:
                service = "unknown"
            open_ports.append((port, service))
    except:
        pass

print("\n" + "="*55)
print("           PYTHON PORT SCANNER")
print("="*55)
print(f"\n Target   : {TARGET}")

try:
    target_ip = socket.gethostbyname(TARGET)
    print(f" IP       : {target_ip}")
except socket.gaierror:
    print(" ERROR    : Could not resolve hostname")
    sys.exit()

print(f" Ports    : 1-1024")
print(f" Threads  : {THREADS}")
print(f" Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("\n Scanning...\n")

start_time = datetime.now()

with ThreadPoolExecutor(max_workers=THREADS) as executor:
    executor.map(scan_port, PORTS)

end_time = datetime.now()
duration = (end_time - start_time).seconds

open_ports.sort()

print(f" {'PORT':<8} {'SERVICE':<20} {'STATUS'}")
print(" " + "-"*40)

for port, service in open_ports:
    print(f" {port:<8} {service:<20} OPEN")

print("\n" + "="*55)
print(f" Open ports found : {len(open_ports)}")
print(f" Scan duration    : {duration} seconds")
print(f" Completed        : {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
print("="*55 + "\n")

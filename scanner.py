import socket
import threading
import csv
from datetime import datetime
import requests

# Configuration (Remove emoji to prevent encoding issues)
TARGET_IP = "192.168.56.1"  # Change to target IP
PORT_RANGE = (20, 100)    # Well-known ports
THREADS = 50              # Concurrent threads
TIMEOUT = 1               # Socket timeout
OUTPUT_FILE = "scan_results.csv"

# Common Vulnerabilities Database
VULNERABLE_SERVICES = {
    "21": "FTP Anonymous Login Possible",
    "22": "Weak SSH Encryption (CVE-2020-15778)",
    "80": "Outdated Apache (CVE-2021-41773)",
    "443": "Heartbleed (CVE-2014-0160)",
    "3389": "RDP BlueKeep (CVE-2019-0708)"
}

def scan_port(ip, port):
    """Scans a single port and checks for vulnerabilities."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(TIMEOUT)
            result = sock.connect_ex((ip, port))
            
            if result == 0:  # Port is open
                service = get_service_name(port)
                vuln = check_vulnerabilities(port, service)
                
                print(f"[+] Port {port} ({service}) is OPEN | {vuln}")
                return (port, service, "OPEN", vuln)
                
    except Exception as e:
        print(f"[-] Error scanning port {port}: {str(e)[:50]}...")
    return None

def get_service_name(port):
    """Returns the service name (HTTP, SSH, etc.)"""
    try:
        return socket.getservbyport(port, "tcp").upper()
    except:
        return "UNKNOWN"

def check_vulnerabilities(port, service):
    """Checks if the service has known vulnerabilities."""
    port_str = str(port)
    return VULNERABLE_SERVICES.get(port_str, "No known vulnerabilities")

def save_results(results):
    """Saves scan results to CSV."""
    headers = ["PORT", "SERVICE", "STATUS", "VULNERABILITIES"]
    with open(OUTPUT_FILE, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        writer.writerows([r for r in results if r])
    print(f"\n[+] Results saved to {OUTPUT_FILE}")

def main():
    print(f"Scanning {TARGET_IP} from port {PORT_RANGE[0]} to {PORT_RANGE[1]}\n")
    open_ports = []
    threads = []
    
    for port in range(PORT_RANGE[0], PORT_RANGE[1] + 1):
        thread = threading.Thread(
            target=lambda p=port: open_ports.append(scan_port(TARGET_IP, p))
        )
        thread.start()
        threads.append(thread)
        
        # Limit active threads
        if len(threads) >= THREADS:
            for t in threads:
                t.join()
            threads = []
    
    # Wait for remaining threads
    for t in threads:
        t.join()
    
    save_results(open_ports)

if __name__ == "__main__":
    main()
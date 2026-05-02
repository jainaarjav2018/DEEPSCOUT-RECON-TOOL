import csv
import socket
import whois
import requests
import dns.resolver
from scapy.all import sr1, IP, TCP

# Helper function to load subdomains from a CSV file
def load_subdomains(filename):
    subdomains = []
    try:
        with open(filename, 'r') as file:
            reader = csv.reader(file)
            for row in reader:
                subdomains.append(row[0].strip())
    except Exception as e:
        print(f"Error loading subdomains from {filename}: {e}")
    return subdomains

# WHOIS Lookup
def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        return w
    except Exception as e:
        return {"Error": f"WHOIS lookup failed: {e}"}

# Fetch HTTP Headers
def fetch_http_headers(url):
    try:
        response = requests.get(url, timeout=5)
        return dict(response.headers)
    except Exception as e:
        return {"Error": f"Failed to fetch headers: {e}"}

# Get Server IP Address
def get_server_ip(domain):
    try:
        result = dns.resolver.query(domain, 'A')  # Updated from resolve to query
        return [ip.address for ip in result]
    except Exception as e:
        return {"Error": f"Failed to retrieve IP: {e}"}

# DNS Enumeration
def dns_enumeration(domain):
    records = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
    dns_data = {}
    try:
        for record in records:
            try:
                answers = dns.resolver.query(domain, record)  # Updated from resolve to query
                dns_data[record] = [rdata.to_text() for rdata in answers]
            except dns.resolver.NoAnswer:
                dns_data[record] = "No answer for this record type."
            except dns.resolver.NXDOMAIN:
                dns_data[record] = "The domain does not exist."
            except Exception as e:
                dns_data[record] = f"Error: {e}"
        return dns_data
    except Exception as e:
        return {"Error": f"DNS enumeration failed: {e}"}

# Port Scanning
def port_scan(domain, ports):
    try:
        ip = socket.gethostbyname(domain)
        open_ports = []
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        return open_ports
    except Exception as e:
        return {"Error": f"Port scan failed: {e}"}

# Service Scanning
def service_scan(domain, open_ports):
    services = []
    if open_ports:
        for port in open_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((domain, port))
                if port == 21:  # FTP port
                    sock.send(b'USER anonymous\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                else:
                    request = b"HEAD / HTTP/1.1\r\nHost: " + domain.encode() + b"\r\n\r\n"
                    sock.send(request)
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                services.append(f"Port {port}: {banner}")
                sock.close()
            except Exception as e:
                services.append(f"Port {port}: Service detection failed ({e})")
    return services

# Firewall Detection
def detect_firewall(domain):
    try:
        ip = socket.gethostbyname(domain)
        ports = [80, 443]  # Common ports to check
        for port in ports:
            syn_packet = IP(dst=ip) / TCP(dport=port, flags="S")
            response = sr1(syn_packet, timeout=2, verbose=0)
            
            if response is None:
                return f"Firewall detected: No response received on port {port}."
            elif response.haslayer(TCP):
                tcp_layer = response.getlayer(TCP)
                if tcp_layer.flags == 0x14:  # TCP RST (Reset) flag
                    return f"Firewall detected: Port {port} closed by firewall."
                elif tcp_layer.flags == 0x12:  # SYN-ACK flag
                    return f"No firewall detected: Port {port} is open."
        return "Firewall detection inconclusive."
    except Exception as e:
        return f"Firewall detection failed: {e}"

# Load Balancer Detection
def detect_load_balancer(domain):
    try:
        url = f"https://{domain}"
        response = requests.get(url, timeout=5)
        headers = response.headers

        # Check for load balancer indicators
        load_balancer_headers = ['via', 'x-forwarded-for', 'x-forwarded-host', 'x-amz-id-2', 'x-amz-request-id', 'x-cache']
        for header in load_balancer_headers:
            if header.lower() in [h.lower() for h in headers]:
                return f"Load balancer detected: {header} present in headers."
        return "No load balancer detected."
    except Exception as e:
        return f"Load balancer detection failed: {e}"

# Simple HTTP Fuzzing
def fuzzing(domain):
    common_paths = ["/admin", "/login", "/test", "/backup"]
    fuzz_results = {}
    try:
        for path in common_paths:
            url = f"https://{domain}{path}"
            response = requests.get(url, timeout=5)
            fuzz_results[path] = response.status_code
        return fuzz_results
    except Exception as e:
        return {"Error": f"Fuzzing failed: {e}"}

# Subdomain Scanning with Hijacking Check
def subdomain_scan(domain):
    subdomains = load_subdomains('subdomains.csv')
    existing_subdomains = []
    hijacked_subdomains = []
    try:
        for sub in subdomains:
            subdomain = f"{sub}.{domain}"
            try:
                response = requests.get(f"http://{subdomain}", timeout=5)
                if response.status_code == 404 or "not found" in response.text.lower():
                    hijacked_subdomains.append(subdomain)
                else:
                    existing_subdomains.append(subdomain)
            except (socket.gaierror, requests.RequestException):
                continue
        if not existing_subdomains:
            existing_subdomains.append("No subdomains exist.")
        return {
            "existing": existing_subdomains,
            "hijacked": hijacked_subdomains
        }
    except Exception as e:
        return {"Error": f"Subdomain scanning failed: {e}"}

# Basic Vulnerability Scanning (Enhanced HTTP checks)
def vulnerability_scan(domain):
    common_vulnerabilities = {
        "/.git/": "Exposed Git Repository",
        "/.env": "Exposed Environment Variables",
        "/wp-admin": "Potential WordPress Admin Page",
        "/phpinfo.php": "Exposed PHP Info Page",
        "/backup": "Backup Directory",
        "/admin": "Admin Page",
        "/login": "Login Page",
        "/test": "Test Directory",
        "/config": "Configuration File",
        "/database": "Database File",
        "/.htaccess": "Exposed .htaccess File"
    }
    vulnerability_results = {}
    try:
        for path, vuln in common_vulnerabilities.items():
            url = f"https://{domain}{path}"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                vulnerability_results[path] = vuln
        if not vulnerability_results:
            return "No vulnerabilities detected."
        return vulnerability_results
    except Exception as e:
        return {"Error": f"Vulnerability scanning failed: {e}"}

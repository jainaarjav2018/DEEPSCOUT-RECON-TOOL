from flask import Flask, render_template, request
import recon_tool  # Import the recon functions

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/recon', methods=['POST'])
def recon():
    domain = request.form['domain']
    url = f"https://{domain}"

    whois_data = recon_tool.whois_lookup(domain)
    headers_data = None
    if 'http_headers' in request.form:
        headers_data = recon_tool.fetch_http_headers(url)
    server_ip = recon_tool.get_server_ip(domain)
    
    open_ports = None
    service_info = None
    firewall_detected = None
    loadbalancer_detected = None
    dns_enum_data = None
    fuzzing_results = None
    subdomain_results = None
    vulnerability_results = None
    subdomain_hijack_results = None

    if 'port_scan' in request.form:
        open_ports = recon_tool.port_scan(domain, [80, 443, 21, 22, 8080])

    if 'service_scan' in request.form:
        service_info = recon_tool.service_scan(domain, open_ports)

    if 'firewall_scan' in request.form:
        firewall_detected = recon_tool.detect_firewall(domain)

    if 'loadbalancer_scan' in request.form:
        loadbalancer_detected = recon_tool.detect_load_balancer(domain)

    if 'dns_enum' in request.form:
        dns_enum_data = recon_tool.dns_enumeration(domain)

    if 'fuzzing' in request.form:
        fuzzing_results = recon_tool.fuzzing(domain)

    if 'subdomain_scan' in request.form:
        subdomain_results = recon_tool.subdomain_scan(domain)

    if 'subdomain_hijack' in request.form:
        subdomain_hijack_results = recon_tool.subdomain_scan(domain)  # Reuse subdomain_scan for hijacking check

    if 'vulnerability_scan' in request.form:
        vulnerability_results = recon_tool.vulnerability_scan(domain)

    return render_template('index.html',
                           whois_data=whois_data,
                           headers_data=headers_data,
                           server_ip=server_ip,
                           open_ports=open_ports,
                           service_info=service_info,
                           firewall_detected=firewall_detected,
                           loadbalancer_detected=loadbalancer_detected,
                           dns_enum_data=dns_enum_data,
                           fuzzing_results=fuzzing_results,
                           subdomain_results=subdomain_results,
                           subdomain_hijack_results=subdomain_hijack_results,
                           vulnerability_results=vulnerability_results,
                           domain=domain)

if __name__ == '__main__':
    app.run(debug=True)

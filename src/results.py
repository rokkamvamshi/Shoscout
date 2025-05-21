# results.py - Manage and process scan results

import os
import json
import csv
import datetime
import time
import logging

class ResultsManager:
    def __init__(self, output_dir, quiet=False, verbose=False):
        self.output_dir = output_dir
        self.quiet = quiet
        self.verbose = verbose
        self.results = {
            'scan_info': {
                'timestamp': int(time.time()),
                'date': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            },
            'domains': [],
            'subdomains': {},
            'ips': {},
            'open_ports': {},
            'services': {},
            'vulnerabilities': {}
        }
        
        # Create output directories
        self._create_output_dirs()
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
    
    def _create_output_dirs(self):
        """Create necessary output directories"""
        # Main output directory
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Subdirectories for different result types
        subdirs = ['subdomains', 'ports', 'services', 'vulnerabilities', 'reports']
        for subdir in subdirs:
            os.makedirs(os.path.join(self.output_dir, subdir), exist_ok=True)
    
    def set_domains(self, domains):
        """Store the target domains"""
        self.results['domains'] = domains
    
    def save_subdomains(self, subdomains):
        """Save discovered subdomains"""
        if not subdomains:
            return
        
        # Store in memory
        self.results['subdomains'] = list(subdomains)
        
        # Save to file
        subdomain_file = os.path.join(self.output_dir, 'subdomains', 'subdomains.txt')
        with open(subdomain_file, 'w') as f:
            for subdomain in sorted(subdomains):
                f.write(f"{subdomain}\n")
        
        print(f"[+] Saved {len(subdomains)} subdomains to {subdomain_file}")
    
    def save_ips(self, ip_mapping):
        """Save IP address mapping"""
        if not ip_mapping:
            return
        
        # Store in memory
        self.results['ips'] = ip_mapping
        
        # Save to file
        ip_file = os.path.join(self.output_dir, 'subdomains', 'ip_mapping.csv')
        with open(ip_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Subdomain', 'IP'])
            for subdomain, ip in ip_mapping.items():
                writer.writerow([subdomain, ip])
        
        print(f"[+] Saved {len(ip_mapping)} IP mappings to {ip_file}")
    
    def save_open_ports(self, open_ports):
        """Save open ports results"""
        if not open_ports:
            return
        
        # Store in memory
        self.results['open_ports'] = open_ports
        
        # Save to JSON file
        ports_file = os.path.join(self.output_dir, 'ports', 'open_ports.json')
        with open(ports_file, 'w') as f:
            json.dump(open_ports, f, indent=4)
        
        # Save to CSV for easier viewing
        csv_file = os.path.join(self.output_dir, 'ports', 'open_ports.csv')
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Host', 'Protocol', 'Port', 'Service', 'Product', 'Version'])
            
            for host, port_data in open_ports.items():
                for proto in port_data:
                    for port, service in port_data[proto].items():
                        writer.writerow([
                            host,
                            proto,
                            port,
                            service.get('name', ''),
                            service.get('product', ''),
                            service.get('version', '')
                        ])
        
        print(f"[+] Saved open ports results to {ports_file} and {csv_file}")
    
    def save_service_results(self, service_results):
        """Save service analysis results"""
        if not service_results:
            return
        
        # Store in memory
        self.results['services'] = service_results
        
        # Save to JSON file
        services_file = os.path.join(self.output_dir, 'services', 'services.json')
        with open(services_file, 'w') as f:
            json.dump(service_results, f, indent=4)
        
        # Extract and save web services to CSV
        web_services = []
        for host, service_types in service_results.items():
            if 'web' in service_types:
                for port, web_info in service_types['web'].items():
                    web_services.append({
                        'host': host,
                        'port': port,
                        'title': web_info.get('title', ''),
                        'server': web_info.get('server', ''),
                        'technologies': ', '.join(web_info.get('technologies', []))
                    })
        
        if web_services:
            web_csv = os.path.join(self.output_dir, 'services', 'web_services.csv')
            with open(web_csv, 'w', newline='') as f:
                fieldnames = ['host', 'port', 'title', 'server', 'technologies']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for service in web_services:
                    writer.writerow(service)
        
        print(f"[+] Saved service analysis results to {services_file}")
    
    def save_vulnerabilities(self, vulnerabilities):
        """Save vulnerability check results"""
        if not vulnerabilities:
            return
        
        # Store in memory
        self.results['vulnerabilities'] = vulnerabilities
        
        # Save to JSON file
        vulns_file = os.path.join(self.output_dir, 'vulnerabilities', 'vulnerabilities.json')
        with open(vulns_file, 'w') as f:
            json.dump(vulnerabilities, f, indent=4)
        
        # Extract and save findings to CSV
        findings = []
        for host, vuln_types in vulnerabilities.items():
            # Process web vulnerabilities
            if 'web' in vuln_types:
                for port, web_vulns in vuln_types['web'].items():
                    for vuln_name, vuln_details in web_vulns.items():
                        findings.append({
                            'host': host,
                            'port': port,
                            'type': 'web',
                            'vulnerability': vuln_name,
                            'details': str(vuln_details)[:100]  # Truncate for CSV
                        })
            
            # Process SSL vulnerabilities
            if 'ssl' in vuln_types:
                for port, ssl_vulns in vuln_types['ssl'].items():
                    for vuln_name, vuln_details in ssl_vulns.items():
                        findings.append({
                            'host': host,
                            'port': port,
                            'type': 'ssl',
                            'vulnerability': vuln_name,
                            'details': str(vuln_details)[:100]  # Truncate for CSV
                        })
            
            # Process Shodan results
            if 'shodan' in vuln_types:
                shodan_vulns = vuln_types['shodan']
                if 'cves' in shodan_vulns:
                    for cve in shodan_vulns['cves']:
                        findings.append({
                            'host': host,
                            'port': 'N/A',
                            'type': 'shodan',
                            'vulnerability': cve,
                            'details': 'Detected by Shodan'
                        })
        
        if findings:
            findings_csv = os.path.join(self.output_dir, 'vulnerabilities', 'findings.csv')
            with open(findings_csv, 'w', newline='') as f:
                fieldnames = ['host', 'port', 'type', 'vulnerability', 'details']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for finding in findings:
                    writer.writerow(finding)
        
        print(f"[+] Saved vulnerability results to {vulns_file}")
    
    def generate_summary(self):
        """Generate summary report of all findings"""
        # Save full results to JSON
        results_file = os.path.join(self.output_dir, 'results.json')
        with open(results_file, 'w') as f:
            json.dump(self.results, f, indent=4)
        
        # Generate readable HTML report
        self._generate_html_report()
        
        # Generate text summary
        self._generate_text_summary()
        
        print(f"[+] Generated summary reports in {self.output_dir}/reports/")
    
    def _generate_html_report(self):
        """Generate an HTML report of findings"""
        # Create a basic HTML report
        html_file = os.path.join(self.output_dir, 'reports', 'report.html')
        
        # Get counts for stats
        subdomain_count = len(self.results.get('subdomains', []))
        ip_count = len(self.results.get('ips', {}))
        open_port_count = sum(len(ports.get('tcp', {})) for ports in self.results.get('open_ports', {}).values())
        
        # Count vulnerabilities
        vuln_count = 0
        high_vuln_count = 0
        for host_vulns in self.results.get('vulnerabilities', {}).values():
            # Count web vulnerabilities
            for port_vulns in host_vulns.get('web', {}).values():
                vuln_count += len(port_vulns)
                # Consider XSS, SQLi, and open redirect as high severity
                if 'xss' in port_vulns or 'sqli' in port_vulns or 'open_redirect' in port_vulns:
                    high_vuln_count += 1
            
            # Count SSL vulnerabilities
            for port_vulns in host_vulns.get('ssl', {}).values():
                vuln_count += len(port_vulns)
                # Consider heartbleed as high severity
                if 'heartbleed' in port_vulns:
                    high_vuln_count += 1
            
            # Count Shodan CVEs
            if 'shodan' in host_vulns and 'cves' in host_vulns['shodan']:
                vuln_count += len(host_vulns['shodan']['cves'])
                # Approximate high severity count (could be more sophisticated)
                high_vuln_count += len([cve for cve in host_vulns['shodan']['cves'] if 'CVE-' in cve])
        
        # Create HTML content
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>BountyScout Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; }}
                h1 {{ color: #2c3e50; }}
                h2 {{ color: #3498db; margin-top: 20px; }}
                .summary {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
                .stats {{ display: flex; flex-wrap: wrap; }}
                .stat-box {{ background-color: #fff; border: 1px solid #ddd; border-radius: 5px; 
                           padding: 15px; margin: 10px; flex: 1 0 200px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .stat-value {{ font-size: 24px; font-weight: bold; margin: 10px 0; }}
                .findings {{ margin-top: 20px; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                tr:nth-child(even) {{ background-color: #f9f9f9; }}
                .high {{ color: #e74c3c; }}
                .medium {{ color: #f39c12; }}
                .low {{ color: #3498db; }}
            </style>
        </head>
        <body>
            <h1>BountyScout Scan Report</h1>
            <div class="summary">
                <p>Scan completed on {self.results['scan_info']['date']}</p>
                <div class="stats">
                    <div class="stat-box">
                        <h3>Subdomains</h3>
                        <div class="stat-value">{subdomain_count}</div>
                    </div>
                    <div class="stat-box">
                        <h3>IPs</h3>
                        <div class="stat-value">{ip_count}</div>
                    </div>
                    <div class="stat-box">
                        <h3>Open Ports</h3>
                        <div class="stat-value">{open_port_count}</div>
                    </div>
                    <div class="stat-box">
                        <h3>Vulnerabilities</h3>
                        <div class="stat-value">{vuln_count}</div>
                        <div>High Severity: <span class="high">{high_vuln_count}</span></div>
                    </div>
                </div>
            </div>
        """
        
        # Add vulnerability findings
        if self.results.get('vulnerabilities'):
            html_content += """
            <h2>Key Findings</h2>
            <div class="findings">
                <table>
                    <tr>
                        <th>Host</th>
                        <th>Port</th>
                        <th>Type</th>
                        <th>Vulnerability</th>
                        <th>Severity</th>
                    </tr>
            """
            
            # Add rows for findings
            for host, vuln_types in self.results.get('vulnerabilities', {}).items():
                # Process web vulnerabilities
                for port, web_vulns in vuln_types.get('web', {}).items():
                    for vuln_name in web_vulns:
                        # Determine severity
                        severity = "High" if vuln_name in ['xss', 'sqli', 'open_redirect'] else "Medium"
                        severity_class = "high" if severity == "High" else "medium"
                        
                        html_content += f"""
                        <tr>
                            <td>{host}</td>
                            <td>{port}</td>
                            <td>Web</td>
                            <td>{vuln_name}</td>
                            <td class="{severity_class}">{severity}</td>
                        </tr>
                        """
                
                # Process SSL vulnerabilities
                for port, ssl_vulns in vuln_types.get('ssl', {}).items():
                    for vuln_name in ssl_vulns:
                        # Determine severity
                        severity = "High" if vuln_name == 'heartbleed' else "Medium"
                        severity_class = "high" if severity == "High" else "medium"
                        
                        html_content += f"""
                        <tr>
                            <td>{host}</td>
                            <td>{port}</td>
                            <td>SSL/TLS</td>
                            <td>{vuln_name}</td>
                            <td class="{severity_class}">{severity}</td>
                        </tr>
                        """
                
                # Process Shodan findings
                if 'shodan' in vuln_types and 'cves' in vuln_types['shodan']:
                    for cve in vuln_types['shodan']['cves']:
                        html_content += f"""
                        <tr>
                            <td>{host}</td>
                            <td>N/A</td>
                            <td>Shodan</td>
                            <td>{cve}</td>
                            <td class="high">High</td>
                        </tr>
                        """
            
            html_content += """
                </table>
            </div>
            """
        
        # Close HTML document
        html_content += """
        </body>
        </html>
        """
        
        # Write to file
        with open(html_file, 'w') as f:
            f.write(html_content)
    
    def _generate_text_summary(self):
        """Generate a plain text summary"""
        summary_file = os.path.join(self.output_dir, 'reports', 'summary.txt')
        
        with open(summary_file, 'w') as f:
            f.write("BountyScout Scan Summary\n")
            f.write("=======================\n\n")
            f.write(f"Scan completed on {self.results['scan_info']['date']}\n\n")
            
            # Domain stats
            f.write("DOMAINS SCANNED\n")
            f.write("--------------\n")
            for domain in self.results.get('domains', []):
                f.write(f"- {domain}\n")
            f.write("\n")
            
            # Subdomain stats
            subdomains = self.results.get('subdomains', [])
            f.write(f"SUBDOMAINS: {len(subdomains)}\n")
            f.write("--------------\n")
            for i, subdomain in enumerate(sorted(subdomains)[:10]):  # Show only first 10
                f.write(f"- {subdomain}\n")
            if len(subdomains) > 10:
                f.write(f"... and {len(subdomains) - 10} more\n")
            f.write("\n")
            
            # Open ports
            open_ports = self.results.get('open_ports', {})
            total_ports = sum(len(ports.get('tcp', {})) for ports in open_ports.values())
            f.write(f"OPEN PORTS: {total_ports}\n")
            f.write("--------------\n")
            for host, ports in open_ports.items():
                tcp_ports = ports.get('tcp', {})
                if tcp_ports:
                    f.write(f"- {host}: " + ", ".join(str(p) for p in tcp_ports.keys()) + "\n")
            f.write("\n")
            
            # Vulnerabilities
            vulnerabilities = self.results.get('vulnerabilities', {})
            f.write("VULNERABILITIES\n")
            f.write("--------------\n")
            if vulnerabilities:
                for host, vuln_types in vulnerabilities.items():
                    f.write(f"Host: {host}\n")
                    
                    # Web vulnerabilities
                    if 'web' in vuln_types:
                        for port, web_vulns in vuln_types['web'].items():
                            for vuln_name in web_vulns:
                                f.write(f"  - Web ({port}): {vuln_name}\n")
                    
                    # SSL vulnerabilities
                    if 'ssl' in vuln_types:
                        for port, ssl_vulns in vuln_types['ssl'].items():
                            for vuln_name in ssl_vulns:
                                f.write(f"  - SSL ({port}): {vuln_name}\n")
                    
                    # Shodan vulnerabilities
                    if 'shodan' in vuln_types and 'cves' in vuln_types['shodan']:
                        for cve in vuln_types['shodan']['cves']:
                            f.write(f"  - Shodan: {cve}\n")
                    
                    f.write("\n")
            else:
                f.write("No vulnerabilities found.\n\n")
            
            # Recommendations
            f.write("RECOMMENDATIONS\n")
            f.write("--------------\n")
            self._generate_recommendations(f)
    
    def _generate_recommendations(self, f):
        """Generate security recommendations based on findings"""
        vulnerabilities = self.results.get('vulnerabilities', {})
        
        # Track which recommendations we've already given
        given_recommendations = set()
        
        if not vulnerabilities:
            f.write("- No specific recommendations based on findings.\n")
            f.write("- Consider implementing regular security scans and maintaining patch levels.\n")
            return
        
        for host, vuln_types in vulnerabilities.items():
            # Web vulnerability recommendations
            if 'web' in vuln_types:
                for port, web_vulns in vuln_types['web'].items():
                    for vuln_name in web_vulns:
                        if vuln_name == 'xss' and 'xss' not in given_recommendations:
                            f.write("- XSS vulnerabilities detected. Implement proper input validation and output encoding.\n")
                            given_recommendations.add('xss')
                        
                        elif vuln_name == 'sqli' and 'sqli' not in given_recommendations:
                            f.write("- SQL Injection vulnerabilities detected. Use parameterized queries and input validation.\n")
                            given_recommendations.add('sqli')
                        
                        elif vuln_name == 'open_redirect' and 'open_redirect' not in given_recommendations:
                            f.write("- Open Redirect vulnerabilities detected. Implement URL validation and whitelist approach.\n")
                            given_recommendations.add('open_redirect')
                        
                        elif vuln_name == 'cors_misconfig' and 'cors_misconfig' not in given_recommendations:
                            f.write("- CORS misconfigurations detected. Restrict 'Access-Control-Allow-Origin' to trusted domains.\n")
                            given_recommendations.add('cors_misconfig')
                        
                        elif vuln_name == 'exposed_git' and 'exposed_git' not in given_recommendations:
                            f.write("- Exposed Git repositories detected. Remove .git directories from web-accessible locations.\n")
                            given_recommendations.add('exposed_git')
            
            # SSL vulnerability recommendations
            if 'ssl' in vuln_types:
                for port, ssl_vulns in vuln_types['ssl'].items():
                    for vuln_name in ssl_vulns:
                        if vuln_name == 'weak_protocol' and 'weak_protocol' not in given_recommendations:
                            f.write("- Weak SSL/TLS protocol versions detected. Disable SSLv2/SSLv3 and consider TLS 1.2+ only.\n")
                            given_recommendations.add('weak_protocol')
                        
                        elif vuln_name == 'weak_ciphers' and 'weak_ciphers' not in given_recommendations:
                            f.write("- Weak ciphers detected. Update cipher configuration to use strong ciphers only.\n")
                            given_recommendations.add('weak_ciphers')
                        
                        elif vuln_name == 'heartbleed' and 'heartbleed' not in given_recommendations:
                            f.write("- Heartbleed vulnerability detected. Update OpenSSL to the latest version immediately.\n")
                            given_recommendations.add('heartbleed')
            
            # General recommendations for CVEs
            if 'shodan' in vuln_types and 'cves' in vuln_types['shodan'] and 'cves' not in given_recommendations:
                f.write("- Multiple CVEs detected by Shodan. Implement a regular patching schedule.\n")
                given_recommendations.add('cves')
        
        # General recommendations
        if 'general' not in given_recommendations:
            f.write("- Implement a proper security program including regular scanning and monitoring.\n")
            f.write("- Develop and test an incident response plan for security breaches.\n")
            f.write("- Consider implementing a bug bounty program to continuously identify vulnerabilities.\n")
            given_recommendations.add('general')
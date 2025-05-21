# enumerator.py - Subdomain enumeration functionality

import dns.resolver
import dns.zone
import requests
import concurrent.futures
from tqdm import tqdm

class Enumerator:
    def __init__(self, shodan_client=None):
        self.shodan_client = shodan_client
        self.subdomains = set()
        self.ip_mapping = {}
        
    def enumerate_targets(self, domains):
        """Enumerate subdomains for a list of domains"""
        print(f"[+] Starting subdomain enumeration for {len(domains)} domain(s)")
        
        all_subdomains = set()
        all_ips = {}
        
        for domain in domains:
            print(f"[+] Enumerating subdomains for {domain}")
            self.subdomains = set()
            self.ip_mapping = {}
            
            # Perform various enumeration techniques
            self._enumerate_dns(domain)
            self._enumerate_certificate_transparency(domain)
            
            # Use Shodan if available
            if self.shodan_client:
                self._enumerate_shodan(domain)
            
            # Resolve IPs for discovered subdomains
            self._resolve_ips()
            
            print(f"[+] Found {len(self.subdomains)} subdomains for {domain}")
            all_subdomains.update(self.subdomains)
            all_ips.update(self.ip_mapping)
        
        return all_subdomains, all_ips
    
    def _enumerate_dns(self, domain):
        """Perform DNS-based enumeration"""
        # Try zone transfer (usually blocked but worth trying)
        try:
            nameservers = dns.resolver.resolve(domain, 'NS')
            for ns in nameservers:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(str(ns), domain))
                    for name, _ in zone.nodes.items():
                        subdomain = f"{name}.{domain}".rstrip('.')
                        if subdomain != domain:
                            self.subdomains.add(subdomain)
                except:
                    pass  # Zone transfer likely blocked
        except:
            pass  # DNS resolution failed
            
        # Common subdomain bruteforce
        common_subdomains = [
            'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2',
            'smtp', 'secure', 'vpn', 'admin', 'mx', 'ftp', 'api', 'dev', 'staging',
            'test', 'portal', 'beta', 'dashboard', 'intranet', 'internal'
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(self._check_subdomain, f"{sub}.{domain}") for sub in common_subdomains]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self.subdomains.add(result)
    
    def _enumerate_certificate_transparency(self, domain):
        """Use certificate transparency logs to find subdomains"""
        try:
            ct_url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(ct_url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '').lower()
                    # Handle wildcards and parse common name format
                    if name.startswith('*.'):
                        name = name[2:]
                    # Add all unique subdomains
                    if domain in name:
                        self.subdomains.add(name)
        except:
            print(f"[-] Error retrieving certificate transparency data for {domain}")
    
    def _enumerate_shodan(self, domain):
        """Use Shodan for enumeration"""
        try:
            results = self.shodan_client.search_domain(domain)
            for result in results:
                if 'hostnames' in result:
                    for hostname in result['hostnames']:
                        if domain in hostname:
                            self.subdomains.add(hostname)
                if 'ip_str' in result and 'hostnames' in result:
                    for hostname in result['hostnames']:
                        if domain in hostname:
                            self.ip_mapping[hostname] = result['ip_str']
        except:
            print(f"[-] Error retrieving Shodan data for {domain}")
    
    def _check_subdomain(self, subdomain):
        """Check if a subdomain exists"""
        try:
            dns.resolver.resolve(subdomain, 'A')
            return subdomain
        except:
            return None
    
    def _resolve_ips(self):
        """Resolve IP addresses for all discovered subdomains"""
        print(f"[+] Resolving IP addresses for {len(self.subdomains)} subdomains")
        for subdomain in tqdm(self.subdomains):
            if subdomain not in self.ip_mapping:
                try:
                    answers = dns.resolver.resolve(subdomain, 'A')
                    self.ip_mapping[subdomain] = str(answers[0])
                except:
                    pass  # Failed to resolve
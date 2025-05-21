# shodan_client.py - Interface with Shodan API

import yaml
import shodan
import os
import time

class ShodanClient:
    def __init__(self, config_path):
        self.api_key = None
        self.client = None
        self.load_config(config_path)
        self.initialize_client()
    
    def load_config(self, config_path):
        """Load Shodan API key from config file"""
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = yaml.safe_load(f)
                self.api_key = config.get('shodan', {}).get('api_key')
            else:
                print("[-] Shodan config file not found. Some functionality will be limited.")
        except Exception as e:
            print(f"[-] Error loading Shodan config: {e}")
    
    def initialize_client(self):
        """Initialize Shodan client with API key"""
        if self.api_key:
            try:
                self.client = shodan.Shodan(self.api_key)
                print("[+] Shodan API initialized successfully")
            except Exception as e:
                print(f"[-] Error initializing Shodan client: {e}")
                self.client = None
        else:
            print("[-] No Shodan API key provided. Shodan functionality disabled.")
    
    def search_domain(self, domain):
        """Search Shodan for information about a domain"""
        if not self.client:
            return []
        
        try:
            # Use hostname search query
            query = f"hostname:{domain}"
            results = self.client.search(query)
            return results.get('matches', [])
        except shodan.APIError as e:
            print(f"[-] Shodan API error: {e}")
            if "request timed out" in str(e).lower():
                print("[*] Waiting 5 seconds before retrying...")
                time.sleep(5)
                try:
                    query = f"hostname:{domain}"
                    results = self.client.search(query)
                    return results.get('matches', [])
                except:
                    return []
            return []
    
    def host_lookup(self, ip):
        """Look up a specific IP address in Shodan"""
        if not self.client:
            return None
        
        try:
            host_info = self.client.host(ip)
            return host_info
        except shodan.APIError as e:
            if "No information available" in str(e):
                return None
            print(f"[-] Shodan API error during host lookup: {e}")
            return None
    
    def check_vulnerabilities(self, ip):
        """Check if an IP has known vulnerabilities according to Shodan"""
        if not self.client:
            return []
        
        try:
            host_info = self.client.host(ip)
            vulnerabilities = host_info.get('vulns', [])
            return vulnerabilities
        except shodan.APIError:
            return []
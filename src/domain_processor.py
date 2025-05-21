# domain_processor.py - Handle domain input processing

import re
import os

class DomainProcessor:
    def __init__(self):
        self.domain_regex = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
    
    def process_single_domain(self, domain):
        """Process a single domain and return as a list"""
        if self.validate_domain(domain):
            return [domain]
        else:
            raise ValueError(f"Invalid domain format: {domain}")
    
    def process_domain_list(self, list_file):
        """Process a file containing a list of domains"""
        if not os.path.exists(list_file):
            raise FileNotFoundError(f"Domain list file not found: {list_file}")
        
        domains = []
        with open(list_file, 'r') as f:
            for line in f:
                domain = line.strip()
                if domain and self.validate_domain(domain):
                    domains.append(domain)
        
        if not domains:
            raise ValueError(f"No valid domains found in {list_file}")
        
        return domains
    
    def validate_domain(self, domain):
        """Validate domain format"""
        # Handle wildcard domains
        if domain.startswith('*.'):
            domain = domain[2:]
        
        return bool(self.domain_regex.match(domain))
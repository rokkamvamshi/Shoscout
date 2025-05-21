#!/usr/bin/env python3
# main.py - Entry point for BountyScout

import argparse
import os
import sys
from src.domain_processor import DomainProcessor
from src.enumerator import Enumerator
from src.port_scanner import PortScanner
from src.service_analyzer import ServiceAnalyzer
from src.vulnerability import VulnerabilityChecker
from src.results import ResultsManager
from src.shodan_client import ShodanClient

def setup_argparse():
    parser = argparse.ArgumentParser(description='BountyScout - A reconnaissance tool for bug bounty hunters')
    parser.add_argument('-d', '--domain', help='Single domain to scan (e.g., example.com)')
    parser.add_argument('-l', '--list', help='File containing list of domains, one per line')
    parser.add_argument('-o', '--output', default='output', help='Output directory for results')
    parser.add_argument('--skip-subdomain', action='store_true', help='Skip subdomain enumeration')
    parser.add_argument('--skip-port-scan', action='store_true', help='Skip port scanning')
    parser.add_argument('--skip-service-check', action='store_true', help='Skip service checking')
    parser.add_argument('--skip-vuln-check', action='store_true', help='Skip vulnerability checking')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    return parser.parse_args()

def main():
    args = setup_argparse()
    
    # Validate input - need either domain or list
    if not args.domain and not args.list:
        print("Error: Must provide either a domain (-d) or domain list file (-l)")
        sys.exit(1)
    
    # Create output directory if it doesn't exist
    os.makedirs(args.output, exist_ok=True)
    
    # Initialize components
    results_manager = ResultsManager(args.output)
    shodan_client = ShodanClient('config/config.yaml')
    domain_processor = DomainProcessor()
    
    # Process domains
    if args.domain:
        domains = domain_processor.process_single_domain(args.domain)
    else:
        domains = domain_processor.process_domain_list(args.list)
    
    # Run the pipeline
    if not args.skip_subdomain:
        enumerator = Enumerator(shodan_client)
        subdomains, ips = enumerator.enumerate_targets(domains)
        results_manager.save_subdomains(subdomains)
        results_manager.save_ips(ips)
    
    if not args.skip_port_scan:
        port_scanner = PortScanner()
        open_ports = port_scanner.scan_targets(ips)
        results_manager.save_open_ports(open_ports)
    
    if not args.skip_service_check:
        service_analyzer = ServiceAnalyzer()
        service_results = service_analyzer.analyze_services(open_ports)
        results_manager.save_service_results(service_results)
    
    if not args.skip_vuln_check:
        vuln_checker = VulnerabilityChecker(shodan_client)
        vulnerabilities = vuln_checker.check_vulnerabilities(ips, open_ports)
        results_manager.save_vulnerabilities(vulnerabilities)
    
    # Generate summary report
    results_manager.generate_summary()
    
    print(f"Scan complete! Results saved to {args.output} directory")

if __name__ == "__main__":
    main()
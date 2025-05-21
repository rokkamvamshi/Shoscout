#!/usr/bin/env python3
# main.py - Entry point for BountyScout

import argparse
import os
import sys
import logging
from src.domain_processor import DomainProcessor
from src.enumerator import Enumerator
from src.port_scanner import PortScanner
from src.service_analyzer import ServiceAnalyzer
from src.vulnerability import VulnerabilityChecker
from src.results import ResultsManager
from src.shodan_client import ShodanClient

# ANSI color codes for colored output
COLORS = {
    'RESET': '\033[0m',
    'RED': '\033[91m',
    'GREEN': '\033[92m',
    'YELLOW': '\033[93m',
    'BLUE': '\033[94m',
    'PURPLE': '\033[95m',
    'CYAN': '\033[96m',
    'WHITE': '\033[97m'
}

# Configure logger
def setup_logging(verbose, quiet):
    """Configure logging based on verbose/quiet flags"""
    # Create custom formatter with colors
    class ColoredFormatter(logging.Formatter):
        def format(self, record):
            levelname = record.levelname
            message = super().format(record)
            
            if levelname == 'INFO':
                return f"{COLORS['GREEN']}{message}{COLORS['RESET']}"
            elif levelname == 'WARNING':
                return f"{COLORS['YELLOW']}{message}{COLORS['RESET']}"
            elif levelname == 'ERROR':
                return f"{COLORS['RED']}{message}{COLORS['RESET']}"
            elif levelname == 'DEBUG':
                return f"{COLORS['BLUE']}{message}{COLORS['RESET']}"
            else:
                return message
    
    # Create logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)  # Base level
    
    # Clear any existing handlers
    logger.handlers = []
    
    # Console handler
    if not quiet:
        console_handler = logging.StreamHandler()
        if verbose:
            console_handler.setLevel(logging.DEBUG)
        else:
            console_handler.setLevel(logging.INFO)
        
        # Use color if not in quiet mode
        formatter = ColoredFormatter('%(message)s')
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    # File handler (always logs everything)
    os.makedirs('logs', exist_ok=True)
    file_handler = logging.FileHandler('logs/bountyscout.log')
    file_handler.setLevel(logging.DEBUG)  # Always log everything to file
    file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    return logger

def setup_argparse():
    parser = argparse.ArgumentParser(description='BountyScout - A reconnaissance tool for bug bounty hunters')
    parser.add_argument('-d', '--domain', help='Single domain to scan (e.g., example.com)')
    parser.add_argument('-l', '--list', help='File containing list of domains, one per line')
    parser.add_argument('-o', '--output', default='output', help='Output directory for results')
    parser.add_argument('--skip-subdomain', action='store_true', help='Skip subdomain enumeration')
    parser.add_argument('--skip-port-scan', action='store_true', help='Skip port scanning')
    parser.add_argument('--skip-service-check', action='store_true', help='Skip service checking')
    parser.add_argument('--skip-vuln-check', action='store_true', help='Skip vulnerability checking')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output (detailed logs)')
    parser.add_argument('-q', '--quiet', action='store_true', help='Suppress non-error messages')
    return parser.parse_args()

def main():
    args = setup_argparse()
    
    # Setup logging based on args
    logger = setup_logging(args.verbose, args.quiet)
    
    # Validate input - need either domain or list
    if not args.domain and not args.list:
        logger.error("Error: Must provide either a domain (-d) or domain list file (-l)")
        sys.exit(1)
    
    # Create output directory if it doesn't exist
    os.makedirs(args.output, exist_ok=True)
    
    # Initialize components - don't pass quiet/verbose params to keep compatibility
    results_manager = ResultsManager(args.output)
    shodan_client = ShodanClient('config/config.yaml')
    domain_processor = DomainProcessor()
    
    # Process domains
    try:
        if args.domain:
            logger.info(f"Starting scan on domain: {args.domain}")
            domains = domain_processor.process_single_domain(args.domain)
        else:
            logger.info(f"Starting scan on domains from file: {args.list}")
            domains = domain_processor.process_domain_list(args.list)
    except Exception as e:
        logger.error(f"Error processing domains: {e}")
        sys.exit(1)
    
    # Run the pipeline
    if not args.skip_subdomain:
        try:
            enumerator = Enumerator(shodan_client)
            subdomains, ips = enumerator.enumerate_targets(domains)
            if not args.quiet:
                logger.info(f"[+] Found {len(subdomains)} subdomains")
            results_manager.save_subdomains(subdomains)
            results_manager.save_ips(ips)
        except Exception as e:
            logger.error(f"Error during subdomain enumeration: {e}")
    else:
        logger.info("Skipping subdomain enumeration")
    
    if not args.skip_port_scan:
        try:
            port_scanner = PortScanner()
            open_ports = port_scanner.scan_targets(ips)
            results_manager.save_open_ports(open_ports)
        except Exception as e:
            logger.error(f"Error during port scanning: {e}")
    else:
        logger.info("Skipping port scanning")
    
    if not args.skip_service_check:
        try:
            service_analyzer = ServiceAnalyzer()
            service_results = service_analyzer.analyze_services(open_ports)
            results_manager.save_service_results(service_results)
        except Exception as e:
            logger.error(f"Error during service analysis: {e}")
    else:
        logger.info("Skipping service checking")
    
    if not args.skip_vuln_check:
        try:
            vuln_checker = VulnerabilityChecker(shodan_client)
            vulnerabilities = vuln_checker.check_vulnerabilities(ips, open_ports)
            results_manager.save_vulnerabilities(vulnerabilities)
        except Exception as e:
            logger.error(f"Error during vulnerability checking: {e}")
    else:
        logger.info("Skipping vulnerability checking")
    
    # Generate summary report
    results_manager.generate_summary()
    
    logger.info(f"Scan complete! Results saved to {args.output} directory")
    if not args.quiet:
        logger.info(f"View the HTML report at: {args.output}/reports/report.html")
        logger.info(f"Full logs available at: logs/bountyscout.log")

if __name__ == "__main__":
    main()
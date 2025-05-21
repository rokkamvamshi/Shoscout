# port_scanner.py - Scan for open ports on target IPs

import nmap
import concurrent.futures
from tqdm import tqdm

class PortScanner:
    def __init__(self):
        self.nmap_scanner = nmap.PortScanner()
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
            993, 995, 1723, 3306, 3389, 5900, 8080, 8443
        ]
    
    def scan_targets(self, ip_mapping):
        """Scan targets for open ports"""
        print(f"[+] Starting port scan on {len(ip_mapping)} targets")
        
        # Extract unique IPs from the mapping
        unique_ips = set(ip_mapping.values())
        
        # Store results
        results = {}
        
        # Use thread pool for faster scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            # Create a dict of {future: ip} to track which IP each future is for
            future_to_ip = {
                executor.submit(self.scan_single_target, ip): ip 
                for ip in unique_ips
            }
            
            # Process results as they complete
            for future in tqdm(concurrent.futures.as_completed(future_to_ip), 
                               total=len(future_to_ip),
                               desc="Scanning targets"):
                ip = future_to_ip[future]
                try:
                    scan_result = future.result()
                    if scan_result:
                        results[ip] = scan_result
                except Exception as e:
                    print(f"[-] Error scanning {ip}: {e}")
        
        # Map results back to hostnames
        host_results = {}
        for hostname, ip in ip_mapping.items():
            if ip in results:
                host_results[hostname] = results[ip]
        
        print(f"[+] Port scan complete. Found open ports on {len(results)} targets")
        return host_results
    
    def scan_single_target(self, ip):
        """Scan a single target for open ports"""
        try:
            # Convert list of ports to string format for nmap
            ports_str = ','.join(map(str, self.common_ports))
            
            # Run the scan
            self.nmap_scanner.scan(ip, ports_str, arguments='-T4 -sV')
            
            # Process results
            if ip in self.nmap_scanner.all_hosts():
                result = {}
                for proto in self.nmap_scanner[ip].all_protocols():
                    result[proto] = {}
                    ports = sorted(self.nmap_scanner[ip][proto].keys())
                    for port in ports:
                        service_info = self.nmap_scanner[ip][proto][port]
                        result[proto][port] = {
                            'state': service_info['state'],
                            'name': service_info['name'],
                            'product': service_info.get('product', ''),
                            'version': service_info.get('version', ''),
                            'extrainfo': service_info.get('extrainfo', '')
                        }
                return result
            return None
        except Exception as e:
            print(f"[-] Error during port scan of {ip}: {e}")
            return None
    
    def quick_scan(self, ip, custom_ports=None):
        """Perform a quicker scan with fewer ports"""
        try:
            if custom_ports:
                ports_to_scan = custom_ports
            else:
                # Just the most common web and SSH ports
                ports_to_scan = [22, 80, 443, 8080, 8443]
            
            ports_str = ','.join(map(str, ports_to_scan))
            self.nmap_scanner.scan(ip, ports_str, arguments='-T4')
            
            if ip in self.nmap_scanner.all_hosts():
                result = {}
                for proto in self.nmap_scanner[ip].all_protocols():
                    result[proto] = {}
                    ports = sorted(self.nmap_scanner[ip][proto].keys())
                    for port in ports:
                        service_info = self.nmap_scanner[ip][proto][port]
                        result[proto][port] = {
                            'state': service_info['state'],
                            'name': service_info['name']
                        }
                return result
            return None
        except:
            return None
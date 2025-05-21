# service_analyzer.py - Analyze detected services

import requests
import concurrent.futures
import urllib3
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import socket
import ssl
import socket

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ServiceAnalyzer:
    def __init__(self):
        self.common_web_paths = [
            "/robots.txt",
            "/.git/HEAD",
            "/.env",
            "/.htaccess",
            "/admin",
            "/wp-admin",
            "/phpinfo.php",
            "/api",
            "/v1",
            "/swagger",
            "/actuator",
            "/.well-known/security.txt"
        ]
        
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        }
    
    def analyze_services(self, port_results):
        """Analyze services detected on open ports"""
        print(f"[+] Analyzing services for {len(port_results)} hosts")
        
        results = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_host = {}
            
            for hostname, port_data in port_results.items():
                if not port_data:
                    continue
                
                # Check for web services (HTTP/HTTPS)
                web_ports = self._identify_web_ports(port_data)
                if web_ports:
                    for port in web_ports:
                        future = executor.submit(self._analyze_web_service, hostname, port)
                        future_to_host[(hostname, port, 'web')] = future
                
                # Check for SSL/TLS services
                ssl_ports = self._identify_ssl_ports(port_data)
                if ssl_ports:
                    for port in ssl_ports:
                        future = executor.submit(self._analyze_ssl_service, hostname, port)
                        future_to_host[(hostname, port, 'ssl')] = future
                        
                # Check for other services
                for proto in port_data:
                    for port, service in port_data[proto].items():
                        service_name = service.get('name', '').lower()
                        
                        # Check for FTP
                        if service_name == 'ftp':
                            future = executor.submit(self._analyze_ftp_service, hostname, port)
                            future_to_host[(hostname, port, 'ftp')] = future
                            
                        # Check for SSH
                        elif service_name == 'ssh':
                            future = executor.submit(self._analyze_ssh_service, hostname, port)
                            future_to_host[(hostname, port, 'ssh')] = future
            
            # Process results
            for (hostname, port, service_type), future in future_to_host.items():
                try:
                    result = future.result()
                    if result:
                        if hostname not in results:
                            results[hostname] = {}
                        if service_type not in results[hostname]:
                            results[hostname][service_type] = {}
                        results[hostname][service_type][port] = result
                except Exception as e:
                    print(f"[-] Error analyzing {service_type} on {hostname}:{port} - {e}")
        
        return results
    
    def _identify_web_ports(self, port_data):
        """Identify ports that are likely running web services"""
        web_ports = []
        
        for proto in port_data:
            if proto != 'tcp':
                continue
                
            for port, service in port_data[proto].items():
                port = int(port)
                service_name = service.get('name', '').lower()
                
                # Common web service names
                if service_name in ['http', 'https', 'http-proxy', 'http-alt']:
                    web_ports.append(port)
                # Common web ports
                elif port in [80, 443, 8080, 8443, 8000, 8888, 3000]:
                    web_ports.append(port)
        
        return web_ports
    
    def _identify_ssl_ports(self, port_data):
        """Identify ports that are likely running SSL/TLS"""
        ssl_ports = []
        
        for proto in port_data:
            if proto != 'tcp':
                continue
                
            for port, service in port_data[proto].items():
                port = int(port)
                service_name = service.get('name', '').lower()
                
                # Common SSL service names
                if 'ssl' in service_name or 'tls' in service_name or service_name == 'https':
                    ssl_ports.append(port)
                # Common SSL ports
                elif port in [443, 8443, 465, 993, 995]:
                    ssl_ports.append(port)
        
        return ssl_ports
    
    def _analyze_web_service(self, hostname, port):
        """Analyze a web service"""
        result = {
            'title': None,
            'headers': {},
            'server': None,
            'technologies': [],
            'interesting_paths': {}
        }
        
        # Determine protocol (HTTP or HTTPS)
        if port == 443 or port == 8443:
            protocol = 'https'
        else:
            # Try HTTPS first, fall back to HTTP
            try:
                r = requests.get(f"https://{hostname}:{port}", 
                                timeout=5, 
                                verify=False, 
                                headers=self.headers)
                protocol = 'https'
            except:
                protocol = 'http'
        
        base_url = f"{protocol}://{hostname}:{port}"
        
        # Get homepage
        try:
            response = requests.get(base_url, 
                                   timeout=10, 
                                   verify=False, 
                                   headers=self.headers)
            
            # Extract response headers
            for header_name, header_value in response.headers.items():
                result['headers'][header_name] = header_value
            
            # Extract server header
            if 'Server' in response.headers:
                result['server'] = response.headers['Server']
            
            # Extract page title
            try:
                soup = BeautifulSoup(response.text, 'html.parser')
                if soup.title:
                    result['title'] = soup.title.string.strip()
            except:
                pass
            
            # Detect technologies
            result['technologies'] = self._detect_web_technologies(response)
            
        except Exception as e:
            print(f"[-] Error accessing {base_url}: {e}")
        
        # Check for interesting paths
        for path in self.common_web_paths:
            try:
                path_url = f"{base_url}{path}"
                response = requests.get(path_url, 
                                       timeout=5, 
                                       verify=False, 
                                       headers=self.headers,
                                       allow_redirects=False)
                
                if response.status_code != 404:
                    result['interesting_paths'][path] = {
                        'status_code': response.status_code,
                        'content_length': len(response.content)
                    }
            except:
                pass
        
        return result
    
    def _detect_web_technologies(self, response):
        """Detect web technologies from response"""
        technologies = []
        
        # Check headers
        headers = response.headers
        if 'X-Powered-By' in headers:
            technologies.append(headers['X-Powered-By'])
        
        if 'Server' in headers:
            technologies.append(headers['Server'])
        
        # Look for common tech signatures
        content = response.text.lower()
        
        # Content Management Systems
        if 'wordpress' in content:
            technologies.append('WordPress')
        elif 'drupal' in content:
            technologies.append('Drupal')
        elif 'joomla' in content:
            technologies.append('Joomla')
        
        # JavaScript frameworks
        if 'react' in content or 'reactjs' in content:
            technologies.append('React')
        elif 'vue' in content or 'vuejs' in content:
            technologies.append('Vue.js')
        elif 'angular' in content:
            technologies.append('Angular')
        
        # Web servers
        if 'nginx' in content:
            technologies.append('Nginx')
        elif 'apache' in content:
            technologies.append('Apache')
        
        # Remove duplicates
        return list(set(technologies))
    
    def _analyze_ssl_service(self, hostname, port):
        """Analyze SSL/TLS configuration"""
        result = {
            'certificate': {},
            'protocols': [],
            'ciphers': []
        }
        
        try:
            # Create socket and connect
            sock = socket.create_connection((hostname, port), timeout=5)
            
            # Wrap with SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect with SSL
            ssl_sock = context.wrap_socket(sock, server_hostname=hostname)
            
            # Get certificate
            cert = ssl_sock.getpeercert(binary_form=False)
            if cert:
                result['certificate'] = {
                    'subject': str(cert.get('subject', '')),
                    'issuer': str(cert.get('issuer', '')),
                    'version': cert.get('version', ''),
                    'notBefore': cert.get('notBefore', ''),
                    'notAfter': cert.get('notAfter', '')
                }
            
            # Get protocol version
            result['protocols'].append(ssl_sock.version())
            
            # Get cipher
            result['ciphers'].append(ssl_sock.cipher())
            
            ssl_sock.close()
            sock.close()
            
        except Exception as e:
            print(f"[-] Error analyzing SSL on {hostname}:{port} - {e}")
        
        return result
    
    def _analyze_ftp_service(self, hostname, port):
        """Basic FTP service analysis"""
        # Just try to connect and get banner
        try:
            sock = socket.create_connection((hostname, port), timeout=5)
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return {'banner': banner}
        except:
            return {'banner': None}
    
    def _analyze_ssh_service(self, hostname, port):
        """Basic SSH service analysis"""
        # Just try to connect and get banner
        try:
            sock = socket.create_connection((hostname, port), timeout=5)
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return {'banner': banner}
        except:
            return {'banner': None}
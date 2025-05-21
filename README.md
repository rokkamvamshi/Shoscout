# BountyScout

BountyScout is a comprehensive reconnaissance tool designed for bug bounty hunters and security researchers. It automates the process of discovering and analyzing attack surfaces of target domains.

## Features

- **Subdomain Enumeration**: Discover subdomains using various techniques including DNS resolution, certificate transparency logs, and Shodan integration
- **Port Scanning**: Identify open ports and services using Nmap
- **Service Analysis**: Analyze detected services including web servers, SSL/TLS, SSH, and FTP
- **Vulnerability Checking**: Check for common vulnerabilities in web applications and SSL/TLS configurations
- **Shodan Integration**: Leverage Shodan for additional reconnaissance and vulnerability information
- **Detailed Reporting**: Generate comprehensive reports in multiple formats (JSON, CSV, HTML, TXT)

## Installation

### Prerequisites

- Python 3.7+
- Nmap
- Shodan API key (optional but recommended)

### Setup

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/bountyscout.git
   cd bountyscout
   ```

2. Create a virtual environment and install dependencies:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. Configure Shodan API key (optional):
   Create a `config/config.yaml` file with your Shodan API key:
   ```yaml
   shodan:
     api_key: "YOUR_SHODAN_API_KEY"
   ```

## Usage

Basic usage:

```
python main.py -d example.com
```

Scan multiple domains from a file:

```
python main.py -l domains.txt
```

Full options:

```
python main.py -h

usage: main.py [-h] [-d DOMAIN] [-l LIST] [-o OUTPUT] [--skip-subdomain] [--skip-port-scan] [--skip-service-check] [--skip-vuln-check] [-v]

BountyScout - A reconnaissance tool for bug bounty hunters

optional arguments:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Single domain to scan (e.g., example.com)
  -l LIST, --list LIST  File containing list of domains, one per line
  -o OUTPUT, --output OUTPUT
                        Output directory for results
  --skip-subdomain      Skip subdomain enumeration
  --skip-port-scan      Skip port scanning
  --skip-service-check  Skip service checking
  --skip-vuln-check     Skip vulnerability checking
  -v, --verbose         Enable verbose output
```

## Example Workflow

1. Scan a single domain with all features:
   ```
   python main.py -d example.com -o example_scan
   ```

2. Skip certain steps for faster scanning:
   ```
   python main.py -d example.com --skip-port-scan --skip-vuln-check
   ```

3. Scan multiple domains from a file:
   ```
   python main.py -l targets.txt -o multi_scan
   ```

## Output Structure

Results are organized in the output directory as follows:

```
output/
├── subdomains/
│   ├── subdomains.txt
│   └── ip_mapping.csv
├── ports/
│   ├── open_ports.json
│   └── open_ports.csv
├── services/
│   ├── services.json
│   └── web_services.csv
├── vulnerabilities/
│   ├── vulnerabilities.json
│   └── findings.csv
├── reports/
│   ├── report.html
│   └── summary.txt
└── results.json
```

## Dependencies

BountyScout relies on the following Python packages:

- dnspython: DNS handling
- python-nmap: Nmap integration
- requests: HTTP requests
- shodan: Shodan API integration
- beautifulsoup4: HTML parsing
- pyyaml: Configuration handling
- tqdm: Progress bars

## Security and Legal Considerations

- Only scan domains that you have permission to test
- Be mindful of the scan intensity and respect rate limits
- Follow responsible disclosure procedures for any vulnerabilities found
- Some techniques may trigger IDS/IPS systems or WAFs

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
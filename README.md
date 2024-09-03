# Domain Enumeration Script

## Overview

This Python script performs comprehensive DNS enumeration and information gathering for a given domain. It's designed for security professionals, network administrators, and penetration testers to gather detailed information about a domain's DNS infrastructure, subdomains, and associated services.

## Features

- Zone transfer attempts
- DNS record enumeration (A, AAAA, CNAME, MX, NS, TXT, SOA, SRV)
- Subdomain discovery using wordlists
- SSL/TLS certificate information retrieval
- WHOIS information lookup
- Web technology fingerprinting
- Open port scanning
- Certificate Transparency log querying
- SPF and DMARC record checking
- ASN information retrieval

## Prerequisites

- Python 3.6 or higher
- pip (Python package manager)

## Installation

1. Clone this repository or download the `domain_enumeration.py` script.

2. Install the required dependencies:

   ```
   pip install -r requirements.txt
   ```

   It's recommended to use a virtual environment:

   ```
   python -m venv dns_enum_env
   source dns_enum_env/bin/activate  # On Windows, use: dns_enum_env\Scripts\activate
   pip install -r requirements.txt
   ```

## Usage

Basic usage:

```
python domain_enumeration.py example.com
```

Advanced usage with options:

```
python domain_enumeration.py example.com -w path/to/wordlist.txt -o results.json -t 20 -d 0.2 --no-ct-logs
```

### Command-line Options

- `domain`: Target domain to enumerate (required)
- `-w, --wordlist`: Path to a custom subdomain wordlist file
- `-o, --output`: Specify an output file to save results in JSON format
- `-t, --threads`: Set the number of threads for subdomain enumeration (default: 10)
- `-d, --delay`: Set the delay between DNS queries in seconds (default: 0.1)
- `--no-ct-logs`: Skip querying Certificate Transparency logs
- `--no-port-scan`: Skip port scanning

## Output

The script provides detailed output in JSON format, either printed to the console or saved to a file if specified. The output includes:

- Discovered subdomains and their IP addresses
- DNS records
- SSL/TLS certificate information
- WHOIS data
- Open ports
- Detected web technologies
- And more...

## Ethical Considerations

This tool is intended for legitimate security testing and network administration tasks. Always ensure you have proper authorization before performing enumeration or scanning activities on any domain or network you do not own or have explicit permission to test.

## Contributing

Contributions to improve the script are welcome. Please feel free to submit pull requests or open issues to suggest improvements or report bugs.

## License

[MIT License](https://opensource.org/licenses/MIT)

## Disclaimer

This tool is provided for educational and professional use only. The authors are not responsible for any misuse or damage caused by this program. Always use this tool in compliance with all applicable laws and regulations.
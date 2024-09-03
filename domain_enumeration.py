import dns.resolver
import dns.zone
import dns.exception
import dns.query
import sys
import concurrent.futures
import ipaddress
import argparse
import json
from datetime import datetime, date
import time
import random
import requests
from tqdm import tqdm
import ssl
import socket
import subprocess
import whois
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import base64
import httpx
from bs4 import BeautifulSoup
from jinja2 import Template
import logging
from typing import List, Dict, Any, Optional
import re
import certifi
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CustomJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder to handle complex objects."""
    def default(self, obj: Any) -> Any:
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        elif isinstance(obj, x509.Version):
            return obj.value
        elif isinstance(obj, bytes):
            return obj.decode('utf-8', errors='replace')
        elif isinstance(obj, x509.Name):
            return obj.rfc4514_string()
        elif isinstance(obj, x509.extensions.Extension):
            return str(obj.value)
        try:
            return super(CustomJSONEncoder, self).default(obj)
        except TypeError:
            return str(obj)

class DNSEnumerator:
    def __init__(self, domain: str, args: argparse.Namespace):
        self.domain = domain
        self.args = args
        self.results: Dict[str, Any] = {
            "zone_transfers": [],
            "dns_records": {},
            "subdomains": {},
            "reverse_dns": {},
            "wildcard": None,
            "dnssec": None,
            "certificate_info": {},
            "whois_info": None,
            "open_ports": {},
            "ct_logs": [],
            "spf_record": None,
            "dmarc_record": None,
            "asn_info": None,
            "web_technologies": {}
        }

    def perform_zone_transfer(self) -> None:
        """Attempt zone transfer for the domain."""
        ns_records = dns.resolver.resolve(self.domain, 'NS')
        for ns in ns_records:
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(str(ns), self.domain))
                self.results["zone_transfers"].append({
                    "ns": str(ns),
                    "records": [f"{name} {node.to_text(name)}" for name, node in zone.nodes.items()]
                })
                logger.info(f"Zone transfer successful for {self.domain} from {ns}")
            except Exception as e:
                logger.warning(f"Zone transfer failed for {self.domain} from {ns}: {str(e)}")

    def enumerate_subdomains(self, wordlist: List[str]) -> None:
        """Enumerate subdomains using a wordlist."""
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            future_to_subdomain = {executor.submit(self.resolve_subdomain, subdomain): subdomain for subdomain in wordlist}
            for future in tqdm(concurrent.futures.as_completed(future_to_subdomain), total=len(wordlist), desc="Enumerating subdomains"):
                subdomain = future_to_subdomain[future]
                try:
                    result = future.result()
                    if result:
                        self.results["subdomains"][subdomain] = result
                except Exception as exc:
                    logger.error(f'{subdomain} generated an exception: {exc}')
                time.sleep(self.args.delay)

    def resolve_subdomain(self, subdomain: str) -> Optional[List[str]]:
        """Resolve a subdomain to its IP addresses."""
        try:
            full_domain = f"{subdomain}.{self.domain}"
            answers = dns.resolver.resolve(full_domain, 'A')
            return [str(rdata) for rdata in answers]
        except dns.resolver.NXDOMAIN:
            return None
        except dns.exception.DNSException:
            return None

    def enumerate_dns_records(self) -> None:
        """Enumerate various DNS record types for the domain."""
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'SRV']
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                self.results["dns_records"][record_type] = [str(rdata) for rdata in answers]
            except dns.exception.DNSException:
                pass

    def fingerprint_web_technology(self, subdomain: str) -> str:
        """Fingerprint web technologies for a subdomain."""
        full_domain = f"{subdomain}.{self.domain}"
        results = []
        try:
            ip = socket.gethostbyname(full_domain)
            results.extend(self.check_http_https(full_domain))
            results.extend(self.check_open_ports(ip))
            if subdomain == "autodiscover":
                results.extend(self.check_autodiscover(full_domain))
            return "; ".join(results) if results else "No specific technologies or services detected"
        except socket.gaierror:
            return f"Error: Unable to resolve hostname {full_domain}"
        except Exception as e:
            return f"Error: {str(e)}"

    def check_http_https(self, domain: str) -> List[str]:
        """Check HTTP and HTTPS for a domain."""
        results = []
        for protocol in ['http', 'https']:
            try:
                response = httpx.get(f"{protocol}://{domain}", timeout=5, verify=False)
                results.append(self.analyze_response(response, protocol.upper()))
            except httpx.HTTPError as e:
                results.append(f"{protocol.upper()}: {str(e)}")
        return results

    def check_open_ports(self, ip: str) -> List[str]:
        """Check for open ports on an IP address."""
        common_ports = [22, 25, 80, 443, 465, 587, 3306, 8080]
        open_ports = self.scan_ports(ip, common_ports)
        return [f"Open ports: {', '.join(map(str, open_ports))}"] if open_ports else []

    @staticmethod
    def scan_ports(ip: str, ports: List[int]) -> List[int]:
        """Scan for open ports on an IP address."""
        open_ports = []
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        return open_ports

    @staticmethod
    def check_autodiscover(domain: str) -> List[str]:
        """Check for Autodiscover SRV records."""
        results = []
        try:
            answers = dns.resolver.resolve(f"_autodiscover._tcp.{domain}", 'SRV')
            for rdata in answers:
                results.append(f"Autodiscover SRV record: {rdata}")
        except dns.exception.DNSException:
            results.append("No Autodiscover SRV record found")
        return results

    def analyze_response(self, response: httpx.Response, protocol: str) -> str:
        """Analyze HTTP/HTTPS response for web technologies."""
        technologies = [f"{protocol} Status: {response.status_code}"]
        technologies.extend(self.detect_web_technologies(response.text))
        server = response.headers.get('Server')
        if server:
            technologies.append(f"Server: {server}")
        return ", ".join(technologies)

    @staticmethod
    def detect_web_technologies(html: str) -> List[str]:
        """Detect web technologies from HTML content."""
        technologies = []
        tech_patterns = {
            'WordPress': r'wp-content|wp-includes',
            'Drupal': r'Drupal|drupal',
            'Joomla': r'joomla',
            'jQuery': r'jquery',
            'React': r'react',
            'Angular': r'ng-',
            'Vue.js': r'vue'
        }
        for tech, pattern in tech_patterns.items():
            if re.search(pattern, html, re.I):
                technologies.append(tech)
        return technologies

    def check_certificate(self, hostname: str) -> None:
        """Check SSL/TLS certificate information."""
        try:
            cert = ssl.get_server_certificate((hostname, 443))
            x509_cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())
            
            try:
                san = x509_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                san_values = [str(name) for name in san.value]
            except x509.ExtensionNotFound:
                san_values = []
            except Exception as e:
                san_values = [f"Error extracting SAN: {str(e)}"]

            self.results["certificate_info"][hostname] = {
                "subject": x509_cert.subject,
                "issuer": x509_cert.issuer,
                "version": x509_cert.version,
                "serial_number": x509_cert.serial_number,
                "not_valid_before": x509_cert.not_valid_before,
                "not_valid_after": x509_cert.not_valid_after,
                "san": san_values
            }
        except Exception as e:
            self.results["certificate_info"][hostname] = f"Error: {str(e)}"

    def get_whois_info(self) -> None:
        """Get WHOIS information for the domain."""
        try:
            w = whois.whois(self.domain)
            self.results["whois_info"] = {
                "registrar": w.registrar,
                "creation_date": w.creation_date,
                "expiration_date": w.expiration_date,
                "name_servers": w.name_servers
            }
        except Exception as e:
            self.results["whois_info"] = f"Error: {str(e)}"

    def query_ct_logs(self) -> None:
        """Query Certificate Transparency logs for subdomains."""
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                self.results["ct_logs"] = list(set([entry["name_value"] for entry in data]))
        except Exception as e:
            logger.error(f"Error querying CT logs: {str(e)}")

    def check_spf_dmarc(self) -> None:
        """Check SPF and DMARC records for the domain."""
        try:
            spf_record = dns.resolver.resolve(self.domain, 'TXT')
            for rdata in spf_record:
                if 'v=spf1' in str(rdata):
                    self.results["spf_record"] = str(rdata)
                    break
        except dns.exception.DNSException:
            self.results["spf_record"] = "No SPF record found"

        try:
            dmarc_record = dns.resolver.resolve(f"_dmarc.{self.domain}", 'TXT')
            for rdata in dmarc_record:
                if 'v=DMARC1' in str(rdata):
                    self.results["dmarc_record"] = str(rdata)
                    break
        except dns.exception.DNSException:
            self.results["dmarc_record"] = "No DMARC record found"

    def get_asn_info(self) -> None:
        """Get ASN information for the domain."""
        try:
            ip = socket.gethostbyname(self.domain)
            url = f"https://ipapi.co/{ip}/json/"
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                self.results["asn_info"] = {
                    "asn": data.get("asn"),
                    "org": data.get("org"),
                    "isp": data.get("isp")
                }
        except Exception as e:
            logger.error(f"Error getting ASN info: {str(e)}")

    def run(self) -> None:
        """Run the DNS enumeration process."""
        logger.info(f"Starting enhanced DNS enumeration for {self.domain}")
        
        self.perform_zone_transfer()
        self.enumerate_dns_records()
        
        wordlist = self.load_wordlist()
        self.enumerate_subdomains(wordlist)
        self.check_certificate(self.domain)
        self.get_whois_info()
        self.query_ct_logs()
        self.check_spf_dmarc()
        self.get_asn_info()

        logger.info("Scanning open ports...")
        for subdomain, ip_list in self.results["subdomains"].items():
            if ip_list:
                self.results["open_ports"][subdomain] = self.scan_ports(ip_list[0], [21, 22, 80, 443, 3306, 3389])

        logger.info("Fingerprinting web technologies...")
        for subdomain in tqdm(self.results["subdomains"]):
            self.results["web_technologies"][subdomain] = self.fingerprint_web_technology(subdomain)

        self.save_results()

    def load_wordlist(self) -> List[str]:
        """Load the subdomain wordlist."""
        if self.args.wordlist:
            try:
                with open(self.args.wordlist, 'r') as f:
                    return [line.strip() for line in f]
            except FileNotFoundError:
                logger.error(f"Wordlist file not found: {self.args.wordlist}")
                sys.exit(1)
        else:
            return ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig']

    def save_results(self) -> None:
        """Save the enumeration results."""
        if self.args.output:
            with open(self.args.output, 'w') as f:
                json.dump(self.results, f, indent=4, cls=CustomJSONEncoder)
            logger.info(f"Results saved to {self.args.output}")
        else:
            print(json.dumps(self.results, indent=4, cls=CustomJSONEncoder))

def validate_domain(domain: str) -> bool:
    """Validate the format of a domain name."""
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, domain))

def main() -> None:
    parser = argparse.ArgumentParser(description="Enhanced DNS Enumeration Script")
    parser.add_argument("domain", help="Target domain to enumerate")
    parser.add_argument("-w", "--wordlist", help="Path to subdomain wordlist file")
    parser.add_argument("-o", "--output", help="Output file to save results (JSON format)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads for subdomain enumeration")
    parser.add_argument("-d", "--delay", type=float, default=0.1, help="Delay between DNS queries in seconds")
    parser.add_argument("--no-ct-logs", action="store_true", help="Skip querying Certificate Transparency logs")
    parser.add_argument("--no-port-scan", action="store_true", help="Skip port scanning")
    args = parser.parse_args()

    if not validate_domain(args.domain):
        logger.error("Invalid domain format")
        sys.exit(1)

    enumerator = DNSEnumerator(args.domain, args)
    enumerator.run()

if __name__ == "__main__":
    main()

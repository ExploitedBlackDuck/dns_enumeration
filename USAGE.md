# Domain Enumeration Script: Usage Guide

## Table of Contents
1. [Basic Usage](#basic-usage)
2. [Command-line Options](#command-line-options)
3. [Advanced Usage Scenarios](#advanced-usage-scenarios)
4. [Output Interpretation](#output-interpretation)
5. [Best Practices](#best-practices)
6. [Troubleshooting](#troubleshooting)

## Basic Usage

To run a basic domain enumeration:

```
python domain_enumeration.py example.com
```

This command will perform a standard enumeration using default settings.

## Command-line Options

- `domain`: The target domain to enumerate (required)
- `-w, --wordlist <file>`: Path to a custom subdomain wordlist file
- `-o, --output <file>`: Specify an output file to save results in JSON format
- `-t, --threads <number>`: Set the number of threads for subdomain enumeration (default: 10)
- `-d, --delay <seconds>`: Set the delay between DNS queries in seconds (default: 0.1)
- `--no-ct-logs`: Skip querying Certificate Transparency logs
- `--no-port-scan`: Skip port scanning

## Advanced Usage Scenarios

### 1. Using a Custom Wordlist

To use your own list of subdomains:

```
python domain_enumeration.py example.com -w /path/to/your/wordlist.txt
```

### 2. Adjusting Thread Count and Delay

For faster enumeration (may be more detectable):

```
python domain_enumeration.py example.com -t 20 -d 0.05
```

For slower, stealthier enumeration:

```
python domain_enumeration.py example.com -t 5 -d 1
```

### 3. Saving Results to a File

To save the results in JSON format:

```
python domain_enumeration.py example.com -o results.json
```

### 4. Excluding Certain Features

To skip Certificate Transparency log querying and port scanning:

```
python domain_enumeration.py example.com --no-ct-logs --no-port-scan
```

### 5. Comprehensive Scan

For a full scan with custom settings:

```
python domain_enumeration.py example.com -w extensive_wordlist.txt -o detailed_results.json -t 15 -d 0.2
```

## Output Interpretation

The script outputs results in JSON format. Here's how to interpret key sections:

- `subdomains`: List of discovered subdomains and their IP addresses
- `dns_records`: Various DNS record types found for the domain
- `certificate_info`: Details about SSL/TLS certificates
- `whois_info`: WHOIS registration data
- `open_ports`: List of open ports found on subdomains
- `web_technologies`: Web technologies detected on subdomains
- `ct_logs`: Subdomains found in Certificate Transparency logs
- `spf_record` and `dmarc_record`: Email security records

## Best Practices

1. **Start Slow**: Begin with default settings and gradually increase thread count or decrease delay if needed.
2. **Use Relevant Wordlists**: Tailor your subdomain wordlist to the target organization's naming conventions if possible.
3. **Respect Rate Limits**: Be mindful of potential rate limiting on DNS servers or web services.
4. **Regular Updates**: Keep the script and its dependencies updated for best performance and security.
5. **Legal Compliance**: Ensure you have permission to perform enumeration on the target domain.

## Troubleshooting

- **SSL Errors**: If you encounter SSL certificate verification errors, ensure your CA certificates are up to date.
- **Rate Limiting**: If you're being rate-limited, try increasing the delay between requests.
- **DNS Resolution Failures**: Check your internet connection and DNS settings. Consider using alternative DNS servers.
- **Wordlist Issues**: Ensure your custom wordlist is properly formatted (one subdomain per line) and uses UTF-8 encoding.

For any persistent issues or feature requests, please open an issue on the project's GitHub repository.

Remember, this tool is powerful and should be used responsibly. Always ensure you have proper authorization before performing any enumeration or scanning activities.
# Security Toolkit

A command-line security toolkit for URL fuzzing, subdomain discovery, and port scanning.

## Features

- **URL Fuzzer**: Discover hidden endpoints and files on a target website
- **Subdomain Finder**: Find subdomains of a target domain
- **Port Scanner**: Scan for open ports on a target host
- **Full Scan Workflow**: Automatically discover subdomains and run tests on each one
- **IP-Based Scanning**: Target IP addresses directly instead of hostnames for improved reliability
- **Robust Error Handling**: Gracefully continues even when encountering SSL or connection issues

## Installation

### Requirements

- Python 3.7+
- Required Python packages (see requirements.txt)

### Setup

1. Clone this repository:
```
git clone https://github.com/yourusername/security-toolkit.git
cd security-toolkit
```

2. Install the required packages:
```
pip install -r requirements.txt
```

## Usage

### Full Scan Workflow

The most comprehensive option - find subdomains and automatically test each one:

```
python security_toolkit.py fullscan example.com
```

Options:
- `-w, --wordlist`: Path to custom wordlist (default: wordlists/subdomains.txt)
- `-e, --extensions`: File extensions to check, comma separated (default: php,html,js,txt)
- `-t, --threads`: Number of threads (default: 50)
- `-s, --speed`: Scan speed - fast, normal, or thorough (default: normal)
- `--timeout`: Timeout in seconds (default: 1.0)
- `--skip-fuzzing`: Skip URL fuzzing phase
- `--skip-portscan`: Skip port scanning phase
- `--use-ip`: Use IP addresses instead of hostnames (avoids SSL issues)

Example:
```
python security_toolkit.py fullscan example.com -s thorough -t 100 --use-ip
```

### URL Fuzzer

Discover hidden endpoints on a target website:

```
python security_toolkit.py fuzz http://example.com
```

Options:
- `-w, --wordlist`: Path to custom wordlist (default: wordlists/common.txt)
- `-e, --extensions`: File extensions to check, comma separated (default: php,html,js,txt)
- `-t, --threads`: Number of threads (default: 50)
- `-o, --output`: Output file path (default: automatically generated)
- `--timeout`: Request timeout in seconds (default: 2.0)
- `--use-ip`: Use IP address instead of hostname (helps bypass some security measures)

Example:
```
python security_toolkit.py fuzz http://example.com -w custom_wordlist.txt -e php,asp,aspx -t 100 --use-ip
```

### Subdomain Finder

Find subdomains of a target domain:

```
python security_toolkit.py subdomains example.com
```

Options:
- `-w, --wordlist`: Path to custom wordlist (default: wordlists/subdomains.txt)
- `-t, --threads`: Number of threads (default: 50)
- `-o, --output`: Output file path (default: automatically generated)

Example:
```
python security_toolkit.py subdomains example.com -w custom_subdomains.txt -t 100
```

### Port Scanner

Scan for open ports on a target host:

```
python security_toolkit.py scan 192.168.1.1
```

Options:
- `-p, --ports`: Port range (e.g., 1-1000 or 80,443,8080) (default: 1-1000)
- `-t, --threads`: Number of threads (default: 50)
- `--timeout`: Timeout in seconds (default: 1.0)
- `-o, --output`: Output file path (default: automatically generated)

Example:
```
python security_toolkit.py scan example.com -p 1-65535 -t 100
```

## Wordlists

- URL fuzzing wordlist: `wordlists/common.txt`
- Subdomain wordlist: `wordlists/subdomains.txt`

You can use your own custom wordlists by specifying the path with the `-w` option.

## Results

All scan results are saved to output files:
- For individual tool usage, results are saved to automatically generated files in the current directory
- For full scans, results are saved to a dedicated directory with the format `results_domain_name_directory`

## Error Handling

The toolkit includes robust error handling that allows it to:
- Continue scanning even when encountering SSL certificate issues
- Gracefully handle connection timeouts and other network errors
- Fall back to IP-based scanning when domain resolution fails
- Complete as much of the scan as possible even when parts fail

## Disclaimer

This tool is provided for educational and legitimate security testing purposes only. Always ensure you have proper authorization before testing any systems you don't own. Unauthorized scanning or testing of systems is illegal and unethical.

## License

MIT 
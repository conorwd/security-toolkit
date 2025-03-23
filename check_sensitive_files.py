#!/usr/bin/env python3
import requests
import sys
from colorama import Fore, Style

def check_file(url, path, host_header=None):
    """Check if a file exists on the target server"""
    target_url = f"{url.rstrip('/')}/{path.lstrip('/')}"
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    
    if host_header:
        headers['Host'] = host_header
    
    try:
        response = requests.get(
            target_url,
            headers=headers,
            timeout=5,
            verify=False
        )
        
        status = response.status_code
        size = len(response.content)
        
        status_color = Fore.GREEN if 200 <= status < 400 else Fore.YELLOW if status == 403 else Fore.RED
        
        print(f"{status_color}[{status}] {target_url} - {size} bytes{Style.RESET_ALL}")
        
        return status, size
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[ERROR] {target_url} - {str(e)}{Style.RESET_ALL}")
        return None, 0

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_url> [host_header]")
        sys.exit(1)
    
    target_url = sys.argv[1]
    host_header = sys.argv[2] if len(sys.argv) > 2 else None
    
    # List of sensitive files to check
    sensitive_files = [
        ".htaccess",
        ".htpasswd",
        ".hta",
        ".htaccess.bak",
        ".htpasswd.bak",
        ".hta.bak",
        ".htaccess.old",
        ".htpasswd.old",
        ".hta.old",
        ".htaccess.bkp",
        ".htpasswd.bkp",
        ".hta.bkp",
        ".env",
        "robots.txt",
        ".git/HEAD",
        ".svn/entries",
        ".DS_Store",
        ".well-known/security.txt",
        "wp-config.php",
        "config.php",
        "configuration.php",
        "info.php",
        "phpinfo.php"
    ]
    
    print(f"{Fore.CYAN}[*] Checking for sensitive files on {target_url}{Style.RESET_ALL}")
    if host_header:
        print(f"{Fore.CYAN}[*] Using Host header: {host_header}{Style.RESET_ALL}")
    
    valid_count = 0
    for path in sensitive_files:
        status, size = check_file(target_url, path, host_header)
        if status in [200, 403]:
            valid_count += 1
    
    print(f"\n{Fore.CYAN}[*] Found {valid_count} sensitive files on {target_url}{Style.RESET_ALL}")

if __name__ == "__main__":
    # Disable SSL warnings
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    
    main() 
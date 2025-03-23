#!/usr/bin/env python3
import argparse
import sys
import os
import socket
from colorama import init, Fore, Style

# Import the tool modules
from modules.url_fuzzer import URLFuzzer
from modules.subdomain_finder import SubdomainFinder
from modules.port_scanner import PortScanner

# Initialize colorama
init()

def banner():
    """Display the tool banner"""
    print(f"""{Fore.CYAN}
 _____                      _ _         _____           _ _    _ _   
/  ___|                    (_) |       |_   _|         | | |  (_) |  
\\ `--.  ___  ___ _   _ _ __ _| |_ _   _  | | ___   ___ | | | ___| |_ 
 `--. \\/ _ \\/ __| | | | '__| | __| | | | | |/ _ \\ / _ \\| | |/ / | __|
/\\__/ /  __/ (__| |_| | |  | | |_| |_| | | | (_) | (_) | |   <| | |_ 
\\____/ \\___|\\___|\\__,_|_|  |_|\\__|\\__, | \\_/\\___/ \\___/|_|_|\\_\\_|\\__|
                                   __/ |                             
                                  |___/                              
{Style.RESET_ALL}
{Fore.GREEN}[ URL Fuzzer | Subdomain Finder | Port Scanner ]{Style.RESET_ALL}
    """)

def create_output_dir(domain):
    """Create an output directory for results"""
    output_dir = f"results_{domain.replace('.', '_')}_{os.path.basename(os.getcwd())}"
    os.makedirs(output_dir, exist_ok=True)
    return output_dir

def resolve_domain_to_ip(domain):
    """Resolve a domain to its IP address"""
    try:
        print(f"{Fore.CYAN}[*] Resolving domain {domain} to IP address{Style.RESET_ALL}")
        ip = socket.gethostbyname(domain)
        print(f"{Fore.GREEN}[+] Domain {domain} resolves to IP address {ip}{Style.RESET_ALL}")
        return ip
    except socket.gaierror as e:
        print(f"{Fore.RED}[!] Error resolving domain: {e}{Style.RESET_ALL}")
        return None

def run_full_scan(args):
    """Run a full scan: find subdomains and then scan each one"""
    domain = args.domain
    output_dir = create_output_dir(domain)
    
    # Resolve main domain to IP address if use_ip is enabled
    main_domain_ip = None
    if args.use_ip:
        main_domain_ip = resolve_domain_to_ip(domain)
    
    # First, find subdomains
    print(f"{Fore.CYAN}[*] Phase 1: Subdomain Discovery{Style.RESET_ALL}")
    
    # Adjust thread count based on speed
    if args.speed == "fast":
        threads = min(100, args.threads)  # Use more threads for faster scanning
        timeout = 1.0  # Shorter timeout
    elif args.speed == "normal":
        threads = args.threads
        timeout = args.timeout
    else:  # thorough
        threads = max(20, args.threads // 2)  # Use fewer threads for more thorough scanning
        timeout = args.timeout * 2  # Longer timeout
    
    # Use subdomain wordlist for subdomain discovery
    subdomain_wordlist = args.wordlist
    subdomain_output = os.path.join(output_dir, f"subdomains_{domain}.txt")
    try:
        finder = SubdomainFinder(
            domain=domain,
            wordlist=subdomain_wordlist,
            threads=threads,
            output=subdomain_output,
            use_advanced=not args.no_advanced_discovery,
            skip_wordlist=args.skip_wordlist
        )
        subdomains = finder.run()
    except Exception as e:
        print(f"{Fore.RED}[!] Error during subdomain discovery: {str(e)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Continuing with only the main domain{Style.RESET_ALL}")
        subdomains = []
    
    # If no subdomains found, still scan the main domain
    if not subdomains:
        if main_domain_ip:
            targets = [(domain, main_domain_ip)]
        else:
            targets = [(domain, "")]
    else:
        targets = subdomains
    
    # Get the common and top ports based on speed level
    if args.speed == "fast":
        ports = "80,443,8080,8443"
        # Limit extensions for fast scanning
        extensions = "html,php"
    elif args.speed == "normal":
        ports = "21-25,80-443,1433,3306,3389,5432,8080-8443"
        extensions = args.extensions
    else:  # thorough
        ports = "1-1024,1433,3306,3389,5432,8080-8443,9000-9001,10000"
        # Add more extensions for thorough scanning
        extensions = args.extensions + ",xml,json,asp,aspx,jsp,cgi,bak,old,backup"
    
    # Always use the common wordlist for URL fuzzing, not the subdomain wordlist
    fuzzing_wordlist = args.fuzz_wordlist
    
    # Group targets by IP to avoid scanning the same IP multiple times
    ip_to_domains = {}
    print(f"{Fore.CYAN}[*] Grouping domains by IP address{Style.RESET_ALL}")
    
    for subdomain, ip in targets:
        # Resolve IP if not already known
        if not ip and args.use_ip:
            ip = resolve_domain_to_ip(subdomain)
        
        if ip:
            if ip not in ip_to_domains:
                ip_to_domains[ip] = []
            ip_to_domains[ip].append(subdomain)
        else:
            # If we can't resolve, keep as a separate target
            if "" not in ip_to_domains:
                ip_to_domains[""] = []
            ip_to_domains[""].append(subdomain)
    
    print(f"{Fore.GREEN}[+] Grouped {len(targets)} domains into {len(ip_to_domains)} unique IPs{Style.RESET_ALL}")
    
    # Create single output files for fuzzing and port scanning
    fuzzing_output = os.path.join(output_dir, f"url_fuzzing_results_{domain}.txt")
    portscan_output = os.path.join(output_dir, f"port_scan_results_{domain}.txt")
    
    # Initialize output files with headers
    if not args.skip_fuzzing:
        with open(fuzzing_output, "w") as f:
            f.write("============================================================\n")
            f.write(f"URL FUZZING RESULTS FOR {domain.upper()}\n")
            f.write("============================================================\n\n")
    
    if not args.skip_portscan:
        with open(portscan_output, "w") as f:
            f.write("============================================================\n")
            f.write(f"PORT SCANNING RESULTS FOR {domain.upper()}\n")
            f.write("============================================================\n\n")
    
    # Run URL fuzzing and port scanning on each unique IP
    for i, (ip, domains) in enumerate(ip_to_domains.items()):
        print(f"\n{Fore.CYAN}[*] Scanning IP {i+1}/{len(ip_to_domains)}: {ip}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Domains on this IP: {', '.join(domains)}{Style.RESET_ALL}")
        
        # Use the first domain for naming the output files
        target_name = domains[0]
        
        # Run URL fuzzing
        if not args.skip_fuzzing:
            print(f"{Fore.CYAN}[*] Phase 2: URL Fuzzing on {ip} (for {len(domains)} domains){Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Using full wordlist: {fuzzing_wordlist} ({os.path.getsize(fuzzing_wordlist) // 1024}KB){Style.RESET_ALL}")
            
            # For IP-based scanning, use the IP directly
            if args.use_ip and ip:
                url = f"https://{ip}"
                target_for_fuzzing = ip
            else:
                # Otherwise use the first domain
                if not target_name.startswith(("http://", "https://")):
                    url = f"https://{target_name}"
                else:
                    url = target_name
                target_for_fuzzing = target_name
                
            # Create a temporary file for fuzzing results
            temp_fuzzer_output = os.path.join(output_dir, f"temp_fuzzing_{i}.txt")
            try:
                # Use adjusted extensions based on speed
                fuzzer_extensions = args.extensions.split(",") if isinstance(args.extensions, str) else args.extensions
                
                # Check that wordlists exist
                if not os.path.exists(fuzzing_wordlist):
                    print(f"{Fore.RED}[!] Wordlist not found: {fuzzing_wordlist}{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}[*] Please create or download a wordlist file{Style.RESET_ALL}")
                    continue
                
                security_wordlist = "wordlists/security_files.txt"
                if not os.path.exists(security_wordlist):
                    print(f"{Fore.YELLOW}[!] Security wordlist not found: {security_wordlist}{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}[*] Please create or download a security wordlist file{Style.RESET_ALL}")
                
                fuzzer = URLFuzzer(
                    target=url,
                    wordlist=fuzzing_wordlist,  # Main wordlist (URLFuzzer will automatically include security files)
                    extensions=fuzzer_extensions,
                    threads=threads,
                    output=temp_fuzzer_output,
                    timeout=timeout,
                    use_ip=args.use_ip
                )
                results = fuzzer.run()
                
                # Process the fuzzing results to identify sensitive files and categorize findings
                # for better reporting in the consolidated output
                protected_files = []
                accessible_files = []
                
                for url, status, size in results:
                    # Identify protected sensitive files (like .htaccess with 403)
                    if status == 403 and any(ext in url.lower() for ext in ['.hta', '.htaccess', '.htpasswd']):
                        protected_files.append((url, status, size))
                    # Regular accessible files
                    elif 200 <= status < 400 or status in [401, 403]:
                        accessible_files.append((url, status, size))
                
                # Append results to the consolidated file with better categorization
                with open(fuzzing_output, "a") as f:
                    f.write(f"IP: {ip}\n")
                    f.write(f"Domains: {', '.join(domains)}\n")
                    f.write("------------------------------------------------------------\n")
                    
                    if protected_files or accessible_files:
                        # First list any protected sensitive files
                        if protected_files:
                            f.write(f"\n{Fore.YELLOW}PROTECTED SENSITIVE FILES:{Style.RESET_ALL}\n")
                            for url, status, size in protected_files:
                                f.write(f"{Fore.YELLOW}[{status}] {url} - {size} bytes [PROTECTED]{Style.RESET_ALL}\n")
                        
                        # Then list regular accessible files
                        if accessible_files:
                            f.write(f"\n{Fore.GREEN}ACCESSIBLE RESOURCES:{Style.RESET_ALL}\n")
                            for url, status, size in accessible_files:
                                color = Fore.GREEN if status < 300 else Fore.YELLOW
                                f.write(f"{color}[{status}] {url} - {size} bytes{Style.RESET_ALL}\n")
                    else:
                        f.write("[!] No valid URLs found\n")
                    
                    f.write("\n============================================================\n\n")
                
                # Remove the temporary file
                try:
                    os.remove(temp_fuzzer_output)
                except:
                    pass
                
            except Exception as e:
                print(f"{Fore.RED}[!] Error running URL fuzzing on {target_for_fuzzing}: {str(e)}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[*] Continuing with next phase{Style.RESET_ALL}")
                
                # Record the error in the output file
                with open(fuzzing_output, "a") as f:
                    f.write(f"IP: {ip}\n")
                    f.write(f"Domains: {', '.join(domains)}\n")
                    f.write("------------------------------------------------------------\n")
                    f.write(f"[!] Error: {str(e)}\n")
                    f.write("\n============================================================\n\n")
        
        # Run port scanning on the IP
        if not args.skip_portscan:
            print(f"{Fore.CYAN}[*] Phase 3: Port Scanning on {ip} (for {len(domains)} domains){Style.RESET_ALL}")
            
            # Create a temporary file for port scan results
            temp_scanner_output = os.path.join(output_dir, f"temp_portscan_{i}.txt")
            
            # Use the IP if available, otherwise use the hostname
            scan_target = ip if ip else target_name
            
            try:
                scanner = PortScanner(
                    target=scan_target,
                    ports=ports,
                    timeout=timeout,
                    output=temp_scanner_output,
                    threads=threads
                )
                scanner.run()
                
                # Append results to the consolidated file
                with open(portscan_output, "a") as f:
                    f.write(f"IP: {ip}\n")
                    f.write(f"Domains: {', '.join(domains)}\n")
                    f.write("------------------------------------------------------------\n")
                    
                    if os.path.exists(temp_scanner_output) and os.path.getsize(temp_scanner_output) > 0:
                        with open(temp_scanner_output, "r") as temp_f:
                            # Skip the header from the temp file
                            lines = temp_f.readlines()
                            found_results_section = False
                            table_header_seen = False
                            for line in lines:
                                if "Port Scan Results" in line:
                                    found_results_section = True
                                    continue
                                if found_results_section:
                                    if "===" not in line:
                                        if "| PORT" in line and table_header_seen:
                                            continue  # Skip duplicate table headers
                                        elif "| PORT" in line:
                                            table_header_seen = True
                                        
                                        if line.strip():
                                            f.write(line)
                    else:
                        f.write("[!] No open ports found\n")
                    
                    f.write("\n============================================================\n\n")
                
                # Remove the temporary file
                try:
                    os.remove(temp_scanner_output)
                except:
                    pass
                
            except Exception as e:
                print(f"{Fore.RED}[!] Error running port scan on {scan_target}: {str(e)}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[*] Continuing with next target{Style.RESET_ALL}")
                
                # Record the error in the output file
                with open(portscan_output, "a") as f:
                    f.write(f"IP: {ip}\n")
                    f.write(f"Domains: {', '.join(domains)}\n")
                    f.write("------------------------------------------------------------\n")
                    f.write(f"[!] Error: {str(e)}\n")
                    f.write("\n============================================================\n\n")
    
    print(f"\n{Fore.GREEN}[+] Full scan completed. Results saved to {output_dir}{Style.RESET_ALL}")
    if not args.skip_fuzzing:
        print(f"{Fore.GREEN}[+] URL fuzzing results: {fuzzing_output}{Style.RESET_ALL}")
    if not args.skip_portscan:
        print(f"{Fore.GREEN}[+] Port scanning results: {portscan_output}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Subdomain discovery results: {subdomain_output}{Style.RESET_ALL}")
    
def main():
    """Main function to parse arguments and run the appropriate tool"""
    parser = argparse.ArgumentParser(description="Security Toolkit for URL fuzzing, subdomain finding, and port scanning")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # URL Fuzzer arguments
    fuzzer_parser = subparsers.add_parser("fuzz", help="Fuzz URLs to find hidden endpoints")
    fuzzer_parser.add_argument("target", help="Target URL (e.g., http://example.com)")
    fuzzer_parser.add_argument("-w", "--wordlist", help="Path to wordlist file", default="wordlists/common.txt")
    fuzzer_parser.add_argument("-e", "--extensions", help="File extensions to check (comma separated)", default="php,html,js,txt")
    fuzzer_parser.add_argument("-t", "--threads", help="Number of threads", type=int, default=50)
    fuzzer_parser.add_argument("-o", "--output", help="Output file path", default=None)
    fuzzer_parser.add_argument("--timeout", help="Request timeout in seconds", type=float, default=2.0)
    fuzzer_parser.add_argument("--use-ip", help="Use IP address instead of hostname", action="store_true")
    fuzzer_parser.add_argument("-s", "--speed", help="Scan speed (affects extensions and timeout)", 
                             choices=["fast", "normal", "thorough"], default="normal")
    
    # Subdomain Finder arguments
    subdomain_parser = subparsers.add_parser("subdomains", help="Find subdomains of a target domain")
    subdomain_parser.add_argument("domain", help="Target domain (e.g., example.com)")
    subdomain_parser.add_argument("-w", "--wordlist", help="Path to wordlist file", default="wordlists/subdomains.txt")
    subdomain_parser.add_argument("-t", "--threads", help="Number of threads", type=int, default=50)
    subdomain_parser.add_argument("-o", "--output", help="Output file path", default=None)
    subdomain_parser.add_argument("-s", "--speed", help="Scan speed (affects threads)", 
                                choices=["fast", "normal", "thorough"], default="normal")
    subdomain_parser.add_argument("--no-advanced-discovery", help="Disable advanced subdomain discovery methods like Certificate Transparency", action="store_true")
    subdomain_parser.add_argument("--skip-wordlist", help="Skip wordlist-based enumeration and rely only on advanced discovery methods", action="store_true")
    
    # Port Scanner arguments
    scanner_parser = subparsers.add_parser("scan", help="Scan ports on a target host")
    scanner_parser.add_argument("target", help="Target IP or hostname")
    scanner_parser.add_argument("-p", "--ports", help="Port range (e.g., 1-1000 or 80,443,8080)", default="1-1000")
    scanner_parser.add_argument("-t", "--threads", help="Number of threads", type=int, default=50)
    scanner_parser.add_argument("--timeout", help="Timeout in seconds", type=float, default=1.0)
    scanner_parser.add_argument("-o", "--output", help="Output file path", default=None)
    scanner_parser.add_argument("-s", "--speed", help="Scan speed (affects port range)", 
                              choices=["fast", "normal", "thorough"], default="normal")
    
    # Full Scan arguments
    fullscan_parser = subparsers.add_parser("fullscan", help="Run full scan: find subdomains then run tests on each")
    fullscan_parser.add_argument("domain", help="Target domain (e.g., example.com)")
    fullscan_parser.add_argument("-w", "--wordlist", help="Path to subdomain wordlist file (for domain discovery only)", default="wordlists/subdomains.txt")
    fullscan_parser.add_argument("-e", "--extensions", help="File extensions to check (comma separated)", default="php,html,js,txt")
    fullscan_parser.add_argument("-t", "--threads", help="Number of threads", type=int, default=50)
    fullscan_parser.add_argument("--timeout", help="Timeout in seconds", type=float, default=1.0)
    fullscan_parser.add_argument("-s", "--speed", help="Scan speed", choices=["fast", "normal", "thorough"], default="normal")
    fullscan_parser.add_argument("--skip-fuzzing", help="Skip URL fuzzing", action="store_true")
    fullscan_parser.add_argument("--skip-portscan", help="Skip port scanning", action="store_true")
    fullscan_parser.add_argument("--use-ip", help="Use IP addresses instead of hostnames", action="store_true")
    fullscan_parser.add_argument("--fuzz-wordlist", help="Path to URL fuzzing wordlist file (defaults to wordlists/common.txt)", default="wordlists/common.txt")
    fullscan_parser.add_argument("--no-advanced-discovery", help="Disable advanced subdomain discovery methods like Certificate Transparency", action="store_true")
    fullscan_parser.add_argument("--skip-wordlist", help="Skip wordlist-based subdomain enumeration and rely only on advanced discovery methods", action="store_true")
    
    # Parse arguments
    args = parser.parse_args()
    
    # Display banner
    banner()
    
    if args.command is None:
        parser.print_help()
        sys.exit(1)
    
    try:
        if args.command == "fuzz":
            # Apply speed adjustments
            timeout = args.timeout
            extensions = args.extensions.split(",")
            threads = args.threads
            
            if args.speed == "fast":
                extensions = ["html", "php"]
                timeout = 1.0
                threads = min(100, threads)
            elif args.speed == "thorough":
                extensions = args.extensions.split(",") + ["xml", "json", "asp", "aspx", "jsp", "cgi", "bak", "old", "backup"]
                timeout = args.timeout * 2
                threads = max(20, threads // 2)
            
            fuzzer = URLFuzzer(
                target=args.target,
                wordlist=args.wordlist,
                extensions=extensions,
                threads=threads,
                output=args.output,
                timeout=timeout,
                use_ip=args.use_ip
            )
            fuzzer.run()
        
        elif args.command == "subdomains":
            # Apply speed adjustments
            threads = args.threads
            
            if args.speed == "fast":
                threads = min(100, threads)
            elif args.speed == "thorough":
                threads = max(20, threads // 2)
                
            finder = SubdomainFinder(
                domain=args.domain,
                wordlist=args.wordlist,
                threads=threads,
                output=args.output,
                use_advanced=not args.no_advanced_discovery,
                skip_wordlist=args.skip_wordlist
            )
            finder.run()
        
        elif args.command == "scan":
            # Apply speed adjustments
            ports = args.ports
            threads = args.threads
            timeout = args.timeout
            
            if args.speed == "fast":
                ports = "80,443,8080,8443"
                threads = min(100, threads)
                timeout = 0.5
            elif args.speed == "normal":
                if ports == "1-1000":  # Only override if using default
                    ports = "21-25,80-443,1433,3306,3389,5432,8080-8443"
            elif args.speed == "thorough":
                if ports == "1-1000":  # Only override if using default
                    ports = "1-1024,1433,3306,3389,5432,8080-8443,9000-9001,10000"
                threads = max(20, threads // 2)
                timeout = args.timeout * 2
                
            scanner = PortScanner(
                target=args.target,
                ports=ports,
                timeout=timeout,
                output=args.output,
                threads=threads
            )
            scanner.run()
            
        elif args.command == "fullscan":
            run_full_scan(args)
    
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Operation cancelled by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")

if __name__ == "__main__":
    main() 
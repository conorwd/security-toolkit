#!/usr/bin/env python3
import dns.resolver
import threading
import os
import sys
import time
import json
import random
import string
import socket
import requests
import re
import concurrent.futures
from queue import Queue
from datetime import datetime
from tqdm import tqdm
from colorama import Fore, Style
from urllib.parse import urlparse

class SubdomainFinder:
    def __init__(self, domain, wordlist="wordlists/subdomains.txt", threads=50, output=None, use_advanced=True, skip_wordlist=False):
        """
        Initialize the subdomain finder
        
        Args:
            domain (str): Target domain
            wordlist (str): Path to wordlist file
            threads (int): Number of threads
            output (str): Output file path
            use_advanced (bool): Whether to use advanced discovery methods
            skip_wordlist (bool): Whether to skip traditional wordlist-based enumeration
        """
        self.domain = domain
        self.wordlist = wordlist
        self.threads = threads
        self.output = output or f"results_subdomains_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        self.queue = Queue()
        self.found_subdomains = []
        self.progress_bar = None
        self.total_subdomains = 0
        self.use_advanced = use_advanced
        self.skip_wordlist = skip_wordlist
        
        # Configure DNS resolver for better performance
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 1
        self.resolver.lifetime = 1
        self.resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']  # Use fast public DNS servers
        
        # For wildcard detection
        self.has_wildcard = False
        self.wildcard_ips = set()
        self.cloudflare_ips = set()
        self.random_response_signatures = {}  # Store response signatures for random subdomains
        
        # Remove protocol if present
        if "://" in self.domain:
            self.domain = self.domain.split("://")[1].strip("/")
        
        # Validate and prepare
        self._validate_domain()
        self._detect_wildcards()
        
        # First use advanced methods if enabled
        if self.use_advanced:
            self._find_from_certificate_transparency()
            self._find_from_common_osint()
            self._find_from_dns_records()
            
        # Then load wordlist for traditional enumeration if not skipped
        if not self.skip_wordlist:
            self._load_wordlist()
    
    def _validate_domain(self):
        """Validate that the domain resolves"""
        try:
            answers = self.resolver.resolve(self.domain, 'A')
            ip_address = answers[0].address
            print(f"{Fore.GREEN}[+] Domain {self.domain} resolves to {ip_address}{Style.RESET_ALL}")
            
            # Check if this is a Cloudflare IP
            if self._is_cloudflare_ip(ip_address):
                print(f"{Fore.YELLOW}[!] Main domain is behind Cloudflare ({ip_address}){Style.RESET_ALL}")
                self.cloudflare_ips.add(ip_address)
                
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout) as e:
            print(f"{Fore.RED}[!] Error resolving domain: {e}{Style.RESET_ALL}")
            sys.exit(1)
    
    def _is_cloudflare_ip(self, ip):
        """Check if an IP belongs to Cloudflare"""
        # Known Cloudflare IP ranges
        cloudflare_ranges = [
            "104.16.0.0/12",
            "104.22.0.0/16",
            "104.23.0.0/16",
            "104.24.0.0/16",
            "172.64.0.0/13",
            "172.67.0.0/16",
            "172.68.0.0/16",
            "172.69.0.0/16"
        ]
        
        # Simple check if IP starts with common Cloudflare prefixes
        for cf_range in cloudflare_ranges:
            prefix = cf_range.split(".")[0]
            if ip.startswith(prefix):
                return True
                
        return False
    
    def _generate_random_subdomain(self, length=10):
        """Generate a random subdomain name"""
        chars = string.ascii_lowercase + string.digits
        return ''.join(random.choice(chars) for _ in range(length))
    
    def _detect_wildcards(self):
        """Detect if the domain has wildcard DNS records"""
        print(f"{Fore.CYAN}[*] Checking for wildcard DNS records...{Style.RESET_ALL}")
        
        # Test 10 random subdomains for more accurate detection
        random_subdomains = [
            f"{self._generate_random_subdomain()}.{self.domain}",
            f"{self._generate_random_subdomain()}.{self.domain}",
            f"{self._generate_random_subdomain()}.{self.domain}",
            f"{self._generate_random_subdomain()}.{self.domain}",
            f"{self._generate_random_subdomain()}.{self.domain}",
            f"{self._generate_random_subdomain()}.{self.domain}",
            f"{self._generate_random_subdomain()}.{self.domain}",
            f"{self._generate_random_subdomain()}.{self.domain}",
            f"{self._generate_random_subdomain()}.{self.domain}",
            f"{self._generate_random_subdomain()}.{self.domain}"
        ]
        
        wildcard_count = 0
        for subdomain in random_subdomains:
            try:
                answers = self.resolver.resolve(subdomain, 'A')
                ip_address = answers[0].address
                
                # Store the HTTP response signature for this random subdomain
                try:
                    response = requests.get(
                        f"https://{subdomain}", 
                        timeout=3, 
                        verify=False,
                        allow_redirects=False,
                        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                    )
                    # Create a simple signature from status code and content length
                    signature = f"{response.status_code}:{len(response.content)}"
                    self.random_response_signatures[ip_address] = signature
                except:
                    pass
                
                # If a random subdomain resolves, it's likely a wildcard
                wildcard_count += 1
                self.wildcard_ips.add(ip_address)
                
                # Check if this is a Cloudflare IP
                if self._is_cloudflare_ip(ip_address):
                    self.cloudflare_ips.add(ip_address)
                
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                pass
        
        # If more than half of random subdomains resolve, it's definitely a wildcard
        if wildcard_count >= 5:
            self.has_wildcard = True
            print(f"{Fore.YELLOW}[!] Wildcard DNS detected! This domain resolves any subdomain to: {', '.join(self.wildcard_ips)}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Additional verification will be performed to filter false positives{Style.RESET_ALL}")
            
            if self.cloudflare_ips:
                print(f"{Fore.YELLOW}[!] Domain is using Cloudflare ({', '.join(self.cloudflare_ips)}){Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[!] Will perform additional validation for Cloudflare IPs{Style.RESET_ALL}")
    
    def _find_from_certificate_transparency(self):
        """Find subdomains from Certificate Transparency logs"""
        print(f"{Fore.CYAN}[*] Searching Certificate Transparency logs for {self.domain}{Style.RESET_ALL}")
        
        # CT Log providers to query
        ct_providers = [
            f"https://crt.sh/?q=%.{self.domain}&output=json",
            f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
        ]
        
        found_from_ct = set()
        
        for provider_url in ct_providers:
            try:
                response = requests.get(
                    provider_url,
                    timeout=10,
                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                )
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        
                        # Process crt.sh data
                        if "crt.sh" in provider_url:
                            for cert in data:
                                # Extract domain and all SANs
                                if 'name_value' in cert:
                                    domains = cert['name_value'].split('\n')
                                    for domain in domains:
                                        if self.domain in domain and domain != self.domain:
                                            found_from_ct.add(domain)
                        
                        # Process certspotter data
                        elif "certspotter" in provider_url:
                            for cert in data:
                                if 'dns_names' in cert:
                                    for domain in cert['dns_names']:
                                        if self.domain in domain and domain != self.domain:
                                            found_from_ct.add(domain)
                    except:
                        # If JSON parsing fails, try regex instead
                        pattern = r'([a-zA-Z0-9][-a-zA-Z0-9]*[a-zA-Z0-9]\.)+' + re.escape(self.domain)
                        matches = re.findall(pattern, response.text)
                        found_from_ct.update(matches)
                        
            except requests.exceptions.RequestException:
                continue
        
        print(f"{Fore.GREEN}[+] Found {len(found_from_ct)} subdomains from Certificate Transparency logs{Style.RESET_ALL}")
        
        # Add found subdomains to the queue for verification
        for subdomain in found_from_ct:
            if subdomain not in [item[0] for item in self.found_subdomains]:
                self.queue.put(subdomain)
                self.total_subdomains += 1
    
    def _find_from_common_osint(self):
        """Find subdomains from common OSINT sources"""
        print(f"{Fore.CYAN}[*] Searching OSINT sources for {self.domain}{Style.RESET_ALL}")
        
        # OSINT APIs to query
        osint_sources = [
            f"https://api.hackertarget.com/hostsearch/?q={self.domain}",
            f"https://rapiddns.io/subdomain/{self.domain}?full=1&down=1"
        ]
        
        found_from_osint = set()
        
        for source_url in osint_sources:
            try:
                response = requests.get(
                    source_url,
                    timeout=10,
                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                )
                
                if response.status_code == 200:
                    # Extract subdomains using regex
                    pattern = r'([a-zA-Z0-9][-a-zA-Z0-9]*[a-zA-Z0-9]\.)+' + re.escape(self.domain)
                    matches = re.findall(pattern, response.text)
                    found_from_osint.update(matches)
                    
            except requests.exceptions.RequestException:
                continue
        
        print(f"{Fore.GREEN}[+] Found {len(found_from_osint)} subdomains from OSINT sources{Style.RESET_ALL}")
        
        # Add found subdomains to the queue for verification
        for subdomain in found_from_osint:
            if subdomain not in [item[0] for item in self.found_subdomains]:
                self.queue.put(subdomain)
                self.total_subdomains += 1
    
    def _find_from_dns_records(self):
        """Find subdomains from common DNS records"""
        print(f"{Fore.CYAN}[*] Checking DNS records for {self.domain}{Style.RESET_ALL}")
        
        # DNS record types to query
        record_types = ['MX', 'NS', 'CNAME', 'SOA', 'TXT']
        found_from_dns = set()
        
        for record_type in record_types:
            try:
                answers = self.resolver.resolve(self.domain, record_type)
                for rdata in answers:
                    answer_text = rdata.to_text()
                    # Extract potential subdomains from DNS records
                    if self.domain in answer_text:
                        pattern = r'([a-zA-Z0-9][-a-zA-Z0-9]*[a-zA-Z0-9]\.)+' + re.escape(self.domain)
                        matches = re.findall(pattern, answer_text)
                        found_from_dns.update(matches)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                continue
        
        print(f"{Fore.GREEN}[+] Found {len(found_from_dns)} subdomains from DNS records{Style.RESET_ALL}")
        
        # Add found subdomains to the queue for verification
        for subdomain in found_from_dns:
            if subdomain not in [item[0] for item in self.found_subdomains]:
                self.queue.put(subdomain)
                self.total_subdomains += 1
    
    def _verify_http_response(self, subdomain, ip):
        """Verify if a subdomain is real by making an HTTP request to it"""
        # Skip verification if no wildcard was detected
        if not self.has_wildcard:
            return True
        
        # Always perform additional verification for Cloudflare IPs
        if ip in self.cloudflare_ips:
            # First check DNS records that wouldn't be affected by wildcard
            for record_type in ['CNAME', 'TXT', 'MX', 'NS']:
                try:
                    answers = self.resolver.resolve(subdomain, record_type)
                    # If we get any valid record, it's likely a real subdomain
                    return True
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                    pass
            
            # Try to connect to the subdomain via HTTP and compare response with random subdomain signatures
            try:
                response = requests.get(
                    f"https://{subdomain}", 
                    timeout=3, 
                    verify=False,
                    allow_redirects=False,
                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                )
                
                # Create a signature from status code and content length
                signature = f"{response.status_code}:{len(response.content)}"
                
                # If the signature is different from our random subdomain signatures, it might be a real subdomain
                if ip in self.random_response_signatures and signature != self.random_response_signatures[ip]:
                    return True
                
                # If we get a specific success status code (not just 200, which Cloudflare might return for anything)
                if response.status_code in [200, 201, 204, 301, 302, 307, 308]:
                    # Additional check: look for headers or content that suggests this is a real page
                    if 'server' in response.headers and 'cloudflare' not in response.headers['server'].lower():
                        return True
                    
                    # Check for common Cloudflare error indicators in content
                    if b"direct IP access not allowed" not in response.content and b"checking your browser" not in response.content:
                        return True
            
            except requests.exceptions.RequestException:
                pass
            
            # If all verification methods failed, and this is a Cloudflare IP that matches our wildcard IPs,
            # we should consider it a false positive
            if ip in self.wildcard_ips:
                return False
        
        # For non-Cloudflare IPs, if the IP differs from our detected wildcard IPs, it's likely real
        if ip not in self.wildcard_ips:
            return True
            
        # If the IP is in our wildcard IPs, do additional HTTP verification
        try:
            url = f"https://{subdomain}"
            response = requests.get(
                url, 
                timeout=3, 
                verify=False,
                allow_redirects=False,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            
            # Create a signature from status code and content length
            signature = f"{response.status_code}:{len(response.content)}"
            
            # If the signature is different from our random subdomain signatures, it might be a real subdomain
            if ip in self.random_response_signatures and signature != self.random_response_signatures[ip]:
                return True
                
            # If we get a success status
            if 200 <= response.status_code < 400:
                return True
                
        except requests.exceptions.RequestException:
            # Try HTTP if HTTPS fails
            try:
                url = f"http://{subdomain}"
                response = requests.get(
                    url, 
                    timeout=3, 
                    allow_redirects=False,
                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                )
                
                if 200 <= response.status_code < 400:
                    return True
                    
            except requests.exceptions.RequestException:
                pass
        
        # Default to False for wildcard IPs that couldn't be verified
        return False
    
    def _load_wordlist(self):
        """Load subdomains from wordlist into queue"""
        if self.skip_wordlist:
            print(f"{Fore.YELLOW}[*] Skipping wordlist-based enumeration as requested{Style.RESET_ALL}")
            return
            
        if not os.path.exists(self.wordlist):
            print(f"{Fore.RED}[!] Wordlist not found: {self.wordlist}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Please create or download a subdomain wordlist file{Style.RESET_ALL}")
            return
        
        with open(self.wordlist, "r") as f:
            wordlist_content = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            
        print(f"{Fore.CYAN}[*] Loaded {len(wordlist_content)} words from wordlist{Style.RESET_ALL}")
        
        # Add wordlist entries to queue
        for word in wordlist_content:
            subdomain = f"{word}.{self.domain}"
            # Only add if not already found by advanced methods
            if subdomain not in [item[0] for item in self.found_subdomains]:
                self.queue.put(subdomain)
                self.total_subdomains += 1
        
        print(f"{Fore.CYAN}[*] Total subdomains to check: {self.total_subdomains}{Style.RESET_ALL}")
    
    def _dns_worker(self):
        """Worker function for DNS resolution threads"""
        while not self.queue.empty():
            subdomain = self.queue.get()
            
            try:
                answers = self.resolver.resolve(subdomain, 'A')
                ip_address = answers[0].address
                
                # Skip known wildcard IPs unless they can be verified
                if ip_address in self.wildcard_ips and not self._verify_http_response(subdomain, ip_address):
                    if self.progress_bar:
                        self.progress_bar.update(1)
                    self.queue.task_done()
                    continue
                
                # Check if this is a Cloudflare IP and update the set
                if self._is_cloudflare_ip(ip_address):
                    self.cloudflare_ips.add(ip_address)
                
                self.found_subdomains.append((subdomain, ip_address))
                
                # Save to file immediately
                with open(self.output, "a") as f:
                    # Add Cloudflare indicator
                    cf_indicator = "CloudFlare" if ip_address in self.cloudflare_ips else "Direct"
                    f.write(f"{subdomain},{ip_address},{cf_indicator}\n")
                
                # Update progress bar without changing description for every found subdomain
                if self.progress_bar:
                    self.progress_bar.update(1)
            
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                if self.progress_bar:
                    self.progress_bar.update(1)
            
            except Exception as e:
                if self.progress_bar:
                    self.progress_bar.update(1)
            
            finally:
                self.queue.task_done()
    
    def run(self):
        """Run the subdomain finder"""
        print(f"{Fore.CYAN}[*] Starting subdomain discovery for {self.domain} with {self.threads} threads{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Results will be saved to {self.output}{Style.RESET_ALL}")
        
        # Create output file with header
        with open(self.output, "w") as f:
            f.write(f"# Subdomain Discovery Results for {self.domain}\n")
            f.write(f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Wordlist: {self.wordlist}\n\n")
            f.write("subdomain,ip_address,type\n")
        
        # Create and start progress bar - with minimal output format
        self.progress_bar = tqdm(total=self.total_subdomains, desc="Checking", unit="sub",
                                bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]')
        
        # Start worker threads
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self._dns_worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Wait for all tasks to be completed
        for t in threads:
            t.join()
        
        # Close progress bar
        self.progress_bar.close()
        
        # Display results - only at the end
        print("\n" + "=" * 60)
        print(f"{Fore.CYAN}[*] Subdomain Discovery Results{Style.RESET_ALL}")
        print("=" * 60)
        
        if not self.found_subdomains:
            print(f"{Fore.YELLOW}[!] No subdomains found{Style.RESET_ALL}")
        else:
            found_ips = {}
            
            # Group by IP for display - limited to save memory
            for subdomain, ip_address in sorted(self.found_subdomains):
                if ip_address not in found_ips:
                    found_ips[ip_address] = []
                found_ips[ip_address].append(subdomain)
            
            # Print summary first
            print(f"{Fore.GREEN}[+] Found {len(self.found_subdomains)} subdomains across {len(found_ips)} unique IPs{Style.RESET_ALL}")
            
            # Display by IP - limit the number of IPs and subdomains shown to conserve output
            max_ips_to_display = 10
            max_subdomains_per_ip = 5
            
            for i, (ip, subdomains) in enumerate(found_ips.items()):
                # Only show up to max_ips_to_display IPs
                if i >= max_ips_to_display:
                    remaining_ips = len(found_ips) - max_ips_to_display
                    print(f"{Fore.YELLOW}[+] ... and {remaining_ips} more IPs (see output file for complete results){Style.RESET_ALL}")
                    break
                
                cf_text = f"{Fore.CYAN} [CloudFlare]{Style.RESET_ALL}" if ip in self.cloudflare_ips else ""
                print(f"{Fore.YELLOW}[+] IP: {ip}{cf_text}{Style.RESET_ALL}")
                
                # Only show up to max_subdomains_per_ip per IP
                for j, subdomain in enumerate(sorted(subdomains)):
                    if j >= max_subdomains_per_ip:
                        remaining_subdomains = len(subdomains) - max_subdomains_per_ip
                        print(f"  {Fore.GREEN}... and {remaining_subdomains} more subdomains{Style.RESET_ALL}")
                        break
                    print(f"  {Fore.GREEN}[+] {subdomain}{Style.RESET_ALL}")
            
            print("\n" + "=" * 60)
            print(f"{Fore.GREEN}[+] Results saved to {self.output}{Style.RESET_ALL}")
        
        # Clean up memory before returning
        result_copy = list(self.found_subdomains)
        self.found_subdomains = []  # Release memory
        self.queue = Queue()  # Reset queue
        self.wildcard_ips.clear()  # Clear sets to free memory
        self.cloudflare_ips.clear()
        self.random_response_signatures.clear()
        
        return result_copy 
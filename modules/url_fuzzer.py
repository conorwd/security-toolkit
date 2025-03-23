#!/usr/bin/env python3
import requests
import threading
import os
import sys
import time
import json
import re
import hashlib
import difflib
import socket
from queue import Queue
from datetime import datetime
from tqdm import tqdm
from colorama import Fore, Style
from urllib.parse import urljoin, urlparse
import ssl
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class URLFuzzer:
    def __init__(self, target, wordlist="wordlists/common.txt", extensions=None, threads=50, output=None, timeout=2, use_ip=False, follow_redirects=True, realtime_callback=None):
        """
        Initialize the URL fuzzer
        
        Args:
            target (str): Target URL
            wordlist (str): Path to wordlist file
            extensions (list): List of file extensions to check. If None, uses a default set optimized for pentesting:
                               - Common web files: php, html, js, txt
                               - Server-side code: asp, aspx, jsp, cgi
                               - Config & data files: xml, json, sql, config, log
                               - Backup files: bak, old, backup
                               - Version control: git, svn
            threads (int): Number of threads
            output (str): Output file path
            timeout (float): Request timeout in seconds
            use_ip (bool): Use IP address instead of hostname
            follow_redirects (bool): Follow redirects for initial target detection
            realtime_callback (function): Callback function for real-time reporting of found URLs
        """
        self.target = target.rstrip("/")
        self.wordlist = wordlist
        # Provide a comprehensive default set of extensions for pentesting
        self.extensions = extensions or ["php", "html", "js", "txt"]
        self.threads = threads
        self.timeout = timeout
        self.use_ip = use_ip
        self.follow_redirects = follow_redirects
        self.realtime_callback = realtime_callback
        
        # Extract domain and resolve IP if needed
        self.target_domain = None
        self.target_ip = None
        self.original_host = None
        self.initial_redirect = None
        
        # Handle any initial redirects in the target URL
        if self.follow_redirects:
            self._follow_initial_redirects()
            
        if self.use_ip:
            self._resolve_target_ip()
            
        # Set up output file
        if not output:
            target_name = self.target_domain or urlparse(self.target).netloc
            self.output = f"results_urlfuzz_{target_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        else:
            self.output = output
            
        self.queue = Queue()
        self.found_urls = []
        self.progress_bar = None
        self.total_paths = 0
        self.session = requests.Session()
        
        # For soft 404 detection
        self.baseline_samples = {}
        self.content_threshold = 0.95  # Similarity threshold for soft 404 detection
        
        # Configure session for better performance
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=threads,
            pool_maxsize=threads,
            max_retries=2
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        
        # Add trailing slash if the URL doesn't have a file extension
        if not any(self.target.endswith(f".{ext}") for ext in self.extensions):
            self.target = f"{self.target}/"
        
        # Track valid domains to avoid rechecking invalid ones
        self.invalid_domains = set()
        
        # To prevent duplicate url reports
        self.found_url_hashes = set()
        
        # Validate and prepare
        self._validate_target()
        self._establish_baseline()
        self._load_wordlist()
    
    def _follow_initial_redirects(self):
        """Follow redirects for the initial target URL and update target if necessary"""
        try:
            print(f"{Fore.CYAN}[*] Checking for redirects at {self.target}{Style.RESET_ALL}")
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'}
            
            resp = requests.get(
                self.target, 
                timeout=self.timeout, 
                headers=headers,
                allow_redirects=True,  # Follow redirects
                verify=False  # Ignore SSL certificate errors
            )
            
            # If we were redirected, update the target
            if resp.url != self.target:
                self.initial_redirect = self.target
                self.target = resp.url.rstrip("/")
                print(f"{Fore.YELLOW}[!] Target redirected from {self.initial_redirect} to {self.target}{Style.RESET_ALL}")
        except requests.exceptions.RequestException as e:
            print(f"{Fore.YELLOW}[!] Error checking for redirects: {e}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Continuing with original target{Style.RESET_ALL}")
    
    def _resolve_target_ip(self):
        """Resolve the target domain to an IP address"""
        parsed_url = urlparse(self.target)
        self.target_domain = parsed_url.netloc
        
        # Remove port from hostname if present
        hostname = self.target_domain.split(':')[0]
        
        try:
            print(f"{Fore.CYAN}[*] Resolving hostname {hostname} to IP address{Style.RESET_ALL}")
            self.target_ip = socket.gethostbyname(hostname)
            print(f"{Fore.GREEN}[+] Hostname {hostname} resolves to IP address {self.target_ip}{Style.RESET_ALL}")
            
            # Save the original host for the Host header
            self.original_host = self.target_domain
            
            # Update the target URL to use the IP address
            scheme = parsed_url.scheme or "https"
            path = parsed_url.path or ""
            
            # Reconstruct the URL with the IP
            port = ""
            if ':' in self.target_domain:
                port = f":{self.target_domain.split(':')[1]}"
                
            self.target = f"{scheme}://{self.target_ip}{port}{path}"
            print(f"{Fore.CYAN}[*] Using IP-based target URL: {self.target}{Style.RESET_ALL}")
            
        except socket.gaierror as e:
            print(f"{Fore.RED}[!] Error resolving hostname: {e}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Continuing with original target{Style.RESET_ALL}")
    
    def _validate_target(self):
        """Validate that the target is accessible"""
        try:
            headers = {}
            if self.use_ip and self.original_host:
                headers['Host'] = self.original_host
                
            resp = self.session.get(
                self.target, 
                timeout=self.timeout, 
                headers=headers,
                verify=False  # Ignore SSL certificate errors
            )
            print(f"{Fore.GREEN}[+] Target {self.target} is accessible (Status: {resp.status_code}){Style.RESET_ALL}")
        except requests.exceptions.SSLError as e:
            print(f"{Fore.YELLOW}[!] SSL Error when connecting to target: {e}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Continuing with SSL verification disabled{Style.RESET_ALL}")
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[!] Error connecting to target: {e}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Continuing anyway, but some requests may fail{Style.RESET_ALL}")
    
    def _establish_baseline(self):
        """Establish baseline responses for 404 detection"""
        print(f"{Fore.CYAN}[*] Establishing baseline responses for 404 detection{Style.RESET_ALL}")
        
        # Generate random strings that are unlikely to exist
        random_paths = [
            f"nonexistent_page_{os.urandom(8).hex()}",
            f"definitely_not_found_{os.urandom(8).hex()}",
            f"random_path_{os.urandom(8).hex()}",
            f"doesnt_exist_{os.urandom(8).hex()}",
            f"404_test_{os.urandom(8).hex()}"
        ]
        
        success_count = 0
        for path in random_paths:
            try:
                url = urljoin(self.target, path)
                headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'}
                
                if self.use_ip and self.original_host:
                    headers['Host'] = self.original_host
                
                resp = self.session.get(
                    url, 
                    timeout=self.timeout,
                    allow_redirects=False,
                    headers=headers,
                    verify=False  # Ignore SSL certificate errors
                )
                
                # Save baseline response details
                content_hash = hashlib.md5(resp.content).hexdigest()
                content_length = len(resp.content)
                self.baseline_samples[content_hash] = {
                    'length': content_length,
                    'status': resp.status_code,
                    'url': url
                }
                success_count += 1
                
            except requests.exceptions.RequestException:
                continue
                
        if success_count > 0:
            print(f"{Fore.GREEN}[+] Established {success_count} baseline 404 responses{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] Failed to establish baseline 404 responses, soft 404 detection may be inaccurate{Style.RESET_ALL}")
    
    def _is_similar_to_baseline(self, response):
        """Check if a response is similar to baseline 404 responses"""
        content = response.content
        content_hash = hashlib.md5(content).hexdigest()
        content_length = len(content)
        
        # Direct hash match
        if content_hash in self.baseline_samples:
            return True
        
        # Similar content length match (within 5%)
        for baseline in self.baseline_samples.values():
            baseline_length = baseline['length']
            
            # If lengths are almost identical (within 5%)
            if abs(content_length - baseline_length) / max(content_length, baseline_length) < 0.05:
                return True
        
        return False
    
    def _is_valid_response(self, response, url):
        """Determine if a response indicates an actual resource"""
        # First check if it's similar to our baseline 404s
        if self._is_similar_to_baseline(response):
            return False
            
        status = response.status_code
        content_length = len(response.content)
        content_type = response.headers.get('Content-Type', '')
        
        # Check status codes
        if status == 404 or status >= 500:
            return False
            
        # 403 Forbidden is often a valid finding for security testing
        if status == 403:
            # For .ht* files, always consider 403 responses valid
            if any(ext in url.lower() for ext in ['.hta', '.htaccess', '.htpasswd']):
                return True
            
            # For other files, consider 403 valid if the content is not a generic error
            # This helps find protected resources
            return True
            
        # Common success status codes
        if status in [200, 201, 301, 302, 401]:
            # For success codes, check content to filter out generic pages
            
            # Very small responses might be empty pages
            if content_length < 10:
                return False
                
            # For redirects, check if it's not redirecting to the homepage or a standard error page
            if status in [301, 302]:
                redirect_url = response.headers.get('Location', '')
                parsed_redirect = urlparse(redirect_url)
                parsed_orig = urlparse(url)
                
                # If it redirects to homepage or root, it might be a default redirect for invalid paths
                if not parsed_redirect.path or parsed_redirect.path == '/' or 'error' in parsed_redirect.path.lower():
                    # Only consider it valid if the status is 301/302 AND it's not redirecting to home/error
                    if redirect_url and not (redirect_url.endswith('/') or 'index' in redirect_url.lower()):
                        return True
                    return False
                return True
                
            # Check for common CMS pages and admin areas
            admin_indicators = [
                'login', 'admin', 'dashboard', 'wp-', 'cpanel',
                'phpmyadmin', 'administrator', 'moderator',
                'user', 'console', 'portal', 'account'
            ]
            
            # Check for generic content/pages that might indicate real pages
            content_indicators = [
                'welcome', 'about', 'contact', 'service',
                'product', 'category', 'gallery', 'news',
                'article', 'blog', 'forum', 'privacy', 'terms',
                'faq', 'help', 'support', 'download', 'upload'
            ]
            
            # Convert response content to lowercase string for easier searching
            content_str = response.content.decode('utf-8', errors='ignore').lower()
            
            # If URL contains admin indicators or content indicators, it's likely valid
            if any(indicator in url.lower() for indicator in admin_indicators + content_indicators):
                return True
                
            # For non-redirect success codes, check title and headers
            if status in [200, 201]:
                # If it's HTML content, look for proper structure
                if 'text/html' in content_type:
                    # Check for HTML indicators that suggest a real page
                    html_indicators = ['<title>', '<h1>', '<article', '<main', '<div id="content']
                    if any(indicator in content_str for indicator in html_indicators):
                        return True
                
                # For API endpoints or other non-HTML content
                if ('application/json' in content_type or 
                    'application/xml' in content_type or 
                    'text/xml' in content_type):
                    return True
            
            # Default is to consider success codes as valid
            return True
            
        # For any other status code, consider valid
        return True
    
    def _load_wordlist(self):
        """Load paths from wordlist into queue"""
        if not os.path.exists(self.wordlist):
            print(f"{Fore.RED}[!] Wordlist not found: {self.wordlist}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Please create or download a wordlist file at {self.wordlist}{Style.RESET_ALL}")
            return
        
        with open(self.wordlist, "r") as f:
            wordlist_content = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            
        print(f"{Fore.CYAN}[*] Loaded {len(wordlist_content)} words from wordlist{Style.RESET_ALL}")
        
        # Always load security-focused wordlist
        security_wordlist = "wordlists/security_files.txt"
        security_content = []
        if os.path.exists(security_wordlist):
            with open(security_wordlist, "r") as f:
                security_content = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            print(f"{Fore.CYAN}[*] Loaded {len(security_content)} security-sensitive paths from {security_wordlist}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] Security wordlist not found: {security_wordlist}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Please create or download a security wordlist file{Style.RESET_ALL}")
        
        # First add all words as plain paths without extensions
        print(f"{Fore.CYAN}[*] Adding all wordlist entries as plain paths (without extensions){Style.RESET_ALL}")
        plain_paths_count = 0
        for word in wordlist_content:
            # Add the base path (this is important for finding paths without extensions like /about, /terms-and-conditions)
            self.queue.put(word)
            plain_paths_count += 1
            
            # Try common variations of path formats
            # Hyphenated version (terms-and-conditions)
            if ' ' in word:
                self.queue.put(word.replace(' ', '-'))
                plain_paths_count += 1
            # Underscored version (terms_and_conditions)
            if ' ' in word:
                self.queue.put(word.replace(' ', '_'))
                plain_paths_count += 1
        
        print(f"{Fore.CYAN}[*] Added {plain_paths_count} plain paths without extensions{Style.RESET_ALL}")
        
        # Then add paths with extensions
        print(f"{Fore.CYAN}[*] Adding paths with extensions: {','.join(self.extensions)}{Style.RESET_ALL}")
        paths_with_extensions = 0
        for word in wordlist_content:
            # Add paths with extensions
            for ext in self.extensions:
                path = f"{word}.{ext}"
                self.queue.put(path)
                paths_with_extensions += 1
        
        print(f"{Fore.CYAN}[*] Added {paths_with_extensions} paths with extensions{Style.RESET_ALL}")
        
        # Always add security-focused paths (these are complete paths that don't need extensions)
        if security_content:
            print(f"{Fore.CYAN}[*] Including security-sensitive files in scan by default{Style.RESET_ALL}")
            for path in security_content:
                self.queue.put(path)
                self.total_paths += 1
        
        self.total_paths = plain_paths_count + paths_with_extensions + len(security_content)
        print(f"{Fore.CYAN}[*] Total paths to fuzz: {self.total_paths}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Will scan plain paths first, then paths with extensions{Style.RESET_ALL}")
    
    def _is_duplicate_url(self, url, status, content_length):
        """Check if this URL has already been found (to prevent duplicate logging)"""
        # Create a unique hash for this URL result
        result_hash = f"{url}:{status}:{content_length}"
        hash_digest = hashlib.md5(result_hash.encode()).hexdigest()
        
        # Check if we've seen this result before
        if hash_digest in self.found_url_hashes:
            return True
        
        # If not, add it to our set
        self.found_url_hashes.add(hash_digest)
        return False

    def _fuzz_worker(self):
        """Worker function for URL fuzzing threads"""
        while not self.queue.empty():
            path = self.queue.get()
            url = urljoin(self.target, path)
            
            # Get domain from URL to check if we've already found it invalid
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            if domain in self.invalid_domains:
                # Skip domains we already know are invalid
                if self.progress_bar:
                    self.progress_bar.update(1)
                self.queue.task_done()
                continue
            
            try:
                headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'}
                
                # Add Host header if using IP address
                if self.use_ip and self.original_host:
                    headers['Host'] = self.original_host
                
                response = self.session.get(
                    url, 
                    timeout=self.timeout, 
                    allow_redirects=False,
                    headers=headers,
                    verify=False  # Ignore SSL certificate errors
                )
                status = response.status_code
                content_length = len(response.content)
                
                # Special handling for sensitive files with 403 Forbidden responses
                is_sensitive_protected = False
                if status == 403 and any(ext in url.lower() for ext in ['.hta', '.htaccess', '.htpasswd']):
                    is_sensitive_protected = True
                
                # Use more comprehensive validation to determine if this is a real page
                if is_sensitive_protected or self._is_valid_response(response, url):
                    # Check if this is a duplicate to avoid repeating the same entry
                    if not self._is_duplicate_url(url, status, content_length):
                        self.found_urls.append((url, status, content_length))
                        
                        # Save to file immediately but without console output
                        with open(self.output, "a") as f:
                            if is_sensitive_protected:
                                f.write(f"{status} - {url} - {content_length} bytes [PROTECTED]\n")
                            else:
                                f.write(f"{status} - {url} - {content_length} bytes\n")
                        
                        # Call the realtime callback function if provided - with reduced payload
                        if self.realtime_callback:
                            # Get the path relative to the target
                            path = url.replace(self.target, "").lstrip("/")
                            if not path:
                                path = "/"
                            
                            result_type = "protected" if is_sensitive_protected else "normal"
                            
                            # Call the callback with the result - minimal data for efficiency
                            self.realtime_callback({
                                "url": url,
                                "status": status,
                                "size": content_length / 1024.0,  # Convert to KB
                                "type": result_type
                            })
                
                # Only update progress counter
                if self.progress_bar:
                    self.progress_bar.update(1)
                
                # If response is 404 or another clear error, mark domain as invalid
                if status == 404 or status >= 500:
                    self.invalid_domains.add(domain)
            
            except (requests.exceptions.RequestException, ssl.SSLError) as e:
                # Mark domain as invalid if we can't connect to it
                if isinstance(e, (requests.exceptions.ConnectionError, 
                                 requests.exceptions.Timeout,
                                 requests.exceptions.TooManyRedirects)):
                    self.invalid_domains.add(domain)
                
                # Update progress
                if self.progress_bar:
                    self.progress_bar.update(1)
            
            finally:
                # Release resources
                response = None
                self.queue.task_done()
    
    def run(self):
        """Run the URL fuzzer"""
        print(f"{Fore.CYAN}[*] Starting URL fuzzing on {self.target} with {self.threads} threads{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Results will be saved to {self.output}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Testing both plain paths and with extensions {','.join(self.extensions)}{Style.RESET_ALL}")
        
        # Create output file with header
        with open(self.output, "w") as f:
            f.write(f"# URL Fuzzing Results for {self.target}\n")
            f.write(f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Wordlist: {self.wordlist}\n")
            f.write(f"# Testing Plain Paths: Yes\n")
            f.write(f"# Extensions: {','.join(self.extensions)}\n\n")
        
        # Create and start progress bar - simplified display format without updating description
        self.progress_bar = tqdm(total=self.total_paths, desc="Fuzzing", unit="req", 
                                 bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]')
        
        # Start worker threads
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self._fuzz_worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Wait for all tasks to be completed
        for t in threads:
            t.join()
        
        # Close progress bar
        self.progress_bar.close()
        
        # Display results - only at the end, not during scan
        print("\n" + "=" * 60)
        print(f"{Fore.CYAN}[*] URL Fuzzing Results{Style.RESET_ALL}")
        print("=" * 60)
        
        if not self.found_urls:
            print(f"{Fore.YELLOW}[!] No valid URLs found{Style.RESET_ALL}")
        else:
            # Sort results and categorize them
            protected_files = []
            plain_paths = []
            extended_paths = []
            
            for url, status, content_length in sorted(self.found_urls, key=lambda x: x[1]):
                # Identify sensitive protected files
                if status == 403 and any(ext in url.lower() for ext in ['.hta', '.htaccess', '.htpasswd']):
                    protected_files.append((url, status, content_length))
                # Identify if this is a plain path or one with extension
                elif not any(f".{ext}" in url.split('/')[-1].lower() for ext in self.extensions):
                    plain_paths.append((url, status, content_length))
                else:
                    extended_paths.append((url, status, content_length))
            
            # Print summary numbers first for overview
            print(f"{Fore.GREEN}[+] Found {len(self.found_urls)} total URLs:{Style.RESET_ALL}")
            if protected_files:
                print(f"{Fore.YELLOW}    - {len(protected_files)} protected sensitive files{Style.RESET_ALL}")
            if plain_paths:
                print(f"{Fore.GREEN}    - {len(plain_paths)} plain paths{Style.RESET_ALL}")
            if extended_paths:
                print(f"{Fore.GREEN}    - {len(extended_paths)} paths with extensions{Style.RESET_ALL}")
            
            # Option to show actual findings - limited to conserve memory/output
            print("\nDetailed results saved to file. Showing sample of findings:")
            
            # Display a limited sample of protected sensitive files
            if protected_files:
                print(f"\n{Fore.YELLOW}PROTECTED SENSITIVE FILES (showing up to 5):{Style.RESET_ALL}")
                for url, status, content_length in protected_files[:5]:
                    print(f"{Fore.YELLOW}[{status}] {url} - {content_length} bytes [PROTECTED]{Style.RESET_ALL}")
                if len(protected_files) > 5:
                    print(f"{Fore.YELLOW}... and {len(protected_files)-5} more{Style.RESET_ALL}")
            
            # Display a limited sample of plain paths
            if plain_paths:
                print(f"\n{Fore.GREEN}PLAIN PATHS (showing up to 5):{Style.RESET_ALL}")
                for url, status, content_length in plain_paths[:5]:
                    color = Fore.GREEN if status < 300 else Fore.YELLOW
                    print(f"{color}[{status}] {url} - {content_length} bytes{Style.RESET_ALL}")
                if len(plain_paths) > 5:
                    print(f"{Fore.GREEN}... and {len(plain_paths)-5} more{Style.RESET_ALL}")
            
            # Display a limited sample of paths with extensions
            if extended_paths:
                print(f"\n{Fore.GREEN}PATHS WITH EXTENSIONS (showing up to 5):{Style.RESET_ALL}")
                for url, status, content_length in extended_paths[:5]:
                    color = Fore.GREEN if status < 300 else Fore.YELLOW
                    print(f"{color}[{status}] {url} - {content_length} bytes{Style.RESET_ALL}")
                if len(extended_paths) > 5:
                    print(f"{Fore.GREEN}... and {len(extended_paths)-5} more{Style.RESET_ALL}")
            
            print("\n" + "=" * 60)                
            print(f"{Fore.GREEN}[+] Results saved to {self.output}{Style.RESET_ALL}")
        
        # Clean up memory and return results
        result_copy = list(self.found_urls)
        self.found_urls = []  # Release memory
        self.queue = Queue()  # Reset queue
        self.invalid_domains.clear()  # Reset invalid domains
        
        return result_copy 
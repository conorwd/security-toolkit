#!/usr/bin/env python3
import socket
import threading
import nmap
import re
import time
import os
from datetime import datetime
from queue import Queue
from tqdm import tqdm
from colorama import Fore, Style

class PortScanner:
    def __init__(self, target, ports="1-1000", timeout=1.0, output=None, threads=50):
        """
        Initialize the port scanner
        
        Args:
            target (str): Target IP or hostname
            ports (str): Port range (e.g., "1-1000" or "80,443,8080")
            timeout (float): Timeout in seconds
            output (str): Output file path
            threads (int): Number of threads
        """
        self.target = target
        self.ports_str = ports
        self.timeout = timeout
        self.threads = threads
        self.output = output or f"results_portscan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        self.open_ports = []
        self.progress_bar = None
        self.port_list = []
        
        # Remove protocol if present
        if "://" in self.target:
            self.target = self.target.split("://")[1].strip("/")
        
        # Remove path if present
        if "/" in self.target:
            self.target = self.target.split("/")[0]
        
        # Parse ports
        self._parse_ports()
    
    def _parse_ports(self):
        """Parse port range string into a list of ports"""
        ports = []
        
        # Check if ports is a range (e.g., "1-1000")
        if "-" in self.ports_str:
            start, end = self.ports_str.split("-")
            try:
                start_port = int(start.strip())
                end_port = int(end.strip())
                ports.extend(range(start_port, end_port + 1))
            except ValueError:
                print(f"{Fore.RED}[!] Invalid port range: {self.ports_str}{Style.RESET_ALL}")
                return
        
        # Check if ports is a list (e.g., "80,443,8080")
        elif "," in self.ports_str:
            for p in self.ports_str.split(","):
                try:
                    ports.append(int(p.strip()))
                except ValueError:
                    print(f"{Fore.RED}[!] Invalid port: {p}{Style.RESET_ALL}")
        
        # Single port
        else:
            try:
                ports.append(int(self.ports_str.strip()))
            except ValueError:
                print(f"{Fore.RED}[!] Invalid port: {self.ports_str}{Style.RESET_ALL}")
        
        self.port_list = ports
    
    def _resolve_host(self):
        """Resolve hostname to IP address"""
        try:
            ip_address = socket.gethostbyname(self.target)
            if ip_address != self.target:
                print(f"{Fore.GREEN}[+] Hostname {self.target} resolves to {ip_address}{Style.RESET_ALL}")
            return ip_address
        except socket.gaierror:
            print(f"{Fore.RED}[!] Could not resolve hostname: {self.target}{Style.RESET_ALL}")
            return self.target
    
    def _scan_port_socket(self, ip, port):
        """Scan a single port using sockets"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    
    def _scan_port_nmap(self, ip, port):
        """Scan a single port using nmap"""
        nm = nmap.PortScanner()
        try:
            result = nm.scan(ip, str(port), arguments='-T4 -sV')
            if ip in result['scan'] and 'tcp' in result['scan'][ip] and port in result['scan'][ip]['tcp']:
                port_info = result['scan'][ip]['tcp'][port]
                state = port_info['state']
                service = port_info['name']
                version = port_info['product'] + " " + port_info['version'] if port_info['product'] else ""
                return state == 'open', service, version
            return False, "", ""
        except:
            return self._scan_port_socket(ip, port), "unknown", ""
    
    def _scan_worker(self, ip):
        """Worker function for port scanning threads"""
        while not self.port_queue.empty():
            port = self.port_queue.get()
            
            try:
                # Try to use nmap for better service detection
                try:
                    is_open, service, version = self._scan_port_nmap(ip, port)
                except:
                    # Fall back to simple socket scan
                    is_open = self._scan_port_socket(ip, port)
                    service = ""
                    version = ""
                
                if is_open:
                    port_info = (port, service, version)
                    self.open_ports.append(port_info)
                    
                    # Save to file immediately
                    with open(self.output, "a") as f:
                        f.write(f"{port},{service},{version}\n")
                    
                # Update progress without changing description for every found port
                if self.progress_bar:
                    self.progress_bar.update(1)
            
            except Exception as e:
                if self.progress_bar:
                    self.progress_bar.update(1)
            
            finally:
                self.port_queue.task_done()
    
    def run(self):
        """Run the port scanner"""
        print(f"{Fore.CYAN}[*] Starting port scan on {self.target} ({len(self.port_list)} ports){Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Results will be saved to {self.output}{Style.RESET_ALL}")
        
        # Resolve hostname to IP
        ip = self._resolve_host()
        
        # Create output file with header
        os.makedirs(os.path.dirname(self.output) if os.path.dirname(self.output) else '.', exist_ok=True)
        with open(self.output, "w") as f:
            f.write(f"# Port Scan Results for {self.target} ({ip})\n")
            f.write(f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Ports: {self.ports_str}\n\n")
            f.write("port,service,version\n")
        
        # Create queue and add ports
        self.port_queue = Queue()
        for port in self.port_list:
            self.port_queue.put(port)
        
        # Create and start progress bar with minimal output format
        self.progress_bar = tqdm(total=len(self.port_list), desc="Scanning", unit="port",
                                bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]')
        
        # Start worker threads
        threads = []
        thread_count = min(self.threads, len(self.port_list))
        for _ in range(thread_count):
            t = threading.Thread(target=self._scan_worker, args=(ip,))
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Wait for all tasks to be completed
        for t in threads:
            t.join()
        
        # Close progress bar
        self.progress_bar.close()
        
        # Display results only at the end
        print("\n" + "=" * 60)
        print(f"{Fore.CYAN}[*] Port Scan Results for {self.target} ({ip}){Style.RESET_ALL}")
        print("=" * 60)
        
        if not self.open_ports:
            print(f"{Fore.YELLOW}[!] No open ports found{Style.RESET_ALL}")
        else:
            # Sort by port number
            self.open_ports.sort(key=lambda x: x[0])
            
            # Print summary first
            print(f"{Fore.GREEN}[+] Found {len(self.open_ports)} open ports{Style.RESET_ALL}")
            
            # Build a table format - with limited output
            max_ports_to_display = 20  # Limit display to save memory and output
            print(f"{Fore.GREEN}| {'PORT':<8} | {'STATE':<8} | {'SERVICE':<15} | {'VERSION':<20} |{Style.RESET_ALL}")
            print(f"{'-' * 60}")
            
            for port, service, version in self.open_ports[:max_ports_to_display]:
                service = service or "unknown"
                version = version or ""
                print(f"| {port:<8} | {'open':<8} | {service:<15} | {version[:20]:<20} |")
            
            # If there are more ports than our display limit, show count of remaining
            if len(self.open_ports) > max_ports_to_display:
                print(f"\n{Fore.GREEN}... and {len(self.open_ports) - max_ports_to_display} more ports (see output file for full results){Style.RESET_ALL}")
            
            print("\n" + "=" * 60)
            print(f"{Fore.GREEN}[+] Results saved to {self.output}{Style.RESET_ALL}")
        
        # Clean up memory before returning
        result_copy = list(self.open_ports)
        self.open_ports = []  # Clear memory
        self.port_list = []   # Clear port list
        self.port_queue = Queue()  # Reset queue
        
        return result_copy 
"""
Enhanced Hostname Resolution for NetWatch SIEM
Provides multiple fallback methods for reliable device name detection
"""

import socket
import subprocess
import threading
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

class EnhancedHostnameResolver:
    def __init__(self, timeout=2, max_workers=4):
        self.timeout = timeout
        self.max_workers = max_workers
        self.cache = {}
        self.cache_ttl = 300  # 5 minutes
        self.logger = logging.getLogger(__name__)
        
    def resolve_hostname(self, ip):
        """
        Resolve hostname using multiple methods with fallbacks
        Returns the best available hostname or None
        """
        # Check cache first
        if ip in self.cache:
            cached_result, timestamp = self.cache[ip]
            if time.time() - timestamp < self.cache_ttl:
                return cached_result
        
        # Try multiple resolution methods
        methods = [
            self._dns_reverse_lookup,
            self._netbios_lookup,
            self._arp_hostname_lookup,
            self._nmap_hostname_scan,
            self._ping_hostname_extract,
            self._smb_hostname_lookup
        ]
        
        results = []
        
        # Run methods in parallel for speed
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_method = {
                executor.submit(method, ip): method.__name__ 
                for method in methods
            }
            
            for future in as_completed(future_to_method, timeout=self.timeout * 2):
                method_name = future_to_method[future]
                try:
                    result = future.result(timeout=self.timeout)
                    if result and result != method_name:  # Make sure we got a hostname, not method name
                        results.append((result, method_name))
                except Exception as e:
                    self.logger.debug(f"Method {method_name} failed for {ip}: {e}")
        
        # Choose the best result
        best_hostname = self._select_best_hostname(results, ip)
        
        # Cache the result
        self.cache[ip] = (best_hostname, time.time())
        
        if self.logger.level <= logging.DEBUG:
            self.logger.debug(f"Hostname resolution for {ip}: {best_hostname} (methods: {[r[1] for r in results]})")
        
        return best_hostname
    
    def _dns_reverse_lookup(self, ip):
        """Standard DNS reverse lookup"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            # Clean up the hostname
            hostname = hostname.split('.')[0]  # Remove domain
            return hostname if hostname != ip else None
        except Exception as e:
            self.logger.debug(f"DNS lookup failed for {ip}: {e}")
            return None
    
    def _netbios_lookup(self, ip):
        """NetBIOS name resolution (Windows/SMB)"""
        try:
            # Try nmblookup if available
            result = subprocess.run(
                ['nmblookup', '-A', ip], 
                capture_output=True, 
                text=True, 
                timeout=self.timeout
            )
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if '<00>' in line and 'UNIQUE' in line:
                        # Extract NetBIOS name
                        parts = line.split()
                        if len(parts) > 0:
                            name = parts[0].strip()
                            if name and name != ip:
                                return name
        except:
            pass
        return None
    
    def _arp_hostname_lookup(self, ip):
        """Try to get hostname from ARP table"""
        try:
            # Check if device is in ARP table with hostname
            result = subprocess.run(
                ['arp', '-a'], 
                capture_output=True, 
                text=True, 
                timeout=self.timeout
            )
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if ip in line and '(' in line and ')' in line:
                        # Extract hostname from ARP entry
                        match = re.search(r'\(([^)]+)\)', line)
                        if match:
                            hostname = match.group(1)
                            if hostname and hostname != ip:
                                return hostname
        except:
            pass
        return None
    
    def _nmap_hostname_scan(self, ip):
        """Use nmap to get hostname"""
        try:
            result = subprocess.run(
                ['nmap', '-sL', ip], 
                capture_output=True, 
                text=True, 
                timeout=self.timeout
            )
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Nmap scan report for' in line:
                        # Extract hostname from nmap output
                        parts = line.split('for ')
                        if len(parts) > 1:
                            hostname = parts[1].strip()
                            if hostname and hostname != ip:
                                return hostname.split()[0]  # Take first word
        except:
            pass
        return None
    
    def _ping_hostname_extract(self, ip):
        """Try to extract hostname from ping response"""
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '1', ip], 
                capture_output=True, 
                text=True, 
                timeout=self.timeout
            )
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'PING' in line and '(' in line and ')' in line:
                        # Extract hostname from ping output
                        match = re.search(r'PING ([^(]+)', line)
                        if match:
                            hostname = match.group(1).strip()
                            if hostname and hostname != ip:
                                return hostname
        except:
            pass
        return None
    
    def _smb_hostname_lookup(self, ip):
        """Try SMB hostname lookup"""
        try:
            # Try to get hostname via SMB
            result = subprocess.run(
                ['smbclient', '-L', ip, '-N'], 
                capture_output=True, 
                text=True, 
                timeout=self.timeout
            )
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Server=' in line:
                        # Extract server name
                        match = re.search(r'Server=([^,]+)', line)
                        if match:
                            hostname = match.group(1).strip()
                            if hostname and hostname != ip:
                                return hostname
        except:
            pass
        return None
    
    def _select_best_hostname(self, results, ip):
        """Select the best hostname from multiple results"""
        if not results:
            return None
        
        # Score different methods
        method_scores = {
            '_dns_reverse_lookup': 10,
            '_netbios_lookup': 8,
            '_arp_hostname_lookup': 6,
            '_nmap_hostname_scan': 7,
            '_ping_hostname_extract': 5,
            '_smb_hostname_lookup': 4
        }
        
        # Filter out invalid hostnames
        valid_results = []
        for hostname, method in results:
            if (hostname and 
                hostname != ip and 
                not hostname.startswith('192.168.') and
                not hostname.startswith('10.') and
                not hostname.startswith('172.') and
                len(hostname) > 1 and
                not re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname)):
                valid_results.append((hostname, method))
        
        if not valid_results:
            return None
        
        # Select the highest scored method
        best_result = max(valid_results, key=lambda x: method_scores.get(x[1], 0))
        return best_result[0]
    
    def resolve_multiple_hostnames(self, ip_list):
        """Resolve hostnames for multiple IPs efficiently"""
        results = {}
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_ip = {
                executor.submit(self.resolve_hostname, ip): ip 
                for ip in ip_list
            }
            
            for future in as_completed(future_to_ip, timeout=self.timeout * 3):
                ip = future_to_ip[future]
                try:
                    hostname = future.result(timeout=self.timeout)
                    results[ip] = hostname
                except Exception as e:
                    self.logger.debug(f"Failed to resolve hostname for {ip}: {e}")
                    results[ip] = None
        
        return results
    
    def clear_cache(self):
        """Clear the hostname cache"""
        self.cache.clear()
    
    def get_cache_stats(self):
        """Get cache statistics"""
        return {
            'cached_entries': len(self.cache),
            'cache_ttl': self.cache_ttl
        }

# Global instance
hostname_resolver = EnhancedHostnameResolver()

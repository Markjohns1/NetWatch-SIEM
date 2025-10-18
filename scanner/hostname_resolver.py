"""
Enhanced Hostname Resolution for NetWatch SIEM
Provides multiple fallback methods for reliable device name detection
Cross-platform compatible (Windows/Linux/macOS)
"""

import socket
import subprocess
import platform
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
import logging

class EnhancedHostnameResolver:
    def __init__(self, timeout=1, max_workers=4):
        self.timeout = timeout
        self.max_workers = max_workers
        self.cache = {}
        self.cache_ttl = 300  # 5 minutes
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.ERROR)  # Silent by default
        self.os_type = platform.system().lower()
        
    def resolve_hostname(self, ip):
        """
        Resolve hostname using multiple methods with fallbacks
        Returns the best available hostname or None
        """
        # Validate IP
        if not self._is_valid_ip(ip):
            return None
            
        # Check cache first
        if ip in self.cache:
            cached_result, timestamp = self.cache[ip]
            if time.time() - timestamp < self.cache_ttl:
                return cached_result
        
        # Try multiple resolution methods (fast ones first)
        methods = [
            self._dns_reverse_lookup,
            self._netbios_lookup,
            self._mdns_lookup,
        ]
        
        best_hostname = None
        
        # Try methods sequentially (faster than parallel for small number)
        for method in methods:
            try:
                result = method(ip)
                if result and self._is_valid_hostname(result, ip):
                    best_hostname = result
                    break  # Use first valid result
            except Exception as e:
                continue
        
        # Cache the result (even if None)
        self.cache[ip] = (best_hostname, time.time())
        
        return best_hostname
    
    def _is_valid_ip(self, ip):
        """Validate IP address format"""
        try:
            parts = ip.split('.')
            return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
        except:
            return False
    
    def _is_valid_hostname(self, hostname, ip):
        """Check if hostname is valid and different from IP"""
        if not hostname or len(hostname) < 2:
            return False
        
        # Hostname shouldn't be the IP itself
        if hostname == ip:
            return False
        
        # Shouldn't be another IP address
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
            return False
        
        # Shouldn't contain only numbers
        if hostname.replace('.', '').replace('-', '').isdigit():
            return False
        
        return True
    
    def _dns_reverse_lookup(self, ip):
        """Standard DNS reverse lookup - Most reliable method"""
        try:
            # Set socket timeout
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(self.timeout)
            
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                # Clean up the hostname
                hostname = hostname.split('.')[0]  # Remove domain
                return hostname if hostname else None
            finally:
                socket.setdefaulttimeout(old_timeout)
                
        except socket.herror:
            # No reverse DNS entry
            return None
        except socket.timeout:
            return None
        except Exception as e:
            return None
    
    def _netbios_lookup(self, ip):
        """NetBIOS name resolution (Windows/SMB networks)"""
        if self.os_type != 'windows':
            return None
            
        try:
            # Windows-specific NetBIOS lookup
            result = subprocess.run(
                ['nbtstat', '-A', ip],
                capture_output=True,
                text=True,
                timeout=self.timeout,
                creationflags=subprocess.CREATE_NO_WINDOW if self.os_type == 'windows' else 0
            )
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    # Look for the computer name (type <00>)
                    if '<00>' in line and 'UNIQUE' in line:
                        parts = line.split()
                        if len(parts) > 0:
                            name = parts[0].strip()
                            if name and len(name) > 1:
                                return name
        except subprocess.TimeoutExpired:
            return None
        except FileNotFoundError:
            # nbtstat not available
            return None
        except Exception as e:
            return None
        
        return None
    
    def _mdns_lookup(self, ip):
        """
        mDNS/Bonjour lookup (Apple devices, IoT)
        Works on local network for devices advertising via mDNS
        """
        try:
            # Try getfqdn which sometimes resolves mDNS names
            hostname = socket.getfqdn(ip)
            if hostname and hostname != ip:
                # Clean up .local domain if present
                hostname = hostname.replace('.local', '')
                hostname = hostname.split('.')[0]
                return hostname
        except Exception as e:
            return None
        
        return None
    
    def _ping_hostname_extract(self, ip):
        """
        Extract hostname from ping response
        Sometimes ping reveals the hostname
        """
        try:
            if self.os_type == 'windows':
                cmd = ['ping', '-n', '1', '-w', str(self.timeout * 1000), ip]
            else:
                cmd = ['ping', '-c', '1', '-W', str(self.timeout), ip]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + 0.5,
                creationflags=subprocess.CREATE_NO_WINDOW if self.os_type == 'windows' else 0
            )
            
            if result.returncode == 0:
                output = result.stdout
                
                # Windows: "Pinging hostname [IP]"
                match = re.search(r'Pinging\s+([^\s\[]+)\s+\[', output)
                if match:
                    hostname = match.group(1)
                    if hostname and hostname != ip:
                        return hostname
                
                # Linux: "PING hostname (IP)"
                match = re.search(r'PING\s+([^\s(]+)\s+\(', output)
                if match:
                    hostname = match.group(1)
                    if hostname and hostname != ip:
                        return hostname
        
        except subprocess.TimeoutExpired:
            return None
        except Exception as e:
            return None
        
        return None
    
    def resolve_with_ping(self, ip):
        """
        Public method to try ping-based hostname resolution
        Slower but sometimes catches what DNS misses
        """
        return self._ping_hostname_extract(ip)
    
    def resolve_multiple_hostnames(self, ip_list):
        """Resolve hostnames for multiple IPs efficiently"""
        results = {}
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_ip = {
                executor.submit(self.resolve_hostname, ip): ip 
                for ip in ip_list
            }
            
            for future in as_completed(future_to_ip, timeout=self.timeout * len(ip_list)):
                ip = future_to_ip[future]
                try:
                    hostname = future.result(timeout=self.timeout)
                    results[ip] = hostname
                except TimeoutError:
                    results[ip] = None
                except Exception as e:
                    results[ip] = None
        
        return results
    
    def clear_cache(self):
        """Clear the hostname cache"""
        self.cache.clear()
    
    def get_cache_stats(self):
        """Get cache statistics"""
        valid_entries = sum(1 for v, _ in self.cache.values() if v is not None)
        return {
            'total_cached': len(self.cache),
            'valid_hostnames': valid_entries,
            'cache_ttl_seconds': self.cache_ttl,
            'cache_hit_rate': f"{(valid_entries/len(self.cache)*100):.1f}%" if self.cache else "0%"
        }
    
    def set_cache_ttl(self, seconds):
        """Set cache time-to-live in seconds"""
        self.cache_ttl = seconds
    
    def enable_debug(self):
        """Enable debug logging"""
        self.logger.setLevel(logging.DEBUG)
    
    def disable_debug(self):
        """Disable debug logging"""
        self.logger.setLevel(logging.ERROR)


# Global instance for easy import
hostname_resolver = EnhancedHostnameResolver(timeout=1, max_workers=4)


# Convenience functions for direct use
def resolve_hostname(ip, timeout=1):
    """Quick hostname resolution for single IP"""
    resolver = EnhancedHostnameResolver(timeout=timeout)
    return resolver.resolve_hostname(ip)


def resolve_multiple(ip_list, timeout=1, max_workers=4):
    """Quick hostname resolution for multiple IPs"""
    resolver = EnhancedHostnameResolver(timeout=timeout, max_workers=max_workers)
    return resolver.resolve_multiple_hostnames(ip_list)


# Testing function
def test_resolver():
    """Test the hostname resolver"""
    print("Testing EnhancedHostnameResolver...")
    print(f"OS: {platform.system()}")
    
    # Test IPs (common router/gateway addresses)
    test_ips = ['192.168.1.1', '192.168.0.1', '8.8.8.8', '1.1.1.1']
    
    resolver = EnhancedHostnameResolver()
    resolver.enable_debug()
    
    print("\nTesting individual resolution:")
    for ip in test_ips:
        hostname = resolver.resolve_hostname(ip)
        print(f"  {ip} -> {hostname if hostname else 'No hostname found'}")
    
    print("\nCache stats:")
    stats = resolver.get_cache_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print("\nTesting batch resolution:")
    results = resolver.resolve_multiple_hostnames(test_ips)
    for ip, hostname in results.items():
        print(f"  {ip} -> {hostname if hostname else 'No hostname found'}")


if __name__ == '__main__':
    test_resolver()
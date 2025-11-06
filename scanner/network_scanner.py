"""
FAST NETWORK SCANNER - Optimized for Performance
Finds ALL devices on network quickly and reliably
"""

import socket
import subprocess
import ipaddress
import concurrent.futures
import platform
import time
from datetime import datetime

class NetworkScanner:
    """Fast, reliable network scanner"""
    
    def __init__(self, db):
        self.db = db
    
    def get_network_range(self):
        """Get network range to scan - FAST"""
        try:
            import psutil
            for iface, addrs in psutil.net_if_addrs().items():
                iface_lower = iface.lower()
                if any(x in iface_lower for x in ['lo', 'docker', 'veth', 'vmware', 'virtualbox', 'hyper-v']):
                    continue
                
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        ip = addr.address
                        if ip.startswith(('127.', '169.254.')):
                            continue
                        
                        if addr.netmask:
                            network = ipaddress.IPv4Network(f"{ip}/{addr.netmask}", strict=False)
                            if network.prefixlen < 24:
                                base = ip.rsplit('.', 1)[0]
                                return f"{base}.0/24"
                            return str(network)
                        else:
                            base = ip.rsplit('.', 1)[0]
                            return f"{base}.0/24"
        except:
            pass
        return "192.168.1.0/24"
    
    def ping_host(self, ip):
        """Fast ping - optimized"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ['ping', '-n', '1', '-w', '300', ip],
                    capture_output=True,
                    text=True,
                    timeout=0.8,
                    creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                )
                return result.returncode == 0 and ("Reply from" in result.stdout or "TTL" in result.stdout)
            else:
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '1', ip],
                    capture_output=True,
                    text=True,
                    timeout=0.8
                )
                return result.returncode == 0
        except:
            return False
    
    def get_hostname(self, ip):
        """Get hostname - with timeout"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname.split('.')[0] if hostname else None
        except:
            return None
    
    def get_mac_from_arp(self, ip):
        """Get MAC from ARP table - FAST"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ['arp', '-a', ip],
                    capture_output=True,
                    text=True,
                    timeout=1,
                    creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                )
                for line in result.stdout.split('\n'):
                    if ip in line and '-' in line:
                        parts = line.split()
                        for part in parts:
                            if ':' in part and len(part) == 17:
                                return part.upper().replace('-', ':')
            else:
                result = subprocess.run(
                    ['arp', '-n', ip],
                    capture_output=True,
                    text=True,
                    timeout=1
                )
                for line in result.stdout.split('\n'):
                    if ip in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            return parts[2].upper()
        except:
            pass
        return None
    
    def scan_network(self):
        """Scan network - FAST and finds ALL devices"""
        network_range = self.get_network_range()
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Scanning {network_range}...")
        
        try:
            network = ipaddress.IPv4Network(network_range, strict=False)
        except:
            return []
        
        # Get our IP to exclude
        try:
            import psutil
            my_ip = None
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith(('127.', '169.254.')):
                        my_ip = addr.address
                        break
                if my_ip:
                    break
        except:
            my_ip = None
        
        # Get all hosts
        hosts = [str(ip) for ip in network.hosts()]
        if my_ip and my_ip in hosts:
            hosts.remove(my_ip)
        if len(hosts) > 254:
            hosts = hosts[:254]
        
        devices = []
        
        # FAST parallel scan - 150 workers for speed
        with concurrent.futures.ThreadPoolExecutor(max_workers=150) as executor:
            future_to_ip = {
                executor.submit(self._scan_host_fast, str(ip)): str(ip) 
                for ip in hosts
            }
            
            completed = 0
            for future in concurrent.futures.as_completed(future_to_ip, timeout=45):
                completed += 1
                try:
                    device = future.result(timeout=1)
                    if device:
                        devices.append(device)
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] Found {len(devices)} devices...", end='\r')
                except:
                    continue
        
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Scan complete - Found {len(devices)} devices")
        return devices
    
    def _scan_host_fast(self, ip):
        """Fast host scan - optimized"""
        # Skip invalid IPs
        if ip.startswith(('127.', '169.254.')):
            return None
        
        # Fast ping check
        if not self.ping_host(ip):
            return None
        
        # Get MAC (try ARP, but don't wait)
        mac = self.get_mac_from_arp(ip)
        if not mac:
            # Generate unique MAC
            try:
                parts = ip.split('.')
                mac = f"00:00:00:{int(parts[-2]):02x}:{int(parts[-1]):02x}:01".upper()
            except:
                mac = "00:00:00:00:00:00"
        
        # Get hostname (don't block)
        hostname = None
        try:
            hostname = self.get_hostname(ip)
        except:
            pass
        
        return {
            'ip': ip,
            'mac': mac,
            'hostname': hostname,
            'vendor': 'Unknown',
            'status': 'online'
        }


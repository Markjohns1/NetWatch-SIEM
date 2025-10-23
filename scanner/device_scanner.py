import socket
import subprocess
import re
from scapy.all import ARP, Ether, srp
import psutil
from datetime import datetime
import threading
import time
import ipaddress
import logging
import hashlib
import os
import concurrent.futures

class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    MAGENTA = '\033[95m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    WHITE = '\033[97m'
    DARK_GRAY = '\033[90m'
    LIGHT_CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_MAGENTA = '\033[95m'

class DynamicNetworkDetector:
    def __init__(self, verbose=False):
        self.previous_network = None
        self.network_cache = {}
        self.verbose = verbose
    
    def auto_detect_network(self):
        current_network = self._get_current_network_context()
        
        if current_network in self.network_cache:
            return self.network_cache[current_network]
        
        network_info = self._discover_network_properties()
        self.network_cache[current_network] = network_info
        return network_info
    
    def _get_current_network_context(self):
        default_gateway = self._get_default_gateway()
        interface = self._get_active_interface()
        ssid = self._get_wifi_ssid() if self._is_wifi() else "wired"
        
        network_id = f"{interface}:{default_gateway}:{ssid}"
        return hashlib.md5(network_id.encode()).hexdigest()
    
    def _discover_network_properties(self):
        network_info = {
            'interface': self._get_active_interface(),
            'ip_address': self._get_my_ip(),
            'subnet': self._calculate_subnet(),
            'network_range': self._get_network_range(),
            'gateway': self._get_default_gateway(),
            'network_type': self._determine_network_type(),
            'optimal_scan_methods': self._determine_best_scan_methods(),
            'estimated_size': self._estimate_network_size(),
            'discovery_time': datetime.now()
        }
        
        return network_info

    def _get_active_interface(self):
        try:
            interfaces = psutil.net_if_stats()
            valid_interfaces = []
            
            for iface, stats in interfaces.items():
                if not stats.isup:
                    continue
                    
                iface_lower = iface.lower()
                
                if iface_lower.startswith(('lo', 'docker', 'veth', 'br-')):
                    continue
                if any(bad in iface_lower for bad in ['vmware', 'vmnet', 'virtual', 'vbox', 'hyper-v', 'virtualbox']):
                    continue
                
                addrs = psutil.net_if_addrs().get(iface, [])
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        ip = addr.address
                        
                        if ip.startswith('127.'):
                            continue
                        
                        priority = self._calculate_interface_priority(iface_lower, ip)
                        valid_interfaces.append((iface, ip, priority))
                        break
            
            if not valid_interfaces:
                return "unknown"
            
            valid_interfaces.sort(key=lambda x: x[2])
            best_iface = valid_interfaces[0][0]
            return best_iface
            
        except Exception as e:
            return "unknown"

    def _calculate_interface_priority(self, iface_lower, ip):
        priority = 100
        
        if ip.startswith('169.254.'):
            priority += 1000
        elif ip.startswith('192.168.'):
            priority -= 50
        elif ip.startswith('10.'):
            priority -= 40
        elif ip.startswith('172.'):
            priority -= 30
        
        if any(term in iface_lower for term in ['ethernet', 'eth']):
            priority -= 20
        if any(term in iface_lower for term in ['wi-fi', 'wlan', 'wireless', 'wifi']):
            priority -= 15
        
        return priority

    def _get_my_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            
            if not ip.startswith('169.254.'):
                return ip
        except:
            pass
        
        try:
            active_iface = self._get_active_interface()
            if active_iface != "unknown":
                interfaces = psutil.net_if_addrs()
                for iface, addrs in interfaces.items():
                    if iface == active_iface:
                        for addr in addrs:
                            if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                                return addr.address
            
            for iface, addrs in psutil.net_if_addrs().items():
                iface_lower = iface.lower()
                
                if any(bad in iface_lower for bad in ['lo', 'docker', 'veth', 'vmware', 'vbox', 'virtual']):
                    continue
                
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        ip = addr.address
                        if not ip.startswith(('127.', '169.254.')):
                            return ip
        except:
            pass
        
        return "127.0.0.1"

    def _calculate_subnet(self):
        try:
            interfaces = psutil.net_if_addrs()
            active_iface = self._get_active_interface()
            
            if active_iface == "unknown":
                return "192.168.1.0/24"
            
            for iface, addrs in interfaces.items():
                if iface == active_iface:
                    for addr in addrs:
                        if addr.family == socket.AF_INET:
                            if addr.address.startswith('169.254.'):
                                continue
                            
                            try:
                                ip = ipaddress.IPv4Interface(f"{addr.address}/{addr.netmask}")
                                network = str(ip.network)
                                
                                net_obj = ipaddress.IPv4Network(network)
                                if net_obj.num_addresses > 1024:
                                    base_ip = addr.address.rsplit('.', 1)[0]
                                    return f"{base_ip}.0/24"
                                
                                return network
                            except:
                                continue
            
            my_ip = self._get_my_ip()
            if not my_ip.startswith(('127.', '169.254.')):
                return f"{my_ip.rsplit('.', 1)[0]}.0/24"
            
            return "192.168.1.0/24"
            
        except Exception as e:
            return "192.168.1.0/24"

    def _get_network_range(self):
        return self._calculate_subnet()

    def _get_default_gateway(self):
        try:
            if os.name == 'nt':
                result = subprocess.run(['ipconfig'], capture_output=True, text=True, shell=True)
                for line in result.stdout.split('\n'):
                    if 'Default Gateway' in line and '.' in line:
                        parts = line.split(':')
                        if len(parts) > 1:
                            gateway = parts[1].strip()
                            if gateway and gateway not in ['0.0.0.0', ''] and not gateway.startswith('169.254.'):
                                return gateway
            else:
                result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'default' in line:
                        parts = line.split()
                        if len(parts) > 2:
                            return parts[2]
            return "unknown"
        except:
            return "unknown"

    def _is_wifi(self):
        try:
            interfaces = psutil.net_if_addrs()
            for iface in interfaces:
                iface_lower = iface.lower()
                if any(wireless_term in iface_lower for wireless_term in ['wireless', 'wlan', 'wi-fi', 'wi fi', 'wifi']):
                    return True
            return False
        except:
            return False

    def _get_wifi_ssid(self):
        try:
            if os.name == 'nt':
                result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], capture_output=True, text=True, shell=True)
                for line in result.stdout.split('\n'):
                    if 'SSID' in line and 'BSSID' not in line:
                        parts = line.split(':')
                        if len(parts) > 1:
                            return parts[1].strip()
            else:
                try:
                    result = subprocess.run(['iwgetid', '-r'], capture_output=True, text=True)
                    if result.stdout.strip():
                        return result.stdout.strip()
                except:
                    pass
        except:
            pass
        return "unknown"

    def _determine_network_type(self):
        my_ip = self._get_my_ip()
        
        if my_ip.startswith('10.'):
            return "Corporate Network"
        elif my_ip.startswith('192.168.'):
            return "Home/Small Business"
        elif my_ip.startswith('172.'):
            try:
                octets = my_ip.split('.')
                second = int(octets[1])
                if 16 <= second <= 31:
                    return "Enterprise Network"
            except:
                pass
            return "Public Network"
        elif my_ip.startswith('169.254.'):
            return "Link-Local (APIPA)"
        else:
            return "Public Network"

    def _determine_best_scan_methods(self):
        network_type = self._determine_network_type()
        my_ip = self._get_my_ip()
        
        if my_ip.startswith('169.254.'):
            return ['ping_sweep']
        
        method_profiles = {
            "Home/Small Business": ['arp_scan', 'ping_sweep'],
            "Corporate Network": ['ping_sweep', 'arp_scan'],
            "Enterprise Network": ['arp_scan', 'ping_sweep'],
            "Public Network": ['ping_sweep'],
            "Link-Local (APIPA)": ['ping_sweep']
        }
        
        return method_profiles.get(network_type, ['arp_scan', 'ping_sweep'])

    def _estimate_network_size(self):
        network_type = self._determine_network_type()
        size_estimates = {
            "Home/Small Business": 50,
            "Corporate Network": 1000,
            "Enterprise Network": 500,
            "Public Network": 200,
            "Link-Local (APIPA)": 10
        }
        return size_estimates.get(network_type, 100)

class DeviceScanner:
    def __init__(self, db, verbose=False, show_banner=True):
        self.db = db
        self.scanning = False
        self.scan_thread = None
        self.mac_vendors = self._load_mac_vendors()
        self.network_detector = DynamicNetworkDetector(verbose=verbose)
        self.verbose = verbose
        self.banner_shown = False
        self.show_banner = show_banner
        
        # Initialize hostname resolver
        self.hostname_resolver = None
        try:
            from .hostname_resolver import hostname_resolver
            self.hostname_resolver = hostname_resolver
        except ImportError:
            pass  # Will use fallback method
        
        if self.show_banner and not self.banner_shown:
            self._print_startup_banner()

    def _print_startup_banner(self):
        """Clean, beautiful startup banner"""
        width = 80
        # Use ASCII characters for Windows compatibility
        print(f"\n{Colors.CYAN}{'=' * width}{Colors.RESET}")
        print(f"{Colors.CYAN}|{Colors.RESET}{' ' * (width - 2)}{Colors.CYAN}|{Colors.RESET}")
        
        title = "NETWATCH SIEM"
        print(f"{Colors.CYAN}|{Colors.RESET}{Colors.BRIGHT_CYAN}{Colors.BOLD}{title.center(width - 2)}{Colors.RESET}{Colors.CYAN}|{Colors.RESET}")
        
        subtitle = "NETWORK SCANNER"
        print(f"{Colors.CYAN}|{Colors.RESET}{Colors.MAGENTA}{subtitle.center(width - 2)}{Colors.RESET}{Colors.CYAN}|{Colors.RESET}")
        
        tagline = ">>> ACTIVE NETWORK DISCOVERY TOOL <<<"
        print(f"{Colors.CYAN}|{Colors.RESET}{Colors.GREEN}{tagline.center(width - 2)}{Colors.RESET}{Colors.CYAN}|{Colors.RESET}")
        
        print(f"{Colors.CYAN}|{Colors.RESET}{' ' * (width - 2)}{Colors.CYAN}|{Colors.RESET}")
        
        author = "Created by: John O. Mark"
        print(f"{Colors.CYAN}|{Colors.RESET}{Colors.YELLOW}{author.center(width - 2)}{Colors.RESET}{Colors.CYAN}|{Colors.RESET}")
        
        division = "Security Research Division"
        print(f"{Colors.CYAN}|{Colors.RESET}{Colors.YELLOW}{division.center(width - 2)}{Colors.RESET}{Colors.CYAN}|{Colors.RESET}")
        
        print(f"{Colors.CYAN}|{Colors.RESET}{' ' * (width - 2)}{Colors.CYAN}|{Colors.RESET}")
        print(f"{Colors.CYAN}{'=' * width}{Colors.RESET}\n")
        
        print(f"{Colors.GREEN}[{datetime.now().strftime('%H:%M:%S')}]{Colors.RESET} {Colors.BRIGHT_GREEN}[OK] NetWatch SIEM initialized successfully{Colors.RESET}")
        print(f"{Colors.CYAN}[{datetime.now().strftime('%H:%M:%S')}]{Colors.RESET} {Colors.BRIGHT_CYAN}Ready to monitor your network...{Colors.RESET}\n")
        self.banner_shown = True

    def smart_scan(self):
        """Silent scanning - only prints scan completion"""
        network_info = self.network_detector.auto_detect_network()
        
        if network_info['interface'] == 'unknown':
            return []
        
        # Single line scanning indicator
        print(f"{Colors.CYAN}[{datetime.now().strftime('%H:%M:%S')}]{Colors.RESET} Scanning network {network_info['network_range']}...", end='\r')
        
        devices = self._adaptive_scan(network_info)
        enriched_devices = self._add_network_context(devices, network_info)
        
        # Clean completion message
        print(f"{Colors.GREEN}[{datetime.now().strftime('%H:%M:%S')}]{Colors.RESET} {Colors.BRIGHT_GREEN}[OK] Scan completed - Found {len(enriched_devices)} devices{Colors.RESET}          ")
        
        return enriched_devices

    def _adaptive_scan(self, network_info):
        """Silent adaptive scanning"""
        all_devices = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            future_to_method = {}
            
            for method_name in network_info['optimal_scan_methods']:
                if method_name == 'arp_scan':
                    future = executor.submit(self.arp_scan, network_info['network_range'])
                elif method_name == 'ping_sweep':
                    future = executor.submit(self.ping_sweep, network_info)
                else:
                    continue
                    
                future_to_method[future] = method_name

            for future in concurrent.futures.as_completed(future_to_method, timeout=60):
                method_name = future_to_method[future]
                try:
                    devices = future.result(timeout=2)
                    if devices:
                        for device in devices:
                            if not any(d['ip'] == device['ip'] for d in all_devices):
                                all_devices.append(device)
                except:
                    pass  # Silent failure
        
        return all_devices

    def scan_network(self):
        return self.smart_scan()

    def _load_mac_vendors(self):
        return {
            '00:50:56': 'VMware', '00:0C:29': 'VMware', '00:05:69': 'VMware',
            '00:1C:14': 'VMware', '08:00:27': 'VirtualBox', '52:54:00': 'QEMU/KVM',
            '00:16:3E': 'Xen', 'DC:A6:32': 'Raspberry Pi', 'B8:27:EB': 'Raspberry Pi',
            'E4:5F:01': 'Raspberry Pi', '00:1A:7D': 'Kindle', '00:17:88': 'Philips',
        }

    def get_vendor_from_mac(self, mac):
        if not mac or mac == 'Unknown':
            return 'Unknown'
        mac_prefix = mac.upper()[:8]
        return self.mac_vendors.get(mac_prefix, 'Unknown')

    def arp_scan(self, target_ip):
        """Silent ARP scanning"""
        try:
            try:
                network = ipaddress.IPv4Network(target_ip)
                if network.num_addresses > 1024:
                    base = str(network.network_address).rsplit('.', 1)[0]
                    target_ip = f"{base}.0/24"
            except:
                pass
            
            arp = ARP(pdst=target_ip)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp

            iface = self.network_detector._get_active_interface()
            if iface == "unknown":
                return []

            result = srp(packet, iface=iface, timeout=3, retry=1, verbose=0)[0]

            devices = []
            for sent, received in result:
                devices.append({
                    'ip': received.psrc,
                    'mac': received.hwsrc.upper(),
                    'vendor': self.get_vendor_from_mac(received.hwsrc),
                    'discovery_method': 'arp_scan'
                })

            return devices

        except:
            return []

    def ping_sweep(self, network_info):
        """Silent ping sweep"""
        devices = []
        
        try:
            network = ipaddress.ip_network(network_info['network_range'])
            
            max_hosts = min(30, network.num_addresses - 2)
            targets = [str(ip) for ip in list(network.hosts())[:max_hosts]]
            
            for ip in targets:
                try:
                    if os.name == 'nt':
                        result = subprocess.run(['ping', '-n', '1', '-w', '500', ip], 
                                              capture_output=True, text=True, shell=True, timeout=1)
                    else:
                        result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                              capture_output=True, text=True, timeout=1)
                    
                    if ("Reply from" in result.stdout or "1 received" in result.stdout or 
                        "bytes from" in result.stdout or "ttl=" in result.stdout.lower()):
                        devices.append({
                            'ip': ip,
                            'mac': 'Unknown',
                            'vendor': 'Unknown',
                            'discovery_method': 'ping_sweep'
                        })
                except:
                    continue
                    
        except:
            pass
        
        return devices

    def get_hostname(self, ip):
        """Enhanced hostname resolution with multiple fallback methods"""
        # Try enhanced resolver first
        if self.hostname_resolver:
            try:
                hostname = self.hostname_resolver.resolve_hostname(ip)
                if hostname:
                    return hostname
            except Exception:
                pass
        
        # Fallback to basic DNS lookup
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname.split('.')[0] if hostname else None
        except:
            return None

    def _add_network_context(self, devices, network_info):
        """Silent device context enrichment and saving"""
        saved_count = 0
        
        # Collect all IPs for batch hostname resolution
        device_ips = [d['ip'] for d in devices if d.get('ip') and d['ip'] != 'Unknown']
        
        # Batch resolve hostnames if enhanced resolver available
        hostname_map = {}
        if self.hostname_resolver and device_ips:
            try:
                hostname_map = self.hostname_resolver.resolve_multiple_hostnames(device_ips)
            except Exception:
                pass  # Will fall back to individual resolution
        
        for device in devices:
            try:
                device['network_context'] = {
                    'network_type': network_info['network_type'],
                    'subnet': network_info['network_range'],
                    'scan_location': self._infer_location(network_info),
                    'trust_level': self._calculate_trust_level(device, network_info),
                }
                
                # Get hostname from batch resolution or individual lookup
                device_ip = device.get('ip')
                if device_ip and device_ip in hostname_map:
                    device['hostname'] = hostname_map[device_ip]
                else:
                    try:
                        hostname = self.get_hostname(device_ip) if device_ip else None
                        device['hostname'] = hostname
                    except:
                        device['hostname'] = None
                
                if not device.get('ip') or device['ip'] == 'Unknown':
                    continue
                
                mac = device.get('mac')
                if not mac or mac == 'Unknown':
                    try:
                        ip_parts = device['ip'].split('.')
                        mac = f"00:00:00:{int(ip_parts[-3]):02x}:{int(ip_parts[-2]):02x}:{int(ip_parts[-1]):02x}".upper()
                        device['mac'] = mac
                    except:
                        mac = "00:00:00:00:00:00"
                        device['mac'] = mac
                
                try:
                    device_id = self.db.add_device(
                        ip=device['ip'],
                        mac=mac,
                        hostname=device.get('hostname'),
                        vendor=device.get('vendor', 'Unknown')
                    )
                    
                    if device_id:
                        saved_count += 1
                        device['device_id'] = device_id
                        
                        self.db.add_event(
                            event_type='device_scan',
                            severity='info',
                            description=f"Device detected: {device['ip']} ({mac}) via {device.get('discovery_method', 'unknown')}",
                            device_id=device_id
                        )
                        
                except Exception as db_error:
                    pass  # Silent DB errors
                    
            except Exception as e:
                continue
        
        return devices

    def _infer_location(self, network_info):
        if network_info['network_type'] == 'Home/Small Business':
            return "home_office"
        elif network_info['network_type'] == 'Corporate Network':
            return "enterprise"
        else:
            return "unknown"

    def _calculate_trust_level(self, device, network_info):
        if device['ip'] == network_info['gateway']:
            return "gateway"
        elif device['vendor'] in ['Apple', 'Samsung', 'Microsoft']:
            return "trusted_vendor"
        else:
            return "unknown"

    def start_continuous_scan(self, interval=300):
        self.scanning = True
        
        def scan_loop():
            while self.scanning:
                self.smart_scan()
                time.sleep(interval)
        
        self.scan_thread = threading.Thread(target=scan_loop, daemon=True)
        self.scan_thread.start()
        
        print(f"{Colors.GREEN}[{datetime.now().strftime('%H:%M:%S')}]{Colors.RESET} {Colors.BRIGHT_GREEN}[OK] Continuous scanning started (interval: {interval}s){Colors.RESET}")

    def stop_scan(self):
        self.scanning = False
        if self.scan_thread:
            self.scan_thread.join(timeout=5)
        
        print(f"{Colors.YELLOW}[{datetime.now().strftime('%H:%M:%S')}]{Colors.RESET} {Colors.YELLOW}⚠ Continuous scanning stopped{Colors.RESET}")
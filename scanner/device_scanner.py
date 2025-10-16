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

class TerminalDisplay:
    """Handles formatted terminal output with clean sections"""
    
    @staticmethod
    def print_header(title):
        print(f"\n{'=' * 80}")
        print(f" {title.upper()}")
        print(f"{'=' * 80}")
    
    @staticmethod
    def print_section(title):
        print(f"\n{'-' * 60}")
        print(f" {title}")
        print(f"{'-' * 60}")
    
    @staticmethod
    def print_info(label, value, indent=0):
        indent_str = " " * indent
        print(f"{indent_str}> {label}: {value}")
    
    @staticmethod
    def print_success(message):
        print(f" [SUCCESS] {message}")
    
    @staticmethod
    def print_warning(message):
        print(f" [WARNING] {message}")
    
    @staticmethod
    def print_error(message):
        print(f" [ERROR] {message}")
    
    @staticmethod
    def print_device(device, index, total):
        print(f" [{index:2d}/{total:2d}] IP: {device['ip']:15} | MAC: {device.get('mac', 'Unknown'):17} | Vendor: {device.get('vendor', 'Unknown')}")

class DynamicNetworkDetector:
    def __init__(self):
        self.previous_network = None
        self.network_cache = {}
        self.display = TerminalDisplay()
    
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
        self.display.print_header("Network Auto-Detection")
        
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
        
        self.display.print_section("Network Configuration")
        self.display.print_info("Network Range", network_info['network_range'])
        self.display.print_info("Network Type", network_info['network_type'])
        self.display.print_info("Interface", network_info['interface'])
        self.display.print_info("Your IP", network_info['ip_address'])
        self.display.print_info("Gateway", network_info['gateway'])
        self.display.print_info("Estimated Size", f"{network_info['estimated_size']} devices")
        self.display.print_info("Scan Methods", ", ".join(network_info['optimal_scan_methods']))
        
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
                self.display.print_warning("No valid network interface found")
                return "unknown"
            
            valid_interfaces.sort(key=lambda x: x[2])
            best_iface = valid_interfaces[0][0]
            return best_iface
            
        except Exception as e:
            self.display.print_error(f"Interface detection error: {e}")
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
            self.display.print_error(f"Subnet calculation error: {e}")
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
    def __init__(self, db):
        self.db = db
        self.scanning = False
        self.scan_thread = None
        self.mac_vendors = self._load_mac_vendors()
        self.network_detector = DynamicNetworkDetector()
        self.display = TerminalDisplay()

    def smart_scan(self):
        # Fantastic centered title
        print("\n")
        print("╔══════════════════════════════════════════════════════════════════════════════╗")
        print("║                                                                              ║")
        print("║                        NETWATCH SIEM - NETWORK SCANNER                       ║")
        print("║                                                                              ║")
        print("║                     >>> ACTIVE NETWORK DISCOVERY TOOL <<<                    ║")
        print("║                                                                              ║")
        print("║                           Created by: John O. Mark                           ║")
        print("║                         Security Research Division                           ║")
        print("║                                                                              ║")
        print("╚══════════════════════════════════════════════════════════════════════════════╝")
        print("")
        
        network_info = self.network_detector.auto_detect_network()
        
        if network_info['interface'] == 'unknown':
            self.display.print_error("No valid network interface detected!")
            self.display.print_error("Check your network connection and try again.")
            return []
        
        if network_info['ip_address'].startswith('169.254.'):
            self.display.print_warning("Using APIPA address (169.254.x.x)")
            self.display.print_warning("This means your computer couldn't get an IP from the router.")
            self.display.print_warning("Scan results may be limited. Check your network connection!")
        
        devices = self._adaptive_scan(network_info)
        enriched_devices = self._add_network_context(devices, network_info)
        
        self.display.print_section("Scan Results Summary")
        self.display.print_success(f"Scan complete. Found {len(enriched_devices)} devices on {network_info['network_range']}")
        
        if enriched_devices:
            self.display.print_section("Discovered Devices")
            for i, device in enumerate(enriched_devices, 1):
                self.display.print_device(device, i, len(enriched_devices))
        
        # Fantastic completion banner
        print("\n")
        print("╔══════════════════════════════════════════════════════════════════════════════╗")
        print("║                                                                              ║")
        print("║                         SCAN COMPLETE - MISSION SUCCESS                      ║")
        print("║                                                                              ║")
        print("║                     Network reconnaissance finished successfully             ║")
        print("║                                                                              ║")
        print("╚══════════════════════════════════════════════════════════════════════════════╝")
        print("")
        
        return enriched_devices

    def _adaptive_scan(self, network_info):
        all_devices = []
        
        self.display.print_section("Starting Network Scan")
        self.display.print_info("Methods", ", ".join(network_info['optimal_scan_methods']))
        
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

            for future in concurrent.futures.as_completed(future_to_method, timeout=20):
                method_name = future_to_method[future]
                try:
                    devices = future.result(timeout=2)
                    if devices:
                        self.display.print_success(f"{method_name}: found {len(devices)} devices")
                        for device in devices:
                            if not any(d['ip'] == device['ip'] for d in all_devices):
                                all_devices.append(device)
                    else:
                        self.display.print_info(f"{method_name}", "no devices found")
                except concurrent.futures.TimeoutError:
                    self.display.print_warning(f"{method_name}: timed out")
                except Exception as e:
                    self.display.print_error(f"{method_name}: {str(e)[:50]}")
        
        return all_devices

    def scan_network(self):
        return self.smart_scan()

    def _load_mac_vendors(self):
        return {
            '00:50:56': 'VMware',
            '00:0C:29': 'VMware',
            '00:05:69': 'VMware',
            '00:1C:14': 'VMware',
            '08:00:27': 'VirtualBox',
            '52:54:00': 'QEMU/KVM',
            '00:16:3E': 'Xen',
            'DC:A6:32': 'Raspberry Pi',
            'B8:27:EB': 'Raspberry Pi',
            'E4:5F:01': 'Raspberry Pi',
            '00:1A:7D': 'Kindle',
            '00:17:88': 'Philips',
            '00:0A:95': 'Apple',
            '00:03:93': 'Apple',
            '00:05:02': 'Apple',
            '00:0D:93': 'Apple',
            '00:11:24': 'Apple',
            '00:14:51': 'Apple',
            '00:16:CB': 'Apple',
            '00:17:F2': 'Apple',
            '00:19:E3': 'Apple',
            '00:1B:63': 'Apple',
            '00:1C:B3': 'Apple',
            '00:1D:4F': 'Apple',
            '00:1E:52': 'Apple',
            '00:1F:5B': 'Apple',
            '00:1F:F3': 'Apple',
            '00:21:E9': 'Apple',
            '00:22:41': 'Apple',
            '00:23:12': 'Apple',
            '00:23:32': 'Apple',
            '00:23:6C': 'Apple',
            '00:23:DF': 'Apple',
            '00:24:36': 'Apple',
            '00:25:00': 'Apple',
            '00:25:4B': 'Apple',
            '00:25:BC': 'Apple',
            '00:26:08': 'Apple',
            '00:26:4A': 'Apple',
            '00:26:B0': 'Apple',
            '00:26:BB': 'Apple',
            '04:0C:CE': 'Apple',
            '04:15:52': 'Apple',
            '04:26:65': 'Apple',
            '04:54:53': 'Apple',
            '08:00:07': 'Apple',
            '08:66:98': 'Apple',
            '08:70:45': 'Apple',
            '0C:3E:9F': 'Apple',
            '0C:4D:E9': 'Apple',
            '0C:74:C2': 'Apple',
            '10:40:F3': 'Apple',
            '10:9A:DD': 'Apple',
            '10:DD:B1': 'Apple',
            '14:10:9F': 'Apple',
            '14:5A:05': 'Apple',
            '14:8F:C6': 'Apple',
            '14:BD:61': 'Apple',
            '18:20:32': 'Apple',
            '18:34:51': 'Apple',
            '18:65:90': 'Apple',
            '18:AF:61': 'Apple',
            '18:E7:F4': 'Apple',
            '18:F1:D8': 'Apple',
            '1C:1A:C0': 'Apple',
            '1C:36:BB': 'Apple',
            '1C:AB:A7': 'Apple',
            '20:78:F0': 'Apple',
            '20:A2:E4': 'Apple',
            '20:AB:37': 'Apple',
            '20:C9:D0': 'Apple',
            '24:A0:74': 'Apple',
            '24:AB:81': 'Apple',
            '24:F0:94': 'Apple',
            '24:F6:77': 'Apple',
            '28:37:37': 'Apple',
            '28:5A:EB': 'Apple',
            '28:6A:B8': 'Apple',
            '28:6A:BA': 'Apple',
            '28:A0:2B': 'Apple',
            '28:CF:DA': 'Apple',
            '28:CF:E9': 'Apple',
            '28:E0:2C': 'Apple',
            '28:E1:4C': 'Apple',
            '28:ED:6A': 'Apple',
            '2C:1F:23': 'Apple',
            '2C:33:11': 'Apple',
            '2C:36:F8': 'Apple',
            '2C:3A:E8': 'Apple',
            '2C:54:CF': 'Apple',
            '2C:6E:85': 'Apple',
            '2C:B4:3A': 'Apple',
            '2C:BE:08': 'Apple',
            '30:35:AD': 'Apple',
            '30:90:AB': 'Apple',
            '30:F7:C5': 'Apple',
            '34:12:F9': 'Apple',
            '34:15:9E': 'Apple',
            '34:51:C9': 'Apple',
            '34:A3:95': 'Apple',
            '34:AB:37': 'Apple',
            '34:C0:59': 'Apple',
            '34:E2:FD': 'Apple',
            '38:0F:4A': 'Apple',
            '38:48:4C': 'Apple',
            '38:89:2C': 'Apple',
            '38:C9:86': 'Apple',
            '3C:07:54': 'Apple',
            '3C:15:C2': 'Apple',
            '3C:2E:F9': 'Apple',
            '40:30:04': 'Apple',
            '40:33:1A': 'Apple',
            '40:3C:FC': 'Apple',
            '40:4D:7F': 'Apple',
            '40:6C:8F': 'Apple',
            '40:A6:D9': 'Apple',
            '40:B3:95': 'Apple',
            '40:CB:C0': 'Apple',
            '40:D3:2D': 'Apple',
            '44:2A:60': 'Apple',
            '44:4C:0C': 'Apple',
            '44:D8:84': 'Apple',
            '44:FB:42': 'Apple',
            '48:43:7C': 'Apple',
            '48:60:BC': 'Apple',
            '48:74:6E': 'Apple',
            '48:A1:95': 'Apple',
            '48:BF:6B': 'Apple',
            '48:D7:05': 'Apple',
            '4C:32:75': 'Apple',
            '4C:57:CA': 'Apple',
            '4C:7C:5F': 'Apple',
            '4C:8D:79': 'Apple',
            '50:32:37': 'Apple',
            '50:A6:67': 'Apple',
            '50:EA:D6': 'Apple',
            '54:26:96': 'Apple',
            '54:4E:90': 'Apple',
            '54:72:4F': 'Apple',
            '54:9F:13': 'Apple',
            '54:AE:27': 'Apple',
            '54:E4:3A': 'Apple',
            '58:1F:AA': 'Apple',
            '58:40:4E': 'Apple',
            '58:55:CA': 'Apple',
            '58:B0:35': 'Apple',
            '5C:59:48': 'Apple',
            '5C:95:AE': 'Apple',
            '5C:96:9D': 'Apple',
            '5C:F9:38': 'Apple',
            '60:03:08': 'Apple',
            '60:33:4B': 'Apple',
            '60:69:44': 'Apple',
            '60:92:17': 'Apple',
            '60:C5:47': 'Apple',
            '60:F8:1D': 'Apple',
            '60:FA:CD': 'Apple',
            '60:FB:42': 'Apple',
            '60:FE:C5': 'Apple',
            '64:20:0C': 'Apple',
            '64:76:BA': 'Apple',
            '64:9A:BE': 'Apple',
            '64:A3:CB': 'Apple',
            '64:B0:A6': 'Apple',
            '64:B9:E8': 'Apple',
            '64:E6:82': 'Apple',
            '68:5B:35': 'Apple',
            '68:96:7B': 'Apple',
            '68:A8:6D': 'Apple',
            '68:D9:3C': 'Apple',
            '68:DB:F5': 'Apple',
            '68:FE:F7': 'Apple',
            '6C:19:C0': 'Apple',
            '6C:3E:6D': 'Apple',
            '6C:40:08': 'Apple',
            '6C:4D:73': 'Apple',
            '6C:70:9F': 'Apple',
            '6C:72:E7': 'Apple',
            '6C:8D:C1': 'Apple',
            '6C:94:66': 'Apple',
            '6C:96:CF': 'Apple',
            '6C:AB:31': 'Apple',
            '70:11:24': 'Apple',
            '70:3E:AC': 'Apple',
            '70:56:81': 'Apple',
            '70:73:CB': 'Apple',
            '70:A2:B3': 'Apple',
            '70:CD:60': 'Apple',
            '70:DE:E2': 'Apple',
            '70:EC:E4': 'Apple',
            '74:1B:B2': 'Apple',
            '74:E1:B6': 'Apple',
            '74:E2:F5': 'Apple',
            '78:31:C1': 'Apple',
            '78:67:D7': 'Apple',
            '78:7B:8A': 'Apple',
            '78:A3:E4': 'Apple',
            '78:CA:39': 'Apple',
            '78:D7:5F': 'Apple',
            '78:FD:94': 'Apple',
            '7C:01:91': 'Apple',
            '7C:04:D0': 'Apple',
            '7C:11:BE': 'Apple',
            '7C:50:79': 'Apple',
            '7C:6D:62': 'Apple',
            '7C:6D:F8': 'Apple',
            '7C:C3:A1': 'Apple',
            '7C:D1:C3': 'Apple',
            '7C:F0:5F': 'Apple',
            '80:49:71': 'Apple',
            '80:92:9F': 'Apple',
            '80:BE:05': 'Apple',
            '80:E6:50': 'Apple',
            '84:38:35': 'Apple',
            '84:85:06': 'Apple',
            '84:89:AD': 'Apple',
            '84:FC:FE': 'Apple',
            '88:1F:A1': 'Apple',
            '88:53:95': 'Apple',
            '88:63:DF': 'Apple',
            '88:66:5A': 'Apple',
            '88:E8:7F': 'Apple',
            '8C:00:6D': 'Apple',
            '8C:2D:AA': 'Apple',
            '8C:58:77': 'Apple',
            '8C:7C:92': 'Apple',
            '8C:85:90': 'Apple',
            '8C:8E:F2': 'Apple',
            '90:27:E4': 'Apple',
            '90:72:40': 'Apple',
            '90:84:0D': 'Apple',
            '90:8D:6C': 'Apple',
            '90:9C:4A': 'Apple',
            '90:B0:ED': 'Apple',
            '90:B2:1F': 'Apple',
            '90:FD:61': 'Apple',
            '94:BF:2D': 'Apple',
            '94:E9:6A': 'Apple',
            '94:F6:A3': 'Apple',
            '98:01:A7': 'Apple',
            '98:03:D8': 'Apple',
            '98:5A:EB': 'Apple',
            '98:B8:E3': 'Apple',
            '98:CA:33': 'Apple',
            '98:D6:BB': 'Apple',
            '98:E0:D9': 'Apple',
            '98:F0:AB': 'Apple',
            '98:FE:94': 'Apple',
            '9C:04:EB': 'Apple',
            '9C:20:7B': 'Apple',
            '9C:28:EF': 'Apple',
            '9C:35:EB': 'Apple',
            '9C:4F:DA': 'Apple',
            '9C:84:BF': 'Apple',
            '9C:B6:54': 'Apple',
            '9C:E6:5E': 'Apple',
            '9C:FC:E8': 'Apple',
            'A0:18:28': 'Apple',
            'A0:99:9B': 'Apple',
            'A0:D7:95': 'Apple',
            'A0:ED:CD': 'Apple',
            'A4:31:35': 'Apple',
            'A4:5E:60': 'Apple',
            'A4:67:06': 'Apple',
            'A4:83:E7': 'Apple',
            'A4:B1:97': 'Apple',
            'A4:C3:61': 'Apple',
            'A4:D1:8C': 'Apple',
            'A4:D1:D2': 'Apple',
            'A8:20:66': 'Apple',
            'A8:5B:78': 'Apple',
            'A8:60:B6': 'Apple',
            'A8:66:7F': 'Apple',
            'A8:86:DD': 'Apple',
            'A8:88:08': 'Apple',
            'A8:96:8A': 'Apple',
            'A8:BB:CF': 'Apple',
            'A8:FA:D8': 'Apple',
            'AC:1F:74': 'Apple',
            'AC:29:3A': 'Apple',
            'AC:3C:0B': 'Apple',
            'AC:61:EA': 'Apple',
            'AC:87:A3': 'Apple',
            'AC:BC:32': 'Apple',
            'AC:CF:5C': 'Apple',
            'AC:E4:B5': 'Apple',
            'AC:FD:EC': 'Apple',
            'B0:34:95': 'Apple',
            'B0:65:BD': 'Apple',
            'B0:9F:BA': 'Apple',
            'B4:18:D1': 'Apple',
            'B4:8B:19': 'Apple',
            'B4:F0:AB': 'Apple',
            'B4:F6:1C': 'Apple',
            'B8:09:8A': 'Apple',
            'B8:17:C2': 'Apple',
            'B8:41:A4': 'Apple',
            'B8:5D:0A': 'Apple',
            'B8:63:4D': 'Apple',
            'B8:78:2E': 'Apple',
            'B8:C1:11': 'Apple',
            'B8:C7:5D': 'Apple',
            'B8:E8:56': 'Apple',
            'B8:F6:B1': 'Apple',
            'B8:FF:61': 'Apple',
            'BC:3B:AF': 'Apple',
            'BC:52:B7': 'Apple',
            'BC:67:1C': 'Apple',
            'BC:6C:21': 'Apple',
            'BC:92:6B': 'Apple',
            'BC:9F:EF': 'Apple',
            'BC:EC:5D': 'Apple',
            'C0:1A:DA': 'Apple',
            'C0:63:94': 'Apple',
            'C0:84:7D': 'Apple',
            'C0:9F:42': 'Apple',
            'C0:B6:58': 'Apple',
            'C0:CC:F8': 'Apple',
            'C0:CE:CD': 'Apple',
            'C0:D0:12': 'Apple',
            'C0:F2:FB': 'Apple',
            'C4:2C:03': 'Apple',
            'C4:61:8B': 'Apple',
            'C4:B3:01': 'Apple',
            'C8:2A:14': 'Apple',
            'C8:33:4B': 'Apple',
            'C8:69:CD': 'Apple',
            'C8:6F:1D': 'Apple',
            'C8:85:50': 'Apple',
            'C8:89:F3': 'Apple',
            'C8:B5:B7': 'Apple',
            'C8:BC:C8': 'Apple',
            'C8:D0:83': 'Apple',
            'C8:E0:EB': 'Apple',
            'CC:08:8D': 'Apple',
            'CC:20:E8': 'Apple',
            'CC:25:EF': 'Apple',
            'CC:29:F5': 'Apple',
            'CC:2D:21': 'Apple',
            'CC:2D:8C': 'Apple',
            'CC:44:63': 'Apple',
            'CC:78:5F': 'Apple',
            'CC:C7:60': 'Apple',
            'D0:03:4B': 'Apple',
            'D0:04:01': 'Apple',
            'D0:23:DB': 'Apple',
            'D0:25:98': 'Apple',
            'D0:33:11': 'Apple',
            'D0:4F:7E': 'Apple',
            'D0:81:7A': 'Apple',
            'D0:A6:37': 'Apple',
            'D0:C5:F3': 'Apple',
            'D0:D2:B0': 'Apple',
            'D0:E1:40': 'Apple',
            'D4:20:6D': 'Apple',
            'D4:61:9D': 'Apple',
            'D4:85:64': 'Apple',
            'D4:90:9C': 'Apple',
            'D4:A3:3D': 'Apple',
            'D4:DC:CD': 'Apple',
            'D4:F4:6F': 'Apple',
            'D8:1D:72': 'Apple',
            'D8:30:62': 'Apple',
            'D8:96:95': 'Apple',
            'D8:9E:3F': 'Apple',
            'D8:A2:5E': 'Apple',
            'D8:BB:2C': 'Apple',
            'D8:CF:9C': 'Apple',
            'DC:2B:2A': 'Apple',
            'DC:2B:61': 'Apple',
            'DC:37:85': 'Apple',
            'DC:37:14': 'Apple',
            'DC:41:E2': 'Apple',
            'DC:56:E7': 'Apple',
            'DC:86:D8': 'Apple',
            'DC:9B:9C': 'Apple',
            'DC:A4:CA': 'Apple',
            'DC:A9:04': 'Apple',
            'DC:AB:82': 'Apple',
            'DC:E4:CC': 'Apple',
            'E0:05:C5': 'Apple',
            'E0:66:78': 'Apple',
            'E0:AC:CB': 'Apple',
            'E0:B5:2D': 'Apple',
            'E0:B9:A5': 'Apple',
            'E0:C7:67': 'Apple',
            'E0:F5:C6': 'Apple',
            'E0:F8:47': 'Apple',
            'E4:25:E7': 'Apple',
            'E4:8B:7F': 'Apple',
            'E4:9A:79': 'Apple',
            'E4:C6:3D': 'Apple',
            'E4:CE:8F': 'Apple',
            'E8:04:0B': 'Apple',
            'E8:06:88': 'Apple',
            'E8:2A:EA': 'Apple',
            'E8:40:F2': 'Apple',
            'E8:80:2E': 'Apple',
            'E8:8D:28': 'Apple',
            'EC:35:86': 'Apple',
            'EC:85:2F': 'Apple',
            'EC:A8:6B': 'Apple',
            'F0:18:98': 'Apple',
            'F0:24:75': 'Apple',
            'F0:4D:A2': 'Apple',
            'F0:61:C8': 'Apple',
            'F0:72:8C': 'Apple',
            'F0:98:9D': 'Apple',
            'F0:9F:C2': 'Apple',
            'F0:B4:79': 'Apple',
            'F0:C1:F1': 'Apple',
            'F0:CB:A1': 'Apple',
            'F0:D1:A9': 'Apple',
            'F0:DB:E2': 'Apple',
            'F0:DC:E2': 'Apple',
            'F0:F6:1C': 'Apple',
            'F4:0F:24': 'Apple',
            'F4:1B:A1': 'Apple',
            'F4:37:B7': 'Apple',
            'F4:5C:89': 'Apple',
            'F4:F1:5A': 'Apple',
            'F4:F9:51': 'Apple',
            'F8:1E:DF': 'Apple',
            'F8:27:93': 'Apple',
            'F8:2D:7C': 'Apple',
            'F8:95:C7': 'Apple',
            'F8:CF:C5': 'Apple',
            'F8:DB:7F': 'Apple',
            'F8:E9:4E': 'Apple',
            'FC:25:3F': 'Apple',
            'FC:2A:9C': 'Apple',
            'FC:64:BA': 'Apple',
            'FC:E9:98': 'Apple',
            'FC:FC:48': 'Apple',
            '00:1B:44': 'Samsung',
            '00:12:FB': 'Samsung',
            '00:13:77': 'Samsung',
            '00:15:B9': 'Samsung',
            '00:16:32': 'Samsung',
            '00:16:6B': 'Samsung',
            '00:16:6C': 'Samsung',
            '00:16:DB': 'Samsung',
            '00:17:C9': 'Samsung',
            '00:17:D5': 'Samsung',
            '00:18:AF': 'Samsung',
            '00:1A:8A': 'Samsung',
            '00:1B:98': 'Samsung',
            '00:1C:43': 'Samsung',
            '00:1D:25': 'Samsung',
            '00:1D:F6': 'Samsung',
            '00:1E:7D': 'Samsung',
            '00:1E:E1': 'Samsung',
            '00:1E:E2': 'Samsung',
            '00:1F:CC': 'Samsung',
            '00:21:19': 'Samsung',
            '00:21:4C': 'Samsung',
            '00:21:D1': 'Samsung',
            '00:21:D2': 'Samsung',
            '00:23:39': 'Samsung',
            '00:23:99': 'Samsung',
            '00:23:C2': 'Samsung',
            '00:23:D6': 'Samsung',
            '00:23:D7': 'Samsung',
            '00:24:54': 'Samsung',
            '00:24:90': 'Samsung',
            '00:24:91': 'Samsung',
            '00:24:E9': 'Samsung',
            '00:26:37': 'Samsung',
            '00:26:5D': 'Samsung',
            '00:26:5F': 'Samsung',
            '34:23:BA': 'Samsung',
            '38:AA:3C': 'Samsung',
            '3C:62:00': 'Samsung',
            '40:0E:85': 'Samsung',
            '40:F3:08': 'Samsung',
            '44:4E:6D': 'Samsung',
            '44:A5:6E': 'Samsung',
            '48:5A:3F': 'Samsung',
            '4C:BC:A5': 'Samsung',
            '50:32:75': 'Samsung',
            '50:B7:C3': 'Samsung',
            '50:CC:F8': 'Samsung',
            '54:88:0E': 'Samsung',
            '58:85:E8': 'Samsung',
            '5C:0A:5B': 'Samsung',
            '5C:F6:DC': 'Samsung',
            '60:6B:BD': 'Samsung',
            '64:16:66': 'Samsung',
            '68:EB:AE': 'Samsung',
            '6C:F3:73': 'Samsung',
            '70:F9:27': 'Samsung',
            '74:45:8A': 'Samsung',
            '78:1F:DB': 'Samsung',
            '78:25:AD': 'Samsung',
            '78:47:1D': 'Samsung',
            '78:59:5E': 'Samsung',
            '78:AB:BB': 'Samsung',
            '78:BD:BC': 'Samsung',
            '78:D6:F0': 'Samsung',
            '7C:11:CB': 'Samsung',
            '7C:61:66': 'Samsung',
            '7C:B0:C2': 'Samsung',
            '80:18:A7': 'Samsung',
            '84:0B:2D': 'Samsung',
            '84:25:DB': 'Samsung',
            '88:32:9B': 'Samsung',
            '88:36:5F': 'Samsung',
            '8C:77:12': 'Samsung',
            '8C:C8:CD': 'Samsung',
            '8C:DE:F9': 'Samsung',
            '90:18:7C': 'Samsung',
            '94:35:0A': 'Samsung',
            '98:52:B1': 'Samsung',
            '98:83:89': 'Samsung',
            '9C:02:98': 'Samsung',
            '9C:3A:AF': 'Samsung',
            '9C:E3:3F': 'Samsung',
            'A0:07:98': 'Samsung',
            'A0:0B:BA': 'Samsung',
            'A0:21:95': 'Samsung',
            'A4:EB:D3': 'Samsung',
            'A8:F2:74': 'Samsung',
            'AC:36:13': 'Samsung',
            'AC:5A:14': 'Samsung',
            'AC:5F:3E': 'Samsung',
            'B0:72:BF': 'Samsung',
            'B0:C5:59': 'Samsung',
            'B0:EC:71': 'Samsung',
            'B4:07:F9': 'Samsung',
            'B4:79:A7': 'Samsung',
            'B8:5E:7B': 'Samsung',
            'BC:14:85': 'Samsung',
            'BC:20:BA': 'Samsung',
            'BC:44:86': 'Samsung',
            'BC:72:B1': 'Samsung',
            'BC:76:70': 'Samsung',
            'BC:8C:CD': 'Samsung',
            'C0:97:27': 'Samsung',
            'C4:42:02': 'Samsung',
            'C4:57:6E': 'Samsung',
            'C4:73:1E': 'Samsung',
            'C8:19:F7': 'Samsung',
            'C8:1E:E7': 'Samsung',
            'C8:97:9F': 'Samsung',
            'CC:05:1B': 'Samsung',
            'CC:07:AB': 'Samsung',
            'CC:3A:61': 'Samsung',
            'CC:FE:3C': 'Samsung',
            'D0:17:6A': 'Samsung',
            'D0:22:BE': 'Samsung',
            'D0:57:7B': 'Samsung',
            'D0:59:E4': 'Samsung',
            'D0:66:7B': 'Samsung',
            'D0:87:E2': 'Samsung',
            'D0:DF:C7': 'Samsung',
            'D4:88:90': 'Samsung',
            'D4:E8:B2': 'Samsung',
            'D8:57:EF': 'Samsung',
            'D8:90:E8': 'Samsung',
            'DC:71:44': 'Samsung',
            'E4:12:1D': 'Samsung',
            'E4:40:E2': 'Samsung',
            'E4:92:FB': 'Samsung',
            'E8:03:9A': 'Samsung',
            'E8:11:32': 'Samsung',
            'E8:50:8B': 'Samsung',
            'E8:E5:D6': 'Samsung',
            'EC:1D:8B': 'Samsung',
            'EC:9B:F3': 'Samsung',
            'F0:08:F1': 'Samsung',
            'F0:25:B7': 'Samsung',
            'F0:5A:09': 'Samsung',
            'F4:09:D8': 'Samsung',
            'F4:7B:5E': 'Samsung',
            'F8:04:2E': 'Samsung',
            'F8:D0:AC': 'Samsung',
            'FC:00:12': 'Samsung',
            'FC:A1:3E': 'Samsung',
            'FC:C7:34': 'Samsung',
        }

    def get_vendor_from_mac(self, mac):
        if not mac or mac == 'Unknown':
            return 'Unknown'
        mac_prefix = mac.upper()[:8]
        return self.mac_vendors.get(mac_prefix, 'Unknown')

    def arp_scan(self, target_ip):
        try:
            self.display.print_info("ARP Scan", f"scanning {target_ip}...")
            
            try:
                network = ipaddress.IPv4Network(target_ip)
                if network.num_addresses > 1024:
                    self.display.print_warning(f"Network too large ({network.num_addresses} hosts), limiting scope")
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

        except PermissionError:
            self.display.print_error("ARP scan requires administrator/root privileges")
            return []
        except Exception as e:
            self.display.print_error(f"ARP scan error: {str(e)[:50]}")
            return []

    def ping_sweep(self, network_info):
        self.display.print_info("Ping Sweep", f"scanning {network_info['network_range']}...")
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
                except (subprocess.TimeoutExpired, Exception):
                    continue
                    
        except Exception as e:
            self.display.print_error(f"Ping sweep error: {str(e)[:50]}")
        
        return devices

    def get_hostname(self, ip):
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None

    def _add_network_context(self, devices, network_info):
        saved_count = 0
        
        self.display.print_section("Saving Devices to Database")
        
        for device in devices:
            try:
                device['network_context'] = {
                    'network_type': network_info['network_type'],
                    'subnet': network_info['network_range'],
                    'scan_location': self._infer_location(network_info),
                    'trust_level': self._calculate_trust_level(device, network_info),
                }
                
                try:
                    hostname = self.get_hostname(device['ip'])
                    if hostname:
                        device['hostname'] = hostname
                except:
                    device['hostname'] = None
                
                if not device.get('ip') or device['ip'] == 'Unknown':
                    self.display.print_warning(f"Skipping device: No valid IP")
                    continue
                
                mac = device.get('mac')
                if not mac or mac == 'Unknown':
                    mac = f"00:00:00:{device['ip'].split('.')[-3]:02x}:{device['ip'].split('.')[-2]:02x}:{device['ip'].split('.')[-1]:02x}".upper()
                    device['mac'] = mac
                    self.display.print_info(f"Generated MAC for {device['ip']}", mac)
                
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
                        self.display.print_success(f"Saved: {device['ip']} (ID: {device_id})")
                    else:
                        self.display.print_warning(f"Failed to save: {device['ip']}")
                        
                except Exception as db_error:
                    self.display.print_error(f"DB Error for {device['ip']}: {db_error}")
                    
            except Exception as e:
                self.display.print_error(f"Error processing device: {e}")
                continue
        
        self.display.print_info("Database Save", f"Saved {saved_count}/{len(devices)} devices")
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
                self.display.print_info("Continuous Scan", f"Next scan in {interval} seconds...")
                time.sleep(interval)
        
        self.scan_thread = threading.Thread(target=scan_loop, daemon=True)
        self.scan_thread.start()
        self.display.print_success(f"Continuous scanning started (interval: {interval}s)")

    def stop_scan(self):
        self.scanning = False
        if self.scan_thread:
            self.scan_thread.join(timeout=5)
        self.display.print_success("Continuous scanning stopped")
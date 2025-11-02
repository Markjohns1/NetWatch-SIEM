"""
Advanced Network Scanner for NetWatch SIEM
Implements enterprise-grade network discovery and monitoring
"""

import asyncio
import concurrent.futures
import ipaddress
import json
import logging
import socket
import subprocess
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
import psutil
import nmap
from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
try:
    import requests
except ImportError:
    requests = None

try:
    import dns.resolver
except ImportError:
    dns = None

logger = logging.getLogger(__name__)

class AdvancedNetworkScanner:
    """Enterprise-grade network scanner with multiple detection methods"""
    
    def __init__(self, db, config=None):
        self.db = db
        self.config = config or {}
        self.active_devices = {}
        self.device_history = defaultdict(list)
        self.network_topology = {}
        self.traffic_monitor = TrafficMonitor()
        self.threat_detector = ThreatDetector()
        
        # Performance settings
        self.max_threads = 50
        self.scan_timeout = 3
        self.ping_timeout = 1
        self.arp_timeout = 2
        
        # Detection methods
        self.detection_methods = [
            'arp_scan',
            'ping_sweep', 
            'port_scan',
            'dhcp_monitor',
            'dns_monitor',
            'traffic_analysis',
            'passive_discovery'
        ]
        
        # Device fingerprinting
        self.device_fingerprints = {}
        self.vendor_database = self._load_vendor_database()
        
        # Real-time monitoring
        self.monitoring_active = False
        self.monitor_thread = None
        
    def _load_vendor_database(self):
        """Load MAC vendor database for device identification"""
        try:
            # Load from local file or online source
            with open('data/oui_database.json', 'r') as f:
                return json.load(f)
        except:
            # Fallback to basic vendor detection
            return {}
    
    async def comprehensive_network_scan(self) -> List[Dict]:
        """Perform comprehensive network discovery using multiple methods"""
        logger.info("Starting comprehensive network scan...")
        
        # Get network information
        network_info = self._get_network_info()
        if not network_info:
            logger.error("Could not determine network configuration")
            return []
        
        # Run all detection methods concurrently
        tasks = []
        for method in self.detection_methods:
            if hasattr(self, f'_{method}'):
                task = asyncio.create_task(getattr(self, f'_{method}')(network_info))
                tasks.append(task)
        
        # Wait for all scans to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Merge and deduplicate results
        all_devices = {}
        for result in results:
            if isinstance(result, list):
                for device in result:
                    if device.get('mac_address'):
                        key = device['mac_address']
                        if key not in all_devices:
                            all_devices[key] = device
                        else:
                            # Merge device information
                            all_devices[key].update(device)
        
        # Enhanced device analysis
        enhanced_devices = []
        for device in all_devices.values():
            enhanced_device = await self._enhance_device_info(device)
            enhanced_devices.append(enhanced_device)
        
        logger.info(f"Comprehensive scan completed. Found {len(enhanced_devices)} devices")
        return enhanced_devices
    
    def _get_network_info(self) -> Optional[Dict]:
        """Get comprehensive network information"""
        try:
            # Check for Windows and warn about limitations
            import platform
            if platform.system() == "Windows":
                logger.warning("Windows detected: ARP scanning requires administrator privileges")
                logger.warning("Consider running as administrator or install Npcap for full functionality")
            
            # Get active network interfaces
            interfaces = psutil.net_if_addrs()
            active_interfaces = []
            
            for interface, addresses in interfaces.items():
                if interface.startswith(('lo', 'docker', 'veth')):
                    continue
                
                for addr in addresses:
                    if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                        active_interfaces.append({
                            'interface': interface,
                            'ip': addr.address,
                            'netmask': addr.netmask,
                            'broadcast': addr.broadcast
                        })
                        break
            
            if not active_interfaces:
                return None
            
            # Use the first active interface
            primary_interface = active_interfaces[0]
            
            # Calculate network range
            network = ipaddress.IPv4Network(
                f"{primary_interface['ip']}/{primary_interface['netmask']}", 
                strict=False
            )
            
            return {
                'interface': primary_interface['interface'],
                'ip': primary_interface['ip'],
                'network': str(network.network_address),
                'netmask': primary_interface['netmask'],
                'broadcast': primary_interface['broadcast'],
                'network_range': str(network),
                'host_count': network.num_addresses
            }
            
        except Exception as e:
            logger.error(f"Error getting network info: {e}")
            return None
    
    async def _arp_scan(self, network_info: Dict) -> List[Dict]:
        """Enhanced ARP scanning with better error handling"""
        devices = []
        
        try:
            # Create ARP request for entire subnet
            network = ipaddress.IPv4Network(network_info['network_range'])
            
            # Split into chunks for better performance
            ip_chunks = list(self._chunk_list(list(network.hosts()), 50))
            
            for chunk in ip_chunks:
                chunk_devices = await self._arp_scan_chunk(chunk)
                devices.extend(chunk_devices)
                await asyncio.sleep(0.1)  # Small delay between chunks
            
        except Exception as e:
            logger.error(f"ARP scan error: {e}")
        
        return devices
    
    async def _arp_scan_chunk(self, ip_list: List) -> List[Dict]:
        """Scan a chunk of IP addresses with Windows compatibility"""
        devices = []
        
        try:
            # Check if we're on Windows and handle accordingly
            import platform
            if platform.system() == "Windows":
                # On Windows, ARP scanning requires administrator privileges
                # Fall back to ping-based discovery
                logger.info("Windows detected - using ping-based discovery instead of ARP")
                return await self._ping_scan_chunk(ip_list)
            
            # Create ARP requests
            arp_requests = []
            for ip in ip_list:
                arp_req = ARP(pdst=str(ip))
                arp_requests.append(arp_req)
            
            # Send ARP requests
            answered, unanswered = sr(arp_requests, timeout=self.arp_timeout, verbose=0)
            
            for sent, received in answered:
                device = {
                    'ip_address': received.psrc,
                    'mac_address': received.hwsrc,
                    'vendor': self._get_vendor(received.hwsrc),
                    'detection_method': 'arp_scan',
                    'timestamp': datetime.now().isoformat()
                }
                devices.append(device)
                
        except (PermissionError, OSError) as e:
            # Silently fall back to ping-based discovery for permission errors
            return await self._ping_scan_chunk(ip_list)
        except Exception as e:
            # Log other errors but still fall back
            logger.debug(f"ARP chunk scan error: {e}")
            # Fall back to ping-based discovery
            return await self._ping_scan_chunk(ip_list)
        
        return devices
    
    async def _ping_scan_chunk(self, ip_list: List) -> List[Dict]:
        """Ping-based device discovery for Windows compatibility"""
        devices = []
        
        try:
            for ip in ip_list:
                if self._ping_host(str(ip)):
                    device = {
                        'ip_address': str(ip),
                        'detection_method': 'ping_scan',
                        'timestamp': datetime.now().isoformat()
                    }
                    devices.append(device)
        except Exception as e:
            logger.error(f"Ping scan chunk error: {e}")
        
        return devices
    
    async def _ping_sweep(self, network_info: Dict) -> List[Dict]:
        """Enhanced ping sweep with parallel processing"""
        devices = []
        
        try:
            network = ipaddress.IPv4Network(network_info['network_range'])
            
            # Use concurrent futures for parallel pings
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                
                for ip in network.hosts():
                    future = executor.submit(self._ping_host, str(ip))
                    futures.append((str(ip), future))
                
                for ip, future in futures:
                    try:
                        if future.result(timeout=self.ping_timeout):
                            device = {
                                'ip_address': ip,
                                'detection_method': 'ping_sweep',
                                'timestamp': datetime.now().isoformat()
                            }
                            devices.append(device)
                    except:
                        pass
                        
        except Exception as e:
            logger.error(f"Ping sweep error: {e}")
        
        return devices
    
    def _ping_host(self, ip: str) -> bool:
        """Ping a single host"""
        try:
            # Use system ping for better reliability
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '1', ip],
                capture_output=True,
                timeout=self.ping_timeout
            )
            return result.returncode == 0
        except:
            return False
    
    async def _port_scan(self, network_info: Dict) -> List[Dict]:
        """Port scanning for service discovery"""
        devices = []
        
        try:
            # Common ports to scan
            common_ports = [22, 23, 53, 80, 135, 139, 443, 445, 993, 995]
            
            network = ipaddress.IPv4Network(network_info['network_range'])
            
            # Use nmap for port scanning
            nm = nmap.PortScanner()
            
            # Scan in chunks to avoid overwhelming the network
            ip_chunks = list(self._chunk_list(list(network.hosts()), 20))
            
            for chunk in ip_chunks:
                ip_range = ','.join(str(ip) for ip in chunk)
                port_range = ','.join(str(port) for port in common_ports)
                
                try:
                    nm.scan(ip_range, port_range, arguments='-sS -T4 --max-retries 1')
                    
                    for host in nm.all_hosts():
                        if nm[host].state() == 'up':
                            open_ports = []
                            for port in nm[host]['tcp']:
                                if nm[host]['tcp'][port]['state'] == 'open':
                                    open_ports.append(port)
                            
                            if open_ports:
                                device = {
                                    'ip_address': host,
                                    'open_ports': open_ports,
                                    'services': self._identify_services(open_ports),
                                    'detection_method': 'port_scan',
                                    'timestamp': datetime.now().isoformat()
                                }
                                devices.append(device)
                                
                except (PermissionError, nmap.PortScannerError) as e:
                    # Silently skip port scan chunks that require privileges
                    logger.debug(f"Port scan chunk error (privileged operation): {e}")
                except Exception as e:
                    logger.debug(f"Port scan chunk error: {e}")
                
                await asyncio.sleep(0.5)  # Delay between chunks
                
        except Exception as e:
            logger.debug(f"Port scan error: {e}")
        
        return devices
    
    async def _dhcp_monitor(self, network_info: Dict) -> List[Dict]:
        """Monitor DHCP traffic for new devices"""
        devices = []
        
        try:
            # This would require packet capture capabilities
            # For now, we'll implement a basic version
            logger.info("DHCP monitoring not fully implemented yet")
            
        except Exception as e:
            logger.error(f"DHCP monitor error: {e}")
        
        return devices
    
    async def _dns_monitor(self, network_info: Dict) -> List[Dict]:
        """Monitor DNS queries for device discovery"""
        devices = []
        
        try:
            # Monitor local DNS cache or queries
            # This is a simplified version
            logger.info("DNS monitoring not fully implemented yet")
            
        except Exception as e:
            logger.error(f"DNS monitor error: {e}")
        
        return devices
    
    async def _traffic_analysis(self, network_info: Dict) -> List[Dict]:
        """Analyze network traffic for device discovery"""
        devices = []
        
        try:
            # This would require packet capture and analysis
            # For now, we'll implement basic traffic monitoring
            logger.info("Traffic analysis not fully implemented yet")
            
        except Exception as e:
            logger.error(f"Traffic analysis error: {e}")
        
        return devices
    
    async def _passive_discovery(self, network_info: Dict) -> List[Dict]:
        """Passive device discovery through network monitoring"""
        devices = []
        
        try:
            # Monitor ARP table changes
            arp_table = self._get_arp_table()
            
            for entry in arp_table:
                device = {
                    'ip_address': entry['ip'],
                    'mac_address': entry['mac'],
                    'vendor': self._get_vendor(entry['mac']),
                    'detection_method': 'passive_discovery',
                    'timestamp': datetime.now().isoformat()
                }
                devices.append(device)
                
        except Exception as e:
            logger.error(f"Passive discovery error: {e}")
        
        return devices
    
    async def _enhance_device_info(self, device: Dict) -> Dict:
        """Enhance device information with additional details"""
        enhanced = device.copy()
        
        try:
            # Get hostname
            if device.get('ip_address'):
                hostname = await self._resolve_hostname(device['ip_address'])
                if hostname:
                    enhanced['hostname'] = hostname
            
            # Get device type
            enhanced['device_type'] = self._identify_device_type(device)
            
            # Get operating system info
            if device.get('open_ports'):
                enhanced['os_info'] = self._identify_os(device['open_ports'])
            
            # Calculate risk score
            enhanced['risk_score'] = self._calculate_risk_score(device)
            
            # Get device status
            enhanced['status'] = await self._check_device_status(device)
            
            # Add fingerprint
            enhanced['fingerprint'] = self._generate_device_fingerprint(device)
            
        except Exception as e:
            logger.error(f"Error enhancing device info: {e}")
        
        return enhanced
    
    async def _resolve_hostname(self, ip: str) -> Optional[str]:
        """Resolve hostname for IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None
    
    def _identify_device_type(self, device: Dict) -> str:
        """Identify device type based on available information"""
        mac = device.get('mac_address', '').upper()
        vendor = device.get('vendor', '').lower()
        ports = device.get('open_ports', [])
        
        # Router/Gateway detection
        if any(port in ports for port in [80, 443, 8080]):
            if 'cisco' in vendor or 'netgear' in vendor or 'linksys' in vendor:
                return 'router'
        
        # Server detection
        if any(port in ports for port in [22, 3389, 5985, 5986]):
            return 'server'
        
        # Printer detection
        if any(port in ports for port in [515, 631, 9100]):
            return 'printer'
        
        # IoT device detection
        if 'unknown' in vendor or not vendor:
            return 'iot_device'
        
        # Default
        return 'unknown'
    
    def _identify_services(self, ports: List[int]) -> List[str]:
        """Identify services running on open ports"""
        service_map = {
            22: 'SSH',
            23: 'Telnet',
            53: 'DNS',
            80: 'HTTP',
            135: 'RPC',
            139: 'NetBIOS',
            443: 'HTTPS',
            445: 'SMB',
            993: 'IMAPS',
            995: 'POP3S'
        }
        
        return [service_map.get(port, f'Port-{port}') for port in ports]
    
    def _identify_os(self, ports: List[int]) -> str:
        """Identify operating system based on open ports"""
        # This is a simplified OS detection
        if 135 in ports and 445 in ports:
            return 'Windows'
        elif 22 in ports and 80 in ports:
            return 'Linux/Unix'
        else:
            return 'Unknown'
    
    def _calculate_risk_score(self, device: Dict) -> int:
        """Calculate risk score for device"""
        score = 0
        
        # Unknown vendor increases risk
        if not device.get('vendor') or device.get('vendor') == 'Unknown':
            score += 3
        
        # Suspicious ports
        suspicious_ports = [23, 135, 139, 445]
        if any(port in device.get('open_ports', []) for port in suspicious_ports):
            score += 2
        
        # No hostname
        if not device.get('hostname'):
            score += 1
        
        return min(score, 10)
    
    async def _check_device_status(self, device: Dict) -> str:
        """Check if device is currently online"""
        try:
            if device.get('ip_address'):
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '1', device['ip_address']],
                    capture_output=True,
                    timeout=2
                )
                return 'online' if result.returncode == 0 else 'offline'
        except:
            pass
        
        return 'unknown'
    
    def _generate_device_fingerprint(self, device: Dict) -> str:
        """Generate unique fingerprint for device"""
        fingerprint_data = {
            'mac': device.get('mac_address', ''),
            'vendor': device.get('vendor', ''),
            'ports': sorted(device.get('open_ports', [])),
            'services': sorted(device.get('services', []))
        }
        
        fingerprint = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.md5(fingerprint.encode()).hexdigest()
    
    def _get_vendor(self, mac: str) -> str:
        """Get vendor from MAC address"""
        if not mac:
            return 'Unknown'
        
        # Extract OUI (first 3 bytes)
        oui = mac.replace(':', '').replace('-', '')[:6].upper()
        
        # Check vendor database
        if oui in self.vendor_database:
            return self.vendor_database[oui]
        
        return 'Unknown'
    
    def _get_arp_table(self) -> List[Dict]:
        """Get system ARP table"""
        arp_entries = []
        
        try:
            # Read ARP table
            with open('/proc/net/arp', 'r') as f:
                lines = f.readlines()[1:]  # Skip header
                
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 4:
                        arp_entries.append({
                            'ip': parts[0],
                            'mac': parts[3],
                            'type': parts[1]
                        })
        except:
            pass
        
        return arp_entries
    
    def _chunk_list(self, lst: List, chunk_size: int) -> List[List]:
        """Split list into chunks"""
        for i in range(0, len(lst), chunk_size):
            yield lst[i:i + chunk_size]
    
    def start_real_time_monitoring(self):
        """Start real-time network monitoring"""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("Real-time monitoring started")
    
    def stop_real_time_monitoring(self):
        """Stop real-time network monitoring"""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("Real-time monitoring stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                # Perform quick device status checks
                self._update_device_status()
                
                # Monitor for new devices
                self._detect_new_devices()
                
                # Update device information
                self._update_device_info()
                
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                time.sleep(60)  # Wait longer on error
    
    def _update_device_status(self):
        """Update status of known devices"""
        # Implementation for updating device status
        pass
    
    def _detect_new_devices(self):
        """Detect new devices on the network"""
        # Implementation for detecting new devices
        pass
    
    def _update_device_info(self):
        """Update information for existing devices"""
        # Implementation for updating device information
        pass


class TrafficMonitor:
    """Monitor network traffic for threat detection"""
    
    def __init__(self):
        self.traffic_stats = defaultdict(int)
        self.anomaly_detector = AnomalyDetector()
    
    def analyze_traffic(self, packet):
        """Analyze network packet for threats"""
        # Implementation for traffic analysis
        pass


class ThreatDetector:
    """Detect security threats and anomalies"""
    
    def __init__(self):
        self.threat_patterns = self._load_threat_patterns()
    
    def _load_threat_patterns(self):
        """Load threat detection patterns"""
        return {
            'port_scan': {'threshold': 10, 'time_window': 60},
            'brute_force': {'threshold': 5, 'time_window': 300},
            'suspicious_traffic': {'threshold': 100, 'time_window': 60}
        }
    
    def detect_threats(self, device_data):
        """Detect threats based on device behavior"""
        threats = []
        
        # Implementation for threat detection
        return threats


class AnomalyDetector:
    """Detect anomalous network behavior"""
    
    def __init__(self):
        self.baseline = {}
        self.deviation_threshold = 2.0
    
    def update_baseline(self, metric, value):
        """Update baseline for anomaly detection"""
        if metric not in self.baseline:
            self.baseline[metric] = deque(maxlen=100)
        
        self.baseline[metric].append(value)
    
    def detect_anomaly(self, metric, value):
        """Detect if value is anomalous"""
        if metric not in self.baseline or len(self.baseline[metric]) < 10:
            return False
        
        baseline_values = list(self.baseline[metric])
        mean = sum(baseline_values) / len(baseline_values)
        std_dev = (sum((x - mean) ** 2 for x in baseline_values) / len(baseline_values)) ** 0.5
        
        if std_dev == 0:
            return False
        
        z_score = abs(value - mean) / std_dev
        return z_score > self.deviation_threshold


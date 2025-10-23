"""
Real-time Traffic Analyzer for NetWatch SIEM
Provides deep packet inspection and traffic analysis
"""

import asyncio
import json
import logging
import socket
import struct
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import psutil
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether # this is for the ethernet layer which is used to extract the source and destination mac addresses
import hashlib

logger = logging.getLogger(__name__)

class TrafficAnalyzer:
    """Real-time network traffic analysis and monitoring"""
    
    def __init__(self, db, config=None):
        self.db = db
        self.config = config or {}
        self.is_monitoring = False
        self.monitor_thread = None
        
        # Traffic statistics
        self.traffic_stats = defaultdict(lambda: {
            'bytes_sent': 0,
            'bytes_received': 0,
            'packets_sent': 0,
            'packets_received': 0,
            'connections': 0,
            'last_seen': None
        })
        
        # Connection tracking
        self.active_connections = {}
        self.connection_history = deque(maxlen=10000)
        
        # Threat detection
        self.threat_detector = ThreatDetector()
        self.anomaly_detector = AnomalyDetector()
        
        # Performance monitoring
        self.performance_metrics = {
            'packets_processed': 0,
            'threats_detected': 0,
            'anomalies_detected': 0,
            'start_time': None
        }
        
        # Bandwidth monitoring
        self.bandwidth_stats = defaultdict(lambda: deque(maxlen=60))  # 60 seconds
        
    def start_monitoring(self, interface=None):
        """Start real-time traffic monitoring"""
        if self.is_monitoring:
            return
        
        self.is_monitoring = True
        self.performance_metrics['start_time'] = datetime.now()
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(
            target=self._monitoring_loop, 
            args=(interface,),
            daemon=True
        )
        self.monitor_thread.start()
        
        logger.info(f"Traffic monitoring started on interface: {interface or 'auto'}")
    
    def stop_monitoring(self):
        """Stop traffic monitoring"""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("Traffic monitoring stopped")
    
    def _monitoring_loop(self, interface=None):
        """Main monitoring loop"""
        try:
            # Get network interface
            if not interface:
                interface = self._get_primary_interface()
            
            if not interface:
                logger.error("No suitable network interface found")
                return
            
            # Start packet capture
            sniff(
                iface=interface,
                prn=self._process_packet,
                store=0,
                stop_filter=lambda x: not self.is_monitoring
            )
            
        except Exception as e:
            logger.error(f"Traffic monitoring error: {e}")
    
    def _get_primary_interface(self) -> Optional[str]:
        """Get primary network interface"""
        try:
            interfaces = psutil.net_if_addrs()
            
            for interface, addresses in interfaces.items():
                if interface.startswith(('lo', 'docker', 'veth')):
                    continue
                
                for addr in addresses:
                    if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                        return interface
            
        except Exception as e:
            logger.error(f"Error getting primary interface: {e}")
        
        return None
    
    def _process_packet(self, packet):
        """Process captured packet"""
        try:
            self.performance_metrics['packets_processed'] += 1
            
            # Extract packet information
            packet_info = self._extract_packet_info(packet)
            if not packet_info:
                return
            
            # Update traffic statistics
            self._update_traffic_stats(packet_info)
            
            # Track connections
            self._track_connection(packet_info)
            
            # Detect threats
            threats = self.threat_detector.analyze_packet(packet_info)
            if threats:
                self.performance_metrics['threats_detected'] += len(threats)
                self._handle_threats(threats, packet_info)
            
            # Detect anomalies
            anomalies = self.anomaly_detector.detect_anomalies(packet_info)
            if anomalies:
                self.performance_metrics['anomalies_detected'] += len(anomalies)
                self._handle_anomalies(anomalies, packet_info)
            
            # Update bandwidth stats
            self._update_bandwidth_stats(packet_info)
            
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def _extract_packet_info(self, packet) -> Optional[Dict]:
        """Extract relevant information from packet"""
        try:
            packet_info = {
                'timestamp': datetime.now(),
                'size': len(packet),
                'protocol': 'unknown'
            }
            
            # Extract IP information
            if IP in packet:
                ip_layer = packet[IP]
                packet_info.update({
                    'src_ip': ip_layer.src,
                    'dst_ip': ip_layer.dst,
                    'protocol': ip_layer.proto,
                    'ttl': ip_layer.ttl,
                    'tos': ip_layer.tos
                })
                
                # Extract TCP information
                if TCP in packet:
                    tcp_layer = packet[TCP]
                    packet_info.update({
                        'src_port': tcp_layer.sport,
                        'dst_port': tcp_layer.dport,
                        'flags': tcp_layer.flags,
                        'seq': tcp_layer.seq,
                        'ack': tcp_layer.ack,
                        'window': tcp_layer.window
                    })
                
                # Extract UDP information
                elif UDP in packet:
                    udp_layer = packet[UDP]
                    packet_info.update({
                        'src_port': udp_layer.sport,
                        'dst_port': udp_layer.dport,
                        'length': udp_layer.len
                    })
                
                # Extract ICMP information
                elif ICMP in packet:
                    icmp_layer = packet[ICMP]
                    packet_info.update({
                        'icmp_type': icmp_layer.type,
                        'icmp_code': icmp_layer.code
                    })
            
            # Extract Ethernet information
            if Ether in packet:
                eth_layer = packet[Ether]
                packet_info.update({
                    'src_mac': eth_layer.src,
                    'dst_mac': eth_layer.dst,
                    'ethertype': eth_layer.type
                })
            
            # Extract ARP information
            if ARP in packet:
                arp_layer = packet[ARP]
                packet_info.update({
                    'arp_op': arp_layer.op,
                    'arp_psrc': arp_layer.psrc,
                    'arp_pdst': arp_layer.pdst,
                    'arp_hwsrc': arp_layer.hwsrc,
                    'arp_hwdst': arp_layer.hwdst
                })
            
            return packet_info
            
        except Exception as e:
            logger.error(f"Error extracting packet info: {e}")
            return None
    
    def _update_traffic_stats(self, packet_info: Dict):
        """Update traffic statistics"""
        try:
            src_ip = packet_info.get('src_ip')
            dst_ip = packet_info.get('dst_ip')
            size = packet_info.get('size', 0)
            
            if src_ip:
                self.traffic_stats[src_ip]['bytes_sent'] += size
                self.traffic_stats[src_ip]['packets_sent'] += 1
                self.traffic_stats[src_ip]['last_seen'] = packet_info['timestamp']
            
            if dst_ip:
                self.traffic_stats[dst_ip]['bytes_received'] += size
                self.traffic_stats[dst_ip]['packets_received'] += 1
                self.traffic_stats[dst_ip]['last_seen'] = packet_info['timestamp']
                
        except Exception as e:
            logger.error(f"Error updating traffic stats: {e}")
    
    def _track_connection(self, packet_info: Dict):
        """Track network connections"""
        try:
            src_ip = packet_info.get('src_ip')
            dst_ip = packet_info.get('dst_ip')
            src_port = packet_info.get('src_port')
            dst_port = packet_info.get('dst_port')
            protocol = packet_info.get('protocol')
            
            if not all([src_ip, dst_ip, src_port, dst_port, protocol]):
                return
            
            # Create connection key
            conn_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
            
            # Update connection info
            if conn_key not in self.active_connections:
                self.active_connections[conn_key] = {
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'start_time': packet_info['timestamp'],
                    'packets': 0,
                    'bytes': 0,
                    'last_seen': packet_info['timestamp']
                }
            
            # Update connection stats
            self.active_connections[conn_key]['packets'] += 1
            self.active_connections[conn_key]['bytes'] += packet_info.get('size', 0)
            self.active_connections[conn_key]['last_seen'] = packet_info['timestamp']
            
            # Add to history
            self.connection_history.append({
                'timestamp': packet_info['timestamp'],
                'connection': conn_key,
                'packet_info': packet_info
            })
            
        except Exception as e:
            logger.error(f"Error tracking connection: {e}")
    
    def _update_bandwidth_stats(self, packet_info: Dict):
        """Update bandwidth statistics"""
        try:
            current_time = packet_info['timestamp']
            size = packet_info.get('size', 0)
            
            # Update per-second bandwidth
            second_key = current_time.strftime('%Y-%m-%d %H:%M:%S')
            self.bandwidth_stats[second_key].append(size)
            
        except Exception as e:
            logger.error(f"Error updating bandwidth stats: {e}")
    
    def _handle_threats(self, threats: List[Dict], packet_info: Dict):
        """Handle detected threats"""
        try:
            for threat in threats:
                # Log threat
                self.db.add_event(
                    event_type='threat_detected',
                    severity=threat.get('severity', 'medium'),
                    description=threat.get('description', 'Unknown threat'),
                    metadata={
                        'threat_type': threat.get('type'),
                        'packet_info': packet_info,
                        'threat_details': threat
                    }
                )
                
                # Create alert
                self.db.add_alert(
                    alert_type=threat.get('type', 'unknown_threat'),
                    severity=threat.get('severity', 'medium'),
                    title=f"Threat Detected: {threat.get('type', 'Unknown')}",
                    description=threat.get('description', 'Unknown threat detected'),
                    metadata=threat
                )
                
                logger.warning(f"Threat detected: {threat}")
                
        except Exception as e:
            logger.error(f"Error handling threats: {e}")
    
    def _handle_anomalies(self, anomalies: List[Dict], packet_info: Dict):
        """Handle detected anomalies"""
        try:
            for anomaly in anomalies:
                # Log anomaly
                self.db.add_event(
                    event_type='anomaly_detected',
                    severity='low',
                    description=anomaly.get('description', 'Network anomaly detected'),
                    metadata={
                        'anomaly_type': anomaly.get('type'),
                        'packet_info': packet_info,
                        'anomaly_details': anomaly
                    }
                )
                
                logger.info(f"Anomaly detected: {anomaly}")
                
        except Exception as e:
            logger.error(f"Error handling anomalies: {e}")
    
    def get_traffic_stats(self) -> Dict:
        """Get current traffic statistics"""
        return {
            'traffic_stats': dict(self.traffic_stats),
            'active_connections': len(self.active_connections),
            'performance_metrics': self.performance_metrics.copy(),
            'bandwidth_stats': {
                key: sum(values) for key, values in self.bandwidth_stats.items()
            }
        }
    
    def get_connection_history(self, limit: int = 100) -> List[Dict]:
        """Get recent connection history"""
        return list(self.connection_history)[-limit:]
    
    def get_bandwidth_usage(self, time_window: int = 60) -> Dict:
        """Get bandwidth usage for time window"""
        current_time = datetime.now()
        start_time = current_time - timedelta(seconds=time_window)
        
        bandwidth_data = []
        for second_key, sizes in self.bandwidth_stats.items():
            try:
                second_time = datetime.strptime(second_key, '%Y-%m-%d %H:%M:%S')
                if second_time >= start_time:
                    bandwidth_data.append({
                        'timestamp': second_time.isoformat(),
                        'bytes': sum(sizes)
                    })
            except:
                continue
        
        return {
            'time_window': time_window,
            'data': sorted(bandwidth_data, key=lambda x: x['timestamp'])
        }


class ThreatDetector:
    """Detect security threats in network traffic"""
    
    def __init__(self):
        self.threat_patterns = {
            'port_scan': {
                'threshold': 10,
                'time_window': 60,
                'description': 'Port scanning detected'
            },
            'brute_force': {
                'threshold': 5,
                'time_window': 300,
                'description': 'Brute force attack detected'
            },
            'ddos': {
                'threshold': 100,
                'time_window': 60,
                'description': 'DDoS attack detected'
            },
            'suspicious_ports': {
                'ports': [23, 135, 139, 445, 1433, 3389],
                'description': 'Suspicious port access detected'
            }
        }
        
        self.detection_counters = defaultdict(lambda: defaultdict(int))
        self.last_reset = datetime.now()
    
    def analyze_packet(self, packet_info: Dict) -> List[Dict]:
        """Analyze packet for threats"""
        threats = []
        
        try:
            # Check for port scanning
            port_scan_threat = self._detect_port_scan(packet_info)
            if port_scan_threat:
                threats.append(port_scan_threat)
            
            # Check for brute force
            brute_force_threat = self._detect_brute_force(packet_info)
            if brute_force_threat:
                threats.append(brute_force_threat)
            
            # Check for suspicious ports
            suspicious_port_threat = self._detect_suspicious_ports(packet_info)
            if suspicious_port_threat:
                threats.append(suspicious_port_threat)
            
            # Check for DDoS
            ddos_threat = self._detect_ddos(packet_info)
            if ddos_threat:
                threats.append(ddos_threat)
            
        except Exception as e:
            logger.error(f"Error analyzing packet for threats: {e}")
        
        return threats
    
    def _detect_port_scan(self, packet_info: Dict) -> Optional[Dict]:
        """Detect port scanning attempts"""
        try:
            src_ip = packet_info.get('src_ip')
            dst_port = packet_info.get('dst_port')
            
            if not src_ip or not dst_port:
                return None
            
            # Reset counters every minute
            if (datetime.now() - self.last_reset).seconds >= 60:
                self.detection_counters.clear()
                self.last_reset = datetime.now()
            
            # Count unique ports accessed by source IP
            port_key = f"port_scan_{src_ip}"
            self.detection_counters[port_key][dst_port] += 1
            
            # Check threshold
            if len(self.detection_counters[port_key]) >= self.threat_patterns['port_scan']['threshold']:
                return {
                    'type': 'port_scan',
                    'severity': 'high',
                    'description': f'Port scanning detected from {src_ip}',
                    'source_ip': src_ip,
                    'ports_scanned': list(self.detection_counters[port_key].keys())
                }
            
        except Exception as e:
            logger.error(f"Error detecting port scan: {e}")
        
        return None
    
    def _detect_brute_force(self, packet_info: Dict) -> Optional[Dict]:
        """Detect brute force attacks"""
        try:
            src_ip = packet_info.get('src_ip')
            dst_ip = packet_info.get('dst_ip')
            dst_port = packet_info.get('dst_port')
            
            if not all([src_ip, dst_ip, dst_port]):
                return None
            
            # Check for SSH brute force (port 22)
            if dst_port == 22:
                brute_key = f"brute_force_{src_ip}_{dst_ip}_{dst_port}"
                self.detection_counters[brute_key]['attempts'] += 1
                
                if self.detection_counters[brute_key]['attempts'] >= self.threat_patterns['brute_force']['threshold']:
                    return {
                        'type': 'brute_force',
                        'severity': 'high',
                        'description': f'Brute force attack detected from {src_ip} to {dst_ip}:{dst_port}',
                        'source_ip': src_ip,
                        'target_ip': dst_ip,
                        'target_port': dst_port,
                        'attempts': self.detection_counters[brute_key]['attempts']
                    }
            
        except Exception as e:
            logger.error(f"Error detecting brute force: {e}")
        
        return None
    
    def _detect_suspicious_ports(self, packet_info: Dict) -> Optional[Dict]:
        """Detect access to suspicious ports"""
        try:
            dst_port = packet_info.get('dst_port')
            src_ip = packet_info.get('src_ip')
            
            if not dst_port or not src_ip:
                return None
            
            suspicious_ports = self.threat_patterns['suspicious_ports']['ports']
            
            if dst_port in suspicious_ports:
                return {
                    'type': 'suspicious_port_access',
                    'severity': 'medium',
                    'description': f'Suspicious port {dst_port} accessed from {src_ip}',
                    'source_ip': src_ip,
                    'suspicious_port': dst_port
                }
            
        except Exception as e:
            logger.error(f"Error detecting suspicious ports: {e}")
        
        return None
    
    def _detect_ddos(self, packet_info: Dict) -> Optional[Dict]:
        """Detect DDoS attacks"""
        try:
            dst_ip = packet_info.get('dst_ip')
            
            if not dst_ip:
                return None
            
            # Count packets to destination IP
            ddos_key = f"ddos_{dst_ip}"
            self.detection_counters[ddos_key]['packets'] += 1
            
            # Check threshold
            if self.detection_counters[ddos_key]['packets'] >= self.threat_patterns['ddos']['threshold']:
                return {
                    'type': 'ddos',
                    'severity': 'critical',
                    'description': f'Potential DDoS attack targeting {dst_ip}',
                    'target_ip': dst_ip,
                    'packet_count': self.detection_counters[ddos_key]['packets']
                }
            
        except Exception as e:
            logger.error(f"Error detecting DDoS: {e}")
        
        return None


class AnomalyDetector:
    """Detect anomalous network behavior"""
    
    def __init__(self):
        self.baseline_metrics = defaultdict(lambda: deque(maxlen=1000))
        self.anomaly_threshold = 2.5  # Z-score threshold
        
    def detect_anomalies(self, packet_info: Dict) -> List[Dict]:
        """Detect anomalies in network behavior"""
        anomalies = []
        
        try:
            # Check bandwidth anomalies
            bandwidth_anomaly = self._detect_bandwidth_anomaly(packet_info)
            if bandwidth_anomaly:
                anomalies.append(bandwidth_anomaly)
            
            # Check connection anomalies
            connection_anomaly = self._detect_connection_anomaly(packet_info)
            if connection_anomaly:
                anomalies.append(connection_anomaly)
            
        except Exception as e:
            logger.error(f"Error detecting anomalies: {e}")
        
        return anomalies
    
    def _detect_bandwidth_anomaly(self, packet_info: Dict) -> Optional[Dict]:
        """Detect bandwidth anomalies"""
        try:
            size = packet_info.get('size', 0)
            
            # Update baseline
            self.baseline_metrics['packet_size'].append(size)
            
            # Check for anomaly
            if len(self.baseline_metrics['packet_size']) >= 100:
                if self._is_anomalous(size, self.baseline_metrics['packet_size']):
                    return {
                        'type': 'bandwidth_anomaly',
                        'description': f'Unusual packet size detected: {size} bytes',
                        'packet_size': size,
                        'severity': 'low'
                    }
            
        except Exception as e:
            logger.error(f"Error detecting bandwidth anomaly: {e}")
        
        return None
    
    def _detect_connection_anomaly(self, packet_info: Dict) -> Optional[Dict]:
        """Detect connection anomalies"""
        try:
            src_ip = packet_info.get('src_ip')
            
            if not src_ip:
                return None
            
            # Update baseline
            self.baseline_metrics[f'connections_{src_ip}'].append(datetime.now())
            
            # Check for anomaly (too many connections)
            recent_connections = [
                conn for conn in self.baseline_metrics[f'connections_{src_ip}']
                if (datetime.now() - conn).seconds <= 60
            ]
            
            if len(recent_connections) > 50:  # Threshold for anomaly
                return {
                    'type': 'connection_anomaly',
                    'description': f'Unusual connection pattern from {src_ip}',
                    'source_ip': src_ip,
                    'connection_count': len(recent_connections),
                    'severity': 'medium'
                }
            
        except Exception as e:
            logger.error(f"Error detecting connection anomaly: {e}")
        
        return None
    
    def _is_anomalous(self, value: float, baseline: deque) -> bool:
        """Check if value is anomalous based on baseline"""
        try:
            if len(baseline) < 10:
                return False
            
            baseline_values = list(baseline)
            mean = sum(baseline_values) / len(baseline_values)
            variance = sum((x - mean) ** 2 for x in baseline_values) / len(baseline_values)
            std_dev = variance ** 0.5
            
            if std_dev == 0:
                return False
            
            z_score = abs(value - mean) / std_dev
            return z_score > self.anomaly_threshold
            
        except Exception as e:
            logger.error(f"Error checking anomaly: {e}")
            return False

import asyncio
import socket
import subprocess
import os
import platform
import logging
from datetime import datetime, timezone
from scapy.all import ARP, Ether, srp
import psutil
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from models import Device, Event
from config import settings
from services.abuseipdb_service import abuse_ipdb
from services.telegram_service import telegram_service

logger = logging.getLogger(__name__)

class ScannerService:
    """
    Service responsible for network device discovery and monitoring.
    Uses ARP scanning (Scapy) as primary method and integrates with
    the local database for device tracking.
    """
    def __init__(self):
        self.is_scanning = False
        self.last_status = "IDLE"
        self.last_error = None
        self.scan_count = 0
        self.local_ip = "0.0.0.0"

    def get_status(self):
        # Always re-check IP if it's 0.0.0.0
        if self.local_ip == "0.0.0.0":
            _, self.local_ip = self.get_active_interface()

        return {
            "is_scanning": self.is_scanning,
            "last_status": self.last_status,
            "last_error": self.last_error,
            "scan_count": self.scan_count,
            "local_ip": self.local_ip,
            "timestamp": datetime.utcnow().isoformat()
        }

    def get_active_interface(self):
        """
        Identifies the active network interface. 
        Strictly avoids APIPA (169.254) and loopback.
        """
        try:
            # 1. Try socket connect to find internet route
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(0.5)
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                s.close()
                if ip and not ip.startswith("169.254") and not ip.startswith("127."):
                    for iface, addrs in psutil.net_if_addrs().items():
                        for addr in addrs:
                            if addr.family == socket.AF_INET and addr.address == ip:
                                self.local_ip = ip
                                return iface, ip
            except: pass

            # 2. Iterate all interfaces and pick the best private one
            best_iface = None
            best_ip = None
            
            for iface, addrs in psutil.net_if_addrs().items():
                if any(x in iface.lower() for x in ["loopback", "localhost", "pseudo", "tunnel"]):
                    continue
                
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        ip = addr.address
                        if ip.startswith("127.") or ip.startswith("169.254"):
                            continue
                        
                        # Use first valid private IP found
                        if ip.startswith("192.") or ip.startswith("10.") or ip.startswith("172."):
                            self.local_ip = ip
                            return iface, ip
                        
                        # Fallback for any other non-APIPA IPv4
                        best_iface, best_ip = iface, ip
            
            if best_ip:
                self.local_ip = best_ip
                return best_iface, best_ip

            return None, "0.0.0.0"
        except Exception as e:
            logger.error(f"Interface detection failed: {e}")
            return None, "0.0.0.0"

    async def system_arp_scan(self, ip_range_prefix: str):
        """
        Windows discovery fallback.
        1. Ping sweep to populate ARP cache.
        2. Try 'Get-NetNeighbor' (PowerShell) - more reliable than 'arp -a'.
        3. Fallback to 'arp -a'.
        """
        self.last_status = "SCANNING_PINGS"
        logger.info(f"Ping sweep on {ip_range_prefix}.0/24")
        
        from concurrent.futures import ThreadPoolExecutor
        loop = asyncio.get_running_loop()

        def ping_sync(ip):
            subprocess.run(["ping", "-n", "1", "-w", "150", ip], 
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        with ThreadPoolExecutor(max_workers=50) as executor:
            tasks = [loop.run_in_executor(executor, ping_sync, f"{ip_range_prefix}.{i}") 
                    for i in range(1, 255)]
            await asyncio.gather(*tasks)
        
        self.last_status = "PARSING_CACHE"
        devices = []
        
        # Method A: Get-NetNeighbor (Modern Windows)
        try:
            cmd = ["powershell", "-Command", "Get-NetNeighbor -AddressFamily IPv4 | Where-Object { $_.State -ne 'Unreachable' } | Select-Object IPAddress, LinkLayerAddress | ConvertTo-Json"]
            output = subprocess.check_output(cmd).decode(errors='ignore')
            if output.strip():
                import json
                data = json.loads(output)
                if isinstance(data, dict): data = [data]
                for item in data:
                    ip = item.get("IPAddress")
                    mac = item.get("LinkLayerAddress")
                    if ip and mac and ip.startswith(ip_range_prefix) and ip != self.local_ip:
                        devices.append({"ip": ip, "mac": mac.replace('-', ':').upper(), "vendor": "Unknown"})
                if devices:
                    logger.info(f"Discovery found {len(devices)} nodes via Get-NetNeighbor")
                    return devices
        except: pass

        # Method B: Classic 'arp -a'
        try:
            output = subprocess.check_output(["arp", "-a"]).decode(errors='ignore')
            for line in output.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[0].startswith(ip_range_prefix):
                    ip = parts[0]
                    mac = parts[1].replace('-', ':').upper()
                    if len(mac) == 17 and ip != self.local_ip:
                        devices.append({"ip": ip, "mac": mac, "vendor": "Unknown"})
            logger.info(f"Discovery found {len(devices)} nodes via ARP cache")
            return devices
        except: return []

    def scapy_arp_scan(self, interface: str, ip_range: str):
        """Scapy scan if driver is present."""
        try:
            from scapy.all import conf, srp, Ether, ARP
            conf.iface = interface
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range), 
                         iface=interface, timeout=2, verbose=False, retry=1)
            
            devices = []
            for _, rcv in ans:
                devices.append({"ip": rcv.psrc, "mac": rcv.hwsrc.upper(), "vendor": "Unknown"})
            return devices
        except Exception:
            return None

    async def scan_ports(self, ip: str) -> list[int]:
        """Simple async port scanner for common services."""
        common_ports = [21, 22, 23, 80, 443, 445, 3389, 8000, 8080]
        open_ports = []
        for port in common_ports:
            try:
                # Use a low timeout for speed
                conn = asyncio.open_connection(ip, port)
                _, writer = await asyncio.wait_for(conn, timeout=0.1)
                open_ports.append(port)
                writer.close()
                await writer.wait_closed()
            except:
                continue
        return open_ports

    def lookup_vendor(self, mac: str) -> str:
        """Heuristic OUI lookup for common enterprise/home vendors."""
        prefix = mac.replace(':', '').upper()[:6]
        oui_table = {
            "00000C": "Cisco Systems",
            "000C29": "VMware",
            "001422": "Dell Inc.",
            "00163E": "XenSource",
            "00215A": "HP",
            "080027": "Oracle (VirtualBox)",
            "186024": "Ubiquiti",
            "B827EB": "Raspberry Pi",
            "DCA632": "Raspberry Pi",
            "FC1807": "Apple Inc.",
            "7081EB": "Apple Inc.",
            "D8CB8A": "Apple Inc.",
            "E4E4AB": "Apple Inc.",
            "30B5C2": "Apple Inc."
        }
        return oui_table.get(prefix, "Discovery Node")

    def calculate_risk(self, device: Device, open_ports: list[int]) -> float:
        """Basic risk scoring algorithm for NOC/SOC environments."""
        score = 0.0
        if not device.is_trusted:
            score += 40.0 # Base penalty for untrusted
        
        # Risk from open ports
        score += len(open_ports) * 10.0
        
        # High-risk services
        if 23 in open_ports: score += 30.0 # Telnet is death
        if 21 in open_ports: score += 15.0 # FTP is weak
        if 445 in open_ports: score += 20.0 # SMB exposure
        
        # Unknown identity penalty
        if device.vendor == "Discovery Node":
            score += 10.0
            
        return min(score, 100.0)

    async def run_scan(self, db: AsyncSession):
        if self.is_scanning:
            return
        
        self.is_scanning = True
        self.last_error = None
        self.last_status = "INIT"
        
        try:
            iface, my_ip = self.get_active_interface()
            if not my_ip or my_ip == "0.0.0.0":
                self.last_error = "NO_NETWORK"
                return

            ip_parts = my_ip.split('.')
            ip_prefix = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
            ip_range = f"{ip_prefix}.0/24"

            # 1. SCAN
            found_devices = None
            if iface:
                loop = asyncio.get_running_loop()
                found_devices = await loop.run_in_executor(None, self.scapy_arp_scan, iface, ip_range)
            
            if found_devices is None: # Scapy failed
                found_devices = await self.system_arp_scan(ip_prefix)

            # 2. TRACK STATUS CHANGES
            self.last_status = "SYNCING"
            
            # Get all current devices from DB
            result = await db.execute(select(Device))
            db_devices = {d.mac_address: d for d in result.scalars().all()}
            found_macs = {d["mac"] for d in found_devices}
            
            # A. Detect JOINED or RECONNECTED
            for dev_data in found_devices:
                mac = dev_data["mac"]
                if mac not in db_devices:
                    # Brand new device
                    device = Device(
                        ip_address=dev_data["ip"],
                        mac_address=mac,
                        vendor=self.lookup_vendor(mac),
                        is_online=True,
                        first_seen=datetime.now(timezone.utc),
                        last_seen=datetime.now(timezone.utc)
                    )
                    
                    # SOC Enrichment
                    import json
                    ports = await self.scan_ports(device.ip_address)
                    device.open_ports = json.dumps(ports)
                    device.risk_score = self.calculate_risk(device, ports)

                    db.add(device)
                    await db.commit()
                    await db.refresh(device)
                    
                    db.add(Event(
                        event_type="joined",
                        device_id=device.id,
                        description=f"New device joined: {device.ip_address} [{mac}]"
                    ))
                else:
                    device = db_devices[mac]
                    if not device.is_online:
                        # Reconnected
                        device.is_online = True
                        db.add(Event(
                            event_type="joined",
                            device_id=device.id,
                            description=f"Device reconnected: {device.ip_address} [{mac}]"
                        ))
                    
                    device.ip_address = dev_data["ip"]
                    device.last_seen = datetime.now(timezone.utc)
                    
                    # Refresh SOC Enrichment
                    import json
                    ports = await self.scan_ports(device.ip_address)
                    device.open_ports = json.dumps(ports)
                    device.vendor = self.lookup_vendor(mac)
                    device.risk_score = self.calculate_risk(device, ports)

            # B. Detect LEFT (Offline)
            for mac, device in db_devices.items():
                if mac not in found_macs and device.is_online:
                    # Device gone
                    device.is_online = False
                    db.add(Event(
                        event_type="left",
                        device_id=device.id,
                        description=f"Device left network: {device.ip_address} [{mac}]"
                    ))

            await db.commit()
            self.scan_count +=1
            self.last_status = "IDLE"
            
        except Exception as e:
            self.last_status = "ERROR"
            self.last_error = f"SCANNER_ERROR: {type(e).__name__} ({str(e)})"
            logger.error(f"Scanner fatal error: {self.last_error}", exc_info=True)
        finally:
            self.is_scanning = False

scanner_service = ScannerService()

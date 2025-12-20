import asyncio
import socket
import subprocess
import os
import platform
import logging
from datetime import datetime
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

    def get_active_interface(self):
        """
        Identifies the primary active network interface for scanning.
        Filters out loopback and virtual interfaces.
        
        Returns:
            tuple: (interface_name, ip_address, netmask) or (None, None, None)
        """
        try:
            interfaces = psutil.net_if_addrs()
            for iface, addrs in interfaces.items():
                if iface.lower().startswith(('lo', 'docker', 'veth')):
                    continue
                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                        return iface, addr.address, addr.netmask
            return None, None, None
        except Exception as e:
            logger.error(f"Error getting active interface: {e}")
            return None, None, None

    def arp_scan(self, interface: str, ip_range: str):
        """Perform ARP scan using Scapy."""
        try:
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range), 
                             iface=interface, timeout=2, verbose=False)
            devices = []
            for snd, rcv in ans:
                devices.append({
                    "ip": rcv.psrc,
                    "mac": rcv.hwsrc.upper(),
                    "vendor": "Unknown"
                })
            return devices
        except Exception as e:
            logger.error(f"ARP scan failed: {e}")
            return []

    async def run_scan(self, db: AsyncSession):
        if self.is_scanning:
            return
        
        self.is_scanning = True
        logger.info("Starting network scan...")
        
        iface, my_ip, netmask = self.get_active_interface()
        if not iface:
            logger.error("No active interface found for scanning")
            self.is_scanning = False
            return

        # Simple /24 range calculation for now
        ip_parts = my_ip.split('.')
        ip_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

        try:
            # Run ARP scan in a thread to avoid blocking event loop
            loop = asyncio.get_running_loop()
            found_devices = await loop.run_in_executor(None, self.arp_scan, iface, ip_range)
            
            for dev_data in found_devices:
                # Check if device exists
                result = await db.execute(select(Device).where(Device.mac_address == dev_data["mac"]))
                device = result.scalars().first()
                
                if not device:
                    # New device found!
                    device = Device(
                        ip_address=dev_data["ip"],
                        mac_address=dev_data["mac"],
                        vendor=dev_data["vendor"],
                        first_seen=datetime.utcnow(),
                        last_seen=datetime.utcnow()
                    )
                    db.add(device)
                    await db.commit()
                    await db.refresh(device)
                    
                    # Create event
                    event = Event(
                        event_type="new_device",
                        device_id=device.id,
                        description=f"New device discovered: {device.ip_address} ({device.mac_address})"
                    )
                    db.add(event)
                    
                    # Telegram alert for new device
                    await telegram_service.send_alert(f"New device detected: {device.ip_address} ({device.mac_address})")
                else:
                    # Update existing device
                    device.ip_address = dev_data["ip"]
                    device.last_seen = datetime.utcnow()
                    await db.commit()

            await db.commit()
            logger.info(f"Scan completed. Found {len(found_devices)} devices.")
            
        except Exception as e:
            logger.error(f"Error during scan: {e}")
        finally:
            self.is_scanning = False

scanner_service = ScannerService()

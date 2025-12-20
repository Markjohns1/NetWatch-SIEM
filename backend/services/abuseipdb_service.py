import httpx
from config import settings
import logging

logger = logging.getLogger(__name__)

class AbuseIPDBService:
    """
    Threat Intelligence service integrating with AbuseIPDB API.
    Provides external IP reputation checks for contextual enrichment.
    """
    def __init__(self):
        self.api_key = settings.ABUSEIPDB_API_KEY
        self.base_url = "https://api.abuseipdb.com/api/v2/check"

    async def check_ip(self, ip_address: str):
        """
        Checks a specific IP address against the AbuseIPDB data.
        
        Args:
            ip_address (str): The IP to investigate.
            
        Returns:
            dict: Reputation data including score and report count.
        """
        if not self.api_key:
            logger.warning("AbuseIPDB API key not configured")
            return None

        headers = {
            "Accept": "application/json",
            "Key": self.api_key
        }
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": "90"
        }

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(self.base_url, headers=headers, params=params)
                if response.status_code == 200:
                    return response.json()["data"]
                else:
                    logger.error(f"AbuseIPDB API error: {response.status_code} - {response.text}")
                    return None
        except Exception as e:
            logger.error(f"Error checking IP in AbuseIPDB: {e}")
            return None

abuse_ipdb = AbuseIPDBService()

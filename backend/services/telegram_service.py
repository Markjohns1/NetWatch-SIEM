import httpx
from config import settings
import logging

logger = logging.getLogger(__name__)

class TelegramService:
    """
    Integration service for the Telegram Bot API.
    Provides automated SOAR notifications for high-severity security events.
    """
    def __init__(self):
        self.bot_token = settings.TELEGRAM_BOT_TOKEN
        self.chat_id = settings.TELEGRAM_CHAT_ID
        self.api_url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage" if self.bot_token else None

    async def send_alert(self, message: str):
        """
        Sends an asynchronous alert message to the configured Telegram chat.
        
        Args:
            message (str): The formatted alert notification message.
        """
        if not self.bot_token or not self.chat_id:
            logger.warning("Telegram configuration missing")
            return False

        payload = {
            "chat_id": self.chat_id,
            "text": f"🚨 *NetWatch-SIEM Alert* 🚨\n\n{message}",
            "parse_mode": "Markdown"
        }

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(self.base_url, json=payload)
                return response.status_code == 200
        except Exception as e:
            logger.error(f"Error sending Telegram alert: {e}")
            return False

telegram_service = TelegramService()

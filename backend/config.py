from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    PROJECT_NAME: str = "NetWatch-SIEM"
    
    # Database Configuration
    # Example for SQLite: sqlite+aiosqlite:///./netwatch_new.db
    # Example for PostgreSQL: postgresql+asyncpg://user:pass@host:port/db
    DATABASE_URL: str = "sqlite+aiosqlite:///./netwatch_new.db"
    
    SECRET_KEY: str = "yoursecretkeyhere"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Telegram Configuration (SOAR-lite)
    TELEGRAM_BOT_TOKEN: Optional[str] = None
    TELEGRAM_CHAT_ID: Optional[str] = None
    
    # AbuseIPDB Configuration
    ABUSEIPDB_API_KEY: Optional[str] = None
    
    # Scan Configuration
    SCAN_INTERVAL: int = 60
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()

from sqlalchemy import String, Integer, DateTime, Boolean, Float
from sqlalchemy.orm import Mapped, mapped_column
from datetime import datetime
from database import Base

class Device(Base):
    __tablename__ = "devices"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    ip_address: Mapped[str] = mapped_column(String, index=True)
    mac_address: Mapped[str] = mapped_column(String, unique=True, index=True)
    hostname: Mapped[str] = mapped_column(String, nullable=True)
    vendor: Mapped[str] = mapped_column(String, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_trusted: Mapped[bool] = mapped_column(Boolean, default=False)
    is_online: Mapped[bool] = mapped_column(Boolean, default=True)
    open_ports: Mapped[str | None] = mapped_column(String, nullable=True) # Serialized JSON list
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    device_name: Mapped[str] = mapped_column(String, nullable=True)

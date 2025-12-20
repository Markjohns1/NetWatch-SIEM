from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List
from pydantic import BaseModel
from datetime import datetime

from database import get_db
from models import Device

router = APIRouter(prefix="/devices", tags=["devices"])

class DeviceSchema(BaseModel):
    id: int
    ip_address: str
    mac_address: str
    hostname: str | None
    vendor: str | None
    last_seen: datetime
    is_trusted: bool
    risk_score: float
    is_online: bool
    open_ports: str | None # Serialized JSON list

    class Config:
        from_attributes = True

@router.get("/", response_model=List[DeviceSchema])
async def get_devices(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Device).order_by(Device.last_seen.desc()))
    return result.scalars().all()

@router.get("/{device_id}", response_model=DeviceSchema)
async def get_device(device_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalars().first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device

@router.post("/{device_id}/trust")
async def toggle_trust(device_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalars().first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    device.is_trusted = not device.is_trusted
    await db.commit()
    return {"status": "success", "is_trusted": device.is_trusted}

class RenameRequest(BaseModel):
    name: str

@router.post("/{device_id}/rename")
async def rename_device(device_id: int, req: RenameRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalars().first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    device.device_name = req.name
    await db.commit()
    return {"status": "success", "device_name": device.device_name}

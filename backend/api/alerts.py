from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List
from pydantic import BaseModel
from datetime import datetime

from database import get_db
from models import Alert

router = APIRouter(prefix="/alerts", tags=["alerts"])

class AlertSchema(BaseModel):
    id: int
    timestamp: datetime
    rule_id: str
    severity: str
    message: str
    is_resolved: bool
    device_id: int | None

    class Config:
        from_attributes = True

@router.get("/", response_model=List[AlertSchema])
async def get_alerts(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).order_by(Alert.timestamp.desc()))
    return result.scalars().all()

@router.post("/{alert_id}/resolve")
async def resolve_alert(alert_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalars().first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.is_resolved = True
    await db.commit()
    return {"status": "success"}

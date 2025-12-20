from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List
from pydantic import BaseModel
from datetime import datetime

from database import get_db
from models import Alert, Event
from sqlalchemy import func
from services.scanner_service import scanner_service

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

class EventSchema(BaseModel):
    id: int
    timestamp: datetime
    event_type: str
    description: str
    device_id: int | None

    class Config:
        from_attributes = True

@router.get("/events", response_model=List[EventSchema])
async def get_events(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Event).order_by(Event.timestamp.desc()))
    return result.scalars().all()

@router.get("/", response_model=List[AlertSchema])
async def get_alerts(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).order_by(Alert.timestamp.desc()))
    return result.scalars().all()

@router.get("/stats")
async def get_stats(db: AsyncSession = Depends(get_db)):
    # Count total events (signals)
    event_count_query = await db.execute(select(func.count(Event.id)))
    total_events = event_count_query.scalar() or 0
    
    # Count active high/critical alerts
    active_alerts_query = await db.execute(
        select(func.count(Alert.id)).where(Alert.is_resolved == False)
    )
    active_count = active_alerts_query.scalar() or 0

    # Count resolved alerts (Operator Metrics)
    resolved_query = await db.execute(
        select(func.count(Alert.id)).where(Alert.is_resolved == True)
    )
    resolved_count = resolved_query.scalar() or 0
    
    return {
        "total_events": total_events,
        "active_critical": active_count,
        "total_resolved": resolved_count,
        "health_score": "STABLE" if active_count == 0 else "AT RISK",
        "operator_level": 10 if resolved_count > 5 else 5
    }

@router.post("/scan")
async def trigger_scan(db: AsyncSession = Depends(get_db)):
    """Manually trigger a network scan."""
    try:
        await scanner_service.run_scan(db)
        return {"message": "Scan completed"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/scan/status")
async def get_scan_status():
    return scanner_service.get_status()

@router.post("/{alert_id}/resolve")
async def resolve_alert(alert_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalars().first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.is_resolved = True
    await db.commit()
    return {"status": "success"}

from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
import asyncio
import json

from api.devices import router as devices_router
from api.alerts import router as alerts_router
from services.scanner_service import scanner_service
from services.alert_engine import alert_engine
from database import SessionLocal
from config import settings

app = FastAPI(title=settings.PROJECT_NAME)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(devices_router, prefix="/api")
app.include_router(alerts_router, prefix="/api")

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket): # Corrected name from library_connect
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)

manager = ConnectionManager()

async def background_scan_task():
    while True:
        try:
            async with SessionLocal() as db:
                await scanner_service.run_scan(db)
                await alert_engine.process_threats(db)
        except Exception as e:
            print(f"Background task error: {e}")
        await asyncio.sleep(settings.SCAN_INTERVAL)

@app.on_event("startup")
async def startup():
    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    # Start background task
    asyncio.create_task(background_scan_task())

@app.get("/")
async def root():
    return {"message": "NetWatch-SIEM API is running"}

@app.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Handle incoming WS messages if needed
    except WebSocketDisconnect:
        manager.disconnect(websocket)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

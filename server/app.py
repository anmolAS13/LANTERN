"""LANTERN central server.
Run from the repo root:  uvicorn server.app:app --reload
Interactive docs:        http://127.0.0.1:8000/docs
"""
import os
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import (Depends, FastAPI, Header, HTTPException, Query, Response,
                     WebSocket, WebSocketDisconnect)
from fastapi.middleware.cors import CORSMiddleware

from .db import Database
from .geo import GeoLookup, alert_ip
from .schemas import AlertIn, AlertOut


class Hub:
    """Keeps track of open dashboards and pushes new alerts to them."""
    def __init__(self):
        self.clients: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.clients.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.clients:
            self.clients.remove(ws)

    async def broadcast(self, data: dict):
        for ws in list(self.clients):
            try:
                await ws.send_json(data)
            except Exception:
                self.disconnect(ws)


def create_app(db_path: Optional[str] = None, geo=None) -> FastAPI:
    db = Database(db_path or os.environ.get("LANTERN_DB", "lantern.db"))
    api_key = os.environ.get("LANTERN_API_KEY")  # optional shared secret for sensors
    hub = Hub()
    geo = geo or GeoLookup()
    app = FastAPI(title="LANTERN server", version="0.2.0")
    app.add_middleware(CORSMiddleware, allow_origins=["*"],
                       allow_methods=["*"], allow_headers=["*"])  # dashboard dev

    def check_key(x_api_key: Optional[str] = Header(default=None)):
        if api_key and x_api_key != api_key:
            raise HTTPException(401, "Invalid or missing X-API-Key")

    @app.get("/health")
    def health():
        return {"status": "ok", "geoip": getattr(geo, "enabled", True)}

    @app.post("/alerts", response_model=AlertOut, status_code=201,
              dependencies=[Depends(check_key)])
    async def receive_alert(alert: AlertIn, response: Response):
        data = alert.model_dump(mode="json")
        data["id"] = data["id"] or uuid.uuid4().hex
        ts = alert.timestamp or datetime.now(timezone.utc)
        data["timestamp"] = ts.astimezone(timezone.utc).isoformat()
        ip = alert_ip(data)
        country = geo.lookup(ip) if ip else None
        saved, created = db.insert(data, country)
        if created:
            await hub.broadcast(saved)
        else:
            response.status_code = 200  # already had it (sensor retry)
        return saved

    @app.get("/alerts", response_model=List[AlertOut])
    def list_alerts(zone: Optional[str] = None, severity: Optional[str] = None,
                    attack: Optional[str] = None,
                    limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)):
        return db.list(zone and zone.lower(), severity and severity.lower(),
                       attack, limit, offset)

    @app.get("/alerts/{alert_id}", response_model=AlertOut)
    def get_alert(alert_id: str):
        row = db.get(alert_id)
        if not row:
            raise HTTPException(404, "Alert not found")
        return row

    @app.get("/stats")
    def stats():
        return db.stats()

    @app.websocket("/ws")
    async def ws_alerts(ws: WebSocket):
        await hub.connect(ws)
        try:
            while True:
                await ws.receive_text()  # keep connection open
        except WebSocketDisconnect:
            hub.disconnect(ws)

    return app


app = create_app()

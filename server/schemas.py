"""Alert shapes, matching the sensor's shared alert format (sensor/alert.py).

AlertIn  = what a sensor POSTs to us.
AlertOut = what we send back / push to the dashboard (same shape + country).
"""
from datetime import datetime, timezone
from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, Field, field_validator

Zone = Literal["inside", "inbound", "outbound"]
Severity = Literal["low", "medium", "high", "critical"]


class Endpoint(BaseModel):
    ip: Optional[str] = None
    mac: Optional[str] = None
    port: Optional[int] = None


class AlertIn(BaseModel):
    zone: Zone
    attack: str = Field(..., examples=["arp_spoofing"])
    severity: Severity
    reason: str = Field(..., examples=["Device 192.168.1.7 is pretending to be your router."])
    source: Endpoint
    target: Optional[Endpoint] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    timestamp: Optional[datetime] = None   # server fills in "now" if missing
    sensor: Optional[str] = None
    id: Optional[str] = None               # server makes one if missing

    @field_validator("zone", "severity", mode="before")
    @classmethod
    def _lower(cls, v):
        return v.strip().lower() if isinstance(v, str) else v

    @field_validator("timestamp")
    @classmethod
    def _utc(cls, v):
        if v is not None and v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v


class AlertOut(BaseModel):
    id: str
    zone: Zone
    attack: str
    severity: Severity
    reason: str
    source: Endpoint
    target: Optional[Endpoint] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str
    sensor: Optional[str] = None
    country: Optional[str] = None          # filled by GeoIP later

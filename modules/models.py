from typing import Optional
from sqlmodel import Field, SQLModel
from datetime import datetime

class Target(SQLModel, table=True):

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    url: str
    interval: int = Field(default=60)
    
    status: str = Field(default="Bekleniyor")
    ssl_days: Optional[int] = Field(default=None)
    open_ports: Optional[str] = Field(default=None)
    vulns: Optional[str] = Field(default=None)
    service_details: Optional[str] = Field(default=None)
    last_check: Optional[datetime] = Field(default=None)
    last_error: Optional[str] = Field(default=None)


class ScanHistory(SQLModel, table=True):

    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id")
    scanned_at: datetime = Field(default_factory=datetime.now)
    status: str
    open_ports: Optional[str] = Field(default=None)
    vulns: Optional[str] = Field(default=None)
    ssl_days: Optional[int] = Field(default=None)
    last_error: Optional[str] = Field(default=None)
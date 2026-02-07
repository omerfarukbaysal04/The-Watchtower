from typing import Optional
from sqlmodel import Field, SQLModel
from datetime import datetime

class Target(SQLModel, table=True): # Veritabanı tablosu 

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    url: str
    interval: int = Field(default=60)
    
    status: str = Field(default="Bekleniyor") # UP, DOWN
    ssl_days: Optional[int] = Field(default=None) # Ssl sertifika kalan gün sayısı
    open_ports: Optional[str] = Field(default=None) # açık portlar
    last_check: Optional[datetime] = Field(default=None) # Son kontrol zamanı
    last_error: Optional[str] = Field(default=None) # Son hata mesajı
    

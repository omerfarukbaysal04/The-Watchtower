from fastapi import FastAPI, Request, Depends, Form
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlmodel import Session, select
import os
import asyncio #
from modules.engine import run_scanner_loop 

from modules.database import create_db_and_tables, get_session
from modules.models import Target

app = FastAPI(title="The Watchtower", version="2.0")

templates = Jinja2Templates(directory="app/templates")


@app.on_event("startup")
async def on_startup(): 
    """Uygulama başlarken veritabanını kur ve motoru çalıştır"""
    create_db_and_tables()
    asyncio.create_task(run_scanner_loop())

@app.get("/", response_class=HTMLResponse)
async def read_dashboard(request: Request, db: Session = Depends(get_session)):

    # Veritabanından tüm hedefleri çek
    targets = db.exec(select(Target)).all()
    
    context = {
        "request": request,
        "app_name": "The Watchtower",
        "targets": targets 
    }
    return templates.TemplateResponse("dashboard.html", context)

@app.post("/add", response_class=HTMLResponse)
async def add_target(
    request: Request,
    name: str = Form(...),
    url: str = Form(...),
    db: Session = Depends(get_session)
):
    new_target = Target(name=name, url=url)
    db.add(new_target)
    db.commit()
    db.refresh(new_target)
    
    # İşlem bitince ana sayfaya yönlendir
    return RedirectResponse(url="/", status_code=303)
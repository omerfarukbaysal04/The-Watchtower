from fastapi import FastAPI, Request, Depends, Form
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlmodel import Session, select
from fastapi import Form
import os
import asyncio 
from modules.engine import run_scanner_loop 

from modules.database import create_db_and_tables, get_session, engine
from modules.models import Target

from modules.pdf_generator import create_target_report
from fastapi.responses import FileResponse


app = FastAPI(title="The Watchtower", version="2.0")

templates = Jinja2Templates(directory="app/templates")


@app.on_event("startup")
async def on_startup(): 
    """Uygulama başlarken veritabanını kur ve motoru çalıştır"""
    create_db_and_tables()
    asyncio.create_task(run_scanner_loop())

@app.get("/", response_class=HTMLResponse)
async def read_dashboard(request: Request, db: Session = Depends(get_session)):

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
    
    return RedirectResponse(url="/", status_code=303)

@app.post("/delete/{target_id}")
async def delete_target(target_id: int):
    with Session(engine) as db:
        target = db.get(Target, target_id)
        if target:
            db.delete(target)
            db.commit()
    return RedirectResponse(url="/", status_code=303)

@app.post("/update/{target_id}")
async def update_target(target_id: int, name: str = Form(...), url: str = Form(...)):
    with Session(engine) as db:
        target = db.get(Target, target_id)
        if target:
            target.name = name
            target.url = url
            target.status = "Güncellendi ⏳"
            db.add(target)
            db.commit()
    return RedirectResponse(url="/", status_code=303)

@app.get("/download_report/{target_id}")
async def download_report(target_id: int, db: Session = Depends(get_session)): 
    
    target = db.get(Target, target_id)
    
    if not target:
        return {"error": "Hedef bulunamadi!"}
        
    pdf_path = create_target_report(
        target_name=target.name,
        target_url=target.url,
        status=target.status,
        open_ports=target.open_ports,
        vulns_string=target.vulns
    )
    
    return FileResponse(path=pdf_path, filename=f"The_Watchtower_{target.name}_Raporu.pdf", media_type='application/pdf')
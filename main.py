from fastapi import FastAPI, Request, Depends, Form
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlmodel import Session, select
from fastapi import Form
from modules.engine import run_scanner_loop, process_single_target
import os
import asyncio 
from modules.engine import run_scanner_loop 

from modules.database import create_db_and_tables, get_session, engine
from modules.models import Target

from modules.pdf_generator import create_target_report
from fastapi.responses import FileResponse

from auth import (
    verify_password, create_session, get_current_user,
    login_required, SESSION_COOKIE, ADMIN_USERNAME, ADMIN_HASH
)


app = FastAPI(title="The Watchtower", version="2.0")

templates = Jinja2Templates(directory="app/templates")


@app.on_event("startup")
async def on_startup(): 
    create_db_and_tables()
    asyncio.create_task(run_scanner_loop())


# ── AUTH ROUTE'LARI ───────────────────────────────────────

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    # Zaten giriş yapmışsa direkt dashboard'a at
    if get_current_user(request):
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login", response_class=HTMLResponse)
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    if username == ADMIN_USERNAME and verify_password(password, ADMIN_HASH):
        token = create_session(username)
        response = RedirectResponse(url="/", status_code=302)
        response.set_cookie(
            key=SESSION_COOKIE,
            value=token,
            httponly=True,    # JS erişemez
            samesite="lax",   # CSRF koruması
            max_age=60 * 60 * 8
        )
        return response
    
    # Hatalı giriş
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": "Kullanıcı adı veya şifre hatalı."
    }, status_code=401)


@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie(SESSION_COOKIE)
    return response


# ── KORUNAN ROUTE'LAR ─────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
@login_required
async def read_dashboard(request: Request, db: Session = Depends(get_session)):
    targets = db.exec(select(Target)).all()
    context = {
        "request": request,
        "app_name": "The Watchtower",
        "targets": targets 
    }
    return templates.TemplateResponse("dashboard.html", context)


@app.post("/add", response_class=HTMLResponse)
@login_required
async def add_target(
    request: Request,
    name: str = Form(...),
    url: str = Form(...),
    interval: int = Form(60),
    db: Session = Depends(get_session)
):
    new_target = Target(name=name, url=url, interval=interval)
    db.add(new_target)
    db.commit()
    db.refresh(new_target)
    asyncio.create_task(process_single_target(new_target.id))
    return RedirectResponse(url="/", status_code=303)


@app.post("/delete/{target_id}")
@login_required
async def delete_target(request: Request, target_id: int):
    with Session(engine) as db:
        target = db.get(Target, target_id)
        if target:
            db.delete(target)
            db.commit()
    return RedirectResponse(url="/", status_code=303)


@app.post("/update/{target_id}")
@login_required
async def update_target(
    request: Request,
    target_id: int,
    name: str = Form(...),
    url: str = Form(...),
    interval: int = Form(...)
):
    with Session(engine) as db:
        target = db.get(Target, target_id)
        if target:
            target.name = name
            target.url = url
            target.interval = interval
            target.last_check = None  # ← bunu ekle
            target.status = "Bekleniyor"  # ← bunu da güncelle
            target.status = "Güncellendi ⏳"
            db.add(target)
            db.commit()
    asyncio.create_task(process_single_target(target_id))  # ← hemen tara
    return RedirectResponse(url="/", status_code=303)


@app.get("/download_report/{target_id}")
@login_required
async def download_report(request: Request, target_id: int, db: Session = Depends(get_session)): 
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
    return FileResponse(
        path=pdf_path,
        filename=f"The_Watchtower_{target.name}_Raporu.pdf",
        media_type='application/pdf'
    )

@app.post("/scan_now/{target_id}")
@login_required
async def scan_now(request: Request, target_id: int):
    with Session(engine) as db:
        target = db.get(Target, target_id)
        if target:
            target.last_check = None
            db.add(target)
            db.commit()
    asyncio.create_task(process_single_target(target_id))
    return RedirectResponse(url="/", status_code=303)

@app.get("/history/{target_id}", response_class=HTMLResponse)
@login_required
async def target_history(request: Request, target_id: int, db: Session = Depends(get_session)):
    from modules.models import ScanHistory
    
    target = db.get(Target, target_id)
    if not target:
        return RedirectResponse(url="/", status_code=302)
    
    history = db.exec(
        select(ScanHistory)
        .where(ScanHistory.target_id == target_id)
        .order_by(ScanHistory.scanned_at.desc())
    ).all()
    
    return templates.TemplateResponse("history.html", {
        "request": request,
        "target": target,
        "history": history,
        "app_name": "The Watchtower"
    })

@app.get("/download_report/history/{history_id}")
@login_required
async def download_history_report(request: Request, history_id: int, db: Session = Depends(get_session)):
    from modules.models import ScanHistory
    
    history = db.get(ScanHistory, history_id)
    if not history:
        return {"error": "Kayıt bulunamadı."}
    
    target = db.get(Target, history.target_id)
    
    pdf_path = create_target_report(
        target_name=target.name if target else "Bilinmiyor",
        target_url=target.url if target else "",
        status=history.status,
        open_ports=history.open_ports,
        vulns_string=history.vulns
    )
    
    tarih = history.scanned_at.strftime("%Y%m%d_%H%M")
    return FileResponse(
        path=pdf_path,
        filename=f"The_Watchtower_{target.name}_{tarih}.pdf",
        media_type='application/pdf'
    )

@app.get("/compare/{history_id}")
@login_required
async def compare_history(request: Request, history_id: int, db: Session = Depends(get_session)):
    from modules.models import ScanHistory
    from fastapi.responses import JSONResponse

    current = db.get(ScanHistory, history_id)
    if not current:
        return JSONResponse({"error": "Kayıt bulunamadı."})

    # Bir önceki taramayı bul
    previous = db.exec(
        select(ScanHistory)
        .where(ScanHistory.target_id == current.target_id)
        .where(ScanHistory.id < current.id)
        .order_by(ScanHistory.id.desc())
    ).first()

    if not previous:
        return JSONResponse({"error": "Karşılaştırılacak önceki tarama yok."})

    # Port karşılaştırması
    def parse_ports(port_str):
        if not port_str:
            return set()
        return set(p.strip() for p in port_str.split(",") if p.strip())

    current_ports  = parse_ports(current.open_ports)
    previous_ports = parse_ports(previous.open_ports)

    yeni_portlar    = list(current_ports - previous_ports)
    kapanan_portlar = list(previous_ports - current_ports)

    # CVE karşılaştırması
    def parse_cves(vuln_str):
        if not vuln_str:
            return set()
        cves = set()
        for item in vuln_str.split("|"):
            for word in item.split():
                if "CVE-" in word or "NGINX:CVE" in word:
                    cves.add(word.strip())
        return cves

    current_cves  = parse_cves(current.vulns)
    previous_cves = parse_cves(previous.vulns)

    yeni_cveler    = list(current_cves - previous_cves)
    kapanan_cveler = list(previous_cves - current_cves)

    # Durum değişimi
    durum_degisti = current.status != previous.status

    return JSONResponse({
        "current_date":  current.scanned_at.strftime("%d.%m.%Y %H:%M"),
        "previous_date": previous.scanned_at.strftime("%d.%m.%Y %H:%M"),
        "yeni_portlar":    yeni_portlar,
        "kapanan_portlar": kapanan_portlar,
        "yeni_cveler":     yeni_cveler,
        "kapanan_cveler":  kapanan_cveler,
        "durum_degisti":   durum_degisti,
        "onceki_durum":    previous.status,
        "yeni_durum":      current.status,
        "degisiklik_var":  bool(yeni_portlar or kapanan_portlar or yeni_cveler or kapanan_cveler or durum_degisti)
    })
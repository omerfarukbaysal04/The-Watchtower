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
    db: Session = Depends(get_session)
):
    new_target = Target(name=name, url=url)
    db.add(new_target)
    db.commit()
    db.refresh(new_target)
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
    url: str = Form(...)
):
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
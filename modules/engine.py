import asyncio
from datetime import datetime
from sqlmodel import Session, select
from modules.database import engine
from modules.scanner import check_website
from modules.recon_scanner import ReconScanner
from modules.models import Target
from urllib.parse import urlparse

scanner = ReconScanner()

def get_hostname(url):
    try:
        parsed = urlparse(url)
        return parsed.netloc if parsed.netloc else parsed.path
    except:
        return url

async def process_single_target(target_id):

    with Session(engine) as db:
        target = db.get(Target, target_id)
        if not target:
            return

        print(f"🔎 [TARAMA BAŞLADI] {target.name} ({target.url})")
        
        target.status = "Taranıyor... ⏳"
        db.add(target)
        db.commit()
        
        try:
            # 1. SSL ve Site Kontrolü 
            report = await asyncio.to_thread(check_website, target.url)
            
            if report["status"] == "UP":
                target.status = "Aktif 🟢"
                target.ssl_days = report.get("ssl_days")
                target.last_error = None
                
                # 2. Port Taraması (Sadece UP ise)
                hostname = get_hostname(target.url)
                
                # Top 100 Port Taraması (Hızlı Mod)
                scan_res = await asyncio.to_thread(scanner.scan_target, hostname)
                
                if isinstance(scan_res, list):
                    # Portları kaydet
                    ports_str = ", ".join([f"{item['port']}/{item['service']}" for item in scan_res])
                    target.open_ports = ports_str
                else:
                    target.last_error = str(scan_res)
            else:
                target.status = "Erişilemiyor 🔴"
                target.last_error = report.get("error")

        except Exception as e:
            target.status = "Hata 💥"
            target.last_error = str(e)
            
        # Sonuçları Kaydet
        target.last_check = datetime.now()
        db.add(target)
        db.commit()
        print(f"✅ [TARAMA BİTTİ] {target.name}")

async def run_scanner_loop():
    print("🚀 [MOTOR] Paralel Tarama Motoru Devrede!")
    
    while True:
        try:
            with Session(engine) as db:
                targets = db.exec(select(Target)).all()
                target_ids = [t.id for t in targets] # Sadece ID'leri alıyoruz
            
            if target_ids:
                # gather: "Hepsini ateşle ve hepsi bitene kadar bekle"
                await asyncio.gather(*(process_single_target(t_id) for t_id in target_ids))
            
            print("💤 [MOTOR] Tüm taramalar bitti, 10 saniye mola...")
            await asyncio.sleep(10)

        except Exception as e:
            print(f"💥 [GENEL MOTOR HATASI] {e}")
            await asyncio.sleep(5)
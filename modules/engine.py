# modules/engine.py
import asyncio
from datetime import datetime
from sqlmodel import Session, select
from modules.database import engine
from modules.scanner import check_website
from modules.recon_scanner import ReconScanner  
from modules.models import Target
from urllib.parse import urlparse



def get_hostname(url):
    try:
        parsed = urlparse(url)
        return parsed.netloc if parsed.netloc else parsed.path
    except:
        return url

async def process_single_target(target_id):
    """
    Tek bir hedefi tarayan izole fonksiyon.
    """
    with Session(engine) as db:
        target = db.get(Target, target_id)
        if not target:
            return

        print(f"🔎 [TARAMA BAŞLADI] {target.name}")
        
        target.status = "Taranıyor... ⏳"
        target.open_ports = None  # Eski portları sil
        target.ssl_days = None    # Eski SSL bilgisini sil
        target.last_error = None
        db.add(target)
        db.commit()
        
        # --- TARAMA AŞAMASI ---
        try:
            # 1. Her işçi için KENDİ scanner'ını oluştur (Race Condition önlemi)
            local_scanner = ReconScanner()

            # 2. Site Ayakta mı?
            report = await asyncio.to_thread(check_website, target.url)
            
            if report["status"] == "UP":
                target.status = "Aktif 🟢"
                target.ssl_days = report.get("ssl_days")
                
                # 3. Port Taraması (Sadece site UP ise)
                hostname = get_hostname(target.url)
                
                # Scanner'ı çalıştır
                scan_res = await asyncio.to_thread(local_scanner.scan_target, hostname)
                
                if isinstance(scan_res, list):
                    if scan_res:
                    
                        details_list = [f"{item['port']}/{item['service']}" for item in scan_res]
                        target.open_ports = ", ".join(details_list)
                        
                        
                        vuln_list = [f"p{item['port']}: {item['vuln']}" for item in scan_res if item['vuln']]
                        target.vulns = " | ".join(vuln_list) if vuln_list else None
                    else:
                        target.open_ports = "Açık Port Yok (Filtrelenmiş Olabilir)"
                else:
                    target.last_error = str(scan_res)

        except Exception as e:
            target.status = "Hata 💥"
            target.last_error = str(e)
            print(f"HATA DETAYI: {e}")
            
        # Sonuçları Kaydet
        target.last_check = datetime.now()
        db.add(target)
        db.commit()
        print(f"✅ [TARAMA BİTTİ] {target.name}")

async def run_scanner_loop():
    print("🚀 [MOTOR] Paralel Tarama Motoru (v2.0 Fix) Devrede!")
    
    while True:
        try:
            with Session(engine) as db:
                targets = db.exec(select(Target)).all()
                target_ids = [t.id for t in targets]
            
            if target_ids:
                # Tüm hedefleri aynı anda ateşle
                await asyncio.gather(*(process_single_target(t_id) for t_id in target_ids))
            
            print("💤 [MOTOR] Mola veriliyor (20 saniye)...")
            await asyncio.sleep(20) 

        except Exception as e:
            print(f"💥 [GENEL MOTOR HATASI] {e}")
            await asyncio.sleep(5)
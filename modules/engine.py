import asyncio
import os
from datetime import datetime
from sqlmodel import Session, select
from modules.database import engine
from modules.scanner import check_website
from modules.recon_scanner import ReconScanner  
from modules.models import Target
from urllib.parse import urlparse
from modules.reporter import send_telegram_alert
from modules.subdomain_scanner import SubdomainScanner


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
        target.open_ports = None  
        target.ssl_days = None    
        target.last_error = None
        db.add(target)
        db.commit()
        
        try:
            local_scanner = ReconScanner()

            report = await asyncio.to_thread(check_website, target.url)
            
            if report["status"] == "UP":
                target.ssl_days = report.get("ssl_days")
                
                hostname = get_hostname(target.url)
                
                scan_res = await asyncio.to_thread(local_scanner.scan_target, hostname)
                
                if isinstance(scan_res, list):
                    if scan_res:
                    
                        details_list = [f"{item['port']}/{item['service']}" for item in scan_res]
                        target.open_ports = ", ".join(details_list)
                        
                        vuln_list = []

                        for item in scan_res:
                            for s in item.get("scripts", []):
                                vuln_list.append(
                                    f"p{item['port']}:[{s['name']}]: {s['output']}"
                                )

                        target.vulns = " | ".join(vuln_list) if vuln_list else None

                        
                        if vuln_list:
                            target.vulns = " | ".join(vuln_list)
                            if "vulners" in target.vulns or "CVE-" in target.vulns:
                                
                                TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
                                CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
                                
                                if TELEGRAM_TOKEN and CHAT_ID:
                                    
                                    msg = f"<b>🚨 WATCHTOWER ALARMI!</b>\n\n" \
                                          f"🎯 <b>Hedef:</b> {target.name}\n" \
                                          f"🌐 <b>URL:</b> {target.url}\n" \
                                          f"⚠️ <b>Tehlike:</b> Kritik Zafiyet Tespit Edildi!\n\n" \
                                          f"🔍 <i>Detaylar panelde...</i>"
                                    
                                    send_telegram_alert(TELEGRAM_TOKEN, CHAT_ID, msg)
                                    print(f"📨 [BİLDİRİM] {target.name} için Telegram gönderildi.")
                                
                                else:
                                    print("⚠️ [UYARI] .env dosyasında Telegram bilgileri eksik, bildirim atlanıyor.")
                        else:
                            target.vulns = None
                    else:
                        target.open_ports = "Açık Port Yok (Filtrelenmiş Olabilir)"
                else:
                    target.last_error = str(scan_res)

        # Subdomain Keşfi
            subdomain_scanner = SubdomainScanner(target.url)
            subdomain_result = await asyncio.to_thread(subdomain_scanner.run)       
            if subdomain_result:

                if target.vulns:
                        target.vulns = target.vulns + " | " + subdomain_result
                else:
                        target.vulns = subdomain_result

        except Exception as e:
            target.status = "Hata 💥"
            target.last_error = str(e)
            print(f"HATA DETAYI: {e}")
            
        if target.last_error is None:
            target.status = "Aktif 🟢"

        # Sonuçları Kaydet
        target.last_check = datetime.now()
        db.add(target)
        db.commit()
        print(f"✅ [TARAMA BİTTİ] {target.name}")

async def run_scanner_loop():
    print("🚀 [MOTOR] Scheduled Tarama Motoru Devrede!")
    
    while True:
        try:
            with Session(engine) as db:
                targets = db.exec(select(Target)).all()
            
            now = datetime.now()
            taranacaklar = []

            for target in targets:
                # Hiç taranmamışsa hemen tara
                if target.last_check is None:
                    taranacaklar.append(target.id)
                    continue
                
                # interval süresi geçmişse tara (dakika cinsinden)
                gecen_dakika = (now - target.last_check).total_seconds() / 60
                if gecen_dakika >= target.interval:
                    taranacaklar.append(target.id)

            if taranacaklar:
                print(f"🎯 [MOTOR] {len(taranacaklar)} hedef taranacak.")
                await asyncio.gather(*(process_single_target(t_id) for t_id in taranacaklar))
            else:
                print("💤 [MOTOR] Taranacak hedef yok.")

        except Exception as e:
            print(f"💥 [GENEL MOTOR HATASI] {e}")

        await asyncio.sleep(60)  # Her dakika kontrol et
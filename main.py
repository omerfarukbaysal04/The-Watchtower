import yaml
import time
from urllib.parse import urlparse  # URL'den hostname ayıklamak için
from modules.scanner import check_website
from modules.reporter import send_discord_alert
from modules.recon_scanner import ReconScanner 

def load_config():
    with open("config.yaml", "r") as file:
        return yaml.safe_load(file)

def get_hostname(url):
    """ 'https://ornek.com/api' adresinden 'ornek.com' kısmını ayıklar. """
    parsed_uri = urlparse(url)
    return parsed_uri.netloc if parsed_uri.netloc else parsed_uri.path

def start_watchtower():
    print("--- The Watchtower Başlatıldı ---")
    config = load_config()
    targets = config["targets"]
    webhook_url = config["notifications"]["discord_webhook"]
    scan_interval = config["settings"]["scan_interval"]
    
    scanner = ReconScanner()

    if config["notifications"]["enable_alert"]:
        send_discord_alert(webhook_url, "🏁 **The Watchtower** göreve başladı! Aktif tarama modülleri devrede...")

    print(f"Hedef Sayısı: {len(targets)}")
    print(f"Tarama Aralığı: {scan_interval} saniye\n")

    while True:
        print(f"🔄 Tarama Başlıyor: {time.strftime('%H:%M:%S')}")
        
        for target in targets:
            report = check_website(target['url'], config['settings']['request_timeout'])
            message_to_send = None 
            port_scan_results_str = ""

            if report["status"] == "UP":
                ssl_msg = ""
                if report.get("ssl_days") is not None:
                    days = report["ssl_days"]
                    if days < 15:
                        ssl_msg = f" | ⚠️ SSL KRİTİK: {days} gün"
                        message_to_send = f"⚠️ **UYARI:** {target['name']} SSL sertifikası bitmek üzere! ({days} gün kaldı)"
                    else:
                        ssl_msg = f" | 🔒 SSL: {days} gün"
                
                print(f"   ✅ [UP] {target['name']} {ssl_msg}")

                if target.get("port_scan", False): 
                    print(f"      🔎 [RECON] {target['name']} portları taranıyor...")
                    hostname = get_hostname(target['url'])
                    
                    p_range = target.get("port_range", "20-100") 
                    scan_res = scanner.scan_target(hostname, p_range)

                    if isinstance(scan_res, list) and scan_res:
                        port_scan_results_str = "\n**🔍 Açık Portlar:**\n"
                        
                        print(f"      🔓 [SONUÇ] {len(scan_res)} port açık bulundu:")
                        for item in scan_res:
                            print(f"         ➡️ Port: {item['port']} | Servis: {item['service']} | Versiyon: {item['version']}")
                            
                            port_scan_results_str += f"`• {item['port']}/{item['service']} - {item['version']}`\n"
                            
                    elif isinstance(scan_res, str) and "ERROR" in scan_res:
                         print(f"      ❌ [RECON ERROR] {scan_res}")


                if config["notifications"].get("notify_on_success") and not message_to_send:
                    message_to_send = f"✅ **UP:** {target['name']} çalışıyor."
                
                if message_to_send and port_scan_results_str:
                    message_to_send += port_scan_results_str

            else:
                error_msg = report.get('error', 'Bilinmeyen Hata')
                print(f"   ❌ [DOWN] {target['name']} - Hata: {error_msg}")
                message_to_send = f"🚨 **ALARM:** {target['name']} erişilemiyor! \nHata: {error_msg}"

            if message_to_send:
                send_discord_alert(webhook_url, message_to_send)

        print(f"💤 Nöbetçi uyuyor... ({scan_interval} saniye bekleyecek)\n")
        
        time.sleep(scan_interval)

if __name__ == "__main__":
    try:
        start_watchtower()
    except KeyboardInterrupt:
        print("\n🛑 Watchtower kullanıcı tarafından durduruldu.")
    except Exception as e:
        print(f"\n💥 KRİTİK HATA: {e}")
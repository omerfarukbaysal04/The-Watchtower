import yaml
import time
from modules.scanner import check_website
from modules.reporter import send_discord_alert

def load_config():
    with open("config.yaml", "r") as file:
        return yaml.safe_load(file)

def start_watchtower():
    print("--- The Watchtower Başlatıldı ---")
    
    config = load_config()
    targets = config["targets"]
    webhook_url = config["notifications"]["discord_webhook"]
    scan_interval = config["settings"]["scan_interval"] 

    if config["notifications"]["enable_alert"]:
        send_discord_alert(webhook_url, "🏁 **The Watchtower** göreve başladı! Nöbet başlıyor...")

    print(f"Hedef Sayısı: {len(targets)}")
    print(f"Tarama Aralığı: {scan_interval} saniye\n")

    while True:
        print(f"🔄 Tarama Başlıyor: {time.strftime('%H:%M:%S')}")
        
        for target in targets:
            
            report = check_website(target['url'], config['settings']['request_timeout'])
            message_to_send = None 

            if report["status"] == "UP":
                ssl_msg = ""
                if report.get("ssl_days") is not None:
                    days = report["ssl_days"]
                    if days < 15:
                        ssl_msg = f" | ⚠️ SSL KRİTİK: {days} gün kaldı!"
                        message_to_send = f"⚠️ **UYARI:** {target['name']} SSL sertifikası bitmek üzere! ({days} gün kaldı)"
                    else:
                        ssl_msg = f" | 🔒 SSL: {days} gün"
                
                print(f"   ✅ [UP] {target['name']} {ssl_msg}")

                if config["notifications"].get("notify_on_success") and not message_to_send:
                    message_to_send = f"✅ **UP:** {target['name']} çalışıyor."

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
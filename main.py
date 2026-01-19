import time
import yaml
from modules.scanner import check_website  # Yeni modülümüzü çağırdık

def load_config():
    with open("config.yaml", "r") as file:
        return yaml.safe_load(file)

def start_watchtower():
    print("--- The Watchtower Başlatıldı ---")
    config = load_config()
    targets = config["targets"]
    
    print(f"Hedef Sayısı: {len(targets)}")
    
    # Tüm hedefleri gez
    for target in targets:
        print(f"\nKontrol ediliyor: {target['name']} ({target['url']})...")
        
        # Tarayıcı modülünü kullan
        report = check_website(target['url'], config['settings']['request_timeout'])
        
        # Sonucu ekrana bas
        if report["status"] == "UP":
            print(f"✅ [UP] {report['url']} - Kod: {report['code']} - Gecikme: {report['latency']}sn")
        else:
            print(f"❌ [DOWN] {report['url']} - Hata: {report.get('error', 'Bilinmeyen Hata')}")

if __name__ == "__main__":
    start_watchtower()
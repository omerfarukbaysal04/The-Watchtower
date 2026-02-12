import requests

def send_telegram_alert(token, chat_id, message):
    """
    Telegram Bot API kullanarak mesaj gönderir.
    
    Args:
        token (str): BotFather'dan alınan API Token
        chat_id (str): Mesajın gideceği Kullanıcı veya Grup ID'si
        message (str): Gönderilecek mesaj içeriği (HTML destekli)
    """

    # Eğer token veya chat_id yoksa hiç uğraşma
    if not token or not chat_id or token == "TOKEN_YOK":
        print("⚠️ [UYARI] Telegram Token veya Chat ID eksik, bildirim gönderilemedi.")
        return False

    url = f"https://api.telegram.org/bot{token}/sendMessage"

    data = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "HTML",  # Kalın/İtalik yazı desteği için
        "disable_web_page_preview": True # Link önizlemelerini kapat (daha temiz görünür)
    }

    try:
        response = requests.post(url, data=data, timeout=10)

        if response.status_code == 200:
            return True
        else:
            print(f"❌ [TELEGRAM HATASI] {response.status_code} - {response.text}")
            return False

    except Exception as e:
        print(f"❌ [BAĞLANTI HATASI] Telegram'a ulaşılamadı: {str(e)}")
        return False
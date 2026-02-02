import requests
import json

def send_discord_alert(webhook_url, message):

    if not webhook_url or webhook_url == "URL_YOK":
        return False

    data = {
        "content": message,
        "username": "The Watchtower",
        "avatar_url": "https://cdn-icons-png.flaticon.com/512/993/993361.png" 
    }

    try:
        response = requests.post(
            webhook_url, 
            data=json.dumps(data),
            headers={"Content-Type": "application/json"},
            timeout=10 
        )
        
        if response.status_code == 204:
            return True
        else:
            print(f"Discord Hatası: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        print(f"Webhook Gönderim Hatası: {str(e)}")
        return False
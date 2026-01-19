import requests
import time

def check_website(url, timeout=5):
    start_time = time.time()
    result = {
        "url": url,
        "status": "DOWN", 
        "code": None,
        "latency": 0
    }

    try:
        response = requests.get(url, timeout=timeout)
        latency = round((time.time() - start_time), 3)
        
        result["status"] = "UP" if response.status_code == 200 else "ERROR"
        result["code"] = response.status_code
        result["latency"] = latency
        
    except requests.exceptions.Timeout:
        result["error"] = "Zaman Aşımı"
    except requests.exceptions.ConnectionError:
        result["error"] = "Bağlantı Hatası"
    except Exception as e:
        result["error"] = str(e)

    return result
import requests
import time
import ssl
import socket

def check_website(url, timeout=5):
    start_time = time.time()
    result = {
        "url": url,
        "status": "DOWN", 
        "code": None,
        "latency": 0
    }
    if url.startswith("https://"):
        days = get_ssl_days_left(url) 
        result["ssl_days"] = days     

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

def get_ssl_days_left(url):
    try :
        hostname = url.replace("https://", "").replace("http://", "").split('/')[0]
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expiry_date = ssl.cert_time_to_seconds(cert['notAfter'])
                days_left = (expiry_date - time.time()) / 86400 #86400 seconds = 1 day
                return int(days_left)
    except:
        return None
import nmap

class ReconScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan_target(self, target_ip):        
        try:
            # -Pn: Ping atma
            # -sT: Connect Scan (Docker için daha stabil)
            arguments = '-sV -sT -T4 -Pn --top-ports 100 --max-retries 1 --version-light'
            self.nm.scan(target_ip, arguments=arguments)
            
            hosts = self.nm.all_hosts()
            
            if not hosts:
                return "[UYARI] Nmap hiçbir host bulamadı (DNS veya Ağ sorunu olabilir)."

            actual_ip = hosts[0]
            
            scan_results = []
            
            if actual_ip in self.nm.all_hosts():
                for proto in self.nm[actual_ip].all_protocols():
                    ports = self.nm[actual_ip][proto].keys()
                    
                    for port in sorted(ports):
                        data = self.nm[actual_ip][proto][port]
                        
                        info = {
                            "port": port,
                            "state": data['state'],
                            "service": data['name'],
                            "version": f"{data.get('product', '')} {data.get('version', '')}".strip()
                        }
                        scan_results.append(info)
                    
            return scan_results

        except Exception as e:
            return f"[ERROR] Tarama hatası: {str(e)}"

if __name__ == "__main__":
    scanner = ReconScanner()
    sonuc = scanner.scan_target("scanme.nmap.org", "20-80") 
    print(sonuc)
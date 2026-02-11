import nmap

class ReconScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan_target(self, target_ip):
        print(f"🕵️ [NMAP] {target_ip} üzerinde detaylı tarama başlatılıyor...")
        
        try:
            # -sV: Versiyon Taraması (Servis adını öğrenmek için şart)
            # --script=default: Nmap'in varsayılan güvenli scriptlerini çalıştır (HTTP başlıkları, DNS vb.)
            # --script-timeout=10s: Bir script takılırsa 10 saniye sonra öldür (Hız için)
            target_ports = "21,22,23,53,80,443,3306,5432,6379,8080,8443,3389"
            
            # 21: FTP (Dosya Transfer)
            # 22: SSH (Linux Yönetim - Çok Kritik!)
            # 23: Telnet (Eski Güvensiz Yönetim)
            # 53: DNS
            # 80, 443: Web
            # 3306: MySQL (Veritabanı)
            # 5432: PostgreSQL (Veritabanı)
            # 6379: Redis (Önbellek)
            # 8080, 8443: Alternatif Web Portları (Admin panelleri genelde buradadır)
            # 3389: RDP (Windows Uzak Masaüstü)

            arguments = f'-sV -sS -T4 -Pn -p {target_ports} --script=vulners,default --script-args mincvss=5.0 --script-timeout=30s'
            
            self.nm.scan(target_ip, arguments=arguments)
            
            hosts = self.nm.all_hosts()
            if not hosts:
                return "[UYARI] Host yanıt vermedi."

            actual_ip = hosts[0]
            scan_results = []
            
            if actual_ip in self.nm.all_hosts():
                for proto in self.nm[actual_ip].all_protocols():
                    ports = self.nm[actual_ip][proto].keys()
                    
                    for port in sorted(ports):
                        data = self.nm[actual_ip][proto][port]
                        
                        product = data.get('product', '')
                        version = data.get('version', '')
                        extrainfo = data.get('extrainfo', '')
                        service_name = data.get('name', 'Bilinmiyor')
                        
                        full_service_name = f"{product} {version} {extrainfo}".strip()
                        
                       
                        if port not in [80, 443, 8080, 8443] and not product:
                            print(f"   🗑️ [FİLTRELENDİ] Port {port} ({service_name}) - Versiyon bilgisi yok (Yalan Port).")
                            continue

                        if not full_service_name:
                            full_service_name = service_name

                        script_output = ""
                        if 'script' in data:
                            for script_name, output in data['script'].items():
                                script_output += f"[{script_name}]: {output[:50]}... "

                        info = {
                            "port": port,
                            "service": full_service_name,
                            "vuln": script_output
                        }
                        scan_results.append(info)
                        print(f"   🔓 {port}: {full_service_name} | {script_output}")
            
            return scan_results

        except Exception as e:
            return f"[ERROR] {str(e)}"
import dns.resolver
from urllib.parse import urlparse

class DNSSecurityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.domain = self._extract_domain(target_url)

    def _extract_domain(self, url):
        # http://www.google.com -> google.com dönüştürmesi yapar
        if not url.startswith('http'):
            url = 'http://' + url
        domain = urlparse(url).hostname
        
        # SPF ve DMARC genelde root domain (www olmadan) kontrol edilir
        if domain and domain.startswith('www.'):
            domain = domain[4:]
        return domain

    def check_spf(self):
        try:
            # Domainin TXT kayıtlarını sorgula
            answers = dns.resolver.resolve(self.domain, 'TXT')
            for rdata in answers:
                txt_record = rdata.to_text().strip('"')
                if txt_record.startswith('v=spf1'):
                    return f"[spf]: BAŞARILI - {txt_record}"
            return "[spf]: EKSİK - Bu alan adı adına sahte e-posta gönderilebilir (Spoofing Riski)!"
        except Exception:
            return "[spf]: EKSİK - SPF kaydı bulunamadı veya DNS yanıt vermedi."

    def check_dmarc(self):
        try:
            # DMARC kayıtları _dmarc.domain.com adresinde tutulur
            dmarc_domain = f"_dmarc.{self.domain}"
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            for rdata in answers:
                txt_record = rdata.to_text().strip('"')
                if txt_record.startswith('v=DMARC1'):
                    return f"[dmarc]: BAŞARILI - {txt_record}"
            return "[dmarc]: EKSİK - DMARC politikası yapılandırılmamış!"
        except Exception:
            return "[dmarc]: EKSİK - DMARC kaydı bulunamadı."

    def run(self):
        """Modülü çalıştırır ve HTML'e uygun formatta string döner"""
        if not self.domain:
            return ""
            
        spf_result = self.check_spf()
        dmarc_result = self.check_dmarc()
        
        return f"{spf_result}<br><br>{dmarc_result}" #spf ve dmarc sonuçlarını alt alta gösterecek şekilde ekle

import requests
import dns.resolver
from urllib.parse import urlparse


import requests
import dns.resolver
from urllib.parse import urlparse


class SubdomainScanner:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.domain = self._extract_domain(target_url)

    def _extract_domain(self, url: str) -> str:
        if not url.startswith('http'):
            url = 'http://' + url
        hostname = urlparse(url).hostname or ""
        if hostname.startswith('www.'):
            hostname = hostname[4:]
        return hostname

    def _fetch_from_crtsh(self) -> list:
        """crt.sh sertifika loglarından subdomain çeker."""
        for attempt in range(3):
            try:
                resp = requests.get(
                    f"https://crt.sh/?q=%.{self.domain}&output=json",
                    timeout=20
                )
                if resp.status_code != 200:
                    return []

                data = resp.json()
                subdomains = set()

                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub and not sub.startswith("*") and sub != self.domain:
                            subdomains.add(sub)

                return sorted(subdomains)

            except requests.Timeout:
                print(f"[SUBDOMAIN] crt.sh timeout, deneme {attempt + 1}/3")
                continue
            except Exception as e:
                print(f"[SUBDOMAIN] crt.sh hatası: {e}")
                return []

        print("[SUBDOMAIN] crt.sh 3 denemede de yanıt vermedi, atlanıyor.")
        return []

    def _check_alive(self, subdomain: str) -> bool:
        """Subdomainin gerçekten aktif olup olmadığını DNS ile kontrol eder."""
        try:
            dns.resolver.resolve(subdomain, 'A', lifetime=3)
            return True
        except Exception:
            return False

    def run(self) -> str:
        """Tarama yapar ve pipeline formatında string döner."""
        print(f"[SUBDOMAIN DEBUG] domain: {self.domain}")
        if not self.domain:
            return ""

        print(f"[SUBDOMAIN] {self.domain} için crt.sh sorgulanıyor...")
        subdomains = self._fetch_from_crtsh()

        if not subdomains:
            return "[subdomain]: Subdomain bulunamadı."

        alive = [s for s in subdomains if self._check_alive(s)]

        if not alive:
            return "[subdomain]: Subdomain bulundu ama aktif olan yok."

        result = ", ".join(alive)
        print(f"[SUBDOMAIN] {len(alive)} aktif subdomain bulundu.")
        return f"[subdomain]: {len(alive)} aktif subdomain bulundu: {result}"


# Test
if __name__ == "__main__":
    scanner = SubdomainScanner("https://www.google.com")
    print(scanner.run())
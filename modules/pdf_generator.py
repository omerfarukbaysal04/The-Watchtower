from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
import string

# ─────────────────────────────────────────────
# RENK PALETİ  (dashboard ile uyumlu)
# ─────────────────────────────────────────────
C_BG        = colors.HexColor("#0d1117")
C_CARD      = colors.HexColor("#161b22")
C_BORDER    = colors.HexColor("#30363d")
C_BLUE      = colors.HexColor("#58a6ff")
C_RED       = colors.HexColor("#dc3545")
C_ORANGE    = colors.HexColor("#e6a817")
C_GREEN     = colors.HexColor("#3fb950")
C_PURPLE    = colors.HexColor("#bc8cff")
C_TEXT      = colors.HexColor("#c9d1d9")
C_MUTED     = colors.HexColor("#8b949e")
C_WHITE     = colors.white


# ─────────────────────────────────────────────
# YARDIMCI: Türkçe karakter + emoji temizleyici
# ─────────────────────────────────────────────
def temizle(metin: str) -> str:
    if not metin:
        return ""
    tr = {'ı':'i','ğ':'g','ü':'u','ş':'s','ö':'o','ç':'c',
          'İ':'I','Ğ':'G','Ü':'U','Ş':'S','Ö':'O','Ç':'C'}
    for k, v in tr.items():
        metin = metin.replace(k, v)
    izin = set(string.printable)
    return "".join(c for c in metin if c in izin).strip()


# ─────────────────────────────────────────────
# CVE SATIRI AYRIŞTIRICI
# Girdi: "NGINX:CVE-2026-1642\t8.2\thttps://..."
# Çıktı: (cve_id, cvss_score, url, exploit_bool)
# ─────────────────────────────────────────────
def parse_cve_line(line: str):
    line = temizle(line)
    exploit = "*EXPLOIT*" in line
    line = line.replace("*EXPLOIT*", "").strip()
    parts = line.split()
    if len(parts) >= 2:
        cve_id = parts[0]
        try:
            score = float(parts[1])
        except ValueError:
            score = 0.0
        url = parts[2] if len(parts) > 2 else ""
        return cve_id, score, url, exploit
    return line, 0.0, "", exploit


def cvss_renk(score: float):
    if score >= 9.0: return colors.HexColor("#ff4444")
    if score >= 7.0: return C_RED
    if score >= 4.0: return C_ORANGE
    return C_GREEN


# ─────────────────────────────────────────────
# ANA RAPOR OLUŞTURUCU
# ─────────────────────────────────────────────
def create_target_report(target_name, target_url, status,
                         open_ports, vulns_string,
                         output_path=None):

    safe_name   = temizle(target_name)
    safe_url    = temizle(target_url)
    safe_status = temizle(status)
    tarih_str   = datetime.now().strftime("%d.%m.%Y %H:%M")

    if output_path is None:
        dosya_adi = f"rapor_{safe_name.replace(' ', '_').lower()}.pdf"
        output_path = f"/tmp/{dosya_adi}"

    # ── SAYFA YAPISI ──────────────────────────
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=15*mm,  rightMargin=15*mm,
        topMargin=10*mm,   bottomMargin=15*mm,
    )
    W = A4[0] - 30*mm   # kullanılabilir genişlik
    story = []

    # ── STİLLER ───────────────────────────────
    def stil(name, **kw):
        base = dict(fontName="Helvetica", fontSize=10,
                    textColor=C_TEXT, leading=14,
                    backColor=None, spaceAfter=0)
        base.update(kw)
        return ParagraphStyle(name, **base)

    S_TITLE   = stil("title",  fontName="Helvetica-Bold", fontSize=22,
                     textColor=C_BLUE, alignment=TA_CENTER, spaceAfter=4)
    S_SUBTITLE= stil("sub",    fontSize=9, textColor=C_MUTED, alignment=TA_CENTER)
    S_SECTION = stil("sec",    fontName="Helvetica-Bold", fontSize=12,
                     textColor=C_WHITE, spaceAfter=6, spaceBefore=4)
    S_BODY    = stil("body",   fontSize=9, textColor=C_TEXT, leading=13)
    S_SMALL   = stil("small",  fontSize=8, textColor=C_MUTED, leading=11)
    S_MONO    = stil("mono",   fontName="Courier", fontSize=8,
                     textColor=C_TEXT, leading=12)
    S_RISK    = stil("risk",   fontName="Helvetica-Bold", fontSize=10,
                     textColor=C_RED, alignment=TA_CENTER)

    def hr(color=C_BORDER, thickness=0.5):
        return HRFlowable(width="100%", thickness=thickness,
                          color=color, spaceAfter=4, spaceBefore=4)

    def section_header(icon, baslik, color=C_BLUE):
        data = [[Paragraph(f'<font color="{color.hexval()}">'
                           f'<b>{icon}  {baslik}</b></font>', S_SECTION)]]
        t = Table(data, colWidths=[W])
        t.setStyle(TableStyle([
            ("BACKGROUND",  (0,0), (-1,-1), C_CARD),
            ("LEFTPADDING",  (0,0), (-1,-1), 8),
            ("RIGHTPADDING", (0,0), (-1,-1), 8),
            ("TOPPADDING",   (0,0), (-1,-1), 6),
            ("BOTTOMPADDING",(0,0), (-1,-1), 6),
            ("LINEBELOW",    (0,0), (-1,-1), 1.5, color),
        ]))
        return t

    # ─────────────────────────────────────────
    # KAPAK / BAŞLIK
    # ─────────────────────────────────────────
    story.append(Spacer(1, 6*mm))

    # Logo kutusu
    logo_data = [[
        Paragraph('<b>THE WATCHTOWER</b>', stil("logo",
            fontName="Helvetica-Bold", fontSize=26,
            textColor=C_BLUE, alignment=TA_CENTER)),
    ]]
    logo_t = Table(logo_data, colWidths=[W])
    logo_t.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), C_CARD),
        ("TOPPADDING",   (0,0), (-1,-1), 12),
        ("BOTTOMPADDING",(0,0), (-1,-1), 12),
        ("LINEBELOW",    (0,0), (-1,-1), 2, C_BLUE),
        ("LINEBEFORE",   (0,0), (-1,-1), 2, C_BLUE),
        ("LINEAFTER",    (0,0), (-1,-1), 2, C_BLUE),
        ("LINEABOVE",    (0,0), (-1,-1), 2, C_BLUE),
    ]))
    story.append(logo_t)
    story.append(Spacer(1, 3*mm))
    story.append(Paragraph("Siber Guvenlik Tarama Raporu", S_SUBTITLE))
    story.append(Spacer(1, 6*mm))

    # ─────────────────────────────────────────
    # EXECUTIVE SUMMARY (özet kutu)
    # ─────────────────────────────────────────
    # CVE'leri önceden say
    cve_lines = []
    exploit_count = 0
    kritik_count  = 0
    yuksek_count  = 0

    if vulns_string:
        for bulgu in vulns_string.split("|"):
            bulgu_t = temizle(bulgu)
            if "vulners" in bulgu_t.lower() or "CVE" in bulgu_t or "NGINX:" in bulgu_t:
                for satir in bulgu_t.split("\n"):
                    satir = satir.strip()
                    if not satir or len(satir) < 4:
                        continue
                    if any(x in satir for x in ["CVE","NGINX:","EDB-ID","PACKETSTORM",
                                                 "1337DAY","githubexploit","F065","B2B"]):
                        cve_id, score, url, exploit = parse_cve_line(satir)
                        cve_lines.append((cve_id, score, url, exploit))
                        if exploit: exploit_count += 1
                        if score >= 9.0: kritik_count += 1
                        elif score >= 7.0: yuksek_count += 1

    status_color = C_GREEN if "aktif" in safe_status.lower() or "up" in safe_status.lower() else C_RED
    status_hex   = status_color.hexval()

    ozet_rows = [
        [Paragraph("<b>OZET BILGILER</b>", stil("oz_h",
             fontName="Helvetica-Bold", fontSize=10,
             textColor=C_BLUE, alignment=TA_CENTER)), "", "", ""],
        [
            Paragraph(f"<b>Hedef</b><br/>{safe_name}", S_BODY),
            Paragraph(f"<b>Durum</b><br/>"
                      f'<font color="{status_hex}"><b>{safe_status}</b></font>', S_BODY),
            Paragraph(f"<b>Kritik / Yuksek CVE</b><br/>"
                      f'<font color="#dc3545"><b>{kritik_count}</b></font>'
                      f' / '
                      f'<font color="#e6a817"><b>{yuksek_count}</b></font>', S_BODY),
            Paragraph(f"<b>Exploit Mevcut</b><br/>"
                      f'<font color="#dc3545"><b>{exploit_count} adet</b></font>', S_BODY),
        ],
        [Paragraph(safe_url, S_SMALL), "", "", ""],
    ]
    ozet_t = Table(ozet_rows, colWidths=[W/4]*4)
    ozet_t.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), C_CARD),
        ("SPAN",         (0,0), (3,0)),
        ("SPAN",         (0,2), (3,2)),
        ("TOPPADDING",   (0,0), (-1,-1), 6),
        ("BOTTOMPADDING",(0,0), (-1,-1), 6),
        ("LEFTPADDING",  (0,0), (-1,-1), 10),
        ("RIGHTPADDING", (0,0), (-1,-1), 10),
        ("LINEBELOW",    (0,0), (-1, 0), 1, C_BORDER),
        ("LINEBELOW",    (0,1), (-1, 1), 1, C_BORDER),
        ("BOX",          (0,0), (-1,-1), 1, C_BORDER),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
    ]))
    story.append(ozet_t)
    story.append(Spacer(1, 5*mm))

    # ─────────────────────────────────────────
    # 1. AÇIK PORTLAR
    # ─────────────────────────────────────────
    story.append(section_header("[ PORT ]", "ACIK PORTLAR VE SERVISLER", C_BLUE))
    story.append(Spacer(1, 2*mm))

    if open_ports:
        port_list = [p.strip() for p in open_ports.split(",") if p.strip()]
        cols = 3
        rows = [port_list[i:i+cols] for i in range(0, len(port_list), cols)]
        # Satırları eşitle
        for r in rows:
            while len(r) < cols:
                r.append("")
        port_data = [[Paragraph(temizle(p), S_MONO) for p in row] for row in rows]
        pt = Table(port_data, colWidths=[W/cols]*cols)
        pt.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,-1), C_CARD),
            ("TOPPADDING",   (0,0), (-1,-1), 5),
            ("BOTTOMPADDING",(0,0), (-1,-1), 5),
            ("LEFTPADDING",  (0,0), (-1,-1), 10),
            ("GRID",         (0,0), (-1,-1), 0.3, C_BORDER),
        ]))
        story.append(pt)
    else:
        story.append(Paragraph("Acik port bulunamadi.", S_BODY))

    story.append(Spacer(1, 5*mm))

    # ─────────────────────────────────────────
    # 2. GÜVENLİK BAŞLIKLARI & DİĞER BULGULAR
    # ─────────────────────────────────────────
    other_bulgular = []
    spf_dmarc = []
    subdomain_bulgular = []

    if vulns_string:
        for bulgu in vulns_string.split("|"):
            clean = temizle(bulgu)
            clean = (clean
                .replace("p80:", "").replace("p443:", "")
                .replace("[mail_sec]:", "").replace("pDNS:", "")
                .replace("<br><br>", "\n").replace("<br>", " ")
                .replace("[spf]:", "SPF:").replace("[dmarc]:", "DMARC:")
                .replace("[vulners]:", "").replace("[http-title]:", "Baslik:")
                .replace("[http-security-headers]:", "Guvenlik Basliklari:"))

            if "SPF:" in clean or "DMARC:" in clean:
                spf_dmarc.append(clean.strip())
            elif "[subdomain]:" in clean or "aktif subdomain" in clean.lower():
                subdomain_bulgular.append(clean.replace("[subdomain]:", "").strip())
            elif any(x in clean for x in ["CVE","NGINX:","EDB-ID","PACKETSTORM",
                                            "githubexploit","1337DAY"]):
                pass
            elif len(clean) > 5:
                other_bulgular.append(clean.strip())

    if other_bulgular:
        story.append(section_header("[ WEB ]", "WEB ANALIZI VE GUVENLIK BASLIKLARI", C_PURPLE))
        story.append(Spacer(1, 2*mm))
        for b in other_bulgular:
            for satir in b.split("\n"):
                satir = satir.strip()
                if satir and len(satir) > 3:
                    story.append(Paragraph(f"• {satir}", S_BODY))
        story.append(Spacer(1, 5*mm))
    
    # ─────────────────────────────────────────
    # 3. SUBDOMAIN KEŞFİ
    # ─────────────────────────────────────────
    if subdomain_bulgular:
        story.append(section_header("[ SUBDOMAIN ]", "SUBDOMAIN KESFI", C_BLUE))
        story.append(Spacer(1, 2*mm))
        for bulgu in subdomain_bulgular:
            subdomains = [s.strip() for s in bulgu.replace("aktif subdomain bulundu:", "").split(",") if s.strip()]
            sub_data = []
            cols = 2
            for i in range(0, len(subdomains), cols):
                row = subdomains[i:i+cols]
                while len(row) < cols:
                    row.append("")
                sub_data.append([Paragraph(temizle(s), S_MONO) for s in row])
            
            if sub_data:
                sub_t = Table(sub_data, colWidths=[W/cols]*cols)
                sub_t.setStyle(TableStyle([
                    ("BACKGROUND",    (0,0), (-1,-1), C_CARD),
                    ("TOPPADDING",    (0,0), (-1,-1), 5),
                    ("BOTTOMPADDING", (0,0), (-1,-1), 5),
                    ("LEFTPADDING",   (0,0), (-1,-1), 10),
                    ("GRID",          (0,0), (-1,-1), 0.3, C_BORDER),
                ]))
                story.append(sub_t)
        story.append(Spacer(1, 5*mm))

    # ─────────────────────────────────────────
    # 4. E-POSTA GÜVENLİĞİ
    # ─────────────────────────────────────────
    if spf_dmarc:
        story.append(section_header("[ MAIL ]", "E-POSTA VE DNS GUVENLIGI", C_ORANGE))
        story.append(Spacer(1, 2*mm))
        for satir in spf_dmarc:
            for s in satir.split("\n"):
                s = s.strip()
                if s and len(s) > 3:
                    if "EKSIK" in s.upper() or "BULUNAMADI" in s.upper():
                        icon = "[!]"
                        renk = C_RED.hexval()
                    else:
                        icon = "[OK]"
                        renk = C_GREEN.hexval()
                    story.append(Paragraph(
                        f'<font color="{renk}"><b>{icon}</b></font>  {s}', S_BODY))
        story.append(Spacer(1, 5*mm))

    # ─────────────────────────────────────────
    # 4. ZAFİYET TABLOSU
    # ─────────────────────────────────────────
    if cve_lines:
        story.append(section_header("[ CVE ]", "KRITIK ZAFIYETLER", C_RED))
        story.append(Spacer(1, 2*mm))

        # Tablo başlığı
        header = [
            Paragraph("<b>CVE / ID</b>", stil("th", fontName="Helvetica-Bold",
                      fontSize=8, textColor=C_WHITE, alignment=TA_CENTER)),
            Paragraph("<b>CVSS</b>", stil("th2", fontName="Helvetica-Bold",
                      fontSize=8, textColor=C_WHITE, alignment=TA_CENTER)),
            Paragraph("<b>RISK</b>", stil("th3", fontName="Helvetica-Bold",
                      fontSize=8, textColor=C_WHITE, alignment=TA_CENTER)),
            Paragraph("<b>EXPLOIT</b>", stil("th4", fontName="Helvetica-Bold",
                      fontSize=8, textColor=C_WHITE, alignment=TA_CENTER)),
            Paragraph("<b>KAYNAK</b>", stil("th5", fontName="Helvetica-Bold",
                      fontSize=8, textColor=C_WHITE, alignment=TA_CENTER)),
        ]

        col_w = [W*0.32, W*0.08, W*0.12, W*0.12, W*0.36]
        tablo_data = [header]
        tablo_styles = [
            ("BACKGROUND",   (0,0), (-1,0), colors.HexColor("#21262d")),
            ("TEXTCOLOR",    (0,0), (-1,0), C_WHITE),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_CARD, colors.HexColor("#161b22")]),
            ("GRID",         (0,0), (-1,-1), 0.3, C_BORDER),
            ("TOPPADDING",   (0,0), (-1,-1), 4),
            ("BOTTOMPADDING",(0,0), (-1,-1), 4),
            ("LEFTPADDING",  (0,0), (-1,-1), 6),
            ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
        ]

        for i, (cve_id, score, url, exploit) in enumerate(cve_lines):
            renk = cvss_renk(score)
            renk_hex = renk.hexval()

            if score >= 9.0:   risk_label = "KRITIK"
            elif score >= 7.0: risk_label = "YUKSEK"
            elif score >= 4.0: risk_label = "ORTA"
            else:              risk_label = "DUSUK"

            exploit_text = "VAR" if exploit else "-"
            exploit_renk = C_RED.hexval() if exploit else C_MUTED.hexval()

            # URL'yi kısa göster
            kisa_url = url.replace("https://vulners.com/","").replace("https://","")
            if len(kisa_url) > 40:
                kisa_url = kisa_url[:37] + "..."

            satir = [
                Paragraph(f'<font color="{C_TEXT.hexval()}">{cve_id}</font>', S_MONO),
                Paragraph(f'<font color="{renk_hex}"><b>{score}</b></font>',
                          stil("sc", fontSize=9, fontName="Helvetica-Bold",
                               textColor=renk, alignment=TA_CENTER)),
                Paragraph(f'<font color="{renk_hex}"><b>{risk_label}</b></font>',
                          stil("rk", fontSize=8, fontName="Helvetica-Bold",
                               textColor=renk, alignment=TA_CENTER)),
                Paragraph(f'<font color="{exploit_renk}"><b>{exploit_text}</b></font>',
                          stil("ex", fontSize=8, fontName="Helvetica-Bold",
                               alignment=TA_CENTER)),
                Paragraph(kisa_url, S_SMALL),
            ]
            tablo_data.append(satir)

        cve_table = Table(tablo_data, colWidths=col_w, repeatRows=1)
        cve_table.setStyle(TableStyle(tablo_styles))
        story.append(cve_table)
        story.append(Spacer(1, 5*mm))

    # ─────────────────────────────────────────
    # 5. AKSİYON ÖNERİLERİ
    # ─────────────────────────────────────────
    story.append(section_header("[ AKSIYON ]", "ONCELIKLI AKSIYON ONERILERI", C_GREEN))
    story.append(Spacer(1, 2*mm))

    aksiyonlar = []
    if kritik_count > 0 or yuksek_count > 0:
        aksiyonlar.append(
            ("KRITIK", C_RED,
             f"Toplam {kritik_count + yuksek_count} adet kritik/yuksek CVE tespit edildi. "
             f"Nginx surumu acilen guncellenmeli. Ozellikle exploit mevcut olan "
             f"{exploit_count} zafiyet icin patch yonetimi derhal baslatilmali."))
    if spf_dmarc and any("EKSIK" in s.upper() for s in spf_dmarc):
        aksiyonlar.append(
            ("YUKSEK", C_ORANGE,
             "SPF veya DMARC kaydi eksik. Bu durum alan adinizdan sahte e-posta "
             "gonderilmesine (spoofing) olanak tanir. DNS kayitlariniza SPF ve "
             "DMARC TXT kaydi eklenmeli."))
    if not aksiyonlar:
        aksiyonlar.append(("BILGI", C_GREEN,
                           "Tespit edilen bulgulari duzenli olarak takip edin."))

    for oncelik, renk, metin in aksiyonlar:
        renk_hex = renk.hexval()
        ak_data = [[
            Paragraph(f'<font color="{renk_hex}"><b>[{oncelik}]</b></font>', S_BODY),
            Paragraph(metin, S_BODY),
        ]]
        ak_t = Table(ak_data, colWidths=[W*0.14, W*0.86])
        ak_t.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,-1), C_CARD),
            ("TOPPADDING",   (0,0), (-1,-1), 6),
            ("BOTTOMPADDING",(0,0), (-1,-1), 6),
            ("LEFTPADDING",  (0,0), (-1,-1), 8),
            ("LINEBEFORE",   (0,0), (0,-1), 3, renk),
            ("VALIGN",       (0,0), (-1,-1), "TOP"),
        ]))
        story.append(ak_t)
        story.append(Spacer(1, 2*mm))

    # ─────────────────────────────────────────
    # FOOTER ÇIZGISI
    # ─────────────────────────────────────────
    story.append(Spacer(1, 5*mm))
    story.append(hr(C_BORDER, 1))
    story.append(Paragraph(
        f'<font color="{C_MUTED.hexval()}">The Watchtower  |  '
        f'Olusturulma: {tarih_str}  |  '
        f'Bu rapor otomatik tarama sonuclarina dayanmaktadir.</font>',
        stil("foot", fontSize=7, textColor=C_MUTED, alignment=TA_CENTER)))

    # ─────────────────────────────────────────
    # PDF OLUŞTUR
    # ─────────────────────────────────────────
    def on_page(canvas, doc):
        """Her sayfaya arka plan rengi ve sayfa numarası ekle."""
        canvas.saveState()
        canvas.setFillColor(C_BG)
        canvas.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)
        canvas.restoreState()

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    return output_path


# ─────────────────────────────────────────────
# TEST
# ─────────────────────────────────────────────
if __name__ == "__main__":
    test_vulns = (
        "p80:[http-title]: Home of Acunetix Art|"
        "p80:[http-security-headers]: Strict-Transport-Security missing<br>X-Frame-Options: SAMEORIGIN<br>X-XSS-Protection: 0 (disabled)|"
        "[mail_sec]:[spf]: EKSIK - Bu alan adi adina sahte e-posta gonderilebilir|"
        "[mail_sec]:[dmarc]: EKSIK - DMARC kaydi bulunamadi|"
        "p80:[vulners]: nginx 1.19.0:\n"
        "3F71F065-66D4-541F-A813-9F1A2F2B1D91 8.8 https://vulners.com/githubexploit/3F71F065 *EXPLOIT*\n"
        "NGINX:CVE-2026-1642 8.2 https://vulners.com/nginx/NGINX:CVE-2026-1642\n"
        "NGINX:CVE-2022-41741 7.8 https://vulners.com/nginx/NGINX:CVE-2022-41741\n"
        "DF041B2B-2DA7-5262-AABE-9EBD2D535041 7.8 https://vulners.com/githubexploit/DF041B2B *EXPLOIT*\n"
        "PACKETSTORM:167720 7.7 https://vulners.com/packetstorm/PACKETSTORM:167720 *EXPLOIT*\n"
        "NGINX:CVE-2021-23017 7.7 https://vulners.com/nginx/NGINX:CVE-2021-23017\n"
        "EDB-ID:50973 7.7 https://vulners.com/exploitdb/EDB-ID:50973 *EXPLOIT*\n"
        "NGINX:CVE-2022-41742 7.1 https://vulners.com/nginx/NGINX:CVE-2022-41742\n"
        "NGINX:CVE-2025-53859 6.3 https://vulners.com/nginx/NGINX:CVE-2025-53859\n"
        "NGINX:CVE-2024-7347 5.7 https://vulners.com/nginx/NGINX:CVE-2024-7347\n"
        "PACKETSTORM:162830 0.0 https://vulners.com/packetstorm/PACKETSTORM:162830 *EXPLOIT*"
    )

    yol = create_target_report(
        target_name="test",
        target_url="http://testphp.vulnweb.com",
        status="Aktif",
        open_ports="80/nginx 1.19.0, 443/https, 8080/http-proxy, 8443/https-alt, DNS/Alan Adi Guvenligi",
        vulns_string=test_vulns,
        output_path="/mnt/user-data/outputs/watchtower_rapor_v2.pdf"
    )
    print(f"PDF olusturuldu: {yol}")

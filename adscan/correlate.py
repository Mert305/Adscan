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

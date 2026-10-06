"""Yetki yükseltme zinciri motoru.

Toplanan bulgulara bakarak klasik AD yetki yükseltme zincirinin hangi
adımlarının elde edildiğini / hangilerinin sırada olduğunu değerlendirir:

    Zehirleme/foothold -> Geçerli kimlik (cleartext/hash) -> Password reuse
    -> ESC8 (ADCS) -> Domain Admin

Bu bir "aktif istismar" değil; mevcut bulgulardan saldırı yolunu ve bir sonraki
adımı çıkaran bir danışman/özetleyicidir (reporting katmanının üstünde).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from .findings import ScanReport


@dataclass
class ChainStep:
    key: str
    title: str
    detect: Callable[[ScanReport], bool]  # bulgulardan elde edildi mi?
    next_hint: str  # elde edilmediyse bir sonraki eylem ipucu


def _has(report: ScanReport, pattern: str) -> bool:
    rx = re.compile(pattern, re.IGNORECASE)
    return any(rx.search(f.title) or rx.search(f.reference) or rx.search(f.source)
               for f in report.findings)


STEPS: list[ChainStep] = [
    ChainStep(
        "poison", "Zehirleme / foothold (LLMNR·NBT-NS·mitm6)",
        lambda r: _has(r, r"poisoning|NetNTLM|yakalandı"),
        "LLMNR/NBT-NS/IPv6 zehirlemesi için: --active-attacks --launch -I <iface>"),
    ChainStep(
        "enum", "Kullanıcı enumerasyonu (RID brute / LDAP / null session)",
        lambda r: bool(r.users) or _has(r, r"RID brute|kullanıcı enumere|anonim|null"),
        "Kullanıcı çıkar: null/guest + --rid-brute (otomatik) ya da windapsearch -U"),
    ChainStep(
        "cred", "Geçerli kimlik (spray / gMSA / LAPS / cleartext / relay / WinRM / MSSQL)",
        lambda r: bool(r.credentials) or _has(
            r, r"spray|doğrulandı|oturum|relay BAŞARILI|cleartext|gMSA|LAPS|winrm|mssql"),
        "Password spraying: --spray veya --auto; gMSA/LAPS için kimlikle tekrar tara"),
    ChainStep(
        "reuse", "Password reuse / yanal hareket (Pwn3d / WinRM / MSSQL / ACL)",
        lambda r: _has(
            r, r"admin erişimi|Pwn3d|reuse|yerel admin|komut çalıştırma|"
               r"yazılabilir AD|sysadmin"),
        "Kimlikleri host'larda dene: --reuse/--winrm/--mssql/--bloodyad (ya da --auto)"),
    ChainStep(
        "secrets", "Secrets dump (SAM/LSA/NTDS hash'leri)",
        lambda r: _has(r, r"secretsdump|SAM|LSA|NTDS|hash dökümü|hash.*döküldü"),
        "Admin host'ta: nxc smb <host> -u <user> -p <pass> --sam --lsa (--auto otomatik yapar)"),
    ChainStep(
        "adcs", "ADCS ESC / ACL suistimali (certipy·bloodyAD -> DA)",
        lambda r: _has(r, r"ESC\d|ADCS|sertifika|bloodyAD|yazılabilir AD"),
        "ADCS tara: --adcs (certipy); yazılabilir ACL yolları: --bloodyad; ya da "
        "ESC8 relay: --active-attacks --launch --adcs-ca-url http://<CA>/certsrv/certfnsh.asp"),
    ChainStep(
        "da", "Domain Admin / DCSync (krbtgt)",
        lambda r: r.domain_admin or _has(r, r"DCSync|Domain Admin|krbtgt"),
        "DC'de DCSync: nxc smb <dc> -u <admin> -H <hash> --ntds (--auto otomatik dener)"),
]


def evaluate(report: ScanReport) -> list[tuple[ChainStep, bool]]:
    return [(step, step.detect(report)) for step in STEPS]


def next_action(report: ScanReport) -> tuple[ChainStep, str] | None:
    """Zincirde elde EDİLMEMİŞ ilk adımı ve önerilen komutu döndürür.

    Domain Admin'e ulaşıldıysa None döner (yapacak bir sonraki adım yok).
    "Sıradaki en iyi eylem" motorunun çekirdeği: operatör bir sonraki adımı
    düşünmeden görebilir.
    """
    if report.domain_admin:
        return None
    for step, ok in evaluate(report):
        if not ok:
            return step, step.next_hint
    return None


_C = {"green": "\033[1;32m", "dim": "\033[2m", "bold": "\033[1m",
      "da": "\033[1;97;41m", "yellow": "\033[1;33m", "reset": "\033[0m"}


def format_chain(report: ScanReport, *, color: bool = False) -> str:
    def c(t, k):
        return f"{_C[k]}{t}{_C['reset']}" if color else t

    rows = evaluate(report)
    achieved = sum(1 for _, ok in rows if ok)
    n = len(rows)
    bar = "■" * achieved + "□" * (n - achieved)
    head = f"SALDIRI YOLU  [{bar}]  {achieved}/{n} adım"
    lines = ["", c(head, "bold")]
    for i, (step, ok) in enumerate(rows):
        connector = "   │" if i else ""
        if connector:
            lines.append(c(connector, "dim"))
        if ok:
            lines.append(f"   {c('◉', 'green')} {c(step.title, 'green')}")
        else:
            lines.append(f"   {c('○', 'dim')} {step.title}")
            lines.append(f"      {c('↳ sonraki: ' + step.next_hint, 'yellow')}")
    if report.domain_admin:
        lines.append("")
        lines.append(c("   ★ DOMAIN ADMIN ELDE EDİLDİ — domain tamamen ele geçirildi ★", "da"))
    else:
        nxt = next_action(report)
        if nxt is not None:
            step, hint = nxt
            lines.append("")
            lines.append(c(f"   ►► SIRADAKİ EN İYİ EYLEM: {step.title}", "bold"))
            lines.append(c(f"      {hint}", "green"))
    return "\n".join(lines)

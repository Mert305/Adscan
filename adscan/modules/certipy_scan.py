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

    first = results[0] if results else None
    if first and first.tool == "certipy:skip":
        return  # kimlik yok — sessizce atla
    if first and not first.ok:
        report.add_error(f"certipy: {first.error or 'çalıştırılamadı'}")
        return

    # Only explicit vulnerability entries belonging to a named object count.
    # A banner, help text or reference mentioning ESC1 is not a finding.
    obj = ""
    kind = ""
    vuln_indent = None
    version_match = re.search(r"Certipy\s+v?(\d+(?:\.\d+)*)", combined)
    for line in combined.splitlines():
        name = re.match(r"\s*(Template Name|CA Name)\s*:\s*(\S.*)", line)
        if name:
            kind, obj = name.group(1), name.group(2).strip()
            vuln_indent = None
            continue
        if line.strip() in {"Certificate Templates", "Certificate Authorities"} \
                or re.fullmatch(r"\s*\d+\s*", line):
            obj, vuln_indent = "", None
            continue
        if re.match(r"\s*\[[!*]\]\s*Vulnerabilities\s*$", line):
            vuln_indent = len(line) - len(line.lstrip())
            continue
        if vuln_indent is None or not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= vuln_indent:
            vuln_indent = None
            continue
        match = re.match(r"\s*ESC(\d{1,2})\s*:\s*(\S.*)", line)
        if not match or not obj:
            continue
        esc, detail = match.groups()
        if re.search(r"\bnot vulnerable\b|\bnot affected\b|\bdisabled\b|^none$|^false$",
                     detail, re.IGNORECASE):
            continue
        report.add(Finding(
            title=f"ADCS savunmasız: ESC{esc} — {obj} — certipy",
            severity=Severity.HIGH, target=target, source="certipy",
            control_id=f"adcs.esc{esc}", object_id=f"{kind}:{obj}",
            verification="tool_reported",
            tool_version=version_match.group(1) if version_match else "unknown",
            description="Certipy yapılandırma riski bildirdi; mevcut kimlikle "
                        "istismar edilebilirlik ve Domain Admin erişimi doğrulanmadı.",
            evidence=f"{kind}: {obj}\nESC{esc}: {detail}",
            remediation="İlgili CA/şablonun enrollment izinlerini, ACL, EKU ve "
                        "sertifika eşleme politikasını inceleyip gereksiz hakları kaldırın.",
            reference=f"ADCS ESC{esc}",
            poc="Aynı nesnede yapılandırma ve etkin erişim izinlerini yeniden kontrol edin.",
            escalation="Önkoşullar doğrulanmadı; olası etki bağımsız inceleme gerektirir."))
    if re.search(r"\bESC\d+\b", combined) and not any(
            f.source == "certipy" for f in report.findings):
        report.add_error("certipy: ESC metni var ancak nesneye bağlı olumlu bulgu ayrıştırılamadı")


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

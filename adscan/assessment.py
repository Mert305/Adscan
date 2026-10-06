"""Execution coverage: completion is not evidence of vulnerability absence."""

from .runner import classify_output

CATALOG = {
    "nxc-ldap": ["nxc:ldap-" + x for x in (
        "info", "users", "groups", "asrep", "kerberoast", "admincount",
        "trusted-delegation", "pass-not-required", "gmsa", "desc", "find-delegation", "adcs")],
    "nxc-smb": ["nxc:smb-" + x for x in (
        "info", "shares", "passpol", "users", "rid-brute", "spooler", "webdav", "laps",
        "ntlmv1", "gpp-autologin", "loggedon", "sessions", "spider")],
    "nxc-vulns": ["nxc:" + x for x in (
        "zerologon", "coerce", "maq", "pre2k", "ms17-010", "gpp-password", "timeroast",
        "nopac", "enum-trusts", "printnightmare", "smbghost", "sccm")],
    "windapsearch": ["windap-" + x for x in (
        "da", "privileged", "unconstrained", "users", "computers")],
    "dns": ["dns-" + x for x in ("axfr", "srv", "wildcard", "soa", "version")],
    "gmsa": ["gmsa-read", "laps-read"],
    "mssql": ["mssql-login", "mssql-priv", "mssql-links"],
    "access": ["access:" + x for x in ("smb", "ldap", "winrm", "mssql", "rdp")],
    "nmap": ["nmap-discover", "nmap"],
    "web": ["web"],
    "smbmap": ["smbmap"],
    "certipy": ["certipy-find", "certipy:json"],
    "bloodhound": ["bloodhound-python", "bloodhound-nxc"],
    "bloodyad": ["bloodyad-writable", "bloodyad-deleted"],
    "winrm": ["winrm-check"],
    "delegation": ["delegation-find"],
    "gpo": ["gpo:analyze"],
    "tickets": ["tickets-gettgt"],
    "shadow": ["shadow-auto"],
    "userenum": ["userenum"],
}

LABELS = {
    "nxc:ldap-info": "LDAP bağlantısı ve kimlik doğrulama",
    "nxc:ldap-users": "LDAP kullanıcı listesi",
    "nxc:ldap-groups": "LDAP grup listesi",
    "nxc:ldap-asrep": "AS-REP roasting kontrolü",
    "nxc:ldap-kerberoast": "Kerberoasting kontrolü",
    "nxc:ldap-admincount": "adminCount ayrıcalıklı hesaplar",
    "nxc:ldap-trusted-delegation": "Güvenilen delegasyon hesapları",
    "nxc:ldap-pass-not-required": "Parola gerektirmeyen hesaplar",
    "nxc:ldap-gmsa": "gMSA parola okuma yetkisi",
    "nxc:ldap-desc": "Hesap açıklamalarında kimlik bilgisi",
    "nxc:ldap-find-delegation": "Kerberos delegasyon yapılandırması",
    "nxc:ldap-adcs": "ADCS kayıt sunucusu keşfi",
}


def control_id(result):
    return result.tool.removesuffix(":skip").removesuffix(":dry")


def controls_for(module):
    if module == "bloodyad-enum":
        from .modules.bloodyAD_scan import _ENUM_QUERIES
        return ["bloodyad-enum-" + q.key for q in _ENUM_QUERIES] + [
            "bloodyad-enum-" + x for x in ("dns", "trusts", "krbtgt", "stale")]
    return CATALOG.get(module, [])


def missing_reason(report, module, cid, results):
    skips = [r.error for r in results or [] if r.tool.endswith(":skip") and r.argv == []]
    if skips and all(r.tool.endswith(":skip") for r in results):
        return skips[0] or "Modül önkoşulları karşılanmadı"
    auth_checks = {"nxc:ldap-gmsa", "nxc:ldap-desc", "nxc:ldap-find-delegation", "nxc:ldap-adcs",
                   "nxc:smb-laps", "nxc:smb-ntlmv1", "nxc:smb-gpp-autologin",
                   "nxc:smb-loggedon", "nxc:smb-sessions", "nxc:smb-spider"}
    if report.scan_mode == "unauthenticated" and cid in auth_checks:
        return "Kimlik gerekli; kimliksiz taramada çalıştırılmadı"
    if cid == "nmap-discover":
        return "Tam port keşfi seçilmedi (--full / --full-ports)"
    if cid == "nxc:smb-spider":
        return "--full seçilmedi veya spider_plus araç desteği bulunamadı"
    if module == "bloodhound":
        return "Alternatif toplayıcı seçildi veya toplayıcı kullanılamadı"
    if module == "dns":
        return "Domain parametresine göre bu DNS sorgusu seçilmedi"
    return "Kontrol seçilmedi veya araç/adaptör desteği bulunamadı"


def result_status(result, *, parse_failed=False):
    kind = result.error_kind or classify_output(result.combined)
    if "[DRY-RUN]" in result.stdout:
        return "planned", "Dry-run; kontrol uygulanmadı"
    if result.tool.endswith(":skip"):
        return "skipped", result.error or "Kontrol önkoşulları karşılanmadı"
    if result.timed_out:
        return "failed", "Zaman aşımı; sonuç eksik olabilir"
    if kind == "auth":
        return "access_denied", "Kimlik doğrulama veya erişim reddedildi"
    if not result.ok or kind:
        return "failed", f"Araç hatası ({kind or result.returncode})"
    if parse_failed:
        return "failed", "Çıktı ayrıştırılamadı"
    if not result.combined.strip():
        return "unknown", "Boş çıktı; kontrol sonucu doğrulanamadı"
    return "completed", "Araç çalıştı; zafiyet yokluğu garantisi değildir"


def record_skipped(report, module, reason):
    report.record_coverage(module, "skipped", reason, module=module, level="module")
    for cid in controls_for(module):
        report.record_coverage(cid, "skipped", reason, module=module)


def record_results(report, module, results, *, parse_failed=False, findings=False):
    statuses, seen = [], set()
    for result in results or []:
        cid = control_id(result)
        seen.add(cid)
        status, reason = result_status(result, parse_failed=parse_failed)
        report.record_coverage(cid, status, reason, module=module,
                               observed_at=result.observed_at, resumed=result.resumed)
        statuses.append(status)
    for cid in controls_for(module):
        if cid not in seen:
            status = "skipped"
            reason = missing_reason(report, module, cid, results)
            if not results:
                status, reason = "unknown", "Modül sonuç döndürmedi; kontrol değerlendirilemedi"
            elif cid == "nmap-discover" or (module in {"dns", "bloodhound"}
                                            and any(r.ok for r in results)):
                status = "not_applicable"  # unselected optional or alternative collector
            report.record_coverage(cid, status, reason, module=module)
            statuses.append(status)
    incomplete = any(s not in {"completed", "not_applicable"} for s in statuses)
    report.record_coverage(module, "failed" if parse_failed or not results else
                           "partial" if incomplete else "findings" if findings else "completed",
                           "Modül özeti; alt kontrol durumlarına bakın", module=module,
                           level="module")

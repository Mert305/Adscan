"""WinRM (5985/5986) yanal hareket kontrolü (netexec winrm).

Verilen kimlikle WinRM üzerinden oturum/exec erişimi olup olmadığını ölçer.
nxc '[+]' => geçerli WinRM; '(Pwn3d!)' => uzaktan komut çalıştırma (evil-winrm).
Kimlik gerektirir; opt-in.
"""

from __future__ import annotations

import re

from ..findings import Credential, Finding, ScanReport, Severity
from ..runner import CommandResult, ToolStatus, run, strip_dryrun
from ..util import grep as _grep
from . import nxc_scan

_HIT_RX = re.compile(
    r"^WINRM\s+(\S+)\s+\d+\s+\S+\s+\[\+\]\s+([^\s\\]*)\\?([^\s:]+):(\S+?)"
    r"(\s+\(Pwn3d!\))?\s*$", re.MULTILINE)


def tool() -> ToolStatus:
    return nxc_scan.tool()


def _auth(username, password, nthash, domain):
    args = ["-u", username or ""]
    if nthash:
        args += ["-H", nthash]
    else:
        args += ["-p", password or ""]
    if domain and username:
        args += ["-d", domain]
    return args


def scan(target, *, domain=None, username=None, password=None, nthash=None,
         timeout=300, dry_run=False):
    if username is None or not (password or nthash):
        return [CommandResult(tool="winrm:skip", argv=[], returncode=None, stdout="",
                              stderr="", duration=0.0,
                              error="winrm: kimlik gerekli")]
    bin_name = tool().name
    argv = [bin_name, "winrm", target] + _auth(username, password, nthash, domain)
    return [run(argv, tool="winrm-check", timeout=timeout, dry_run=dry_run)]


def parse(results: list[CommandResult], report: ScanReport) -> None:
    report.raw_outputs["winrm"] = "\n\n".join(r.combined for r in results)
    combined = strip_dryrun("\n\n".join(r.combined for r in results))
    target = report.target

    first = results[0] if results else None
    if first and first.tool == "winrm:skip":
        return
    if first and not first.ok:
        report.add_error(f"winrm: {first.error or 'çalıştırılamadı'}")
        return

    hits = _HIT_RX.findall(combined)
    if not hits:
        return

    pwned = [(h, u) for h, _d, u, _s, pwn in hits if pwn]
    for h, dom, u, s, pwn in hits:
        report.add_credential(Credential(
            username=u, secret=s,
            kind="nthash" if re.fullmatch(r"[0-9a-f]{32}", s) else "password",
            domain=dom, source="winrm", host=h, admin=bool(pwn)))

    if pwned:
        report.add(Finding(
            title=f"WinRM uzaktan komut çalıştırma — {len(pwned)} host (evil-winrm)",
            severity=Severity.CRITICAL, target=target, source="winrm",
            description="WinRM üzerinden kabuk erişimi var; sunucuda komut çalıştırılabilir.",
            evidence="\n".join(f"{h}  {u}" for h, u in pwned),
            remediation="WinRM erişimini kıs (yalnızca yönetim ağı); Remote Management "
                        "Users üyeliklerini denetle.",
            reference="WinRM / Lateral Movement",
            poc=f"nxc winrm {target} -u <user> -p <pass>",
            escalation="İnteraktif kabuk: 'evil-winrm -i <host> -u <user> -p <pass>' "
                       "(hash ile -H <nt>); ardından mimikatz/secretsdump ile kimlik dök."))
    else:
        report.add(Finding(
            title=f"Geçerli WinRM kimliği — {len(hits)} host",
            severity=Severity.HIGH, target=target, source="winrm",
            description="WinRM auth başarılı ama exec (Pwn3d) yok; yine de geçerli kimlik.",
            evidence=_grep(combined, r"WINRM.*\[\+\]", context=0),
            remediation="WinRM erişimini sınırla.",
            reference="WinRM valid credentials",
            poc=f"nxc winrm {target} -u <user> -p <pass>",
            escalation="Admin olunan host'larda exec için grup üyeliklerini yükselt."))


# ---------------------------------------------------------------------------
from ..registry import ScanContext, ScanModule  # noqa: E402


def _run(ctx: ScanContext) -> list[CommandResult]:
    return scan(ctx.target, domain=ctx.domain, username=ctx.username,
                password=ctx.password, nthash=ctx.nthash,
                timeout=ctx.timeout, dry_run=ctx.dry_run)


MODULE = ScanModule(
    name="winrm",
    label="netexec WinRM yanal hareket kontrolü (opt-in, kimlik gerektirir)",
    run=_run,
    parse=parse,
    requires_creds=True,
    optin=True,
)

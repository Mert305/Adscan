"""kerbrute ile Kerberos pre-auth kullanıcı doğrulama (opt-in).

kerbrute, KDC'ye AS-REQ göndererek bir kullanıcı adının var olup olmadığını
**kimlik gerektirmeden** ve hesabı kilitlemeden saptar (AS-REQ başarısız pre-auth
= kullanıcı var). Bu, LDAP okuması kısıtlı/confidential olduğunda (bkz.
[[ldap.confidential]]) kullanıcıları enumere etmenin tek güvenilir yoludur — nxc
LDAP `--users` çoğu nesneyi göremese de kerbrute SAMR/LDAP'ı hiç kullanmaz.

Ek olarak pre-auth GEREKMEYEN hesapları (AS-REP roasting adayları) işaretler.

Girdi kullanıcı adları: --spray-userlist / --spray-namelist / --spray-users
(spray ile aynı kaynak). Domain gerekir (-d).
"""

from __future__ import annotations

import re

from ..findings import Finding, ScanReport, Severity
from ..registry import ScanContext, ScanModule
from ..runner import CommandResult, resolve_tool, run, strip_dryrun, which
from . import spray_scan

KERBRUTE_CANDIDATES = ["kerbrute", "kerbrute_linux_amd64"]


def tool():
    return resolve_tool(KERBRUTE_CANDIDATES)


def _dc_host(ctx: ScanContext) -> str:
    return ctx.target.split(",")[0].split("/")[0].strip()


def _run(ctx: ScanContext) -> list[CommandResult]:
    if ctx.dry_run:
        dom = ctx.domain or "<domain>"
        dc = _dc_host(ctx)
        return [CommandResult(tool="userenum:dry", argv=["kerbrute", "userenum",
                              "-d", dom, "--dc", dc, "<userlist>"], returncode=0,
                              stdout="[DRY-RUN] kerbrute userenum", stderr="",
                              duration=0.0)]
    if not which(KERBRUTE_CANDIDATES[0]) and not which(KERBRUTE_CANDIDATES[1]):
        return [CommandResult(tool="userenum:skip", argv=[], returncode=None,
                              stdout="", stderr="", duration=0.0,
                              error="kerbrute bulunamadı (userenum atlandı)")]
    if not ctx.domain:
        return [CommandResult(tool="userenum:skip", argv=[], returncode=None,
                              stdout="", stderr="", duration=0.0,
                              error="userenum: domain (-d) gerekli")]
    users = spray_scan._collect_users(ctx)
    if not users:
        return [CommandResult(tool="userenum:skip", argv=[], returncode=None,
                              stdout="", stderr="", duration=0.0,
                              error="userenum: kullanıcı/isim listesi verilmedi "
                                    "(--spray-userlist / --spray-namelist / --spray-users)")]
    import os
    import tempfile
    bin_name = tool().name
    tmp = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8")
    try:
        tmp.write("\n".join(users))
        tmp.close()
        argv = [bin_name, "userenum", "-d", ctx.domain, "--dc",
                _dc_host(ctx), tmp.name]
        return [run(argv, tool="userenum", timeout=ctx.timeout, dry_run=ctx.dry_run)]
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


# kerbrute çıktısı ANSI renk kodları içerebilir — temizle.
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_VALID_RX = re.compile(r"VALID USERNAME:\s+(\S+)", re.IGNORECASE)
_NOPREAUTH_RX = re.compile(r"(\S+).*(?:no\s*pre.?auth|NO PREAUTH|has no pre auth)",
                           re.IGNORECASE)


def parse(results: list[CommandResult], report: ScanReport) -> None:
    raw = "\n\n".join(r.combined for r in results)
    report.raw_outputs["userenum"] = raw
    first = results[0] if results else None
    if first and first.tool in ("userenum:skip",):
        if first.error:
            report.add_error(f"userenum: {first.error}")
        return
    if first and not first.ok and not (first.stdout or ""):
        report.add_error(f"userenum: {first.error or 'çalıştırılamadı'}")
        return

    text = _ANSI.sub("", strip_dryrun(raw))
    valid = []
    seen = set()
    for m in _VALID_RX.finditer(text):
        u = m.group(1).split("@")[0]
        if u.lower() not in seen:
            seen.add(u.lower())
            valid.append(u)
            if u not in report.users:
                report.users.append(u)
    nopreauth = sorted({m.group(1).split("@")[0] for m in _NOPREAUTH_RX.finditer(text)})

    if valid:
        report.add(Finding(
            title=f"kerbrute ile {len(valid)} kullanıcı doğrulandı (Kerberos pre-auth)",
            severity=Severity.INFO, target=report.target, source="userenum",
            control_id="kerberos.userenum",
            reference="Kerberos user enumeration (AS-REQ)",
            mitre="T1087.002",
            description="KDC'ye AS-REQ ile, kimlik gerektirmeden ve hesap kilitlemeden "
                        "geçerli kullanıcı adları doğrulandı. LDAP okuması kısıtlıysa "
                        "(confidential) bu liste spray/roast için ana girdidir.",
            evidence="\n".join(valid[:40]),
            poc=f"kerbrute userenum -d {report.domain or '<domain>'} --dc {_dc_host_report(report)} users.txt",
            escalation="Doğrulanan kullanıcılar -> güvenli spray ('adscan --spray') ve "
                       "AS-REP/kerberoast girdisi."))
    if nopreauth:
        report.add(Finding(
            title=f"AS-REP roasting adayı: {len(nopreauth)} hesapta pre-auth kapalı",
            severity=Severity.HIGH, target=report.target, source="userenum",
            control_id="kerberos.asrep.nopreauth",
            reference="AS-REP Roasting",
            mitre="T1558.004",
            description="Bu hesaplarda Kerberos pre-authentication devre dışı; AS-REP "
                        "yanıtı kimlik gerektirmeden alınıp çevrimdışı kırılabilir.",
            evidence="\n".join(nopreauth),
            remediation="Etkilenen hesaplarda 'Do not require Kerberos preauthentication' "
                        "seçeneğini kapat; güçlü parola ata.",
            poc=f"GetNPUsers.py {report.domain or '<dom>'}/ -no-pass -usersfile users.txt "
                f"-dc-ip {report.target} -format hashcat",
            escalation="Hash'i çevrimdışı kır (hashcat -m 18200) -> geçerli kimlik -> yanal hareket."))


def _dc_host_report(report: ScanReport) -> str:
    return report.target.split(",")[0].split("/")[0].strip()


MODULE = ScanModule(
    name="userenum",
    label="kerbrute Kerberos kullanıcı doğrulama + AS-REP tespiti (opt-in)",
    run=_run,
    parse=parse,
    requires_creds=False,
    optin=True,
)

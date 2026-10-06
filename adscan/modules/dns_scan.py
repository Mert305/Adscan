"""DNS / ADIDNS enumerasyonu (port 53 — AD'de DC genellikle DNS sunucusudur).

Eski araç 53'ü hiç taramıyordu. Bu modül `dig` ile kimlik gerektirmeden:

  * **AXFR (zone transfer)** dener — başarılıysa tüm iç DNS kayıtları sızar (yüksek).
  * SOA/NS ve AD SRV kayıtlarını (`_ldap._tcp.dc._msdcs`) sorgular (bilgi).
  * **ADIDNS wildcard** (`*.<domain>`) kaydı var mı bakar — varsa WPAD/ad-hoc
    isim çözümlemesi suistimali mümkündür.

Domain (`-d`) verilmemişse yalnız SOA denenir; AXFR/SRV için domain gerekir.
"""

from __future__ import annotations

import re

from ..findings import Finding, ScanReport, Severity
from ..runner import CommandResult, ToolStatus, resolve_tool, run, strip_dryrun


def tool() -> ToolStatus:
    return resolve_tool(["dig"])


def scan(target: str, *, domain: str | None = None, timeout: int = 120,
         dry_run: bool = False, **_: object) -> list[CommandResult]:
    st = tool()
    if not st.available and not dry_run:
        return [CommandResult(tool="dns:skip", argv=[], returncode=None, stdout="",
                              stderr="", duration=0.0, error="dig bulunamadı",
                              error_kind="skipped")]
    host = target.split(",")[0].split("/")[0].strip()
    out: list[CommandResult] = []
    if domain:
        out.append(run(["dig", f"@{host}", "AXFR", domain, "+time=8", "+tries=1"],
                       tool="dns-axfr", timeout=timeout, dry_run=dry_run))
        out.append(run(["dig", f"@{host}", "SRV", f"_ldap._tcp.dc._msdcs.{domain}",
                        "+short", "+time=5"], tool="dns-srv", timeout=timeout,
                       dry_run=dry_run))
        out.append(run(["dig", f"@{host}", "A", f"wildcardprobe-adscan.{domain}",
                        "+short", "+time=5"], tool="dns-wildcard", timeout=timeout,
                       dry_run=dry_run))
        out.append(run(["dig", f"@{host}", "SOA", domain, "+short", "+time=5"],
                       tool="dns-soa", timeout=timeout, dry_run=dry_run))
    else:
        out.append(run(["dig", f"@{host}", "version.bind", "CH", "TXT", "+short",
                        "+time=5"], tool="dns-version", timeout=timeout, dry_run=dry_run))
    return out


def parse(results: list[CommandResult], report: ScanReport) -> None:
    report.raw_outputs["dns"] = "\n\n".join(
        f"$ {' '.join(r.argv)}\n{r.combined}" for r in results)
    first = results[0] if results else None
    if first and first.tool == "dns:skip":
        return
    target = report.target

    def _out(tool_suffix: str) -> str:
        return strip_dryrun(next(
            (r.combined for r in results if r.tool == tool_suffix), ""))

    # AXFR: birden çok kayıt satırı döndüyse zone transfer başarılı
    axfr = _out("dns-axfr")
    rec_lines = [ln for ln in axfr.splitlines()
                 if re.search(r"\bIN\s+(A|AAAA|CNAME|SRV|MX|NS|TXT|PTR)\b", ln)]
    if len(rec_lines) >= 2 and "failed" not in axfr.lower():
        report.add(Finding(
            title=f"DNS zone transfer (AXFR) açık — {len(rec_lines)} kayıt sızdı",
            severity=Severity.HIGH, target=target, source="dns",
            control_id="dns.axfr", mitre="T1590.002",
            reference="DNS Zone Transfer (AXFR)",
            description="DNS sunucusu kimlik gerektirmeden tüm zone'u (AXFR) kopyalattı. "
                        "İç host/servis isimleri, IP'ler ve AD topolojisi ifşa olur.",
            evidence="\n".join(rec_lines[:40]),
            remediation="AXFR'ı yalnız yetkili ikincil DNS sunucularıyla sınırla.",
            poc=f"dig @{target} AXFR <domain>",
            escalation="Sızan isimlerden ek saldırı yüzeyi (web/DB/yönetim host'ları) çıkar."))

    # ADIDNS wildcard: var olmayan isim çözülüyorsa wildcard kaydı vardır
    wc = _out("dns-wildcard").strip()
    if wc and re.search(r"\d+\.\d+\.\d+\.\d+", wc):
        report.add(Finding(
            title="ADIDNS wildcard kaydı var — isim çözümleme suistimali mümkün",
            severity=Severity.MEDIUM, target=target, source="dns",
            control_id="dns.adidns-wildcard", mitre="T1557",
            reference="ADIDNS wildcard / WPAD",
            description="Var olmayan bir isim de çözümleniyor (wildcard). Saldırgan "
                        "WPAD/ad-hoc isimleri ele geçirip NTLM yakalama/relay yapabilir.",
            evidence=f"wildcardprobe-adscan.<domain> -> {wc}",
            remediation="ADIDNS wildcard kaydını kaldır; WPAD'i GPO ile devre dışı bırak.",
            poc=f"dig @{target} A rasgele-isim.<domain> +short",
            escalation="ADIDNS'e kayıt ekle (authenticated) -> WPAD spoof -> Responder/relay."))

    srv = _out("dns-srv").strip()
    soa = _out("dns-soa").strip()
    if srv or soa:
        report.add(Finding(
            title="AD DNS kayıtları enumere edildi (SRV/SOA)",
            severity=Severity.INFO, target=target, source="dns",
            control_id="dns.records", mitre="T1590.002",
            description="DC DNS üzerinden AD servis kayıtları okundu.",
            evidence=(f"_ldap._tcp.dc._msdcs SRV:\n{srv}\n" if srv else "")
                     + (f"SOA: {soa}" if soa else ""),
            poc=f"dig @{target} SRV _ldap._tcp.dc._msdcs.<domain> +short"))


# ---------------------------------------------------------------------------
from ..registry import ScanContext, ScanModule  # noqa: E402


def _run(ctx: ScanContext) -> list[CommandResult]:
    return scan(ctx.target, domain=ctx.domain, timeout=ctx.timeout, dry_run=ctx.dry_run)


MODULE = ScanModule(
    name="dns",
    label="DNS/ADIDNS enumerasyonu (AXFR + SRV + wildcard)",
    run=_run,
    parse=parse,
    requires_creds=False,
    optin=False,
)

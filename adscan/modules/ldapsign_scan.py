"""LDAP imzalama (signing) ve LDAPS channel binding zorlaması kontrolü.

Bir DC, LDAP imzalamayı ZORLAMIYORSA ya da LDAPS kanal bağlamayı (channel binding,
EPA) zorlamıyorsa, yakalanan/zorlanan (coerced) NTLM kimlik doğrulaması LDAP'a
RELAY edilebilir. Bu, en yüksek etkili AD saldırı primitiflerinden biridir:

    NTLM coercion (PetitPotam/PrinterBug) -> ntlmrelayx -> LDAP(S)
      -> RBCD yaz / shadow-cred ekle / makine hesabı oluştur (MAQ)
      -> hedef host'a/DC'ye yetki -> Domain Admin

Bu modül nxc `ldap-checker` modülüyle her iki zorlamayı da sınar. Yalnızca OKUMA
yapar (ağa müdahale etmez), ama bind için kimlik gerekir -> opt-in + requires_creds.

İlgili: coercion primitifi [[smb-spooler]] / webdav (relay kaynağı), ESC8 (ADCS relay).
"""

from __future__ import annotations

import re

from ..findings import Finding, ScanReport, Severity
from ..registry import ScanContext, ScanModule
from ..runner import CommandResult, run, strip_dryrun
from . import nxc_scan

# nxc ldap-checker çıktısı (sürüme göre küçük farklar). Tolerant, case-insensitive:
#   "LDAP Signing NOT Enforced!"
#   "LDAP signing is not required"
_SIGNING_RX = re.compile(
    r"ldap\s+signing\s+(?:is\s+)?(?:not\s+(?:enforced|required)|not\s+enforced)",
    re.IGNORECASE)
#   'LDAPS Channel Binding is set to "NEVER"'  /  "channel binding ... not enforced"
#   "when supported" da güvensizdir (yalnızca istemci isterse uygulanır)
_CB_RX = re.compile(
    r"channel\s+binding[^\n]*?(?:\"?never\"?|not\s+enforced|when\s+supported)",
    re.IGNORECASE)


def scan(target, *, domain=None, username=None, password=None, nthash=None,
         use_kerberos=False, timeout=300, dry_run=False) -> list[CommandResult]:
    # ldap-checker bind gerektirir; kimlik yoksa anlamsız.
    if username is None or not (password or nthash or use_kerberos):
        return [CommandResult(tool="ldap-signing:skip", argv=[], returncode=None,
                              stdout="", stderr="", duration=0.0,
                              error="ldap-signing: bind için kimlik gerekli",
                              error_kind="skipped")]
    status = nxc_scan.tool()
    if not status.available:
        return [CommandResult(tool="ldap-signing:skip", argv=[], returncode=None,
                              stdout="", stderr="", duration=0.0,
                              error="netexec (nxc) bulunamadı", error_kind="skipped")]
    argv = [status.name, "ldap", target] + nxc_scan._creds_args(
        username, password, nthash, domain, use_kerberos) + ["-M", "ldap-checker"]
    return [run(argv, tool="ldap-checker", timeout=timeout, dry_run=dry_run)]


def parse(results: list[CommandResult], report: ScanReport) -> None:
    report.raw_outputs["ldap-signing"] = "\n\n".join(r.combined for r in results)
    first = results[0] if results else None
    if first and first.tool == "ldap-signing:skip":
        return
    out = strip_dryrun(next((r.combined for r in results
                             if r.tool == "ldap-checker"), ""))
    if not out:
        return
    target = report.target

    if _SIGNING_RX.search(out):
        report.add(Finding(
            title="LDAP imzalama (signing) ZORLANMIYOR — NTLM relay-to-LDAP mümkün",
            severity=Severity.HIGH, target=target, source="ldap-signing",
            control_id="ldap.signing.not-enforced", mitre="T1557.001",
            reference="LDAP signing not enforced (CVE-2017-8563 sınıfı)",
            description="DC, LDAP imzalamayı zorlamıyor. Yakalanan/zorlanan NTLM "
                        "auth'u LDAP'a relay edilip RBCD yazma, shadow-cred ekleme "
                        "veya makine hesabı oluşturma ile yetki yükseltilebilir.",
            evidence=_first_match(out, _SIGNING_RX),
            remediation="DC'de 'Domain controller: LDAP server signing requirements' "
                        "= 'Require signing' GPO'sunu zorla; mümkünse LDAP'ı kapat, "
                        "yalnız LDAPS + channel binding kullan.",
            poc=f"nxc ldap {target} -u <u> -p <p> -M ldap-checker",
            escalation="Coercion (PetitPotam/PrinterBug) -> ntlmrelayx -t "
                       f"ldap://{target} --delegate-access (RBCD) / --add-computer; "
                       "ardından S4U ile hedefe yerel admin -> DCSync."))

    if _CB_RX.search(out):
        report.add(Finding(
            title="LDAPS channel binding (EPA) ZORLANMIYOR — LDAPS relay mümkün",
            severity=Severity.HIGH, target=target, source="ldap-signing",
            control_id="ldaps.channel-binding.not-enforced", mitre="T1557.001",
            reference="LDAPS channel binding not enforced",
            description="DC, LDAPS için kanal bağlamayı (EPA) zorlamıyor. İmzalama "
                        "zorlansa bile NTLM auth LDAPS'a relay edilebilir ve aynı "
                        "RBCD/shadow-cred/MAQ primitifleri kullanılabilir.",
            evidence=_first_match(out, _CB_RX),
            remediation="DC'de LDAP kanal bağlama zorlamasını (EPA) 'Always' yap "
                        "(msPKI/registry: LdapEnforceChannelBinding=2).",
            poc=f"nxc ldap {target} -u <u> -p <p> -M ldap-checker",
            escalation="Coercion -> ntlmrelayx -t ldaps://<DC> --delegate-access / "
                       "--add-computer -> RBCD -> S4U -> yerel admin -> DCSync."))


def _first_match(text: str, rx: re.Pattern) -> str:
    """Eşleşen satırı (kanıt) döndürür; yoksa boş."""
    for line in text.splitlines():
        if rx.search(line):
            return line.strip()
    return ""


def _run(ctx: ScanContext) -> list[CommandResult]:
    return scan(ctx.target, domain=ctx.domain, username=ctx.username,
                password=ctx.password, nthash=ctx.nthash,
                use_kerberos=ctx.use_kerberos, timeout=ctx.timeout,
                dry_run=ctx.dry_run)


MODULE = ScanModule(
    name="ldap-signing",
    label="LDAP imzalama / LDAPS channel binding zorlaması (relay-to-LDAP riski)",
    run=_run,
    parse=parse,
    requires_creds=True,
    optin=True,
)

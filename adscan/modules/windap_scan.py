"""windapsearch ile LDAP tabanlı AD enumerasyonu.

Domain admin'ler, ayrıcalıklı kullanıcılar, unconstrained delegation'lı
hesaplar ve genel kullanıcı/bilgisayar listesini çeker.
"""

from __future__ import annotations

import re

from ..findings import Finding, ScanReport, Severity
from ..runner import CommandResult, ToolStatus, resolve_tool, run, strip_dryrun
from ..util import grep as _grep

WINDAP_CANDIDATES = ["windapsearch", "windapsearch.py"]

# GERÇEK bir LDAP sonuç satırı: bir nesnenin ilk sütunda yazılmış attribute'u.
# windapsearch'in ilerleme banner'larını ('[+] Using DN: CN=...', '[+]\tFound: DC=...',
# '[+] ...success! Binded as:') AYIKLAR — bunlar 'DN:' / 'CN=' içerse de veri DEĞİLDİR.
# Anonim bind açık ama arama reddediliyorsa ('successful bind must be completed') hiç
# attribute dönmez; bu regex o durumda eşleşmeyerek yanlış pozitifi önler.
_RESULT_RX = re.compile(
    r"^[ \t]*(?:sAMAccountName|distinguishedName|userPrincipalName):[ \t]*\S",
    re.IGNORECASE | re.MULTILINE,
)


def _has_results(text: str) -> bool:
    """windapsearch çıktısında gerçekten enumere edilmiş nesne var mı?"""
    return bool(_RESULT_RX.search(text))


def tool() -> ToolStatus:
    return resolve_tool(WINDAP_CANDIDATES)


def scan(
    dc_ip: str,
    *,
    domain: str | None = None,
    username: str | None = None,
    password: str | None = None,
    timeout: int = 300,
    dry_run: bool = False,
) -> list[CommandResult]:
    status = tool()
    bin_name = status.name

    auth: list[str] = []
    if username:
        auth += ["-u", username]
        if domain:
            # windapsearch user genelde user@domain bekler
            if "@" not in username and "\\" not in username:
                auth[-1] = f"{username}@{domain}"
        if password:
            auth += ["-p", password]

    base = [bin_name, "--dc-ip", dc_ip] + auth

    runs = [
        ("windap-da", base + ["--da"]),  # domain admins
        ("windap-privileged", base + ["-PU"]),  # privileged users
        ("windap-unconstrained", base + ["--unconstrained-users"]),
        ("windap-users", base + ["-U"]),
        ("windap-computers", base + ["-C"]),
    ]
    results = []
    for label, argv in runs:
        results.append(run(argv, tool=label, timeout=timeout, dry_run=dry_run))
    return results


def parse(results: list[CommandResult], report: ScanReport) -> None:
    report.raw_outputs["windapsearch"] = "\n\n".join(r.combined for r in results)
    combined = strip_dryrun("\n\n".join(r.combined for r in results))

    target = report.target

    # windapsearch bağlantı/bind hatasında da sıfırdan farklı kod döndürür ama
    # yararlı bir mesajı stdout'a '[!] ...' satırı olarak yazar. Bir tek run'ın
    # (ör. ilk sıradaki --da) başarısız olması TÜM enumerasyonu geçersiz kılmaz;
    # yalnızca HİÇBİR run veri üretmediyse ve hepsi hatalıysa sert hata ver.
    got_any_data = _has_results(combined)
    all_failed = bool(results) and all(not r.ok for r in results)
    if all_failed and not got_any_data:
        # Aracın kendi hata nedenini (bağlantı yok / anonim bind reddedildi /
        # kimlik hatası) çıkar; yoksa ilk run'ın hata alanına düş.
        reason = ""
        err_line = _grep(combined, r"^\s*\[!\].*", context=0)
        if err_line:
            reason = err_line.splitlines()[0].strip()
        if not reason:
            first = results[0]
            reason = first.error or "çalıştırılamadı (çıktı üretilmedi)"
        report.add_error(f"windapsearch: {reason}")
        return

    # Anonim bind ile veri çekilebildi mi? (kimlik verilmeden sonuç geldiyse)
    used_creds = any("-u" in r.argv for r in results)
    got_data = _has_results(combined)
    if not used_creds and got_data:
        report.add(
            Finding(
                title="Anonim LDAP bind ile enumerasyon mümkün",
                severity=Severity.HIGH,
                target=target,
                source="windapsearch",
                description="Kimlik bilgisi olmadan LDAP'tan kullanıcı/grup bilgisi okunabildi.",
                evidence=_grep(combined, r"^[ \t]*sAMAccountName:", context=0),
                remediation="Anonim LDAP bind'i kapatın (dsHeuristics).",
                reference="Anonymous LDAP bind",
                poc=f"windapsearch --dc-ip {target} -U   # kimliksiz kullanıcı listesi",
                escalation=f"Kullanıcıları çıkar -> password spraying: 'adscan {target} --spray "
                "--spray-userlist users.txt --spray-passwords 123456,Password1'.",
            )
        )

    # Domain Admin sayısı
    da_block = strip_dryrun(next((r.combined for r in results if "windap-da" in r.tool), ""))
    da_users = re.findall(r"sAMAccountName:\s*(\S+)", da_block)
    if da_users:
        for u in da_users:
            if u not in report.da_members:
                report.da_members.append(u)
        sev = Severity.MEDIUM if len(da_users) > 5 else Severity.INFO
        report.add(
            Finding(
                title=f"Domain Admins üyeleri listelendi ({len(da_users)} hesap)",
                severity=sev,
                target=target,
                source="windapsearch",
                description="Domain Admins grubu üyeleri. Çok sayıda DA = geniş saldırı yüzeyi.",
                evidence="\n".join(da_users[:30]),
                remediation="DA üyeliklerini en aza indirin; tiered admin modeli uygulayın.",
                poc=f"windapsearch --dc-ip {target} -u <user>@<domain> -p <pass> --da",
                escalation="Bu DA hesaplarını kerberoast/AS-REP/spray hedefi yap; biri "
                "ele geçerse domain tamamen düşer.",
            )
        )

    # Unconstrained delegation'lı hesaplar
    unc_block = strip_dryrun(next((r.combined for r in results if "unconstrained" in r.tool), ""))
    unc = re.findall(r"sAMAccountName:\s*(\S+)", unc_block)
    if unc:
        report.add(
            Finding(
                title=f"Unconstrained delegation'lı hesap(lar) ({len(unc)})",
                severity=Severity.HIGH,
                target=target,
                source="windapsearch",
                description="Bu hesaplar ele geçirilirse DC taklidi ile tam domain ele geçirilebilir.",
                evidence="\n".join(unc[:30]),
                remediation="Unconstrained delegation'ı kaldırın; constrained/RBCD kullanın.",
                reference="Kerberos Unconstrained Delegation",
                poc=f"windapsearch --dc-ip {target} --unconstrained-users",
                escalation="Bu host ele geçerse: printerbug/PetitPotam ile DC'yi auth'a zorla, "
                "DC TGT yakala (Rubeus/krbrelayx) -> DCSync (Domain Admin).",
            )
        )

    # Kullanıcı sayımı (bilgi)
    users_block = strip_dryrun(next((r.combined for r in results if "windap-users" in r.tool), ""))
    all_users = re.findall(r"sAMAccountName:\s*(\S+)", users_block)
    if all_users:
        report.add(
            Finding(
                title=f"Toplam {len(all_users)} kullanıcı enumere edildi",
                severity=Severity.INFO,
                target=target,
                source="windapsearch",
                evidence="\n".join(all_users[:40]),
                poc=f"windapsearch --dc-ip {target} -U",
                escalation="Kullanıcı listesini users.txt'e kaydet -> password spraying "
                "(--spray) ve AS-REP roasting için girdi.",
            )
        )


# ---------------------------------------------------------------------------
# Registry adaptörü + kaydı
# ---------------------------------------------------------------------------

from ..registry import ScanContext, ScanModule  # noqa: E402


def _run(ctx: ScanContext) -> list[CommandResult]:
    return scan(ctx.target, domain=ctx.domain, username=ctx.username,
                password=ctx.password, timeout=ctx.timeout, dry_run=ctx.dry_run)


MODULE = ScanModule(
    name="windapsearch",
    label="windapsearch LDAP enumerasyonu",
    run=_run,
    parse=parse,
    requires_creds=False,
)

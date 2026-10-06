"""MSSQL enumerasyonu/privesc (netexec mssql) — AD'de çok yaygın yanal/privesc yolu.

Geçerli kimlikle MSSQL'e bağlanır ve:
  * oturum açılabiliyor mu (geçerli DB kimliği),
  * sysadmin / impersonation (EXECUTE AS) mümkün mü (`-M mssql_priv`),
ölçer. sysadmin veya impersonation -> `xp_cmdshell` ile SYSTEM = host ele geçirme.
Komut çalıştırma (`-x/-X`) OTOMATİK yapılmaz; PoC olarak gösterilir.

Kimlik gerektirir (login auth); yoksa modül kendini atlar. opt-in.
"""

from __future__ import annotations

import re

from ..findings import Finding, ScanReport, Severity
from ..runner import CommandResult, ToolStatus, run, strip_dryrun
from ..util import grep as _grep
from . import nxc_scan

MSSQL_PORT_HINT = 1433


def tool() -> ToolStatus:
    return nxc_scan.tool()  # netexec (nxc) tek araç; mssql alt protokolü


def _auth(username, password, nthash, domain, local_auth):
    args = ["-u", username or ""]
    if nthash:
        args += ["-H", nthash]
    else:
        args += ["-p", password or ""]
    if local_auth:
        args += ["--local-auth"]
    elif domain and username:
        args += ["-d", domain]
    return args


def scan(target, *, domain=None, username=None, password=None, nthash=None,
         local_auth=False, timeout=300, dry_run=False):
    if username is None or not (password or nthash):
        return [CommandResult(tool="mssql:skip", argv=[], returncode=None, stdout="",
                              stderr="", duration=0.0,
                              error="mssql: kimlik gerekli (login auth ister)")]
    bin_name = tool().name
    base = [bin_name, "mssql", target] + _auth(username, password, nthash, domain, local_auth)
    links_q = ("SELECT name, product, is_rpc_out_enabled FROM sys.servers "
               "WHERE is_linked = 1")
    return [
        run(base, tool="mssql-login", timeout=timeout, dry_run=dry_run),
        run(base + ["-M", "mssql_priv"], tool="mssql-priv", timeout=timeout, dry_run=dry_run),
        run(base + ["-q", links_q], tool="mssql-links", timeout=timeout, dry_run=dry_run),
    ]


# MSSQL durum/başlık satırları ve banner — linked-server verisi DEĞİL (FP guard)
_MSSQL_NOISE_RX = re.compile(
    r"\[[\-*+!]\]|is_rpc_out_enabled|^name\b|pwn3d|running|protocol|\bNone\b",
    re.IGNORECASE)


def _linked_servers(combined: str) -> list[str]:
    """mssql-links sorgu çıktısından GERÇEK linked-server satırlarını süzer.

    nxc satır düzeni: 'MSSQL  host  1433  SQLHOST  <veri>'. Status/başlık/banner
    satırları ve kendi instance adı elenir; yalnızca veri satırları kalır.
    """
    rows: list[str] = []
    for ln in combined.splitlines():
        m = re.match(r"^MSSQL\s+\S+\s+\d+\s+\S+\s+(.+?)\s*$", ln)
        if not m:
            continue
        payload = m.group(1).strip()
        if not payload or _MSSQL_NOISE_RX.search(payload):
            continue
        rows.append(payload)
    # tekilleştir, sırayı koru
    seen: set[str] = set()
    out: list[str] = []
    for r in rows:
        if r.lower() not in seen:
            seen.add(r.lower())
            out.append(r)
    return out


def parse(results: list[CommandResult], report: ScanReport) -> None:
    report.raw_outputs["mssql"] = "\n\n".join(r.combined for r in results)
    combined = strip_dryrun("\n\n".join(r.combined for r in results))
    target = report.target

    first = results[0] if results else None
    if first and first.tool == "mssql:skip":
        return
    if first and not first.ok:
        report.add_error(f"mssql: {first.error or 'çalıştırılamadı'}")
        return

    if "[+]" not in combined:
        return  # login başarısız / port kapalı

    # Linked server'lar: 'EXECUTE ... AT [link]' ile komşu SQL sunuculara yanal hareket.
    links_out = strip_dryrun(next(
        (r.combined for r in results if r.tool == "mssql-links"), ""))
    links = _linked_servers(links_out)
    if links:
        report.add(Finding(
            title=f"MSSQL linked server(lar) ({len(links)}) — yanal hareket (EXECUTE AT)",
            severity=Severity.HIGH, target=target, source="mssql",
            description="Bu MSSQL örneği başka SQL sunucularına 'linked server' ile bağlı. "
                        "RPC out açıksa 'EXECUTE (...) AT [link]' ile komşu sunucuda sorgu/komut "
                        "çalıştırılabilir; linked-server zinciri çoğu zaman daha yüksek yetkili "
                        "(sysadmin) bir bağlama sıçratır.",
            evidence="\n".join(links[:25]),
            remediation="Gereksiz linked server'ları kaldırın; RPC out'u kapatın; bağlantı için "
                        "en az yetkili hesap kullanın.",
            reference="MSSQL Linked Servers (lateral movement)", mitre="T1210",
            poc=f"nxc mssql {target} -u <user> -p <pass> "
                "-q 'SELECT name FROM sys.servers WHERE is_linked=1'",
            escalation="Zinciri izle: EXEC ('SELECT IS_SRVROLEMEMBER(''sysadmin'')') AT [LINK]; "
                       "sysadmin'e ulaşınca linked üzerinden xp_cmdshell -> SYSTEM."))

    sysadmin = bool(re.search(r"sysadmin|is a sysadmin|\(Pwn3d!\)", combined, re.IGNORECASE))
    impersonate = bool(re.search(r"impersonate|execute as|EXECUTE AS", combined, re.IGNORECASE))

    if sysadmin or impersonate:
        report.add(Finding(
            title="MSSQL sysadmin / impersonation — host SYSTEM'e yükseltilebilir",
            severity=Severity.CRITICAL, target=target, source="mssql",
            description="MSSQL'de sysadmin veya EXECUTE AS ile yetki yükseltme mümkün; "
                        "xp_cmdshell etkinleştirilerek sunucuda SYSTEM olarak komut çalışır.",
            evidence=_grep(combined, r"sysadmin|impersonate|execute as|Pwn3d", context=0),
            remediation="Servis hesabı yetkilerini kıs (en az yetki); xp_cmdshell'i kapat; "
                        "impersonation izinlerini kaldır; MSSQL'i güncel tut.",
            reference="MSSQL privesc / xp_cmdshell",
            poc=f"nxc mssql {target} -u <user> -p <pass> -M mssql_priv",
            escalation=f"Komut çalıştır: nxc mssql {target} -u <user> -p <pass> -x 'whoami' "
                       "(xp_cmdshell) -> SYSTEM; linked server'lar varsa "
                       "'EXECUTE ... AT [linked]' ile başka sunuculara sıçra."))
    else:
        report.add(Finding(
            title="Geçerli MSSQL kimliği — oturum açıldı",
            severity=Severity.MEDIUM, target=target, source="mssql",
            description="MSSQL'e geçerli kimlikle bağlanıldı. Veri erişimi ve linked "
                        "server / privesc denemeleri için başlangıç noktası.",
            evidence=_grep(combined, r"\[\+\]|mssql", context=0),
            remediation="Gereksiz DB erişimlerini kaldırın; güçlü parola politikası uygulayın.",
            reference="MSSQL valid credentials",
            poc=f"nxc mssql {target} -u <user> -p <pass>",
            escalation=f"Privesc dene: -M mssql_priv; linked servers: nxc mssql {target} "
                       "-u <user> -p <pass> -q 'SELECT name FROM sys.servers'."))


# ---------------------------------------------------------------------------
from ..registry import ScanContext, ScanModule  # noqa: E402


def _run(ctx: ScanContext) -> list[CommandResult]:
    return scan(ctx.target, domain=ctx.domain, username=ctx.username,
                password=ctx.password, nthash=ctx.nthash,
                timeout=ctx.timeout, dry_run=ctx.dry_run)


MODULE = ScanModule(
    name="mssql",
    label="netexec MSSQL enum/privesc (opt-in, kimlik gerektirir)",
    run=_run,
    parse=parse,
    requires_creds=True,
    optin=True,
)

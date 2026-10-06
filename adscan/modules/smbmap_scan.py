"""smbmap ile SMB paylaşım yetkilerini çıkarma (null session dahil).

"Hangi paylaşımlarda READ/WRITE yetkimiz var?" sorusunu yanıtlar. nxc --shares'e
göre daha ayrıntılı izin tablosu verir ve null/anonim oturumda erişilebilir
paylaşımları net gösterir. C$/ADMIN$ üzerinde WRITE = fiilî yerel admin; SYSVOL
okunabiliyorsa GPP (cpassword) avı için işaret bırakır.
"""

from __future__ import annotations

import re

from ..findings import Finding, ScanReport, Severity
from ..runner import CommandResult, ToolStatus, resolve_tool, run, strip_dryrun
from ..util import grep as _grep

SMBMAP_CANDIDATES = ["smbmap"]

# smbmap izin satırı:  "  C$                 READ, WRITE  Default share"
_SHARE_RX = re.compile(
    r"^\s*(\S.*?)\s{2,}(NO ACCESS|READ ONLY|READ, WRITE|WRITE ONLY)\b",
    re.MULTILINE,
)
_DEFAULT_SHARES = {"ADMIN$", "IPC$", "print$"}


def tool() -> ToolStatus:
    return resolve_tool(SMBMAP_CANDIDATES)


def scan(
    target: str,
    *,
    domain: str | None = None,
    username: str | None = None,
    password: str | None = None,
    nthash: str | None = None,
    timeout: int = 300,
    dry_run: bool = False,
) -> list[CommandResult]:
    bin_name = tool().name
    auth: list[str] = []
    if username is not None:
        auth += ["-u", username]
        if nthash:
            auth += ["-p", f"aad3b435b51404eeaad3b435b51404ee:{nthash}"]  # PtH biçimi
        else:
            auth += ["-p", password if password is not None else ""]
        if domain:
            auth += ["-d", domain]
    else:
        # null/anonim oturum
        auth += ["-u", "", "-p", ""]

    argv = [bin_name, "-H", target] + auth
    return [run(argv, tool="smbmap", timeout=timeout, dry_run=dry_run)]


def parse(results: list[CommandResult], report: ScanReport) -> None:
    report.raw_outputs["smbmap"] = "\n\n".join(r.combined for r in results)
    combined = strip_dryrun("\n\n".join(r.combined for r in results))
    target = report.target

    first = results[0] if results else None
    if first and not first.ok:
        report.add_error(f"smbmap: {first.error or 'çalıştırılamadı'}")
        return

    used_creds = any("-u" in r.argv and r.argv[r.argv.index("-u") + 1]
                     for r in results)

    shares = [(name.strip(), perm) for name, perm in _SHARE_RX.findall(combined)]
    readable = [(n, p) for n, p in shares if p != "NO ACCESS"]
    writable = [(n, p) for n, p in shares if "WRITE" in p]
    admin_write = [(n, p) for n, p in writable if n.upper() in ("C$", "ADMIN$")]

    if not readable:
        return

    # 1) Null/anonim oturumda erişilebilir paylaşım — kimliksiz veri sızıntısı
    if not used_creds:
        report.add(Finding(
            title=f"Null/anonim SMB oturumunda {len(readable)} paylaşıma erişim — smbmap",
            severity=Severity.HIGH, target=target, source="smbmap",
            description="Kimlik bilgisi olmadan paylaşımlar listelenip okunabiliyor.",
            evidence="\n".join(f"{n}: {p}" for n, p in readable[:30]),
            remediation="Anonim/null erişimi kapatın; paylaşım ACL'lerini sıkılaştırın.",
            reference="Null Session / SMB shares",
            poc=f"smbmap -H {target} -u '' -p ''",
            escalation=f"İçeriğe gir: 'smbmap -H {target} -u \"\" -p \"\" -r <share>' ile "
                       "özyinelemeli tara; SYSVOL'de GPP cpassword, konfig/yedeklerde parola ara."))

    # 2) Yazılabilir paylaşımlar (yanal hareket / kalıcılık / GPP)
    if writable:
        sev = Severity.CRITICAL if admin_write else Severity.MEDIUM
        extra = ("  C$/ADMIN$ üzerinde WRITE = fiilî yerel admin!"
                 if admin_write else "")
        report.add(Finding(
            title=f"Yazılabilir SMB paylaşım(lar)ı: {len(writable)} — smbmap{extra}",
            severity=sev, target=target, source="smbmap",
            description="Yazma yetkisi; dosya yerleştirme (SCF/LNK ile hash yakalama), "
                        "kalıcılık ve veri değişikliği için kullanılabilir." + extra,
            evidence="\n".join(f"{n}: {p}" for n, p in writable[:30]),
            remediation="Yazma ACL'lerini en az yetki ilkesine göre kısıtlayın.",
            reference="Writable Share / Lateral Movement",
            poc=f"smbmap -H {target} -u <user> -p <pass>   # WRITE sütununa bak",
            escalation=("C$/ADMIN$ WRITE: secretsdump/psexec ile SYSTEM; "
                        if admin_write else
                        "Yazılabilir paylaşıma SCF/LNK koy -> gelen NetNTLM'i relay/crack; ")
                       + "SYSVOL yazılabilirse GPO suistimali."))

    # 3) SYSVOL / NETLOGON okunur -> GPP cpassword avı
    if any(n.upper() in ("SYSVOL", "NETLOGON") for n, _ in readable):
        report.add(Finding(
            title="SYSVOL/NETLOGON okunabiliyor — GPP (cpassword) avı mümkün",
            severity=Severity.MEDIUM, target=target, source="smbmap",
            description="SYSVOL'deki Group Policy Preferences dosyalarında (Groups.xml vb.) "
                        "AES ile şifreli cpassword bulunabilir; anahtar herkese açıktır.",
            evidence=_grep(combined, r"SYSVOL|NETLOGON", context=0),
            remediation="MS14-025'i uygulayın; SYSVOL'deki eski GPP cpassword'leri temizleyin.",
            reference="GPP cpassword / MS14-025",
            poc=f"smbmap -H {target} -u <user> -p <pass> -r SYSVOL --depth 10 | grep -i xml",
            escalation="Groups.xml'deki cpassword'ü 'gpp-decrypt' ile çöz -> genelde yerel "
                       "admin parolası -> --reuse ile yanal hareket."))


# ---------------------------------------------------------------------------
# Registry adaptörü + kaydı
# ---------------------------------------------------------------------------

from ..registry import ScanContext, ScanModule  # noqa: E402


def _run(ctx: ScanContext) -> list[CommandResult]:
    return scan(ctx.target, domain=ctx.domain, username=ctx.username,
                password=ctx.password, nthash=ctx.nthash,
                timeout=ctx.timeout, dry_run=ctx.dry_run)


MODULE = ScanModule(
    name="smbmap",
    label="smbmap paylaşım yetkileri (null session dahil)",
    run=_run,
    parse=parse,
    requires_creds=False,
)

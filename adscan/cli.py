"""adscan — Active Directory pentest yardımcı orkestratörü.

nmap (SMB/LDAP/RDP zafiyet taraması) + netexec (nxc smb/ldap) + windapsearch
araçlarını tek komutla çalıştırır, çıktıları ayrıştırır ve risk seviyesine
göre terminal + JSON + Markdown rapor üretir.

!!! YALNIZCA sahip olduğunuz veya YAZILI test izniniz olan sistemlerde kullanın.
"""

from __future__ import annotations

import argparse
import getpass
import glob
import ipaddress
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

# Windows konsolunda (cp1254 vb.) Unicode karakterler için UTF-8'e geç
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

from . import (
    aclgraph,
    aclpwn,
    bhpath,
    cleanup,
    config,
    correlate,
    crack,
    escalate,
    export,
    guide,
    harvest,
    krbtime,
    mitre,
    nxcdb,
    pocfill,
    progress,
    sweep,
)
from . import chain as chaining
from . import live as live_ui
from . import report as reporting
from .assessment import record_results
from .findings import Credential, Finding, ScanReport, Severity
from .modules import nxc_scan, spray_scan, windap_scan
from .registry import ScanContext, get_module, noise_of, plan_modules, select_modules
from .runner import impacket_status, resolve_tool

CONSENT_TEXT = (
    "Bu araç aktif tarama yapar. Yalnızca sahibi olduğunuz ya da YAZILI izniniz "
    "olan hedeflerde çalıştırın.\nDevam etmek için 'evet' yazın: "
)

ACTIVE_CONSENT_TEXT = (
    "\n*** DİKKAT: AKTİF SALDIRI MODU ***\n"
    "Password spraying hesapları KİLİTLEYEBİLİR; poisoning/relay BAŞKA kullanıcıların\n"
    "kimlik bilgilerini YAKALAR ve relay eder. Bu işlemler üretim ağında hizmet\n"
    "kesintisine ve yasal sonuçlara yol açabilir.\n"
    "Yalnızca kontrollü, YAZILI izinli lab/engagement ortamında devam edin.\n"
    "Onaylıyorsanız aynen 'yetkiliyim' yazın: "
)


def tool_check() -> None:
    """Gerekli araçların kurulu olup olmadığını gösterir."""
    print("Araç durumu:")
    from .modules import bloodhound_scan, bloodyAD_scan, certipy_scan, smbmap_scan
    checks = [
        ("nmap", resolve_tool(["nmap"])),
        ("netexec (nxc)", nxc_scan.tool()),
        ("windapsearch", windap_scan.tool()),
        ("smbmap", smbmap_scan.tool()),
        ("certipy (ADCS)", certipy_scan.tool()),
        ("bloodyAD (ACL privesc)", bloodyAD_scan.tool()),
        ("bloodhound-python", resolve_tool(bloodhound_scan.BH_PY_CANDIDATES)),
        ("kerbrute (userenum/spray)", resolve_tool(["kerbrute"])),
        ("impacket (relay/secretsdump)", impacket_status()),
        ("pygpoabuse (GPO abuse)", resolve_tool(["pygpoabuse", "pygpoabuse.py"])),
        ("mitm6 (IPv6 poisoning)", resolve_tool(["mitm6"])),
        ("responder (LLMNR/NBT-NS)", resolve_tool(["responder", "Responder"])),
        ("proxychains (pivot)", resolve_tool(["proxychains4", "proxychains"])),
        ("hashcat (kırma)", resolve_tool(["hashcat"])),
        ("john (kırma, yedek)", resolve_tool(["john"])),
    ]
    # Sürüm tespiti (F): kurulu araçların sürümünü ve nxc modüllerini sapta.
    from . import capabilities as _cap
    _ver = {
        "nmap": lambda: _cap.tool_version("nmap"),
        "netexec (nxc)": lambda: _cap.tool_version(
            "nxc", candidates=["nxc", "netexec", "crackmapexec", "cme"]),
        "certipy (ADCS)": lambda: _cap.tool_version(
            "certipy", candidates=["certipy", "certipy-ad"]),
        "bloodyAD (ACL privesc)": lambda: _cap.tool_version(
            "bloodyAD", candidates=["bloodyAD", "bloodyad"]),
    }
    for label, status in checks:
        mark = "OK" if status.available else "--"
        extra = f" -> {status.path}" if status.path else f"  ({status.note})"
        ver = _ver.get(label, lambda: None)() if status.available else None
        vtxt = f"  (v{ver})" if ver else ""
        print(f"  [{mark}] {label}{vtxt}{extra}")
    # nxc modül yetenekleri: sürüm kayması sessiz başarısızlık yaratmasın
    nxc_mods = _cap.nxc_modules()
    if nxc_mods:
        want = ["coerce_plus", "zerologon", "maq", "pre2k", "timeroast",
                "nopac", "enum_trusts", "laps", "adcs"]
        present = [m for m in want if m in nxc_mods]
        missing = [m for m in want if m not in nxc_mods]
        print(f"  [i ] nxc modülleri: var={', '.join(present) or '-'}")
        if missing:
            print(f"       yok/eski ad={', '.join(missing)} "
                  "(bu sürümde farklı adla olabilir)")
    # Sözlük durumu (kırma için)
    wl = crack.default_wordlist()
    if wl:
        print(f"  [OK] sözlük -> {wl}")
    else:
        print("  [--] sözlük  (bulunamadı; --wordlist ile verin, ör. rockyou.txt)")
    print()


def _resolve_password(args) -> str | None:
    """Parolayı güvenli biçimde çözer.

    Öncelik: --ask-pass veya '-p -'  ->  gizli giriş (getpass)
             ADSCAN_PASSWORD ortam değişkeni (eğer -p verilmediyse)
             -p <değer>  ->  kullanılır ama process list'te görüneceği uyarılır.
    """
    if args.ask_pass or args.password == "-":
        return getpass.getpass("AD parolası (gizli): ")
    if args.password is None:
        env_pw = os.environ.get("ADSCAN_PASSWORD")
        if env_pw:
            print("[i] Parola ADSCAN_PASSWORD ortam değişkeninden alındı.")
            return env_pw
        return None
    # Düz -p ile verildi: işletim sisteminin process listesinde görünebilir.
    print(
        "[!] Uyarı: parola komut satırında verildi; sistemdeki process "
        "listesinde görünebilir. Daha güvenlisi: --ask-pass veya ADSCAN_PASSWORD."
    )
    return args.password


def _run_autopilot(args, ctx, report, password) -> None:
    """Otonom zincir: enum -> kullanıcı keşfi -> spray -> Domain Admin yükseltme.

    Her aşama bir öncekinin çıktısını besler. Spray kilitlenme-farkındadır;
    yükseltme motoru (escalate) eldeki kimlikleri host'larda dener, admin olunan
    host'larda secrets döker ve DC'de DCSync ile Domain Admin'e ulaşmayı dener.
    Tüm fazlar tek canlı UI'da akar.
    """
    # 0) CLI'den gelen kimliği + otomatik tespit edilen domain'i havuza/bağlama kat
    if args.username and (password or args.nthash):
        report.add_credential(Credential(
            username=args.username, secret=args.nthash or password,
            kind="nthash" if args.nthash else "password",
            domain=args.domain or report.domain or "", source="cli"))
    if report.domain and not ctx.domain:
        ctx.domain = report.domain

    # Parola-tekrarı süpürmesi parolasını Live UI BAŞLAMADAN sor (spinner çakışmasın)
    sweep_pw = _ask_sweep_password(reporting._supports_color())

    ui = live_ui.Live(total=4).start()
    progress.set_sink(_make_sink(ui))
    try:
        # 1) Kullanıcı + host keşfi
        ui.log(_phase("AUTOPILOT 1/4 — kullanıcı & host keşfi", ui.color))
        users, hosts = harvest.harvest(report)
        extra = f", domain: {report.domain}" if report.domain else ""
        ui.log(f"    keşfedilen: {len(users)} kullanıcı, {len(hosts)} host{extra}")
        if users:
            users_path = os.path.join(args.outdir, "autopilot-users.txt")
            try:
                with open(users_path, "w", encoding="utf-8") as fh:
                    fh.write("\n".join(users))
                ui.log(f"    kullanıcı listesi → {users_path}")
            except OSError:
                pass
        ui.advance()
        _push_stats(ui, report)

        # 2) Password spraying (kilitlenme-farkında)
        ui.log(_phase("AUTOPILOT 2/4 — password spraying (kilitlenme-farkında)", ui.color))
        pws = (args.auto_passwords.split(",") if args.auto_passwords
               else (ctx.spray_passwords or spray_scan.DEFAULT_SPRAY_PASSWORDS))
        if users and pws:
            ctx.spray_users = users
            ctx.spray_passwords = [p for p in pws if p]
            spray_mod = get_module("spray")
            n0 = len(report.findings)
            spray_mod.parse(spray_mod.run(ctx), report)
            pocfill.fill(report)  # spray kimliği bulundu -> PoC'leri gerçek değerle doldur
            for f in sorted(report.findings[n0:], key=lambda x: x.severity, reverse=True):
                ui.log(reporting.render_finding(f, color=ui.color))
            if len(report.findings) == n0:
                ui.log("    (spray geçerli kimlik üretmedi)")
        else:
            ui.log("    spray atlandı (kullanıcı bulunamadı).")
        ui.advance()
        _push_stats(ui, report)

        # 3) ACL suistimali: reanimation + parola-tekrarı + ACL kısa-yol (DA'ya yol bul/yürü)
        ui.log(_phase("AUTOPILOT 3/4 — ACL suistimali (reanimation / parola / kısa-yol)",
                      ui.color))
        aclpwn.run(ctx, report, ui=ui, sweep_pw=sweep_pw)
        aclgraph.analyze(ctx, report, ui=ui, exploit=True)  # DA'ya ACL yolunu bul ve yürü
        bhpath.analyze(report, ui=ui)  # toplanan BloodHound grafiğinden en kısa yol
        pocfill.fill(report)
        ui.advance()
        _push_stats(ui, report)

        # 4) Domain Admin yükseltme motoru
        ui.log(_phase("AUTOPILOT 4/4 — Domain Admin yükseltme zinciri", ui.color))
        ctx.found_credentials = list(report.credentials)
        if not ctx.reuse_targets:
            ctx.reuse_targets = args.reuse_targets or (
                ",".join(hosts) if hosts else args.target)
        escalate.run_to_da(ctx, report, ui=ui)
        ui.advance()
        _push_stats(ui, report)
    finally:
        progress.set_sink(None)
        ui.stop()


def _run_brain_autopilot(args, ctx, report, password) -> None:
    """LLM-güdümlü otonom mod: her turda Ollama bir sonraki modülü seçer.

    Sabit 4-fazlı --auto yerine, mevcut bulgu durumuna bakıp registry
    whitelist'inden modül seçtiren bir ajan döngüsü. Model yalnızca SEÇER;
    gerçek komutu runner kurar (bkz. brain.py güvenlik ilkesi). Aktif modüller
    yalnızca --brain-active ile aday olur ve yine kendi --launch kapısına tabidir.
    """
    from . import brain as brain_mod

    # Kimliği havuza + domain'i bağlama kat (autopilot ile aynı başlangıç)
    if args.username and (password or args.nthash):
        report.add_credential(Credential(
            username=args.username, secret=args.nthash or password,
            kind="nthash" if args.nthash else "password",
            domain=args.domain or report.domain or "", source="cli"))
    if report.domain and not ctx.domain:
        ctx.domain = report.domain

    brain = brain_mod.OllamaBrain(
        url=args.ollama_url, model=args.ollama_model, timeout=args.ollama_timeout,
        keep_alive=getattr(args, "ollama_keep_alive", "30m"),
        quiet=getattr(args, "quiet", False))
    if getattr(args, "brain_bare_prompt", False):
        brain.system_prompt = None  # özel modelin gömülü SYSTEM'i devreye girsin
    trace_path = (getattr(args, "brain_trace", None)
                  or os.path.join(args.outdir, "brain-trace.jsonl"))

    ui = live_ui.Live(total=args.brain_max_steps).start()
    progress.set_sink(_make_sink(ui))
    try:
        if not args.dry_run and not brain.available():
            ui.log(_phase(f"BEYİN — Ollama erişilemiyor ({brain.url}); "
                          "deterministik zincire düşülecek", ui.color))
        elif not args.dry_run:
            # Modeli döngüden ÖNCE belleğe yükle: tur-içi kararlar soğuk-yükleme
            # gecikmesi yaşamasın (keep_alive ile sıcak kalır).
            if brain.warmup():
                ui.log(_phase(f"BEYİN — model sıcak ({brain.model}, "
                              f"keep_alive={brain.keep_alive})", ui.color))
        # 0) Ucuz keşif: beyne zengin başlangıç durumu ver
        harvest.harvest(report)
        _push_stats(ui, report)

        # escalate yeniden-seçim izi: en son escalate çalıştığındaki gizli-kimlik
        # sayısı. Yeni kimlik kazanılırsa escalate history'de olsa da tekrar aday olur.
        escalate_cred_mark = -1

        done = False
        for step in range(1, args.brain_max_steps + 1):
            exclude = set(brain.history)
            cur_secret = sum(1 for c in report.credentials
                             if getattr(c, "secret", None))
            if "escalate" in exclude and cur_secret > escalate_cred_mark:
                exclude.discard("escalate")  # yeni kimlik -> yeni yükseltme turu
            candidates = brain_mod.runnable_candidates(
                ctx, report, allow_active=args.brain_active,
                exclude=exclude)
            decision = brain.decide(report, ctx, candidates)
            tag = "ollama" if decision.source == "ollama" else "yedek"
            ui.log(_phase(f"BEYİN {step}/{args.brain_max_steps} [{tag}] — "
                          f"{decision.rationale}", ui.color))
            if decision.done or not decision.next_module:
                brain_mod.append_trace(trace_path, {
                    "step": step, "target": report.target, "model": brain.model,
                    "source": decision.source, "state": brain.last_snapshot,
                    "decision": {"next_module": None, "rationale": decision.rationale,
                                 "confidence": decision.confidence, "done": True},
                    "outcome": {"stopped": True, "domain_admin": report.domain_admin}})
                done = True
                break

            mod = get_module(decision.next_module)
            if mod.active:
                ui.log("    ⚠ AKTİF modül (ağa müdahale; --launch planı/yürütmeyi belirler)")
            ui.log(f"    → {mod.name} ({mod.label}) · güven={decision.confidence:.2f}")
            brain.history.append(mod.name)
            n0 = len(report.findings)
            c0 = len(report.credentials)
            run_err = ""
            # Beyin belirli bir host seçtiyse (known_hosts whitelist'inden; decide()
            # doğruladı) modülü o host'a yönelt; tur sonunda eski hedefe dön.
            prev_target = ctx.target
            if decision.target and decision.target != ctx.target:
                ctx.target = decision.target
                ui.log(f"    → hedef host: {ctx.target} (beyin seçimi)")
            try:
                if mod.name == "escalate":
                    # Otonom kimlik→Domain Admin zinciri. run/parse sözleşmesine
                    # sığmaz (ctx + report birlikte gerekir), bu yüzden burada
                    # doğrudan yürütülür. --launch verilmediyse gerçek komut
                    # ÇALIŞMAZ; yalnızca plan (dry-run) gösterilir (aktif modül kapısı).
                    from . import escalate as escalate_mod
                    prev_dry = ctx.dry_run
                    if not ctx.launch:
                        ctx.dry_run = True
                        ui.log("    (escalate: --launch yok → PLAN modu; "
                               "gerçek yükseltme için --brain-active --launch)")
                    try:
                        escalate_mod.run_to_da(ctx, report, ui=ui)
                    finally:
                        ctx.dry_run = prev_dry
                    # Bu turdaki gizli-kimlik sayısını işaretle: yeni kimlik gelmezse
                    # escalate tekrar seçilmez (sonsuz döngü yok); gelirse yeni tur.
                    escalate_cred_mark = sum(1 for c in report.credentials
                                             if getattr(c, "secret", None))
                else:
                    mod.parse(mod.run(ctx), report)
            except Exception as exc:  # modül patlasa da döngü sürsün
                run_err = str(exc)
                report.add_error(f"{mod.name}: {exc}")
                ui.log(f"    modül hata verdi: {exc}")
            finally:
                ctx.target = prev_target  # geçici hedef değişimini geri al
            pocfill.fill(report)
            for f in sorted(report.findings[n0:], key=lambda x: x.severity,
                            reverse=True):
                ui.log(reporting.render_finding(f, color=ui.color))
            if len(report.findings) == n0:
                ui.log("    (yeni bulgu yok)")
            ui.advance()
            _push_stats(ui, report)
            # Yeni kimlik/kullanıcı sonraki tura beslensin
            harvest.harvest(report)
            ctx.found_credentials = list(report.credentials)
            brain_mod.append_trace(trace_path, {
                "step": step, "target": report.target, "model": brain.model,
                "source": decision.source, "state": brain.last_snapshot,
                "decision": {"next_module": mod.name, "rationale": decision.rationale,
                             "confidence": decision.confidence, "done": False},
                "outcome": {"new_findings": len(report.findings) - n0,
                            "new_credentials": len(report.credentials) - c0,
                            "error": run_err, "domain_admin": report.domain_admin}})
            if report.domain_admin:
                done = True
                break
        if not done:
            ui.log(_phase(f"BEYİN — adım limiti ({args.brain_max_steps}) doldu",
                          ui.color))
    finally:
        progress.set_sink(None)
        ui.stop()


def _run_escalation_phase(args, ctx, report, password) -> None:
    """--assume-breach: eldeki kimlikle (spray yok) doğrudan DA yükseltme fazı."""
    if args.username and (password or args.nthash):
        report.add_credential(Credential(
            username=args.username, secret=args.nthash or password,
            kind="nthash" if args.nthash else "password",
            domain=args.domain or report.domain or "", source="cli"))
    if report.domain and not ctx.domain:
        ctx.domain = report.domain

    _, hosts = harvest.harvest(report)
    ctx.found_credentials = list(report.credentials)
    if not ctx.reuse_targets:
        ctx.reuse_targets = args.reuse_targets or (
            ",".join(hosts) if hosts else args.target)

    ui = live_ui.Live(total=1).start()
    progress.set_sink(_make_sink(ui))
    try:
        ui.log(_phase("ASSUME-BREACH — eldeki kimlikle Domain Admin yükseltme", ui.color))
        if report.domain:
            ui.log(f"    domain: {report.domain}"
                   + (f" · DC: {report.dc_name}" if report.dc_name else ""))
        aclgraph.analyze(ctx, report, ui=ui, exploit=True)  # ACL kısa-yolu bul ve yürü
        escalate.run_to_da(ctx, report, ui=ui)
        ui.advance()
        _push_stats(ui, report)
    finally:
        progress.set_sink(None)
        ui.stop()


def _run_crack_phase(args, ctx, report, color: bool) -> None:
    """Harvest edilen kerberoast/AS-REP hash'lerini kırar (autopilot/escalate'ten ÖNCE).

    Kırılan parolalar `report.credentials`'a eklenir; sonraki reuse/escalate/ACL
    fazları bunları doğrudan kullanır.
    """
    os.makedirs(args.outdir, exist_ok=True)
    ui = live_ui.Live(total=1).start()
    progress.set_sink(_make_sink(ui))
    try:
        ui.log(_phase("HASH KIRMA — kerberoast / AS-REP (çevrimdışı sözlük)", ui.color))
        _push_stats(ui, report)
        new = crack.crack_hashes(report, wordlist=args.wordlist,
                                 timeout=args.crack_timeout, dry_run=args.dry_run, ui=ui)
        ui.advance()
        _push_stats(ui, report)
    finally:
        progress.set_sink(None)
        ui.stop()
    if new:
        print(_c(f"  [crack] {len(new)} parola kırıldı ve zincire kimlik olarak eklendi.",
                 "green", color))


def _resolve_spray_passwords(args) -> list[str] | None:
    """--spray-passwords ve/veya --spray-passlist'ten parola listesi derler."""
    pws: list[str] = []
    if args.spray_passwords:
        pws += [p for p in args.spray_passwords.split(",") if p]
    if args.spray_passlist and os.path.isfile(args.spray_passlist):
        with open(args.spray_passlist, encoding="utf-8", errors="replace") as fh:
            pws += [ln.rstrip("\n") for ln in fh if ln.strip()]
    return pws or None


# ---------------------------------------------------------------------------
# Canlı çalıştırma: her modül biter bitmez sonucunu akıt + alt barı güncelle
# ---------------------------------------------------------------------------

# Modül çalışırken gösterilecek anlamlı durum satırları (worker thread'de yayınlanır)
_MODULE_PHASE = {
    "nmap": "AD portları + NSE zafiyet scriptleri taranıyor (1-3 dk sürebilir)",
    "nxc-smb": "SMB: oturum / paylaşım / parola politikası sorgulanıyor",
    "nxc-ldap": "LDAP: kerberoast / AS-REP / delegasyon sorgulanıyor",
    "nxc-vulns": "aktif zafiyet kontrolleri: zerologon / petitpotam / maq",
    "smbmap": "SMB paylaşım yetkileri çıkarılıyor (null session dahil)",
    "windapsearch": "LDAP: domain admin / ayrıcalıklı / delegasyon / kullanıcı çekiliyor",
    "spray": "password spraying (kilitlenme-farkında)",
    "relay": "poisoning / relay planı hazırlanıyor",
    "reuse": "kimlikler host'larda deneniyor (yanal hareket)",
}


def _make_sink(ui: live_ui.Live):
    """progress olaylarını canlı UI'a bağlar."""
    def sink(kind: str, module: str, text: str) -> None:
        if kind == "control":
            ui.observe_control(json.loads(text))
        elif kind == "cmd":
            # Çalışan komut: alttaki barda geçici olarak göster (günlüğü boğmamak için).
            from .assessment import LABELS
            ui.set_detail(text if config.TERMINAL_UI == "detailed" else LABELS.get(module, module))
        elif kind == "start":
            ui.log(f"  {_c('▸', 'dim', ui.color)} {text}")
        elif kind == "info":
            ui.log(f"    {_c('•', 'dim', ui.color)} {text}")
    return sink


def _push_stats(ui: live_ui.Live, report: ScanReport) -> None:
    """Rapordaki güncel bulgu/kimlik/DA/zincir durumunu canlı panele yansıtır."""
    counts = report.count_by_severity()
    ui.set_coverage(report.coverage)
    try:
        rows = chaining.evaluate(report)
        chain_done = sum(1 for _, ok in rows if ok)
        chain_total = len(rows)
    except Exception:
        chain_done = chain_total = 0
    ui.set_stats(
        CRITICAL=counts["CRITICAL"], HIGH=counts["HIGH"], MEDIUM=counts["MEDIUM"],
        LOW=counts["LOW"], INFO=counts["INFO"], creds=len(report.credentials),
        da=report.domain_admin, chain_done=chain_done, chain_total=chain_total)


_ANSI = {"dim": "\033[2m", "green": "\033[1;32m", "red": "\033[1;31m",
         "yellow": "\033[1;33m", "bold": "\033[1m", "reset": "\033[0m"}


def _c(text: str, key: str, color: bool) -> str:
    return f"{_ANSI[key]}{text}{_ANSI['reset']}" if color else text


def _phase(title: str, color: bool) -> str:
    """Autopilot faz başlığı (görsel ayraç)."""
    line = f"━━ {title} " + "━" * max(0, 60 - len(title))
    return f"\n{_ANSI['bold']}{line}{_ANSI['reset']}" if color else f"\n{line}"


_CLOCK_THRESHOLD = 60  # sn: bunun altındaki fark göz ardı edilir


def _setup_clock(args, color: bool) -> None:
    """DC ile saat farkını ölçer; gerekiyorsa tüm alt süreçleri faketime ile senkronlar.

    Kerberos (kerberoast / certipy PKINIT / shadow creds / -k) saat kaymasına
    duyarlıdır; sistem saatine dokunmadan yalnızca çocuk süreçleri DC'ye hizalar.
    """
    if getattr(args, "no_clock_fix", False):
        return
    host = args.target.split(",")[0].split("/")[0].strip()
    offset = krbtime.probe_offset(host)
    if offset is None or abs(offset) < _CLOCK_THRESHOLD:
        return  # ölçülemedi ya da zaten senkron
    env = krbtime.faketime_env(offset)
    if env:
        config.set_child_env(env)
        print(_c(f"  [saat] DC ile {offset:+.0f}s fark — Kerberos için faketime ile "
                 f"otomatik düzeltildi.", "green", color))
    else:
        target_epoch = int(time.time() + offset)
        print(_c(f"  [saat] UYARI: DC ile {offset:+.0f}s fark — Kerberos 'clock skew' "
                 f"verebilir. Düzeltme için: sudo apt install -y libfaketime  "
                 f"(ya da: sudo date -u -s @{target_epoch})", "yellow", color))


def _ask_sweep_password(color: bool) -> str | None:
    """Parola-tekrarı süpürmesi için parolayı gizli sorar (TTY değilse atlar)."""
    if not sys.stdin.isatty():
        return None
    try:
        pw = getpass.getpass(
            "  [pw-sweep] Tekrar denenecek parola (gizli; boş = bilinen parolalar): ")
        return pw or None
    except (EOFError, KeyboardInterrupt):
        return None


def _run_pw_sweep(args, ctx, report, color: bool) -> None:
    """Tek seferlik (autopilot dışı) parola-tekrarı süpürmesi: parolayı sorar ve dener."""
    users = [u for u in dict.fromkeys(report.users) if u]
    if not users:
        print(_c("  [pw-sweep] enumere edilmiş kullanıcı yok — önce enum çalışmalı "
                 "(kimlik ver ya da null/anonim enum).", "yellow", color))
        return
    pw = _ask_sweep_password(color)
    if not pw:
        print(_c("  [pw-sweep] parola girilmedi — atlandı.", "dim", color))
        return
    print(_c(f"  [pw-sweep] {len(users)} kullanıcıda deneniyor (kullanıcı başına tek deneme)…",
             "dim", color))
    new = sweep.sweep_password(ctx, report, pw, users=users)
    if new:
        for c in new:
            print(reporting.render_credential(c, color=color))
        print(_c(f"  [pw-sweep] {len(new)} kullanıcı bu parolayı tekrar kullanıyor!",
                 "green", color))
    else:
        print(_c("  [pw-sweep] eşleşme yok.", "dim", color))


def _print_dc_banner(report: ScanReport, target: str, color: bool) -> None:
    """DC host adı/FQDN tespit edildiyse EN GÖRÜNÜR biçimde gösterir.

    Amaç: IP ile uğraşmaya gerek kalmadan DC'nin FQDN'ini ve hazır bir /etc/hosts
    satırını hemen verebilmek (LDAP/Kerberos genelde FQDN ister).
    """
    if not report.dc_name:
        return
    ip = target.split(",")[0].split("/")[0].strip()
    domain = (report.domain or "").strip().lower()
    fqdn = f"{report.dc_name}.{domain}" if domain else report.dc_name
    show_ip = ip and ip.lower() != fqdn.lower()
    print()
    print(_c(f"  ►► DC: {fqdn}" + (f"   ({ip})" if show_ip else ""), "green", color))
    if domain:
        print(_c(f"     domain: {domain}", "dim", color))
        print(_c(f"     /etc/hosts:  echo '{ip} {fqdn} {report.dc_name}' "
                 "| sudo tee -a /etc/hosts", "dim", color))
    print()


def _prune_old_reports(outdir: str, safe_target: str, keep_base: str) -> list[str]:
    """Aynı hedefe ait ESKİ raporları siler; yalnızca yeni yazılanı bırakır.

    Dosya deseni: adscan-<hedef>-<zaman>.<uzantı>. Hedef sınırını sondaki '-'
    korur, böylece '10.0.0.5' hedefi '10.0.0.50' raporlarını silmez. Mevcut
    taramanın TÜM çıktıları (json/md/html + navigator/loot/graph/csv) korunur:
    bunların hepsi `keep_base` ön-ekini paylaşır.
    """
    removed: list[str] = []
    keep_prefix = os.path.abspath(keep_base)  # bu taramanın tüm dosyaları bununla başlar
    # Yalnızca rapor uzantılarını hedefle (loot/ gibi alt klasörlere dokunma)
    exts = (".json", ".md", ".html", ".csv")
    pattern = os.path.join(outdir, f"adscan-{safe_target}-*.*")
    for path in glob.glob(pattern):
        if not path.endswith(exts):
            continue
        if os.path.abspath(path).startswith(keep_prefix):
            continue  # bu taramaya ait (aynı zaman damgası) — koru
        try:
            os.remove(path)
            removed.append(path)
        except OSError:
            pass
    return removed


def _in_scope(target: str, scope_file: str) -> tuple[bool, str]:
    """Hedef(ler)in izinli kapsamda olup olmadığını kontrol eder.

    Kapsam dosyası: satır başına bir IP/CIDR/hostname (# ile yorum). Virgülle
    verilen çok hedefli taramada HER hedef kapsamda olmalıdır.
    """
    try:
        with open(scope_file, encoding="utf-8") as fh:
            entries = [ln.strip() for ln in fh
                       if ln.strip() and not ln.lstrip().startswith("#")]
    except OSError as exc:
        return False, f"kapsam dosyası okunamadı: {exc}"
    if not entries:
        return False, "kapsam dosyası boş"

    nets: list[ipaddress._BaseNetwork] = []
    hosts: list[str] = []
    for e in entries:
        try:
            nets.append(ipaddress.ip_network(e, strict=False))
        except ValueError:
            hosts.append(e.lower())

    for tok in (t.strip() for t in target.split(",") if t.strip()):
        try:
            requested = ipaddress.ip_network(tok, strict=False)
            if not any(requested.version == n.version and requested.subnet_of(n) for n in nets):
                return False, f"{tok} hiçbir izinli ağda değil"
        except ValueError:
            low = tok.lower()
            if not any(low == h for h in hosts):
                return False, f"{tok} izinli host listesinde değil"
    return True, ""


def _load_prior_report(outdir: str, safe_target: str, *, exclude: str = "") -> dict | None:
    """Aynı hedefin EN SON JSON raporunu (exclude hariç) yükler."""
    paths = sorted(glob.glob(os.path.join(outdir, f"adscan-{safe_target}-*.json")))
    paths = [p for p in paths if os.path.abspath(p) != os.path.abspath(exclude)]
    if not paths:
        return None
    try:
        with open(paths[-1], encoding="utf-8") as fh:
            data = json.load(fh)
        data["_path"] = paths[-1]
        return data
    except (OSError, ValueError):
        return None


def _resume_from(report: ScanReport, prior: dict) -> None:
    """Önceki rapordan kullanıcı/host/domain/kimlik bilgisini mevcut rapora taşır."""
    report.domain = report.domain or prior.get("domain", "")
    report.dc_name = report.dc_name or prior.get("dc_name", "")
    for u in prior.get("users", []):
        if u not in report.users:
            report.users.append(u)
    for h in prior.get("hosts", []):
        if h not in report.hosts:
            report.hosts.append(h)
    for c in prior.get("credentials", []):
        sec = c.get("secret", "")
        if sec and "***" not in sec:  # maskeli kimlik geri yüklenemez
            report.add_credential(Credential(
                username=c.get("username", ""), secret=sec,
                kind=c.get("kind", "password"), domain=c.get("domain", ""),
                source="resume", host=c.get("host", ""), admin=c.get("admin", False)))


def _diff_reports(report: ScanReport, prior: dict) -> tuple[list[str], list[str]]:
    """(yeni bulgu başlıkları, çözülen/kaybolan bulgu başlıkları) döndürür."""
    cur = {f.title for f in report.findings}
    old = {f.get("title", "") for f in prior.get("findings", [])}
    new = sorted(cur - old)
    resolved = sorted(old - cur)
    return new, resolved


def _debug_dump(report: ScanReport) -> None:
    """--debug: her modülün ham çıktı kuyruğunu ve tüm hataları dök."""
    print(f"\n{_ANSI['bold']}=== DEBUG: ham modül çıktıları (son 12 satır) ==={_ANSI['reset']}")
    for mod, out in report.raw_outputs.items():
        tail = [ln for ln in (out or "").splitlines() if ln.strip()][-12:]
        print(f"\n  --- {mod} ---")
        for ln in tail:
            print(f"    {ln}")
    if report.errors:
        print(f"\n{_ANSI['bold']}=== DEBUG: hatalar ==={_ANSI['reset']}")
        for e in report.errors:
            print(f"    ! {e}")


def _worker(mod, ctx, ui: live_ui.Live):
    """Thread havuzunda çalışan sarmalayıcı: başladı/bitti durumunu işaretler."""
    ui.set_running(mod.name)
    progress.emit("start", mod.name, f"{mod.label} başladı")
    phase = _MODULE_PHASE.get(mod.name)
    if phase:
        progress.emit("info", mod.name, phase)
    try:
        if ctx.checkpoint:
            with ctx.checkpoint.module(mod.name, not mod.active and not ctx.use_kerberos):
                return mod.run(ctx)
        return mod.run(ctx)
    finally:
        ui.set_running(mod.name, False)


def _attach_commands(results, report, n0: int) -> None:
    """Modülün çalıştırdığı gerçek komut(lar)ı, o modülün YENİ bulgularına iliştirir.

    Her modül `run()` sırasında bir veya daha çok `CommandResult` üretir; bunların
    `safe_cmd` (gerekirse maskeli) dizgesi, bulguyu DOĞRULAMA PoC'sinden farklı
    olarak adscan'in gerçekte çalıştırdığı komuttur. Bulguyu açıkça komut
    belirten (ör. nxc-db gibi sentetik) bulgular ezilmez.
    """
    cmds: list[str] = []
    for r in results or []:
        sc = getattr(r, "safe_cmd", "")
        if sc:
            cmds.append(sc)
    if not cmds:
        return
    joined = "\n".join(dict.fromkeys(cmds))  # sırayı koru, tekrarları ele
    for f in report.findings[n0:]:
        if not f.command:
            f.command = joined


def _finish_module(ui: live_ui.Live, mod, results, report) -> None:
    """Bir modül bitince: hemen ayrıştır ve SADECE o modülün bulgularını bas."""
    n0, c0 = len(report.findings), len(report.credentials)
    parse_failed = False
    try:
        mod.parse(results, report)
    except Exception as exc:  # ayrıştırma çökse de tarama sürsün
        parse_failed = True
        report.add_error(f"{mod.name}: ayrıştırma hatası: {exc}")
        if getattr(report, "checkpoint", None):
            report.checkpoint.invalidate(mod.name)
    record_results(report, mod.name, results, parse_failed=parse_failed,
                   findings=len(report.findings) > n0)
    incomplete = any(c["module"] == mod.name and c["status"] not in
                     {"completed", "findings", "not_applicable"} for c in report.coverage)
    ui.finish_module(mod.name, "hata" if parse_failed else "kısmi" if incomplete else "tamamlandı")
    if mod.name == "bloodyad" and not parse_failed:
        from .permissions import record_tool_results
        record_tool_results(results, report)
    _attach_commands(results, report, n0)  # her yeni bulguya onu üreten komutu iliştir
    pocfill.fill(report)  # PoC'lerdeki <user>/<pass>'i bilinen kimlikle doldur
    ui.advance()
    _push_stats(ui, report)

    new = sorted(report.findings[n0:], key=lambda f: f.severity, reverse=True)
    new_creds = report.credentials[c0:]
    el = f" {_c(f'· {ui.elapsed(mod.name):.1f}s', 'dim', ui.color)}"

    if new:
        top = max(f.severity for f in new)
        key = ("red" if top >= Severity.HIGH else
               "yellow" if top >= Severity.MEDIUM else "dim")
        brk = ", ".join(f"{s.label}:{sum(1 for f in new if f.severity == s)}"
                        for s in reversed(list(Severity))
                        if any(f.severity == s for f in new))
        ui.log(f"  {_c('✔', key, ui.color)} {mod.label} — {len(new)} bulgu ({brk}){el}")
        for f in new:
            ui.log(reporting.render_finding(f, color=ui.color))
    else:
        incomplete = any(c["module"] == mod.name and c["status"] not in
                         {"completed", "findings", "not_applicable"} for c in report.coverage)
        label = "değerlendirme eksik" if incomplete else "bulgu üretilmedi"
        ui.log(f"  {mod.label} — {label}{el}")

    for cr in new_creds:
        ui.log(reporting.render_credential(cr, color=ui.color))


def _run_modules_live(modules, ctx, report, jobs: int) -> None:
    """Modülleri (paralel ya da sıralı) canlı UI ile çalıştırır."""
    ui = live_ui.Live(total=len(modules), title=f"adscan · {report.target}")
    ui.register_modules(mod.name for mod in modules)
    _push_stats(ui, report)
    ui.start()
    progress.set_sink(_make_sink(ui))
    try:
        if jobs == 1 or len(modules) == 1:
            for mod in modules:
                try:
                    results = _worker(mod, ctx, ui)
                except Exception as exc:
                    report.add_error(f"{mod.name}: beklenmeyen hata: {exc}")
                    record_results(report, mod.name, [], parse_failed=True)
                    ui.finish_module(mod.name, "hata")
                    _push_stats(ui, report)
                    ui.advance()
                    ui.log(f"  {mod.label} — HATA: {exc}")
                    continue
                _finish_module(ui, mod, results, report)
        else:
            with ThreadPoolExecutor(max_workers=jobs) as pool:
                futs = {pool.submit(_worker, mod, ctx, ui): mod for mod in modules}
                for fut in as_completed(futs):
                    mod = futs[fut]
                    try:
                        res = fut.result()
                    except Exception as exc:  # modül çökse de diğerleri sürsün
                        report.add_error(f"{mod.name}: beklenmeyen hata: {exc}")
                        record_results(report, mod.name, [], parse_failed=True)
                        ui.finish_module(mod.name, "hata")
                        _push_stats(ui, report)
                        ui.advance()
                        ui.log(f"  {_c('✘', 'red', ui.color)} {mod.label} — HATA: {exc}")
                        continue
                    _finish_module(ui, mod, res, report)
    finally:
        progress.set_sink(None)
        ui.stop()


def _enrich_from_nxc_db(report: ScanReport, args) -> None:
    """netexec workspace DB'sinden (regex'e göre çok daha sağlam) rapor zenginleştirir.

    LDAP/SMB stdout ayrıştırması sürüme göre boş kalsa bile, nxc'nin kendi
    veritabanından kullanıcı/host/admin/paylaşım/kimlik çeker. Hedef tek IP ise
    o host'a filtreler; değilse (CIDR/hostname) bilinen host'lara göre süzer.
    """
    if args.no_nxc_db or args.dry_run:
        return
    try:
        targets: set[str] = set()
        t = args.target.split("/")[0].split(",")[0].strip()
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", t):
            targets.add(t)
        targets.update(h for h in report.hosts if h)
        rec = nxcdb.collect(targets=targets or None, workspace=args.nxc_workspace)
    except Exception:
        return  # DB okuma asla taramayı düşürmez

    if not (rec.users or rec.hosts or rec.admin or rec.shares):
        return

    color = reporting._supports_color()

    # domain / DC adı (DB'de dc işareti olan host'tan)
    for h in rec.hosts:
        dom = h.get("domain")
        if dom and "." in str(dom) and not report.domain:
            report.domain = str(dom)
        if h.get("dc") and h.get("hostname") and not report.dc_name:
            report.dc_name = str(h["hostname"])
        if h.get("_ip") and h["_ip"] not in report.hosts:
            report.hosts.append(h["_ip"])

    # admin erişimi olan (ip, user) çiftleri -> hızlı arama kümesi
    admin_pairs = {(ip, user.lower()) for ip, _dom, user in rec.admin if user}
    admin_users = {user.lower() for _ip, _dom, user in rec.admin if user}

    # kullanıcılar -> report.users + (parola varsa) kimlik
    new_users = 0
    new_creds = 0
    for u in rec.users:
        name = u.get("username")
        if not name or str(name).endswith("$"):
            continue
        if name not in report.users:
            report.users.append(name)
            new_users += 1
        secret = u.get("password")
        if secret:
            credtype = (u.get("credtype") or "").lower()
            kind = "nthash" if ("hash" in credtype
                                or re.fullmatch(r"[0-9a-f]{32}", str(secret))) else "password"
            before = len(report.credentials)
            report.add_credential(Credential(
                username=name, secret=str(secret), kind=kind,
                domain=str(u.get("domain") or report.domain or ""),
                source="nxc-db", admin=name.lower() in admin_users))
            if len(report.credentials) > before:
                new_creds += 1

    # mevcut kimliklerde admin işaretini DB'ye göre zenginleştir
    for c in report.credentials:
        if c.username.lower() in admin_users:
            c.admin = True

    writable = [s for s in rec.shares if s.get("write")]

    # Konsolide bilgilendirici bulgu
    summary = (f"{len(rec.users)} kullanıcı, {len(rec.hosts)} host, "
               f"{len(admin_pairs)} admin erişimi, {len(rec.shares)} paylaşım")
    ev_lines = []
    if rec.admin:
        ev_lines.append("Yerel admin (DB):")
        ev_lines += [f"  {ip}  {dom + chr(92) if dom else ''}{user}"
                     for ip, dom, user in rec.admin[:20]]
    if writable:
        ev_lines.append("Yazılabilir paylaşımlar (DB):")
        ev_lines += [f"  {s.get('ip') or '?'}  {s.get('name')}" for s in writable[:20]]
    report.add(Finding(
        title=f"netexec DB'den zenginleştirme: {summary} — nxc-db",
        severity=Severity.CRITICAL if admin_pairs else Severity.INFO,
        target=args.target, source="nxc-db",
        description="netexec workspace veritabanından okunan sonuçlar (stdout ayrıştırmaya "
                    "göre daha güvenilir). " + (f"{new_users} yeni kullanıcı, "
                    f"{new_creds} yeni kimlik rapora eklendi." if (new_users or new_creds)
                    else ""),
        evidence="\n".join(ev_lines) or summary,
        remediation="",
        reference="netexec workspace DB",
        poc=f"nxc smb {args.target} --users   # sonuçlar ~/.nxc/workspaces/"
            f"{args.nxc_workspace}/*.db içine yazılır",
        escalation="DB'deki admin erişimi olan host'larda secrets dump -> yanal hareket; "
                   "kimlikler --auto/--assume-breach ile DA yükseltmeye beslenir."))

    print(f"  {_c('✔', 'green', color)} netexec DB okundu — {summary}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="adscan",
        description="Active Directory pentest yardımcı aracı (nmap + nxc + windapsearch)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Örnek:\n"
        "  python -m adscan 10.10.10.5\n"
        "  python -m adscan 10.10.10.5 -u testuser -p 'Parola1' -d corp.local\n"
        "  python -m adscan 10.10.10.5 --only nmap,nxc-smb --dry-run",
    )
    from . import __version__
    p.add_argument("--version", action="version", version=f"adscan {__version__}")
    p.add_argument("--terminal-ui", choices=("compact", "detailed", "plain"), default="detailed",
                   help="Terminal görünümü: ayrıntılı (VARSAYILAN; her bulguda gerçek PoC "
                        "komutu + kanıt/çıktı + yükseltme yolu), kısa kartlar (compact) veya "
                        "animasyonsuz düz metin (plain)")
    p.add_argument("--terminal-preview", action="store_true", help="Ağa bağlanmadan örnek terminal görünümü")
    p.add_argument("target", nargs="?", help="Hedef IP / CIDR / hostname (DC)")
    p.add_argument("-u", "--username", help="AD kullanıcı adı (opsiyonel)")
    p.add_argument("-p", "--password", help="AD parolası (opsiyonel)")
    p.add_argument("-H", "--hash", dest="nthash", help="NT hash (pass-the-hash)")
    p.add_argument("-d", "--domain", help="Domain (ör. corp.local)")
    p.add_argument(
        "--only",
        help="Sadece seçili modüller: nmap,nxc-smb,nxc-ldap,nxc-vulns,smbmap,windapsearch (virgülle)",
    )
    p.add_argument(
        "--ask-pass",
        action="store_true",
        help="Parolayı gizli (ekrana yazmadan) sor — process list'te görünmez",
    )
    p.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=4,
        help="Paralel çalışacak modül sayısı (varsayılan 4; 1 = sıralı)",
    )
    p.add_argument(
        "-o",
        "--outdir",
        default="adscan-reports",
        help="Rapor çıktı klasörü (varsayılan: adscan-reports)",
    )
    p.add_argument(
        "--keep-old-reports",
        action="store_true",
        help="Aynı hedefin eski raporlarını SİLME (varsayılan: sadece en günceli tutulur)",
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=600,
        help="Komut başına zaman aşımı (saniye, varsayılan 600)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Komutları çalıştırmadan ne yapılacağını göster",
    )
    p.add_argument(
        "--yes",
        action="store_true",
        help="Onay sorusunu atla (izin aldığınızı teyit edersiniz)",
    )
    p.add_argument(
        "--check",
        action="store_true",
        help="Sadece araçların kurulu olup olmadığını kontrol et",
    )
    p.add_argument(
        "--guide",
        action="store_true",
        help="Adım adım kullanım/metodoloji kılavuzunu göster ve çık",
    )
    p.add_argument(
        "--cleanup",
        metavar="MANIFEST",
        help="Ortamda yapılan değişiklikleri (reanimation/gruba-ekleme/DCSync-hakkı) "
             "bir temizlik manifestinden (JSON) GERİ AL ve çık",
    )
    p.add_argument(
        "--redact",
        action="store_true",
        help="Parola/hash değerlerini çıktıda ve raporda maskele (varsayılan: açık göster)",
    )
    p.add_argument(
        "-k", "--kerberos",
        action="store_true",
        help="Kerberos auth kullan (nxc -k). ccache/KRB5CCNAME ve DC FQDN gerektirir.",
    )
    p.add_argument(
        "--proxychains",
        action="store_true",
        help="Ağa dönük tüm komutları 'proxychains -q' ile sar (ele geçirilen host "
             "üzerinden SOCKS pivot ile iç ağ taraması). /etc/proxychains.conf gerekir.",
    )
    p.add_argument(
        "--no-clock-fix",
        dest="no_clock_fix",
        action="store_true",
        help="Kerberos saat-kayması otomatik düzeltmesini (DC saati + faketime) kapat.",
    )
    p.add_argument(
        "--retries",
        type=int,
        default=2,
        metavar="N",
        help="Geçici bağlantı hatalarında (IO timeout/reset/broken pipe) komut başına "
             "yeniden deneme sayısı (varsayılan: 2; 0 = kapalı).",
    )
    p.add_argument(
        "--pw-sweep",
        dest="pw_sweep",
        action="store_true",
        help="Parola-tekrarı süpürmesi: bir parolayı (SORULUR) tüm enumere edilen "
             "kullanıcılarda dener (kullanıcı başına tek deneme). autopilot bunu zincire katar.",
    )
    p.add_argument(
        "--aclpath",
        dest="aclpath",
        action="store_true",
        help="ACL kısa-yol analizi: kontrol edilen kimlik(ler)den Domain Admin'e giden "
             "ACL zincirini bulur ve raporlar (salt tespit; yürütme için --auto/--assume-breach).",
    )
    p.add_argument(
        "--debug",
        action="store_true",
        help="Hata ayıklama: çalıştırılan komutları ve ham hata ayrıntılarını göster",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="OPSEC: yalnızca DÜŞÜK gürültülü modülleri çalıştır (nmap NSE ve aktif "
             "zafiyet kontrolleri gibi gürültülü modüller atlanır; IDS/EDR tetiğini azaltır)",
    )
    p.add_argument(
        "--audit-log",
        dest="audit_log",
        metavar="DOSYA",
        help="Çalıştırılan HER komutu zaman damgasıyla bu dosyaya yaz (engagement kaydı)",
    )
    p.add_argument(
        "--scope",
        metavar="DOSYA",
        help="İzinli hedef kapsamı (satır başına IP/CIDR/host). Kapsam dışı hedef REDDEDİLİR.",
    )
    p.add_argument(
        "--no-discover", dest="no_discover", action="store_true",
        help="Subnet keşfini KAPAT. Varsayılanda hedef bir CIDR/aralık (ör. "
             "10.0.0.0/24) ise önce canlı host'lar + DC + domain otomatik bulunur "
             "ve tarama bulunan DC üzerinden yürür. Bu bayrak hedefi aynen kullanır.",
    )
    p.add_argument(
        "--profile",
        metavar="DOSYA",
        help="Engagement profili (JSON; pyyaml varsa YAML). Hedef/domain/kapsam/modül "
             "seti gibi ayarları tek dosyadan yükler. Komut satırı değerleri profili ezer.",
    )
    p.add_argument(
        "--resume",
        action="store_true",
        help="Kontrol checkpoint'inden devam et; son rapordan kullanıcı/host/kimlik yükle",
    )
    p.add_argument(
        "--diff",
        metavar="JSON",
        help="Bu taramayı önceki bir JSON raporuyla kıyasla (yeni/çözülen bulgular)",
    )
    p.add_argument("--context-label", help="Karşılaştırmada gösterilecek tarama kimliği etiketi")
    p.add_argument("--context-role", choices=["anonymous", "standard", "auditor", "privileged", "custom"],
                   help="Test bağlamının kullanıcı tarafından belirtilen rolü")
    p.add_argument("--compare-reports", nargs="+", metavar="JSON",
                   help="Aynı hedefin raporlarını kontrol/kimlik bazında karşılaştır; hedefsiz kullanım çevrimdışıdır")
    p.add_argument("--acl-snapshot", metavar="JSON",
                   help="Sıralı DACL + kimlik/grup snapshot'ından etkin AD haklarını hesapla")
    p.add_argument(
        "--html",
        action="store_true",
        help="JSON+MD'ye ek olarak tek dosyalık HTML rapor da üret",
    )
    p.add_argument(
        "--screenshots", dest="screenshots", action="store_true",
        help="Web yüzeyinin (IIS/ADCS enrollment/login) headless tarayıcıyla ekran "
             "görüntüsünü al ve HTML rapora göm. Headless chromium/chrome gerekir. "
             "(--full bunu otomatik açar.)",
    )
    p.add_argument(
        "--no-extra-reports",
        dest="no_extra_reports",
        action="store_true",
        help="Ek teslimat çıktılarını (MITRE Navigator layer + loot manifesti + CSV) "
             "üretme (varsayılan: üretilir)",
    )
    p.add_argument(
        "--no-nxc-db",
        action="store_true",
        dest="no_nxc_db",
        help="netexec workspace veritabanından (~/.nxc) zenginleştirmeyi kapat",
    )
    p.add_argument(
        "--nxc-workspace",
        default="default",
        help="Okunacak netexec workspace adı (varsayılan: default)",
    )

    auto = p.add_argument_group("autopilot (tek komutla uçtan uca zincir)")
    auto.add_argument(
        "--full", action="store_true",
        help="KAPSAMLI tarama: tüm tespit modüllerini aç (ADCS + bloodyAD + BloodHound + "
             "MSSQL + WinRM). Kimlik verilirse kimlikli modüller de çalışır; aktif ağ "
             "saldırıları (spray/relay) yine ayrı bayrak + onay ister. --auto ile birleştir.")
    auto.add_argument(
        "--full-ports", action="store_true",
        help="nmap'te önce hızlı tam-TCP (-p-) keşfi yap, sonra açık portlarda "
             "NSE/servis taraması çalıştır (sabit AD port listesi dışındaki IIS/certsrv "
             "gibi servisleri de kapsar). --full bunu otomatik açar.")
    auto.add_argument(
        "--auto", action="store_true",
        help="Otonom mod: enum -> kullanıcı çıkar -> spray -> Domain Admin yükseltme")
    auto.add_argument(
        "--auto-passwords",
        help="Autopilot spray parolaları (virgülle); verilmezse yerleşik liste")
    auto.add_argument(
        "--assume-breach", action="store_true", dest="assume_breach",
        help="Eldeki kimlikle (nmap/port taraması ATMADAN) doğrudan kimlikli enum "
             "+ Domain Admin yükseltme. -u ve -p/-H gerekir.")
    auto.add_argument(
        "--adcs", action="store_true",
        help="ADCS ESC1-ESC8 zafiyet taraması (certipy) ekle — kimlik gerektirir")
    auto.add_argument(
        "--bloodyad", action="store_true",
        help="bloodyAD ile yazılabilir nesne / ACL privesc taraması — kimlik gerektirir")
    auto.add_argument(
        "--bloodhound", action="store_true",
        help="BloodHound veri toplama (saldırı grafiği) ekle — kimlik + domain gerektirir")
    auto.add_argument(
        "--mssql", action="store_true",
        help="MSSQL enum/privesc taraması ekle — kimlik gerektirir")
    auto.add_argument(
        "--winrm", action="store_true",
        help="WinRM yanal hareket kontrolü ekle — kimlik gerektirir")

    brain = p.add_argument_group("LLM beyin (Ollama) — otonom karar motoru")
    brain.add_argument(
        "--brain", action="store_true",
        help="LLM-güdümlü otonom mod: her turda yerel Ollama modeli mevcut "
             "bulgulara bakıp whitelist'ten BİR SONRAKİ modülü seçer. Model yalnızca "
             "seçer; komutu runner kurar. Ollama yoksa deterministik zincire düşer.")
    brain.add_argument(
        "--ollama-url", dest="ollama_url", default=os.environ.get(
            "OLLAMA_HOST", "http://localhost:11434"),
        help="Ollama HTTP adresi (varsayılan: $OLLAMA_HOST ya da localhost:11434). "
             "Ollama WSL'de, AdScan VM'deyse: http://<windows-host-ip>:11434")
    brain.add_argument(
        "--ollama-model", dest="ollama_model",
        default=os.environ.get("ADSCAN_OLLAMA_MODEL", "adscan-brain"),
        help="Kullanılacak Ollama modeli (varsayılan: adscan-brain; qwen3:8b tabanlı "
             "özel beyin modeli — `ollama create` ile kurulur). Düz taban model de "
             "verilebilir, ör. --ollama-model qwen3:8b")
    brain.add_argument(
        "--ollama-timeout", dest="ollama_timeout", type=int, default=120,
        metavar="SN", help="Her LLM çağrısı için zaman aşımı (sn, varsayılan 120)")
    brain.add_argument(
        "--ollama-keep-alive", dest="ollama_keep_alive", default="30m",
        metavar="SÜRE", help="Modeli bellekte sıcak tutma süresi (Ollama keep_alive; "
             "ör. '30m', '2h', '-1' süresiz, '0' hemen boşalt). Döngü öncesi ön-ısıtma "
             "ile birlikte tur-içi kararları hızlandırır (varsayılan: 30m).")
    brain.add_argument(
        "--brain-max-steps", dest="brain_max_steps", type=int, default=12,
        metavar="N", help="Beyin döngüsü üst sınırı (varsayılan 12 tur)")
    brain.add_argument(
        "--brain-active", dest="brain_active", action="store_true",
        help="Beynin AKTİF (ağa müdahale: spray/relay/poisoning) modülleri de "
             "SEÇEBİLMESİNE izin ver. Aktif modüller yine kendi --launch kapısına "
             "tabidir. Bu bayrak olmadan beyin yalnızca pasif/tespit modülü seçer.")
    brain.add_argument(
        "--brain-trace", dest="brain_trace", metavar="DOSYA", default=None,
        help="Her beyin kararını (durum→seçim→sonuç) JSONL olarak yaz (denetim + "
             "ileride fine-tune veri seti). Varsayılan: <outdir>/brain-trace.jsonl")
    brain.add_argument(
        "--brain-bare-prompt", dest="brain_bare_prompt", action="store_true",
        help="İstekte system mesajı GÖNDERME; özel modele (ör. `ollama create "
             "adscan-brain`) gömülü SYSTEM promptunu kullan. Uzmanlaştırılmış model "
             "ile birlikte kullan.")
    brain.add_argument(
        "--brain-export-dataset", dest="brain_export_dataset", metavar="İZ",
        default=None,
        help="Beyin iz log(lar)ından (brain-trace.jsonl; joker * olabilir) fine-tune "
             "veri seti üret ve çık. Yalnız başarılı (yeni bulgu/kimlik/DA üreten) "
             "LLM kararları alınır. Çıktı için --dataset-out kullan.")
    brain.add_argument(
        "--dataset-out", dest="dataset_out", metavar="DOSYA", default="brain-dataset.jsonl",
        help="--brain-export-dataset çıktısı (sohbet-formatı JSONL; varsayılan: "
             "brain-dataset.jsonl)")

    cr = p.add_argument_group("çevrimdışı kırma (kerberoast / AS-REP)")
    cr.add_argument(
        "--crack", action="store_true",
        help="Harvest edilen kerberoast/AS-REP hash'lerini (loot/kerb.txt, loot/asrep.txt) "
             "hashcat/john ile kır; kırılan parolaları zincire kimlik olarak besle. "
             "(--auto bunu otomatik yapar; --full için açıkça --crack gerekir.)")
    cr.add_argument(
        "--wordlist", metavar="DOSYA",
        help="Kırma sözlüğü (varsayılan: otomatik rockyou.txt araması).")
    cr.add_argument(
        "--crack-timeout", dest="crack_timeout", type=int, default=300, metavar="SN",
        help="Kırma için toplam süre sınırı (saniye, varsayılan 300; hashcat --runtime).")

    spray = p.add_argument_group("password spraying (opt-in, aktif — kilitlenme-farkında)")
    spray.add_argument("--spray", action="store_true",
                       help="Password spraying modülünü etkinleştir")
    spray.add_argument("--spray-passwords",
                       help="Denenecek parolalar (virgülle): 123456,Password1,...")
    spray.add_argument("--spray-passlist", help="Parola listesi dosyası (satır başına bir parola)")
    spray.add_argument("--spray-userlist", help="Kullanıcı adı listesi dosyası")
    spray.add_argument("--spray-namelist",
                       help="'Ad Soyad' listesi dosyası (OSINT) -> olası kullanıcı adları "
                            "otomatik üretilir (first.last, flast, f.last, …)")
    spray.add_argument("--spray-users", help="Kullanıcılar (virgülle)")
    spray.add_argument("--spray-delay", type=float, default=0.0,
                       help="Her parola turu arası bekleme (sn)")
    spray.add_argument("--spray-force", action="store_true",
                       help="TEHLİKELİ: kilitlenme güvenlik kontrolünü atla")

    active = p.add_argument_group("aktif saldırılar (opt-in: poisoning/relay/ESC8)")
    active.add_argument("--active-attacks", action="store_true",
                        help="Aktif saldırı modülünü etkinleştir (varsayılan: sadece PLAN)")
    active.add_argument("--launch", action="store_true",
                        help="Planı GERÇEKTEN çalıştır (--active-attacks + ek onay gerekir)")
    active.add_argument("-I", "--interface", help="Ağ arayüzü (Responder/mitm6)")
    active.add_argument("--listener-ip", help="Relay/listener IP")
    active.add_argument("--relay-targets", help="Relay hedef(ler)i (ör. ldaps://dc.ip)")
    active.add_argument("--adcs-ca-url", help="ESC8 için CA web enrollment URL'i")
    active.add_argument("--shadow-target",
                        help="Shadow Credentials uygulanacak hesap (sAMAccountName); "
                             "boşsa BloodHound'dan AddKeyCredentialLink kenarı seçilir")
    active.add_argument("--adcs-exploit", action="store_true",
                        help="Savunmasız ADCS şablonu bulunursa (ESC1) otomatik sertifika "
                             "isteyip PKINIT ile NT hash dene (aktif; --active-attacks onayı)")
    active.add_argument("--capture-seconds", type=int, default=120,
                        help="Aktif yakalama penceresi (sn, varsayılan 120)")
    active.add_argument("--reuse", action="store_true",
                        help="Bulunan kimlikleri host'larda dene (yanal hareket, 2. aşama)")
    active.add_argument("--reuse-targets",
                        help="Reuse için host'lar (IP/CIDR/dosya; varsayılan: hedef)")
    return p


def _run_cleanup(args) -> int:
    """`--cleanup <manifest>`: kaydedilmiş değişiklikleri geri alır.

    `undo_argv` olan aksiyonlar OTOMATİK çalıştırılır; ELLE işaretli olanlar
    yalnızca talimatla listelenir (uydurma komut üretmeyiz).
    """
    color = reporting._supports_color()
    acts = cleanup.load_manifest(args.cleanup)
    if not acts:
        print(f"HATA: temizlik manifesti okunamadı ya da boş: {args.cleanup}")
        return 2

    pending = [a for a in acts if not a.done]
    print(_c(f"  Temizlik planı — {len(acts)} aksiyon "
             f"({len(pending)} bekliyor):", "bold", color) if color else
          f"  Temizlik planı — {len(acts)} aksiyon ({len(pending)} bekliyor):")
    for line in cleanup.teardown_plan(acts):
        print("    " + line)

    auto = [a for a in pending if a.undo_argv]
    manual = [a for a in pending if not a.undo_argv]
    if not auto:
        print("\n  Otomatik geri-alınacak aksiyon yok.")
    if manual:
        print(_c(f"\n  {len(manual)} aksiyon ELLE geri alınmalı "
                 "(açıklamadaki adımları izleyin).", "yellow", color) if color else
              f"\n  {len(manual)} aksiyon ELLE geri alınmalı "
              "(açıklamadaki adımları izleyin).")

    if not auto:
        return 0

    if not args.yes and not args.dry_run:
        try:
            ans = input(f"\n  {len(auto)} aksiyon OTOMATİK geri alınsın mı? [evet/hayır]: "
                        ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nİptal edildi.")
            return 1
        if ans not in ("evet", "e", "yes", "y"):
            print("Geri alma iptal edildi.")
            return 1

    results = cleanup.execute_teardown(acts, dry_run=args.dry_run)
    ok = sum(1 for a, r in results if r is not None and getattr(r, "ok", False))
    fail = [(a, r) for a, r in results if r is not None and not getattr(r, "ok", False)]
    if args.dry_run:
        print(f"\n  [DRY-RUN] {len(auto)} geri-alma komutu çalıştırılacaktı.")
        return 0
    print(_c(f"\n  Geri alındı: {ok}/{len(auto)} aksiyon.", "green", color) if color else
          f"\n  Geri alındı: {ok}/{len(auto)} aksiyon.")
    for a, r in fail:
        print(_c(f"    ✘ başarısız: [{a.kind}] {a.identifier}@{a.target} "
                 f"({getattr(r, 'error', None) or 'yetki?'})", "red", color) if color else
              f"    ✘ başarısız: [{a.kind}] {a.identifier}@{a.target} "
              f"({getattr(r, 'error', None) or 'yetki?'})")
    return 0 if not fail else 1


def _attach_analysis(args, report, *, include_current=True):
    from .comparison import compare, read_report
    from .permissions import load_snapshot

    if args.acl_snapshot:
        load_snapshot(args.acl_snapshot, report)
    if args.compare_reports:
        inputs = [(read_report(path), path) for path in args.compare_reports]
        if any(str(data["target"]).strip().casefold() != report.target.strip().casefold()
               for data, _ in inputs):
            raise ValueError("Karşılaştırma hedefi mevcut raporla uyuşmuyor")
        if include_current:
            inputs.append((report.to_dict(), "Bu tarama"))
        if len(inputs) < 2:
            raise ValueError("Çevrimdışı karşılaştırma için en az iki rapor gerekli")
        report.comparison = compare(inputs)


def _validate_analysis_inputs(args):
    from .comparison import compare, read_report
    from .permissions import load_snapshot

    if args.compare_reports:
        inputs = [(read_report(path), path) for path in args.compare_reports]
        if any(str(data["target"]).strip().casefold() != args.target.strip().casefold()
               for data, _ in inputs):
            raise ValueError("Karşılaştırılan raporların hedefi tarama hedefiyle uyuşmuyor")
        compare(inputs)
    if args.acl_snapshot:
        load_snapshot(args.acl_snapshot, ScanReport(args.target))


def _offline_analysis(args):
    import hashlib
    from pathlib import Path

    from .comparison import read_report

    try:
        if args.compare_reports:
            first = read_report(args.compare_reports[0])
            target = first["target"]
        else:
            with open(args.acl_snapshot, encoding="utf-8-sig") as stream:
                snapshot = json.load(stream)
            target = snapshot.get("target") if isinstance(snapshot, dict) else None
        if not isinstance(target, str) or not target:
            raise ValueError("Değerlendirme girdisinde target gerekli")
        report = ScanReport(target, outdir=args.outdir, scan_mode="offline_analysis")
        _attach_analysis(args, report, include_current=False)
        Path(args.outdir).mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256(target.encode()).hexdigest()[:12]
        from uuid import uuid4
        base = Path(args.outdir) / f"adscan-analysis-{digest}-{datetime.now():%Y%m%d-%H%M%S}-{uuid4().hex[:6]}"
        for suffix, writer in [(".json", reporting.write_json), (".md", reporting.write_markdown),
                               (".html", reporting.write_html)]:
            writer(report, str(base) + suffix)
        print(f"Çevrimdışı analiz kaydedildi: {base}.html")
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"HATA: çevrimdışı değerlendirme: {exc}")
        return 2


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    # --profile: ayarları dosyadan yükle (varsayılan olarak); CLI değerleri ezer.
    if getattr(args, "profile", None):
        from . import profile as _profile
        try:
            prof = _profile.load(args.profile)
        except _profile.ProfileError as exc:
            print(f"HATA: profil okunamadı: {exc}")
            return 2
        parser = build_parser()
        parser.set_defaults(**prof)
        args = parser.parse_args(argv)
        print(f"  [profile] {len(prof)} ayar yüklendi: {args.profile}")

    # --full: tek komutla maksimum kapsam — tüm tespit modüllerini aç.
    # (Kimlikli modüller kimlik yoksa kendini atlar; aktif saldırılar hâlâ ayrı onay ister.)
    if args.full:
        args.adcs = args.bloodyad = args.bloodhound = args.mssql = args.winrm = True
        if not args.html:
            args.html = True  # kapsamlı taramada paylaşılabilir HTML de üret

    config.set_redact(args.redact)
    config.TERMINAL_UI = args.terminal_ui
    config.set_proxychains(getattr(args, "proxychains", False))
    config.set_debug(args.debug)
    config.set_retries(args.retries)

    print(reporting.banner(reporting._supports_color()))
    if args.terminal_preview:
        from .terminal_demo import preview
        preview()
        return 0

    if args.guide:
        guide.print_guide()
        return 0

    if args.check:
        tool_check()
        return 0

    if args.cleanup:
        return _run_cleanup(args)

    if getattr(args, "brain_export_dataset", None):
        from . import finetune
        try:
            n, total = finetune.build_dataset(
                [args.brain_export_dataset], args.dataset_out)
        except OSError as exc:
            print(f"HATA: veri seti yazılamadı: {exc}")
            return 2
        print(f"  [fine-tune] {n} örnek yazıldı ({total} iz satırından): "
              f"{args.dataset_out}")
        print("  Sonraki adım (adscan ÇALIŞTIRMAZ): qwen3:8b üzerine LoRA fine-tune "
              "(unsloth/llama-factory) → 'ollama create adscan-brain-ft'.")
        return 0

    if not args.target and (args.compare_reports or args.acl_snapshot):
        return _offline_analysis(args)

    if not args.target:
        print("HATA: hedef belirtilmedi. Kullanım: python -m adscan <hedef>\n")
        build_parser().print_help()
        return 2

    # --- kapsam (scope) koruması: izinli kapsam dışına çıkmayı reddet ---
    if args.scope:
        ok, reason = _in_scope(args.target, args.scope)
        if not ok:
            print(f"HATA: hedef kapsam dışı ({reason}). "
                  f"İzinli kapsam: {args.scope}. Yanlışlıkla kapsam-dışı tarama engellendi.")
            return 2

    # --- denetim (audit) kaydı: çalıştırılan her komut dosyaya yazılsın ---
    try:
        _validate_analysis_inputs(args)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"HATA: değerlendirme girdisi geçersiz: {exc}")
        return 2
    if args.audit_log:
        config.set_audit_log(args.audit_log)
        config.audit(f"=== adscan başladı — hedef: {args.target} ===")

    tool_check()

    # Onay (yetkilendirme teyidi)
    if not args.yes and not args.dry_run:
        try:
            ans = input(CONSENT_TEXT).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nİptal edildi.")
            return 1
        if ans not in ("evet", "e", "yes", "y"):
            print("Onay verilmedi — çıkılıyor.")
            return 1

    # --- subnet keşfi: hedef CIDR/aralık ise host'ları + DC'yi + domain'i otomatik bul ---
    # Tek IP yerine /24 verilirse burada canlı host'lar + DC tespit edilir; tarama
    # pivotu (args.target) bulunan DC'ye çevrilir, diğer host'lar reuse hedefi olur.
    _discovered = None
    if not args.dry_run and not getattr(args, "no_discover", False):
        from . import discover as _discover
        if _discover.looks_like_range(args.target):
            _discovered = _discover.discover(
                args.target, timeout=args.timeout, domain_hint=args.domain)
            if _discovered.dc_ip:
                args.target = _discovered.dc_ip  # pivot = bulunan DC
                if _discovered.domain and not args.domain:
                    args.domain = _discovered.domain
            elif _discovered.hosts:
                # DC yok ama canlı host var: ilkini hedef al, kalanı reuse'a bırak
                args.target = _discovered.hosts[0]
                print(f"  [keşif] DC imzalı host yok; pivot: {args.target}")
            else:
                print("  [keşif] canlı host bulunamadı; girilen hedef aynen taranacak.")
                _discovered = None

    # --- kimlik bilgisi çözümleme (güvenli) ---
    password = _resolve_password(args)
    if args.full and args.username and password is None and not args.nthash and not args.kerberos:
        print("HATA: --full ile -u için --ask-pass, -p, -H veya -k gerekli.")
        return 2
    if args.full and not args.username and (password is not None or args.nthash or args.kerberos):
        print("HATA: kimlikli --full için -u gerekli.")
        return 2
    spray_passwords = _resolve_spray_passwords(args)

    # --- modül seçimi (registry) ---
    only = {s.strip() for s in args.only.split(",") if s.strip()} if args.only else None
    try:
        modules = select_modules(only)
        # --only verilmediyse opt-in modülleri ilgili bayraklarla ekle
        if only is None:
            if args.spray:
                modules.append(get_module("spray"))
            if args.active_attacks:
                modules.append(get_module("relay"))
            if args.reuse:
                modules.append(get_module("reuse"))
            # ADCS: açıkça --adcs ile ya da kimlikli auto/assume-breach'te otomatik
            if args.adcs or ((args.auto or args.assume_breach) and args.username):
                modules.append(get_module("certipy"))
            # bloodyAD: açıkça --bloodyad ile ya da kimlikli auto/assume-breach'te otomatik
            if args.bloodyad or ((args.auto or args.assume_breach) and args.username):
                modules.append(get_module("bloodyad"))
            if args.full:
                modules.append(get_module("bloodyad-enum"))
            # BloodHound/MSSQL/WinRM: açıkça bayrakla istenirse ekle (opt-in, kimlik ister)
            if args.bloodhound:
                modules.append(get_module("bloodhound"))
            if args.mssql:
                modules.append(get_module("mssql"))
            if args.winrm:
                modules.append(get_module("winrm"))
            # web ekran görüntüsü: --full ile ya da açıkça --screenshots
            if args.full or getattr(args, "screenshots", False):
                modules.append(get_module("webshot"))
    except (ValueError, KeyError) as exc:
        print(f"HATA: {exc}")
        return 2

    # reuse 2. aşamadır: 1. aşama kimlikleri bulduktan SONRA çalışır
    stage2 = [m for m in modules if m.name == "reuse"]
    modules = [m for m in modules if m.name != "reuse"]

    # --quiet: OPSEC — yalnızca düşük gürültülü modülleri bırak (açık --only hariç)
    selection_skips = []
    if args.quiet and only is None:
        selection_skips = [m for m in modules if noise_of(m.name) != "low"]
        before = len(modules)
        modules = [m for m in modules if noise_of(m.name) == "low"]
        dropped = before - len(modules)
        if dropped:
            print(f"  [quiet] {dropped} gürültülü modül atlandı "
                  "(nmap/aktif kontroller); yalnızca düşük gürültülü enum çalışacak.")

    # --- assume-breach: kimlik zorunlu; nmap/port taraması atlanır ---
    if args.assume_breach:
        if not (args.username and (password or args.nthash)):
            print("HATA: --assume-breach için -u ve -p/-H (kimlik) gereklidir.")
            return 2
        if only is None:  # kullanıcı --only ile açıkça seçmediyse nmap'ı çıkar
            modules = [m for m in modules if m.name != "nmap"]

    # --- aktif modüller için EK onay ---
    active_selected = (any(m.active for m in modules + stage2)
                       or args.auto or args.assume_breach)
    if active_selected and not args.dry_run and not args.yes:
        try:
            ans = input(ACTIVE_CONSENT_TEXT).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nİptal edildi.")
            return 1
        if ans != "yetkiliyim":
            print("Aktif saldırı onayı verilmedi — çıkılıyor.")
            return 1

    if args.launch and not args.active_attacks:
        print("HATA: --launch için --active-attacks da gereklidir.")
        return 2

    ctx = ScanContext(
        target=args.target,
        username=args.username,
        password=password,
        nthash=args.nthash,
        domain=args.domain,
        timeout=args.timeout,
        dry_run=args.dry_run,
        spray_userlist=args.spray_userlist,
        spray_namelist=args.spray_namelist,
        spray_users=[u.strip() for u in args.spray_users.split(",")] if args.spray_users else None,
        spray_passwords=spray_passwords,
        spray_delay=args.spray_delay,
        spray_force=args.spray_force,
        active_attacks=args.active_attacks,
        launch=args.launch,
        interface=args.interface,
        listener_ip=args.listener_ip,
        relay_targets=args.relay_targets,
        adcs_ca_url=args.adcs_ca_url,
        adcs_exploit=getattr(args, "adcs_exploit", False),
        capture_seconds=args.capture_seconds,
        reuse_targets=args.reuse_targets,
        shadow_target=getattr(args, "shadow_target", None),
        outdir=args.outdir,
        use_kerberos=args.kerberos,
        full=args.full,
        full_ports=args.full or getattr(args, "full_ports", False),
    )

    report = ScanReport(target=args.target, outdir=args.outdir)
    # Subnet keşfinde bulunan host'ları/domain'i rapora + reuse hedeflerine bağla
    if _discovered is not None:
        for h in _discovered.hosts:
            if h not in report.hosts:
                report.hosts.append(h)
        if _discovered.dc_name and not report.dc_name:
            report.dc_name = _discovered.dc_name
        if _discovered.domain and not report.domain:
            report.domain = _discovered.domain
        if not ctx.reuse_targets and _discovered.hosts:
            ctx.reuse_targets = ",".join(_discovered.hosts)
        report.raw_outputs["discover"] = (
            f"hedef subnet: {_discovered.host_ports and 'tarandı' or ''}\n"
            f"canlı host: {len(_discovered.hosts)}\n"
            f"DC adayları: {', '.join(_discovered.dc_candidates) or '-'}\n"
            f"seçilen DC: {_discovered.dc_ip or '-'} "
            f"({_discovered.dc_name or '?'}) · domain: {_discovered.domain or '?'}")
    from uuid import uuid4
    principal = ((ctx.domain + "\\" if ctx.domain else "") + ctx.username) if ctx.has_auth else "Anonymous"
    report.execution_context = {
        "id": str(uuid4()), "label": args.context_label or principal,
        "principal": principal, "domain": ctx.domain or "",
        "role": args.context_role or ("custom" if ctx.has_auth else "anonymous"),
        "auth_type": "kerberos" if ctx.use_kerberos else "hash" if ctx.nthash else
                     "password" if ctx.has_auth else "anonymous",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "requested_modules": [m.name for m in modules] + [m.name for m in selection_skips]}
    if not args.dry_run:
        from .checkpoint import Checkpoint
        try:
            ctx.checkpoint = Checkpoint(args.outdir, args.target, resume=args.resume)
            report.checkpoint = ctx.checkpoint
        except (OSError, ValueError, KeyError, TypeError) as exc:
            print(f"[!] Checkpoint okunamadı/yazılamadı: {exc}")
            return 2
    for mod in selection_skips:
        from .assessment import record_skipped
        record_skipped(report, mod.name, "--quiet filtresi")
    modules = plan_modules(modules, ctx, report)

    # Bu çalışmanın temizlik kuyruğu taze başlasın (manifest yalnızca bu koşuyu kapsar)
    cleanup.reset()

    # --- CLI ile verilen kimliği havuza kat: PoC'ler gerçek user/pass ile dolsun ---
    if args.username and (password or args.nthash):
        report.add_credential(Credential(
            username=args.username, secret=args.nthash or password,
            kind="nthash" if args.nthash else "password",
            domain=args.domain or "", source="cli"))

    # --- resume: aynı hedefin son raporundan bağlamı yükle (delta tarama) ---
    if args.resume:
        safe = args.target.replace("/", "_").replace(":", "_")
        prior = _load_prior_report(args.outdir, safe)
        if prior:
            _resume_from(report, prior)
            print(f"  [resume] önceki rapordan yüklendi: {len(report.users)} kullanıcı, "
                  f"{len(report.hosts)} host, {len(report.credentials)} kimlik "
                  f"({os.path.basename(prior.get('_path', ''))})")
            if report.credentials and not ctx.found_credentials:
                ctx.found_credentials = list(report.credentials)
        else:
            print("  [resume] önceki rapor yok; mevcut kontrol checkpoint'leri kullanılacak.")

    # --- modülleri çalıştır (paralel) ---
    # Modüller I/O-bound (harici subprocess beklenir) olduğundan thread havuzu
    # GIL'e takılmadan ciddi hızlanma sağlar. Çalıştırma paralel; AYRIŞTIRMA
    # ise sıralı yapılır çünkü hepsi aynı 'report' nesnesini mutasyona uğratır.
    jobs = max(1, args.jobs)
    _t0 = time.time()
    color = reporting._supports_color()
    mode = ("AUTOPILOT (otonom Domain Admin)" if args.auto else
            "ASSUME-BREACH (kimlikle doğrudan DA)" if args.assume_breach else
            "ENUM + zafiyet taraması")
    if args.full:
        mode = ("KAPSAMLI KİMLİKLİ · " if ctx.has_auth else "KAPSAMLI KİMLİKSİZ · ") + mode
    who = (f"{args.username}" + (f"@{args.domain}" if args.domain else "")
           if args.username else "kimliksiz (null/anonim)")
    print(reporting.render_header_box(args.target, mode, who, len(modules), jobs, color))
    # Kerberos'a dokunan akışlarda (kimlik / -k / auto / assume-breach) saat farkını düzelt
    if not args.dry_run and (args.username or args.kerberos or args.auto or args.assume_breach):
        _setup_clock(args, color)
    print(_c("  (her modül biter bitmez sonucu görünecek)", "dim", color) + "\n")

    # Çalıştırma paralel; AYRIŞTIRMA her modül biter bitmez ana thread'de yapılır
    # (hepsi aynı 'report' nesnesini mutasyona uğratır) ve o modülün bulguları
    # anında ekrana akıtılır — çıktı sona yığılmaz.
    _run_modules_live(modules, ctx, report, jobs)

    # --- netexec DB'den zenginleştir (stdout ayrıştırmaya göre daha sağlam) ---
    # Autopilot/escalate'ten ÖNCE: DB'den gelen kullanıcı/kimlikler zincire beslensin.
    if any(m.name.startswith("nxc") for m in modules):
        _enrich_from_nxc_db(report, args)

    # --- DC host adı/FQDN tespit edildiyse hemen göster (IP ile uğraşma) ---
    _print_dc_banner(report, args.target, color)

    # --- çevrimdışı kırma: kerberoast/AS-REP hash'lerini kır (autopilot/escalate'ten ÖNCE) ---
    if args.crack or args.auto:
        _run_crack_phase(args, ctx, report, color)

    # --- BloodHound yol analizi: toplanan grafikte DA'ya en kısa yolu çıkar (veri varsa) ---
    bhpath.analyze(report)

    # --- korelasyon: tiering ihlali (DA, DC-olmayan host'ta aktif) ---
    correlate.correlate_tiering(report)
    # --- korelasyon: coercion + imzalama zorlanmıyor -> uçtan uca relay-to-DA yolu ---
    correlate.correlate_relay_path(report)
    # --- korelasyon: LDAP gizleme (SAMR >> LDAP -> confidential/ACL) ---
    correlate.correlate_ldap_confidential(report)
    # --- korelasyon: Kerberos saat-kayması kaldı mı? ---
    correlate.correlate_clock_skew(report)

    # --- ADCS ESC1 otomatik istismarı (aktif; --adcs-exploit + --active-attacks) ---
    if getattr(args, "adcs_exploit", False) and args.active_attacks:
        from .modules import certipy_scan as _cp
        _cp.exploit_esc1(ctx, report)

    # --- BEYİN: LLM-güdümlü otonom mod (her turda Ollama modül seçer) ---
    if getattr(args, "brain", False):
        os.makedirs(args.outdir, exist_ok=True)
        _run_brain_autopilot(args, ctx, report, password)
        stage2 = []  # beyin zincirini kendisi yürüttü

    # --- AUTOPILOT: enum -> kullanıcı çıkar -> spray -> Domain Admin yükseltme ---
    elif args.auto:
        os.makedirs(args.outdir, exist_ok=True)
        _run_autopilot(args, ctx, report, password)
        stage2 = []  # auto zaten yükseltme yaptı

    # --- ASSUME-BREACH: eldeki kimlikle doğrudan DA yükseltme (spray/nmap yok) ---
    elif args.assume_breach:
        os.makedirs(args.outdir, exist_ok=True)
        _run_escalation_phase(args, ctx, report, password)
        stage2 = []  # yükseltme zaten reuse/DCSync yaptı

    # --- 2. aşama: credential reuse (1. aşamada bulunan kimliklerle) ---
    if stage2:
        # CLI'den gelen kimliği de havuza kat
        if args.username and (password or args.nthash):
            report.add_credential(Credential(
                username=args.username, secret=args.nthash or password,
                kind="nthash" if args.nthash else "password",
                domain=args.domain or "", source="cli"))
        ctx.found_credentials = list(report.credentials)
        if not ctx.found_credentials:
            print("[i] reuse: denenecek kimlik yok (spray/relay kimlik bulamadı).")
        for mod in stage2:
            print(f"[*] 2. aşama: {mod.label} ({len(ctx.found_credentials)} kimlik)")
            mod.parse(mod.run(ctx), report)

    # --- parola-tekrarı süpürmesi (tek seferlik; autopilot kendi fazında yapar) ---
    if args.pw_sweep and not args.auto:
        os.makedirs(args.outdir, exist_ok=True)
        _run_pw_sweep(args, ctx, report, color)

    # --- ACL kısa-yol analizi (salt tespit; autopilot/assume-breach yürütür) ---
    if args.aclpath and not args.auto and not args.assume_breach:
        if (args.username and (password or args.nthash)
                and not any(c.username.lower() == args.username.lower()
                            for c in report.credentials)):
            report.add_credential(Credential(
                username=args.username, secret=args.nthash or password,
                kind="nthash" if args.nthash else "password",
                domain=args.domain or report.domain or "", source="cli"))
        aclgraph.analyze(ctx, report, ui=None, exploit=False)

    # --- raporlama ---
    try:
        _attach_analysis(args, report)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"HATA: değerlendirme girdisi geçersiz: {exc}")
        return 2
    # Ayrıntılar tarama sırasında zaten akıtıldı; burada KOMPAKT özet veriyoruz.
    os.makedirs(args.outdir, exist_ok=True)
    mitre.annotate(report)  # bulgulara MITRE ATT&CK teknik id'leri ekle
    pocfill.fill(report)  # PoC/escalation yer tutucularını bilinen kimlikle doldur
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe_target = args.target.replace("/", "_").replace(":", "_")
    base = os.path.join(args.outdir, f"adscan-{safe_target}-{stamp}")

    # --- diff için önceki raporu pruning'DEN ÖNCE yükle ---
    diff_prior = None
    if args.diff:
        try:
            with open(args.diff, encoding="utf-8") as fh:
                diff_prior = json.load(fh)
        except (OSError, ValueError) as exc:
            print(f"  [diff] önceki rapor okunamadı: {exc}")
    else:
        diff_prior = _load_prior_report(args.outdir, safe_target, exclude=base)

    reporting.write_json(report, base + ".json")
    reporting.write_markdown(report, base + ".md")
    saved = [base + ".json", base + ".md"]
    if args.html:
        reporting.write_html(report, base + ".html")
        saved.append(base + ".html")

    # --- teslimat ek çıktıları: MITRE Navigator layer + loot manifesti + CSV ---
    if not args.no_extra_reports:
        try:
            export.write_navigator_layer(report, base + ".navigator.json")
            export.write_loot_manifest(report, base + ".loot.json")
            export.write_attack_graph(report, base + ".graph.json")
            export.write_csv(report, base + ".findings.csv")
            export.write_sarif(report, base + ".sarif")
            saved += [base + ".navigator.json", base + ".loot.json",
                      base + ".graph.json", base + ".findings.csv", base + ".sarif"]
        except OSError as exc:
            print(f"  [export] ek çıktı yazılamadı: {exc}")

    # --- temizlik manifesti: ortamda yapılan geri-alınabilir değişiklikler ---
    # Aktif akışlar (auto/assume-breach) reanimation, gruba-ekleme, DCSync-hakkı
    # gibi kalıcı değişiklikler yapmış olabilir. Hepsi kuyruğa kaydedildi; teste
    # sonunda `--cleanup <manifest>` ile geri alınabilsin diye JSON'a yazıyoruz.
    cleanup_path = base + ".cleanup.json"
    if cleanup.write_manifest(cleanup_path, target=args.target):
        saved.append(cleanup_path)
        acts = cleanup.actions()
        print(_c(f"\n  Temizlik manifesti: {len(acts)} geri-alınabilir değişiklik "
                 f"kaydedildi → {os.path.basename(cleanup_path)}", "yellow", color)
              if color else
              f"\n  Temizlik manifesti: {len(acts)} geri-alınabilir değişiklik "
              f"kaydedildi → {os.path.basename(cleanup_path)}")
        for line in cleanup.teardown_plan(acts):
            print("    " + line)
        print(_c(f"    Geri almak için: python -m adscan --cleanup {cleanup_path}",
                 "dim", color) if color else
              f"    Geri almak için: python -m adscan --cleanup {cleanup_path}")

    # Aynı hedefin eski raporlarını temizle (yalnızca en günceli kalsın)
    if not args.keep_old_reports and not args.context_label and not args.context_role and not args.compare_reports:
        pruned = _prune_old_reports(args.outdir, safe_target, base)
        if pruned:
            print(f"  (aynı hedefin {len(pruned)} eski raporu silindi — "
                  "saklamak için --keep-old-reports)")

    reporting.print_recap(report, saved=saved)

    # --- diff: önceki taramaya göre yeni/çözülen bulgular ---
    if diff_prior is not None:
        new, resolved = _diff_reports(report, diff_prior)
        if new or resolved:
            print(f"\n  {_ANSI['bold']}Değişim (önceki taramaya göre):{_ANSI['reset']}"
                  if color else "\n  Değişim (önceki taramaya göre):")
            for t in new:
                print(_c(f"    + YENİ: {t}", "green", color))
            for t in resolved:
                print(_c(f"    - BU TARAMADA GÖRÜLMEDİ (çözüldüğü doğrulanmadı): {t}", "dim", color))

    # Aktif/spray modülü çalıştıysa yetki yükseltme zinciri özetini göster
    if (args.auto or args.assume_breach or stage2
            or any(m.name in ("spray", "relay") for m in modules)):
        print(chaining.format_chain(report, color=reporting._supports_color()))
        print()

    if args.debug:
        _debug_dump(report)

    total = time.time() - _t0
    tinfo = f"[+] Toplam süre: {total:.1f}s"
    print(f"{_ANSI['dim']}{tinfo}{_ANSI['reset']}" if color else tinfo)
    if args.audit_log:
        config.audit(f"=== adscan bitti — {total:.1f}s, {len(report.findings)} bulgu ===")

    # MEDIUM+ bulgu varsa exit code 1 (CI/otomasyon için sinyal)
    return 1 if report.has_actionable() else 0


if __name__ == "__main__":
    sys.exit(main())

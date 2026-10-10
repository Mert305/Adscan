"""Web ekran görüntüsü — ADCS web enrollment / IIS / login sayfalarının gerçek SS'i.

Kurumsal rapora görsel kanıt ekler: hedefin web yüzeyini (http/https ve ADCS
`/certsrv/` enrollment) headless bir tarayıcıyla açıp PNG ekran görüntüsü alır,
base64 olarak rapora gömer (HTML raporda "Ekran Görüntüleri" bölümü).

Best-effort: sistemde bir headless tarayıcı (chromium/chrome) YOKSA sessizce
atlanır (ek bağımlılık zorlamaz). Yalnız HTTP GET yapar (sayfayı görüntüler) —
düşük riskli recon; opt-in. `--full` bunu otomatik ekler.
"""

from __future__ import annotations

import base64
import os
import shutil

from ..findings import Finding, ScanReport, Severity
from ..registry import ScanContext, ScanModule
from ..runner import CommandResult, run

# Denenecek headless tarayıcı binary'leri (ilk bulunan kullanılır)
_BROWSERS = ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable",
             "chrome", "chrome.exe")
_MAX_PNG = 2_000_000  # tek SS için üst sınır (~2MB; rapor şişmesin)


def _browser() -> str | None:
    for b in _BROWSERS:
        path = shutil.which(b)
        if path:
            return path
    return None


def _urls_for(ctx: ScanContext) -> list[str]:
    """Hedef için denenecek web URL'leri (http/https + ADCS enrollment)."""
    t = ctx.target.split(",")[0].split("/")[0].strip()
    urls = [f"http://{t}/", f"https://{t}/", f"http://{t}/certsrv/"]
    ca = getattr(ctx, "adcs_ca_url", None)
    if ca:
        urls.insert(0, ca)
    # tekilleştir, sırayı koru
    seen: set[str] = set()
    out = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def capture(ctx: ScanContext) -> list[CommandResult]:
    browser = _browser()
    if browser is None:
        return [CommandResult(tool="webshot:skip", argv=[], returncode=None,
                              stdout="", stderr="", duration=0.0,
                              error="headless tarayıcı yok (chromium/chrome) — SS atlandı",
                              error_kind="skipped")]
    results: list[CommandResult] = []
    shot_dir = os.path.join(ctx.outdir, "screenshots")
    try:
        os.makedirs(shot_dir, exist_ok=True)
    except OSError:
        pass
    for i, url in enumerate(_urls_for(ctx)):
        png = os.path.join(shot_dir, f"shot_{i}.png")
        argv = [browser, "--headless=new", "--disable-gpu", "--no-sandbox",
                "--hide-scrollbars", "--ignore-certificate-errors",
                "--virtual-time-budget=5000", "--window-size=1280,900",
                f"--screenshot={png}", url]
        res = run(argv, tool=f"webshot:{url}", timeout=min(ctx.timeout, 60),
                  dry_run=ctx.dry_run)
        # PNG oluştuysa base64'e çevirip CommandResult.stdout'a koy (parse okur)
        b64 = ""
        if not ctx.dry_run:
            try:
                if os.path.isfile(png) and os.path.getsize(png) <= _MAX_PNG:
                    with open(png, "rb") as fh:
                        b64 = base64.b64encode(fh.read()).decode("ascii")
            except OSError:
                b64 = ""
        results.append(CommandResult(
            tool=f"webshot:{url}", argv=argv, returncode=res.returncode,
            stdout=b64, stderr="", duration=res.duration, error=res.error))
    return results


def parse(results: list[CommandResult], report: ScanReport) -> None:
    first = results[0] if results else None
    if first and first.tool == "webshot:skip":
        report.raw_outputs["webshot"] = first.error or "atlandı"
        return
    captured = []
    for r in results:
        if r.tool.startswith("webshot:") and r.stdout:
            url = r.tool.split("webshot:", 1)[1]
            report.screenshots[url] = r.stdout  # base64 PNG
            captured.append(url)
    report.raw_outputs["webshot"] = (
        f"{len(captured)} ekran görüntüsü: " + ", ".join(captured) if captured
        else "ekran görüntüsü alınamadı")
    if captured:
        report.add(Finding(
            title=f"Web yüzeyi ekran görüntüsü alındı ({len(captured)} sayfa)",
            severity=Severity.INFO, target=report.target, source="webshot",
            control_id="web.screenshot",
            reference="Web surface capture",
            description="Hedefin web yüzeyi (IIS/ADCS enrollment/login) görsel kanıt "
                        "olarak yakalandı. Raporun 'Ekran Görüntüleri' bölümüne bakın.",
            evidence="\n".join(captured),
            remediation="Gereksiz web enrollment/yönetim arayüzlerini kısıtlayın; "
                        "ADCS web enrollment (ESC8) için HTTPS + EPA zorlayın.",
            poc="(headless tarayıcı ile görüntülendi)",
            escalation="ADCS /certsrv görünüyorsa ESC8 (web enrollment relay) değerlendir."))


def _run(ctx: ScanContext) -> list[CommandResult]:
    return capture(ctx)


MODULE = ScanModule(
    name="webshot",
    label="Web ekran görüntüsü (ADCS/IIS/login — headless tarayıcı; opt-in)",
    run=_run,
    parse=parse,
    optin=True,
)

"""Raporlama: terminal renkli özet, JSON ve Markdown çıktıları."""

from __future__ import annotations

import json
import os
import re
import shutil
from datetime import datetime

from .findings import ScanReport, Severity

# ANSI renkleri (Windows 10+ terminalleri destekler)
_COLORS = {
    Severity.CRITICAL: "\033[1;97;41m",  # beyaz/kırmızı zemin
    Severity.HIGH: "\033[1;31m",  # kırmızı
    Severity.MEDIUM: "\033[1;33m",  # sarı
    Severity.LOW: "\033[1;36m",  # camgöbeği
    Severity.INFO: "\033[0;37m",  # gri
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


_DIM = "\033[2m"

# --- 256-renk vurgu paleti (marka + seviye çizgileri) ---
_BRAND = "\033[38;5;44m"   # camgöbeği (çerçeve/aksan)
_BRAND2 = "\033[38;5;39m"  # mavi
_SEV_FG = {               # seviyeye göre ön-plan rengi (sol şerit + çubuk)
    Severity.CRITICAL: "\033[38;5;196m",
    Severity.HIGH: "\033[38;5;208m",
    Severity.MEDIUM: "\033[38;5;220m",
    Severity.LOW: "\033[38;5;44m",
    Severity.INFO: "\033[38;5;245m",
}
_SEV_ICON = {
    Severity.CRITICAL: "✖", Severity.HIGH: "▲", Severity.MEDIUM: "◆",
    Severity.LOW: "●", Severity.INFO: "·",
}

_ANSI_RX = re.compile(r"\033\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    return _ANSI_RX.sub("", text)


def _vlen(text: str) -> int:
    """Görünür (ANSI'siz) uzunluk — kutu hizalaması için."""
    return len(_strip_ansi(text))


def _termwidth(default: int = 80) -> int:
    return shutil.get_terminal_size((default, 20)).columns


def _paint(code: str, text: str, color: bool) -> str:
    return f"{code}{text}{_RESET}" if color else text


def _box(title: str, rows: list[str], *, color: bool, accent: str = _BRAND,
         width: int | None = None) -> str:
    """Yuvarlak köşeli bir kutu çizer; satırlar ANSI içerebilir (hizalama korunur)."""
    w = min(width or 68, max(40, _termwidth() - 2))
    inner = w - 2
    t = f" {title} "
    fill = max(0, inner - 1 - _vlen(t))
    out = [_paint(accent, "╭─" + t + "─" * fill, color) + _paint(accent, "╮", color)]
    for r in rows:
        pad = max(0, inner - 1 - _vlen(r))
        out.append(_paint(accent, "│", color) + " " + r + " " * pad
                   + _paint(accent, "│", color))
    out.append(_paint(accent, "╰" + "─" * inner + "╯", color))
    return "\n".join(out)


def _tile(label: str, value: str, vcolor: str, color: bool, w: int = 13) -> list[str]:
    """Tek bir istatistik kutucuğu (3 satır) döndürür."""
    lab = label[: w - 2].center(w - 2)
    val = _strip_ansi(value)[: w - 2].center(w - 2)
    val_c = _paint(vcolor, val, color) if color else val
    b = _BRAND
    return [
        _paint(b, "┌" + "─" * (w - 2) + "┐", color),
        _paint(b, "│", color) + _paint(_DIM, lab, color) + _paint(b, "│", color),
        _paint(b, "│", color) + val_c + _paint(b, "│", color),
        _paint(b, "└" + "─" * (w - 2) + "┘", color),
    ]


def _tiles_row(tiles: list[tuple[str, str, str]], color: bool) -> str:
    """Birden çok kutucuğu yan yana basar. tiles: (label, value, vcolor)."""
    cols = [_tile(lbl, val, vc, color, w=14) for lbl, val, vc in tiles]
    return "\n".join("  " + "  ".join(col[i] for col in cols) for i in range(4))


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.name == "nt":
        # Windows Terminal / VT etkinleştirme
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return False
    return True


def _c(text: str, sev: Severity, color: bool) -> str:
    return f"{_COLORS[sev]}{text}{_RESET}" if color else text


def _b(text: str, color: bool) -> str:
    return f"{_BOLD}{text}{_RESET}" if color else text


def _dim(text: str, color: bool) -> str:
    return f"{_DIM}{text}{_RESET}" if color else text


def _version() -> str:
    from . import __version__
    return __version__


def banner(color: bool = True) -> str:
    """Açılış afişi — çerçeveli, renkli ASCII logo."""
    art = [
        _paint("\033[38;5;39m", r"   __ _ ___| |___ __ __ _ _ _", color),
        _paint("\033[38;5;44m", r"  / _` / _` (_-< _/ _/ _` | ' \ ", color)
        + "  " + _paint(_BOLD, "adscan", color)
        + _paint(_DIM, f" v{_version()}", color),
        _paint("\033[38;5;51m", r"  \__,_\__,_/__/__\__\__,_|_||_|", color)
        + "  " + _paint(_DIM, "AD Pentest Orkestratörü", color),
    ]
    return _box("yetkili test · eğitim", art, color=color, accent=_BRAND, width=62)


def render_header_box(target: str, mode: str, who: str, n_modules: int, jobs: int,
                      color: bool) -> str:
    """Tarama başlığı — çerçeveli bilgi kutusu."""
    rows = [
        _paint(_DIM, "Hedef   ", color) + _b(target, color),
        _paint(_DIM, "Mod     ", color) + _paint(_BRAND2, mode, color),
        _paint(_DIM, "Kimlik  ", color) + who,
        _paint(_DIM, "Modül   ", color) + f"{n_modules} modül  ·  paralellik {jobs}",
    ]
    return _box("TARAMA", rows, color=color, accent=_BRAND2, width=58)


def _finding_bar(color: bool, sev: Severity) -> str:
    return _paint(_SEV_FG[sev], "┃", color)


def render_finding(f, *, color: bool, index: int | None = None) -> str:
    """Tek bir bulguyu renkli, sol-şeritli 'kart' olarak çizer."""
    bar = _finding_bar(color, f.severity)
    icon = _paint(_SEV_FG[f.severity], _SEV_ICON[f.severity], color)
    badge = _c(f" {f.severity.label} ", f.severity, color)
    num = f"{index}. " if index else ""
    blocks = [f"{icon} {badge} {_b(num + f.title, color)}"]

    meta = (_paint(_DIM, "kaynak", color) + f" {f.source}   "
            + _paint(_DIM, "hedef", color) + f" {f.target}")
    if f.mitre:
        meta += "   " + _paint(_DIM, "MITRE", color) + f" {f.mitre}"
    blocks.append(meta)

    if f.description:
        blocks.append(f.description)
    if f.evidence:
        ev = f.evidence.strip().replace("\n", "\n    ")
        blocks.append(_paint(_DIM, "kanıt", color) + "\n    " + ev)
    if f.poc:
        if "\n" in f.poc:
            poc_body = f.poc.strip().replace("\n", "\n    ")
            blocks.append(_paint(_BRAND, "▸ PoC", color) + "\n    " + poc_body)
        else:
            blocks.append(_paint(_BRAND, "▸ PoC     ", color) + f.poc)
    if f.escalation:
        if "\n" in f.escalation:
            esc_body = f.escalation.strip().replace("\n", "\n    ")
            blocks.append(_paint(_SEV_FG[Severity.HIGH], "▲ YÜKSELTME YOLU", color)
                          + "\n    " + esc_body)
        else:
            blocks.append(_paint(_SEV_FG[Severity.HIGH], "▲ yükselt ", color) + f.escalation)
    if f.remediation:
        blocks.append(_paint("\033[38;5;42m", "✓ çözüm   ", color) + f.remediation)
    if f.reference:
        blocks.append(_paint(_DIM, "ref       " + f.reference, color))

    raw = "\n".join(blocks)
    # Her fiziksel satırı seviye renginde sol şeritle öne-ekle (kart görünümü)
    return "\n".join((bar + " " + ln) if ln.strip() else bar for ln in raw.split("\n"))


def _sevbar(report: ScanReport, color: bool) -> str:
    """Seviye dağılımını yatay çubuk grafiği olarak çizer."""
    counts = report.count_by_severity()
    maxc = max((counts[s.label] for s in Severity), default=0) or 1
    out = []
    for sev in reversed(list(Severity)):
        n = counts[sev.label]
        if not n:
            continue
        blocks = max(1, round(22 * n / maxc))
        bar = _paint(_SEV_FG[sev], "█" * blocks, color)
        label = _paint(_SEV_FG[sev], f"{_SEV_ICON[sev]} {sev.label:<8}", color)
        out.append(f"  {label} {bar} {_b(str(n), color)}")
    return "\n".join(out)


def render_credential(cr, *, color: bool) -> str:
    """Ele geçirilen bir kimliği tek satıra dönüştürür."""
    dom = f"{cr.domain}\\" if cr.domain else ""
    adm = _c("  [ADMIN]", Severity.CRITICAL, color) if cr.admin else ""
    return f"  {dom}{cr.username}:{cr.display_secret()}  ({cr.kind}, {cr.source}){adm}"


_RISK_FG = {
    "KRİTİK": "\033[1;97;41m", "YÜKSEK": _SEV_FG[Severity.HIGH],
    "ORTA": _SEV_FG[Severity.MEDIUM], "DÜŞÜK": _SEV_FG[Severity.LOW],
    "TEMİZ": "\033[38;5;42m",
}


def _risk_banner(report: ScanReport, color: bool) -> str:
    """Risk puanı + etiket + 0-100 ölçekli görsel çubuk (yönetici özeti)."""
    score = report.risk_score()
    label = report.risk_label()
    fg = _RISK_FG.get(label, _DIM)
    filled = max(0, min(24, round(24 * score / 100)))
    bar = _paint(fg, "█" * filled, color) + _paint(_DIM, "░" * (24 - filled), color)
    tag = _paint(fg, f" {label} ", color)
    head = f"{_paint(_DIM, 'RİSK', color)} {tag} {bar} {_b(f'{score}/100', color)}"
    rows = [head]
    tops = report.top_findings(3)
    if tops:
        rows.append(_paint(_DIM, "en kritik:", color))
        for f in tops:
            icon = _paint(_SEV_FG[f.severity], _SEV_ICON[f.severity], color)
            rows.append(f"  {icon} {f.title}")
    # Önce-bunu-yap: en öncelikli tek düzeltme (D)
    plan = report.remediation_plan()
    if plan:
        top = plan[0]
        extra = f" (+{top['count'] - 1})" if top["count"] > 1 else ""
        rows.append(_paint(_DIM, "önce düzelt:", color)
                    + f" {top['action']}{extra}")
    return _box("YÖNETİCİ ÖZETİ", rows, color=color,
                accent=_RISK_FG.get(label, _BRAND), width=62)


def print_recap(report: ScanReport, *, saved: list[str] | None = None) -> None:
    """Tarama sonunda görsel özet panosu: kutucuklar + çubuk grafik + dizin.

    Ayrıntılar zaten tarama sırasında akışta ve kaydedilen raporda olduğundan
    burada her şeyi tekrar dökmeyiz; hızlı, görsel bir genel bakış veririz.
    """
    color = _supports_color()
    counts = report.count_by_severity()
    total = len(report.findings)
    crit = counts["CRITICAL"] + counts["HIGH"]
    da = getattr(report, "domain_admin", False)

    print()
    # --- istatistik kutucukları ---
    print(_tiles_row([
        ("BULGU", str(total), _BRAND),
        ("KRİT+YÜK", str(crit), _SEV_FG[Severity.CRITICAL] if crit else _DIM),
        ("KİMLİK", str(len(report.credentials)),
         "\033[38;5;42m" if report.credentials else _DIM),
        ("DOMAIN ADMIN", "EVET ✓" if da else "hayır",
         _SEV_FG[Severity.CRITICAL] if da else _DIM),
    ], color))
    print()

    # --- yönetici özeti: risk puanı + en kritik bulgular ---
    print(_risk_banner(report, color))
    print()

    # --- başlık + hedef/DC kutusu ---
    fqdn = (f"{report.dc_name}.{report.domain}".lower()
            if report.dc_name and report.domain else (report.dc_name or "—"))
    rows = [_paint(_DIM, "Hedef ", color) + _b(report.target, color)]
    if report.dc_name or report.domain:
        rows.append(_paint(_DIM, "DC    ", color) + fqdn
                    + (f"   {_paint(_DIM, 'domain', color)} {report.domain}"
                       if report.domain else ""))
    print(_box(f"ÖZET — {report.target}", rows, color=color))

    # --- seviye dağılımı (çubuk grafik) ---
    if total:
        print()
        print(_sevbar(report, color))

    # --- bulgu dizini (tek satır) ---
    if total:
        print()
        for i, f in enumerate(report.sorted_findings(), 1):
            icon = _paint(_SEV_FG[f.severity], _SEV_ICON[f.severity], color)
            tag = _c(f" {f.severity.label} ", f.severity, color)
            print(f"  {i:>2}. {icon} {tag} {f.title}  {_dim('· ' + f.source, color)}")

    # --- saldırı yolu zinciri (format_chain kendi başlığını basar) ---
    try:
        from . import chain as _chain
        chain_txt = _chain.format_chain(report, color=color).strip("\n")
        if chain_txt.strip():
            print()
            for ln in chain_txt.split("\n"):
                print("  " + ln)
    except Exception:
        pass

    if report.credentials:
        print(_b(f"\n  Ele geçirilen kimlikler ({len(report.credentials)}):", color))
        for cr in report.credentials:
            print(render_credential(cr, color=color))
        from . import config as _cfg
        if not _cfg.REDACT:
            print(_c("    ⚠ Kimlikler raporda AÇIK yazılı — dosyaları güvenli tutun / "
                     "paylaşmadan önce --redact ile tarayın.", Severity.MEDIUM, color))

    if report.errors:
        print(_b("\n  Uyarılar / çalıştırılamayanlar:", color))
        for e in report.errors:
            print(f"    {_paint(_SEV_FG[Severity.MEDIUM], '!', color)} {e}")

    if report.has_actionable():
        print(_c("\n  ►► MEDIUM ve üzeri bulgu(lar) var — incelenmesi önerilir.",
                 Severity.HIGH, color))

    if saved:
        print(_b("\n  Rapor kaydedildi:", color))
        for p in saved:
            print(f"    {_paint(_BRAND, '→', color)} {p}")
    print()


def print_summary(report: ScanReport) -> None:
    """Terminale renkli, TAM ayrıntılı özet basar (klasik tek-seferlik mod)."""
    color = _supports_color()

    def c(text: str, sev: Severity) -> str:
        return _c(text, sev, color)

    def b(text: str) -> str:
        return _b(text, color)

    print()
    print(b("=" * 64))
    print(b(f"  AD TARAMA RAPORU  —  Hedef: {report.target}"))
    print(b(f"  {datetime.now():%Y-%m-%d %H:%M:%S}"))
    print(b("=" * 64))

    counts = report.count_by_severity()
    summary_line = "  ".join(
        c(f"{sev.label}:{counts[sev.label]}", sev)
        for sev in reversed(list(Severity))
        if counts[sev.label] > 0
    )
    print(f"\nÖzet: {summary_line or 'bulgu yok'}\n")

    findings = report.sorted_findings()
    if not findings:
        print("  (bulgu üretilmedi)")
    for f in findings:
        print(render_finding(f, color=color))
        print()

    if report.credentials:
        print(b(f"\nELE GEÇİRİLEN KİMLİKLER ({len(report.credentials)}):"))
        for cr in report.credentials:
            print(render_credential(cr, color=color))

    if report.errors:
        print(b("\nUYARILAR / ÇALIŞTIRILAMAYANLAR:"))
        for e in report.errors:
            print(f"  ! {e}")

    if report.has_actionable():
        print(
            c(
                "\n>>> MEDIUM ve üzeri bulgu(lar) var — incelenmesi önerilir. <<<",
                Severity.HIGH,
            )
        )
    print()


def write_json(report: ScanReport, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report.to_dict(), fh, ensure_ascii=False, indent=2)


def write_markdown(report: ScanReport, path: str) -> None:
    lines: list[str] = []
    lines.append(f"# AD Tarama Raporu — {report.target}")
    lines.append("")
    lines.append(f"*Oluşturulma:* {datetime.now():%Y-%m-%d %H:%M:%S}")
    lines.append("")

    counts = report.count_by_severity()
    lines.append("## Özet")
    lines.append("")
    lines.append("| Seviye | Adet |")
    lines.append("|--------|------|")
    for sev in reversed(list(Severity)):
        if counts[sev.label]:
            lines.append(f"| {sev.label} | {counts[sev.label]} |")
    lines.append("")

    # Öncelikli düzeltmeler (D): önce-bunu-yap planı
    plan = report.remediation_plan()
    if plan:
        lines.append("## Öncelikli Düzeltmeler (önce bunu yap)")
        lines.append("")
        lines.append("| # | Öncelik | Düzeltme | Kapsadığı bulgu |")
        lines.append("|---|---------|----------|------------------|")
        for i, item in enumerate(plan[:10], 1):
            action = item["action"].replace("|", "\\|")
            lines.append(f"| {i} | {item['severity']} | {action} | {item['count']} |")
        lines.append("")

    lines.append("## Bulgular")
    lines.append("")
    for i, f in enumerate(report.sorted_findings(), 1):
        lines.append(f"### {i}. [{f.severity.label}] {f.title}")
        lines.append("")
        lines.append(f"- **Kaynak:** {f.source}")
        lines.append(f"- **Hedef:** {f.target}")
        if f.reference:
            lines.append(f"- **Referans:** {f.reference}")
        if f.mitre:
            from . import mitre as _mitre
            lines.append(f"- **MITRE ATT&CK:** {f.mitre}"
                         + (f" ({_mitre.TECH_NAMES[f.mitre]})" if f.mitre in _mitre.TECH_NAMES else ""))
        if f.description:
            lines.append(f"- **Açıklama:** {f.description}")
        if f.poc:
            if "\n" in f.poc:
                lines.append("- **Doğrula (PoC):**")
                lines.append("")
                lines.append("```bash")
                lines.append(f.poc.strip())
                lines.append("```")
            else:
                lines.append(f"- **Doğrula (PoC):** `{f.poc}`")
        if f.escalation:
            if "\n" in f.escalation:
                lines.append("- **Yükseltme yolu:**")
                lines.append("")
                lines.append("```")
                lines.append(f.escalation.strip())
                lines.append("```")
            else:
                lines.append(f"- **Yükseltme:** {f.escalation}")
        if f.remediation:
            lines.append(f"- **Çözüm:** {f.remediation}")
        if f.evidence:
            lines.append("")
            lines.append("```")
            lines.append(f.evidence.strip())
            lines.append("```")
        lines.append("")

    if report.credentials:
        lines.append("## Ele Geçirilen Kimlikler")
        lines.append("")
        lines.append("| Domain | Kullanıcı | Sır | Tür | Kaynak | Admin |")
        lines.append("|--------|-----------|-----|-----|--------|-------|")
        for cr in report.credentials:
            lines.append(
                f"| {cr.domain} | {cr.username} | `{cr.display_secret()}` | "
                f"{cr.kind} | {cr.source} | {'✓' if cr.admin else ''} |")
        lines.append("")

    if report.errors:
        lines.append("## Uyarılar")
        lines.append("")
        for e in report.errors:
            lines.append(f"- {e}")
        lines.append("")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


# ---------------------------------------------------------------------------
# HTML rapor (tek dosya, bağımsız — paylaşılabilir)
# ---------------------------------------------------------------------------

_HTML_SEV = {
    Severity.CRITICAL: "#b00020", Severity.HIGH: "#d9534f",
    Severity.MEDIUM: "#e0a800", Severity.LOW: "#17a2b8", Severity.INFO: "#6c757d",
}

_HTML_RISK = {
    "KRİTİK": "#b00020", "YÜKSEK": "#d9534f",
    "ORTA": "#e0a800", "DÜŞÜK": "#17a2b8", "TEMİZ": "#28a745",
}


def _risk_html_color(label: str) -> str:
    return _HTML_RISK.get(label, "#6c757d")


def _esc(text: str) -> str:
    """HTML özel karakterlerini kaçır."""
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def write_html(report: ScanReport, path: str) -> None:
    """Tek dosyalık, bağımsız (inline CSS) HTML rapor üretir."""
    from . import chain as chaining
    from . import mitre as _mitre

    counts = report.count_by_severity()
    parts: list[str] = []
    for sev in reversed(list(Severity)):
        if counts[sev.label]:
            parts.append(
                f'<span class="pill" style="background:{_HTML_SEV[sev]}">'
                f'{sev.label}: {counts[sev.label]}</span>')
    summary = " ".join(parts) or '<span class="pill" style="background:#6c757d">bulgu yok</span>'

    dc_fqdn = (f"{report.dc_name}.{report.domain}".lower()
               if report.dc_name and report.domain else (report.dc_name or "—"))

    rows = []
    for i, f in enumerate(report.sorted_findings(), 1):
        color = _HTML_SEV[f.severity]
        mitre_txt = ""
        if f.mitre:
            name = _mitre.TECH_NAMES.get(f.mitre, "")
            mitre_txt = (f'<div class="kv"><b>MITRE ATT&amp;CK:</b> '
                         f'<code>{_esc(f.mitre)}</code> {_esc(name)}</div>')
        ev = (f'<pre>{_esc(f.evidence.strip())}</pre>' if f.evidence.strip() else "")
        # PoC: çok-satırlıysa <pre> blok, tek satırsa inline <code>
        if not f.poc:
            poc_html = ""
        elif "\n" in f.poc:
            poc_html = (f'<div class="kv"><b>Doğrula (PoC):</b></div>'
                        f'<pre>{_esc(f.poc.strip())}</pre>')
        else:
            poc_html = f'<div class="kv"><b>Doğrula (PoC):</b> <code>{_esc(f.poc)}</code></div>'
        # Yükseltme: çok-satırlıysa adım bloğu (<pre>), tek satırsa satır içi
        if not f.escalation:
            esc_html = ""
        elif "\n" in f.escalation:
            esc_html = (f'<div class="kv"><b>Yükseltme yolu:</b></div>'
                        f'<pre class="esc">{_esc(f.escalation.strip())}</pre>')
        else:
            esc_html = f'<div class="kv"><b>Yükseltme:</b> {_esc(f.escalation)}</div>'
        rows.append(f"""
        <details class="finding" open>
          <summary><span class="tag" style="background:{color}">{f.severity.label}</span>
            <span class="ftitle">{i}. {_esc(f.title)}</span>
            <span class="src">{_esc(f.source)}</span></summary>
          <div class="body">
            {f'<div class="kv"><b>Hedef:</b> {_esc(f.target)}</div>'}
            {f'<div class="kv"><b>Referans:</b> {_esc(f.reference)}</div>' if f.reference else ''}
            {mitre_txt}
            {f'<div class="kv"><b>Açıklama:</b> {_esc(f.description)}</div>' if f.description else ''}
            {poc_html}
            {esc_html}
            {f'<div class="kv"><b>Çözüm:</b> {_esc(f.remediation)}</div>' if f.remediation else ''}
            {ev}
          </div>
        </details>""")

    # Saldırı yolu zinciri (ANSI'siz düz metin)
    chain_txt = _esc(chaining.format_chain(report, color=False))

    creds_rows = ""
    if report.credentials:
        trs = "".join(
            f"<tr><td>{_esc(c.domain)}</td><td>{_esc(c.username)}</td>"
            f"<td><code>{_esc(c.display_secret())}</code></td><td>{_esc(c.kind)}</td>"
            f"<td>{_esc(c.source)}</td><td>{'✓' if c.admin else ''}</td></tr>"
            for c in report.credentials)
        creds_rows = f"""
        <h2>Ele Geçirilen Kimlikler ({len(report.credentials)})</h2>
        <table><thead><tr><th>Domain</th><th>Kullanıcı</th><th>Sır</th>
        <th>Tür</th><th>Kaynak</th><th>Admin</th></tr></thead><tbody>{trs}</tbody></table>"""

    errors_html = ""
    if report.errors:
        lis = "".join(f"<li>{_esc(e)}</li>" for e in report.errors)
        errors_html = f"<h2>Uyarılar</h2><ul class='warn'>{lis}</ul>"

    html = f"""<!doctype html>
<html lang="tr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AD Tarama Raporu — {_esc(report.target)}</title>
<style>
  :root {{ --bg:#0f1115; --card:#1a1d24; --fg:#e6e6e6; --muted:#9aa0a6; --line:#2a2e37; }}
  @media (prefers-color-scheme: light) {{
    :root {{ --bg:#f5f6f8; --card:#fff; --fg:#1a1a1a; --muted:#666; --line:#e2e4e8; }} }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--fg);
    font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; }}
  .wrap {{ max-width:960px; margin:0 auto; padding:24px 16px; }}
  h1 {{ font-size:22px; margin:0 0 4px; }}
  h2 {{ font-size:18px; margin:28px 0 10px; border-bottom:1px solid var(--line); padding-bottom:6px; }}
  .meta {{ color:var(--muted); font-size:13px; margin-bottom:14px; }}
  .pill, .tag {{ color:#fff; border-radius:10px; padding:2px 10px; font-size:12px;
    font-weight:600; white-space:nowrap; }}
  .summary {{ display:flex; gap:8px; flex-wrap:wrap; margin:10px 0 4px; }}
  .finding {{ background:var(--card); border:1px solid var(--line); border-radius:10px;
    margin:10px 0; padding:4px 12px; }}
  .finding summary {{ cursor:pointer; display:flex; gap:10px; align-items:center;
    padding:8px 0; list-style:none; }}
  .finding summary::-webkit-details-marker {{ display:none; }}
  .ftitle {{ font-weight:600; flex:1; }}
  .src {{ color:var(--muted); font-size:12px; }}
  .body {{ padding:4px 0 12px; }}
  .kv {{ margin:6px 0; }}
  pre.esc {{ border-left:3px solid #d9534f; }}
  code {{ background:rgba(127,127,127,.18); padding:1px 5px; border-radius:4px;
    font-family:ui-monospace,Menlo,Consolas,monospace; font-size:12.5px; }}
  pre {{ background:rgba(127,127,127,.12); padding:10px; border-radius:6px;
    overflow:auto; font-size:12px; white-space:pre-wrap; word-break:break-word; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th, td {{ text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); }}
  th {{ color:var(--muted); font-weight:600; }}
  .warn li {{ color:#e0a800; }}
  .chain {{ background:var(--card); border:1px solid var(--line); border-radius:10px;
    padding:12px; white-space:pre-wrap; font-family:ui-monospace,Menlo,Consolas,monospace;
    font-size:12.5px; }}
</style></head>
<body><div class="wrap">
  <h1>AD Tarama Raporu — {_esc(report.target)}</h1>
  <div class="meta">Oluşturulma: {datetime.now():%Y-%m-%d %H:%M:%S}
    &nbsp;·&nbsp; DC: {_esc(dc_fqdn)} &nbsp;·&nbsp; domain: {_esc(report.domain or '—')}
    {' &nbsp;·&nbsp; <b style="color:#b00020">DOMAIN ADMIN ELDE EDİLDİ</b>' if report.domain_admin else ''}</div>
  <div class="summary">
    <span class="pill" style="background:{_risk_html_color(report.risk_label())}">
      RİSK: {report.risk_label()} — {report.risk_score()}/100</span>
    {summary}</div>

  <h2>Saldırı Yolu</h2>
  <div class="chain">{chain_txt}</div>

  <h2>Bulgular ({len(report.findings)})</h2>
  {''.join(rows) or '<p>Bulgu yok.</p>'}
  {creds_rows}
  {errors_html}
</div></body></html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)

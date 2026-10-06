"""Canlı terminal arayüzü — çok-satırlı dashboard.

Ekranın altında yerinde güncellenen kalıcı bir **durum paneli** çizer; üstünde
akan olay günlüğü kayar. Panel terminal boyutuna göre 1–8 satırdır:

    1) spinner + ilerleme çubuğu + geçen süre + çalışan modüller
    2) canlı bulgu sayacı (seviyeye göre) + ele geçen kimlik + Domain Admin
    3) saldırı-yolu mini çubuğu + o an çalışan komut

Paralel modüllerin hepsi tek terminale yazdığından her çıktı tek kilitten
(RLock) geçer; böylece panel ile log satırları birbirine karışmaz. Panel
yüksekliği terminal boyutuna uyum sağlar; her kare satır-satır
`\\033[2K` ile temizlenip yeniden yazılır.

TTY değilse veya plain seçilmişse panel kapanır ve `log()` düz `print`e düşer —
çıktı otomasyon/log dosyalarında temiz kalır.
"""

from __future__ import annotations

import itertools
import os
import shutil
import sys
import threading
import time

from . import config
from .terminal import clean, fit

_SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_RESET = "\033[0m"
_DIM = "\033[2m"
_BOLD = "\033[1m"
_CLEAR = "\033[2K"  # tüm satırı temizle
_CLEAR_DOWN = "\033[J"  # imleçten ekran sonuna kadar temizle
_CYAN = "\033[38;5;44m"  # dolu çubuk / marka
_BRAND2 = "\033[38;5;39m"  # mavi aksan
_SPINC = "\033[38;5;39m"  # spinner
_GREEN = "\033[38;5;42m"

# Seviye renkleri + ikonları (report.py ile uyumlu)
_SEV = {
    "CRITICAL": ("\033[38;5;196m", "✖"),
    "HIGH": ("\033[38;5;208m", "▲"),
    "MEDIUM": ("\033[38;5;220m", "◆"),
    "LOW": ("\033[38;5;44m", "●"),
    "INFO": ("\033[38;5;245m", "·"),
}
_DA_HOT = "\033[1;97;41m"  # Domain Admin: beyaz/kırmızı zemin


def _fit(text: str, width: int) -> str:
    """ANSI kodlarını koruyarak metni görünür `width` karaktere kırpar."""
    return fit(text, width)


class Live:
    """Çok-satırlı canlı dashboard: altta sabit panel, üstünde akan günlük."""

    def __init__(self, total: int, *, enabled: bool | None = None,
                 title: str = "adscan"):
        self.total = max(0, total)
        self.done = 0
        self.title = title
        self._running: set[str] = set()
        self._started: dict[str, float] = {}
        self._detail = ""
        self._modules: dict[str, str] = {}
        self._coverage: list[dict] = []
        self._observations: dict[tuple, dict] = {}
        self._lock = threading.RLock()
        self._spin = itertools.cycle(_SPIN)
        self._frame = next(self._spin)
        self._t0 = time.time()
        tty = sys.stdout.isatty()
        self.enabled = (tty if enabled is None else (enabled and tty)) and config.TERMINAL_UI != "plain"
        self.color = tty and not os.environ.get("NO_COLOR") and config.TERMINAL_UI != "plain"
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._drawn = 0  # panelin o an kapladığı fiziksel satır sayısı
        self._height = self._panel_height()
        # canlı istatistikler (set_stats ile güncellenir)
        self._stats: dict = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
            "creds": 0, "da": False, "chain_done": 0, "chain_total": 0,
        }

    def _panel_height(self) -> int:
        """Terminal ölçüsüne göre panel yüksekliği (3 tam, 1 dar/kısa)."""
        size = shutil.get_terminal_size((80, 20))
        if size.columns < 40 or size.lines < 8:
            return 1
        if size.columns < 72 or size.lines < 14:
            return 3
        return min(8, size.lines - 6)

    # ------------------------------------------------------------------ yaşam döngüsü
    def start(self) -> Live:
        if self.enabled:
            sys.stdout.write("\033[?25l")
            self._thread = threading.Thread(target=self._animate, daemon=True)
            self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=0.5)
        with self._lock:
            if self.enabled and self._drawn:
                self._erase()
            if self.enabled:
                sys.stdout.write("\033[?25h")
                sys.stdout.flush()

    def __enter__(self) -> Live:
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    # ------------------------------------------------------------------ durum güncelleme
    def set_running(self, label: str, running: bool = True) -> None:
        with self._lock:
            if running:
                self._running.add(label)
                self._modules[label] = "çalışıyor"
                self._started.setdefault(label, time.time())
            else:
                self._running.discard(label)
                self._modules[label] = "ayrıştırılıyor"

    def register_modules(self, names) -> None:
        with self._lock:
            self._modules.update(dict.fromkeys(names, "bekliyor"))

    def finish_module(self, name: str, status: str) -> None:
        with self._lock:
            self._running.discard(name)
            self._modules[name] = status

    def set_coverage(self, rows) -> None:
        with self._lock:
            self._coverage = [dict(row) for row in rows if row.get("level") == "control"]

    def observe_control(self, row) -> None:
        with self._lock:
            self._observations[(row["module"], row["control_id"])] = dict(row)

    def _coverage_str(self) -> str:
        merged = dict(self._observations)
        for row in self._coverage:
            merged.pop(("", row["control_id"]), None)
            key = (row["module"], row["control_id"])
            # Planned rows do not overwrite an observation received during execution.
            if row["status"] != "planned" or key not in merged:
                merged[key] = row
        rows = list(merged.values())
        completed = sum(r["status"] in {"completed", "findings"} for r in rows)
        denied = sum(r["status"] == "access_denied" for r in rows)
        failed = sum(r["status"] == "failed" for r in rows)
        other = len(rows) - completed - denied - failed
        cached = sum(bool(r.get("resumed")) for r in rows)
        return (f"Kontrol: tamam {completed} · erişim yok {denied} · hata {failed} "
                f"· diğer {other} · checkpoint {cached}")

    def elapsed(self, label: str) -> float:
        """Modülün başlamasından bu yana geçen süre (sn)."""
        return time.time() - self._started.get(label, time.time())

    def set_detail(self, text: str) -> None:
        with self._lock:
            self._detail = clean(text).replace("\n", " ")

    def advance(self, n: int = 1) -> None:
        with self._lock:
            self.done += n

    def set_stats(self, **kw) -> None:
        """Canlı sayaçları günceller (crit/high/med/low/info/creds/da/chain_*)."""
        with self._lock:
            # CRITICAL=.. gibi büyük-harf anahtarlar da kabul (report sayacıyla uyum)
            for k, v in kw.items():
                key = k.upper() if k.upper() in self._stats else k
                if key in self._stats:
                    self._stats[key] = v

    # ------------------------------------------------------------------ çıktı
    def log(self, text: str = "") -> None:
        """Kalıcı bir satır basar (panelin üstüne); sonra paneli yeniden çizer."""
        with self._lock:
            if self.enabled and self._drawn:
                self._erase()
            print(text if self.color else clean(text))
            if self.enabled:
                self._render()

    # ------------------------------------------------------------------ iç çizim
    def _animate(self) -> None:
        while not self._stop.wait(0.1):
            with self._lock:
                self._frame = next(self._spin)
                self._render()

    def _erase(self) -> None:
        """Paneli ekrandan siler (imleci panel başına alıp alta kadar temizler)."""
        if not self._drawn:
            return
        buf = ["\r"]
        if self._drawn > 1:
            buf.append(f"\033[{self._drawn - 1}A")
        buf.append(_CLEAR_DOWN)
        sys.stdout.write("".join(buf))
        sys.stdout.flush()
        self._drawn = 0

    def _render(self) -> None:
        """Paneli yerinde (satır-satır temizleyerek) yeniden çizer."""
        if not self.enabled:
            return
        lines = self._compose()
        self._erase()
        buf: list[str] = ["\r"]
        for i, ln in enumerate(lines):
            buf.append(_CLEAR)
            buf.append(ln)
            if i < len(lines) - 1:
                buf.append("\n")
        sys.stdout.write("".join(buf))
        sys.stdout.flush()
        self._drawn = len(lines)

    # ------------------------------------------------------------------ panel içeriği
    def _c(self, code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if self.color else text

    def _bar(self, done: int, total: int, width: int, fill: str, empty: str,
             code: str) -> str:
        n = total or 1
        filled = max(0, min(width, round(width * done / n)))
        if self.color:
            return (f"{code}{fill * filled}{_RESET}{_DIM}{empty * (width - filled)}"
                    f"{_RESET}")
        return fill * filled + empty * (width - filled)

    def _fmt_elapsed(self) -> str:
        s = int(time.time() - self._t0)
        return f"{s // 60:02d}:{s % 60:02d}"

    def _running_str(self) -> str:
        if not self._running:
            return self._c(_DIM, "—")
        parts = []
        for lbl in sorted(self._running):
            el = int(self.elapsed(lbl))
            parts.append(f"{lbl}{self._c(_DIM, f' {el}s')}")
        return ", ".join(parts)

    def _tally_str(self) -> str:
        st = self._stats
        chips = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            code, icon = _SEV[sev]
            n = st[sev]
            chip = f"{icon}{n}"
            chips.append(self._c(code, chip) if n else self._c(_DIM, chip))
        creds = st["creds"]
        creds_s = (self._c(_GREEN, f"kimlik {creds}") if creds
                   else self._c(_DIM, "kimlik 0"))
        da_s = (self._c(_DA_HOT, " DA ✓ ") if st["da"]
                else self._c(_DIM, "DA ✗"))
        return "  ".join(["bulgu " + " ".join(chips), creds_s, da_s])

    def _compose(self) -> list[str]:
        width = shutil.get_terminal_size((80, 20)).columns
        self._height = self._panel_height()
        acc = self._c(_CYAN, "┃")
        spin = self._c(_SPINC, self._frame)

        # ---- 1 satırlık dar mod ----
        if self._height == 1:
            bar = self._bar(self.done, self.total, 10, "█", "░", _CYAN)
            line = (f"{spin} [{bar}] {self.done}/{self.total} "
                    f"{self._c(_DIM, self._fmt_elapsed())} {self._tally_str()}")
            return [_fit(line, width - 1)]

        # ---- satır 1: ilerleme ----
        bar = self._bar(self.done, self.total, 16, "█", "░", _CYAN)
        title = self._c(_BOLD, self.title) if self.color else self.title
        l1 = (f"{acc} {spin} {title} [{bar}] "
              f"{self._c(_BOLD, f'{self.done}/{self.total}')}  "
              f"{self._c(_DIM, self._fmt_elapsed())}  "
              f"{self._c(_DIM, '·')} {self._running_str()}")

        # ---- satır 2: bulgu sayacı / kimlik / DA ----
        l2 = f"{acc}   {self._tally_str()}"

        # ---- satır 3: saldırı yolu + o anki komut ----
        ct = self._stats["chain_total"]
        cd = self._stats["chain_done"]
        if ct:
            cbar = self._bar(cd, ct, 10, "■", "□", _GREEN)
            chain = f"yol [{cbar}] {cd}/{ct}"
        else:
            chain = self._c(_DIM, "yol  —")
        detail = self._detail.strip()
        detail_s = f"  {self._c(_DIM, '· ' + detail)}" if detail else ""
        l3 = f"{acc}   {chain}{detail_s}"

        if self._height == 3:
            return [_fit(l1, width - 1), _fit(l2, width - 1),
                    _fit(self._coverage_str(), width - 1)]
        lines = [l1, l2, f"{acc} {self._coverage_str()}"]
        remaining = sum(v == "bekliyor" for v in self._modules.values())
        lines.append(f"{acc} Modüller · kuyruk {remaining} · çalışan {len(self._running)}")
        ordered = sorted(self._modules, key=lambda n: (n not in self._running, self._modules[n] == "bekliyor", n))
        for name in ordered[:max(0, self._height - 5)]:
            elapsed = f" · {self.elapsed(name):.0f}s" if name in self._running else ""
            lines.append(f"{acc}   {name:<20} {self._modules[name]}{elapsed}")
        lines.append(l3)
        return [_fit(line, width - 1) for line in lines]

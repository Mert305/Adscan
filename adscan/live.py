"""Canlı terminal arayüzü — çok-satırlı dashboard.

Ekranın altında yerinde güncellenen kalıcı bir **durum paneli** çizer; üstünde
akan olay günlüğü kayar. Panel üç satırdır:

    1) spinner + ilerleme çubuğu + geçen süre + çalışan modüller
    2) canlı bulgu sayacı (seviyeye göre) + ele geçen kimlik + Domain Admin
    3) saldırı-yolu mini çubuğu + o an çalışan komut

Paralel modüllerin hepsi tek terminale yazdığından her çıktı tek kilitten
(RLock) geçer; böylece panel ile log satırları birbirine karışmaz. Panel
yüksekliği sabittir (daralma/büyüme titremesi olmaz); her kare satır-satır
`\\033[2K` ile temizlenip yeniden yazılır.

TTY değilse (boru/dosya/NO_COLOR) panel kapanır ve `log()` düz `print`e düşer —
çıktı otomasyon/log dosyalarında temiz kalır.
"""

from __future__ import annotations

import itertools
import os
import re
import shutil
import sys
import threading
import time

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
_ANSI_RX = re.compile(r"\033\[[0-9;]*m")

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
    if width <= 0:
        return ""
    out: list[str] = []
    vis = 0
    i = 0
    n = len(text)
    truncated = False
    while i < n:
        ch = text[i]
        if ch == "\033":
            m = _ANSI_RX.match(text, i)
            if m:
                out.append(m.group())
                i = m.end()
                continue
        if vis >= width:
            truncated = True
            break
        out.append(ch)
        vis += 1
        i += 1
    res = "".join(out)
    if truncated:
        res += _RESET
    return res


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
        self._lock = threading.RLock()
        self._spin = itertools.cycle(_SPIN)
        self._frame = next(self._spin)
        self._t0 = time.time()
        tty = sys.stdout.isatty()
        self.enabled = tty if enabled is None else (enabled and tty)
        self.color = tty and not os.environ.get("NO_COLOR")
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
        if size.columns < 54 or size.lines < 8:
            return 1
        return 3

    # ------------------------------------------------------------------ yaşam döngüsü
    def start(self) -> Live:
        if self.enabled:
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

    def __enter__(self) -> Live:
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    # ------------------------------------------------------------------ durum güncelleme
    def set_running(self, label: str, running: bool = True) -> None:
        with self._lock:
            if running:
                self._running.add(label)
                self._started.setdefault(label, time.time())
            else:
                self._running.discard(label)

    def elapsed(self, label: str) -> float:
        """Modülün başlamasından bu yana geçen süre (sn)."""
        return time.time() - self._started.get(label, time.time())

    def set_detail(self, text: str) -> None:
        with self._lock:
            self._detail = text

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
            print(text)
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
        buf: list[str] = ["\r"]
        if self._drawn > 1:
            buf.append(f"\033[{self._drawn - 1}A")
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
        inner = max(10, width - 2)
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

        return [_fit(l1, inner + 1), _fit(l2, inner + 1), _fit(l3, inner + 1)]

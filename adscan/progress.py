"""Modüllerden UI'a gevşek bağlı, thread-safe ilerleme olayları.

runner ve modüller `emit()` çağırır; UI katmanı `set_sink()` ile dinler.
Sink yoksa (test/import/boru hattı) olaylar sessizce yutulur — bu yüzden
modüller UI'dan habersiz kalır, orkestrasyon kodu bağımlılığı tek yerde tutar.

Olay türleri (kind):
  "start" — modül çalışmaya başladı            (module=label)
  "cmd"   — bir harici komut çalıştırılıyor     (module=adım, text=komut)
  "info"  — anlamlı durum (null session vb.)    (module=ad, text=mesaj)
"""

from __future__ import annotations

import threading
from collections.abc import Callable

_lock = threading.Lock()
_sink: Callable[[str, str, str], None] | None = None


def set_sink(fn: Callable[[str, str, str], None] | None) -> None:
    """Olayları alacak dinleyiciyi ayarlar (None = dinleyici yok)."""
    global _sink
    with _lock:
        _sink = fn


def emit(kind: str, module: str = "", text: str = "") -> None:
    """Bir olay yayınlar. Sink kaydı yoksa hiçbir şey yapmaz."""
    with _lock:
        sink = _sink
    # sink'i kilit DIŞINDA çağır: UI kendi kilidini alır, kilitlenme olmasın.
    if sink is not None:
        try:
            sink(kind, module, text)
        except Exception:
            # UI hatası taramayı asla düşürmesin.
            pass

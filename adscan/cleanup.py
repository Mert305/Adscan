"""Engagement temizliği / rollback (B).

Aktif modlar ortamda değişiklik yapabilir: hesap reanimasyonu (tombstone
restore), RBCD yazımı, shadow credential, parola sıfırlama, makine hesabı
ekleme. Profesyonel sızma testi "iz bırakmaz" — bu yüzden yapılan HER
değişikliği bir temizlik manifestine kaydederiz ve test sonunda (ya da sonradan
`--cleanup <manifest>` ile) geri alırız.

Kayıt, `config.audit` gibi süreç-global ve thread-safe'tir; modüller plumbing
olmadan `cleanup.record(...)` çağırır. Manifest `<outdir>`'e JSON yazılır.
Geri-alma komutu bilinen aksiyonlar `undo_argv` ile OTOMATİK geri alınabilir;
bilinmeyenler ELLE talimatıyla kaydedilir (dürüstlük: uydurma komut üretmeyiz).
"""

from __future__ import annotations

import datetime as _dt
import json
import threading
from dataclasses import asdict, dataclass, field

_lock = threading.Lock()
_ACTIONS: list[CleanupAction] = []


@dataclass
class CleanupAction:
    """Ortamda yapılan, geri alınması gereken tek bir değişiklik."""

    kind: str          # reanimation | rbcd | shadowcred | password-reset | computer-account | group-member
    target: str        # etkilenen nesne/host
    identifier: str    # hesap/SPN/isim
    description: str   # insan-okunur: ne yapıldı + nasıl geri alınır
    module: str = ""   # kaydeden modül
    undo_argv: list[str] = field(default_factory=list)  # varsa: otomatik geri-alma komutu
    done: bool = False  # teardown'da geri alındı mı
    ts: str = field(default_factory=lambda: _dt.datetime.now().isoformat(timespec="seconds"))


def record(kind: str, target: str, identifier: str, description: str, *,
           module: str = "", undo_argv: list[str] | None = None) -> CleanupAction:
    """Yapılan bir değişikliği temizlik kuyruğuna yazar (thread-safe)."""
    act = CleanupAction(kind=kind, target=target, identifier=identifier,
                        description=description, module=module,
                        undo_argv=list(undo_argv) if undo_argv else [])
    with _lock:
        _ACTIONS.append(act)
    try:
        from . import config
        config.audit(f"[cleanup:record] {kind} {identifier}@{target} ({module})")
    except Exception:
        pass
    return act


def actions() -> list[CleanupAction]:
    with _lock:
        return list(_ACTIONS)


def pending() -> list[CleanupAction]:
    """Henüz geri alınmamış aksiyonlar."""
    return [a for a in actions() if not a.done]


def reset() -> None:
    """Kuyruğu temizler (yeni tarama / test başlangıcı)."""
    with _lock:
        _ACTIONS.clear()


# ---------------------------------------------------------------------------
# Manifest (JSON) oku/yaz
# ---------------------------------------------------------------------------

def write_manifest(path: str, *, target: str = "") -> bool:
    """Kuyruktaki aksiyonları JSON manifestine yazar. Aksiyon yoksa yazmaz."""
    acts = actions()
    if not acts:
        return False
    data = {
        "target": target,
        "created": _dt.datetime.now().isoformat(timespec="seconds"),
        "actions": [asdict(a) for a in acts],
    }
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
        return True
    except OSError:
        return False


def load_manifest(path: str) -> list[CleanupAction]:
    """Manifestten aksiyonları yükler (hatada boş liste)."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []
    out: list[CleanupAction] = []
    for d in data.get("actions", []):
        if not isinstance(d, dict):
            continue
        out.append(CleanupAction(
            kind=d.get("kind", ""), target=d.get("target", ""),
            identifier=d.get("identifier", ""), description=d.get("description", ""),
            module=d.get("module", ""), undo_argv=list(d.get("undo_argv") or []),
            done=bool(d.get("done", False)), ts=d.get("ts", "")))
    return out


# ---------------------------------------------------------------------------
# Teardown (geri alma)
# ---------------------------------------------------------------------------

def teardown_plan(acts: list[CleanupAction]) -> list[str]:
    """Çalıştırmadan, insan-okunur geri-alma planı satırları."""
    lines: list[str] = []
    for i, a in enumerate(acts, 1):
        mode = "OTO" if a.undo_argv else "ELLE"
        status = " (geri alındı)" if a.done else ""
        lines.append(f"{i}. [{a.kind}] {a.identifier}@{a.target} [{mode}]{status} — {a.description}")
    return lines


def execute_teardown(acts: list[CleanupAction], *, dry_run: bool = False, runner=None):
    """`undo_argv` olan aksiyonları çalıştırır; (aksiyon, sonuç) listesi döndürür.

    `undo_argv` boş olan (ELLE) aksiyonlar atlanır (sonuç None). Test için
    `runner` enjekte edilebilir.
    """
    if runner is None:
        from .runner import run as runner
    results = []
    for a in acts:
        if a.done or not a.undo_argv:
            results.append((a, None))
            continue
        res = runner(a.undo_argv, tool=f"cleanup:{a.kind}", dry_run=dry_run)
        if getattr(res, "ok", False) and not dry_run:
            a.done = True
        results.append((a, res))
    return results

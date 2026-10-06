"""Çalışma zamanı görüntüleme ayarları (süreç boyunca tek yer).

Kimlik maskeleme kesişen (cross-cutting) bir görüntüleme kaygısı olduğundan
(runner dry-run echo + parser kanıtları) tek bir bayrakta toplanır.

Varsayılan: REDACT = False -> parola/hash çıktıda ve raporda AÇIK gösterilir
(yetkili test raporlaması için istenen davranış). `--redact` ile açılabilir.
"""

from __future__ import annotations

import datetime as _dt
import threading

REDACT = False
DEBUG = False  # --debug: ham komut/hata ayrıntılarını göster
AUDIT_LOG: str | None = None  # ayarlıysa çalıştırılan HER komut buraya yazılır
RETRIES = 2  # geçici bağlantı hatalarında komut başına yeniden deneme sayısı

# Her alt sürece (subprocess) eklenecek ortam değişkenleri. Kerberos saat-kayması
# düzeltmesi (faketime) bunu kullanır; boşsa süreçler normal ortamı miras alır.
CHILD_ENV: dict[str, str] = {}

_audit_lock = threading.Lock()


def set_child_env(env: dict[str, str] | None) -> None:
    """Tüm alt süreçlere eklenecek ortam değişkenlerini ayarlar ({}/None = temizle)."""
    global CHILD_ENV
    CHILD_ENV = dict(env) if env else {}


def set_redact(value: bool) -> None:
    global REDACT
    REDACT = value


def set_debug(value: bool) -> None:
    global DEBUG
    DEBUG = value


def set_audit_log(path: str | None) -> None:
    global AUDIT_LOG
    AUDIT_LOG = path


def set_retries(n: int) -> None:
    global RETRIES
    RETRIES = max(0, int(n))


def audit(line: str) -> None:
    """Denetim kaydına tek satır ekler (thread-safe). AUDIT_LOG yoksa no-op."""
    if not AUDIT_LOG:
        return
    stamp = _dt.datetime.now().isoformat(timespec="seconds")
    try:
        with _audit_lock, open(AUDIT_LOG, "a", encoding="utf-8") as fh:
            fh.write(f"{stamp}  {line}\n")
    except OSError:
        pass

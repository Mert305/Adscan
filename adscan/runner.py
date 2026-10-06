"""Harici araçları güvenli biçimde çalıştıran yardımcı katman.

Tüm komutlar subprocess ile liste olarak çağrılır (shell=False) — komut
enjeksiyonu riskini azaltır. Her çağrı için zaman aşımı ve tam çıktı döner.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass

from . import config, progress
from .util import redact_argv


@dataclass
class CommandResult:
    """Bir harici komut çalıştırmasının sonucu."""

    tool: str
    argv: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False
    error: str | None = None  # araç bulunamadı vb.
    error_kind: str = ""  # taksonomi: missing|timeout|oserror|auth|host-down|""

    @property
    def ok(self) -> bool:
        return self.error is None and not self.timed_out

    @property
    def combined(self) -> str:
        return (self.stdout or "") + ("\n" + self.stderr if self.stderr else "")

    @property
    def safe_cmd(self) -> str:
        """Komut dizgesi. config.REDACT açıksa parola/hash maskelenir."""
        argv = redact_argv(self.argv) if config.REDACT else self.argv
        return " ".join(argv)


@dataclass
class ToolStatus:
    """Bir aracın sistemde kurulu olup olmadığı."""

    name: str
    available: bool
    path: str | None = None
    note: str = ""


def strip_dryrun(text: str) -> str:
    """[DRY-RUN] önbilgi satırlarını analiz metninden çıkarır.

    Dry-run çıktısı çalıştırılacak komutu içerir; bu komut '--kerberoasting'
    gibi anahtar kelimeler barındırdığından ayrıştırıcıyı yanıltmasın diye
    tespit öncesi temizlenir.
    """
    return "\n".join(
        line for line in text.splitlines() if "[DRY-RUN]" not in line
    )


def which(name: str) -> str | None:
    """Aracın PATH üzerindeki yolunu döndürür (yoksa None)."""
    return shutil.which(name)


def resolve_tool(candidates: list[str]) -> ToolStatus:
    """Verilen isim adaylarından ilk bulunanı döndürür.

    Örn. netexec bazı sistemlerde `nxc`, bazılarında `netexec` adıyla kurulu.
    """
    for cand in candidates:
        path = which(cand)
        if path:
            return ToolStatus(name=cand, available=True, path=path)
    return ToolStatus(
        name=candidates[0],
        available=False,
        note=f"bulunamadı (denenen: {', '.join(candidates)})",
    )


def run(
    argv: list[str],
    *,
    tool: str,
    timeout: int = 300,
    dry_run: bool = False,
    cwd: str | None = None,
    retries: int | None = None,
) -> CommandResult:
    """Komutu çalıştırır; GEÇİCİ bağlantı hatalarında üstel backoff ile yeniden dener.

    Yalnızca bağlantı düzeyinde geçici hatalar (IO timeout / connection reset /
    broken pipe / refused — classify_output == 'host-down') yeniden denenir;
    kimlik hatası, eksik araç ve subprocess zaman aşımı yeniden DENENMEZ
    (ikincisi tam bütçe çalıştığından iş yapmış olabilir).
    """
    attempts = config.RETRIES if retries is None else retries
    delay = 1.5
    res = _run_once(argv, tool=tool, timeout=timeout, dry_run=dry_run, cwd=cwd)
    if dry_run:
        return res
    for _ in range(max(0, attempts)):
        if not _is_transient(res):
            return res
        time.sleep(delay)
        delay *= 2
        progress.emit("info", tool, "geçici bağlantı hatası — yeniden deneniyor…")
        res = _run_once(argv, tool=tool, timeout=timeout, dry_run=dry_run, cwd=cwd)
    return res


def _is_transient(res: CommandResult) -> bool:
    """Sonuç, yeniden denemeye değer GEÇİCİ bir bağlantı hatası mı?"""
    if res.ok and not classify_output(res.combined):
        return False  # başarılı ve temiz
    if res.error_kind == "missing" or res.timed_out:
        return False  # araç yok / tam zaman aşımı -> yeniden deneme
    text = (res.error or "") + "\n" + res.combined
    if _AUTH_FAIL_RX.search(text):
        return False  # kimlik hatası kalıcıdır
    if res.error_kind == "oserror":
        return True
    return bool(_HOST_DOWN_RX.search(text))


def _run_once(
    argv: list[str],
    *,
    tool: str,
    timeout: int = 300,
    dry_run: bool = False,
    cwd: str | None = None,
) -> CommandResult:
    """Bir komutu TEK sefer çalıştırır ve sonucu yapılandırılmış biçimde döndürür."""
    start = time.time()

    # Canlı UI'a "şu komut çalışıyor" bilgisini ver (sink yoksa no-op).
    disp = redact_argv(argv) if config.REDACT else argv
    cmdline = " ".join(disp)
    progress.emit("cmd", tool, cmdline)
    config.audit(f"[{tool}] {'(dry-run) ' if dry_run else ''}{cmdline}")

    if dry_run:
        return CommandResult(
            tool=tool,
            argv=argv,
            returncode=0,
            stdout=f"[DRY-RUN] çalıştırılacaktı: {cmdline}",
            stderr="",
            duration=0.0,
        )

    if which(argv[0]) is None:
        return CommandResult(
            tool=tool,
            argv=argv,
            returncode=None,
            stdout="",
            stderr="",
            duration=0.0,
            error=f"'{argv[0]}' PATH üzerinde bulunamadı",
            error_kind="missing",
        )

    # Saat-kayması düzeltmesi vb. için alt sürece ek ortam değişkenleri (varsa).
    child_env = {**os.environ, **config.CHILD_ENV} if config.CHILD_ENV else None

    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            cwd=cwd,
            env=child_env,
        )
        return CommandResult(
            tool=tool,
            argv=argv,
            returncode=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            duration=time.time() - start,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            tool=tool,
            argv=argv,
            returncode=None,
            stdout=(exc.stdout or b"").decode(errors="replace")
            if isinstance(exc.stdout, bytes)
            else (exc.stdout or ""),
            stderr=(exc.stderr or b"").decode(errors="replace")
            if isinstance(exc.stderr, bytes)
            else (exc.stderr or ""),
            duration=time.time() - start,
            timed_out=True,
            error=f"zaman aşımı ({timeout}s)",
            error_kind="timeout",
        )
    except OSError as exc:
        return CommandResult(
            tool=tool,
            argv=argv,
            returncode=None,
            stdout="",
            stderr="",
            duration=time.time() - start,
            error=str(exc),
            error_kind="oserror",
        )


# Çıktıdan auth/host-down gibi durumları sınıflandırmak için (modüller kullanır)
import re as _re  # noqa: E402

_AUTH_FAIL_RX = _re.compile(
    r"STATUS_LOGON_FAILURE|STATUS_ACCOUNT_RESTRICTION|STATUS_ACCOUNT_LOCKED_OUT|"
    r"STATUS_PASSWORD_EXPIRED|KDC_ERR_PREAUTH_FAILED|KDC_ERR_C_PRINCIPAL_UNKNOWN|"
    r"invalid credentials|authentication failed|access_denied|STATUS_ACCESS_DENIED",
    _re.IGNORECASE,
)
_HOST_DOWN_RX = _re.compile(
    r"connection refused|no route to host|timed out|connection reset|"
    r"host unreachable|STATUS_IO_TIMEOUT|unable to connect|network is unreachable|"
    r"broken pipe|connection error",
    _re.IGNORECASE,
)


def classify_output(text: str) -> str:
    """Araç çıktısından durum çıkarır: 'auth' | 'host-down' | '' (belirsiz)."""
    if _AUTH_FAIL_RX.search(text):
        return "auth"
    if _HOST_DOWN_RX.search(text):
        return "host-down"
    return ""

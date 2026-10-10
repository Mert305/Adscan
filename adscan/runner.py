"""Harici araçları güvenli biçimde çalıştıran yardımcı katman.

Tüm komutlar subprocess ile liste olarak çağrılır (shell=False) — komut
enjeksiyonu riskini azaltır. Her çağrı için zaman aşımı ve tam çıktı döner.
"""

from __future__ import annotations

import json
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
    observed_at: str = ""
    resumed: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None and not self.timed_out and self.returncode == 0

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


import glob as _glob

# impacket örnek scriptleri için ÇALIŞAN bir dizin (önbellek). None = henüz bakılmadı,
# "" = bulunamadı, "system" = PATH'teki scriptler sağlam, aksi halde dizin yolu.
_IMPACKET_DIR: str | None = None


def _impacket_script_runs(path: str) -> bool:
    """Verilen impacket script'i (pkg_resources hatası olmadan) çalışıyor mu?"""
    try:
        proc = subprocess.run([path, "-h"], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return False
    blob = (proc.stdout or "") + (proc.stderr or "")
    if "DistributionNotFound" in blob or ("pkg_resources" in blob and "Error" in blob):
        return False
    return "usage:" in blob.lower() or "impacket" in blob.lower()


def _find_impacket_dir() -> str:
    """impacket scriptlerinin SAĞLAM çalıştığı dizini bulur (önbellekli).

    Sırayla: PATH'teki sistem scripti sağlamsa 'system'; değilse bilinen venv
    konumlarında (pipx / go tool venv'leri / /opt) çalışan bir kopya aranır.
    """
    global _IMPACKET_DIR
    if _IMPACKET_DIR is not None:
        return _IMPACKET_DIR
    # 1) Sistem scripti sağlam mı?
    sysscript = which("secretsdump.py") or which("getST.py")
    if sysscript and _impacket_script_runs(sysscript):
        _IMPACKET_DIR = "system"
        return _IMPACKET_DIR
    # 2) Bilinen venv konumları
    patterns = [
        os.path.expanduser("~/.local/share/pipx/venvs/*/bin/secretsdump.py"),
        os.path.expanduser("~/go/bin/*/venv/bin/secretsdump.py"),
        "/root/go/bin/*/venv/bin/secretsdump.py",
        "/opt/*/venv/bin/secretsdump.py",
        "/opt/impacket/examples/secretsdump.py",
    ]
    for pat in patterns:
        for cand in sorted(_glob.glob(pat)):
            d = os.path.dirname(cand)
            if _impacket_script_runs(cand):
                _IMPACKET_DIR = d
                return _IMPACKET_DIR
    _IMPACKET_DIR = ""
    return _IMPACKET_DIR


def resolve_impacket(script: str) -> str | None:
    """Bir impacket script adını (ör. 'getST.py') ÇALIŞAN bir yola çözer.

    Sistem kopyası bozuksa (DistributionNotFound) otomatik olarak çalışan bir
    venv kopyasına yönlendirir. Hiçbir yerde yoksa None döner.
    """
    d = _find_impacket_dir()
    if d == "system":
        return which(script)
    if d:
        cand = os.path.join(d, script)
        if os.path.isfile(cand):
            return cand
    # Son çare: PATH'te varsa (çalışmasa bile çağıran plan/komut için kullanabilir)
    return which(script)


def impacket_status() -> ToolStatus:
    """impacket örnek scriptlerinin (secretsdump/ntlmrelayx) gerçekten çalışır
    durumda olup olmadığını saptar.

    Bazı sistemlerde script'ler PATH'te olsa da kurulum meta verisi (egg-info /
    pkg_resources) kırık olduğundan `DistributionNotFound` ile anında patlar —
    bu sessiz başarısızlığı önceden yakalamak için scripti `-h` ile dener.
    """
    path = which("secretsdump.py") or which("ntlmrelayx.py")
    name = "impacket (secretsdump/ntlmrelayx)"
    if not path:
        return ToolStatus(name=name, available=False,
                          note="impacket örnek scriptleri PATH'te yok")
    try:
        proc = subprocess.run([path, "-h"], capture_output=True, text=True,
                              timeout=20)
    except (OSError, subprocess.SubprocessError) as exc:
        return ToolStatus(name=name, available=False, path=path,
                          note=f"çalıştırılamadı: {exc}")
    blob = (proc.stdout or "") + (proc.stderr or "")
    if "DistributionNotFound" in blob or "pkg_resources" in blob and "Error" in blob:
        # Sistem kopyası bozuk — çalışan bir venv kopyası var mı?
        resolved = resolve_impacket("secretsdump.py")
        if resolved and resolved != path and _impacket_script_runs(resolved):
            return ToolStatus(name=name, available=True, path=resolved,
                              note="sistem kopyası bozuk; çalışan kopyaya yönlendirildi")
        return ToolStatus(name=name, available=False, path=path,
                          note="KIRIK kurulum (DistributionNotFound) — çalışan kopya da yok; "
                               "onarın: pipx install impacket --force")
    return ToolStatus(name=name, available=True, path=path)


def _run_with_retries(
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


def run(argv: list[str], *, tool: str, timeout: int = 300, dry_run: bool = False,
        cwd: str | None = None, retries: int | None = None) -> CommandResult:
    from datetime import datetime, timezone

    from .checkpoint import current

    scope = current() if not dry_run else None
    key = scope[0].key(scope[1], argv, tool, cwd) if scope else None
    cached = scope[0].get(key, argv) if scope else None
    if cached:
        progress.emit("info", tool, "checkpoint: tamamlanan kontrol geri yüklendi")
        _notify_control(cached, scope)
        return cached
    result = _run_with_retries(argv, tool=tool, timeout=timeout, dry_run=dry_run,
                               cwd=cwd, retries=retries)
    result.observed_at = datetime.now(timezone.utc).isoformat()
    if scope:
        scope[0].save(key, scope[1], result, cwd)
    _notify_control(result, scope)
    return result


def _notify_control(result, scope):
    from .assessment import control_id, result_status
    status, _ = result_status(result)
    progress.emit("control", result.tool, json.dumps({
        "control_id": control_id(result), "module": scope[1] if scope else "",
        "status": status, "resumed": result.resumed, "level": "control"}))


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


# proxychains ile SARILMAYACAK yerel/offline araçlar (ağ kullanmaz).
_NO_PROXY_TOOLS = {"hashcat", "john", "dig", "nslookup", "faketime"}


def _maybe_proxy(argv: list[str]) -> list[str]:
    """config.PROXYCHAINS açıksa ağa dönük komutu 'proxychains -q' ile sarar."""
    if not getattr(config, "PROXYCHAINS", False) or not argv:
        return argv
    if argv[0] in _NO_PROXY_TOOLS or os.path.basename(argv[0]) in _NO_PROXY_TOOLS:
        return argv
    if argv[0] in ("proxychains", "proxychains4"):
        return argv  # zaten sarılı
    if which("proxychains4"):
        return ["proxychains4", "-q", *argv]
    if which("proxychains"):
        return ["proxychains", "-q", *argv]
    return argv


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

    # Pivoting: ağa dönük komutları proxychains ile sar (yerel/offline araçlar hariç).
    argv = _maybe_proxy(argv)

    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            cwd=cwd,
            env=child_env,
            # Orkestratör etkileşimsizdir: stdin'i kapat ki parola soran bir araç
            # (ör. windapsearch -u verilip -p verilmezse) terminalden girdi
            # bekleyip askıda KALMASIN; getpass EOF alıp hızlıca hata versin.
            stdin=subprocess.DEVNULL,
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

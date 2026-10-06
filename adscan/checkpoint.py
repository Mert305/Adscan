"""Atomic command checkpoints, scoped to one scan and one worker module."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, replace
from datetime import datetime, timezone
from pathlib import Path

from . import config

_current = ContextVar("checkpoint", default=None)
# Only collection modules may reuse results. Stateful attack flows always execute.
REUSABLE = {"nmap", "dns", "nxc-smb", "nxc-ldap", "windapsearch", "smbmap",
            "certipy", "bloodhound", "bloodyad", "bloodyad-enum", "gmsa", "access",
            "mssql", "winrm"}


class Checkpoint:
    def __init__(self, outdir, target, *, resume=False):
        digest = hashlib.sha256(target.encode()).hexdigest()[:24]
        self.path = Path(outdir) / f"checkpoint-{digest}.json"
        self.lock = threading.Lock()
        self.entries = {}
        if resume and self.path.exists():
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if data.get("version") != 1 or data.get("target") != target:
                raise ValueError("Checkpoint sürümü veya hedefi uyuşmuyor")
            self.entries = data["entries"]
        self.target = target
        self._write()

    def _write(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".checkpoint-", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump({"version": 1, "target": self.target, "entries": self.entries},
                          stream, ensure_ascii=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    @contextmanager
    def module(self, name, enabled=True):
        token = _current.set((self, name) if enabled and name in REUSABLE else None)
        try:
            yield
        finally:
            _current.reset(token)

    def invalidate(self, module):
        with self.lock:
            self.entries = {k: v for k, v in self.entries.items() if v["module"] != module}
            self._write()

    def key(self, module, argv, tool, cwd):
        from .runner import which
        binary = which(argv[0]) if argv else None
        stat = os.stat(binary) if binary else None
        identity = [module, argv, tool, os.path.abspath(cwd or os.getcwd()),
                    config.CHILD_ENV, config.PROXYCHAINS, config.REDACT,
                    binary, (stat.st_size, stat.st_mtime_ns) if stat else None]
        return hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()

    def get(self, key, argv):
        from .runner import CommandResult
        with self.lock:
            entry = self.entries.get(key)
            if not entry:
                return None
            # Collectors with output files must run again if artifacts disappeared.
            if any(not Path(p).is_file() for p in entry.get("artifacts", [])):
                return None
            return replace(CommandResult(**entry["result"]), argv=argv, resumed=True)

    def save(self, key, module, result, cwd=None):
        from .assessment import result_status
        if result_status(result)[0] != "completed":
            return
        artifacts = []
        for i, arg in enumerate(result.argv[:-1]):
            if arg in {"-oX", "-output", "--asreproast", "--kerberoasting"}:
                path = Path(result.argv[i + 1])
                if str(path) == "-":
                    continue  # stdout is persisted in the result
                files = list(path.parent.glob(path.name + "*.json")) if arg == "-output" else [path]
                if not files or any(not p.is_file() for p in files):
                    return
                artifacts.extend(str(p.resolve()) for p in files)
        if module == "bloodhound":
            if not cwd:
                return  # nxc collector writes outside our artifact directory
            files = list(Path(cwd).glob("*.json")) + list(Path(cwd).glob("*.zip"))
            if not files:
                return
            artifacts.extend(str(p.resolve()) for p in files)
        if module == "certipy" and not artifacts:
            return
        saved = asdict(result)
        saved["argv"] = []  # credentials in command arguments are never persisted
        saved["observed_at"] = result.observed_at or datetime.now(timezone.utc).isoformat()
        with self.lock:
            self.entries[key] = {"module": module, "result": saved, "artifacts": artifacts}
            self._write()


def current():
    return _current.get()

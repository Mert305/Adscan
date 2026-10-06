"""Parola-tekrarı süpürmesi (password reuse sweep).

Bilinen/sorulan TEK bir parolayı, enumere edilmiş TÜM domain kullanıcılarında
dener. Amaç: bir kullanıcının parolasının başka hesaplarda tekrar kullanılmasını
yakalamak (ör. checkpoint.htb'de mark.davies, alex.turner'ın parolasını tekrar
kullanıyordu).

Kullanıcı başına **tek deneme** yapıldığından kilitlenme riski en düşüktür
(badPwdCount hesap başına en fazla 1 artar).
"""

from __future__ import annotations

import os
import re

from .findings import Credential, ScanReport
from .modules import nxc_scan
from .registry import ScanContext
from .runner import run, strip_dryrun


def parse_hits(output: str, password: str, report: ScanReport,
               *, source: str = "pw-sweep") -> list[Credential]:
    """nxc çıktısından, TAM bu parolayla doğrulanan kullanıcıları çıkarır.

    Yalnızca `:<password>` ile biten `[+]` satırlarını kabul eder (gürültü/yanlış
    eşleşme olmaz). Yeni eklenen kimlikleri döndürür.
    """
    rx = re.compile(
        r"\[\+\]\s+(?:([^\s\\]+)\\)?([^\s:]+):" + re.escape(password)
        + r"(\s+\(Pwn3d!\))?")
    new: list[Credential] = []
    for m in rx.finditer(strip_dryrun(output)):
        dom, user, pwn = m.group(1), m.group(2), m.group(3)
        cred = Credential(
            username=user, secret=password, kind="password",
            domain=dom or report.domain or "", source=source, admin=bool(pwn))
        before = len(report.credentials)
        report.add_credential(cred)
        if len(report.credentials) > before:
            new.append(cred)
    return new


def sweep_password(ctx: ScanContext, report: ScanReport, password: str, *,
                   users: list[str] | None = None, ui=None,
                   source: str = "pw-sweep") -> list[Credential]:
    """Tek parolayı verilen kullanıcı listesinde dener; yeni kimlikleri döndürür."""
    users = users or list(report.users)
    users = [u for u in dict.fromkeys(users) if u]  # tekilleştir, boşları at
    if not users or not password:
        return []

    dc = ctx.target.split(",")[0].split("/")[0].strip()
    try:
        os.makedirs(ctx.outdir, exist_ok=True)
        userfile = os.path.join(ctx.outdir, "pw-sweep-users.txt")
        with open(userfile, "w", encoding="utf-8") as fh:
            fh.write("\n".join(users))
    except OSError:
        return []

    argv = [nxc_scan.tool().name, "smb", dc, "-u", userfile, "-p", password,
            "--continue-on-success"]
    if ctx.domain:
        argv += ["-d", ctx.domain]
    if ctx.use_kerberos:
        argv += ["-k"]
    res = run(argv, tool="pw-sweep", timeout=ctx.timeout, dry_run=ctx.dry_run)
    return parse_hits(res.combined, password, report, source=source)

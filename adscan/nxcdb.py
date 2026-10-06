"""netexec / crackmapexec SQLite veritabanından sonuç okuma.

Neden: stdout'u regex'le kazımak sürümden sürüme (nxc çıktı formatı, LDAP tablo
düzeni) kırılıyor. netexec zaten her şeyi kendi çalışma alanı (workspace)
veritabanına yazar:  ~/.nxc/workspaces/<ws>/{smb,ldap}.db
Bu DB'yi okumak çok daha sağlamdır.

Şema sürümden sürüme değiştiğinden burada HİÇBİR sütun sabit varsayılmaz:
tablolar `sqlite_master`'dan, sütunlar `PRAGMA table_info`'dan dinamik
keşfedilir ve yalnızca var olanlar okunur. Her şey salt-okunur açılır ve
tüm hatalar yutulur — DB okuma asla taramayı düşürmez.
"""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass, field

# netexec'in (ve eski crackmapexec'in) workspace kök dizinleri
DEFAULT_DB_DIRS = [
    "~/.nxc/workspaces",
    "~/.netexec/workspaces",
    "~/.cme/workspaces",
]


@dataclass
class DbRecords:
    """Bir veya birden çok nxc DB'sinden birleştirilmiş kayıtlar."""

    hosts: list[dict] = field(default_factory=list)   # ip, hostname, domain, os, dc, signing...
    users: list[dict] = field(default_factory=list)   # domain, username, password, credtype
    admin: list[tuple] = field(default_factory=list)  # (host_ip, domain, username)
    shares: list[dict] = field(default_factory=list)  # ip, name, read, write, remark
    groups: list[dict] = field(default_factory=list)  # domain, name


# ---------------------------------------------------------------------------
# Düşük seviye yardımcılar (hepsi hataya dayanıklı)
# ---------------------------------------------------------------------------

def find_dbs(proto: str, workspace: str = "default", base: str | None = None) -> list[str]:
    """Verilen protokol (smb/ldap) için var olan DB dosyalarının yollarını döndürür."""
    dirs = [base] if base else [os.path.expanduser(d) for d in DEFAULT_DB_DIRS]
    out: list[str] = []
    for d in dirs:
        if not d:
            continue
        path = os.path.join(d, workspace, f"{proto}.db")
        if os.path.isfile(path) and path not in out:
            out.append(path)
    return out


def _tables(con: sqlite3.Connection) -> set[str]:
    try:
        return {r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
    except sqlite3.Error:
        return set()


def _columns(con: sqlite3.Connection, table: str) -> set[str]:
    try:
        return {r[1] for r in con.execute(f"PRAGMA table_info({table})")}
    except sqlite3.Error:
        return set()


def _rows(con: sqlite3.Connection, table: str) -> list[sqlite3.Row]:
    try:
        return con.execute(f"SELECT * FROM {table}").fetchall()
    except sqlite3.Error:
        return []


def _pick(d: dict, *names):
    """Verilen aday isimlerden ilk var olan (ve boş olmayan) değeri döndürür."""
    for n in names:
        if n in d and d[n] not in (None, ""):
            return d[n]
    return None


# ---------------------------------------------------------------------------
# Tek DB okuma
# ---------------------------------------------------------------------------

def read_db(path: str, *, targets: set[str] | None = None) -> DbRecords:
    """Tek bir nxc DB dosyasını okuyup kayıtları döndürür (salt-okunur, güvenli)."""
    rec = DbRecords()
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except sqlite3.Error:
        return rec
    con.row_factory = sqlite3.Row
    try:
        tabs = _tables(con)

        # --- hosts ---
        host_by_id: dict = {}
        if "hosts" in tabs:
            hcols = _columns(con, "hosts")
            for r in _rows(con, "hosts"):
                d = {k: r[k] for k in hcols}
                ip = _pick(d, "ip", "host", "address")
                d["_ip"] = ip
                if "id" in d:
                    host_by_id[d["id"]] = d
                if targets and ip and ip not in targets:
                    continue
                rec.hosts.append(d)

        # --- users ---
        user_by_id: dict = {}
        if "users" in tabs:
            ucols = _columns(con, "users")
            for r in _rows(con, "users"):
                d = {k: r[k] for k in ucols}
                if "id" in d:
                    user_by_id[d["id"]] = d
                rec.users.append(d)

        # --- admin erişimi (admin_relations: userid -> hostid) ---
        for tname in ("admin_relations", "admin_access", "loggedin_relations"):
            if tname not in tabs:
                continue
            acols = _columns(con, tname)
            uid_col = "userid" if "userid" in acols else ("user_id" if "user_id" in acols else None)
            hid_col = "hostid" if "hostid" in acols else ("host_id" if "host_id" in acols else None)
            if not (uid_col and hid_col):
                continue
            for r in _rows(con, tname):
                u = user_by_id.get(r[uid_col])
                h = host_by_id.get(r[hid_col])
                if not (u and h):
                    continue
                ip = h.get("_ip")
                if targets and ip and ip not in targets:
                    continue
                rec.admin.append((ip, _pick(u, "domain") or "",
                                  _pick(u, "username") or ""))
            break  # ilk bulunan admin tablosu yeter

        # --- paylaşımlar (shares: hostid -> read/write) ---
        if "shares" in tabs:
            scols = _columns(con, "shares")
            hid_col = "hostid" if "hostid" in scols else ("host_id" if "host_id" in scols else None)
            for r in _rows(con, "shares"):
                d = {k: r[k] for k in scols}
                ip = None
                if hid_col and d.get(hid_col) in host_by_id:
                    ip = host_by_id[d[hid_col]].get("_ip")
                if targets and ip and ip not in targets:
                    continue
                rec.shares.append({
                    "ip": ip,
                    "name": _pick(d, "name", "share", "sharename"),
                    "read": bool(_pick(d, "read", "readable")),
                    "write": bool(_pick(d, "write", "writable")),
                    "remark": _pick(d, "remark", "comment") or "",
                })

        # --- gruplar ---
        if "groups" in tabs:
            gcols = _columns(con, "groups")
            for r in _rows(con, "groups"):
                d = {k: r[k] for k in gcols}
                rec.groups.append({"domain": _pick(d, "domain") or "",
                                   "name": _pick(d, "name", "groupname") or ""})
    finally:
        con.close()
    return rec


# ---------------------------------------------------------------------------
# smb + ldap birleştirme
# ---------------------------------------------------------------------------

def collect(*, targets: set[str] | None = None, workspace: str = "default",
            base: str | None = None, protocols=("smb", "ldap")) -> DbRecords:
    """smb ve ldap DB'lerini okuyup tek DbRecords'ta birleştirir."""
    merged = DbRecords()
    for proto in protocols:
        for path in find_dbs(proto, workspace, base):
            rec = read_db(path, targets=targets)
            merged.hosts += rec.hosts
            merged.users += rec.users
            merged.admin += rec.admin
            merged.shares += rec.shares
            merged.groups += rec.groups
    return merged


def available(workspace: str = "default", base: str | None = None) -> bool:
    """Herhangi bir nxc DB'si bulunuyor mu?"""
    return bool(find_dbs("smb", workspace, base) or find_dbs("ldap", workspace, base))

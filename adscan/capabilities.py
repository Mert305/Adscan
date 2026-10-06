"""Harici araç sürüm + yetenek tespiti (F).

netexec/nmap/certipy sürümden sürüme bayrak ve modül adı değiştirir
(ör. eski 'petitpotam' modülü NetExec'ten kaldırıldı, yerine 'coerce_plus'
geldi). Bu modül kurulu araçların sürümünü saptar ve "şu nxc modülü var mı?"
sorusunu yanıtlar; böylece komutlar uyarlanır ve sessiz başarısızlıklar önlenir.

Tasarım: saf ayrıştırıcılar (`parse_version`, `parse_nxc_modules`) metinden
çalışır ve bağımsız test edilir; araç çağıran sarmalayıcılar sonucu
önbelleğe alır (araç başına tek çağrı) ve tüm hataları yutar — yetenek
tespiti asla taramayı düşürmez.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .runner import resolve_tool, run

# Sürüm: "7.94SVN", "1.3.0", "v4.8.2" — sondaki harfe (SVN vb.) takılmasın diye
# sonda \b YOK; baştaki rakam bir sürüm parçasının ortasında başlamasın diye
# öncesinde rakam/nokta olmamalı.
_VERSION_RX = re.compile(r"(?<![\d.])(\d+\.\d+(?:\.\d+)?)")

# nxc -L çıktısında modül satırı: "modul_adi   Açıklama..." (2+ boşlukla ayrılır)
_NXC_MODULE_RX = re.compile(r"^\s*(?:\[\*\]\s*)?([a-z][a-z0-9_\-]{2,})\s{2,}\S", re.MULTILINE)
_NXC_MODULE_NOISE = {"description", "options", "usage", "modules", "available"}


def parse_version(text: str) -> str | None:
    """Araç `--version`/`-V` çıktısından ilk anlamlı sürüm dizgesini çıkarır."""
    if not text:
        return None
    m = _VERSION_RX.search(text)
    return m.group(1) if m else None


def parse_nxc_modules(text: str) -> set[str]:
    """`nxc <proto> -L` çıktısından modül adlarını çıkarır."""
    mods: set[str] = set()
    for name in _NXC_MODULE_RX.findall(text or ""):
        low = name.lower()
        if low in _NXC_MODULE_NOISE:
            continue
        mods.add(low)
    return mods


# ---------------------------------------------------------------------------
# Araç çağıran sarmalayıcılar (önbellekli, hataya dayanıklı)
# ---------------------------------------------------------------------------

_version_cache: dict[str, str | None] = {}
_nxc_modules_cache: set[str] | None = None


def tool_version(name: str, *, candidates: list[str] | None = None) -> str | None:
    """Aracın sürümünü döndürür (bulunamazsa/parse edilemezse None). Önbellekli."""
    key = name
    if key in _version_cache:
        return _version_cache[key]
    status = resolve_tool(candidates or [name])
    if not status.available:
        _version_cache[key] = None
        return None
    ver = None
    for flag in ("--version", "-V", "version"):
        res = run([status.name, flag], tool=f"cap:{status.name}", timeout=20, retries=0)
        if res.ok and (res.stdout or res.stderr):
            ver = parse_version(res.combined)
            if ver:
                break
    _version_cache[key] = ver
    return ver


def nxc_modules(candidates: list[str] | None = None) -> set[str]:
    """Kurulu nxc/netexec'in sunduğu modül adları kümesi (önbellekli)."""
    global _nxc_modules_cache
    if _nxc_modules_cache is not None:
        return _nxc_modules_cache
    status = resolve_tool(candidates or ["nxc", "netexec", "crackmapexec", "cme"])
    mods: set[str] = set()
    if status.available:
        res = run([status.name, "smb", "-L"], tool=f"cap:{status.name}-L",
                  timeout=30, retries=0)
        if res.ok:
            mods = parse_nxc_modules(res.combined)
    _nxc_modules_cache = mods
    return mods


def nxc_has_module(name: str) -> bool:
    """nxc'de verilen modül kurulu mu? Modül listesi boşsa (tespit edilemedi)
    engellememek için True döner — yani 'bilmiyorsak dene'."""
    mods = nxc_modules()
    return (name.lower() in mods) if mods else True


@dataclass
class Capabilities:
    """Kurulu araçların sürüm + yetenek anlık görüntüsü (--check için)."""

    nxc: str | None = None
    nmap: str | None = None
    certipy: str | None = None
    bloodyad: str | None = None
    nxc_mods: set[str] = field(default_factory=set)

    @property
    def nmap_supports_xml(self) -> bool:
        """nmap her sürümde -oX destekler; kurulu ise True."""
        return self.nmap is not None


def detect() -> Capabilities:
    """Tüm ilgili araçların sürüm/yeteneklerini bir kez saptar."""
    return Capabilities(
        nxc=tool_version("nxc", candidates=["nxc", "netexec", "crackmapexec", "cme"]),
        nmap=tool_version("nmap"),
        certipy=tool_version("certipy", candidates=["certipy", "certipy-ad"]),
        bloodyad=tool_version("bloodyAD", candidates=["bloodyAD", "bloodyad"]),
        nxc_mods=nxc_modules(),
    )


def reset_cache() -> None:
    """Test/yeniden-tespit için önbelleği temizler."""
    global _nxc_modules_cache
    _version_cache.clear()
    _nxc_modules_cache = None

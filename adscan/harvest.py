"""Tarama çıktılarından kullanıcı adı / host çıkarma (autopilot için).

Bir aşamanın (nmap/nxc/windapsearch) çıktısından sonraki aşamaya girdi üretir:
kullanıcı listesi (spray/asrep için) ve host listesi (reuse için).
"""

from __future__ import annotations

import re

# "domain\user" sütunu (nxc --users) ya da sAMAccountName (ldap/windapsearch)
_SAM_RX = re.compile(r"sAMAccountName:\s*([A-Za-z0-9._$-]+)", re.IGNORECASE)
_DOMUSER_RX = re.compile(r"\b[A-Za-z0-9.-]+\\([A-Za-z0-9._$-]+)")
_IP_RX = re.compile(r"Nmap scan report for (?:\S+ \()?(\d{1,3}(?:\.\d{1,3}){3})")

# Kullanıcı sayılmayacak gürültü (başarı/durum anahtar kelimeleri)
_NOT_USER = {
    "pwn3d", "guest", "status_logon_failure", "smb", "ldap", "winrm",
    "enumerated", "domain", "false", "true", "none",
}


def _clean(users: list[str], *, keep_machines: bool = False) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for u in users:
        uu = u.strip()
        low = uu.lower()
        if not uu or low in _NOT_USER:
            continue
        if uu.endswith("$") and not keep_machines:
            continue  # makine hesabı (spray için anlamsız)
        if low not in seen:
            seen.add(low)
            out.append(uu)
    return out


def users_from_text(text: str, *, keep_machines: bool = False) -> list[str]:
    """Metinden kullanıcı adlarını çıkarır (sAMAccountName + domain\\user)."""
    found = _SAM_RX.findall(text)
    for m in _DOMUSER_RX.finditer(text):
        # [+]/[*] durum satırlarından kullanıcı çıkarma (host\user olabilir)
        found.append(m.group(1))
    return _clean(found, keep_machines=keep_machines)


def hosts_from_text(text: str) -> list[str]:
    """nmap çıktısından host IP'lerini çıkarır."""
    seen: set[str] = set()
    out: list[str] = []
    for ip in _IP_RX.findall(text):
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def harvest(report) -> tuple[list[str], list[str]]:
    """Rapordaki ham çıktılardan (kullanıcılar, host'lar) döndürür ve rapora yazar."""
    blob = "\n".join(report.raw_outputs.values())
    users = users_from_text(blob)
    hosts = hosts_from_text(blob)
    # mevcutlarla birleştir
    for u in users:
        if u not in report.users:
            report.users.append(u)
    for h in hosts:
        if h not in report.hosts:
            report.hosts.append(h)
    return report.users, report.hosts

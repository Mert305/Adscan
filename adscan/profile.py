"""Engagement profili: tekrar eden ayarları tek dosyada topla (JSON / YAML).

Bir engagement'ta hedef, domain, kapsam dosyası, modül seti, sözlük, çıktı klasörü
hep aynıdır. Her seferinde uzun komut yazmak yerine bir profil dosyası verilir:

    adscan --profile engagement.json

Profildeki anahtarlar argparse `dest` adlarıdır (target, domain, username, scope,
wordlist, full, adcs, listener_ip, …). KOMUT SATIRINDA açıkça verilen değerler
profili EZER (profil yalnızca varsayılanları değiştirir).

Bağımlılık yok: JSON standart kütüphane; YAML yalnızca `pyyaml` kuruluysa.
"""

from __future__ import annotations

import json
import os

# Profilden kabul edilen argparse dest'leri (bilinmeyen anahtarlar reddedilir —
# yazım hatası sessizce yutulmasın, bir şey ezmesin).
ALLOWED_KEYS = {
    "target", "username", "password", "nthash", "domain", "only", "jobs", "outdir",
    "timeout", "redact", "kerberos", "retries", "scope", "audit_log", "html",
    "no_extra_reports", "nxc_workspace", "no_nxc_db", "keep_old_reports",
    "full", "auto", "auto_passwords", "assume_breach", "adcs", "bloodyad",
    "bloodhound", "mssql", "winrm", "crack", "wordlist", "crack_timeout", "quiet",
    "spray", "spray_passwords", "spray_passlist", "spray_userlist", "spray_namelist",
    "spray_users", "spray_delay", "spray_force",
    "active_attacks", "launch", "interface", "listener_ip", "relay_targets",
    "adcs_ca_url", "capture_seconds", "reuse", "reuse_targets",
}


class ProfileError(Exception):
    """Profil okunamadı / geçersiz."""


def _load_raw(path: str) -> dict:
    if not os.path.isfile(path):
        raise ProfileError(f"profil dosyası yok: {path}")
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    # Uzantıya göre: .json -> json; .yaml/.yml -> pyyaml (varsa)
    low = path.lower()
    if low.endswith((".yaml", ".yml")):
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise ProfileError(
                "YAML profili için 'pyyaml' gerekli (pip install pyyaml) ya da .json kullanın"
            ) from exc
        data = yaml.safe_load(text)
    else:
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise ProfileError(f"geçersiz JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ProfileError("profil bir nesne (anahtar: değer) olmalı")
    return data


def load(path: str) -> dict:
    """Profili okur, yalnızca izinli anahtarları döndürür; bilinmeyende hata verir."""
    data = _load_raw(path)
    unknown = set(data) - ALLOWED_KEYS
    if unknown:
        raise ProfileError(
            f"profilde bilinmeyen anahtar(lar): {', '.join(sorted(unknown))}. "
            f"Geçerli anahtarlar argparse dest adlarıdır (ör. target, domain, full, scope)."
        )
    return data

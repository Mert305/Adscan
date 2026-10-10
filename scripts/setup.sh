#!/usr/bin/env bash
# AdScan kurulum — Debian/Ubuntu/WSL (24.04 / PEP 668 uyumlu).
#   bash scripts/setup.sh
# Harici araçları kurar: nmap + netexec(nxc) + certipy + bloodyAD + impacket.
# adscan'in KENDİSİ saf stdlib olduğundan kurulum gerektirmez — repo dizininden
# `python3 -m adscan ...` ile çalışır. Bu script yalnız bağımlılık araçlarını kurar.
#
# NOT: sudo (apt) için parola ister — GERÇEK bir WSL/terminal oturumunda çalıştır,
# arka planda değil (parola istemi takılır).
set -uo pipefail

say()  { printf '\033[1;36m[kurulum]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[uyarı]\033[0m %s\n' "$*"; }

# 1) Sistem paketleri (araçlar + pipx + istemciler)
if command -v apt-get >/dev/null 2>&1; then
    say "apt paketleri (nmap, pipx, ldap/krb/smb istemcileri)…"
    sudo apt-get update -qq
    sudo apt-get install -y -qq \
        nmap pipx python3-full \
        dnsutils ldap-utils krb5-user smbclient git curl \
        || warn "bazı apt paketleri kurulamadı"
else
    warn "apt yok — nmap/pipx'i elle kurman gerekebilir."
fi

export PATH="$HOME/.local/bin:$PATH"
command -v pipx >/dev/null 2>&1 && pipx ensurepath >/dev/null 2>&1 || true

# 2) Pentest CLI araçları (pipx = izole venv; PEP 668'i aşar)
inst() {  # ad  kaynak
    if command -v "$1" >/dev/null 2>&1; then
        say "$1 zaten kurulu — atlanıyor."
    else
        say "$1 kuruluyor ($2)…"
        pipx install "$2" || warn "$1 kurulamadı — elle dene: pipx install $2"
    fi
}
if command -v pipx >/dev/null 2>&1; then
    inst nxc            "git+https://github.com/Pennyw0rth/NetExec.git"
    inst certipy        "certipy-ad"
    inst bloodyAD       "bloodyAD"
    command -v secretsdump.py >/dev/null 2>&1 || { say "impacket…"; pipx install impacket || warn "impacket kurulamadı"; }
else
    warn "pipx yok — araçlar kurulamadı."
fi

# 3) Doğrulama
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
say "Kontrol:  cd $SCRIPT_DIR && python3 -m adscan --check"
echo
command -v nmap    >/dev/null 2>&1 && say "nmap     ✓" || warn "nmap     ✗"
command -v nxc     >/dev/null 2>&1 && say "nxc      ✓" || warn "nxc      ✗ (pipx install git+https://github.com/Pennyw0rth/NetExec.git)"
command -v certipy >/dev/null 2>&1 && say "certipy  ✓" || warn "certipy  ✗ (pipx install certipy-ad)"
command -v bloodyAD >/dev/null 2>&1 && say "bloodyAD ✓" || warn "bloodyAD ✗ (pipx install bloodyAD)"
command -v secretsdump.py >/dev/null 2>&1 && say "impacket ✓" || warn "impacket ✗ (pipx install impacket)"
echo
say "Yeni kabuk aç (PATH için) ya da: export PATH=\"\$HOME/.local/bin:\$PATH\""

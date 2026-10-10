"""Subnet keşfi — CIDR/aralık hedeften host'ları, DC'yi ve domain'i otomatik bul.

Kullanıcı tek bir IP yerine bir /24 (ör. 10.10.10.0/24) verdiğinde:

  1. nmap ile AD-anlamlı portları (88/389/445/636/3268/53...) tüm subnette tara
     (yalnız --open; hızlı, NSE yok).
  2. Canlı host'ları çıkar; **DC imzası = 88 (Kerberos) + 389 (LDAP) açık** olan
     host'ları Domain Controller adayı olarak işaretle (3268 GC = güçlü işaret).
  3. Birincil DC'ye `nxc smb` (null session) ile sor → AD domain adı + DC adı.
  4. Bulunan DC'yi tarama pivotu yap; tüm canlı host'ları yanal-hareket/reuse
     hedefi olarak sakla.

Bu modül yalnız keşif yapar (pasif-agresif nmap + null SMB); gerçek saldırı
modülleri sonra çalışır. stdlib + nmap/nxc; ek bağımlılık yok.
"""

from __future__ import annotations

import ipaddress
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from .modules import nxc_scan
from .runner import run, strip_dryrun

# DC imzası: Kerberos + LDAP birlikte = Domain Controller (çok güvenilir).
_DC_PORTS = {"88", "389"}
# Keşifte taranan portlar: DC tespiti + temel yanal-hareket yüzeyi.
DISCOVERY_PORTS = "53,88,135,139,389,445,464,636,3268,3269,5985"


@dataclass
class Discovered:
    """Subnet keşfi sonucu."""

    hosts: list[str] = field(default_factory=list)       # tüm canlı host IP'leri
    dc_candidates: list[str] = field(default_factory=list)  # DC imzalı host'lar
    dc_ip: str = ""       # seçilen birincil DC (tarama pivotu)
    dc_name: str = ""     # DC bilgisayar adı (nxc'den)
    domain: str = ""      # AD domain FQDN (nxc'den)
    host_ports: dict = field(default_factory=dict)       # ip -> açık port kümesi


def looks_like_range(target: str) -> bool:
    """Hedef bir subnet/aralık mı (tek host değil)?

    CIDR ("/" içerir), nmap tarzı oktet aralığı ("10.0.0.1-50") ya da birden çok
    virgüllü giriş → aralık. Tek IP/hostname → False.
    """
    if not target:
        return False
    t = target.strip()
    if "/" in t:
        return True
    # virgüllü çok-hedef
    parts = [p for p in t.split(",") if p.strip()]
    if len(parts) > 1:
        return True
    # son oktette dash aralığı: 10.0.0.1-50 (ama tarih/hostname değil)
    if re.search(r"\d+\.\d+\.\d+\.\d+-\d+$", t) or re.search(r"\d+-\d+$", t.split(".")[-1]):
        return bool(re.match(r"^\d+\.\d+\.\d+\.", t))
    return False


def parse_hosts_ports(xml_str: str) -> dict[str, set[str]]:
    """Nmap XML'inden {ip: {açık portlar}} haritası çıkarır (yalnız 'up' host'lar)."""
    out: dict[str, set[str]] = {}
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return out
    for host in root.iter("host"):
        status = host.find("status")
        if status is not None and status.get("state") == "down":
            continue
        ip = ""
        for addr in host.iter("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr", "")
                break
        if not ip:
            continue
        ports: set[str] = set()
        for port in host.iter("port"):
            state = port.find("state")
            if state is not None and state.get("state") == "open":
                pid = port.get("portid")
                if pid:
                    ports.add(pid)
        # 'up' ama port yoksa bile host'u kaydet (canlı ama filtreli olabilir)
        out[ip] = ports
    return out


def pick_dcs(host_ports: dict[str, set[str]]) -> list[str]:
    """DC adaylarını seç ve güçten zayıfa sırala.

    DC = 88 ve 389 birlikte açık. GC (3268) ve SMB (445) ek güven verir; bunlara
    göre sıralanır (en olası DC başta).
    """
    dcs = [ip for ip, ports in host_ports.items() if _DC_PORTS <= ports]

    def score(ip: str) -> tuple:
        p = host_ports[ip]
        return ("3268" in p, "445" in p, "636" in p, ip)

    return sorted(dcs, key=score, reverse=True)


def domain_from_nxc(output: str) -> tuple[str, str]:
    """nxc smb çıktısından (name:DC01) (domain:corp.local) → (dc_name, domain)."""
    m = nxc_scan._DOMAIN_RX.search(strip_dryrun(output))
    if not m:
        return "", ""
    name, dom = m.group(1).strip(), m.group(2).strip()
    # Gerçek AD domain nokta içerir (workgroup/bilgisayar adı değil)
    return name, (dom if "." in dom else "")


def _probe_domain(dc_ip: str, *, timeout: int, dry_run: bool) -> tuple[str, str]:
    """DC'ye null SMB ile sorup (dc_name, domain) döndürür. Hata → ('', '')."""
    status = nxc_scan.tool()
    if not status.available or dry_run:
        return "", ""
    argv = [status.name, "smb", dc_ip]
    res = run(argv, tool=f"discover:domain:{dc_ip}", timeout=min(timeout, 120),
              dry_run=dry_run)
    return domain_from_nxc(res.combined)


def discover(target: str, *, timeout: int = 600, dry_run: bool = False,
             domain_hint: str | None = None, ui=None) -> Discovered:
    """Subnet'i tara, host'ları + DC'yi + domain'i bul."""
    def say(msg: str) -> None:
        if ui is not None:
            ui.log(msg)
        else:
            print(msg)

    result = Discovered()
    if dry_run:
        return result

    # 1) Hızlı subnet port taraması (yalnız açık, NSE yok, -n DNS yok)
    argv = ["nmap", "-Pn", "-n", "--open", "-p", DISCOVERY_PORTS,
            "--min-rate", "1500", "-T4", "-oX", "-", target]
    say(f"  [keşif] subnet taranıyor: {target} (portlar: {DISCOVERY_PORTS})")
    res = run(argv, tool="discover:nmap", timeout=timeout, dry_run=dry_run)
    host_ports = parse_hosts_ports(res.stdout or "")
    result.host_ports = host_ports
    result.hosts = sorted(host_ports.keys(), key=_ip_key)

    if not result.hosts:
        say("  [keşif] canlı host bulunamadı.")
        return result

    # 2) DC adayları
    result.dc_candidates = pick_dcs(host_ports)
    say(f"  [keşif] {len(result.hosts)} canlı host, "
        f"{len(result.dc_candidates)} DC adayı")

    if not result.dc_candidates:
        return result

    # 3) Birincil DC'den domain + DC adı
    result.dc_ip = result.dc_candidates[0]
    dc_name, domain = _probe_domain(result.dc_ip, timeout=timeout, dry_run=dry_run)
    result.dc_name = dc_name
    result.domain = domain or (domain_hint or "")
    label = result.dc_ip + (f" ({dc_name})" if dc_name else "")
    say(f"  [keşif] DC: {label}"
        + (f" · domain: {result.domain}" if result.domain else " · domain: ?"))
    return result


def _ip_key(ip: str):
    """IP'leri sayısal sırala (string sırası yerine)."""
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, ip)

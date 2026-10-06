"""Nmap tabanlı port + NSE zafiyet taraması.

AD için önemli servisleri hedefler: SMB (139/445), LDAP (389/636/3268),
RDP (3389), Kerberos (88). Çıktıyı regex ile ayrıştırıp bulguya çevirir.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from ..findings import Finding, ScanReport, Severity
from ..runner import CommandResult, run, strip_dryrun
from ..util import grep as _grep

# AD servisleri + ilgili NSE zafiyet scriptleri
AD_PORTS = "88,135,139,389,445,464,636,3268,3269,3389,5985,5986"

NSE_SCRIPTS = ",".join(
    [
        "smb-os-discovery",
        "smb-security-mode",
        "smb2-security-mode",
        "smb-protocols",
        "smb2-capabilities",
        "smb-vuln-ms17-010",
        "smb-vuln-ms08-067",
        "smb-double-pulsar-backdoor",
        "rdp-ntlm-info",
        "rdp-enum-encryption",
        "ldap-rootdse",
        "ssl-cert",
    ]
)


def build_argv(target: str, *, fast: bool = False, xml: bool = True) -> list[str]:
    """Nmap komut satırını oluşturur.

    xml=True iken çıktıyı `-oX -` ile XML olarak ister: yapılandırılmış
    ayrıştırma (A) stdout'u regex'le kazımaktan çok daha sağlamdır — script
    sınırları ve port durumları kesin gelir, NSE biçim kaymasından etkilenmez.
    """
    argv = [
        "nmap",
        "-Pn",  # ping atma (AD host'ları ICMP'yi sık sık bloklar)
        "-p",
        AD_PORTS,
        "--script",
        NSE_SCRIPTS,
    ]
    if not fast:
        argv += ["-sV"]  # servis/versiyon tespiti
    if xml:
        argv += ["-oX", "-"]  # XML'i stdout'a yaz (yapılandırılmış ayrıştırma)
    argv += [target]
    return argv


def scan(target: str, *, timeout: int = 600, dry_run: bool = False,
         xml: bool = True) -> CommandResult:
    return run(build_argv(target, xml=xml), tool="nmap", timeout=timeout, dry_run=dry_run)


def _run(ctx) -> list[CommandResult]:
    """Registry adaptörü: ScanContext'ten tek bir nmap taraması."""
    return [scan(ctx.target, timeout=ctx.timeout, dry_run=ctx.dry_run)]


# ---------------------------------------------------------------------------
# Yapılandırılmış (XML) çıktı -> grep'lenebilir metin
# ---------------------------------------------------------------------------

def _script_text(script: ET.Element) -> str:
    """Bir <script id=.. output=..> öğesini `| id:` + gövde biçimine çevirir.

    Mevcut `_script_block`/`_check_*` fonksiyonları `| script:` metin biçimini
    beklediğinden, XML'i bu biçime geri yazıp tüm tespit tanımlarını AYNEN
    yeniden kullanırız (yalnızca KAYNAK değişir: kazıma yerine yapılandırılmış).
    """
    sid = script.get("id", "")
    out = script.get("output", "") or ""
    body = "\n".join("|   " + ln.strip() for ln in out.splitlines() if ln.strip())
    return f"| {sid}:\n{body}" if body else f"| {sid}:"


def xml_to_text(xml_str: str) -> str | None:
    """Nmap XML'ini (`-oX`) mevcut ayrıştırıcıların anladığı metne çevirir.

    Geçersiz/eksik XML'de None döner (çağıran düz metne geri düşer).
    """
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None
    lines: list[str] = []
    for host in root.iter("host"):
        for port in host.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = port.get("portid", "")
            proto = port.get("protocol", "tcp")
            svc = port.find("service")
            name = svc.get("name", "") if svc is not None else ""
            lines.append(f"{portid}/{proto} open {name}".rstrip())
            for script in port.findall("script"):
                lines.append(_script_text(script))
        hs = host.find("hostscript")
        if hs is not None:
            for script in hs.findall("script"):
                lines.append(_script_text(script))
    return "\n".join(line for line in lines if line)


def _source_text(result: CommandResult) -> str:
    """Ayrıştırılacak metni verir: XML ise yapılandırılmıştan, değilse ham stdout'tan."""
    raw = result.stdout or ""
    if "<nmaprun" in raw[:4000] or raw.lstrip().startswith("<?xml"):
        txt = xml_to_text(raw)
        if txt is not None:
            return txt
    return strip_dryrun(result.combined)


# ---------------------------------------------------------------------------
# Çıktı ayrıştırma
# ---------------------------------------------------------------------------

def parse(result: CommandResult, report: ScanReport) -> None:
    """Nmap çıktısını okuyup bulgu üretir.

    Kaynak XML ise (`-oX`) yapılandırılmış ayrıştırılır (A); değilse düz metin
    (geriye dönük uyum + testler). İki yolda da aynı `_check_*` tanımları çalışır.
    """
    if not result.ok:
        report.raw_outputs["nmap"] = result.combined
        report.add_error(f"nmap: {result.error or 'çalıştırılamadı'}")
        return

    text = _source_text(result)
    report.raw_outputs["nmap"] = text

    target = report.target

    # Açık portları topla (bilgi amaçlı)
    open_ports = re.findall(r"^(\d+)/tcp\s+open\s+(\S+)", text, re.MULTILINE)
    if open_ports:
        ports_str = ", ".join(f"{p}/{svc}" for p, svc in open_ports)
        report.add(
            Finding(
                title="Açık portlar tespit edildi",
                severity=Severity.INFO,
                target=target,
                source="nmap",
                description="AD ile ilgili açık servisler.",
                evidence=ports_str,
                poc=f"nmap -Pn -sV -p {AD_PORTS} {target}",
                escalation="445 açık -> SMB enum (nxc smb); 389/636 -> LDAP enum; 88 -> "
                "Kerberos (AS-REP/kerberoast); 3389 -> RDP.",
            )
        )

    _check_smb_signing(text, target, report)
    _check_smbv1(text, target, report)
    _check_ms17_010(text, target, report)
    _check_ms08_067(text, target, report)
    _check_double_pulsar(text, target, report)
    _check_rdp_nla(text, target, report)
    _check_os_discovery(text, target, report)


def parse_results(results: list[CommandResult], report: ScanReport) -> None:
    """Registry adaptörü: tek elemanlı sonuç listesini `parse`'a yönlendirir."""
    if results:
        parse(results[0], report)


def _check_double_pulsar(text: str, target: str, report: ScanReport) -> None:
    block = _script_block(text, "smb-double-pulsar-backdoor")
    if block and re.search(r"VULNERABLE|infected|backdoor", block, re.IGNORECASE) \
            and "not" not in block.lower()[:200]:
        report.add(
            Finding(
                title="DoublePulsar backdoor tespit edildi",
                severity=Severity.CRITICAL,
                target=target,
                source="nmap",
                description="Host zaten DoublePulsar implantı ile enfekte — aktif tehlike.",
                evidence=block.strip(),
                remediation="Host'u izole edin, imajı yeniden kurun; MS17-010 yamasını uygulayın.",
                reference="DoublePulsar / MS17-010",
                poc=f"nmap -Pn -p445 --script smb-double-pulsar-backdoor {target}",
                escalation="Mevcut implant üzerinden komut çalıştırma mümkün olabilir; önce "
                "olay müdahalesi (IR) — bu host zaten tehlikede.",
            )
        )


def _check_smb_signing(text: str, target: str, report: ScanReport) -> None:
    # "Message signing enabled but not required" -> relay mümkün
    if re.search(r"message signing enabled but not required", text, re.IGNORECASE) or \
       re.search(r"Message signing:.*(disabled|not required)", text, re.IGNORECASE):
        report.add(
            Finding(
                title="SMB imzalama zorunlu değil (NTLM relay riski)",
                severity=Severity.HIGH,
                target=target,
                source="nmap",
                description=(
                    "SMB imzalama (signing) zorunlu tutulmuyor. Saldırgan "
                    "NTLM kimlik bilgilerini başka bir host'a relay edebilir."
                ),
                evidence=_grep(text, r"signing"),
                remediation="GPO ile 'Microsoft network server: Digitally sign "
                "communications (always)' = Enabled yapın.",
                reference="NTLM Relay / SMB signing",
                poc=f"nxc smb {target} --gen-relay-list relay.txt   # signing:False listesi",
                escalation="NTLM relay: bir kullanıcıyı buraya kimlik doğrulamaya zorlayıp "
                f"ntlmrelayx ile LDAP/SMB'ye relay et -> 'adscan {target} --active-attacks --launch "
                "-I <iface>'. İmzalama kapalı host'lar relay HEDEFİ olabilir.",
            )
        )


def _check_smbv1(text: str, target: str, report: ScanReport) -> None:
    if re.search(r"SMBv1.*enabled", text, re.IGNORECASE) or \
       re.search(r"\bNT LM 0\.12\b", text):
        report.add(
            Finding(
                title="SMBv1 etkin (eski/güvensiz protokol)",
                severity=Severity.HIGH,
                target=target,
                source="nmap",
                description="SMBv1 birçok kritik zafiyete (ör. EternalBlue) açıktır.",
                evidence=_grep(text, r"SMBv1|NT LM 0\.12"),
                remediation="SMBv1'i tamamen devre dışı bırakın.",
                reference="SMBv1 / MS17-010",
                poc=f"nmap -Pn -p445 --script smb-protocols {target}",
                escalation="SMBv1 açık -> MS17-010 (EternalBlue) kontrolü yap: "
                f"'nmap -p445 --script smb-vuln-ms17-010 {target}'. Zafiyetliyse RCE.",
            )
        )


def _check_ms17_010(text: str, target: str, report: ScanReport) -> None:
    block = _script_block(text, "smb-vuln-ms17-010")
    if block and re.search(r"State:\s*VULNERABLE", block, re.IGNORECASE):
        report.add(
            Finding(
                title="MS17-010 (EternalBlue) ZAFİYETLİ",
                severity=Severity.CRITICAL,
                target=target,
                source="nmap",
                description="Uzaktan kod çalıştırmaya (RCE) açık kritik SMB zafiyeti.",
                evidence=block.strip(),
                remediation="İlgili güvenlik güncellemesini (MS17-010) derhal uygulayın.",
                reference="CVE-2017-0143 / MS17-010",
                poc=f"nmap -Pn -p445 --script smb-vuln-ms17-010 {target}",
                escalation="RCE: (yalnızca LAB) metasploit 'exploit/windows/smb/ms17_010_eternalblue' "
                "ya da AutoBlue ile SYSTEM shell -> secretsdump -> Domain Admin.",
            )
        )


def _check_ms08_067(text: str, target: str, report: ScanReport) -> None:
    block = _script_block(text, "smb-vuln-ms08-067")
    if block and re.search(r"State:\s*VULNERABLE", block, re.IGNORECASE):
        report.add(
            Finding(
                title="MS08-067 ZAFİYETLİ",
                severity=Severity.CRITICAL,
                target=target,
                source="nmap",
                description="Klasik uzaktan kod çalıştırma zafiyeti.",
                evidence=block.strip(),
                remediation="MS08-067 yamasını uygulayın.",
                reference="CVE-2008-4250 / MS08-067",
                poc=f"nmap -Pn -p445 --script smb-vuln-ms08-067 {target}",
                escalation="RCE: (LAB) metasploit 'exploit/windows/smb/ms08_067_netapi' -> SYSTEM.",
            )
        )


def _check_rdp_nla(text: str, target: str, report: ScanReport) -> None:
    block = _script_block(text, "rdp-enum-encryption") or _script_block(
        text, "rdp-ntlm-info"
    )
    if not block:
        return
    # NLA kapalıysa CredSSP/NLA zorunlu değildir
    if re.search(r"CredSSP.*:\s*(FALSE|no)", block, re.IGNORECASE) or \
       re.search(r"Security layer.*RDP", block, re.IGNORECASE):
        report.add(
            Finding(
                title="RDP NLA (Network Level Authentication) zorunlu değil",
                severity=Severity.MEDIUM,
                target=target,
                source="nmap",
                description="NLA olmadan RDP, kimlik doğrulama öncesi saldırılara daha açık.",
                evidence=block.strip(),
                remediation="RDP sunucularında NLA'yı zorunlu kılın.",
                reference="RDP / NLA",
                poc=f"nmap -Pn -p3389 --script rdp-enum-encryption,rdp-ntlm-info {target}",
                escalation=f"NLA yoksa: bulunan kimliklerle 'nxc rdp {target} -u <user> -p <pass>' "
                "ile RDP erişimi dene; BlueKeep (CVE-2019-0708) yama durumunu kontrol et.",
            )
        )


def _check_os_discovery(text: str, target: str, report: ScanReport) -> None:
    block = _script_block(text, "smb-os-discovery")
    # Domain + DC adını otomatik yakala (downstream: -d vermeye gerek kalmaz)
    dom = re.search(r"Domain name:\s*(\S+)", block or text)
    if dom and "." in dom.group(1) and not report.domain:
        report.domain = dom.group(1).rstrip(".")
    comp = re.search(r"(?:NetBIOS computer name|Computer name):\s*(\S+)", block or text)
    if comp and not report.dc_name:
        report.dc_name = comp.group(1).rstrip("\\").split(".")[0]
    if block:
        report.add(
            Finding(
                title="Host/Domain bilgisi ifşa",
                severity=Severity.INFO,
                target=target,
                source="nmap",
                description="SMB üzerinden işletim sistemi ve domain bilgisi okunabiliyor.",
                evidence=block.strip(),
                poc=f"nmap -Pn -p445 --script smb-os-discovery {target}",
                escalation="Domain adını not al; LDAP/windapsearch ve kerberos saldırılarında "
                "domain parametresi olarak kullan (-d <domain>).",
            )
        )


# ---------------------------------------------------------------------------
# Yardımcılar
# ---------------------------------------------------------------------------

def _script_block(text: str, script_name: str) -> str | None:
    """Belirli bir NSE scriptinin çıktı bloğunu çıkarır.

    Nmap host-script çıktısı `| script-adi:` (pipe + boşluk + ad) biçimindedir;
    blok, bir sonraki `| baska-script:` satırına ya da port/dosya sonuna kadar
    uzanır.
    """
    pattern = (
        rf"\|_?\s*{re.escape(script_name)}:.*?"
        rf"(?=\n\d+/tcp|\n\|_?\s*[a-z][\w-]+:|\nNmap|\Z)"
    )
    m = re.search(pattern, text, re.DOTALL)
    return m.group(0) if m else None


# ---------------------------------------------------------------------------
# Registry kaydı
# ---------------------------------------------------------------------------

from ..registry import ScanModule  # noqa: E402  (döngüsel import'u önlemek için sonda)

MODULE = ScanModule(
    name="nmap",
    label="nmap port + NSE zafiyet taraması",
    run=_run,
    parse=parse_results,
)

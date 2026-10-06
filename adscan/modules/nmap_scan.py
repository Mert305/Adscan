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
# AD servisleri + web (IIS/certsrv), DNS, RPC-over-HTTP, CES/CEP ve ADWS.
# Eski liste yalnız çekirdek AD portlarıydı; 80/443/53/593/9389 kaçtığı için
# IIS/ADCS web enrollment ve ADWS gibi gerçek saldırı yüzeyleri görünmüyordu.
AD_PORTS = "53,80,88,135,139,389,443,445,464,593,636,3268,3269,3389,5985,5986,9389"

NSE_SCRIPTS = ",".join(
    [
        "smb-os-discovery",
        "smb-security-mode",
        "smb2-security-mode",
        "smb-protocols",
        "smb2-capabilities",
        "smb-vuln-ms17-010",
        "smb-vuln-ms08-067",
        "smb-vuln-cve-2017-7494",  # SambaCry (Linux Samba RCE)
        "smb-vuln-ms10-061",       # Print Spooler RCE (Stuxnet)
        "smb-vuln-ms10-054",       # SMB pool overflow
        "smb-vuln-cve2009-3103",   # MS09-050 SMBv2 negotiation RCE
        "smb-vuln-ms06-025",       # RRAS RPC RCE
        "smb-vuln-ms07-029",       # DNS RPC RCE
        "smb-double-pulsar-backdoor",
        "rdp-ntlm-info",
        "rdp-enum-encryption",
        "rdp-vuln-ms12-020",       # CVE-2012-0002 (RDP pre-auth RCE/DoS)
        "ldap-rootdse",
        "ssl-cert",
        "ssl-heartbleed",          # CVE-2014-0160 (Heartbleed, bellek sızıntısı)
        "ssl-ccs-injection",       # CVE-2014-0224 (OpenSSL CCS injection)
        "ssl-poodle",              # CVE-2014-3566 (POODLE, SSLv3)
        "ssl-dh-params",           # CVE-2015-4000 (Logjam) / zayıf DH
        "http-vuln-cve2015-1635",  # MS15-034 (HTTP.sys uzaktan kod çalıştırma)
    ]
)


def build_argv(target: str, *, fast: bool = False, xml: bool = True,
               ports: str | None = None) -> list[str]:
    """Nmap komut satırını oluşturur.

    xml=True iken çıktıyı `-oX -` ile XML olarak ister: yapılandırılmış
    ayrıştırma (A) stdout'u regex'le kazımaktan çok daha sağlamdır — script
    sınırları ve port durumları kesin gelir, NSE biçim kaymasından etkilenmez.

    `ports` verilirse (iki-fazlı keşif sonrası bulunan açık portlar), AD_PORTS
    yerine o liste taranır.
    """
    argv = [
        "nmap",
        "-Pn",  # ping atma (AD host'ları ICMP'yi sık sık bloklar)
        "-p",
        ports or AD_PORTS,
        "--script",
        NSE_SCRIPTS,
    ]
    if not fast:
        argv += ["-sV"]  # servis/versiyon tespiti
    if xml:
        argv += ["-oX", "-"]  # XML'i stdout'a yaz (yapılandırılmış ayrıştırma)
    argv += [target]
    return argv


def discover_argv(target: str) -> list[str]:
    """Hızlı tam-TCP keşif taraması (65535 port, NSE yok) — yalnız açık portlar."""
    return ["nmap", "-Pn", "-n", "-p-", "--min-rate", "3000", "-T4",
            "-oX", "-", target]


def _open_ports_from_xml(xml_str: str) -> list[str]:
    """Keşif XML'inden açık TCP port numaralarını çıkarır."""
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return []
    ports: list[str] = []
    for port in root.iter("port"):
        state = port.find("state")
        if state is not None and state.get("state") == "open":
            pid = port.get("portid")
            if pid:
                ports.append(pid)
    return ports


def scan(target: str, *, timeout: int = 600, dry_run: bool = False,
         xml: bool = True, ports: str | None = None) -> CommandResult:
    return run(build_argv(target, xml=xml, ports=ports), tool="nmap",
               timeout=timeout, dry_run=dry_run)


def _run(ctx) -> list[CommandResult]:
    """Registry adaptörü: ScanContext'ten nmap taraması.

    ctx.full_ports (ör. --full / --full-ports) açıksa önce hızlı bir tam-TCP
    keşif yapıp açık portları bulur, sonra NSE/servis taramasını yalnız o
    portlarda çalıştırır — böylece sabit AD listesi dışındaki servisler
    (IIS/certsrv, özel uygulamalar vb.) de kapsanır.
    """
    results: list[CommandResult] = []
    ports: str | None = None
    if getattr(ctx, "full_ports", False):
        disc = run(discover_argv(ctx.target), tool="nmap-discover",
                   timeout=ctx.timeout, dry_run=ctx.dry_run)
        results.append(disc)
        if not ctx.dry_run and disc.ok:
            found = _open_ports_from_xml(disc.stdout or "")
            if found:
                # AD_PORTS + keşfedilenler birleşimi (tekrarsız, sayısal sıralı)
                union = sorted({*AD_PORTS.split(","), *found}, key=int)
                ports = ",".join(union)
    results.append(scan(ctx.target, timeout=ctx.timeout, dry_run=ctx.dry_run,
                        ports=ports))
    return results


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
    _check_smbghost(text, target, report)  # CVE-2020-0796 (SMBv3.1.1 compression)
    _check_bluekeep(text, target, report)  # CVE-2019-0708 (RDP pre-auth RCE)
    # Tablo-güdümlü ek NSE zafiyet kontrolleri (yeni CVE eklemek = tek sözlük girdisi)
    for chk in _NSE_VULN_CHECKS:
        _check_nse_vuln(text, target, report, chk)


def parse_results(results: list[CommandResult], report: ScanReport) -> None:
    """Registry adaptörü: NSE/servis taraması sonucunu `parse`'a yönlendirir.

    İki-fazlı modda liste [keşif, nse-taraması] olur; ayrıştırılacak olan son
    eleman (açık portların tümünü -sV ile tarayan asıl sonuç).
    """
    if results:
        parse(results[-1], report)


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
# Tablo-güdümlü NSE zafiyet kontrolleri
# ---------------------------------------------------------------------------
# Yeni bir "State: VULNERABLE" biçimli NSE zafiyeti eklemek için bu listeye tek
# bir sözlük ekleyin; ayrıca scripti NSE_SCRIPTS'e dahil edin. Kod değişmez.
_NSE_VULN_CHECKS: list[dict] = [
    {
        "script": "smb-vuln-cve-2017-7494",
        "title": "SambaCry (CVE-2017-7494) ZAFİYETLİ",
        "severity": Severity.CRITICAL,
        "description": "Samba uzaktan kod çalıştırma: yazılabilir bir paylaşıma yüklenen "
                       "paylaşımlı kütüphane (.so) sunucu tarafında yüklenip çalıştırılabilir.",
        "remediation": "Samba'yı 4.6.4 / 4.5.10 / 4.4.14+ sürümüne güncelleyin; geçici "
                       "azaltma: smb.conf içine 'nt pipe support = no'.",
        "reference": "CVE-2017-7494 / SambaCry",
        "mitre": "T1210",
        "escalation": "RCE (yalnızca LAB): metasploit "
                      "'exploit/linux/samba/is_known_pipename' -> shell -> yanal hareket.",
    },
    {
        "script": "smb-vuln-ms10-061",
        "title": "MS10-061 (Print Spooler) ZAFİYETLİ",
        "severity": Severity.CRITICAL,
        "description": "Print Spooler servisindeki zafiyet uzaktan dosya yazımı/kod "
                       "çalıştırmaya izin verir (Stuxnet'in kullandığı vektör).",
        "remediation": "MS10-061 güvenlik güncellemesini uygulayın.",
        "reference": "CVE-2010-2729 / MS10-061",
        "mitre": "T1210",
        "escalation": "RCE (LAB): spooler üzerinden SYSTEM dizinine yazıp çalıştırma.",
    },
    {
        "script": "smb-vuln-ms10-054",
        "title": "MS10-054 (SMB pool overflow) ZAFİYETLİ",
        "severity": Severity.HIGH,
        "description": "SRV.sys içindeki havuz taşması; kimlik doğrulamalı bir saldırgan "
                       "çekirdek tarafında bellek bozulması tetikleyebilir.",
        "remediation": "MS10-054 güvenlik güncellemesini uygulayın.",
        "reference": "CVE-2010-1899 / MS10-054",
        "mitre": "T1210",
        "escalation": "Çekirdek bellek bozulması -> kararsız; genelde DoS/LPE araştırması.",
    },
    {
        "script": "smb-vuln-cve2009-3103",
        "title": "MS09-050 (SMBv2 negotiation) ZAFİYETLİ",
        "severity": Severity.CRITICAL,
        "description": "SMBv2 negotiation protokolündeki hata uzaktan kod çalıştırmaya "
                       "(çekirdek) açıktır — Windows Vista/Server 2008.",
        "remediation": "MS09-050 güvenlik güncellemesini uygulayın; SMBv2'yi güncel tutun.",
        "reference": "CVE-2009-3103 / MS09-050",
        "mitre": "T1210",
        "escalation": "RCE (LAB): metasploit 'exploit/windows/smb/ms09_050_smb2_negotiate_"
                      "func_index' -> SYSTEM.",
    },
    {
        "script": "smb-vuln-ms06-025",
        "title": "MS06-025 (RRAS) ZAFİYETLİ",
        "severity": Severity.CRITICAL,
        "description": "Routing and Remote Access servisindeki RPC zafiyeti uzaktan kod "
                       "çalıştırmaya açıktır.",
        "remediation": "MS06-025 güvenlik güncellemesini uygulayın.",
        "reference": "CVE-2006-2370 / MS06-025",
        "mitre": "T1210",
        "escalation": "RCE (LAB): metasploit 'exploit/windows/smb/ms06_025_rras' -> SYSTEM.",
    },
    {
        "script": "smb-vuln-ms07-029",
        "title": "MS07-029 (DNS RPC) ZAFİYETLİ",
        "severity": Severity.CRITICAL,
        "description": "DNS Server RPC arayüzündeki zafiyet uzaktan kod çalıştırmaya açıktır "
                       "(DC'lerde kritik — DNS rolü yaygındır).",
        "remediation": "MS07-029 güvenlik güncellemesini uygulayın.",
        "reference": "CVE-2007-1748 / MS07-029",
        "mitre": "T1210",
        "escalation": "RCE (LAB): metasploit 'exploit/windows/dcerpc/ms07_029_msdns_zonename' "
                      "-> SYSTEM (DC üzerinde = domain ele geçirme).",
    },
    {
        "script": "rdp-vuln-ms12-020",
        "title": "MS12-020 (RDP) ZAFİYETLİ — CVE-2012-0002",
        "severity": Severity.HIGH,
        "ports": "3389",
        "description": "RDP protokolündeki use-after-free; kimlik doğrulaması OLMADAN "
                       "uzaktan kod çalıştırma (pratikte çoğunlukla çekirdek paniği/DoS).",
        "remediation": "MS12-020'yi uygulayın; RDP'yi NLA ardına alın ve ağ erişimini kısıtlayın.",
        "reference": "CVE-2012-0002 / MS12-020",
        "mitre": "T1210",
        "escalation": "DoS (BSOD) kesin; RCE PoC'si nadir. NLA zorunlu kılın.",
    },
    {
        "script": "ssl-heartbleed",
        "title": "Heartbleed (CVE-2014-0160) ZAFİYETLİ",
        "severity": Severity.HIGH,
        "ports": "443,636,3269,5986",
        "description": "OpenSSL TLS heartbeat bellek aşırı-okuması; kimlik doğrulaması "
                       "olmadan sunucu belleğinden (özel anahtar, oturum, kimlik) sızıntı.",
        "remediation": "OpenSSL'i 1.0.1g+ sürümüne güncelleyin; sunucu sertifikasını "
                       "yeniden üretip eski anahtarı iptal edin.",
        "reference": "CVE-2014-0160 / Heartbleed",
        "mitre": "T1040",
        "escalation": "Belleği sız: özel anahtar/oturum çerezi/kimlik -> MITM / kimlik hırsızlığı.",
    },
    {
        "script": "ssl-ccs-injection",
        "title": "OpenSSL CCS Injection (CVE-2014-0224) ZAFİYETLİ",
        "severity": Severity.MEDIUM,
        "ports": "443,636,3269,5986",
        "description": "ChangeCipherSpec enjeksiyonu; MITM saldırganı zayıf anahtar "
                       "materyali zorlayıp trafiği çözebilir.",
        "remediation": "OpenSSL'i güncelleyin (1.0.1h+).",
        "reference": "CVE-2014-0224 / CCS Injection",
        "mitre": "T1557",
        "escalation": "MITM konumunda TLS oturumunu çöz/değiştir.",
    },
    {
        "script": "ssl-poodle",
        "title": "POODLE (CVE-2014-3566) — SSLv3 ZAFİYETLİ",
        "severity": Severity.MEDIUM,
        "ports": "443,636,3269,5986",
        "description": "SSLv3 CBC padding oracle; MITM ile oturum çerezi gibi veriler "
                       "byte-byte çözülebilir.",
        "remediation": "SSLv3'ü tamamen kapatın; TLS 1.2+ zorunlu kılın.",
        "reference": "CVE-2014-3566 / POODLE",
        "mitre": "T1557",
        "escalation": "MITM: SSLv3 downgrade -> çerez/oturum çöz.",
    },
    {
        "script": "ssl-dh-params",
        "title": "Zayıf Diffie-Hellman / Logjam (CVE-2015-4000)",
        "severity": Severity.MEDIUM,
        "ports": "443,636,3269,5986",
        "description": "Zayıf/ihracat sınıfı DH parametreleri (<=1024 bit ya da ortak "
                       "asal); MITM ile anahtar değişimi kırılabilir (Logjam).",
        "remediation": "2048+ bit benzersiz DH parametreleri kullanın; export cipher'ları kapatın.",
        "reference": "CVE-2015-4000 / Logjam",
        "mitre": "T1557",
        "escalation": "MITM: zayıf DH -> oturum anahtarını hesapla.",
    },
    {
        "script": "http-vuln-cve2015-1635",
        "title": "MS15-034 (HTTP.sys) ZAFİYETLİ — CVE-2015-1635",
        "severity": Severity.CRITICAL,
        "ports": "80,443",
        "description": "IIS/HTTP.sys içindeki tamsayı taşması; kimlik doğrulaması OLMADAN "
                       "uzaktan kod çalıştırma ya da DoS (Range başlığı).",
        "remediation": "MS15-034 güncellemesini uygulayın.",
        "reference": "CVE-2015-1635 / MS15-034",
        "mitre": "T1210",
        "escalation": "DoS kesin; RCE PoC'si mevcut (LAB). IIS yamasını öncelikle uygula.",
    },
]


def _check_nse_vuln(text: str, target: str, report: ScanReport, chk: dict) -> None:
    """Tek bir NSE 'State: VULNERABLE' bulgusunu (tablo girdisinden) rapora ekler."""
    block = _script_block(text, chk["script"])
    if not block or not re.search(r"State:\s*VULNERABLE", block, re.IGNORECASE):
        return
    report.add(
        Finding(
            title=chk["title"],
            severity=chk["severity"],
            target=target,
            source="nmap",
            description=chk.get("description", ""),
            evidence=block.strip(),
            remediation=chk.get("remediation", ""),
            reference=chk.get("reference", ""),
            mitre=chk.get("mitre", ""),
            poc=f"nmap -Pn -p{chk.get('ports', '445')} --script {chk['script']} {target}",
            escalation=chk.get("escalation", ""),
            verification="verified",
        )
    )


def _check_smbghost(text: str, target: str, report: ScanReport) -> None:
    """CVE-2020-0796 (SMBGhost / CoronaBlue) — SMBv3.1.1 compression.

    nmap sıkıştırma kapasitesini güvenilir biçimde ayırt edemediğinden, SMB 3.1.1
    varlığı yalnızca BİR ADAY işaretidir. 'smb2-capabilities' çıktısında sıkıştırma
    görünürse güven yükselir; görünmezse bulgu `unverified` olarak, zararsız teyit
    komutuyla (ollypwn scanner) birlikte raporlanır — yanlış-pozitifi önlemek için.
    """
    proto = _script_block(text, "smb-protocols") or ""
    caps = _script_block(text, "smb2-capabilities") or ""
    if "3.1.1" not in proto and "3.1.1" not in caps:
        return
    compress = bool(re.search(r"compress", caps, re.IGNORECASE))
    report.add(
        Finding(
            title=("SMBGhost (CVE-2020-0796) — SMBv3.1.1 sıkıştırma ETKİN"
                   if compress else
                   "SMBGhost (CVE-2020-0796) ADAYI — SMBv3.1.1 (doğrulanmadı)"),
            severity=Severity.HIGH if compress else Severity.MEDIUM,
            target=target,
            source="nmap",
            description=(
                "SMB 3.1.1 kullanımda. CVE-2020-0796, SMBv3.1.1 sıkıştırması ETKİN olan "
                "Windows 10 / Server 1903–1909 sürümlerinde kimlik doğrulamasız uzaktan "
                "kod çalıştırma ve yerel SYSTEM yükseltme sağlar. Kesinlik için sıkıştırma "
                "kapasitesinin (SMB2_GLOBAL_CAP compression) teyidi gerekir."
            ),
            evidence=(proto + ("\n" + caps if caps else "")).strip(),
            remediation=(
                "KB4551762 güncellemesini uygulayın. Geçici azaltma (sunucu): "
                "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\"
                "LanmanServer\\Parameters' DisableCompression -Type DWORD -Value 1 -Force; "
                "ayrıca 445/TCP'yi dış ağdan filtreleyin."
            ),
            reference="CVE-2020-0796 / SMBGhost / CoronaBlue",
            mitre="T1210",
            poc=(
                "# Zararsız teyit — compression capability'yi kontrol eder:\n"
                "git clone https://github.com/ollypwn/SMBGhost /tmp/smbghost\n"
                f"python3 /tmp/smbghost/scanner.py {target}\n"
                f"# dialect teyidi: nmap -Pn -p445 --script smb-protocols {target}"
            ),
            escalation=(
                "Teyitliyse (yalnızca LAB): yerel yükseltme danigargu/CVE-2020-0796-LPE "
                "-> SYSTEM; uzak RCE chompie1337/SMBGhost_RCE_PoC (KARARSIZ — yanlış "
                "offset'te BSOD, makine reseti gerekebilir). Önce foothold + LPE tercih et."
            ),
            verification="verified" if compress else "unverified",
        )
    )


_BLUEKEEP_OS_RX = re.compile(
    r"Windows (?:XP|Vista|7\b|Server 2003|Server 2008)",
    re.IGNORECASE,
)


def _check_bluekeep(text: str, target: str, report: ScanReport) -> None:
    """CVE-2019-0708 (BlueKeep) — RDP kimlik-doğrulamasız RCE.

    Güvenli bir NSE tespiti standart nmap'te yok. Bu yüzden yalnızca RDP açık VE
    işletim sistemi BlueKeep'e açık bir sürüme (XP/Vista/7/2003/2008/2008 R2)
    işaret ediyorsa bir ADAY olarak, `unverified` biçiminde bildirir — yanlış
    pozitifi önlemek için teyit komutu (msf check modülü) PoC'ye konur.
    """
    rdp = _script_block(text, "rdp-enum-encryption") or _script_block(text, "rdp-ntlm-info")
    if not rdp:
        return
    os_ctx = "\n".join(filter(None, [
        _script_block(text, "smb-os-discovery"),
        _script_block(text, "rdp-ntlm-info"),
    ]))
    m = _BLUEKEEP_OS_RX.search(os_ctx)
    if not m:
        return  # OS BlueKeep aralığında değil -> aday bildirme (gürültü azalt)
    report.add(
        Finding(
            title="BlueKeep (CVE-2019-0708) ADAYI — eski RDP OS (doğrulanmadı)",
            severity=Severity.HIGH,
            target=target,
            source="nmap",
            description=(
                f"RDP (3389) açık ve işletim sistemi BlueKeep'e açık bir sürüme işaret "
                f"ediyor ({m.group(0)}). CVE-2019-0708, Windows 7 / Server 2008(R2) ve "
                "öncesinde kimlik doğrulamasız uzaktan kod çalıştırma sağlar. Yama/azaltma "
                "durumu teyit edilmeden kesin değildir."
            ),
            evidence=os_ctx.strip() or rdp.strip(),
            remediation="İlgili güvenlik güncellemesini uygulayın; NLA'yı zorunlu kılın "
                        "(NLA tek başına tam azaltma değildir) ve 3389'u dış ağdan filtreleyin.",
            reference="CVE-2019-0708 / BlueKeep",
            mitre="T1210",
            poc=(
                "# Zararsız teyit (yalnızca CHECK modu — exploit DEĞİL):\n"
                f"msfconsole -q -x 'use auxiliary/scanner/rdp/cve_2019_0708_bluekeep; "
                f"set RHOSTS {target}; run; exit'"
            ),
            escalation=(
                "Teyitliyse (yalnızca LAB): metasploit "
                "'exploit/windows/rdp/cve_2019_0708_bluekeep_rce' — KARARSIZ, yanlış "
                "hedef/bellek ayarında BSOD; HTB'de makine reseti gerekebilir."
            ),
            verification="unverified",
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

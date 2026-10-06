"""nmap_scan.parse — örnek NSE çıktılarıyla tespit testleri."""

from conftest import cr, severity_of, titles

from adscan.findings import Severity
from adscan.modules import nmap_scan

VULN_OUTPUT = """\
Nmap scan report for 10.10.10.5
Host is up.
PORT     STATE SERVICE
445/tcp  open  microsoft-ds
Host script results:
| smb2-security-mode:
|_  Message signing enabled but not required
| smb-protocols:
|   dialects:
|     NT LM 0.12 (SMBv1) [dangerous, but default]
|_    2.02
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|_      IDs:  CVE:CVE-2017-0143
| smb-double-pulsar-backdoor:
|   VULNERABLE:
|     State: VULNERABLE
|_    Looks like you got a backdoor
"""


def test_nmap_detects_critical_and_high(report):
    nmap_scan.parse(cr(VULN_OUTPUT), report)
    t = titles(report)
    assert any("MS17-010" in x for x in t)
    assert any("DoublePulsar" in x for x in t)
    assert any("SMBv1" in x for x in t)
    assert any("imzalama" in x for x in t)


def test_nmap_severities(report):
    nmap_scan.parse(cr(VULN_OUTPUT), report)
    assert severity_of(report, "MS17-010") == Severity.CRITICAL
    assert severity_of(report, "DoublePulsar") == Severity.CRITICAL
    assert severity_of(report, "imzalama") == Severity.HIGH


def test_nmap_open_ports_info(report):
    nmap_scan.parse(cr(VULN_OUTPUT), report)
    assert severity_of(report, "Açık portlar") == Severity.INFO


def test_nmap_clean_output_no_vulns(report):
    clean = "445/tcp open microsoft-ds\n| smb2-security-mode:\n|_  Message signing required"
    nmap_scan.parse(cr(clean), report)
    assert not any("MS17-010" in x for x in titles(report))


def test_nmap_error_result_records_error(report):
    nmap_scan.parse(cr("", error="nmap bulunamadı"), report)
    assert report.errors
    assert not report.findings


def test_nmap_findings_have_poc_and_escalation(report):
    nmap_scan.parse(cr(VULN_OUTPUT), report)
    ms17 = next(f for f in report.findings if "MS17-010" in f.title)
    assert "smb-vuln-ms17-010" in ms17.poc  # doğrulanabilir komut
    assert ms17.escalation  # yükseltme ipucu dolu
    # to_dict de bu alanları içermeli (JSON rapora yansır)
    d = ms17.to_dict()
    assert "poc" in d and "escalation" in d


def test_nmap_registry_adapter(report):
    # parse_results tek elemanlı listeyi parse'a yönlendirir
    nmap_scan.parse_results([cr(VULN_OUTPUT)], report)
    assert any("MS17-010" in x for x in titles(report))


# ---------------------------------------------------------------------------
# A: yapılandırılmış XML (-oX) ayrıştırma — aynı bulgular, sağlam kaynak
# ---------------------------------------------------------------------------

NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
 <host>
  <ports>
   <port protocol="tcp" portid="445">
    <state state="open"/>
    <service name="microsoft-ds"/>
    <script id="smb-vuln-ms17-010" output="&#10;  VULNERABLE:&#10;    State: VULNERABLE&#10;    IDs: CVE:CVE-2017-0143"/>
   </port>
   <port protocol="tcp" portid="389">
    <state state="open"/>
    <service name="ldap"/>
   </port>
  </ports>
  <hostscript>
   <script id="smb2-security-mode" output="&#10;  Message signing enabled but not required"/>
   <script id="smb-protocols" output="&#10;  dialects:&#10;    NT LM 0.12 (SMBv1) [dangerous, but default]&#10;    2.02"/>
   <script id="smb-double-pulsar-backdoor" output="&#10;  VULNERABLE:&#10;    State: VULNERABLE&#10;    Looks like you got a backdoor"/>
   <script id="smb-os-discovery" output="&#10;  OS: Windows Server 2019&#10;  Computer name: DC01&#10;  Domain name: corp.local"/>
  </hostscript>
 </host>
</nmaprun>
"""


def _xml_result():
    # stdout = XML (gerçek `-oX -` çıktısı gibi)
    return cr(NMAP_XML)


def test_nmap_xml_detects_same_findings(report):
    nmap_scan.parse(_xml_result(), report)
    t = titles(report)
    assert any("MS17-010" in x for x in t)
    assert any("DoublePulsar" in x for x in t)
    assert any("SMBv1" in x for x in t)
    assert any("imzalama" in x for x in t)
    assert severity_of(report, "MS17-010") == Severity.CRITICAL
    assert severity_of(report, "imzalama") == Severity.HIGH


def test_nmap_xml_open_ports_and_domain(report):
    nmap_scan.parse(_xml_result(), report)
    assert severity_of(report, "Açık portlar") == Severity.INFO
    # smb-os-discovery'den domain/DC otomatik yakalanmalı
    assert report.domain == "corp.local"
    assert report.dc_name == "DC01"


def test_nmap_xml_clean_no_vulns(report):
    clean = ('<?xml version="1.0"?><nmaprun><host><ports>'
             '<port protocol="tcp" portid="445"><state state="open"/>'
             '<service name="microsoft-ds"/></port></ports>'
             '<hostscript><script id="smb2-security-mode" '
             'output="&#10;  Message signing enabled and required"/>'
             '</hostscript></host></nmaprun>')
    nmap_scan.parse(cr(clean), report)
    t = titles(report)
    assert not any("MS17-010" in x for x in t)
    assert not any("imzalama" in x for x in t)


def test_nmap_xml_invalid_falls_back_to_text(report):
    # Bozuk XML görünümlü ama aslında metin -> düz metin yoluna düşer
    nmap_scan.parse(cr(VULN_OUTPUT), report)  # düz metin hâlâ çalışır
    assert any("MS17-010" in x for x in titles(report))


def test_nmap_build_argv_xml_flag():
    argv = nmap_scan.build_argv("10.0.0.1", xml=True)
    assert "-oX" in argv and "-" in argv
    assert nmap_scan.build_argv("10.0.0.1", xml=False).count("-oX") == 0

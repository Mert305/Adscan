"""nxc_scan — SMB / LDAP / vuln parser testleri."""

from conftest import cr, severity_of, titles

from adscan.findings import Severity
from adscan.modules import nxc_scan

SMB_INFO = (
    "SMB  10.10.10.5  445  DC01  [*] Windows Server 2019 "
    "(domain:corp.local) (signing:False) (SMBv1:True)\n"
    "SMB  10.10.10.5  445  DC01  [+] corp.local\\admin:Secret (Pwn3d!)"
)
SMB_GUEST = "SMB  10.10.10.5  445  DC01  [+] corp.local\\bad:bad (Guest)"
SMB_SHARES = "SMB share SYSVOL READ\nSMB share Data READ,WRITE"
SMB_PASSPOL = "Minimum password length: 5\nAccount lockout threshold: None"


def test_nxc_smb_signing_and_smbv1(report):
    nxc_scan.parse_smb([cr(SMB_INFO)], report)
    assert severity_of(report, "signing") == Severity.HIGH
    assert any("SMBv1" in x for x in titles(report))


def test_nxc_smb_pwned_is_critical(report):
    nxc_scan.parse_smb([cr(SMB_INFO)], report)
    assert severity_of(report, "admin erişimi") == Severity.CRITICAL


def test_nxc_smb_guest(report):
    nxc_scan.parse_smb([cr(SMB_GUEST)], report)
    assert severity_of(report, "Guest") == Severity.HIGH


def test_nxc_smb_writable_share_medium(report):
    # Paylaşım tespiti artık yalnızca 'smb-shares' etiketli çıktıdan okunur (FP↓)
    nxc_scan.parse_smb(
        [cr(SMB_INFO), cr(SMB_SHARES, tool="nxc:smb-shares")], report)
    assert severity_of(report, "paylaşım") == Severity.MEDIUM


def test_nxc_smb_null_session(report):
    out = "SMB 10.10.10.5 445 DC [+] corp.local\\: "  # boş kullanıcı = null
    nxc_scan.parse_smb([cr(out)], report)
    assert severity_of(report, "Null/anonim") == Severity.HIGH
    # PoC kullanıcının doğrulayabileceği komutu içermeli
    f = next(f for f in report.findings if "Null" in f.title)
    assert "-u '' -p ''" in f.poc


def test_nxc_smb_no_false_positive_on_failed_login(report):
    # Sadece başarısız giriş ([-]) varsa oturum bulgusu ÜRETİLMEMELİ
    out = "SMB 10.10.10.5 445 DC [-] corp.local\\alice:wrong STATUS_LOGON_FAILURE"
    nxc_scan.parse_smb([cr(out)], report)
    assert not any("oturum" in t.lower() or "admin erişimi" in t.lower()
                   for t in titles(report))


def test_nxc_smb_weak_passpol(report):
    nxc_scan.parse_smb([cr(SMB_INFO), cr(SMB_PASSPOL)], report)
    assert severity_of(report, "parola politikası") == Severity.MEDIUM


def test_nxc_smb_error_short_circuits(report):
    nxc_scan.parse_smb([cr("", error="nxc yok")], report)
    assert report.errors and not report.findings


LDAP_OUT = (
    "LDAP corp.local  [+] $krb5asrep$23$user@CORP.LOCAL:aaaa\n"
    "LDAP corp.local  [+] $krb5tgs$23$*svc$CORP.LOCAL$svc*$bbbb\n"
    "LDAP corp.local  account PASSWD_NOTREQD set\n"
    "LDAP corp.local  DC01$ is trusted for delegation\n"
    "LDAP corp.local  LDAP signing is not required"
)


def test_nxc_ldap_roasting(report):
    nxc_scan.parse_ldap([cr(LDAP_OUT)], report)
    t = titles(report)
    assert any("AS-REP" in x for x in t)
    assert any("Kerberoasting" in x for x in t)
    assert severity_of(report, "Kerberoasting") == Severity.HIGH


def test_nxc_ldap_passwd_notreqd_and_delegation(report):
    nxc_scan.parse_ldap([cr(LDAP_OUT)], report)
    t = titles(report)
    assert any("Parola gerektirmeyen" in x for x in t)
    assert any("delegasyon" in x.lower() for x in t)


def test_nxc_ldap_signing_medium(report):
    nxc_scan.parse_ldap([cr(LDAP_OUT)], report)
    assert severity_of(report, "LDAP signing") == Severity.MEDIUM


VULN_OUT = (
    "SMB 10.10.10.5 [+] zerologon: Target is VULNERABLE to Zerologon\n"
    "SMB 10.10.10.5 [+] petitpotam: VULNERABLE\n"
    "LDAP 10.10.10.5 MachineAccountQuota: 10"
)


def test_nxc_vuln_zerologon_critical(report):
    nxc_scan.parse_vuln([cr(VULN_OUT)], report)
    assert severity_of(report, "Zerologon") == Severity.CRITICAL


def test_nxc_vuln_petitpotam_high(report):
    nxc_scan.parse_vuln([cr(VULN_OUT)], report)
    assert severity_of(report, "PetitPotam") == Severity.HIGH


def test_nxc_vuln_maq_medium(report):
    nxc_scan.parse_vuln([cr(VULN_OUT)], report)
    assert severity_of(report, "MachineAccountQuota") == Severity.MEDIUM


def test_nxc_vuln_maq_zero_no_finding(report):
    nxc_scan.parse_vuln([cr("MachineAccountQuota: 0")], report)
    assert not any("MachineAccountQuota" in x for x in titles(report))


# ---------------------------------------------------------------------------
# FALSE-POSITIVE regresyon testleri: YAMALI/temiz sistem çıktısı -> BULGU YOK.
# (Tespit, aracın olumsuz/banner satırındaki anahtar kelimeye TAKILMAMALI.)
# ---------------------------------------------------------------------------

def test_nxc_vuln_zerologon_not_vulnerable_no_finding(report):
    # Yamalı DC: "NOT vulnerable" -> Zerologon bulgusu ÜRETİLMEMELİ
    out = "SMB 10.10.10.5 445 DC01 [-] zerologon: Target is NOT vulnerable to Zerologon"
    nxc_scan.parse_vuln([cr(out)], report)
    assert not any("zerologon" in t.lower() for t in titles(report))


def test_nxc_vuln_coerce_attempt_banner_no_finding(report):
    # coerce_plus sadece DENEDİĞİ yöntemleri yazmış; hedef zafiyetsiz -> BULGU YOK
    out = ("SMB 10.10.10.5 445 DC01 [*] coerce_plus: Trying PetitPotam, DFSCoerce, "
           "ShadowCoerce, PrinterBug, MS-EVEN\n"
           "SMB 10.10.10.5 445 DC01 [-] coerce_plus: Target is not vulnerable")
    nxc_scan.parse_vuln([cr(out)], report)
    assert not any("zorlama" in t.lower() for t in titles(report))


def test_nxc_vuln_coerce_exploit_success_confirmed_critical(report):
    # Gerçek "Exploit Success" -> ONAYLANDI + CRITICAL
    out = "SMB 10.10.10.5 445 DC01 [+] coerce_plus: Exploit Success, MS-EFSR (PetitPotam)"
    nxc_scan.parse_vuln([cr(out)], report)
    assert severity_of(report, "zorlama") == Severity.CRITICAL
    assert any("ONAYLANDI" in t for t in titles(report))


def test_nxc_vuln_pre2k_none_no_finding(report):
    out = "LDAP 10.10.10.5 389 DC01 [-] pre2k: No pre-created computer accounts found"
    nxc_scan.parse_vuln([cr(out)], report)
    assert not any("pre-windows" in t.lower() or "pre2k" in t.lower() for t in titles(report))


def test_nxc_vuln_pre2k_positive_high(report):
    out = ("LDAP 10.10.10.5 389 DC01 [+] pre2k: WS01$ is vulnerable\n"
           "LDAP 10.10.10.5 389 DC01 GOT TGT for WS01$")
    nxc_scan.parse_vuln([cr(out)], report)
    assert severity_of(report, "Pre-Windows") == Severity.HIGH


def test_nxc_ldap_unconstrained_banner_no_finding(report):
    # Sadece arama banner'ı + olumsuz sonuç -> unconstrained bulgusu YOK
    out = ("LDAP 10.10.10.5 389 DC01 [*] Searching for unconstrained delegation\n"
           "LDAP 10.10.10.5 389 DC01 [-] No accounts trusted for delegation found")
    nxc_scan.parse_ldap([cr(out)], report)
    assert not any("unconstrained" in t.lower() for t in titles(report))


def test_nxc_ldap_unconstrained_real_account_high(report):
    out = "LDAP 10.10.10.5 389 DC01 WS02$ is trusted for delegation"
    nxc_scan.parse_ldap([cr(out)], report)
    assert severity_of(report, "unconstrained") == Severity.HIGH


def test_nxc_ldap_passwd_notreqd_negative_no_finding(report):
    out = "LDAP 10.10.10.5 389 DC01 [-] No accounts with PASSWD_NOTREQD found"
    nxc_scan.parse_ldap([cr(out)], report)
    assert not any("parola gerektirmeyen" in t.lower() for t in titles(report))


def test_nxc_ldap_signing_required_no_finding(report):
    # "signing is required" güvenli -> LDAP signing bulgusu YOK
    out = "LDAP 10.10.10.5 389 DC01 [*] LDAP signing is required, channel binding is required"
    nxc_scan.parse_ldap([cr(out)], report)
    assert not any("ldap signing" in t.lower() for t in titles(report))


# ---------------------------------------------------------------------------
# C (kapsam): timeroast / noPac / trusts — pozitif + negatif-yol
# ---------------------------------------------------------------------------

def test_nxc_vuln_timeroast_positive_high(report):
    out = ("SMB 10.10.10.5 445 DC01 [+] timeroast\n"
           "1000:$sntp-ms$abcdef0123456789$deadbeef\n"
           "1103:$sntp-ms$0011223344556677$cafebabe")
    nxc_scan.parse_vuln([cr(out)], report)
    assert severity_of(report, "Timeroast") == Severity.HIGH
    assert any("2 makine" in t for t in titles(report))


def test_nxc_vuln_timeroast_none_no_finding(report):
    out = "SMB 10.10.10.5 445 DC01 [-] timeroast: No hashes collected"
    nxc_scan.parse_vuln([cr(out)], report)
    assert not any("timeroast" in t.lower() for t in titles(report))


def test_nxc_vuln_nopac_positive_critical(report):
    out = "SMB 10.10.10.5 445 DC01 [+] nopac: Target is VULNERABLE to noPac"
    nxc_scan.parse_vuln([cr(out)], report)
    assert severity_of(report, "noPac") == Severity.CRITICAL


def test_nxc_vuln_nopac_not_vulnerable_no_finding(report):
    out = "SMB 10.10.10.5 445 DC01 [-] nopac: Target is NOT vulnerable to noPac"
    nxc_scan.parse_vuln([cr(out)], report)
    assert not any("nopac" in t.lower() for t in titles(report))


def test_nxc_vuln_trusts_positive_medium(report):
    out = ("LDAP 10.10.10.5 389 DC01 [+] enum_trusts\n"
           "LDAP 10.10.10.5 389 DC01 corp.local -> dev.corp.local (Bidirectional, ParentChild)")
    nxc_scan.parse_vuln([cr(out)], report)
    assert severity_of(report, "trust") == Severity.MEDIUM


def test_nxc_vuln_trusts_none_no_finding(report):
    out = "LDAP 10.10.10.5 389 DC01 [-] enum_trusts: No trusts found"
    nxc_scan.parse_vuln([cr(out)], report)
    assert not any("trust" in t.lower() for t in titles(report))


def test_nxc_smb_windows_laps_host_format(report):
    # Windows LAPS "Host: … Password: …" formatı da yakalanmalı
    out = "LAPS 10.10.10.5 445 WS01 Host: WS01 User: Administrator Password: Wind0wsLAPS!"
    nxc_scan.parse_smb([cr(out, tool="nxc:smb-info"),
                        cr(out, tool="nxc:smb-laps")], report)
    assert any("LAPS" in t for t in titles(report))


# ---------------------------------------------------------------------------
# Yeni tespitler: adminCount=1 / description'da parola / Print Spooler
# ---------------------------------------------------------------------------

def test_nxc_admincount_positive_medium(report):
    out = ("LDAP 10.10.10.5 389 DC01 Administrator\n"
           "LDAP 10.10.10.5 389 DC01 svc_legacy_admin")
    nxc_scan.parse_ldap([cr(out, tool="nxc:ldap-admincount")], report)
    assert severity_of(report, "adminCount") == Severity.MEDIUM
    ev = next(f.evidence for f in report.findings if "adminCount" in f.title)
    assert "svc_legacy_admin" in ev


def test_nxc_admincount_negative_no_finding(report):
    out = ("LDAP 10.10.10.5 389 DC01 [*] Total of records returned 0\n"
           "LDAP 10.10.10.5 389 DC01 [-] No accounts found")
    nxc_scan.parse_ldap([cr(out, tool="nxc:ldap-admincount")], report)
    assert not any("adminCount" in t for t in titles(report))


def test_nxc_description_password_positive_high(report):
    out = ("LDAP 10.10.10.5 389 DC01 User: svc_sql description: Password set to Summer2023!\n"
           "LDAP 10.10.10.5 389 DC01 User: guest description: Built-in account for guest access")
    nxc_scan.parse_ldap([cr(out, tool="nxc:ldap-desc")], report)
    assert severity_of(report, "description") == Severity.HIGH
    ev = next(f.evidence for f in report.findings if "description" in f.title)
    assert "Summer2023" in ev
    assert "guest access" not in ev  # parola ipucu yok -> FP değil


def test_nxc_description_benign_no_finding(report):
    out = ("LDAP 10.10.10.5 389 DC01 User: jdoe description: Sales department EMEA\n"
           "LDAP 10.10.10.5 389 DC01 [-] No entries found")
    nxc_scan.parse_ldap([cr(out, tool="nxc:ldap-desc")], report)
    assert not any("description" in t for t in titles(report))


def test_nxc_spooler_positive_medium(report):
    out = "SPOOLER 10.10.10.5 445 DC01 Spooler service enabled"
    nxc_scan.parse_smb([cr(out, tool="nxc:smb-info"),
                        cr(out, tool="nxc:smb-spooler")], report)
    assert severity_of(report, "Spooler") == Severity.MEDIUM


def test_nxc_spooler_disabled_no_finding(report):
    out = "SPOOLER 10.10.10.5 445 DC01 Spooler service disabled"
    nxc_scan.parse_smb([cr(out, tool="nxc:smb-info"),
                        cr(out, tool="nxc:smb-spooler")], report)
    assert not any("Spooler" in t for t in titles(report))


def test_nxc_ntlmv1_positive_high(report):
    out = "NTLMV1 10.10.10.5 445 DC01 NTLMv1 allowed: True (LmCompatibilityLevel: 2)"
    nxc_scan.parse_smb([cr(out, tool="nxc:smb-info"),
                        cr(out, tool="nxc:smb-ntlmv1")], report)
    assert severity_of(report, "NTLMv1") == Severity.HIGH


def test_nxc_ntlmv1_not_allowed_no_finding(report):
    out = "NTLMV1 10.10.10.5 445 DC01 NTLMv1 not allowed: False"
    nxc_scan.parse_smb([cr(out, tool="nxc:smb-info"),
                        cr(out, tool="nxc:smb-ntlmv1")], report)
    assert not any("NTLMv1" in t for t in titles(report))


# ---------------------------------------------------------------------------
# WebDAV / GPP-autologin / spider_plus / lockout-yok
# ---------------------------------------------------------------------------

def test_nxc_webdav_positive_medium(report):
    out = "WEBDAV 10.10.10.5 445 WS01 WebClient service running"
    nxc_scan.parse_smb([cr(out, tool="nxc:smb-info"),
                        cr(out, tool="nxc:smb-webdav")], report)
    assert severity_of(report, "WebDAV") == Severity.MEDIUM


def test_nxc_webdav_not_running_no_finding(report):
    out = "WEBDAV 10.10.10.5 445 WS01 WebClient service not running"
    nxc_scan.parse_smb([cr(out, tool="nxc:smb-info"),
                        cr(out, tool="nxc:smb-webdav")], report)
    assert not any("WebDAV" in t for t in titles(report))


def test_nxc_gpp_autologin_positive_adds_credential(report):
    out = ("GPP_AUTOLOGIN 10.10.10.5 445 DC01 Found credentials\n"
           "GPP_AUTOLOGIN 10.10.10.5 445 DC01 Usernames: [svc_auto] Passwords: [Autol0gon!]")
    nxc_scan.parse_smb([cr(out, tool="nxc:smb-info"),
                        cr(out, tool="nxc:smb-gpp-autologin")], report)
    assert severity_of(report, "GPP autologin") == Severity.HIGH
    assert any(c.username == "svc_auto" and c.secret == "Autol0gon!"
               for c in report.credentials)


def test_nxc_spider_sensitive_files_medium(report):
    out = ("SPIDER_PLUS 10.10.10.5 445 FS01 //FS01/Backup/unattend.xml\n"
           "SPIDER_PLUS 10.10.10.5 445 FS01 //FS01/IT/vault.kdbx\n"
           "SPIDER_PLUS 10.10.10.5 445 FS01 //FS01/Public/readme.txt")
    nxc_scan.parse_smb([cr(out, tool="nxc:smb-info"),
                        cr(out, tool="nxc:smb-spider")], report)
    assert severity_of(report, "hassas dosya") == Severity.MEDIUM
    ev = next(f.evidence for f in report.findings if "hassas dosya" in f.title)
    assert "unattend.xml" in ev and "vault.kdbx" in ev
    assert "readme.txt" not in ev  # ilgi çekici değil


def test_nxc_lockout_none_medium(report):
    passpol = ("SMB 10.10.10.5 445 DC01 Minimum password length: 10\n"
               "SMB 10.10.10.5 445 DC01 Account Lockout Threshold: None")
    nxc_scan.parse_smb([cr(passpol, tool="nxc:smb-info"),
                        cr(passpol, tool="nxc:smb-passpol")], report)
    assert severity_of(report, "kilitleme YOK") == Severity.MEDIUM


def test_nxc_lockout_set_no_finding(report):
    passpol = ("SMB 10.10.10.5 445 DC01 Minimum password length: 10\n"
               "SMB 10.10.10.5 445 DC01 Account Lockout Threshold: 5")
    nxc_scan.parse_smb([cr(passpol, tool="nxc:smb-info"),
                        cr(passpol, tool="nxc:smb-passpol")], report)
    assert not any("kilitleme YOK" in t for t in titles(report))


# ---------------------------------------------------------------------------
# PrintNightmare / SMBGhost / SCCM
# ---------------------------------------------------------------------------

def test_nxc_printnightmare_positive_critical(report):
    out = "PRINTNIGHTMARE 10.10.10.5 445 DC01 Vulnerable to PrintNightmare"
    nxc_scan.parse_vuln([cr(out, tool="nxc:printnightmare")], report)
    assert severity_of(report, "PrintNightmare") == Severity.CRITICAL


def test_nxc_printnightmare_not_vuln_no_finding(report):
    out = "PRINTNIGHTMARE 10.10.10.5 445 DC01 Target is NOT vulnerable to PrintNightmare"
    nxc_scan.parse_vuln([cr(out, tool="nxc:printnightmare")], report)
    assert not any("PrintNightmare" in t for t in titles(report))


def test_nxc_smbghost_positive_critical(report):
    out = "SMBGHOST 10.10.10.5 445 SRV01 Target is vulnerable to SMBGhost"
    nxc_scan.parse_vuln([cr(out, tool="nxc:smbghost")], report)
    assert severity_of(report, "SMBGhost") == Severity.CRITICAL


def test_nxc_sccm_positive_medium(report):
    out = "SCCM 10.10.10.5 389 DC01 Found Management Point -> MP01.corp.local (site code: P01)"
    nxc_scan.parse_vuln([cr(out, tool="nxc:sccm")], report)
    assert severity_of(report, "SCCM") == Severity.MEDIUM


def test_nxc_sccm_none_no_finding(report):
    out = "SCCM 10.10.10.5 389 DC01 [-] No SCCM infrastructure found"
    nxc_scan.parse_vuln([cr(out, tool="nxc:sccm")], report)
    assert not any("SCCM" in t for t in titles(report))

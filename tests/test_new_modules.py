"""MSSQL / WinRM / BloodHound / certipy / smbmap parse testleri."""

import os

from conftest import cr, severity_of

from adscan.findings import ScanReport, Severity
from adscan.modules import (
    bloodhound_scan,
    certipy_scan,
    mssql_scan,
    smbmap_scan,
    winrm_scan,
)

# --- MSSQL ---

def test_mssql_skip_without_creds(report):
    res = mssql_scan.scan("10.10.10.5", dry_run=True)
    mssql_scan.parse(res, report)
    assert res[0].tool == "mssql:skip"
    assert report.findings == []


def test_mssql_sysadmin_is_critical(report):
    out = "MSSQL 10.10.10.5 1433 DC [+] corp.local\\sa (Pwn3d!) is a sysadmin!"
    mssql_scan.parse([cr(out, tool="mssql-login")], report)
    assert severity_of(report, "sysadmin") == Severity.CRITICAL


def test_mssql_valid_login_is_medium(report):
    out = "MSSQL 10.10.10.5 1433 DC [+] corp.local\\svc:pass"
    mssql_scan.parse([cr(out, tool="mssql-login")], report)
    assert severity_of(report, "Geçerli MSSQL") == Severity.MEDIUM


# --- WinRM ---

def test_winrm_pwned_is_critical_and_adds_cred(report):
    out = "WINRM 10.0.0.2 5985 WS02 [+] corp.local\\alice:Passw0rd (Pwn3d!)"
    winrm_scan.parse([cr(out, tool="winrm-check")], report)
    assert severity_of(report, "komut çalıştırma") == Severity.CRITICAL
    assert any(c.username == "alice" and c.admin for c in report.credentials)


def test_winrm_valid_no_exec_is_high(report):
    out = "WINRM 10.0.0.3 5985 WS03 [+] corp.local\\bob:Passw0rd"
    winrm_scan.parse([cr(out, tool="winrm-check")], report)
    assert severity_of(report, "Geçerli WinRM") == Severity.HIGH


def test_winrm_skip_without_creds(report):
    res = winrm_scan.scan("10.10.10.5", dry_run=True)
    winrm_scan.parse(res, report)
    assert report.findings == []


# --- BloodHound ---

def test_bloodhound_skip_without_domain():
    r = ScanReport(target="10.10.10.5")
    res = bloodhound_scan.scan("10.10.10.5", username="a", password="b", dry_run=True)
    bloodhound_scan.parse(res, r)
    assert res[0].tool == "bloodhound:skip"
    assert r.findings == []


def test_bloodhound_reports_collected(tmp_path):
    r = ScanReport(target="10.10.10.5", outdir=str(tmp_path))
    loot = tmp_path / "loot" / "bloodhound"
    loot.mkdir(parents=True)
    (loot / "20260101_bloodhound.zip").write_text("x")
    bloodhound_scan.parse([cr("[+] Done collecting", tool="bloodhound-python")], r)
    assert severity_of(r, "BloodHound verisi toplandı") == Severity.INFO


# --- certipy (boşluk dolduruldu) ---

def test_certipy_esc_is_critical(report):
    out = ("Certipy v4\n[*] Vulnerabilities\n  ESC1: 'CORP\\Domain Users' can enroll\n"
           "Template Name    : VulnTemplate")
    certipy_scan.parse([cr(out, tool="certipy-find")], report)
    assert severity_of(report, "ADCS savunmasız") == Severity.CRITICAL


def test_certipy_skip_without_creds(report):
    res = certipy_scan.scan("10.10.10.5", dry_run=True)
    certipy_scan.parse(res, report)
    assert report.findings == []


def test_certipy_fills_real_ca_and_template_in_poc(report):
    out = ("Certificate Authorities\n  0\n    CA Name  : corp-DC01-CA\n"
           "Certificate Templates\n  0\n    Template Name   : UserCert\n"
           "    [!] Vulnerabilities\n      ESC1 : 'CORP\\Domain Users' can enroll")
    certipy_scan.parse([cr(out, tool="certipy-find")], report)
    esc = next(f.escalation for f in report.findings if "ADCS savunmasız" in f.title)
    assert "corp-DC01-CA" in esc and "UserCert" in esc        # gerçek CA + şablon
    assert "<CA-ADI>" not in esc and "<SAVUNMASIZ-TPL>" not in esc  # placeholder kalmadı


def test_certipy_ldaps_retry_on_ssl_error():
    # LDAPS TLS reset -> _ldaps_failed True; düz LDAP'a geçmeli
    from adscan.runner import CommandResult
    bad = CommandResult(tool="certipy-find", argv=["x"], returncode=1, stdout="",
                        stderr="Got error: socket ssl wrapping error: [Errno 104] "
                               "Connection reset by peer", duration=0.1)
    assert certipy_scan._ldaps_failed(bad) is True


# --- smbmap (boşluk dolduruldu) ---

def test_smbmap_admin_write_is_critical(report):
    out = ("[+] IP: 10.10.10.5\n"
           "\tC$                 \tREAD, WRITE\tDefault share\n"
           "\tIPC$               \tREAD ONLY\tRemote IPC")
    smbmap_scan.parse([cr(out, tool="smbmap", argv=["smbmap", "-H", "10.10.10.5",
                                                    "-u", "alice", "-p", "x"])], report)
    assert severity_of(report, "Yazılabilir SMB") == Severity.CRITICAL

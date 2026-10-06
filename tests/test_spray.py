"""spray_scan — kilitlenme güvenliği ve başarılı kimlik ayrıştırma testleri."""

from conftest import cr, severity_of, titles

from adscan.findings import Severity
from adscan.modules import spray_scan
from adscan.modules.spray_scan import parse_lockout_threshold, safe_password_count
from adscan.registry import ScanContext

# --- kilitlenme eşiği ayrıştırma ---

def test_threshold_numeric():
    assert parse_lockout_threshold("Account Lockout Threshold: 5") == 5


def test_threshold_none_means_disabled():
    assert parse_lockout_threshold("Account Lockout Threshold: None") == 0


def test_threshold_unreadable():
    assert parse_lockout_threshold("alakasız çıktı") is None


# --- güvenli parola sayısı ---

def test_safe_count_leaves_margin():
    assert safe_password_count(5) == 4  # eşik-1


def test_safe_count_disabled_is_large():
    assert safe_password_count(0) >= 1000


def test_safe_count_unknown_is_cautious():
    assert safe_password_count(None) <= 2


# --- lockout koruması: eşiği aşan spray iptal edilir ---

def test_spray_aborts_when_exceeds_threshold(monkeypatch, report):
    class FakeTool:
        name = "nxc"
    monkeypatch.setattr(spray_scan.nxc_scan, "tool", lambda: FakeTool())
    # pass-pol eşiği 3 döndürsün; parse için run'ı sahtele
    monkeypatch.setattr(
        spray_scan, "run",
        lambda argv, **kw: cr("Account Lockout Threshold: 3", tool=kw.get("tool", "x")))
    ctx = ScanContext(target="10.0.0.1", spray_users=["a", "b"],
                      spray_passwords=["1", "2", "3", "4", "5"], spray_force=False)
    results = spray_scan._run(ctx)
    spray_scan.parse(results, report)
    assert any(r.tool == "spray:aborted" for r in results)
    assert any("iptal" in e.lower() for e in report.errors)


def test_spray_force_bypasses_guard(monkeypatch):
    class FakeTool:
        name = "nxc"
    monkeypatch.setattr(spray_scan.nxc_scan, "tool", lambda: FakeTool())
    monkeypatch.setattr(
        spray_scan, "run",
        lambda argv, **kw: cr("Account Lockout Threshold: 3\n[+] corp\\a:1",
                              tool=kw.get("tool", "x")))
    ctx = ScanContext(target="10.0.0.1", spray_users=["a"],
                      spray_passwords=["1", "2", "3", "4", "5"], spray_force=True)
    results = spray_scan._run(ctx)
    assert not any(r.tool == "spray:aborted" for r in results)


# --- başarılı kimlik ayrıştırma + istatistik ---

SPRAY_OUT = (
    "Account Lockout Threshold: None\n"
    "SMB 10.0.0.1 445 DC [+] corp.local\\alice:123456\n"
    "SMB 10.0.0.1 445 DC [+] corp.local\\bob:123456\n"
    "SMB 10.0.0.1 445 DC [-] corp.local\\carol:123456 STATUS_LOGON_FAILURE\n"
    "SMB 10.0.0.1 445 DC [+] corp.local\\admin:Password1 (Pwn3d!)"
)


def test_spray_parse_counts_valid(report):
    spray_scan.parse([cr(SPRAY_OUT)], report)
    t = titles(report)
    assert any("hesap doğrulandı" in x for x in t)


def test_spray_parse_pwned_is_critical(report):
    spray_scan.parse([cr(SPRAY_OUT)], report)
    assert severity_of(report, "doğrulandı") == Severity.CRITICAL


def test_spray_dry_run_builds_plan():
    ctx = ScanContext(target="10.0.0.1", dry_run=True,
                      spray_passwords=["123456", "Password1"])
    results = spray_scan._run(ctx)
    assert all(r.ok for r in results)
    assert any("DRY-RUN" in r.stdout for r in results)

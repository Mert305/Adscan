"""reuse modülü + credential store + maskeleme (config.REDACT) testleri."""

import pytest
from conftest import cr, severity_of, titles

from adscan import config
from adscan.findings import Credential, ScanReport, Severity
from adscan.modules import reuse_scan
from adscan.registry import ScanContext


@pytest.fixture(autouse=True)
def _reset_redact():
    config.set_redact(False)
    yield
    config.set_redact(False)


# --- credential store ---

def test_add_credential_dedup():
    r = ScanReport(target="t")
    r.add_credential(Credential("alice", "123456", domain="corp"))
    r.add_credential(Credential("alice", "123456", domain="corp", admin=True))
    assert len(r.credentials) == 1
    assert r.credentials[0].admin is True  # zenginleştirildi


def test_credential_display_open_by_default():
    c = Credential("alice", "123456")
    assert c.display_secret() == "123456"


def test_credential_display_masked_when_redact():
    config.set_redact(True)
    assert Credential("alice", "123456").display_secret() == "***"
    assert Credential("x", "a" * 32, kind="nthash").display_secret().endswith("…")


def test_report_json_includes_credentials():
    r = ScanReport(target="t")
    r.add_credential(Credential("alice", "123456", domain="corp", source="spray"))
    d = r.to_dict()
    assert d["credentials"][0]["username"] == "alice"
    assert d["credentials"][0]["secret"] == "123456"  # açık


# --- reuse modülü ---

REUSE_OUT = (
    "SMB 10.0.0.10 445 WS01 [+] corp.local\\alice:123456\n"
    "SMB 10.0.0.11 445 WS02 [+] corp.local\\alice:123456 (Pwn3d!)\n"
    "SMB 10.0.0.12 445 WS03 [-] corp.local\\alice:123456 STATUS_LOGON_FAILURE"
)


def test_reuse_parse_lateral_and_admin(report):
    reuse_scan.parse([cr(REUSE_OUT)], report)
    assert severity_of(report, "Credential reuse") == Severity.CRITICAL  # admin var
    # iki host'ta geçerli, biri admin
    assert any("2 host" in t for t in titles(report))


def test_reuse_parse_populates_store(report):
    reuse_scan.parse([cr(REUSE_OUT)], report)
    # Aynı kimlik dedup edilir; geçerli olduğu host'lar bulgu kanıtında listelenir
    ev = next(f.evidence for f in report.findings if "reuse" in f.title.lower())
    assert "10.0.0.10" in ev and "10.0.0.11" in ev
    assert any(c.admin for c in report.credentials)


def test_reuse_evidence_open_vs_redacted(report):
    reuse_scan.parse([cr(REUSE_OUT)], report)
    ev = next(f.evidence for f in report.findings if "reuse" in f.title.lower())
    assert "123456" in ev  # açık gösterim

    config.set_redact(True)
    r2 = ScanReport(target="t")
    reuse_scan.parse([cr(REUSE_OUT)], r2)
    ev2 = next(f.evidence for f in r2.findings if "reuse" in f.title.lower())
    assert "123456" not in ev2


def test_reuse_skips_without_credentials():
    ctx = ScanContext(target="10.0.0.1", found_credentials=[])
    results = reuse_scan._run(ctx)
    assert any(r.tool == "reuse:skip" for r in results)


def test_reuse_builds_hash_argument(monkeypatch):
    captured = {}

    def fake_run(argv, **kw):
        captured["argv"] = argv
        return cr("", tool=kw.get("tool", "x"))

    class FakeTool:
        name = "nxc"
    monkeypatch.setattr(reuse_scan.nxc_scan, "tool", lambda: FakeTool())
    monkeypatch.setattr(reuse_scan, "run", fake_run)
    ctx = ScanContext(target="10.0.0.1", reuse_targets="10.0.0.0/24",
                      found_credentials=[Credential("svc", "a" * 32, kind="nthash",
                                                     domain="corp")])
    reuse_scan._run(ctx)
    argv = captured["argv"]
    assert "-H" in argv
    assert "10.0.0.0/24" in argv
    # domain -d ile ayrı verilmeli; kullanıcı adı -u'da ÇIPLAK (DOMAIN\user DEĞİL)
    assert argv[argv.index("-u") + 1] == "svc"
    assert "-d" in argv and argv[argv.index("-d") + 1] == "corp"
    assert "corp\\svc" not in argv

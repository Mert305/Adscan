"""Autopilot entegrasyonu: harvest -> spray -> reuse zinciri uçtan uca."""

from types import SimpleNamespace

import pytest

from adscan import cli, config, escalate
from adscan.findings import ScanReport
from adscan.modules import reuse_scan, spray_scan
from adscan.registry import ScanContext
from adscan.runner import CommandResult


def _cr(stdout, tool="t"):
    return CommandResult(tool=tool, argv=["x"], returncode=0, stdout=stdout,
                         stderr="", duration=0.0)


@pytest.fixture(autouse=True)
def _reset():
    config.set_redact(False)
    yield
    config.set_redact(False)


def test_autopilot_chains_enum_spray_reuse(monkeypatch, tmp_path):
    # 1. aşama çıktıları (enum) rapora önceden konur
    report = ScanReport(target="10.0.0.1")
    report.raw_outputs["nxc-smb"] = (
        "SMB 10.0.0.1 445 DC corp.local\\alice badpwdcount: 0\n"
        "SMB 10.0.0.1 445 DC corp.local\\bob badpwdcount: 0")
    report.raw_outputs["nmap"] = "Nmap scan report for 10.0.0.1"

    class FakeTool:
        name = "nxc"
    monkeypatch.setattr(spray_scan.nxc_scan, "tool", lambda: FakeTool())
    monkeypatch.setattr(reuse_scan.nxc_scan, "tool", lambda: FakeTool())

    # Spray: pass-pol (kilitleme kapalı) + alice zayıf parolayla doğrulanır
    def fake_spray_run(argv, **kw):
        tool = kw.get("tool", "")
        if "pass-pol" in tool:
            return _cr("Account Lockout Threshold: None", tool=tool)
        return _cr("SMB 10.0.0.1 445 DC [+] corp.local\\alice:123456", tool=tool)
    monkeypatch.setattr(spray_scan, "run", fake_spray_run)

    # Escalate motoru: alice başka host'ta yerel admin (Pwn3d) — yanal hareket
    def fake_escalate_run(argv, **kw):
        return _cr("SMB 10.0.0.2 445 WS02 [+] corp.local\\alice:123456 (Pwn3d!)",
                   tool=kw.get("tool", "t"))
    monkeypatch.setattr(escalate, "run", fake_escalate_run)

    args = SimpleNamespace(
        outdir=str(tmp_path), auto_passwords=None, username=None, nthash=None,
        domain="corp.local", target="10.0.0.1", reuse_targets=None)
    ctx = ScanContext(target="10.0.0.1", domain="corp.local")

    cli._run_autopilot(args, ctx, report, None)

    titles = [f.title for f in report.findings]
    # Spray geçerli kimlik buldu
    assert any("doğrulandı" in t for t in titles)
    # Escalate motoru yanal hareket + yerel admin tespit etti (alice admin olarak işaretlendi)
    assert any(c.username == "alice" and c.admin for c in report.credentials)
    # Keşfedilen kullanıcılar rapora ve dosyaya yazıldı
    assert "alice" in report.users and "bob" in report.users
    assert (tmp_path / "autopilot-users.txt").exists()
    # Credential store dolduruldu
    assert any(c.username == "alice" for c in report.credentials)


def test_autopilot_no_users_skips_gracefully(monkeypatch, tmp_path):
    report = ScanReport(target="10.0.0.1")  # boş çıktı -> kullanıcı yok
    args = SimpleNamespace(
        outdir=str(tmp_path), auto_passwords=None, username=None, nthash=None,
        domain=None, target="10.0.0.1", reuse_targets=None)
    ctx = ScanContext(target="10.0.0.1")
    # Hiç kimlik yoksa çökmemeli, bulgu da üretmemeli
    cli._run_autopilot(args, ctx, report, None)
    assert report.findings == []

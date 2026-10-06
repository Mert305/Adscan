"""Parola-tekrarı süpürmesi (sweep) + ACL zinciri (aclpwn) testleri."""

from conftest import cr

from adscan import aclpwn, sweep
from adscan.findings import Credential
from adscan.modules import bloodyAD_scan
from adscan.registry import ScanContext

# --- sweep.parse_hits ---

def test_sweep_parse_hits_matches_only_our_password(report):
    report.domain = "checkpoint.htb"
    out = (
        "SMB 10.129.152.246 445 DC01 [-] checkpoint.htb\\alex.turner:WrongPw\n"
        "SMB 10.129.152.246 445 DC01 [+] checkpoint.htb\\mark.davies:Checkpoint2024!\n"
        "SMB 10.129.152.246 445 DC01 [+] checkpoint.htb\\svc_x:Checkpoint2024! (Pwn3d!)\n")
    new = sweep.parse_hits(out, "Checkpoint2024!", report)
    names = {c.username for c in new}
    assert names == {"mark.davies", "svc_x"}
    assert next(c for c in new if c.username == "svc_x").admin  # Pwn3d -> admin


def test_sweep_parse_hits_ignores_other_passwords(report):
    out = "SMB 10.0.0.1 445 DC [+] d\\u:SomeOtherPass\n"
    assert sweep.parse_hits(out, "Checkpoint2024!", report) == []


# --- bloodyAD yardımcıları ---

def test_bloodyad_deleted_candidates_extracts():
    res = cr(
        "distinguishedName: CN=Mark Davies\\0ADEL:x,CN=Deleted Objects,DC=c,DC=h\n"
        "sAMAccountName: mark.davies\n"
        "lastKnownParent: OU=Employees,DC=c,DC=h\n",
        tool="bloodyad-deleted")
    assert bloodyAD_scan.deleted_candidates([res]) == [
        ("mark.davies", "OU=Employees,DC=c,DC=h")]


def test_bloodyad_restore_builds_argv(monkeypatch):
    captured = {}

    def fake_run(argv, **kw):
        captured["argv"] = argv
        return cr("mark.davies has been restored successfully", tool="bloodyad-restore")

    monkeypatch.setattr(bloodyAD_scan, "run", fake_run)
    bloodyAD_scan.restore("10.0.0.1", "mark.davies", domain="c", username="u", password="p")
    argv = captured["argv"]
    assert argv[-3:] == ["set", "restore", "mark.davies"]


# --- aclpwn ---

def test_aclpwn_sweep_passwords_prefers_asked(report):
    report.add_credential(Credential(username="alex", secret="A", kind="password"))
    report.add_credential(Credential(username="bob", secret="B", kind="password"))
    pws = aclpwn._sweep_passwords(report, "ASKED")
    assert pws[0] == "ASKED"
    assert len(pws) <= aclpwn.MAX_SWEEP_PWS


def test_aclpwn_sweep_passwords_known_when_no_ask(report):
    report.add_credential(Credential(username="alex", secret="A", kind="password"))
    assert aclpwn._sweep_passwords(report, None) == ["A"]


def test_aclpwn_skips_without_creds(report):
    ctx = ScanContext(target="10.0.0.1")  # kimlik yok
    assert aclpwn.run(ctx, report) == []

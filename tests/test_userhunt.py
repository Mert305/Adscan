"""User hunting (loggedon-users / sessions) parse testleri."""

from conftest import cr, severity_of

from adscan.findings import ScanReport, Severity
from adscan.modules import nxc_scan


def test_user_hunting_maps_hosts_and_flags_admin():
    out = (
        "SMB 10.0.0.5 445 WS01 [+] corp.local\\alice:Passw0rd (Pwn3d!)\n"   # auth echo -> atla
        "SMB 10.0.0.5 445 WS01 [+] Enumerated loggedon users\n"
        "SMB 10.0.0.5 445 WS01 CORP\\admin.dave   logon_server: DC01\n"
        "SMB 10.0.0.5 445 WS01 CORP\\bob\n"
    )
    r = ScanReport(target="10.0.0.5")
    nxc_scan._parse_user_hunting([cr(out, tool="nxc:smb-loggedon")], r)
    f = next(f for f in r.findings if "User hunting" in f.title)
    assert f.severity == Severity.HIGH          # admin.dave -> ilgi çekici
    assert "admin.dave" in f.evidence and "bob" in f.evidence
    assert "alice" not in f.evidence            # auth echo elendi


def test_user_hunting_sessions_user_colon_form():
    out = (
        "SMB 10.0.0.9 445 FS01 [*] Enumerated sessions\n"
        "SMB 10.0.0.9 445 FS01 user: carol\n"
    )
    r = ScanReport(target="10.0.0.9")
    nxc_scan._parse_user_hunting([cr(out, tool="nxc:smb-sessions")], r)
    assert severity_of(r, "User hunting") == Severity.MEDIUM   # admin yok -> MEDIUM
    f = next(f for f in r.findings if "User hunting" in f.title)
    assert "carol" in f.evidence


def test_user_hunting_none_when_empty():
    r = ScanReport(target="t")
    nxc_scan._parse_user_hunting([cr("SMB 10.0.0.5 445 WS01 [-] no sessions",
                                     tool="nxc:smb-sessions")], r)
    assert not any("User hunting" in f.title for f in r.findings)

"""Delegasyon/persistence/pivot/bilet eklentileri için regresyon testleri (ağsız)."""

from adscan import bhpath, config
from adscan.findings import Credential, ScanReport
from adscan.modules import certipy_scan, delegation_scan, gpo_scan, tickets_scan
from adscan.runner import CommandResult, _maybe_proxy


def _cr(tool, stdout):
    return CommandResult(tool=tool, argv=[], returncode=0, stdout=stdout,
                         stderr="", duration=0.0)


# --- #1 delegasyon ayrıştırma ---

DELEG_OUT = """\
LDAP  10.0.0.1  389  DC  WEB01$       Computer  Unconstrained
LDAP  10.0.0.1  389  DC  svc_sql      User      Constrained w/ Protocol Transition  MSSQLSvc/db.corp.local
LDAP  10.0.0.1  389  DC  WS02$        Computer  Resource-Based Constrained  host/ws02
"""


def test_delegation_parses_all_types():
    r = ScanReport(target="10.0.0.1", domain="corp.local")
    delegation_scan.parse([_cr("delegation-find", DELEG_OUT)], r)
    cids = {f.control_id for f in r.findings}
    assert "deleg.unconstrained" in cids
    assert "deleg.constrained" in cids
    assert "deleg.rbcd" in cids
    con = next(f for f in r.findings if f.control_id == "deleg.constrained")
    assert "getST.py" in con.escalation and "impersonate Administrator" in con.escalation


# --- #4 golden certificate (ManageCA) ---

def test_certipy_golden_cert_from_manageca():
    stdout = ("CA Name : corp-CA\n    Permissions\n      Access Rights\n"
              "        ManageCa : CORP.LOCAL\\PKI_Admins\n")
    r = ScanReport(target="10.0.0.1")
    certipy_scan._check_esc7_ca_rights(stdout, "10.0.0.1", r)
    assert any(f.control_id == "adcs.golden-cert" for f in r.findings)
    f = next(f for f in r.findings if f.control_id == "adcs.golden-cert")
    assert "ca -backup" in f.poc


# --- #6 DACL persistence (DCSync non-default) ---

def test_bhpath_persistence_dcsync_nondefault():
    g = bhpath.Graph()
    low = "S-1-5-21-1-1-1-1105"
    dom = "S-1-5-21-1-1-1"
    g.add_node(low, "HELPDESK@CORP", "Group", False)
    g.add_node(dom, "CORP.LOCAL", "Domain", True)
    g.add_edge(low, dom, "GetChangesAll")
    r = ScanReport(target="10.0.0.1")
    bhpath.detect_persistence(g, r)
    f = next((f for f in r.findings if f.control_id == "bhpath.dacl-persistence"), None)
    assert f is not None and "HELPDESK@CORP" in f.evidence and "DCSync" in f.evidence


def test_bhpath_persistence_ignores_default():
    g = bhpath.Graph()
    da = "S-1-5-21-1-1-1-512"
    dom = "S-1-5-21-1-1-1"
    g.add_node(da, "DOMAIN ADMINS@CORP", "Group", True)
    g.add_node(dom, "CORP.LOCAL", "Domain", True)
    g.add_edge(da, dom, "GetChangesAll")
    r = ScanReport(target="10.0.0.1")
    bhpath.detect_persistence(g, r)
    assert not any(f.control_id == "bhpath.dacl-persistence" for f in r.findings)


# --- #5 GPO abuse (writable GPO edge) ---

def test_gpo_writable(tmp_path):
    import json
    import zipfile
    bh = tmp_path / "loot" / "bloodhound"
    bh.mkdir(parents=True)
    me = "S-1-5-21-1-1-1-2601"
    gpo = "S-1-5-21-1-1-1-7000"
    blobs = {
        "users.json": {"meta": {"type": "users"}, "data": [
            {"ObjectIdentifier": me, "Properties": {"name": "ANDERSON.W@CORP"}, "Aces": []}]},
        "gpos.json": {"meta": {"type": "gpos"}, "data": [
            {"ObjectIdentifier": gpo, "Properties": {"name": "DEFAULT POLICY@CORP"},
             "Aces": [{"PrincipalSID": me, "RightName": "GenericWrite"}]}]},
    }
    with zipfile.ZipFile(bh / "bh.zip", "w") as z:
        for name, blob in blobs.items():
            z.writestr(name, json.dumps(blob))
    r = ScanReport(target="10.0.0.1", domain="corp.local", outdir=str(tmp_path))
    r.add_credential(Credential(username="anderson.w", secret="p", domain="corp.local"))
    gpo_scan.parse([_cr("gpo:analyze", "")], r)
    f = next((f for f in r.findings if f.control_id == "gpo.writable"), None)
    assert f is not None and "pygpoabuse" in f.escalation


# --- #3 golden ticket (krbtgt in pool) ---

def test_tickets_golden_from_krbtgt():
    r = ScanReport(target="10.0.0.1", domain="corp.local")
    r.add_credential(Credential(username="krbtgt", secret="a" * 32, kind="nthash"))
    tickets_scan.parse([_cr("tickets:plan", "")], r)
    assert any(f.control_id == "kerberos.golden" for f in r.findings)


def test_tickets_overpth_detected():
    r = ScanReport(target="10.0.0.1", domain="corp.local")
    tickets_scan.parse(
        [_cr("tickets-gettgt", "[*] Saving ticket in alice.ccache")], r)
    assert any(f.control_id == "kerberos.overpth" for f in r.findings)


# --- #7 proxychains sarma ---

def test_maybe_proxy_wraps_network_tool(monkeypatch):
    config.set_proxychains(True)
    monkeypatch.setattr("adscan.runner.which",
                        lambda n: "/usr/bin/proxychains4" if "proxychains4" in n else "/x")
    try:
        out = _maybe_proxy(["nxc", "smb", "10.0.0.1"])
        assert out[:2] == ["proxychains4", "-q"] and "nxc" in out
    finally:
        config.set_proxychains(False)


def test_maybe_proxy_skips_offline_tool():
    config.set_proxychains(True)
    try:
        assert _maybe_proxy(["hashcat", "-m", "13100"])[0] == "hashcat"
    finally:
        config.set_proxychains(False)


def test_maybe_proxy_off_by_default():
    assert _maybe_proxy(["nxc", "smb", "x"]) == ["nxc", "smb", "x"]


# --- impacket resolver (bozuk sistem -> çalışan venv) ---

def test_resolve_impacket_system_ok(monkeypatch):
    import adscan.runner as R
    R._IMPACKET_DIR = None
    monkeypatch.setattr(R, "which", lambda n: "/usr/local/bin/" + n if n.endswith(".py") else None)
    monkeypatch.setattr(R, "_impacket_script_runs", lambda p: True)  # sistem sağlam
    try:
        assert R.resolve_impacket("getST.py") == "/usr/local/bin/getST.py"
    finally:
        R._IMPACKET_DIR = None


def test_resolve_impacket_falls_back_to_venv(monkeypatch, tmp_path):
    import adscan.runner as R
    R._IMPACKET_DIR = None
    venv = tmp_path / "venv" / "bin"
    venv.mkdir(parents=True)
    (venv / "secretsdump.py").write_text("#!/usr/bin/python3\n")
    (venv / "getST.py").write_text("#!/usr/bin/python3\n")
    monkeypatch.setattr(R, "which", lambda n: "/usr/local/bin/" + n)
    # sistem scripti bozuk, venv kopyası sağlam
    monkeypatch.setattr(R, "_impacket_script_runs",
                        lambda p: "/usr/local/bin/" not in p)
    monkeypatch.setattr(R, "_glob", R._glob)
    monkeypatch.setattr(R._glob, "glob",
                        lambda pat: [str(venv / "secretsdump.py")] if "secretsdump" in pat else [])
    try:
        got = R.resolve_impacket("getST.py")
        assert got == str(venv / "getST.py")
    finally:
        R._IMPACKET_DIR = None

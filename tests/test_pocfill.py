"""pocfill — PoC/escalation yer tutucularının gerçek kimlikle doldurulması."""

from adscan import config, pocfill
from adscan.findings import Credential, Finding, ScanReport, Severity


def _rep(poc="", esc="", *, creds=(), domain="", dc_name=""):
    r = ScanReport(target="10.0.0.1", domain=domain, dc_name=dc_name)
    r.add(Finding(title="t", severity=Severity.LOW, target="t", source="x",
                  poc=poc, escalation=esc))
    for c in creds:
        r.add_credential(c)
    return r


def setup_function(_):
    config.set_redact(False)


def teardown_function(_):
    config.set_redact(False)


def test_fills_user_pass_domain():
    c = Credential(username="alice", secret="P@ss w0rd", domain="corp.local")
    r = _rep(poc="smbmap -H 10.0.0.1 -u <user> -p <pass> -R SYSVOL", creds=[c])
    pocfill.fill(r)
    assert r.findings[0].poc == "smbmap -H 10.0.0.1 -u alice -p 'P@ss w0rd' -R SYSVOL"


def test_fills_user_at_domain_and_dc():
    c = Credential(username="bob", secret="x", domain="corp.local")
    r = _rep(poc="certipy -u <user>@<domain> -dc-ip <dc>", creds=[c],
             domain="corp.local", dc_name="DC01")
    pocfill.fill(r)
    assert r.findings[0].poc == "certipy -u bob@corp.local -dc-ip dc01.corp.local"


def test_nthash_converts_pass_flag_to_hash():
    c = Credential(username="svc", secret="a" * 32, kind="nthash", domain="corp.local")
    r = _rep(poc="nxc smb <dc> -u <user> -p <pass> --ntds", creds=[c],
             domain="corp.local", dc_name="DC01")
    pocfill.fill(r)
    assert f"-H {'a' * 32}" in r.findings[0].poc
    assert "-p <pass>" not in r.findings[0].poc


def test_redact_leaves_placeholders():
    config.set_redact(True)
    c = Credential(username="alice", secret="secret", domain="corp.local")
    r = _rep(poc="nxc smb x -u <user> -p <pass>", creds=[c])
    pocfill.fill(r)
    assert r.findings[0].poc == "nxc smb x -u <user> -p <pass>"  # değişmez


def test_no_cred_leaves_unchanged():
    r = _rep(poc="nxc smb x -u <user> -p <pass>")
    pocfill.fill(r)
    assert r.findings[0].poc == "nxc smb x -u <user> -p <pass>"


def test_prefers_password_over_hash_and_admin():
    hashc = Credential(username="h", secret="b" * 32, kind="nthash")
    passc = Credential(username="admin", secret="pw", domain="corp.local", admin=True)
    r = _rep(poc="-u <user> -p <pass>", creds=[hashc, passc])
    pocfill.fill(r)
    assert r.findings[0].poc == "-u admin -p 'pw'"

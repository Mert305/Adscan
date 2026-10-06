"""windap_scan.parse — LDAP enumerasyon tespitleri."""

from conftest import cr, severity_of, titles

from adscan.findings import Severity
from adscan.modules import windap_scan

DA = "dn: CN=Administrator\nsAMAccountName: Administrator\nsAMAccountName: svc-adm"
UNC = "dn: CN=DC01\nsAMAccountName: DC01$"
USERS = "sAMAccountName: alice\nsAMAccountName: bob\nsAMAccountName: carol"

# argv'de -u YOK -> anonim bind
ANON_ARGV = ["windapsearch", "--dc-ip", "10.10.10.5", "--da"]


def _results():
    return [
        cr(DA, tool="windap-da", argv=ANON_ARGV),
        cr("", tool="windap-privileged", argv=ANON_ARGV),
        cr(UNC, tool="windap-unconstrained", argv=ANON_ARGV),
        cr(USERS, tool="windap-users", argv=ANON_ARGV),
        cr("", tool="windap-computers", argv=ANON_ARGV),
    ]


def test_windap_anonymous_bind_high(report):
    windap_scan.parse(_results(), report)
    assert severity_of(report, "Anonim LDAP bind") == Severity.HIGH


def test_windap_domain_admins_listed(report):
    windap_scan.parse(_results(), report)
    assert any("Domain Admins" in x for x in titles(report))


def test_windap_unconstrained_high(report):
    windap_scan.parse(_results(), report)
    assert severity_of(report, "Unconstrained") == Severity.HIGH


def test_windap_user_count(report):
    windap_scan.parse(_results(), report)
    assert any("3 kullanıcı" in x for x in titles(report))


def test_windap_with_creds_no_anon_finding(report):
    creds_argv = ["windapsearch", "--dc-ip", "10.10.10.5", "-u", "bob", "--da"]
    res = [cr(DA, tool="windap-da", argv=creds_argv)]
    windap_scan.parse(res, report)
    assert not any("Anonim" in x for x in titles(report))

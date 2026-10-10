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


def test_windap_first_run_fails_rest_parsed(report):
    # İlk run (--da) başarısız (örn. özyineleme hatası) ama diğer run'lar veri
    # üretti -> TÜM enumerasyon iptal EDİLMEMELİ, veri ayrıştırılmalı.
    res = [
        cr("[!] Error enumerating Domain Admins", tool="windap-da",
           argv=ANON_ARGV, returncode=1),
        cr("", tool="windap-privileged", argv=ANON_ARGV),
        cr(UNC, tool="windap-unconstrained", argv=ANON_ARGV),
        cr(USERS, tool="windap-users", argv=ANON_ARGV),
        cr("", tool="windap-computers", argv=ANON_ARGV),
    ]
    windap_scan.parse(res, report)
    assert not report.errors  # sert hata yok
    assert any("Unconstrained" in x for x in titles(report))
    assert any("kullanıcı" in x for x in titles(report))


def test_windap_anon_bind_banner_not_data(report):
    # Anonim bind RootDSE'ye bağlanır ama arama reddedilir (DC auth ister).
    # windapsearch yine '[+] Using DN: CN=...' / 'Found: DC=...' banner'ları basar;
    # bunlar 'DN:'/'CN=' içerse de GERÇEK veri değildir -> anon-bind bulgusu OLMAMALI.
    out = (
        "[+] Getting defaultNamingContext from Root DSE\n"
        "[+]\tFound: DC=danglingtree,DC=htb\n"
        "[+] Using DN: CN=Domain Admins,CN=Users,DC=danglingtree,DC=htb\n"
        "[+]\t...success! Binded as: \n"
        "[!] Error doing search\n"
        "[!] {'desc': 'Operations error', 'info': 'successful bind must be completed'}"
    )
    res = [cr(out, tool=lbl, argv=ANON_ARGV, returncode=1)
           for lbl in ("windap-da", "windap-privileged", "windap-unconstrained",
                       "windap-users", "windap-computers")]
    windap_scan.parse(res, report)
    assert not any("Anonim" in x for x in titles(report))
    assert report.errors  # bunun yerine anlamlı hata


def test_windap_all_fail_reports_real_reason(report):
    # Tüm run'lar başarısız ve hiç veri yok -> aracın gerçek '[!]' nedenini ver.
    err = "[+] Using Domain Controller at: 10.10.10.5\n[!] Error retrieving the root DSE"
    res = [cr(err, tool=lbl, argv=ANON_ARGV, returncode=1)
           for lbl in ("windap-da", "windap-privileged", "windap-unconstrained",
                       "windap-users", "windap-computers")]
    windap_scan.parse(res, report)
    assert report.errors
    assert any("root DSE" in e for e in report.errors)
    assert not titles(report)

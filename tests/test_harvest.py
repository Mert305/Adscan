"""harvest — çıktıdan kullanıcı/host çıkarma testleri."""

from adscan import harvest
from adscan.findings import ScanReport
from adscan.modules import spray_scan


def test_users_from_samaccountname():
    txt = "sAMAccountName: alice\nsAMAccountName: bob"
    assert harvest.users_from_text(txt) == ["alice", "bob"]


def test_users_from_domain_user_column():
    txt = ("SMB 10.0.0.1 445 DC [*] Enumerated domain user(s)\n"
           "SMB 10.0.0.1 445 DC corp.local\\alice  badpwdcount: 0\n"
           "SMB 10.0.0.1 445 DC corp.local\\bob    badpwdcount: 1")
    users = harvest.users_from_text(txt)
    assert "alice" in users and "bob" in users


def test_users_dedup_and_noise_filtered():
    txt = "sAMAccountName: Alice\ncorp\\alice\nsAMAccountName: Guest"
    users = harvest.users_from_text(txt)
    assert len([u for u in users if u.lower() == "alice"]) == 1  # dedup (case-insensitive)
    assert "Guest" not in users  # gürültü filtresi


def test_machine_accounts_excluded_by_default():
    txt = "sAMAccountName: DC01$\nsAMAccountName: alice"
    assert harvest.users_from_text(txt) == ["alice"]
    assert "DC01$" in harvest.users_from_text(txt, keep_machines=True)


def test_hosts_from_nmap():
    txt = "Nmap scan report for dc01 (10.0.0.5)\nNmap scan report for 10.0.0.6"
    assert harvest.hosts_from_text(txt) == ["10.0.0.5", "10.0.0.6"]


def test_harvest_writes_to_report():
    r = ScanReport(target="10.0.0.1")
    r.raw_outputs["nxc"] = "sAMAccountName: alice"
    r.raw_outputs["nmap"] = "Nmap scan report for 10.0.0.9"
    users, hosts = harvest.harvest(r)
    assert "alice" in users and "10.0.0.9" in hosts
    assert r.users == users and r.hosts == hosts


def test_default_spray_list_nonempty():
    assert len(spray_scan.DEFAULT_SPRAY_PASSWORDS) >= 5
    assert "123456" in spray_scan.DEFAULT_SPRAY_PASSWORDS

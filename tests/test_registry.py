"""registry — modül kaydı ve --only seçimi testleri."""

import pytest

from adscan.registry import (
    ScanContext,
    all_modules,
    get_module,
    passive_modules,
    select_modules,
)


def test_all_modules_names():
    names = {m.name for m in all_modules()}
    assert names == {"nmap", "web", "dns", "nxc-smb", "nxc-ldap", "nxc-vulns",
                     "smbmap", "windapsearch", "certipy", "bloodyad", "bloodyad-enum",
                     "bloodhound", "mssql", "gmsa", "access", "delegation", "gpo",
                     "tickets", "winrm", "shadow", "userenum", "spray", "relay", "reuse"}


def test_select_none_returns_only_passive():
    # Opt-in (spray/relay) varsayılan seçime GİRMEZ
    names = {m.name for m in select_modules(None)}
    assert names == {m.name for m in passive_modules()}
    assert "spray" not in names and "relay" not in names


def test_optin_modules_are_flagged():
    assert get_module("spray").optin and get_module("spray").active
    assert get_module("relay").optin and get_module("relay").active


def test_select_subset():
    mods = select_modules({"nmap", "nxc-smb"})
    assert {m.name for m in mods} == {"nmap", "nxc-smb"}


def test_select_optin_by_name():
    # Açıkça adıyla istenirse opt-in modül seçilebilir
    assert {m.name for m in select_modules({"spray"})} == {"spray"}


def test_select_unknown_raises():
    with pytest.raises(ValueError) as exc:
        select_modules({"nmap", "bogus"})
    assert "bogus" in str(exc.value)


def test_modules_have_callables():
    for m in all_modules():
        assert callable(m.run)
        assert callable(m.parse)


def test_dry_run_through_registry():
    # Gerçek araç gerektirmeden dry-run tüm boru hattını egzersiz eder.
    ctx = ScanContext(target="10.0.0.1", dry_run=True)
    # reuse 2. aşamadır ve certipy kimlik gerektirir: kimlik olmadan 'skip'
    # dönerler, bu yüzden dry-run boru hattı kontrolünden hariç tutulur
    for m in all_modules():
        if m.name == "reuse" or m.requires_creds:
            continue
        results = m.run(ctx)
        assert isinstance(results, list)
        assert all(r.ok or r.error_kind == "skipped" for r in results)

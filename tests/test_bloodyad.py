"""bloodyAD 'get writable' parse + LDAP ayrıcalıklı grup zenginleştirme testleri."""

from conftest import cr, severity_of, titles

from adscan.findings import Severity
from adscan.modules import bloodyAD_scan, nxc_scan

# --- bloodyAD ---

def test_bloodyad_skip_without_creds(report):
    results = bloodyAD_scan.scan("10.10.10.5", dry_run=True)
    bloodyAD_scan.parse(results, report)
    assert results[0].tool == "bloodyad:skip"
    assert report.findings == []  # kimlik yok -> sessizce atla


def test_bloodyad_writable_privileged_is_critical(report):
    out = (
        "distinguishedName: CN=svc_sql,CN=Users,DC=corp,DC=local\n"
        "servicePrincipalName: WRITE\n\n"
        "distinguishedName: CN=Domain Admins,CN=Users,DC=corp,DC=local\n"
        "member: WRITE\n")
    bloodyAD_scan.parse([cr(out, tool="bloodyad-writable")], report)
    assert severity_of(report, "yazılabilir") == Severity.CRITICAL
    esc = next(f.escalation for f in report.findings if "yazılabilir" in f.title)
    assert "Gruba ekle" in esc          # member -> gruba ekle PoC
    assert "Kerberoast" in esc          # SPN -> targeted kerberoast PoC


def test_bloodyad_writable_deleted_object_is_reanimation(report):
    # Silinmiş + yazılabilir nesne -> KRİTİK tombstone reanimation bulgusu
    out = (
        "distinguishedName: CN=Mark Davies\\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,"
        "CN=Deleted Objects,DC=checkpoint,DC=htb\n"
        "permission: WRITE\n")
    bloodyAD_scan.parse([cr(out, tool="bloodyad-writable")], report)
    f = next(f for f in report.findings if "reanimation" in f.title.lower())
    assert f.severity == Severity.CRITICAL
    assert "Mark Davies" in f.title
    assert "set restore" in f.poc
    assert "Kerberoast" in f.escalation and "Parola tekrarı" in f.escalation


def test_bloodyad_reanimation_names_deleted_users(report):
    # Deleted Objects yazılabilir + ayrı 'show deleted' sorgusu mark.davies'i buluyor
    writable = cr("distinguishedName: CN=Deleted Objects,DC=checkpoint,DC=htb\n"
                  "DACL: WRITE\n", tool="bloodyad-writable")
    deleted = cr(
        "distinguishedName: CN=Mark Davies\\0ADEL:2217e877,CN=Deleted Objects,DC=checkpoint,DC=htb\n"
        "sAMAccountName: mark.davies\n"
        "lastKnownParent: OU=Employees,DC=checkpoint,DC=htb\n",
        tool="bloodyad-deleted")
    bloodyAD_scan.parse([writable, deleted], report)
    f = next(f for f in report.findings if "reanimation" in f.title.lower())
    assert f.severity == Severity.CRITICAL
    assert "mark.davies" in f.title                 # aday isimle başlıkta
    assert "set restore mark.davies" in f.poc       # PoC doğrudan o kullanıcıya
    assert "mark.davies" in f.evidence and "OU=Employees" in f.evidence


def test_bloodyad_no_writable_no_finding(report):
    bloodyAD_scan.parse([cr("No writable object found", tool="bloodyad-writable")], report)
    assert report.findings == []


def test_bloodyad_error_is_reported(report):
    bad = cr("", tool="bloodyad-writable", error="bağlanılamadı")
    bloodyAD_scan.parse([bad], report)
    assert any("bloodyAD" in e for e in report.errors)


# --- bloodyAD LDAP enumerasyon (get search / dnsDump / trusts) ---

def test_bloodyad_enum_skip_without_creds(report):
    results = bloodyAD_scan.scan_enum("10.10.10.5", dry_run=True)
    bloodyAD_scan.parse_enum(results, report)
    assert results[0].tool == "bloodyad-enum:skip"
    assert report.findings == []  # kimlik yok -> sessizce atla


def test_bloodyad_enum_asrep_is_high(report):
    out = (
        "distinguishedName: CN=svc-web,CN=Users,DC=corp,DC=local\n"
        "sAMAccountName: svc-web\n"
        "userAccountControl: 4260352\n")
    bloodyAD_scan.parse_enum([cr(out, tool="bloodyad-enum-asrep")], report)
    assert severity_of(report, "AS-REP roastable") == Severity.HIGH
    f = next(f for f in report.findings if "AS-REP" in f.title)
    assert "svc-web" in f.title     # sAMAccountName önizlemesi başlıkta
    assert "18200" in f.escalation  # hashcat AS-REP modu


def test_bloodyad_enum_kerberoast_counts_records(report):
    out = (
        "distinguishedName: CN=svc-sql,CN=Users,DC=corp,DC=local\n"
        "sAMAccountName: svc-sql\n"
        "servicePrincipalName: MSSQLSvc/db.corp.local:1433\n\n"
        "distinguishedName: CN=svc-http,CN=Users,DC=corp,DC=local\n"
        "sAMAccountName: svc-http\n"
        "servicePrincipalName: HTTP/web.corp.local\n")
    bloodyAD_scan.parse_enum([cr(out, tool="bloodyad-enum-kerberoast")], report)
    f = next(f for f in report.findings if "Kerberoastable" in f.title)
    assert f.severity == Severity.HIGH
    assert "2 kayıt" in f.title
    assert "svc-sql" in f.title and "svc-http" in f.title


def test_bloodyad_enum_description_medium(report):
    out = (
        "distinguishedName: CN=jdoe,CN=Users,DC=corp,DC=local\n"
        "sAMAccountName: jdoe\n"
        "description: Initial password Welcome2024!\n")
    bloodyAD_scan.parse_enum([cr(out, tool="bloodyad-enum-desc")], report)
    assert severity_of(report, "description") == Severity.MEDIUM


def test_bloodyad_enum_desc_filters_builtin_accounts(report):
    # Yerleşik hesap açıklamaları gürültüdür -> bulgu üretmemeli
    out = (
        "distinguishedName: CN=Administrator,CN=Users,DC=corp,DC=local\n"
        "sAMAccountName: Administrator\n"
        "description: Built-in account for administering the computer/domain\n\n"
        "distinguishedName: CN=krbtgt,CN=Users,DC=corp,DC=local\n"
        "sAMAccountName: krbtgt\n"
        "description: Key Distribution Center Service Account\n")
    bloodyAD_scan.parse_enum([cr(out, tool="bloodyad-enum-desc")], report)
    assert severity_of(report, "description") is None  # hepsi yerleşik -> bulgu yok


def test_bloodyad_enum_trusts_none_when_empty(report):
    # bloodyAD 'No Trusts found' hata bloğu trust sanılmamalı
    out = ("[-] Something went wrong when trying to perform this ldap search\n"
           "[-] Error NoResultError: No object found\n"
           "[!] No Trusts found\n")
    bloodyAD_scan.parse_enum([cr(out, tool="bloodyad-enum-trusts")], report)
    assert severity_of(report, "trust") is None


def test_bloodyad_enum_dns_is_info(report):
    out = ("recordName: DC01\nA: 10.129.0.10\n\n"
           "recordName: WS01\nA: 10.129.0.20\n")
    bloodyAD_scan.parse_enum([cr(out, tool="bloodyad-enum-dns")], report)
    assert severity_of(report, "DNS kayıt") == Severity.INFO


def test_bloodyad_enum_trusts_medium(report):
    out = "corp.local\n  -> child.corp.local\n"
    bloodyAD_scan.parse_enum([cr(out, tool="bloodyad-enum-trusts")], report)
    assert severity_of(report, "trust") == Severity.MEDIUM


def test_bloodyad_enum_all_fail_reports_error(report):
    bad = cr("", tool="bloodyad-enum-asrep", error="bind başarısız")
    bloodyAD_scan.parse_enum([bad], report)
    assert any("bloodyAD enum" in e for e in report.errors)


def test_bloodyad_enum_registered_in_registry():
    from adscan.registry import get_module
    m = get_module("bloodyad-enum")
    assert m.optin and m.requires_creds


# --- LDAP ayrıcalıklı grup zenginleştirme (nxc) ---

def test_ldap_privileged_groups_bump_to_medium(report):
    groups = (
        "LDAP 10.10.10.5 389 DC Domain Admins\n"
        "LDAP 10.10.10.5 389 DC Backup Operators\n"
        "LDAP 10.10.10.5 389 DC DnsAdmins\n"
        "LDAP 10.10.10.5 389 DC Users\n")
    nxc_scan._parse_ldap_enum([cr(groups, tool="nxc-ldap-groups")], report)
    assert severity_of(report, "grup enumere") == Severity.MEDIUM
    esc = next(f.escalation for f in report.findings if "grup enumere" in f.title)
    assert "Backup Operators" in esc and "DnsAdmins" in esc


def test_ldap_groups_without_privileged_stay_info(report):
    groups = ("LDAP 10.10.10.5 389 DC Users\n"
              "LDAP 10.10.10.5 389 DC Guests\n")
    nxc_scan._parse_ldap_enum([cr(groups, tool="nxc-ldap-groups")], report)
    assert severity_of(report, "grup enumere") == Severity.INFO


# --- v0.3: --json yolu, LDAPS retry, argüman üretimi (profesyonel bloodyAD) ---

import json as _json  # noqa: E402

from adscan.runner import CommandResult  # noqa: E402


def _crj(entries, tool):
    """--json çıktısını taklit eden sahte sonuç (JSON stdout'ta, log stderr'de)."""
    return CommandResult(tool=tool, argv=["bloodyAD"], returncode=0,
                         stdout=_json.dumps(entries), stderr="[*] bind ok\n", duration=0.1)


def test_base_argv_json_secure_kerberos():
    argv = bloodyAD_scan._base_argv("dc", "corp.local", "u", "pw", None,
                                    json_out=True, secure=True)
    assert "--json" in argv and "-s" in argv
    # kerberos + ccache (parola yok) -> -p verilmez
    k = bloodyAD_scan._base_argv("dc", "corp.local", "u", None, None,
                                 use_kerberos=True)
    assert "-k" in k and "-p" not in k
    # nthash -> LMHASH:NTHASH biçimi
    h = bloodyAD_scan._base_argv("dc", "corp.local", "u", None, "a" * 32)
    assert any(x.endswith(":" + "a" * 32) for x in h)


def test_needs_secure_detects_signing():
    sign = CommandResult(tool="t", argv=["x"], returncode=0, stdout="",
                         stderr="strongerAuthRequired: data 80090346", duration=0.0)
    assert bloodyAD_scan._needs_secure(sign) is True
    ok = CommandResult(tool="t", argv=["x"], returncode=0, stdout="[]",
                       stderr="", duration=0.0)
    assert bloodyAD_scan._needs_secure(ok) is False


def test_json_entries_and_fallback():
    r = _crj([{"distinguishedName": "CN=x,DC=c,DC=l", "member": ["WRITE"]}], "bloodyad-writable")
    recs = bloodyAD_scan._records_of(r)
    assert recs and recs[0]["member"] == ["WRITE"]
    # düz metin -> fallback _records
    txt = cr("distinguishedName: CN=y,DC=c,DC=l\nmember: WRITE\n", tool="bloodyad-writable")
    recs2 = bloodyAD_scan._records_of(txt)
    assert recs2 and "member" in recs2[0]


def test_bloodyad_writable_json_rbcd_shadow(report):
    w = _crj([
        {"distinguishedName": "CN=web01,OU=Servers,DC=corp,DC=local",
         "msDS-AllowedToActOnBehalfOfOtherIdentity": ["WRITE"]},
        {"distinguishedName": "CN=alice,CN=Users,DC=corp,DC=local",
         "msDS-KeyCredentialLink": ["WRITE"]},
    ], "bloodyad-writable")
    bloodyAD_scan.parse([w], report)
    f = next(x for x in report.findings if "yazılabilir" in x.title)
    assert "RBCD" in f.escalation and "Shadow creds" in f.escalation
    assert "serviceprincipalname" not in f.escalation.lower()  # SPN hak yoktu


def test_privdn_not_overbroad(report):
    # Sıradan bir nesne (web01) yüksek değerli SAYILMAMALI; sadece grup/kök sayılır
    w = _crj([
        {"distinguishedName": "CN=web01,OU=Servers,DC=corp,DC=local", "member": ["WRITE"]},
        {"distinguishedName": "CN=Domain Admins,CN=Users,DC=corp,DC=local", "member": ["WRITE"]},
        {"distinguishedName": "DC=corp,DC=local", "DACL": ["WRITE"]},
    ], "bloodyad-writable")
    bloodyAD_scan.parse([w], report)
    f = next(x for x in report.findings if "yazılabilir" in x.title)
    assert "2 yüksek değerli" in f.title  # web01 hariç
    hv = [ln for ln in f.evidence.splitlines() if "YÜKSEK DEĞER" in ln]
    assert not any("web01" in ln for ln in hv)


def test_enum_json_kerberoast(report):
    out = _crj([
        {"distinguishedName": "CN=svc-sql,CN=Users,DC=corp,DC=local",
         "sAMAccountName": ["svc-sql"], "servicePrincipalName": ["MSSQLSvc/db:1433"]},
    ], "bloodyad-enum-kerberoast")
    bloodyAD_scan.parse_enum([out], report)
    f = next(x for x in report.findings if "Kerberoastable" in x.title)
    assert "1 kayıt" in f.title and "svc-sql" in f.title
    assert "svc-sql" in f.evidence


def test_enum_json_dns(report):
    out = _crj([
        {"recordName": "DC01", "A": ["10.0.0.10"]},
        {"recordName": "WS01", "A": ["10.0.0.20"]},
    ], "bloodyad-enum-dns")
    bloodyAD_scan.parse_enum([out], report)
    assert severity_of(report, "DNS kayıt") == Severity.INFO
    f = next(x for x in report.findings if "DNS" in x.title)
    assert "DC01" in f.evidence and "10.0.0.10" in f.evidence


def test_bloodyad_enum_des_encryption_high(report):
    out = (
        "distinguishedName: CN=svc-legacy,CN=Users,DC=corp,DC=local\n"
        "sAMAccountName: svc-legacy\n"
        "msDS-SupportedEncryptionTypes: 3\n")
    bloodyAD_scan.parse_enum([cr(out, tool="bloodyad-enum-encryption-des")], report)
    f = next(f for f in report.findings if "DES" in f.title)
    assert f.severity == Severity.HIGH
    assert "svc-legacy" in f.title


def test_bloodyad_enum_rc4_only_medium(report):
    out = (
        "distinguishedName: CN=svc-sql,CN=Users,DC=corp,DC=local\n"
        "sAMAccountName: svc-sql\n"
        "msDS-SupportedEncryptionTypes: 4\n")
    bloodyAD_scan.parse_enum([cr(out, tool="bloodyad-enum-rc4-only")], report)
    f = next(f for f in report.findings if "RC4" in f.title)
    assert f.severity == Severity.MEDIUM
    assert "13100" in f.escalation  # RC4 kerberoast hashcat modu


def test_bloodyad_enum_rc4_none_no_finding(report):
    # Sorgu eşleşmediyse (AES yapılandırılmış hesaplar) kayıt yok -> bulgu yok
    bloodyAD_scan.parse_enum(
        [cr("[-] No results\n", tool="bloodyad-enum-rc4-only")], report)
    assert not any("RC4" in t for t in titles(report))


def test_bloodyad_enum_reversible_pw_high(report):
    out = ("sAMAccountName: svc-legacy\n"
           "userAccountControl: 128\n")
    bloodyAD_scan.parse_enum([cr(out, tool="bloodyad-enum-reversible-pw")], report)
    assert severity_of(report, "döndürülebilir") == Severity.HIGH


def test_bloodyad_enum_neverexpire_priv_medium(report):
    out = ("sAMAccountName: admin-old\n"
           "userAccountControl: 66048\n")
    bloodyAD_scan.parse_enum([cr(out, tool="bloodyad-enum-neverexpire-priv")], report)
    assert severity_of(report, "hiç dolmayan") == Severity.MEDIUM


def test_age_days_parses_iso_and_filetime_and_bad():
    assert bloodyAD_scan._age_days("2019-01-01 00:00:00+00:00") > 1000
    assert bloodyAD_scan._age_days("130000000000000000") > 1000   # eski FILETIME
    assert bloodyAD_scan._age_days("saçma") is None
    assert bloodyAD_scan._age_days("") is None


def test_bloodyad_krbtgt_old_is_finding(report):
    out = "sAMAccountName: krbtgt\npwdLastSet: 2019-01-01 00:00:00+00:00\n"
    bloodyAD_scan.parse_enum([cr(out, tool="bloodyad-enum-krbtgt")], report)
    assert any("krbtgt parolası çok eski" in t for t in titles(report))


def test_bloodyad_krbtgt_recent_no_finding(report):
    import datetime as dt
    recent = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=10)
              ).strftime("%Y-%m-%d %H:%M:%S%z")
    out = f"sAMAccountName: krbtgt\npwdLastSet: {recent}\n"
    bloodyAD_scan.parse_enum([cr(out, tool="bloodyad-enum-krbtgt")], report)
    assert not any("krbtgt" in t for t in titles(report))


def test_bloodyad_stale_filters_recent_record(report):
    import datetime as dt
    recent = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=5)
              ).strftime("%Y-%m-%d %H:%M:%S%z")
    out = (f"sAMAccountName: old_user\nlastLogonTimestamp: 2019-01-01 00:00:00+00:00\n\n"
           f"sAMAccountName: active_user\nlastLogonTimestamp: {recent}\n")
    bloodyAD_scan.parse_enum([cr(out, tool="bloodyad-enum-stale")], report)
    f = next(f for f in report.findings if "Bayat" in f.title)
    assert "old_user" in f.evidence
    assert "active_user" not in f.evidence  # parser yaş yeniden-doğrulaması eledi

"""Scope guard, diff, resume, loot, MITRE ve HTML rapor testleri."""

import os

from adscan import cli, mitre, util
from adscan import report as reporting
from adscan.findings import Credential, Finding, ScanReport, Severity

# --- scope guard ---

def _scope(tmp_path, *entries):
    p = tmp_path / "scope.txt"
    p.write_text("\n".join(entries) + "\n")
    return str(p)


def test_scope_allows_in_range(tmp_path):
    sf = _scope(tmp_path, "10.10.10.0/24", "# yorum", "dc.corp.local")
    assert cli._in_scope("10.10.10.5", sf)[0] is True
    assert cli._in_scope("dc.corp.local", sf)[0] is True


def test_scope_rejects_out_of_range(tmp_path):
    sf = _scope(tmp_path, "10.10.10.0/24")
    ok, reason = cli._in_scope("192.168.1.5", sf)
    assert ok is False and "192.168.1.5" in reason


def test_scope_multi_target_all_must_match(tmp_path):
    sf = _scope(tmp_path, "10.10.10.0/24")
    assert cli._in_scope("10.10.10.5,10.10.10.9", sf)[0] is True
    assert cli._in_scope("10.10.10.5,192.168.1.1", sf)[0] is False


# --- diff ---

def test_diff_detects_new_and_resolved():
    r = ScanReport(target="t")
    r.add(Finding(title="YeniBulgu", severity=Severity.HIGH, target="t", source="x"))
    r.add(Finding(title="Ortak", severity=Severity.LOW, target="t", source="x"))
    prior = {"findings": [{"title": "Ortak"}, {"title": "EskiBulgu"}]}
    new, resolved = cli._diff_reports(r, prior)
    assert new == ["YeniBulgu"] and resolved == ["EskiBulgu"]


# --- resume ---

def test_resume_loads_prior_context(tmp_path):
    prior = ScanReport(target="10.0.0.1", domain="corp.local", dc_name="DC01")
    prior.users.extend(["alice", "bob"])
    prior.hosts.append("10.0.0.2")
    prior.add_credential(Credential(username="alice", secret="Pw1", domain="corp.local"))
    reporting.write_json(prior, str(tmp_path / "adscan-10.0.0.1-20260101-000000.json"))

    loaded = cli._load_prior_report(str(tmp_path), "10.0.0.1")
    assert loaded is not None
    fresh = ScanReport(target="10.0.0.1")
    cli._resume_from(fresh, loaded)
    assert "alice" in fresh.users and "10.0.0.2" in fresh.hosts
    assert fresh.domain == "corp.local" and fresh.dc_name == "DC01"
    assert any(c.username == "alice" for c in fresh.credentials)


def test_resume_skips_redacted_secret(tmp_path):
    prior = {"credentials": [{"username": "x", "secret": "***", "domain": "d"}]}
    fresh = ScanReport(target="t")
    cli._resume_from(fresh, prior)
    assert fresh.credentials == []  # maskeli sır geri yüklenmez


# --- prune ---

def test_prune_keeps_latest_and_scopes_by_target(tmp_path):
    for name in ("adscan-10.0.0.5-20260101-000000.json",
                 "adscan-10.0.0.5-20260101-000000.md",
                 "adscan-10.0.0.50-20260101-000000.json"):  # farklı hedef
        (tmp_path / name).write_text("{}")
    base = str(tmp_path / "adscan-10.0.0.5-20260102-000000")
    (tmp_path / "adscan-10.0.0.5-20260102-000000.json").write_text("{}")
    removed = cli._prune_old_reports(str(tmp_path), "10.0.0.5", base)
    names = {os.path.basename(p) for p in removed}
    assert "adscan-10.0.0.5-20260101-000000.json" in names
    assert "adscan-10.0.0.50-20260101-000000.json" not in names  # başka hedef korunur
    assert (tmp_path / "adscan-10.0.0.5-20260102-000000.json").exists()


# --- loot ---

def test_loot_path_under_outdir(tmp_path):
    p = util.loot_path(str(tmp_path), "kerb.txt")
    assert p.endswith(os.path.join("loot", "kerb.txt"))
    assert os.path.isdir(os.path.join(str(tmp_path), "loot"))


# --- MITRE ---

def test_mitre_maps_kerberoast():
    assert mitre.technique_for("nxc-ldap Kerberoasting'e açık") == "T1558.003"


def test_mitre_annotate_fills_blank_only():
    r = ScanReport(target="t")
    r.add(Finding(title="Kerberoasting", severity=Severity.HIGH, target="t",
                  source="nxc-ldap"))
    r.add(Finding(title="elle", severity=Severity.LOW, target="t", source="x",
                  mitre="T9999"))
    mitre.annotate(r)
    assert r.findings[0].mitre == "T1558.003"
    assert r.findings[1].mitre == "T9999"  # elle verilen korunur


# --- HTML rapor ---

def test_write_html_is_valid(tmp_path):
    r = ScanReport(target="10.10.10.5", domain="corp.local", dc_name="DC01")
    r.add(Finding(title="Kerberoasting'e açık", severity=Severity.HIGH, target="t",
                  source="nxc-ldap", evidence="$krb5tgs$...", mitre="T1558.003"))
    r.add_credential(Credential(username="alice", secret="Pw1", domain="corp.local",
                                admin=True))
    out = str(tmp_path / "r.html")
    reporting.write_html(r, out)
    html = open(out, encoding="utf-8").read()
    assert html.startswith("<!doctype html>")
    for token in ("Kerberoasting", "T1558.003", "dc01.corp.local", "alice",
                  "prefers-color-scheme", "Saldırı Yolu"):
        assert token in html

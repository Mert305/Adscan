"""Beyin geliştirmeleri + yeni modüller için testler.

Kapsar:
  - ldap-signing modülü (signing / channel-binding parse, kimliksiz skip)
  - escalate modülünün registry'ye kaydı
  - brain.runnable_candidates: escalate yalnız kimlik varken aday; quiet/noise snapshot
  - OllamaBrain geçersiz-JSON retry ve keep_alive payload (ağ çağrısı stub'lanır)
"""

import os

from conftest import cr, severity_of

from adscan import brain as brain_mod
from adscan.findings import Credential, ScanReport, Severity
from adscan.modules import ldapsign_scan
from adscan.registry import ScanContext, all_modules, noise_of

# --- ldap-signing modülü ---------------------------------------------------

def test_ldapsign_skip_without_creds(report):
    res = ldapsign_scan.scan("10.10.10.5", dry_run=True)
    ldapsign_scan.parse(res, report)
    assert res[0].tool == "ldap-signing:skip"
    assert report.findings == []


def test_ldapsign_signing_not_enforced_is_high(report):
    out = "LDAP 10.10.10.5 389 DC01 LDAP Signing NOT Enforced!"
    ldapsign_scan.parse([cr(out, tool="ldap-checker")], report)
    assert severity_of(report, "imzalama") == Severity.HIGH


def test_ldapsign_channel_binding_is_high(report):
    out = 'LDAP 10.10.10.5 636 DC01 LDAPS Channel Binding is set to "NEVER"!'
    ldapsign_scan.parse([cr(out, tool="ldap-checker")], report)
    assert severity_of(report, "channel binding") == Severity.HIGH


def test_ldapsign_clean_output_no_finding(report):
    out = "LDAP 10.10.10.5 389 DC01 LDAP signing is enforced; channel binding Always"
    ldapsign_scan.parse([cr(out, tool="ldap-checker")], report)
    assert report.findings == []


# --- registry kaydı --------------------------------------------------------

def test_escalate_and_ldapsign_registered():
    names = {m.name for m in all_modules()}
    assert "escalate" in names
    assert "ldap-signing" in names


def test_escalate_is_active_and_noisy():
    esc = next(m for m in all_modules() if m.name == "escalate")
    assert esc.active is True
    assert noise_of("escalate") == "high"
    assert noise_of("ldap-signing") == "low"


# --- brain aday seçimi -----------------------------------------------------

def _ctx():
    return ScanContext(target="10.10.10.5")


def test_escalate_not_candidate_without_credential():
    report = ScanReport(target="10.10.10.5")
    cands = brain_mod.runnable_candidates(
        _ctx(), report, allow_active=True, exclude=set())
    assert "escalate" not in {m.name for m in cands}


def test_escalate_candidate_when_secret_credential_exists():
    report = ScanReport(target="10.10.10.5")
    report.add_credential(Credential(username="svc", secret="aad3b" * 6 + "00000",
                                     kind="nthash", domain="corp", source="spray"))
    cands = brain_mod.runnable_candidates(
        _ctx(), report, allow_active=True, exclude=set())
    assert "escalate" in {m.name for m in cands}


def test_escalate_hidden_without_brain_active():
    report = ScanReport(target="10.10.10.5")
    report.add_credential(Credential(username="svc", secret="pw", kind="password",
                                     domain="corp", source="spray"))
    cands = brain_mod.runnable_candidates(
        _ctx(), report, allow_active=False, exclude=set())
    assert "escalate" not in {m.name for m in cands}


# --- snapshot: quiet + noise -----------------------------------------------

def test_snapshot_includes_noise_and_quiet():
    report = ScanReport(target="10.10.10.5")
    report.scan_mode = "unauthenticated"
    b = brain_mod.OllamaBrain(quiet=True)
    cands = brain_mod.runnable_candidates(
        _ctx(), report, allow_active=False, exclude=set())
    snap = b._snapshot(report, _ctx(), cands)
    assert snap["quiet_opsec"] is True
    assert all("noise" in m for m in snap["available_modules"])


# --- decide: geçersiz JSON retry + keep_alive payload ----------------------

def test_decide_retries_on_invalid_json(monkeypatch):
    report = ScanReport(target="10.10.10.5")
    report.scan_mode = "unauthenticated"
    b = brain_mod.OllamaBrain(keep_alive="15m")
    cands = brain_mod.runnable_candidates(
        _ctx(), report, allow_active=False, exclude=set())
    valid = {m.name for m in cands}
    chosen = next(iter(valid))

    calls = {"n": 0, "keep_alive": None}

    def fake_chat(payload):
        calls["n"] += 1
        calls["keep_alive"] = payload.get("keep_alive")
        if calls["n"] == 1:
            return "bu gecerli json degil {{"
        return f'{{"next_module": "{chosen}", "rationale": "ok", "confidence": 0.8, "done": false}}'

    monkeypatch.setattr(b, "_chat", fake_chat)
    decision = b.decide(report, _ctx(), cands)
    assert calls["n"] == 2  # ilk bozuk -> bir retry
    assert calls["keep_alive"] == "15m"  # keep_alive payload'a eklendi
    assert decision.next_module == chosen
    assert decision.source == "ollama"


def test_decide_falls_back_after_two_invalid(monkeypatch):
    report = ScanReport(target="10.10.10.5")
    report.scan_mode = "unauthenticated"
    b = brain_mod.OllamaBrain()
    cands = brain_mod.runnable_candidates(
        _ctx(), report, allow_active=False, exclude=set())
    monkeypatch.setattr(b, "_chat", lambda payload: "hala bozuk {{")
    decision = b.decide(report, _ctx(), cands)
    assert decision.source == "fallback"

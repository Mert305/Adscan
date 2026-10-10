"""Yeni özellikler için testler: fine-tune veri seti, relay korelasyonu,
saldırı-yolu SVG, beyin hedef-host seçimi."""

import json

from conftest import severity_of

from adscan import brain as brain_mod
from adscan import correlate, finetune
from adscan import report as reporting
from adscan.findings import Credential, Finding, ScanReport, Severity
from adscan.registry import ScanContext, all_modules

# --- fine-tune veri seti ---------------------------------------------------

def _rec(module, *, source="ollama", new_findings=0, new_credentials=0,
         domain_admin=False, error=""):
    return {
        "step": 1, "target": "10.0.0.1", "model": "adscan-brain", "source": source,
        "state": {"scan_mode": "unauthenticated", "available_modules": [{"name": module}]},
        "decision": {"next_module": module, "rationale": "x", "confidence": 0.8,
                     "done": module is None},
        "outcome": {"new_findings": new_findings, "new_credentials": new_credentials,
                    "error": error, "domain_admin": domain_admin},
    }


def test_useful_example_from_productive_decision():
    ex = finetune.trace_to_example(_rec("nmap", new_findings=3), "SYS")
    assert ex is not None
    assert ex["messages"][0]["role"] == "system"
    assert json.loads(ex["messages"][-1]["content"])["next_module"] == "nmap"


def test_fallback_decisions_excluded():
    assert finetune.trace_to_example(_rec("nmap", source="fallback",
                                          new_findings=3), "SYS") is None


def test_unproductive_decision_excluded():
    assert finetune.trace_to_example(_rec("nmap", new_findings=0,
                                          new_credentials=0), "SYS") is None


def test_errored_decision_excluded():
    assert finetune.trace_to_example(_rec("nmap", new_findings=2,
                                          error="boom"), "SYS") is None


def test_build_dataset_roundtrip(tmp_path):
    trace = tmp_path / "trace.jsonl"
    lines = [_rec("nmap", new_findings=2), _rec("spray", source="fallback"),
             _rec("escalate", domain_admin=True)]
    trace.write_text("\n".join(json.dumps(x) for x in lines), encoding="utf-8")
    out = tmp_path / "ds.jsonl"
    written, read = finetune.build_dataset([str(trace)], str(out))
    assert read == 3
    assert written == 2  # fallback hariç
    rows = [json.loads(ln) for ln in out.read_text(encoding="utf-8").splitlines()]
    assert all("messages" in r for r in rows)


# --- relay korelasyonu -----------------------------------------------------

def _report_with(*findings) -> ScanReport:
    r = ScanReport(target="10.0.0.1")
    r.dc_name = "DC01"
    for f in findings:
        r.add(f)
    return r


def test_relay_correlation_fires_with_surface_and_coercion():
    r = _report_with(
        Finding(title="LDAP imzalama zorlanmıyor", severity=Severity.HIGH,
                target="10.0.0.1", source="ldap-signing",
                control_id="ldap.signing.not-enforced"),
        Finding(title="Print Spooler açık (PrinterBug)", severity=Severity.MEDIUM,
                target="10.0.0.1", source="nxc-smb", control_id="coerce.spooler"),
    )
    f = correlate.correlate_relay_path(r)
    assert f is not None
    assert severity_of(r, "relay") == Severity.CRITICAL


def test_relay_correlation_silent_without_coercion():
    r = _report_with(
        Finding(title="LDAP imzalama zorlanmıyor", severity=Severity.HIGH,
                target="10.0.0.1", source="ldap-signing",
                control_id="ldap.signing.not-enforced"))
    assert correlate.correlate_relay_path(r) is None


def test_relay_correlation_silent_without_surface():
    r = _report_with(
        Finding(title="Print Spooler açık", severity=Severity.MEDIUM,
                target="10.0.0.1", source="nxc-smb", control_id="coerce.spooler"))
    assert correlate.correlate_relay_path(r) is None


# --- saldırı yolu SVG ------------------------------------------------------

def test_attack_path_svg_renders():
    r = ScanReport(target="10.0.0.1")
    svg = reporting._attack_path_svg(r)
    assert svg.startswith("<svg") and "</svg>" in svg
    assert "DOMAIN ADMIN" in svg


# --- beyin hedef-host seçimi ----------------------------------------------

def test_brain_accepts_known_host_target(monkeypatch):
    r = ScanReport(target="10.0.0.1")
    r.scan_mode = "unauthenticated"
    r.hosts.extend(["10.0.0.5", "10.0.0.6"])
    b = brain_mod.OllamaBrain()
    cands = brain_mod.runnable_candidates(ScanContext(target="10.0.0.1"), r,
                                          allow_active=False, exclude=set())
    name = next(m.name for m in cands)
    monkeypatch.setattr(b, "_chat", lambda p: json.dumps(
        {"next_module": name, "rationale": "x", "confidence": 0.7, "done": False,
         "target": "10.0.0.5"}))
    d = b.decide(r, ScanContext(target="10.0.0.1"), cands)
    assert d.target == "10.0.0.5"  # known host kabul


def test_brain_rejects_unknown_host_target(monkeypatch):
    r = ScanReport(target="10.0.0.1")
    r.scan_mode = "unauthenticated"
    b = brain_mod.OllamaBrain()
    cands = brain_mod.runnable_candidates(ScanContext(target="10.0.0.1"), r,
                                          allow_active=False, exclude=set())
    name = next(m.name for m in cands)
    monkeypatch.setattr(b, "_chat", lambda p: json.dumps(
        {"next_module": name, "rationale": "x", "confidence": 0.7, "done": False,
         "target": "8.8.8.8"}))  # scope dışı / bilinmeyen
    d = b.decide(r, ScanContext(target="10.0.0.1"), cands)
    assert d.target == ""  # reddedildi -> varsayılan hedef


def test_webshot_registered():
    assert "webshot" in {m.name for m in all_modules()}

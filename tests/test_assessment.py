"""Offline regression cases for coverage, auth selection and evidence quality."""

import json
from dataclasses import replace

import pytest

from adscan import cli
from adscan import report as reporting
from adscan.assessment import record_results
from adscan.findings import Finding, ScanReport, Severity
from adscan.modules import certipy_scan, nxc_scan
from adscan.registry import ScanContext, all_modules, plan_modules
from adscan.runner import CommandResult


def result(**kwargs):
    defaults = dict(tool="check", argv=["tool"], returncode=0,
                    stdout="checked", stderr="", duration=0)
    return CommandResult(**(defaults | kwargs))


@pytest.mark.parametrize("changes,status", [
    ({"returncode": 1}, "failed"),
    ({"timed_out": True}, "failed"),
    ({"stdout": "STATUS_ACCESS_DENIED"}, "access_denied"),
    ({"stdout": "[DRY-RUN] planned"}, "planned"),
    ({"stdout": ""}, "unknown"),
    ({"tool": "check:skip"}, "skipped"),
    ({"error_kind": "missing", "error": "missing"}, "failed"),
])
def test_incomplete_never_means_clean(changes, status):
    report = ScanReport("dc")
    record_results(report, "module", [result(**changes)])
    assert report.coverage[0]["status"] == status
    assert not report.assessment_complete
    assert report.risk_label() != "TEMİZ"


def test_nonzero_process_is_not_success():
    assert not result(returncode=1).ok
    assert not result(returncode=None).ok


def test_parser_failure_marks_even_successful_process_incomplete():
    report = ScanReport("dc")
    record_results(report, "module", [result()], parse_failed=True)
    assert not report.assessment_complete


def test_unauthenticated_plan_never_calls_auth_modules():
    report = ScanReport("dc")
    modules = [m for m in all_modules() if not m.active]
    chosen = plan_modules(modules, ScanContext("dc", full=True), report)
    assert chosen and not any(m.requires_creds for m in chosen)
    assert report.scan_mode == "unauthenticated"
    assert {c["control_id"] for c in report.coverage} >= {"certipy", "bloodhound"}


@pytest.mark.parametrize("auth", [{"password": "test"}, {"nthash": "a" * 32}])
def test_authenticated_plan_keeps_supported_auth_modules(auth):
    report = ScanReport("dc")
    chosen = plan_modules([m for m in all_modules() if not m.active],
                          ScanContext("dc", username="auditor", full=True, **auth), report)
    assert {m.name for m in chosen} >= {"certipy", "bloodhound", "bloodyad-enum"}
    assert report.scan_mode == "authenticated"


def test_unauthenticated_subchecks_never_invoke_credential_checks(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr("adscan.capabilities.nxc_has_module", lambda _: True)
    def fake_run(argv, **kwargs):
        calls.append(argv)
        return result(tool=kwargs["tool"], argv=argv)
    monkeypatch.setattr(nxc_scan, "run", fake_run)
    ldap = nxc_scan.ldap_scan("dc", outdir=str(tmp_path))
    vulns = nxc_scan.vuln_scan("dc")
    assert not any("--kerberoasting" in c for c in calls)
    assert not any(x in c for c in calls for x in ["maq", "pre2k", "nopac", "sccm"])
    assert any(r.tool == "nxc:ldap-kerberoast:skip" for r in ldap)
    assert any(r.tool == "nxc:maq:skip" for r in vulns)


@pytest.mark.parametrize("text", [
    "Certipy help: ESC1 ESC8 supported",
    "Template Name : User\n[!] Vulnerabilities\n  ESC1 : Not vulnerable",
    "Template Name : User\nESC1 : can enroll",
    "[!] Vulnerabilities\n  ESC1 : can enroll",  # object missing
])
def test_certipy_noise_is_not_a_finding(text):
    report = ScanReport("dc")
    certipy_scan.parse([result(stdout=text)], report)
    assert not report.findings


def test_certipy_keeps_objects_separate():
    report = ScanReport("dc")
    text = ("Certipy v5.0.3\nTemplate Name : A\n[!] Vulnerabilities\n  ESC1 : can enroll\n"
            "Template Name : B\n[!] Vulnerabilities\n  ESC4 : writable\n")
    certipy_scan.parse([result(stdout=text)], report)
    assert {f.object_id for f in report.findings} == {"Template Name:A", "Template Name:B"}
    assert {f.tool_version for f in report.findings} == {"5.0.3"}


def test_identical_findings_deduplicate_but_distinct_objects_remain():
    report = ScanReport("dc")
    finding = Finding("risk", Severity.HIGH, "dc", "x", evidence="proof", object_id="A")
    report.add(finding)
    report.add(replace(finding))
    report.add(replace(finding, object_id="B"))
    assert len(report.findings) == 2


def test_coverage_and_verification_export(tmp_path):
    report = ScanReport("dc")
    report.add(Finding("risk", Severity.HIGH, "dc", "x"))
    report.record_coverage("sample-control", "access_denied", "insufficient rights")
    for extension, writer in [("json", reporting.write_json), ("md", reporting.write_markdown),
                              ("html", reporting.write_html)]:
        path = tmp_path / ("report." + extension)
        writer(report, str(path))
        text = path.read_text(encoding="utf-8")
        assert "sample-control" in text and "access_denied" in text and "unverified" in text
    assert not json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))["assessment_complete"]


def test_scope_rejects_supernet_and_unlisted_subdomain(tmp_path):
    path = tmp_path / "scope.txt"
    path.write_text("10.0.0.0/24\ndc.example.test\n")
    assert not cli._in_scope("10.0.0.0/8", str(path))[0]
    assert cli._in_scope("10.0.0.128/25", str(path))[0]
    assert not cli._in_scope("other.dc.example.test", str(path))[0]


@pytest.mark.parametrize("credentials,expected", [
    ([], "unauthenticated"), (["-u", "auditor", "-p", "test"], "authenticated"),
    (["-u", "auditor", "-H", "a" * 32], "authenticated"),
])
def test_full_cli_selects_correct_plan_without_automatic_cracking(
        monkeypatch, tmp_path, credentials, expected):
    monkeypatch.delenv("ADSCAN_PASSWORD", raising=False)
    monkeypatch.setattr(cli, "tool_check", lambda: None)
    monkeypatch.setattr(cli, "_setup_clock", lambda *a: None)
    monkeypatch.setattr(cli, "_run_crack_phase", lambda *a: pytest.fail("implicit cracking"))
    captured = []
    def run_plan(modules, ctx, report, jobs):
        captured.extend(modules)
        for module in modules:
            report.record_coverage(module.name, "planned", "dry-run")
    monkeypatch.setattr(cli, "_run_modules_live", run_plan)
    assert cli.main(["192.0.2.1", "--full", "--dry-run", "--no-nxc-db",
                     "--keep-old-reports", "--outdir", str(tmp_path)] + credentials) == 0
    names = {m.name for m in captured}
    assert "nmap" in names and "nxc-smb" in names
    assert ("certipy" in names) == bool(credentials)
    assert ("bloodyad-enum" in names) == bool(credentials)
    reports = [json.loads(p.read_text(encoding="utf-8")) for p in tmp_path.glob("adscan-*.json")]
    data = next(d for d in reports if "schema_version" in d)
    assert data["scan_mode"] == expected
    assert not data["assessment_complete"]

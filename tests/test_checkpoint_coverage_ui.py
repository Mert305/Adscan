"""Offline regressions for interruption recovery and report navigation."""

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from adscan import runner
from adscan.assessment import record_results
from adscan.checkpoint import Checkpoint
from adscan.findings import Finding, ScanReport, Severity
from adscan.report import write_html


def success(argv, *, tool, **kwargs):
    return runner.CommandResult(tool, argv, 0, "checked", "", 0)


def test_restart_after_interruption_replays_only_completed_commands(tmp_path, monkeypatch):
    calls = []
    def interrupted(argv, **kwargs):
        calls.append(kwargs["tool"])
        if kwargs["tool"] == "second":
            raise KeyboardInterrupt
        return success(argv, **kwargs)
    monkeypatch.setattr(runner, "_run_once", interrupted)
    checkpoint = Checkpoint(tmp_path, "dc")
    with pytest.raises(KeyboardInterrupt), checkpoint.module("nxc-ldap"):
        first = runner.run(["fake", "--users"], tool="first")
        runner.run(["fake", "--groups"], tool="second")
    assert first.observed_at
    checkpoint = Checkpoint(tmp_path, "dc", resume=True)
    monkeypatch.setattr(runner, "_run_once", success)
    with checkpoint.module("nxc-ldap"):
        replay = runner.run(["fake", "--users"], tool="first")
        second = runner.run(["fake", "--groups"], tool="second")
    assert replay.resumed and not second.resumed
    assert replay.observed_at == first.observed_at
    report = ScanReport("dc")
    record_results(report, "nxc-ldap", [replay, second])
    assert report.coverage[0]["resumed"]


@pytest.mark.parametrize("changes", [
    {"stdout": "STATUS_ACCESS_DENIED"}, {"stdout": ""}, {"returncode": 1},
    {"timed_out": True}, {"stdout": "[DRY-RUN] planned"},
])
def test_incomplete_commands_are_never_reused(tmp_path, monkeypatch, changes):
    monkeypatch.setattr(runner, "_run_once", lambda argv, **kw: replace(success(argv, **kw), **changes))
    checkpoint = Checkpoint(tmp_path, "dc")
    with checkpoint.module("nxc-ldap"):
        runner.run(["fake"], tool="check", retries=0)
    assert not Checkpoint(tmp_path, "dc", resume=True).entries


def test_auth_change_dryrun_and_active_flows_do_not_replay(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "_run_once", success)
    checkpoint = Checkpoint(tmp_path, "dc")
    with checkpoint.module("nxc-ldap"):
        runner.run(["fake", "-p", "one"], tool="check")
        assert not runner.run(["fake", "-p", "two"], tool="check").resumed
        assert not runner.run(["fake", "-p", "one"], tool="check", dry_run=True).resumed
    with checkpoint.module("shadow"):
        assert not runner.run(["fake", "-p", "one"], tool="check").resumed
    data = json.loads(checkpoint.path.read_text(encoding="utf-8"))
    assert all(not e["result"]["argv"] for e in data["entries"].values())


def test_missing_artifact_and_parser_failure_force_execution(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "_run_once", success)
    artifact = tmp_path / "kerb.txt"
    artifact.write_text("hash")
    checkpoint = Checkpoint(tmp_path, "dc")
    argv = ["fake", "--kerberoasting", str(artifact)]
    with checkpoint.module("nxc-ldap"):
        runner.run(argv, tool="check")
        assert runner.run(argv, tool="check").resumed
        artifact.unlink()
        assert not runner.run(argv, tool="check").resumed
    checkpoint.invalidate("nxc-ldap")
    assert not Checkpoint(tmp_path, "dc", resume=True).entries


def test_stdout_xml_is_reusable(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "_run_once", success)
    checkpoint = Checkpoint(tmp_path, "dc")
    with checkpoint.module("nmap"):
        runner.run(["fake", "-oX", "-"], tool="nmap")
        assert runner.run(["fake", "-oX", "-"], tool="nmap").resumed


def test_parallel_workers_keep_module_identity_and_atomic_file(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "_run_once", success)
    checkpoint = Checkpoint(tmp_path, "dc")
    def execute(module):
        with checkpoint.module(module):
            for i in range(5):
                runner.run(["fake", str(i)], tool="check")
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(execute, ["nxc-smb", "nxc-ldap"]))
    loaded = Checkpoint(tmp_path, "dc", resume=True)
    assert len(loaded.entries) == 10
    assert {e["module"] for e in loaded.entries.values()} == {"nxc-smb", "nxc-ldap"}


def test_fresh_scan_does_not_reuse_previous_checkpoint(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "_run_once", success)
    checkpoint = Checkpoint(tmp_path, "dc")
    with checkpoint.module("nxc-ldap"):
        runner.run(["fake"], tool="check")
    assert not Checkpoint(tmp_path, "dc").entries


def test_module_pipeline_rebuilds_findings_without_rerunning_commands(tmp_path, monkeypatch):
    from adscan.cli import _run_modules_live
    from adscan.registry import ScanContext, ScanModule

    calls = []
    def execute(argv, **kwargs):
        calls.append(argv)
        return success(argv, **kwargs)
    monkeypatch.setattr(runner, "_run_once", execute)
    def collect(ctx):
        return [runner.run(["fake", ctx.target], tool="winrm-check")]
    def parse(results, report):
        report.add(Finding("Example", Severity.HIGH, report.target, "winrm",
                           evidence=results[0].stdout))
    module = ScanModule("winrm", "Example", collect, parse)
    reports = []
    for resume in (False, True):
        ctx = ScanContext("dc", checkpoint=Checkpoint(tmp_path, "dc", resume=resume))
        report = ScanReport("dc")
        _run_modules_live([module], ctx, report, jobs=1)
        reports.append(report)
    assert len(calls) == 1
    assert reports[0].findings[0].fingerprint == reports[1].findings[0].fingerprint
    assert reports[1].coverage[0]["resumed"]


def test_optional_port_discovery_does_not_make_completed_scan_incomplete():
    report = ScanReport("dc")
    record_results(report, "nmap", [success(["fake"], tool="nmap")])
    assert report.assessment_complete


def test_control_skips_are_stable_and_missing_checks_visible():
    report = ScanReport("dc")
    record_results(report, "nxc-ldap", [
        success(["fake"], tool="nxc:ldap-users"),
        runner.CommandResult("nxc:ldap-kerberoast:skip", [], None, "", "", 0, error="Kimlik gerekli")])
    coverage = {c["control_id"]: c for c in report.coverage}
    assert coverage["nxc:ldap-kerberoast"]["reason"] == "Kimlik gerekli"
    assert coverage["nxc:ldap-users"]["status"] == "completed"
    assert coverage["nxc:ldap-gmsa"]["status"] == "skipped"
    assert coverage["nxc-ldap"]["level"] == "module"


def test_html_filters_links_and_untrusted_content(tmp_path):
    report = ScanReport('dc"<x>')
    finding = Finding('<script>alert(1)</script>', Severity.HIGH, report.target,
                      'ldap"<x>', evidence="proof <unsafe>", remediation="Restrict access")
    report.add(finding)
    report.record_coverage("users", "access_denied", "insufficient rights", module="ldap")
    path = tmp_path / "report.html"
    write_html(report, str(path))
    html = path.read_text(encoding="utf-8")
    for name in ["search", "severity", "target", "verification", "module", "view", "status"]:
        assert f'id="{name}"' in html
    assert f'href="#evidence-{finding.fingerprint}"' in html
    assert f'id="evidence-{finding.fingerprint}"' in html
    assert '<script>alert(1)</script>' not in html
    assert 'data-target="dc&quot;&lt;x&gt;"' in html
    assert "Restrict access" in html and "access_denied" in html

import os
from io import StringIO

from adscan import cli, config, live, report, runner
from adscan.findings import Finding, ScanReport, Severity
from adscan.terminal import cells, clean, fit, table, wrap


def test_cell_width_and_wrapping():
    assert cells("界e\u0301") == 3
    assert cells(fit("界abc", 3)) == 3
    assert all(cells(line) <= 12 for line in wrap("çokuzunhedef.example 界界 uzun kanıt", 12))
    assert clean("\x1b]0;untrusted\x07test\x1b[31m") == "test"


def test_responsive_panel_and_boxes(monkeypatch):
    ui = live.Live(4, enabled=False)
    ui.register_modules(["ldap", "smb"])
    ui.set_running("ldap")
    ui.set_detail("界" * 100)
    for columns, height in [(110, 8), (60, 3), (30, 1)]:
        monkeypatch.setattr(live.shutil, "get_terminal_size", lambda *_, columns=columns: os.terminal_size((columns, 24)))
        lines = ui._compose()
        assert len(lines) <= height
        assert all(cells(line) < columns for line in lines)
        box = report._box("Uzun başlık " * 10, ["界" * 100], color=False)
        assert all(cells(line) < columns for line in box.splitlines())


def test_control_observation_replaced_by_final_parser_status():
    ui = live.Live(1, enabled=False)
    ui.observe_control(dict(module="", control_id="ldap-users", status="completed", resumed=True))
    r = ScanReport(target="lab")
    r.record_coverage("ldap-users", "failed", module="ldap", resumed=True)
    ui.set_coverage(r.coverage)
    assert "tamam 0" in ui._coverage_str()
    assert "hata 1" in ui._coverage_str()
    assert "checkpoint 1" in ui._coverage_str()


def test_preview_never_runs_tools_and_plain_has_no_escapes(monkeypatch, capsys):
    monkeypatch.setattr(runner, "run", lambda *_a, **_kw: (_ for _ in ()).throw(AssertionError("network")))
    monkeypatch.setattr(config, "TERMINAL_UI", "compact")
    assert cli.main(["--terminal-preview", "--terminal-ui", "plain"]) == 0
    output = capsys.readouterr().out
    assert "\x1b" not in output
    assert "ÖRNEK VERİ" in output and "Checkpoint" in output and "erişim yetersiz" in output


def test_plain_and_cursor_lifecycle(monkeypatch):
    class TTY(StringIO):
        def isatty(self):
            return True
    stdout = TTY()
    monkeypatch.setattr(live.sys, "stdout", stdout)
    monkeypatch.setattr(config, "TERMINAL_UI", "plain")
    ui = live.Live(1).start()
    ui.log("\x1b[31mhello\x1b[0m")
    ui.stop()
    assert stdout.getvalue() == "hello\n"
    monkeypatch.setattr(config, "TERMINAL_UI", "compact")
    ui = live.Live(1).start()
    ui.stop()
    assert "\x1b[?25l" in stdout.getvalue() and stdout.getvalue().endswith("\x1b[?25h")


def test_compact_finding_preserves_title_and_limits_evidence(monkeypatch):
    monkeypatch.setattr(config, "TERMINAL_UI", "compact")
    finding = Finding(title="A very long finding title " * 4, severity=Severity.HIGH,
                      target="lab", source="ldap", evidence="evidence " * 100)
    output = report.render_finding(finding, color=False)
    assert "A very long finding title" in output
    assert len(output) < 1400
    monkeypatch.setattr(config, "TERMINAL_UI", "detailed")
    assert len(report.render_finding(finding, color=False)) > len(output)


def test_table_falls_back_on_narrow_terminal():
    rendered = table(["Modül", "Erişim yok", "Checkpoint"], [("ldap", "2", "3")], max_width=18)
    assert all(cells(line) <= 18 for line in rendered.splitlines())


def test_runner_emits_control_without_stdout(monkeypatch):
    events = []
    monkeypatch.setattr(runner.progress, "emit", lambda *args: events.append(args))
    result = runner.CommandResult("ldap", [], 0, "private evidence", "", 0.1)
    runner._notify_control(result, None)
    assert events[0][0] == "control"
    assert '"status": "completed"' in events[0][2]
    assert "private evidence" not in events[0][2]

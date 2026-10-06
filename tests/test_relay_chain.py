"""relay_scan plan/parse + chain motoru testleri."""

from conftest import cr, severity_of, titles

from adscan import chain as chaining
from adscan.findings import Severity
from adscan.modules import relay_scan
from adscan.registry import ScanContext


def test_relay_plan_default_no_launch(report):
    ctx = ScanContext(target="10.0.0.1", domain="corp.local",
                      active_attacks=True, launch=False)
    results = relay_scan._run(ctx)
    relay_scan.parse(results, report)
    assert any(r.tool == "relay:plan" for r in results)
    assert severity_of(report, "zinciri planı") == Severity.INFO


def test_build_plan_includes_esc8_and_relay():
    ctx = ScanContext(target="dc.corp", domain="corp.local",
                      adcs_ca_url="http://ca/certsrv/certfnsh.asp")
    labels = " ".join(label for label, _ in relay_scan.build_plan(ctx))
    assert "ESC8" in labels
    assert "relay" in labels.lower()
    assert "mitm6" in labels.lower()


def test_launch_requires_trigger(report):
    # Tetikleyici yok: ne interface (poisoning) ne listener-ip (coercion) -> hata
    ctx = ScanContext(target="10.0.0.1", domain="corp.local",
                      active_attacks=True, launch=True, interface=None, listener_ip=None)
    results = relay_scan._run(ctx)
    assert any(r.error and ("listener" in r.error.lower() or "iface" in r.error.lower())
               for r in results)


def test_build_plan_includes_coercion_step():
    ctx = ScanContext(target="10.0.0.1", domain="corp.local",
                      listener_ip="10.0.0.99",
                      adcs_ca_url="http://ca/certsrv/certfnsh.asp")
    labels = " ".join(label for label, _ in relay_scan.build_plan(ctx)).lower()
    assert "coerce" in labels or "zorla" in labels
    # coercion komutu LISTENER ve METHOD içermeli
    cmds = [" ".join(argv) for _l, argv in relay_scan.build_plan(ctx)]
    assert any("coerce_plus" in c and "LISTENER=10.0.0.99" in c for c in cmds)


def test_coerce_argv_builds_listener_and_creds():
    ctx = ScanContext(target="10.0.0.1", domain="corp.local",
                      username="svc", password="Pw!", listener_ip="10.0.0.99")
    argv = relay_scan._coerce_argv(ctx, "10.0.0.1", "10.0.0.99")
    assert "coerce_plus" in argv
    assert "LISTENER=10.0.0.99" in argv and "METHOD=All" in argv
    assert argv[argv.index("-u") + 1] == "svc"
    assert argv[argv.index("-d") + 1] == "corp.local"


def test_relay_parse_coercion_triggered(report):
    out = ("SMB  10.0.0.1  445  DC01  [+] Printerbug  Success!\n"
           "SMB  10.0.0.1  445  DC01  [+] DFSCoerce  authenticated to listener")
    relay_scan.parse([cr(out, tool="relay:coerce")], report)
    f = next((f for f in report.findings if "Coercion TETİKLENDİ" in f.title), None)
    assert f is not None and f.severity == Severity.CRITICAL
    assert "printerbug" in f.title.lower()


def test_relay_parse_esc8_capture(report):
    out = "[*] GOT CERTIFICATE! Base64 certificate of user DC01$"
    relay_scan.parse([cr(out)], report)
    assert severity_of(report, "ESC8") == Severity.CRITICAL


def test_relay_parse_relay_success(report):
    out = "[*] Authenticating against ldaps://dc as CORP/ADMIN SUCCEED"
    relay_scan.parse([cr(out)], report)
    assert severity_of(report, "relay BAŞARILI") == Severity.CRITICAL


# --- chain motoru ---

def test_chain_all_steps_present(report):
    rows = chaining.evaluate(report)
    keys = {step.key for step, _ in rows}
    assert keys == {"poison", "enum", "cred", "reuse", "secrets", "adcs", "da"}


def test_chain_detects_progress():
    from adscan.findings import Finding, ScanReport
    r = ScanReport(target="t")
    r.add(Finding(title="Zayıf parolalarla 5 hesap doğrulandı",
                  severity=Severity.HIGH, target="t", source="spray"))
    r.add(Finding(title="ADCS ESC8 — DC sertifikası elde edildi",
                  severity=Severity.CRITICAL, target="t", source="relay",
                  reference="ADCS ESC8"))
    rows = dict((s.key, ok) for s, ok in chaining.evaluate(r))
    assert rows["cred"] is True
    assert rows["adcs"] is True
    assert rows["da"] is False


def test_chain_format_shows_marks(report):
    text = chaining.format_chain(report)
    assert "SALDIRI YOLU" in text
    assert "sonraki:" in text  # elde edilmemiş adımlar ipucu gösterir


def test_chain_count_zero_when_empty(report):
    # Boş raporda hiçbir adım elde edilmemiş olmalı (0/7)
    assert "0/7 adım" in chaining.format_chain(report)

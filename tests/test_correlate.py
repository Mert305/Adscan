"""correlate — tiering ihlali (DA, DC-olmayan host'ta aktif)."""

from adscan import correlate
from adscan.findings import ScanReport, Severity


def _report():
    r = ScanReport(target="10.0.0.1")
    r.dc_name = "DC01"
    r.da_members = ["Administrator", "da_bob"]
    return r


def test_tiering_violation_on_workstation_is_critical():
    r = _report()
    r.sessions = {"WS01": ["da_bob", "alice"], "DC01": ["Administrator"]}
    f = correlate.correlate_tiering(r)
    assert f is not None and f.severity == Severity.CRITICAL
    assert "da_bob @ WS01" in f.evidence
    assert "Administrator" not in f.evidence  # DC'deki DA oturumu ihlal değil


def test_no_violation_when_da_only_on_dc():
    r = _report()
    r.sessions = {"DC01": ["Administrator", "da_bob"]}
    assert correlate.correlate_tiering(r) is None


def test_no_violation_without_da_or_sessions():
    r = _report()
    r.sessions = {}
    assert correlate.correlate_tiering(r) is None

"""remediation_plan — "önce bunu yap" önceliklendirme (D)."""

from adscan.findings import Finding, ScanReport, Severity


def _f(title, sev, rem, ref="", target="10.0.0.1"):
    return Finding(title=title, severity=sev, target=target, source="t",
                   remediation=rem, reference=ref)


def test_plan_groups_by_remediation_and_orders():
    r = ScanReport(target="10.0.0.1")
    r.add(_f("SMBv1 A", Severity.HIGH, "SMBv1'i devre dışı bırakın", "MS17-010", "hostA"))
    r.add(_f("SMBv1 B", Severity.HIGH, "SMBv1'i devre dışı bırakın", "SMBv1", "hostB"))
    r.add(_f("Zerologon", Severity.CRITICAL, "Yamaları uygulayın", "CVE-2020-1472"))
    r.add(_f("Zayıf politika", Severity.MEDIUM, "Parola politikasını güçlendirin"))
    plan = r.remediation_plan()
    # CRITICAL önce
    assert plan[0]["severity"] == "CRITICAL"
    # Aynı çözüm tek grupta, iki bulguyu kapsıyor
    smbv1 = next(p for p in plan if "SMBv1" in p["action"])
    assert smbv1["count"] == 2
    assert set(smbv1["targets"]) == {"hostA", "hostB"}
    assert set(smbv1["references"]) == {"MS17-010", "SMBv1"}


def test_plan_skips_info_and_empty_remediation():
    r = ScanReport(target="10.0.0.1")
    r.add(_f("Bilgi", Severity.INFO, "önemsiz"))          # INFO -> atlanır
    r.add(_f("Çözümsüz", Severity.HIGH, ""))              # remediation yok -> atlanır
    r.add(_f("Gerçek", Severity.HIGH, "Bir şey yapın"))
    plan = r.remediation_plan()
    assert len(plan) == 1
    assert plan[0]["action"] == "Bir şey yapın"


def test_plan_in_to_dict():
    r = ScanReport(target="10.0.0.1")
    r.add(_f("Zerologon", Severity.CRITICAL, "Yamaları uygulayın"))
    d = r.to_dict()
    assert "remediation_plan" in d
    assert d["remediation_plan"][0]["action"] == "Yamaları uygulayın"


def test_plan_tiebreak_by_count():
    r = ScanReport(target="10.0.0.1")
    r.add(_f("tek", Severity.HIGH, "X çözümü"))
    r.add(_f("çok1", Severity.HIGH, "Y çözümü"))
    r.add(_f("çok2", Severity.HIGH, "Y çözümü"))
    plan = r.remediation_plan()
    # Aynı seviyede daha çok bulgu kapsayan önce
    assert plan[0]["action"] == "Y çözümü"
    assert plan[0]["count"] == 2

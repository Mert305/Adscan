"""v0.3 geliştirmeleri: UI dashboard, risk skoru, teslimat çıktıları,
saldırı grafiği, sıradaki-eylem ve yeni nxc kapsama parser'ları."""

import json

from conftest import cr

from adscan import chain, cli, export, live
from adscan import report as reporting
from adscan.findings import Credential, Finding, ScanReport, Severity
from adscan.modules import nxc_scan


# --------------------------------------------------------------------------- UI
def test_fit_truncates_visible_length_keeping_ansi():
    s = "\033[1mhello world\033[0m"
    out = live._fit(s, 5)
    assert "hello" in out and "world" not in out
    assert out.endswith("\033[0m")  # kırpınca reset eklenir


def test_fit_short_string_untouched():
    assert live._fit("abc", 10) == "abc"


def test_live_non_tty_fallback_is_plain(capsys):
    ui = live.Live(total=3, enabled=False).start()
    ui.set_running("nmap")
    ui.set_stats(CRITICAL=2, creds=1, da=True)
    ui.advance()
    ui.log("satir")
    ui.stop()
    out = capsys.readouterr().out
    assert "satir" in out
    assert "\033[" not in out  # panel/renk yok


def test_live_set_stats_accepts_upper_and_lower_keys():
    ui = live.Live(total=1, enabled=False)
    ui.set_stats(CRITICAL=3, creds=2, da=True, chain_done=4, chain_total=7)
    assert ui._stats["CRITICAL"] == 3
    assert ui._stats["creds"] == 2 and ui._stats["da"] is True
    assert ui._stats["chain_done"] == 4 and ui._stats["chain_total"] == 7


# ----------------------------------------------------------------------- risk skoru
def test_risk_score_domain_admin_is_100():
    r = ScanReport(target="t")
    r.domain_admin = True
    assert r.risk_score() == 100 and r.risk_label() == "KRİTİK"


def test_risk_score_weighted_and_capped():
    r = ScanReport(target="t")
    r.add(Finding(title="a", severity=Severity.CRITICAL, target="t", source="x"))
    r.add(Finding(title="b", severity=Severity.HIGH, target="t", source="x"))
    assert r.risk_score() == 55  # 40 + 15
    for _ in range(10):
        r.add(Finding(title="c", severity=Severity.CRITICAL, target="t", source="x"))
    assert r.risk_score() == 100  # 100'de kırpılır


def test_risk_label_thresholds():
    r = ScanReport(target="t")
    assert r.risk_label() == "TEMİZ"
    r.add(Finding(title="l", severity=Severity.LOW, target="t", source="x"))
    assert r.risk_label() == "DÜŞÜK"


def test_top_findings_sorted_desc():
    r = ScanReport(target="t")
    r.add(Finding(title="low", severity=Severity.LOW, target="t", source="x"))
    r.add(Finding(title="crit", severity=Severity.CRITICAL, target="t", source="x"))
    tops = r.top_findings(1)
    assert len(tops) == 1 and tops[0].title == "crit"


def test_report_to_dict_has_risk_fields():
    r = ScanReport(target="t")
    r.add(Finding(title="a", severity=Severity.HIGH, target="t", source="x"))
    d = r.to_dict()
    assert d["risk_score"] == 15 and d["risk_label"] == "DÜŞÜK"


# ------------------------------------------------------------------- teslimat çıktıları
def _demo_report(tmp_path):
    r = ScanReport(target="10.0.0.1", domain="corp.local", dc_name="DC01",
                   outdir=str(tmp_path))
    r.add(Finding(title="Kerberoasting", severity=Severity.HIGH, target="t",
                  source="nxc-ldap", mitre="T1558.003"))
    r.add(Finding(title="SMB signing kapalı", severity=Severity.MEDIUM, target="t",
                  source="nmap", mitre="T1557.001"))
    r.add_credential(Credential(username="alice", secret="Pw1", domain="corp.local",
                                admin=True, source="spray"))
    return r


def test_navigator_layer_valid(tmp_path):
    r = _demo_report(tmp_path)
    p = str(tmp_path / "n.json")
    export.write_navigator_layer(r, p)
    data = json.load(open(p, encoding="utf-8"))
    ids = {t["techniqueID"] for t in data["techniques"]}
    assert "T1558.003" in ids and "T1557.001" in ids
    assert data["domain"] == "enterprise-attack"
    assert all("score" in t and "color" in t for t in data["techniques"])


def test_loot_manifest_lists_creds_and_admin(tmp_path):
    r = _demo_report(tmp_path)
    p = str(tmp_path / "l.json")
    export.write_loot_manifest(r, p)
    data = json.load(open(p, encoding="utf-8"))
    assert data["credentials"][0]["username"] == "alice"
    assert len(data["admin_credentials"]) == 1
    assert data["domain"] == "corp.local"


def test_csv_has_header_and_rows(tmp_path):
    r = _demo_report(tmp_path)
    p = str(tmp_path / "f.csv")
    export.write_csv(r, p)
    lines = open(p, encoding="utf-8").read().splitlines()
    assert lines[0].startswith("severity,title")
    assert any("Kerberoasting" in ln for ln in lines[1:])


def test_attack_graph_nodes_and_edges(tmp_path):
    r = _demo_report(tmp_path)
    r.credentials[0].host = "10.0.0.5"
    r.domain_admin = True
    p = str(tmp_path / "g.json")
    export.write_attack_graph(r, p)
    data = json.load(open(p, encoding="utf-8"))
    types = {n["type"] for n in data["nodes"]}
    assert "attacker" in types and "credential" in types and "domain_admin" in types
    assert any(e["type"] == "escalation" for e in data["edges"])
    assert any(s["achieved"] for s in data["chain"])


# ----------------------------------------------------------------- sıradaki eylem
def test_next_action_returns_first_unachieved():
    r = ScanReport(target="t")
    na = chain.next_action(r)
    assert na is not None and na[0].key == "poison"


def test_next_action_none_when_domain_admin():
    r = ScanReport(target="t")
    r.domain_admin = True
    assert chain.next_action(r) is None


def test_format_chain_shows_next_best_action():
    r = ScanReport(target="t")
    txt = chain.format_chain(r, color=False)
    assert "SIRADAKİ EN İYİ EYLEM" in txt


# -------------------------------------------------------- yeni nxc kapsama parser'ları
def test_constrained_delegation_detected():
    r = ScanReport(target="10.0.0.1")
    text = ("LDAP 10.0.0.1 389 DC01 websvc$ Computer Constrained cifs/sql01\n"
            "LDAP 10.0.0.1 389 DC01 ws05$ Computer Unconstrained N/A")
    nxc_scan._parse_delegation_adcs(text, r)
    titles = [f.title for f in r.findings]
    assert any("Constrained delegation" in t for t in titles)
    # unconstrained ayrı bulguda; burada constrained olarak SAYILMAMALI
    assert not any("RBCD" in t for t in titles)


def test_rbcd_delegation_detected():
    r = ScanReport(target="10.0.0.1")
    text = "LDAP 10.0.0.1 389 DC01 app01$ Computer Resource-Based Constrained srv2$"
    nxc_scan._parse_delegation_adcs(text, r)
    assert any("RBCD" in f.title for f in r.findings)


def test_adcs_ca_discovery_detected():
    r = ScanReport(target="10.0.0.1")
    text = "ADCS 10.0.0.1 389 DC01 Found PKI Enrollment Server: ca01.corp.local"
    nxc_scan._parse_delegation_adcs(text, r)
    adcs = [f for f in r.findings if "ADCS" in f.title]
    assert adcs and adcs[0].mitre == "T1649"


def test_pre2k_detected():
    r = ScanReport(target="10.0.0.1")
    out = "LDAP 10.0.0.1 389 DC01 [+] pre2k GOT TGT for ws01$ (pre-created account)"
    nxc_scan.parse_vuln([cr(out, tool="nxc:pre2k")], r)
    assert any("Pre-Windows 2000" in f.title for f in r.findings)


def test_delegation_lines_excludes_unconstrained():
    text = ("x Constrained cifs/a\n"
            "y Unconstrained N/A\n"
            "z Resource-Based Constrained b$")
    assert "Unconstrained" not in nxc_scan._delegation_lines(text, "constrained")
    assert "Resource-Based" in nxc_scan._delegation_lines(text, "rbcd")


# ---------------------------------------------------------------------- CLI --full
def test_parser_has_full_and_version():
    p = cli.build_parser()
    ns = p.parse_args(["10.0.0.1", "--full"])
    assert ns.full is True


def test_prune_keeps_all_current_scan_deliverables(tmp_path):
    # Bu taramanın tüm çıktıları (aynı zaman damgası) korunmalı; eskiler silinmeli
    base = str(tmp_path / "adscan-10.0.0.5-20260102-000000")
    for ext in (".json", ".md", ".html", ".navigator.json", ".loot.json",
                ".graph.json", ".findings.csv"):
        (tmp_path / f"adscan-10.0.0.5-20260102-000000{ext}").write_text("{}")
    (tmp_path / "adscan-10.0.0.5-20260101-000000.navigator.json").write_text("{}")
    removed = cli._prune_old_reports(str(tmp_path), "10.0.0.5", base)
    names = {__import__("os").path.basename(p) for p in removed}
    assert "adscan-10.0.0.5-20260101-000000.navigator.json" in names  # eski silinir
    for ext in (".navigator.json", ".loot.json", ".graph.json", ".findings.csv"):
        assert (tmp_path / f"adscan-10.0.0.5-20260102-000000{ext}").exists()


def test_risk_banner_renders():
    r = _demo_report_min()
    out = reporting._risk_banner(r, color=False)
    assert "YÖNETİCİ ÖZETİ" in out and "RİSK" in out


def _demo_report_min():
    r = ScanReport(target="t")
    r.add(Finding(title="x", severity=Severity.HIGH, target="t", source="nmap"))
    return r

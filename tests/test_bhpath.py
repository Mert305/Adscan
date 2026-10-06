"""BloodHound çevrimdışı yol analizi (bhpath) testleri — sentetik grafikle."""

import json
import os
import zipfile

from adscan import bhpath
from adscan.findings import Credential, ScanReport

ALICE = "S-1-5-21-1-1-1-1105"
SVC = "S-1-5-21-1-1-1-1106"
DA = "S-1-5-21-1-1-1-512"
DOM = "S-1-5-21-1-1-1"


def _write_bh(tmp_path, blobs):
    bh = tmp_path / "loot" / "bloodhound"
    bh.mkdir(parents=True)
    with zipfile.ZipFile(bh / "bh.zip", "w") as z:
        for name, blob in blobs.items():
            z.writestr(name, json.dumps(blob))


def test_bhpath_multihop_to_domain_admins(tmp_path):
    _write_bh(tmp_path, {
        "users.json": {"meta": {"type": "users"}, "data": [
            {"ObjectIdentifier": ALICE, "Properties": {"name": "ALICE@CORP.LOCAL"}, "Aces": []},
            {"ObjectIdentifier": SVC, "Properties": {"name": "SVC@CORP.LOCAL"},
             "Aces": [{"PrincipalSID": ALICE, "RightName": "GenericAll"}]},
        ]},
        "groups.json": {"meta": {"type": "groups"}, "data": [
            {"ObjectIdentifier": DA, "Properties": {"name": "DOMAIN ADMINS@CORP.LOCAL",
             "highvalue": True}, "Members": [{"ObjectIdentifier": SVC, "ObjectType": "User"}]},
        ]},
    })
    r = ScanReport(target="10.0.0.1", domain="corp.local", outdir=str(tmp_path))
    r.add_credential(Credential(username="alice", secret="Pw1", domain="corp.local"))
    path = bhpath.analyze(r)
    assert path is not None and len(path) == 2
    # En kısa-yol bulgusu (first-degree bulgusundan ayrı): referansla seç
    f = next(f for f in r.findings
             if f.source == "bhpath" and "shortest-path" in f.reference)
    assert "GenericAll" in f.evidence and "MemberOf" in f.evidence
    assert "DOMAIN ADMINS" in f.evidence


def test_bhpath_dcsync_edge(tmp_path):
    _write_bh(tmp_path, {
        "users.json": {"meta": {"type": "users"}, "data": [
            {"ObjectIdentifier": ALICE, "Properties": {"name": "ALICE@CORP.LOCAL"}}]},
        "domains.json": {"meta": {"type": "domains"}, "data": [
            {"ObjectIdentifier": DOM, "Properties": {"name": "CORP.LOCAL"},
             "Aces": [{"PrincipalSID": ALICE, "RightName": "GetChangesAll"}]}]},
    })
    r = ScanReport(target="10.0.0.1", domain="corp.local", outdir=str(tmp_path))
    r.add_credential(Credential(username="alice", secret="Pw1"))
    path = bhpath.analyze(r)
    assert path is not None
    # DCSync kenarı hem persistence hem yol bulgusunda görünebilir; birinde yeterli
    assert any("GetChangesAll" in f.evidence or "DCSync" in f.evidence
               for f in r.findings if f.source == "bhpath")


def test_bhpath_no_data_is_silent(tmp_path):
    r = ScanReport(target="10.0.0.1", outdir=str(tmp_path))
    r.add_credential(Credential(username="alice", secret="Pw1"))
    assert bhpath.analyze(r) is None
    assert r.findings == []


def test_bhpath_idempotent(tmp_path):
    _write_bh(tmp_path, {
        "users.json": {"meta": {"type": "users"}, "data": [
            {"ObjectIdentifier": ALICE, "Properties": {"name": "ALICE@CORP.LOCAL"}}]},
        "domains.json": {"meta": {"type": "domains"}, "data": [
            {"ObjectIdentifier": DOM, "Properties": {"name": "CORP.LOCAL"},
             "Aces": [{"PrincipalSID": ALICE, "RightName": "GetChangesAll"}]}]},
    })
    r = ScanReport(target="10.0.0.1", domain="corp.local", outdir=str(tmp_path))
    r.add_credential(Credential(username="alice", secret="Pw1"))
    bhpath.analyze(r)
    n = sum(1 for f in r.findings if f.source == "bhpath")
    bhpath.analyze(r)  # ikinci çağrı yeni bulgu EKLEMEMELİ (idempotent)
    assert n >= 1
    assert sum(1 for f in r.findings if f.source == "bhpath") == n


def test_bhpath_graph_export_integration(tmp_path):
    # export.write_attack_graph bhpath bulgusundan bağımsız çalışmalı
    from adscan import export
    r = ScanReport(target="10.0.0.1", domain="corp.local", outdir=str(tmp_path))
    r.add_credential(Credential(username="alice", secret="Pw1", domain="corp.local"))
    p = str(tmp_path / "g.json")
    export.write_attack_graph(r, p)
    data = json.load(open(p, encoding="utf-8"))
    assert data["target"] == "10.0.0.1" and "nodes" in data

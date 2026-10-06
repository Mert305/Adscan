"""Regression cases for identity matrices and conservative ordered AD access checks."""

import copy
import json

import pytest

from adscan import cli
from adscan.comparison import compare
from adscan.findings import ScanReport
from adscan.permissions import analyze_snapshot, evaluate, mask, token_for

USER = "S-1-5-21-1-2-3-1100"
GROUP = "S-1-5-21-1-2-3-2100"
PARENT = "S-1-5-21-1-2-3-2101"
GUID = "bf9679c0-0de6-11d0-a285-00aa003049e2"
OTHER_GUID = "bf9679c1-0de6-11d0-a285-00aa003049e2"


def principal(**kwargs):
    return {"sid": USER, "name": "LAB\\auditor", "token_complete": True, "groups": [GROUP], **kwargs}


def ace(kind="allow", trustee=GROUP, rights="write_dacl", **kwargs):
    return {"type": kind, "trustee_sid": trustee, "mask": [rights], **kwargs}


def access(aces, *, identity=None, rights="write_dacl", obj_changes=None, check_changes=None, groups=None):
    obj = {"id": "target", "dacl": aces, "dacl_complete": True,
           "owner_sid": "S-1-5-21-1-2-3-500", **(obj_changes or {})}
    check = {"rights": [rights], **(check_changes or {})}
    return evaluate(identity or principal(), obj, check, groups or [])


def test_nested_groups_cycles_and_explanatory_path():
    groups = [{"sid": GROUP, "name": "Helpdesk", "members": [USER, PARENT]},
              {"sid": PARENT, "name": "Delegated admins", "members": [GROUP]}]
    result = access([ace(trustee=PARENT)], groups=groups)
    assert result["decision"] == "granted"
    assert result["trace"][0]["path"] == [USER, GROUP, PARENT]
    assert result["trace"][0]["path_labels"] == ["LAB\\auditor", "Helpdesk", "Delegated admins"]


@pytest.mark.parametrize("aces,decision", [
    ([ace("deny", USER), ace()], "denied"),
    ([ace(), ace("deny", USER)], "granted"),  # preserve actual, noncanonical order
    ([ace(inherit_only=True)], "denied"),
    ([ace(inherited=True)], "granted"),
    ([], "denied"),
    ([ace(conditional=True)], "unknown"),
    ([ace("unsupported", "*", "generic_all")], "unknown"),
])
def test_order_inheritance_and_unsupported_aces(aces, decision):
    assert access(aces)["decision"] == decision


def test_deny_only_sid_can_deny_but_never_grant():
    identity = principal(deny_only_sids=[GROUP])
    assert access([ace()], identity=identity)["decision"] == "denied"
    assert access([ace("deny"), ace(trustee=USER)], identity=identity)["decision"] == "denied"
    assert access([ace()], identity=principal(disabled_sids=[GROUP]))["decision"] == "denied"


def test_deny_only_membership_does_not_grant_parent_group_rights():
    allow, deny = token_for(principal(deny_only_sids=[GROUP]), [{"sid": PARENT, "members": [GROUP]}])
    assert PARENT not in allow and PARENT in deny


def test_primary_group_and_authenticated_users():
    assert access([ace(trustee=PARENT)], identity=principal(groups=[], primary_group_sid=PARENT))["decision"] == "granted"
    assert access([ace(trustee="S-1-5-11")], identity=principal(authenticated=True))["decision"] == "granted"


@pytest.mark.parametrize("changes", [
    {"token_complete": False}, {"restricted_token": True}, {"privileges": ["SeTakeOwnershipPrivilege"]},
    {"sid_history": [PARENT]},
])
def test_incomplete_or_unsupported_token_is_unknown(changes):
    assert access([ace()], identity=principal(**changes))["decision"] == "unknown"


def test_explicitly_enabled_sid_history():
    assert access([ace(trustee=PARENT)], identity=principal(
        groups=[], sid_history=[PARENT], sid_history_enabled=True))["decision"] == "granted"


def test_incomplete_dacl_missing_null_and_empty_are_distinct():
    assert access([ace()], obj_changes={"dacl_complete": False})["decision"] == "unknown"
    assert access(None)["decision"] == "unknown"
    assert access(None, obj_changes={"null_dacl": True})["decision"] == "granted"
    assert access([])["decision"] == "denied"


def test_owner_implicit_rights_and_owner_rights_sid_override():
    assert access([], obj_changes={"owner_sid": USER})["decision"] == "granted"
    assert access([ace("deny", "S-1-3-4")], obj_changes={"owner_sid": USER})["decision"] == "denied"
    assert access([], obj_changes={"owner_sid": GROUP})["decision"] == "denied"


def test_missing_owner_does_not_produce_a_false_denial_of_implicit_owner_rights():
    assert access([], obj_changes={"owner_sid": ""})["decision"] == "unknown"
    assert access([ace()], obj_changes={"owner_sid": ""})["decision"] == "granted"
    assert access([ace("deny")], obj_changes={"owner_sid": ""})["decision"] == "unknown"
    assert access([], rights="write_owner", obj_changes={"owner_sid": ""})["decision"] == "denied"


def test_principal_self_maps_to_object_sid_not_owner():
    assert access([ace(trustee="S-1-5-10")], obj_changes={"object_sid": USER})["decision"] == "granted"
    assert access([ace(trustee="S-1-5-10")], obj_changes={"owner_sid": USER}, rights="write_owner")["decision"] == "denied"


def test_scoped_rights_require_schema_and_match_property_sets():
    scoped = [ace(rights="write_property", object_type_guid=GUID)]
    check = {"object_type_guid": GUID, "schema_complete": True}
    assert access(scoped, rights="write_property", check_changes=check)["decision"] == "granted"
    assert access(scoped, rights="write_property")["decision"] == "unknown"
    assert access(scoped, rights="write_property", check_changes={"object_type_guid": GUID})["decision"] == "unknown"
    assert access(scoped, rights="write_property", check_changes={**check, "object_type_guid": OTHER_GUID})["decision"] == "denied"
    assert access(scoped, rights="write_property", check_changes={**check,
        "object_type_guid": OTHER_GUID, "property_set_guids": [GUID]})["decision"] == "granted"


def test_standard_rights_are_not_filtered_by_property_guid():
    assert access([ace(object_type_guid=GUID)])["decision"] == "granted"


def test_generic_mapping_and_rights_split_across_aces():
    assert mask("generic_write") == 0x20028
    assert mask("generic_all") == 0xF01FF
    assert access([ace(rights="write_dacl"), ace(rights="write_owner")],
                  check_changes={"rights": ["write_dacl", "write_owner"]})["decision"] == "granted"
    with pytest.raises(ValueError):
        mask("typo")


def report_data(label, status, *, cid="ldap-users"):
    report = ScanReport("dc.lab", scan_mode="authenticated")
    report.execution_context = {"id": label, "label": label, "principal": label, "auth_type": "password"}
    report.record_coverage(cid, status, module="ldap")
    return report.to_dict()


def test_identity_matrix_differentiates_missing_and_denied_and_contains_no_secrets():
    standard = report_data("Standard", "access_denied")
    auditor = report_data("Auditor", "completed")
    standard["credentials"] = [{"secret": "sensitive-do-not-copy"}]
    comparison = compare([(standard, "standard.json"), (auditor, "auditor.json"),
                          (report_data("Other", "completed", cid="other"), "other.json")])
    row = next(r for r in comparison["controls"] if r["control_id"] == "ldap-users")
    assert [c["status"] for c in row["cells"]] == ["access_denied", "completed", "not_tested"]
    assert comparison["access_differences"] == 1
    assert "sensitive-do-not-copy" not in json.dumps(comparison)


def test_legacy_identity_not_inferred_from_loot_credentials():
    data = report_data("Legacy", "completed")
    data.pop("execution_context")
    data["credentials"] = [{"username": "Administrator"}]
    result = compare([(data, "old.json")])
    assert result["sessions"][0]["principal"] == "Belirtilmedi"
    assert "Administrator" not in json.dumps(result)
    assert result["warnings"]


def test_comparison_rejects_cross_targets_duplicate_context_and_duplicate_controls():
    first = report_data("First", "completed")
    second = report_data("Second", "completed")
    second["target"] = "other.dc"
    with pytest.raises(ValueError):
        compare([(first, "one.json"), (second, "two.json")])
    with pytest.raises(ValueError):
        compare([(first, "one.json"), (first, "one.json")])
    first["coverage"].append(copy.deepcopy(first["coverage"][0]))
    with pytest.raises(ValueError):
        compare([(first, "one.json")])


def test_offline_compare_and_snapshot_never_invoke_tools(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "tool_check", lambda: pytest.fail("offline invoked tools"))
    paths = []
    for label, state in [("Standard", "access_denied"), ("Auditor", "completed")]:
        path = tmp_path / (label + ".json")
        path.write_text(json.dumps(report_data(label, state)), encoding="utf-8")
        paths.append(str(path))
    assert cli.main(["--compare-reports", *paths, "--outdir", str(tmp_path)]) == 0
    output = next(tmp_path.glob("adscan-analysis-*.json"))
    data = json.loads(output.read_text(encoding="utf-8"))
    assert len(data["comparison"]["sessions"]) == 2
    assert not data["credentials"]
    assert cli.main(["--acl-snapshot", "examples/acl-snapshot.json", "--outdir", str(tmp_path)]) == 0


def test_example_snapshot_is_executable_and_malformed_data_rejected():
    with open("examples/acl-snapshot.json", encoding="utf-8") as stream:
        data = json.load(stream)
    assert [r["decision"] for r in analyze_snapshot(data)] == ["granted", "denied", "denied"]
    data["checks"][0]["principal_sid"] = "missing"
    with pytest.raises(ValueError):
        analyze_snapshot(data)
    with pytest.raises(ValueError):
        analyze_snapshot({"version": 1, "principals": "malformed"})


def test_malformed_memberships_are_rejected_instead_of_silently_ignored():
    with open("examples/acl-snapshot.json", encoding="utf-8") as stream:
        data = json.load(stream)
    data["principals"][0]["disabled_sids"] = GROUP
    with pytest.raises(ValueError):
        analyze_snapshot(data)


def test_invalid_live_analysis_input_fails_before_any_network_tools(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "tool_check", lambda: pytest.fail("invalid input invoked tools"))
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(report_data("Other", "completed")), encoding="utf-8")
    assert cli.main(["different.target", "--compare-reports", str(bad), "--dry-run"]) == 2


def test_live_context_metadata_is_execution_identity_and_contains_no_secret(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "tool_check", lambda: None)
    monkeypatch.setattr(cli, "_run_modules_live", lambda modules, ctx, report, jobs:
                        report.record_coverage("users", "planned", module="nxc-ldap"))
    assert cli.main(["dc.lab", "--only", "nxc-ldap", "--dry-run", "--no-nxc-db",
                     "--no-extra-reports", "--outdir", str(tmp_path),
                     "-u", "auditor", "-p", "dont-copy-secret", "-d", "lab.example",
                     "--context-label", "Denetçi", "--context-role", "auditor"]) == 0
    data = json.loads(next(tmp_path.glob("adscan-*.json")).read_text(encoding="utf-8"))
    context = data["execution_context"]
    assert context["principal"] == "lab.example\\auditor"
    assert context["role"] == "auditor" and context["auth_type"] == "password"
    assert "dont-copy-secret" not in json.dumps(context)
    assert context["started_at"] and context["id"]

"""Conservative AD DACL evaluation over explicit, ordered ACL snapshots.

This evaluates the supplied access token and materialized DACL, not arbitrary
Windows authorization contexts. Unsupported conditions yield unknown.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from pathlib import Path
from uuid import UUID

RIGHTS = {"create_child": 0x1, "delete_child": 0x2, "list_contents": 0x4,
          "self": 0x8, "read_property": 0x10, "write_property": 0x20,
          "delete_tree": 0x40, "list_object": 0x80, "control_access": 0x100,
          "delete": 0x10000, "read_control": 0x20000, "write_dacl": 0x40000,
          "write_owner": 0x80000, "generic_read": 0x80000000,
          "generic_write": 0x40000000, "generic_execute": 0x20000000,
          "generic_all": 0x10000000}
GENERIC = {0x80000000: 0x20094, 0x40000000: 0x20028,
           0x20000000: 0x20004, 0x10000000: 0xF01FF}
SUPPORTED_MASK = 0xF01FF
OBJECT_SPECIFIC = 0x13B  # child creation/deletion, self, properties, extended rights
OWNER_RIGHTS = "S-1-3-4"
SID_PATTERN = re.compile(r"^S-\d+-\d+(?:-\d+)*$", re.IGNORECASE)


def mask(value):
    if isinstance(value, bool):
        raise ValueError("Hak maskesi boolean olamaz")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str):
        result = RIGHTS[value.lower()] if value.lower() in RIGHTS else int(value, 0)
    elif isinstance(value, list):
        result = 0
        for part in value:
            result |= mask(part)
    else:
        raise ValueError("Hak listesi veya sayısal maskesi gerekli")
    if result < 0 or result > 0xFFFFFFFF:
        raise ValueError("Hak maskesi 32-bit aralığında olmalı")
    for generic, expanded in GENERIC.items():
        if result & generic:
            result = (result & ~generic) | expanded
    return result


def guid(value):
    return str(UUID(str(value))) if value else ""


def token_for(principal, groups):
    """Transitive memberships preserve a shortest explanatory path and cycles stop."""
    sid = principal["sid"]
    allow = {sid: [sid]}
    deny = {sid: [sid]}
    disabled = set(principal.get("disabled_sids", []))
    deny_only = set(principal.get("deny_only_sids", []))
    roots = list(principal.get("groups", [])) + list(principal.get("sid_history", []))
    if principal.get("primary_group_sid"):
        roots.append(principal["primary_group_sid"])
    if principal.get("authenticated") is True:
        roots.extend(["S-1-1-0", "S-1-5-11"])
    elif principal.get("anonymous") is True:
        roots.append("S-1-5-7")
    queue = deque([(sid, [sid], True)] + [(s, [sid, s], True) for s in roots])
    visited = set()
    parents = {}
    for group in groups:
        for member in group.get("members", []):
            parents.setdefault(member, []).append(group["sid"])
    while queue:
        current, path, enabled = queue.popleft()
        enabled = enabled and current not in deny_only
        if (current, enabled) in visited or current in disabled:
            continue
        visited.add((current, enabled))
        deny.setdefault(current, path)
        if enabled:
            allow.setdefault(current, path)
        for parent in parents.get(current, []):
            queue.append((parent, path + [parent], enabled))
    for current in deny_only:
        if current not in disabled:
            deny.setdefault(current, [sid, current])
            allow.pop(current, None)
    return allow, deny


def evaluate(principal, obj, check, groups):
    requested = mask(check.get("rights", []))
    permission = ", ".join(check["rights"]) if isinstance(check.get("rights"), list) \
        and all(isinstance(r, str) for r in check["rights"]) else hex(requested)
    evidence_id = hashlib.sha256(json.dumps(
        [principal["sid"], obj["id"], requested, guid(check.get("object_type_guid"))],
        sort_keys=True).encode()).hexdigest()[:24]
    result = {"id": evidence_id, "principal_sid": principal["sid"],
              "principal": principal.get("name", principal["sid"]),
              "object_id": obj["id"], "object_name": obj.get("name", obj["id"]),
              "permission": permission, "requested_mask": hex(requested),
              "decision": "unknown", "verification": "calculated", "trace": [],
              "observed_at": obj.get("observed_at", ""), "source": "acl_snapshot"}
    trace = result["trace"]
    def finish(decision, reason):
        names = {g["sid"]: g.get("name", g["sid"]) for g in groups}
        names[principal["sid"]] = principal.get("name", principal["sid"])
        for step in trace:
            step["path_labels"] = [names.get(s, s) for s in step.get("path", [])]
        result.update(decision=decision, reason=reason)
        return result
    if not requested or requested & ~SUPPORTED_MASK:
        return finish("unknown", "İstenen hak boş veya desteklenen AD DACL maskesinin dışında")
    if principal.get("token_complete") is not True or obj.get("dacl_complete") is not True:
        return finish("unknown", "Grup/token veya nesnenin materialize DACL verisi eksik")
    if principal.get("restricted_token") or principal.get("privileges"):
        return finish("unknown", "Restricted token veya ayrıcalık temelli AccessCheck desteklenmiyor")
    if principal.get("sid_history") and principal.get("sid_history_enabled") is not True:
        return finish("unknown", "SIDHistory'nin bu bağlamda etkin olduğu doğrulanmadı")
    allow, deny = token_for(principal, groups)
    remaining = requested
    dacl = obj.get("dacl")
    if dacl is None:
        if obj.get("null_dacl") is True:
            return finish("granted", "Açıkça belirtilen NULL DACL; DACL düzeyinde erişim serbest")
        return finish("unknown", "DACL yok; NULL DACL olduğu doğrulanmadı")
    if not isinstance(dacl, list):
        raise ValueError("dacl sıralı ACE listesi olmalı")
    if any(not isinstance(ace, dict) for ace in dacl):
        raise ValueError("ACE bir nesne olmalı")
    is_owner = obj.get("owner_sid") == principal["sid"] or obj.get("owner_sid") in principal.get("owner_sids", [])
    owner_known = bool(obj.get("owner_sid")) or obj.get("owner_known") is True
    uncertain_owner_mask = requested & 0x60000 if not owner_known else 0
    owner_rights_ace = any(ace.get("trustee_sid") == OWNER_RIGHTS and not ace.get("inherit_only") for ace in dacl)
    if owner_rights_ace and not owner_known:
        return finish("unknown", "OWNER RIGHTS ACE var; nesne sahibi bilgisi eksik")
    if is_owner and not owner_rights_ace:
        implicit = remaining & 0x60000
        remaining &= ~implicit
        if implicit:
            trace.append({"kind": "owner", "effect": "allow", "mask": hex(implicit),
                          "path": [principal["sid"]], "reason": "Sahibin READ_CONTROL / WRITE_DACL hakları"})
    scope = guid(check.get("object_type_guid"))
    related = {scope} if scope else set()
    related.update(guid(g) for g in check.get("property_set_guids", []))
    if scope and requested & OBJECT_SPECIFIC and check.get("schema_complete") is not True:
        return finish("unknown", "Nesneye özgü hak için şema/property-set eşlemesi eksik")
    for index, ace in enumerate(dacl):
        if not remaining:
            break  # later denies cannot revoke an already satisfied AccessCheck
        if not isinstance(ace, dict):
            raise ValueError("ACE bir nesne olmalı")
        if ace.get("inherit_only"):
            continue
        kind = ace.get("type")
        trustee = ace.get("trustee_sid", "")
        if trustee == "S-1-5-10":  # PRINCIPAL_SELF, not the DACL owner
            trustee = obj.get("object_sid", "")
        if trustee == "*" and kind not in {"allow", "deny"}:
            applies, path = True, []
        elif trustee == OWNER_RIGHTS:
            applies = is_owner
            path = [principal["sid"], OWNER_RIGHTS]
        else:
            applicable_token = allow if kind == "allow" else deny
            applies = trustee in applicable_token
            path = applicable_token.get(trustee, [])
        if not applies:
            continue
        affected = remaining & mask(ace.get("mask", []))
        ace_scope = guid(ace.get("object_type_guid"))
        if ace_scope:
            scoped_bits = affected & OBJECT_SPECIFIC
            if not scope and scoped_bits:
                return finish("unknown", "Nesneye özgü ACE için kontrol GUID'i belirtilmedi")
            if ace_scope not in related:
                affected &= ~OBJECT_SPECIFIC
        if not affected:
            continue
        if kind not in {"allow", "deny"} or ace.get("conditional"):
            return finish("unknown", f"ACE {index + 1}: desteklenmeyen veya koşullu ACE")
        trace.append({"ace_index": index + 1, "kind": "ace", "effect": kind,
                      "trustee_sid": trustee, "mask": hex(affected), "path": path,
                      "inherited": bool(ace.get("inherited")), "object_type_guid": ace_scope,
                      "reason": "Kalıtılan ACE" if ace.get("inherited") else "Doğrudan ACE"})
        if kind == "deny":
            if affected & uncertain_owner_mask:
                return finish("unknown", "Deny ACE eşleşti fakat nesne sahibinin örtük hakları bilinmiyor")
            return finish("denied", f"ACE {index + 1} kalan istenen hakları reddetti")
        remaining &= ~affected
    if remaining:
        if remaining & uncertain_owner_mask:
            return finish("unknown", "Verilmeyen DACL hakları için nesne sahibi bilgisi gerekli")
        return finish("denied", f"DACL sonunda verilmeyen haklar: {hex(remaining)}")
    return finish("granted", "İstenen haklar sıralı DACL değerlendirmesinde verildi")


def analyze_snapshot(data):
    if not isinstance(data, dict) or data.get("version") != 1:
        raise ValueError("ACL snapshot version=1 olmalı")
    for field in ("principals", "objects", "groups", "checks"):
        values = data.get(field, [])
        if not isinstance(values, list) or any(not isinstance(v, dict) for v in values):
            raise ValueError(f"{field} nesne listesi olmalı")
    for field, key in (("principals", "sid"), ("objects", "id"), ("groups", "sid")):
        for item in data.get(field, []):
            if not isinstance(item.get(key), str) or not item[key]:
                raise ValueError(f"{field}.{key} boş olmayan metin olmalı")
            if key == "sid" and not SID_PATTERN.fullmatch(item[key]):
                raise ValueError(f"Geçersiz SID: {item[key]}")
    for principal in data.get("principals", []):
        for field in ("groups", "sid_history", "disabled_sids", "deny_only_sids", "owner_sids"):
            values = principal.get(field, [])
            if not isinstance(values, list) or any(not isinstance(s, str) or not SID_PATTERN.fullmatch(s) for s in values):
                raise ValueError(f"principals.{field} SID listesi olmalı")
    group_ids = set()
    for group in data.get("groups", []):
        if group["sid"] in group_ids:
            raise ValueError("Tekrarlanan grup SID")
        group_ids.add(group["sid"])
        members = group.get("members", [])
        if not isinstance(members, list) or any(not isinstance(s, str) or not SID_PATTERN.fullmatch(s) for s in members):
            raise ValueError("groups.members SID listesi olmalı")
    principals = {p["sid"]: p for p in data.get("principals", [])}
    objects = {o["id"]: o for o in data.get("objects", [])}
    if len(principals) != len(data.get("principals", [])) or len(objects) != len(data.get("objects", [])):
        raise ValueError("Tekrarlanan principal SID veya nesne kimliği")
    output = []
    check_ids = set()
    for check in data.get("checks", []):
        if check.get("principal_sid") not in principals or check.get("object_id") not in objects:
            raise ValueError("Kontrolün kimliği veya nesnesi snapshot içinde bulunamadı")
        result = evaluate(principals[check["principal_sid"]], objects[check["object_id"]],
                          check, data.get("groups", []))
        if result["id"] in check_ids:
            raise ValueError("Aynı kimlik/nesne/hak kontrolü birden fazla kez belirtildi")
        check_ids.add(result["id"])
        if data.get("source"):
            result["source"] = str(data["source"])
        result["observed_at"] = result["observed_at"] or str(data.get("observed_at", ""))
        output.append(result)
    if not output:
        raise ValueError("ACL snapshot en az bir kontrol içermeli")
    return output


def load_snapshot(path, report):
    with open(path, encoding="utf-8-sig") as stream:
        data = json.load(stream)
    if not isinstance(data, dict):
        raise ValueError("ACL snapshot bir JSON nesnesi olmalı")
    if str(data.get("target", "")).casefold() != report.target.casefold():
        raise ValueError("ACL snapshot hedefi rapor hedefiyle uyuşmuyor")
    output = analyze_snapshot(data)
    report.effective_rights.extend(output)
    for result in output:
        report.record_coverage("effective-rights:" + result["id"],
                               "unknown" if result["decision"] == "unknown" else "completed",
                               result["reason"], module="effective-rights",
                               observed_at=result["observed_at"],
                               label=f"{result['principal']} → {result['object_name']} / {result['permission']}")
    return Path(path).name


def record_tool_results(results, report):
    """Keep server-reported writable rights distinct from calculated DACL rights."""
    from .assessment import result_status
    from .modules.bloodyAD_scan import _DANGER, _records_of

    principal = report.execution_context.get("principal") or "Aktif kimlik (kayıtsız)"
    for result in results:
        if result.tool != "bloodyad-writable" or result_status(result)[0] != "completed":
            continue
        for record in _records_of(result):
            dn = (record.get("distinguishedname") or [""])[0]
            if not dn:
                continue
            for right in record:
                if right not in _DANGER:
                    continue
                identity = hashlib.sha256(f"{principal}:{dn}:{right}".encode()).hexdigest()[:24]
                item = {"id": identity, "principal": principal, "principal_sid": "",
                        "object_id": dn, "object_name": dn, "permission": right,
                        "decision": "granted", "verification": "tool_reported",
                        "reason": "bloodyAD yazılabilir hak bildirdi; tam DACL/grup zinciri hesaplanmadı",
                        "observed_at": result.observed_at, "source": result.tool,
                        "trace": [], "resumed": result.resumed}
                if not any(r["id"] == identity for r in report.effective_rights):
                    report.effective_rights.append(item)

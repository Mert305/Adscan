"""Compare observed coverage across identities without claiming causality."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

SUCCESS = {"completed", "findings"}


def read_report(path):
    with open(path, encoding="utf-8-sig") as stream:
        data = json.load(stream)
    if not isinstance(data, dict) or not data.get("target") or not isinstance(data.get("coverage"), list):
        raise ValueError(f"Geçerli kapsam raporu değil: {Path(path).name}")
    return data


def compare(reports):
    """Inputs are (report dict, source label) pairs; no secrets are copied."""
    if not reports:
        return {"sessions": [], "controls": [], "findings": [], "warnings": []}
    targets = {str(data["target"]).strip().casefold() for data, _ in reports}
    if len(targets) != 1:
        raise ValueError("Karşılaştırılan raporların hedefi aynı olmalı")
    sessions, matrix, findings, warnings = [], {}, {}, []
    context_ids = set()
    for index, (data, source) in enumerate(reports):
        context = data.get("execution_context") or {}
        if not isinstance(context, dict):
            raise ValueError("execution_context bir nesne olmalı")
        label = context.get("label") or context.get("principal") or data.get("scan_mode", "Bilinmeyen kimlik")
        session = {"id": context.get("id") or hashlib.sha256(
            f"{index}:{source}:{label}".encode()).hexdigest()[:16],
            "label": str(label), "principal": str(context.get("principal") or "Belirtilmedi"),
            "role": context.get("role", "unknown"), "auth_type": context.get("auth_type", "unknown"),
            "started_at": context.get("started_at", ""), "source": Path(source).name,
            "scan_mode": data.get("scan_mode", "unspecified"), "controls": 0, "completed": 0}
        if not context:
            warnings.append(f"{session['source']}: çalıştıran kimlik kaydı yok; eski rapor.")
        if session["id"] in context_ids:
            raise ValueError("Aynı tarama bağlamı birden fazla kez karşılaştırmaya eklendi")
        context_ids.add(session["id"])
        sessions.append(session)
        seen = set()
        for control in data["coverage"]:
            if not isinstance(control, dict) or not control.get("control_id") or not control.get("status"):
                raise ValueError("Geçersiz kapsam kaydı")
            if control.get("level") == "module":
                continue
            key = (str(control.get("target") or data["target"]).casefold(),
                   str(control.get("module") or control["control_id"]), str(control["control_id"]))
            if key in seen:
                raise ValueError(f"Tekrarlanan kontrol: {key[2]}")
            seen.add(key)
            row = matrix.setdefault(key, {"target": key[0], "module": key[1], "control_id": key[2],
                                          "label": str(control.get("label") or key[2]), "cells": {}})
            row["cells"][index] = {"status": str(control["status"]),
                                   "reason": str(control.get("reason", "")),
                                   "observed_at": str(control.get("observed_at", "")),
                                   "resumed": bool(control.get("resumed")),
                                   "granularity": str(control.get("level", "legacy"))}
            session["controls"] += 1
            session["completed"] += control["status"] in SUCCESS
        for finding in data.get("findings", []):
            if not isinstance(finding, dict):
                raise ValueError("Geçersiz bulgu kaydı")
            fingerprint = finding.get("fingerprint")
            if not fingerprint:
                continue  # titles are not stable object identities
            row = findings.setdefault(fingerprint, {"fingerprint": fingerprint,
                "title": str(finding.get("title", "")), "target": str(finding.get("target", "")),
                "present_in": []})
            if index not in row["present_in"]:
                row["present_in"].append(index)
    rows = []
    for key in sorted(matrix):
        row = matrix[key]
        row["cells"] = [row["cells"].get(i, {"status": "not_tested", "reason": "Bu raporda kontrol kaydı yok",
                           "observed_at": "", "resumed": False, "granularity": "none"})
                        for i in range(len(sessions))]
        states = {cell["status"] for cell in row["cells"]}
        row["different"] = len(states) > 1
        row["access_difference"] = "access_denied" in states and bool(states & SUCCESS)
        rows.append(row)
    warnings.append("Farklar kimlik etkisini tek başına kanıtlamaz; zaman, araç sürümü ve kapsam farklı olabilir. "
                    "Bulgunun bir raporda görünmemesi çözüldüğü anlamına gelmez.")
    return {"sessions": sessions, "controls": rows, "findings": list(findings.values()),
            "warnings": warnings, "different_controls": sum(r["different"] for r in rows),
            "access_differences": sum(r["access_difference"] for r in rows)}

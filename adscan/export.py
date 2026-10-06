"""Red-team teslimatı ek çıktıları: MITRE Navigator layer, loot manifesti, CSV.

Bunlar `report.py`'deki insan-okunur çıktıların (terminal/MD/HTML) yanında,
engagement teslimatında işe yarayan **makine-okunur** yan ürünlerdir:

* **Navigator layer**  — bulgu tekniklerini ATT&CK Navigator'da renklendirir.
* **Loot manifesti**   — ele geçen kimlik/host/kullanıcı + loot dosyaları (tek JSON).
* **Bulgu CSV'si**     — SIEM/takip tablosuna aktarım için düz tablo.
"""

from __future__ import annotations

import csv
import json
import os
from datetime import datetime

from . import config
from .findings import ScanReport, Severity

# Seviye -> Navigator renk kodu (koyu kırmızı … gri)
_NAV_COLOR = {
    Severity.CRITICAL: "#b00020",
    Severity.HIGH: "#d9534f",
    Severity.MEDIUM: "#e0a800",
    Severity.LOW: "#17a2b8",
    Severity.INFO: "#6c757d",
}
# Seviye -> Navigator skoru (0-100)
_NAV_SCORE = {
    Severity.CRITICAL: 100, Severity.HIGH: 75,
    Severity.MEDIUM: 50, Severity.LOW: 25, Severity.INFO: 10,
}


def write_navigator_layer(report: ScanReport, path: str) -> None:
    """Bulguların ATT&CK tekniklerini bir Navigator layer JSON'una yazar.

    Her teknik, o tekniğe eşlenen bulguların EN YÜKSEK seviyesine göre
    renklendirilir; yorumda bulgu başlıkları listelenir.
    """
    from . import mitre as _mitre

    # technique_id -> (max_severity, [başlıklar])
    agg: dict[str, tuple[Severity, list[str]]] = {}
    for f in report.findings:
        tid = f.mitre or _mitre.technique_for(f"{f.source} {f.reference} {f.title}")
        if not tid:
            continue
        for one in (t.strip() for t in tid.split(",") if t.strip()):
            sev, titles = agg.get(one, (Severity.INFO, []))
            new_sev = max(sev, f.severity)
            titles = titles + [f.title]
            agg[one] = (new_sev, titles)

    techniques = []
    for tid, (sev, titles) in sorted(agg.items()):
        techniques.append({
            "techniqueID": tid,
            "score": _NAV_SCORE[sev],
            "color": _NAV_COLOR[sev],
            "comment": "; ".join(dict.fromkeys(titles))[:500],
            "enabled": True,
        })

    layer = {
        "name": f"adscan — {report.target}",
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": (f"adscan AD taraması — {report.target} "
                        f"({datetime.now():%Y-%m-%d %H:%M}). "
                        f"Risk: {report.risk_label()} ({report.risk_score()}/100)."
                        + (" DOMAIN ADMIN ELDE EDİLDİ." if report.domain_admin else "")),
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffe766", "#ffaf66", "#b00020"],
            "minValue": 0, "maxValue": 100,
        },
        "legendItems": [
            {"label": "Kritik/Yüksek bulgu", "color": _NAV_COLOR[Severity.CRITICAL]},
            {"label": "Orta", "color": _NAV_COLOR[Severity.MEDIUM]},
            {"label": "Düşük/Bilgi", "color": _NAV_COLOR[Severity.LOW]},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#205b8f",
        "selectTechniquesAcrossTactics": True,
        "sorting": 3,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(layer, fh, ensure_ascii=False, indent=2)


def write_loot_manifest(report: ScanReport, path: str) -> None:
    """Ele geçen kimlik/host/kullanıcı + loot dosyalarını tek JSON'a toplar.

    `config.REDACT` açıksa sırlar maskeli yazılır (güvenli paylaşım).
    """
    loot_dir = os.path.join(report.outdir, "loot")
    loot_files: list[str] = []
    if os.path.isdir(loot_dir):
        for root, _dirs, files in os.walk(loot_dir):
            for fn in sorted(files):
                full = os.path.join(root, fn)
                try:
                    size = os.path.getsize(full)
                except OSError:
                    size = -1
                loot_files.append({"path": full, "bytes": size})

    manifest = {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "target": report.target,
        "domain": report.domain,
        "dc_name": report.dc_name,
        "domain_admin": report.domain_admin,
        "risk_score": report.risk_score(),
        "risk_label": report.risk_label(),
        "redacted": config.REDACT,
        "credentials": [c.to_dict() for c in report.credentials],
        "admin_credentials": [c.to_dict() for c in report.credentials if c.admin],
        "hosts": report.hosts,
        "users": report.users,
        "loot_files": loot_files,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=2)


def write_attack_graph(report: ScanReport, path: str) -> None:
    """Saldırı grafiğini düğüm/kenar JSON'u olarak yazar (dış araçlarla görselleştirilebilir).

    Düğümler: saldırgan · ele geçen kimlikler · host'lar · (varsa) Domain Admin.
    Kenarlar: saldırgan→kimlik (nasıl elde edildi) · kimlik→host (erişim/admin) ·
    admin→DA. chain.py adımları da 'tamamlandı/bekliyor' metaverisiyle eklenir.
    """
    from . import chain as _chain

    nodes: list[dict] = [{"id": "attacker", "label": "Saldırgan", "type": "attacker"}]
    edges: list[dict] = []
    seen_nodes = {"attacker"}

    def add_node(nid: str, label: str, ntype: str, **extra) -> None:
        if nid not in seen_nodes:
            nodes.append({"id": nid, "label": label, "type": ntype, **extra})
            seen_nodes.add(nid)

    for c in report.credentials:
        who = f"{c.domain}\\{c.username}" if c.domain else c.username
        nid = f"cred:{who.lower()}"
        add_node(nid, who, "credential", kind=c.kind, admin=c.admin, source=c.source)
        edges.append({"from": "attacker", "to": nid, "label": c.source or "elde edildi",
                      "type": "obtained"})
        if c.host:
            hid = f"host:{c.host.lower()}"
            add_node(hid, c.host, "host")
            edges.append({"from": nid, "to": hid,
                          "label": "yerel admin" if c.admin else "erişim",
                          "type": "admin" if c.admin else "access"})

    for h in report.hosts:
        add_node(f"host:{h.lower()}", h, "host")

    if report.domain_admin:
        add_node("da", "DOMAIN ADMIN", "domain_admin")
        for c in report.credentials:
            if c.admin:
                who = f"{c.domain}\\{c.username}" if c.domain else c.username
                edges.append({"from": f"cred:{who.lower()}", "to": "da",
                              "label": "DCSync/privesc", "type": "escalation"})

    steps = [{"key": s.key, "title": s.title, "achieved": ok}
             for s, ok in _chain.evaluate(report)]

    graph = {
        "target": report.target,
        "domain": report.domain,
        "domain_admin": report.domain_admin,
        "risk_score": report.risk_score(),
        "nodes": nodes,
        "edges": edges,
        "chain": steps,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(graph, fh, ensure_ascii=False, indent=2)


def write_csv(report: ScanReport, path: str) -> None:
    """Bulguları düz CSV olarak yazar (SIEM / takip tablosu için)."""
    cols = ["severity", "title", "target", "source", "mitre", "reference",
            "description", "poc", "escalation", "remediation"]
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(cols)
        for f in report.sorted_findings():
            writer.writerow([
                f.severity.label, f.title, f.target, f.source, f.mitre,
                f.reference, f.description, f.poc, f.escalation, f.remediation,
            ])

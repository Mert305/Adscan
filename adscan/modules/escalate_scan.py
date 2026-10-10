"""Otonom yetki yükseltme modülü — beyin (LLM) için "kimlik→Domain Admin" eylemi.

Bu modül, enum/privesc bulgularında bir YÜKSELTME YOLU (bkz. Finding.escalation)
belirdiğinde beynin seçebileceği tek bir "eylem" sunar: eldeki kimliklerle
`escalate.run_to_da` zincirini (reuse → secrets dump → DCSync → krbtgt → Domain
Admin) çalıştırmak.

Mimari not — neden `run`/`parse` burada boş:
    Beyin döngüsü modülleri `mod.parse(mod.run(ctx), report)` olarak çağırır;
    yani `run` yalnızca `ctx`, `parse` yalnızca `report` görür. Yükseltme zinciri
    ise ikisine BİRDEN (ctx + report + ui, turlu durum) ihtiyaç duyar. Bu yüzden
    gerçek iş `cli._run_brain` içinde `escalate.run_to_da(ctx, report, ui=ui)` ile
    özel olarak yürütülür; buradaki `run`/`parse` yalnızca modülü registry
    whitelist'ine ve beynin aday listesine sokmak için vardır (no-op).

Güvenlik:
    - `active=True`: beyin yalnızca `--brain-active` verildiğinde bunu aday görür.
    - `requires_creds=True`: anlamlı olması için elde gizli-içeren bir kimlik gerekir
      (aday filtresi `brain.runnable_candidates` içinde report.credentials'a bakar).
    - Gerçek çalıştırma `--launch` kapısına tabidir; aksi halde plan (dry-run) kalır
      (bkz. cli._run_brain özel dalı). Komutları yine `runner.run` kurar.
"""

from __future__ import annotations

from ..findings import ScanReport
from ..registry import ScanContext, ScanModule
from ..runner import CommandResult


def _run(ctx: ScanContext) -> list[CommandResult]:
    # Gerçek zincir cli._run_brain içinde (ctx+report birlikte) yürütülür.
    return []


def _parse(results: list[CommandResult], report: ScanReport) -> None:
    # Bu modül için parse yok; run_to_da report'u doğrudan günceller.
    return None


MODULE = ScanModule(
    name="escalate",
    label="Kimlik→Domain Admin yükseltme zinciri (reuse→dump→DCSync)",
    run=_run,
    parse=_parse,
    requires_creds=True,
    optin=True,
    active=True,
)

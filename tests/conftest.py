"""Paylaşılan test yardımcıları.

Parser'lar 'metin -> Finding' saf fonksiyonları olduğu için, gerçek araçları
çalıştırmadan örnek çıktılarla test edebiliriz. `cr()` sahte bir CommandResult
üretir.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Proje kökünü import yoluna ekle (tests/ alt klasöründen çalışınca)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from adscan.findings import ScanReport  # noqa: E402
from adscan.runner import CommandResult  # noqa: E402


def cr(stdout: str, *, tool: str = "test", argv: list[str] | None = None,
       error: str | None = None) -> CommandResult:
    """Testler için sahte komut sonucu."""
    return CommandResult(
        tool=tool,
        argv=argv or ["dummy"],
        returncode=0,
        stdout=stdout,
        stderr="",
        duration=0.0,
        error=error,
    )


@pytest.fixture
def report() -> ScanReport:
    return ScanReport(target="10.10.10.5")


def titles(report: ScanReport) -> list[str]:
    return [f.title for f in report.findings]


def severity_of(report: ScanReport, needle: str):
    for f in report.findings:
        if needle.lower() in f.title.lower():
            return f.severity
    return None

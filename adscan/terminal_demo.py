"""Offline terminal preview: synthetic observations, no external tools."""

from .findings import Finding, ScanReport, Severity
from .live import Live
from .report import render_coverage, render_finding


def preview():
    report = ScanReport(target="lab.example")
    for cid, status, resumed in [("ldap-users", "completed", True),
                                 ("ldap-gmsa", "access_denied", False),
                                 ("ldap-groups", "completed", True)]:
        report.record_coverage(cid, status, "Okuma yetkisi yok" if status == "access_denied" else "",
                               module="nxc-ldap", resumed=resumed)
    ui = Live(3, enabled=False, title="adscan · ÖRNEK / lab.example")
    ui.register_modules(["nmap", "nxc-ldap", "nxc-smb"])
    ui.finish_module("nmap", "tamamlandı")
    ui.finish_module("nxc-ldap", "kısmi")
    ui.set_running("nxc-smb")
    ui.advance(2)
    ui.set_stats(HIGH=1)
    ui.set_coverage(report.coverage)
    ui.set_detail("SMB paylaşım erişimi")
    print("ÖRNEK VERİ — ağ bağlantısı veya tarama yapılmaz.\n")
    print('\n'.join(ui._compose()))
    print(render_finding(Finding(title="SMB imzalama zorunlu değil", severity=Severity.HIGH,
                                 target=report.target, source="nxc-smb", verification="tool_reported",
                                 evidence="Signing: False", remediation="SMB imzalamayı zorunlu kılın."), color=ui.color))
    print(render_coverage(report))

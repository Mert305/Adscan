"""Conservative execution coverage; a successful process is not proof of safety."""

from .runner import classify_output


def record_results(report, module, results, *, parse_failed=False, findings=False):
    if not results:
        report.record_coverage(module, "failed", "Araç sonuç döndürmedi", module=module)
        return
    statuses = []
    for result in results:
        kind = result.error_kind or classify_output(result.combined)
        if "[DRY-RUN]" in result.stdout:
            status, reason = "planned", "Dry-run; kontrol uygulanmadı"
        elif result.tool.endswith(":skip"):
            status, reason = "skipped", "Modül önkoşulları karşılanmadı"
        elif result.timed_out:
            status, reason = "failed", "Zaman aşımı; sonuç eksik olabilir"
        elif kind == "auth":
            status, reason = "access_denied", "Kimlik doğrulama veya erişim reddedildi"
        elif not result.ok or kind:
            status, reason = "failed", f"Araç hatası ({kind or result.returncode})"
        elif parse_failed:
            status, reason = "failed", "Çıktı ayrıştırılamadı"
        elif not result.combined.strip():
            status, reason = "unknown", "Boş çıktı; kontrol sonucu doğrulanamadı"
        else:
            status, reason = "completed", "Araç çalıştı; zafiyet yokluğu garantisi değildir"
        report.record_coverage(result.tool, status, reason, module=module)
        statuses.append(status)
    incomplete = any(s != "completed" for s in statuses)
    report.record_coverage(module, "failed" if parse_failed else "partial" if incomplete else
                           "findings" if findings else "completed",
                           "Modül özeti; alt kontrol durumlarına bakın", module=module)

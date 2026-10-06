"""Offline browser smoke check for the standalone HTML report."""

import json
from pathlib import Path

from playwright.sync_api import sync_playwright

from adscan.comparison import compare
from adscan.findings import Finding, ScanReport, Severity
from adscan.permissions import load_snapshot
from adscan.report import write_html


def main():
    output = Path("adscan-reports")
    output.mkdir(exist_ok=True)
    report = ScanReport("lab.example", scan_mode="authenticated")
    report.execution_context = {"id": "demo-auditor", "label": "Denetçi", "principal": "LAB\\auditor",
                                "role": "auditor", "auth_type": "password", "started_at": "2026-10-06T12:00:00Z"}
    for title, severity, target, source, verification in [
        ("LDAP erişim yetkisi", Severity.HIGH, "dc.lab.example", "nxc-ldap", "tool_reported"),
        ("SMB yapılandırması", Severity.MEDIUM, "fs.lab.example", "nxc-smb", "unverified"),
        ("Kullanıcı listesi", Severity.INFO, "dc.lab.example", "nxc-ldap", "unverified"),
    ]:
        report.add(Finding(title, severity, target, source, verification=verification,
                           evidence="Örnek kanıt <script>window.injected=true</script>",
                           remediation="Yetkileri ve yapılandırmayı gözden geçirin."))
    report.record_coverage("nxc:ldap-users", "completed", module="nxc-ldap", resumed=True)
    report.record_coverage("nxc:smb-shares", "access_denied", "Erişim reddedildi", module="nxc-smb")
    report.record_coverage("nxc:smb-info", "completed", module="nxc-smb")
    load_snapshot("examples/acl-snapshot.json", report)
    sessions = []
    for context_id, label, role, auth, users_status, shares_status in [
        ("demo-anon", "Kimliksiz", "anonymous", "anonymous", "access_denied", "skipped"),
        ("demo-standard", "Standart kullanıcı", "standard", "password", "completed", "access_denied"),
    ]:
        session = ScanReport("lab.example", scan_mode="unauthenticated" if role == "anonymous" else "authenticated")
        session.execution_context = {"id": context_id, "label": label, "role": role,
                                     "principal": "Anonymous" if role == "anonymous" else "LAB\\standard", "auth_type": auth,
                                     "started_at": "2026-10-06T12:00:00Z"}
        session.record_coverage("nxc:ldap-users", users_status, module="nxc-ldap")
        session.record_coverage("nxc:smb-shares", shares_status, module="nxc-smb")
        session.record_coverage("nxc:smb-info", "completed", module="nxc-smb")
        sessions.append((session.to_dict(), label + ".json"))
    sessions.append((report.to_dict(), "denetci.json"))
    for data, source in sessions:
        (output / source).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    report.comparison = compare(sessions)
    path = output / "interactive-demo.html"
    write_html(report, str(path))
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="msedge", headless=True)
        page = browser.new_page(viewport={"width": 1280, "height": 900})
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto(path.resolve().as_uri())
        assert page.locator('#comparison').is_visible()
        assert page.locator('.comparison-row:visible').count() == 6
        page.check('#different-only')
        assert page.locator('.comparison-row:visible').count() == 5
        page.uncheck('#different-only')
        with page.expect_download() as pending_download:
            page.click('#export-visible')
        download = pending_download.value
        assert download.suggested_filename == 'adscan-comparison.csv'
        page.click('#tab-findings')
        assert page.locator(".finding:visible").count() == 3
        page.select_option("#severity", "HIGH")
        assert page.locator(".finding:visible").count() == 1
        page.select_option("#target", "fs.lab.example")
        assert page.locator(".finding:visible").count() == 0
        page.click("#reset-filters")
        page.select_option("#module", "nxc-ldap")
        page.select_option("#verification", "tool_reported")
        assert page.locator(".finding:visible").count() == 1
        page.click('#tab-coverage')
        assert page.locator(".coverage-row:visible").count() == 1
        page.click('#tab-findings')
        page.click("#reset-filters")
        page.select_option("#status", "access_denied")
        page.click('#tab-coverage')
        assert page.locator(".coverage-row:visible").count() == 1
        page.click('#tab-findings')
        page.click("#reset-filters")
        page.fill("#search", "SMB yapılandırması")
        assert page.locator(".finding:visible").count() == 1
        page.click("#reset-filters")
        page.select_option("#view", "technical")
        assert page.locator(".finding[open]").count() == 3
        page.locator('.finding a[href^="#evidence-"]').first.click()
        assert page.url.split("#")[-1].startswith("evidence-")
        assert page.evaluate("window.injected") is None
        page.click("#collapse-all")
        assert page.locator(".finding[open]").count() == 0
        page.click("#expand-all")
        assert page.locator(".finding[open]").count() == 3
        page.click("#reset-filters")
        page.click('#tab-permissions')
        assert page.locator('.permission-row:visible').count() == 3
        page.select_option('#permission-decision', 'granted')
        assert page.locator('.permission-row:visible').count() == 1
        page.locator('.permission-row:visible details summary').click()
        assert 'Helpdesk' in page.locator('.permission-row:visible').inner_text()
        page.click('#reset-filters')
        page.click('#theme-toggle')
        assert page.locator('html').get_attribute('data-theme') == 'dark'
        page.click('#theme-toggle')
        page.click('#tab-overview')
        page.screenshot(path=str(output / "interactive-demo.png"), full_page=True)
        page.click('#tab-comparison')
        page.screenshot(path=str(output / 'interactive-demo-comparison.png'), full_page=True)
        page.click('#tab-permissions')
        page.locator('.permission-row details').first.locator('summary').click()
        page.screenshot(path=str(output / 'interactive-demo-permissions.png'), full_page=True)
        page.set_viewport_size({"width": 390, "height": 844})
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        page.click('#tab-comparison')
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        page.screenshot(path=str(output / 'interactive-demo-mobile.png'), full_page=True)
        page.locator('#tab-comparison').focus()
        page.keyboard.press('ArrowRight')
        assert page.locator('#tab-permissions').get_attribute('aria-selected') == 'true'
        paginated = ScanReport('pagination.lab')
        for index in range(55):
            paginated.add(Finding(f'Unique risk {index:02d}', Severity.HIGH, 'pagination.lab',
                                  'ldap', evidence=f'Proof {index}'))
        paginated_path = output / 'pagination-demo.html'
        write_html(paginated, str(paginated_path))
        page.goto(paginated_path.resolve().as_uri())
        page.click('#tab-findings')
        assert page.locator('.finding:visible').count() == 25
        page.click('#page-next')
        assert page.locator('.finding:visible').count() == 25
        page.click('#page-next')
        assert page.locator('.finding:visible').count() == 5
        page.fill('#search', 'Unique risk 00')
        assert page.locator('.finding:visible').count() == 1
        last = paginated.sorted_findings()[-1]
        page.goto(paginated_path.resolve().as_uri() + '#evidence-' + last.fingerprint)
        assert page.locator('.finding:visible').count() == 5
        assert page.locator('#page-position').inner_text() == '3 / 3'
        assert page.locator('#evidence-' + last.fingerprint).is_visible()
        assert not errors, errors
        browser.close()
    print(f"Browser checks passed: {path.resolve()}")


if __name__ == "__main__":
    main()

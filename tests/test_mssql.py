"""mssql_scan — login/privesc + linked-server parser testleri."""

from conftest import cr, severity_of, titles

from adscan.findings import Severity
from adscan.modules import mssql_scan

LOGIN_OK = "MSSQL 10.10.10.5 1433 SQL01 [+] corp.local\\svc:Pass (Pwn3d!)"


def test_mssql_linked_servers_high(report):
    links = (LOGIN_OK + "\n"
             "MSSQL 10.10.10.5 1433 SQL01 name product is_rpc_out_enabled\n"
             "MSSQL 10.10.10.5 1433 SQL01 SQL02 SQL Server True")
    mssql_scan.parse([cr(LOGIN_OK, tool="mssql-login"),
                      cr("", tool="mssql-priv"),
                      cr(links, tool="mssql-links")], report)
    assert severity_of(report, "linked server") == Severity.HIGH
    ev = next(f.evidence for f in report.findings if "linked server" in f.title)
    assert "SQL02" in ev


def test_mssql_no_linked_servers_no_finding(report):
    links = (LOGIN_OK + "\n"
             "MSSQL 10.10.10.5 1433 SQL01 name product is_rpc_out_enabled")
    mssql_scan.parse([cr(LOGIN_OK, tool="mssql-login"),
                      cr("", tool="mssql-priv"),
                      cr(links, tool="mssql-links")], report)
    assert not any("linked server" in t for t in titles(report))

"""HTTP/HTTPS yüzeyi + ADCS web enrollment (ESC8) / CES-CEP tespiti.

Eski nmap modülü sabit AD port listesi taradığı için 80/443 ve oradaki IIS /
ADCS web enrollment (certsrv) tamamen görünmezdi — oysa bu, ESC8 (NTLM relay ->
sertifika -> DCSync) için en kritik yüzeydir. Bu modül kimlik GEREKTİRMEDEN,
yalnızca stdlib (http.client + ssl) ile hedefin 80/443'ünü yoklar:

  * `/` -> Server başlığı + <title> (IIS/uygulama tespiti)
  * `/certsrv/` ve `/certsrv/certfnsh.asp` -> ADCS **web enrollment** (ESC8)
  * `/ADPolicyProvider_CEP_*/service.svc`, `/<CA>_CES_*/service.svc` -> **CES/CEP**
    (Certificate Enrollment Web Services — HTTP(S) relay yüzeyi / ESC8 varyantı)

certipy "web enrollment: False" dese bile bu endpoint'ler canlı/erişilebilir
olabilir; relay hedefi gerçekte ERİŞİLEBİLİRLİKTİR, CA bayrağı değil.
"""

from __future__ import annotations

import http.client
import ssl

from ..findings import Finding, ScanReport, Severity
from ..runner import CommandResult, ToolStatus

# Yoklanacak yollar: (yol, "ne")
_CERT_PATHS = [
    ("/certsrv/", "ADCS web enrollment (certsrv)"),
    ("/certsrv/certfnsh.asp", "ADCS web enrollment (certfnsh.asp)"),
    ("/certsrv/certrqxz.asp", "ADCS web enrollment (certrqxz.asp)"),
    ("/ADPolicyProvider_CEP_Kerberos/service.svc", "ADCS CEP (Kerberos)"),
    ("/ADPolicyProvider_CEP_UsernamePassword/service.svc", "ADCS CEP (User/Pass)"),
    ("/ADPolicyProvider_CEP_Certificate/service.svc", "ADCS CEP (Certificate)"),
    ("/KEYFACTOR_CA_CES_Kerberos/service.svc", "ADCS CES (Kerberos)"),
]

_TIMEOUT = 8


def tool() -> ToolStatus:
    # Harici araç yok; her zaman kullanılabilir (stdlib).
    return ToolStatus(name="http(stdlib)", available=True, path="builtin")


def _request(host: str, port: int, path: str, tls: bool) -> tuple[int, dict, str] | None:
    """Tek bir HTTP(S) GET; (status, headers, gövde-başı) ya da None (ulaşılamaz)."""
    conn = None
    try:
        if tls:
            cctx = ssl._create_unverified_context()
            conn = http.client.HTTPSConnection(host, port, timeout=_TIMEOUT,
                                               context=cctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=_TIMEOUT)
        conn.request("GET", path, headers={"User-Agent": "adscan/web"})
        resp = conn.getresponse()
        body = resp.read(2048).decode("latin-1", "replace")
        return resp.status, dict(resp.getheaders()), body
    except (OSError, http.client.HTTPException, ssl.SSLError):
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass


def _title(body: str) -> str:
    low = body.lower()
    i = low.find("<title>")
    if i == -1:
        return ""
    j = low.find("</title>", i)
    return body[i + 7:j].strip() if j != -1 else ""


def scan(target: str, *, timeout: int = 300, dry_run: bool = False,
         **_: object) -> list[CommandResult]:
    host = target.split(",")[0].split("/")[0].strip()
    if dry_run:
        return [CommandResult(tool="web:dry", argv=["GET", f"http(s)://{host}/..."],
                              returncode=0, stdout="[DRY-RUN] web probe", stderr="",
                              duration=0.0)]
    lines: list[str] = []
    for port, tls in ((80, False), (443, True)):
        root = _request(host, port, "/", tls)
        if root is None:
            continue
        status, headers, body = root
        scheme = "https" if tls else "http"
        server = headers.get("Server", "")
        lines.append(f"PORT {port}/{scheme} open  status={status}  "
                     f"server={server!r}  title={_title(body)!r}")
        for path, what in _CERT_PATHS:
            r = _request(host, port, path, tls)
            if r is None:
                continue
            st = r[0]
            # 404 => endpoint yok; 200/401/403/405 => VAR (çoğu kimlik/metot ister)
            if st != 404:
                lines.append(f"  [{what}] {scheme}://{host}:{port}{path}  -> HTTP {st}")
    text = "\n".join(lines) if lines else "web: 80/443 kapalı veya yanıt yok"
    return [CommandResult(tool="web", argv=["web-probe", host], returncode=0,
                          stdout=text, stderr="", duration=0.0)]


def parse(results: list[CommandResult], report: ScanReport) -> None:
    text = "\n\n".join(r.combined for r in results)
    report.raw_outputs["web"] = text
    if results and results[0].tool == "web:dry":
        return
    target = report.target

    web_lines = [ln for ln in text.splitlines() if ln.startswith("PORT ")]
    if web_lines:
        report.add(Finding(
            title="HTTP/HTTPS servisi açık (web yüzeyi)",
            severity=Severity.INFO, target=target, source="web",
            control_id="web.surface",
            description="DC/host üzerinde web servisi var; sabit AD port taraması "
                        "bunu kaçırabilir. IIS/uygulama ve ADCS web enrollment buradan gelir.",
            evidence="\n".join(web_lines),
            mitre="T1595.003",
            poc=f"curl -sik http://{target}/   ;  curl -sik https://{target}/",
            escalation="certsrv/CES açıksa ESC8 relay; uygulama varsa ayrı web testi."))

    # ADCS web enrollment (ESC8) / CES-CEP erişilebilir mi?
    enroll = [ln for ln in text.splitlines()
              if "web enrollment" in ln.lower() and "-> HTTP" in ln]
    ces = [ln for ln in text.splitlines()
           if ("CES" in ln or "CEP" in ln) and "-> HTTP" in ln]
    if enroll:
        report.add(Finding(
            title="ADCS web enrollment (certsrv) erişilebilir — ESC8 relay yüzeyi",
            severity=Severity.HIGH, target=target, source="web",
            control_id="adcs.esc8.web", verification="tool_reported",
            reference="ADCS ESC8 (NTLM relay -> certificate)",
            mitre="T1649",
            description="HTTP(S) web enrollment endpoint'i yanıt veriyor. Coercion "
                        "(PetitPotam/PrinterBug) ile zorlanan makine/DC auth'u buraya "
                        "relay edilerek sertifika alınır -> PKINIT -> DCSync (DA).",
            evidence="\n".join(enroll),
            remediation="Web enrollment'ta EPA (Extended Protection) + HTTPS zorunlu kıl; "
                        "gerekmiyorsa certsrv rolünü kaldır; RPC coercion yüzeylerini kapat.",
            poc=f"certipy find -u <user>@<dom> -p <pass> -dc-ip {target} -stdout | grep -i 'Web Enrollment'",
            escalation="ntlmrelayx.py -t http://<CA>/certsrv/certfnsh.asp -smb2support "
                       "--adcs --template DomainController  +  coerce (PetitPotam/printerbug) "
                       "-> certipy auth -pfx DC\\$.pfx -> secretsdump -just-dc (krbtgt=DA)."))
    if ces:
        report.add(Finding(
            title="ADCS CES/CEP enrollment web servisi erişilebilir",
            severity=Severity.MEDIUM, target=target, source="web",
            control_id="adcs.ces", verification="tool_reported",
            reference="ADCS CES/CEP (Certificate Enrollment Web Services)",
            mitre="T1649",
            description="Certificate Enrollment Policy/Service endpoint'i canlı. "
                        "HTTP(S) üzerinden kayıt sağlar; EPA yoksa NTLM relay (ESC8 varyantı) "
                        "hedefi olabilir.",
            evidence="\n".join(ces),
            remediation="CES/CEP üzerinde Channel Binding/EPA zorunlu kıl; kullanılmıyorsa kaldır.",
            poc=f"curl -sik https://{target}/ADPolicyProvider_CEP_Kerberos/service.svc",
            escalation="EPA kapalıysa: coerce + ntlmrelayx -> CES endpoint -> sertifika."))


# ---------------------------------------------------------------------------
from ..registry import ScanContext, ScanModule  # noqa: E402


def _run(ctx: ScanContext) -> list[CommandResult]:
    return scan(ctx.target, timeout=ctx.timeout, dry_run=ctx.dry_run)


MODULE = ScanModule(
    name="web",
    label="HTTP/HTTPS + ADCS web enrollment (ESC8) / CES-CEP tespiti",
    run=_run,
    parse=parse,
    requires_creds=False,
    optin=False,  # pasif, varsayılan taramada çalışır
)

"""PoC/escalation komutlarındaki placeholder'ları gerçek değerlerle doldurur.

Bilinen bir kimlik (spray/relay/reuse/cli ile bulunmuş) varsa, bulgulardaki
`<user>`, `<pass>`, `<domain>`, `<dc>` gibi yer tutucuları doğrudan kopyala-yapıştır
çalışır komutlara çevirir. Parola shell için tek tırnakla sarılır; yalnızca NT hash
biliniyorsa `-p <pass>` otomatik `-H <hash>`'e döner.

`config.REDACT` açıkken HİÇBİR gerçek değer yazılmaz (yer tutucular korunur).
"""

from __future__ import annotations

from .findings import Credential, ScanReport


def _shq(s: str) -> str:
    """Değeri POSIX shell için tek tırnakla güvenli biçimde sarar."""
    return "'" + s.replace("'", "'\\''") + "'"


def _best_cred(report: ScanReport) -> Credential | None:
    """PoC'leri doldurmak için en uygun kimliği seçer.

    Öncelik: parola (hash değil) > admin > domain'i olan. Böylece çoğu PoC'teki
    `-p <pass>` doğrudan doldurulur.
    """
    creds = [c for c in report.credentials if c.secret]
    if not creds:
        return None
    creds.sort(key=lambda c: (c.kind != "password", not c.admin, not c.domain))
    return creds[0]


def _subst(text: str, cred: Credential, domain: str, dc: str) -> str:
    if not text:
        return text
    user = cred.username
    t = text
    # Birleşik token önce (yoksa <user> ve <domain> parçalı bozulur)
    if user and domain:
        t = t.replace("<user>@<domain>", f"{user}@{domain}")
    if cred.kind == "nthash":
        # Pass-the-hash: -p <pass> yerine -H <hash>
        t = t.replace("-p <pass>", f"-H {cred.secret}")
        t = t.replace("-p <password>", f"-H {cred.secret}")
        for tok in ("<hash>", "<nt>", "<nthash>"):
            t = t.replace(tok, cred.secret)
    else:
        pw = _shq(cred.secret)
        t = t.replace("<pass>", pw).replace("<password>", pw)
    if user:
        t = t.replace("<user>", user)
    if domain:
        t = t.replace("<domain>", domain).replace("<corp.local>", domain)
    if dc:
        t = t.replace("<dc>", dc)
    return t


def fill(report: ScanReport) -> None:
    """Rapordaki bulguların poc/escalation alanlarını bilinen kimlikle doldurur.

    Idempotent: doldurulan token kaybolduğu için birden çok kez çağrılabilir
    (modül bittikçe + rapor yazımından önce).
    """
    from . import config
    if config.REDACT:
        return
    cred = _best_cred(report)
    if cred is None:
        return
    domain = cred.domain or report.domain or ""
    dc = (f"{report.dc_name}.{report.domain}".lower()
          if report.dc_name and report.domain else (report.dc_name or ""))
    for f in report.findings:
        f.poc = _subst(f.poc, cred, domain, dc)
        f.escalation = _subst(f.escalation, cred, domain, dc)

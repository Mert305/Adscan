"""Yazılabilir GPO istismarı (opt-in).

Owned kimlik bir GPO üzerinde yazma hakkına sahipse (BloodHound GPO kenarı:
GenericAll/GenericWrite/WriteDacl/Owner), o GPO'ya bağlı tüm OU'lardaki makine/
kullanıcılarda zamanlanmış görev (immediate task) ile kod çalıştırılabilir —
genelde SYSTEM. Bu modül toplanan BloodHound grafiğinden yazılabilir GPO'ları
bulur ve pygpoabuse/SharpGPOAbuse komutunu HAZIR üretir.

Yalnız tespit + plan (kod çalıştırmak ayrı araç + --active-attacks ister).
"""

from __future__ import annotations

from ..findings import Finding, ScanReport, Severity
from ..runner import CommandResult


def scan(ctx, *, timeout=120):
    # Veri BloodHound grafiğinden gelir; komut çalıştırmaz (tespit/plan).
    return [CommandResult(tool="gpo:analyze", argv=[], returncode=0, stdout="",
                          stderr="", duration=0.0)]


def _run(ctx) -> list[CommandResult]:
    return scan(ctx, timeout=ctx.timeout)


def parse(results: list[CommandResult], report: ScanReport) -> None:
    try:
        from .. import bhpath
    except ImportError:
        return
    g = bhpath.load_graph(report.outdir)
    if not g.nodes:
        return
    # Owned principal(ler)in SID'leri
    names = {c.username.lower() for c in report.credentials if c.username}
    names |= {u.lower() for u in report.users if u}
    sids = set()
    for n in names:
        sid = g.name2sid.get(n) or g.name2sid.get(n.split("@", 1)[0])
        if sid:
            sids.add(sid)
    if not sids:
        return
    fd = bhpath.first_degree_control(g, sids)
    gpos = [(r, name) for (r, name, t) in fd if (t or "").upper() == "GPO"]
    if not gpos:
        return
    dom = report.domain or "<domain>"
    ev = "\n".join(f"{r}  ->  {name}" for r, name in gpos[:20])
    report.add(Finding(
        title=f"Yazılabilir GPO: {len(gpos)} GPO üzerinde kontrol — kod çalıştırma (SYSTEM)",
        severity=Severity.CRITICAL, target=report.target, source="gpo",
        control_id="gpo.writable", mitre="T1484.001",
        reference="GPO Abuse (immediate scheduled task)",
        description="Owned kimlik bir GPO'yu değiştirebiliyor. GPO'ya bağlı OU'lardaki "
                    "makine/kullanıcılarda zamanlanmış görev enjekte edilerek (SYSTEM) kod "
                    "çalıştırılabilir — DC'ye bağlı GPO ise doğrudan domain ele geçirme.",
        evidence=ev,
        remediation="GPO üzerindeki yazma haklarını (ACL) yalnız GPO yöneticileriyle sınırla.",
        poc="BloodHound: GPO -> 'Affected Objects'; hangi OU'lara bağlı olduğunu gör.",
        escalation=(f"pygpoabuse '{dom}' -u <user> -p <pass> -gpo-id <GUID> "
                    "-command 'net localgroup administrators <user> /add'  (ya da reverse shell)\n"
                    "Alternatif (Windows): SharpGPOAbuse --AddComputerTask ... ; "
                    "ardından 'gpupdate /force' beklenir veya tetiklenir.")))


# ---------------------------------------------------------------------------
from ..registry import ScanModule  # noqa: E402

MODULE = ScanModule(
    name="gpo",
    label="yazılabilir GPO istismarı (BloodHound, opt-in)",
    run=_run,
    parse=parse,
    requires_creds=True,
    optin=True,
)

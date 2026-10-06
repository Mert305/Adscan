"""Zafiyet/bulgu veri modeli ve risk seviyeleri."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Risk seviyeleri (büyük = daha kritik)."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return {
            Severity.INFO: "INFO",
            Severity.LOW: "LOW",
            Severity.MEDIUM: "MEDIUM",
            Severity.HIGH: "HIGH",
            Severity.CRITICAL: "CRITICAL",
        }[self]


@dataclass
class Credential:
    """Ele geçirilmiş/doğrulanmış bir kimlik bilgisi (parola veya NT hash)."""

    username: str
    secret: str  # açık parola ya da NT hash
    kind: str = "password"  # "password" | "nthash"
    domain: str = ""
    source: str = ""  # hangi modül: spray/relay/...
    host: str = ""  # doğrulandığı host (reuse için)
    admin: bool = False  # bu host'ta yerel admin (Pwn3d) mi?

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.domain.lower(), self.username.lower(), self.secret)

    def display_secret(self) -> str:
        """config.REDACT açıksa maskeli, değilse açık değer."""
        from . import config

        if not config.REDACT:
            return self.secret
        if self.kind == "nthash":
            return self.secret[:6] + "…" if len(self.secret) > 6 else "***"
        return "***"

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "domain": self.domain,
            "secret": self.display_secret(),
            "kind": self.kind,
            "source": self.source,
            "host": self.host,
            "admin": self.admin,
        }


@dataclass
class Finding:
    """Tek bir bulgu/zafiyet."""

    title: str
    severity: Severity
    target: str
    source: str  # hangi modül: nmap/nxc-smb/nxc-ldap/windapsearch
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    reference: str = ""  # CVE / teknik adı
    poc: str = ""  # kullanıcının bulguyu DOĞRULAYABİLECEĞİ komut
    escalation: str = ""  # bu bulgudan ne çıkabilir / nasıl yükseltilir
    mitre: str = ""  # MITRE ATT&CK teknik id(leri), ör. "T1558.003"

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity.label,
            "target": self.target,
            "source": self.source,
            "description": self.description,
            "evidence": self.evidence.strip(),
            "remediation": self.remediation,
            "reference": self.reference,
            "poc": self.poc,
            "escalation": self.escalation,
            "mitre": self.mitre,
        }


@dataclass
class ScanReport:
    """Bir tarama oturumunun tüm sonuçları."""

    target: str
    findings: list[Finding] = field(default_factory=list)
    raw_outputs: dict[str, str] = field(default_factory=dict)  # modül -> ham çıktı
    errors: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)  # keşfedilen kullanıcı adları
    credentials: list[Credential] = field(default_factory=list)
    domain: str = ""  # otomatik tespit edilen AD domain (ör. corp.local)
    dc_name: str = ""  # otomatik tespit edilen DC hostadı (ör. DC01)
    domain_admin: bool = False  # zincir Domain Admin'e ulaştı mı? (krbtgt/DCSync)
    outdir: str = "adscan-reports"  # loot/çıktı klasörü (bloodhound vb. konumları için)
    da_members: list[str] = field(default_factory=list)  # Domain Admins üye adları (korelasyon)
    sessions: dict = field(default_factory=dict)  # host -> [oturum açmış kullanıcılar] (korelasyon)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_error(self, msg: str) -> None:
        self.errors.append(msg)

    def add_credential(self, cred: Credential) -> None:
        """Kimliği ekler (aynı domain+user+secret ikilemini tekrarlamaz)."""
        if any(c.key == cred.key for c in self.credentials):
            # Varsa admin/host bilgisini zenginleştir
            for c in self.credentials:
                if c.key == cred.key:
                    c.admin = c.admin or cred.admin
                    c.host = c.host or cred.host
            return
        self.credentials.append(cred)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.severity, reverse=True)

    def count_by_severity(self) -> dict[str, int]:
        counts = {s.label: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.label] += 1
        return counts

    def has_actionable(self) -> bool:
        """MEDIUM ve üzeri bulgu var mı? (bildirim tetikleyici)"""
        return any(f.severity >= Severity.MEDIUM for f in self.findings)

    def risk_score(self) -> int:
        """0-100 arası birleşik risk puanı (yönetici özeti için tek kaynak).

        Domain Admin elde edildiyse tam ele geçirme = 100. Aksi halde seviye
        ağırlıklarının toplamı 100'de kırpılır.
        """
        if self.domain_admin:
            return 100
        weights = {
            Severity.CRITICAL: 40, Severity.HIGH: 15,
            Severity.MEDIUM: 5, Severity.LOW: 1, Severity.INFO: 0,
        }
        return min(100, sum(weights[f.severity] for f in self.findings))

    def risk_label(self) -> str:
        """Risk puanını okunur etikete çevirir."""
        s = self.risk_score()
        if self.domain_admin or s >= 80:
            return "KRİTİK"
        if s >= 50:
            return "YÜKSEK"
        if s >= 20:
            return "ORTA"
        if s > 0:
            return "DÜŞÜK"
        return "TEMİZ"

    def top_findings(self, n: int = 3) -> list[Finding]:
        """En kritik n bulgu (yönetici özeti/rapor başı için)."""
        return self.sorted_findings()[:n]

    def remediation_plan(self) -> list[dict]:
        """"Önce bunu yap" düzeltme planı (D).

        Aynı çözümü (remediation) paylaşan bulguları gruplar ve (en yüksek etki,
        sonra kapsadığı bulgu sayısı) sırasına koyar — tek bir düzeltmenin kaç
        bulguyu/ne kadar riski kapattığını gösterir; savunan için somut
        önceliklendirme. INFO ve çözümü olmayan bulgular atlanır.
        """
        groups: dict[str, dict] = {}
        for f in self.findings:
            rem = (f.remediation or "").strip()
            if not rem or f.severity <= Severity.INFO:
                continue
            g = groups.get(rem)
            if g is None:
                g = groups[rem] = {
                    "action": rem, "_sev": f.severity, "count": 0,
                    "references": set(), "targets": set(), "findings": [],
                }
            g["_sev"] = max(g["_sev"], f.severity)
            g["count"] += 1
            if f.reference:
                g["references"].add(f.reference)
            if f.target:
                g["targets"].add(f.target)
            g["findings"].append(f.title)
        plan = [{
            "action": g["action"],
            "severity": g["_sev"].label,
            "_sev": int(g["_sev"]),
            "count": g["count"],
            "references": sorted(g["references"]),
            "targets": sorted(g["targets"]),
            "findings": g["findings"],
        } for g in groups.values()]
        plan.sort(key=lambda x: (x["_sev"], x["count"]), reverse=True)
        for item in plan:
            item.pop("_sev", None)
        return plan

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "domain": self.domain,
            "dc_name": self.dc_name,
            "domain_admin": self.domain_admin,
            "risk_score": self.risk_score(),
            "risk_label": self.risk_label(),
            "hosts": self.hosts,
            "users": self.users,
            "summary": self.count_by_severity(),
            "remediation_plan": self.remediation_plan(),
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "credentials": [c.to_dict() for c in self.credentials],
            "errors": self.errors,
        }

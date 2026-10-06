"""Modül kayıt (registry) deseni + tarama bağlamı.

Önceden `cli.py` her modülü elle, farklı imzalarla çağırıyordu. Bu desende:

* `ScanContext`   — tüm tarama parametrelerini tek nesnede taşır (imza dağınıklığı biter).
* `ScanModule`    — bir modülü (ad + run + parse) deklaratif olarak tanımlar.
* `all_modules()` — kayıtlı tüm modülleri toplar.

Yeni bir modül eklemek için: ilgili dosyada bir `ScanModule(...)` tanımlayıp
`all_modules()` listesine eklemek yeterli — orkestrasyon kodu değişmez.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from .findings import ScanReport
from .runner import CommandResult


@dataclass
class ScanContext:
    """Bir tarama oturumunun tüm girdileri."""

    target: str
    username: str | None = None
    password: str | None = None
    nthash: str | None = None
    domain: str | None = None
    timeout: int = 600
    dry_run: bool = False
    outdir: str = "adscan-reports"  # loot/çıktı klasörü (kerberoast hash'leri vb.)
    use_kerberos: bool = False  # -k: Kerberos auth (ccache / FQDN gerekir)
    full: bool = False  # --full: kapsamlı/gürültülü ek modüller (spider_plus vb.) açık
    full_ports: bool = False  # --full-ports / --full: nmap'te önce tam-TCP (-p-) keşfi yap
    checkpoint: object | None = None

    # --- password spraying (opt-in, aktif) ---
    spray_userlist: str | None = None  # kullanıcı adı listesi (dosya)
    spray_namelist: str | None = None  # "Ad Soyad" listesi (dosya) -> kullanıcı adı üret
    spray_users: list[str] | None = None  # doğrudan verilmiş kullanıcılar
    spray_passwords: list[str] | None = None  # denenecek parolalar
    spray_delay: float = 0.0  # her parola turu arası bekleme (sn)
    spray_force: bool = False  # kilitlenme güvenlik kontrolünü atla (TEHLİKELİ)

    # --- aktif ağ saldırıları (opt-in: poisoning/relay) ---
    active_attacks: bool = False  # Responder/mitm6/ntlmrelayx planı/çalıştırması
    launch: bool = False  # planı sadece göster (False) yoksa gerçekten başlat (True)
    interface: str | None = None  # Responder/mitm6 için ağ arayüzü
    listener_ip: str | None = None  # relay/listener IP
    relay_targets: str | None = None  # relay hedef(ler)i (IP/CIDR/dosya)
    adcs_ca_url: str | None = None  # ESC8 için CA web enrollment URL'i
    adcs_exploit: bool = False  # --adcs-exploit: ESC1 bulunursa otomatik cert+PKINIT dene
    capture_seconds: int = 120  # aktif yakalama penceresi (sn)

    # --- credential reuse / yanal hareket (opt-in, aktif; 2. aşama) ---
    reuse_targets: str | None = None  # kimliklerin deneneceği host'lar (IP/CIDR/dosya)
    found_credentials: list = field(default_factory=list)  # 1. aşamadan gelen kimlikler
    shadow_target: str | None = None  # --shadow-target: shadow-cred uygulanacak hesap (boşsa BH'den seç)

    @property
    def has_auth(self) -> bool:
        return bool(self.username and (self.password is not None or self.nthash
                                      or self.use_kerberos))


def plan_modules(modules, ctx, report):
    """Filter unmet credential prerequisites before invoking any module."""
    selected = []
    report.scan_mode = "authenticated" if ctx.has_auth else "unauthenticated"
    for mod in modules:
        reason = ""
        if mod.requires_creds and not ctx.has_auth:
            reason = "Kimlik gerekli; kimliksiz taramada çalıştırılmadı"
        elif ctx.has_auth and ctx.password is None and not ctx.nthash \
                and not mod.name.startswith("nxc") and mod.name != "nmap":
            reason = "Bu adaptör yalnızca Kerberos önbelleği ile çalışmayı desteklemiyor"
        elif ctx.has_auth and ctx.password is None and mod.name == "windapsearch":
            reason = "windapsearch adaptörü parola gerektiriyor; hash aktarımı desteklenmiyor"
        if reason:
            from .assessment import record_skipped
            record_skipped(report, mod.name, reason)
        else:
            selected.append(mod)
    return selected


# Bir modülün çalıştırıcısı ctx alır, komut sonuçları döndürür.
RunFn = Callable[[ScanContext], list[CommandResult]]
# Ayrıştırıcı sonuçları alıp rapora bulgu ekler.
ParseFn = Callable[[list[CommandResult], ScanReport], None]


@dataclass
class ScanModule:
    """Tek bir tarama modülü (ör. nmap, nxc-smb)."""

    name: str  # --only ile eşleşen kısa ad
    label: str  # terminalde gösterilen açıklama
    run: RunFn
    parse: ParseFn
    requires_creds: bool = False  # kimlik olmadan anlamsızsa True
    optin: bool = False  # varsayılan pasif taramaya DAHİL DEĞİL (açıkça istenmeli)
    active: bool = False  # ağa müdahale eden aktif saldırı (ek onay gerekir)


def all_modules() -> list[ScanModule]:
    """Kayıtlı tüm modülleri döndürür (çalışma sırasına göre).

    İçe aktarmayı fonksiyon içinde yapıyoruz: modül dosyaları `registry`'yi
    import ettiği için döngüsel import'u önler.
    """
    from .modules import (
        access_scan,
        bloodhound_scan,
        bloodyAD_scan,
        certipy_scan,
        delegation_scan,
        dns_scan,
        gmsa_scan,
        gpo_scan,
        mssql_scan,
        nmap_scan,
        nxc_scan,
        relay_scan,
        reuse_scan,
        shadow_scan,
        smbmap_scan,
        spray_scan,
        tickets_scan,
        userenum_scan,
        web_scan,
        windap_scan,
        winrm_scan,
    )

    return [
        nmap_scan.MODULE,
        web_scan.MODULE,
        dns_scan.MODULE,
        nxc_scan.SMB_MODULE,
        nxc_scan.LDAP_MODULE,
        nxc_scan.VULN_MODULE,
        smbmap_scan.MODULE,
        windap_scan.MODULE,
        certipy_scan.MODULE,  # opt-in (ADCS, kimlik gerektirir)
        bloodyAD_scan.ENUM_MODULE,  # opt-in (LDAP enum: AS-REP/kerberoast/deleg, kimlik gerektirir)
        bloodyAD_scan.MODULE,  # opt-in (yazılabilir ACL privesc, kimlik gerektirir)
        bloodhound_scan.MODULE,  # opt-in (saldırı grafiği toplama, kimlik gerektirir)
        mssql_scan.MODULE,  # opt-in (MSSQL privesc, kimlik gerektirir)
        gmsa_scan.MODULE,  # opt-in (gMSA/LAPS parola okuma, kimlik gerektirir)
        access_scan.MODULE,  # opt-in (kimlik -> protokol erişim matrisi)
        delegation_scan.MODULE,  # opt-in (Kerberos delegasyon istismarı)
        gpo_scan.MODULE,  # opt-in (yazılabilir GPO istismarı, BloodHound)
        tickets_scan.MODULE,  # opt-in (overpass-the-hash / golden ticket)
        winrm_scan.MODULE,  # opt-in (WinRM yanal hareket, kimlik gerektirir)
        shadow_scan.MODULE,  # opt-in + active (shadow credentials istismarı)
        userenum_scan.MODULE,  # opt-in (kerbrute kullanıcı doğrulama; kimlik gerektirmez)
        spray_scan.MODULE,  # opt-in
        relay_scan.MODULE,  # opt-in + active
        reuse_scan.MODULE,  # opt-in + active (2. aşama)
    ]


# Modül gürültü seviyesi (OPSEC): "low" sessiz enum, "high" gürültülü/aktif.
# --quiet yalnızca "low" modülleri çalıştırır (IDS/EDR tetiklemesini azaltmak için).
_NOISE = {
    "nmap": "high",          # NSE zafiyet scriptleri + port taraması = gürültülü
    "web": "low",            # birkaç HTTP GET; sessiz
    "dns": "low",            # dig sorguları; sessiz (AXFR denemesi hariç)
    "nxc-smb": "low",
    "nxc-ldap": "low",
    "nxc-vulns": "high",     # zerologon/coerce_plus = aktif, DC'ye dokunur
    "smbmap": "low",
    "windapsearch": "low",
    "certipy": "low",
    "bloodyad": "low",
    "bloodyad-enum": "low",
    "bloodhound": "medium",  # tüm grafiği çeker = hacimli LDAP trafiği
    "mssql": "low",
    "gmsa": "low",
    "access": "low",
    "delegation": "low",
    "gpo": "low",
    "tickets": "low",
    "winrm": "low",
    "shadow": "high",  # hedef hesabın msDS-KeyCredentialLink'ini değiştirir (aktif)
    "userenum": "medium",  # kerbrute AS-REQ: kilitlemez ama KDC'de log üretir
    "spray": "high",
    "relay": "high",
    "reuse": "high",
}


def noise_of(name: str) -> str:
    """Modülün gürültü seviyesi: low | medium | high (bilinmiyorsa medium)."""
    return _NOISE.get(name, "medium")


def passive_modules() -> list[ScanModule]:
    """Varsayılan (opt-in olmayan) pasif modüller."""
    return [m for m in all_modules() if not m.optin]


def select_modules(only: set[str] | None) -> list[ScanModule]:
    """`--only` filtresine göre modülleri seçer; bilinmeyen adlar için uyarır.

    `only` None ise yalnızca pasif modüller döner — spray/relay gibi aktif
    modüller kazara çalışmaz, açıkça adıyla ya da ilgili bayrakla istenmelidir.
    """
    mods = all_modules()
    if only is None:
        return passive_modules()
    known = {m.name for m in mods}
    unknown = only - known
    if unknown:
        raise ValueError(
            f"Bilinmeyen modül(ler): {', '.join(sorted(unknown))}. "
            f"Geçerli: {', '.join(sorted(known))}"
        )
    return [m for m in mods if m.name in only]


def get_module(name: str) -> ScanModule:
    """Adıyla tek bir modül döndürür."""
    for m in all_modules():
        if m.name == name:
            return m
    raise KeyError(name)

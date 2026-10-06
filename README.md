# adscan — Active Directory Pentest Yardımcısı

> ⚠️ **Yalnızca sahibi olduğunuz ya da YAZILI test izniniz olan sistemlerde kullanın.**
> Aktif modüller (spray/poisoning/relay/escalate) ayrıca "yetkiliyim" onayı ister.

Eğitim ve yetkili sızma testi için bir orkestratör. Standart araçları (nmap,
netexec, windapsearch, certipy, bloodyAD, BloodHound, smbmap) tek komutla
çalıştırır, çıktıları ayrıştırır, risk seviyesine göre **canlı** raporlar ve
saldırı yolunu Domain Admin'e kadar izler.

## Hızlı başlangıç

```bash
python -m adscan 10.10.10.5                         # kimliksiz enum + zafiyet taraması
python -m adscan 10.10.10.5 -u user -p 'Pw!' -d corp.local
python -m adscan 10.10.10.5 --full -u user -p 'Pw!' -d corp.local   # KAPSAMLI
python -m adscan 10.10.10.5 --auto -u user -p 'Pw!' -d corp.local   # otonom -> DA
python -m adscan --check                            # araçlar kurulu mu?
```

- **`--full`** — tek komutla **maksimum kapsam**: tüm tespit modüllerini açar
  (ADCS + bloodyAD + BloodHound + MSSQL + WinRM) ve paylaşılabilir HTML üretir.
  Kimlik verilirse kimlikli modüller de çalışır; aktif ağ saldırıları yine ayrı
  bayrak + onay ister.
- **`--auto`** — otonom zincir: enum → kullanıcı çıkar → spray (kilitlenme-farkında)
  → ACL kısa-yol → Domain Admin yükseltme.
- **`--cleanup <manifest>`** — iz bırakma: aktif akışlar ortamda yaptığı her
  değişikliği (reanimation / gruba-ekleme / DCSync-hakkı) bir temizlik
  manifestine (`*.cleanup.json`) kaydeder; test sonunda bu komut otomatik
  geri-alınabilir aksiyonları geri alır, ELLE olanları talimatla listeler.

## Kapsama (ne bulur?)

- **Port/servis + NSE**: MS17-010, SMB signing, SMBv1, RDP NLA…
- **SMB/LDAP enum**: null session, kullanıcı/grup, parola politikası, RID brute,
  paylaşımlar, LAPS/gMSA okuma.
- **Kerberos**: Kerberoasting, AS-REP roasting, saat-kayması otomatik düzeltme.
  **Çevrimdışı kırma** (`--crack`): harvest edilen `$krb5tgs$`/`$krb5asrep$`
  hash'lerini hashcat (etype'a göre RC4 `-m 13100` / AES `-m 19600`·`19700`,
  AS-REP `-m 18200`) ya da john ile kırar; kırılan parolayı zincire kimlik olarak
  besler. `--auto`/`--full` otomatik kırar.
- **Delegasyon**: unconstrained, **constrained (S4U)**, **RBCD** (`--find-delegation`).
- **Ayrıcalık/hijyen**: **adminCount=1 / adminSDHolder** artığı hesaplar, AD
  **`description` alanında saklanan parolalar** (get-desc-users), parola
  gerektirmeyen hesaplar, **geri döndürülebilir şifreleme**, **parolası hiç
  dolmayan ayrıcalıklı** hesaplar, **bayat ama etkin** hesaplar, **eski krbtgt
  parolası** (golden-ticket ömrü).
- **Coercion primitifi**: **Print Spooler / PrinterBug (MS-RPRN)** ve **WebDAV
  (WebClient)** açık DC/host tespiti → relay/coerce zincirine (`--active-attacks`)
  besleme.
- **Zayıf Kerberos şifreleme**: **DES** etkin hesaplar ve **AES'siz RC4** hesapları
  (`msDS-SupportedEncryptionTypes` LDAP sorgusu) → hızlı offline kırma hedefleri.
- **NTLMv1 / LM**: izinli `LmCompatibilityLevel` tespiti (`-M ntlmv1`) → yakalanan
  auth'un NT hash'e kırılması + downgrade/relay.
- **Kimlik avı**: **GPP autologin** (SYSVOL Registry.xml), paylaşım içeriğinde
  **hassas dosya avı** (`spider_plus`, `--full`), **hesap kilitleme yok** (sınırsız spray).
- **Korelasyon**: **tiering ihlali** — bir Domain Admin'in DC-olmayan host'ta aktif
  oturumu (DA üye listesi × user-hunting) → tek adımda domain ele geçirme kısa yolu.
- **MSSQL**: geçerli kimlik, sysadmin/impersonation, **linked server** zinciri
  (`EXECUTE AT` ile yanal hareket).
- **Zafiyetler**: Zerologon, PetitPotam/coercion, MachineAccountQuota, **pre2k**,
  **PrintNightmare** (CVE-2021-1675/34527), **SMBGhost** (CVE-2020-0796),
  **SCCM/MECM** keşfi.
- **ADCS**: certipy ile ESC1–ESC16; certipy yoksa **nxc ile CA/enrollment keşfi**.
- **ACL privesc**: bloodyAD yazılabilir nesneler + **ACL kısa-yol** (DA'ya BFS),
  shadow creds / RBCD / reanimation / DCSync tespiti.
- **Yanal hareket**: credential reuse (Pwn3d), WinRM, MSSQL, secrets dump → DCSync.

## Canlı terminal arayüzü

Tarama sırasında ekranın altında yerinde güncellenen bir **dashboard** çizilir:

```
┃ ⠿ adscan [██████████░░░░░░] 6/9  01:12  · nxc-ldap 3s
┃   bulgu ✖2 ▲3 ◆1 ●0   kimlik 2   DA ✗
┃   yol [■■■□□□□] 3/7  · nxc-ldap: kerberoast sorgulanıyor…
```

Üstünde her modülün bulguları biter bitmez **kart** olarak akar; sonunda
**yönetici özeti** (risk puanı + en kritik bulgular) ve **saldırı yolu** +
"sıradaki en iyi eylem" gösterilir. TTY değilse / `NO_COLOR` ile düz metne düşer.

## Teslimat çıktıları (`adscan-reports/`)

Her tarama, paylaşılabilir ve makine-okunur çıktılar üretir:

| Dosya | İçerik |
|-------|--------|
| `*.json` / `*.md` | Tam bulgu raporu |
| `*.html` | Tek dosyalık, bağımsız HTML rapor (risk rozeti + saldırı yolu) |
| `*.navigator.json` | **MITRE ATT&CK Navigator** layer (tekniği renklendirir) |
| `*.loot.json` | Loot manifesti: kimlikler + admin erişimleri + loot dosyaları |
| `*.graph.json` | Saldırı grafiği: düğüm/kenar (saldırgan→kimlik→host→DA) |
| `*.findings.csv` | Bulgular düz tablo (SIEM/takip) |

(Ek çıktıları kapatmak için `--no-extra-reports`.)

## Engagement güvenliği

- **`--scope <dosya>`** — izinli IP/CIDR/host kapsamı; kapsam dışı hedef reddedilir.
- **`--audit-log <dosya>`** — çalıştırılan her komut zaman damgasıyla kaydedilir.
- **`--redact`** — parola/hash değerlerini çıktıda ve raporda maskeler.
- **`--resume` / `--diff`** — önceki taramayla delta.
- Spray **kilitlenme-farkındadır**; aktif saldırılar çift onay ister.

Bağımlılık yok (yalnızca Python 3.10+ standart kütüphanesi); harici CLI araçları
PATH'te olmalıdır. `python -m adscan --guide` ile adım adım metodoloji.

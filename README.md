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

- **`--full`** — tek komutla **kimliğe göre kapsam**: uygun tespit modüllerini seçer
  (ADCS + bloodyAD + BloodHound + MSSQL + WinRM) ve paylaşılabilir HTML üretir.
  Kimlik yoksa kimliksiz akış çalışır; kimlik gerektiren modüller ve Kerberoasting,
  MAQ, pre2k, noPac, SCCM gibi kimlikli alt kontroller çağrılmaz, raporda atlandı
  olarak gösterilir. Kimlik varsa desteklenen kimlikli modüller de seçilir.
  Yalnızca kullanıcı adı yeterli değildir; parola, hash veya desteklenen Kerberos
  akışı gerekir. Aktif ağ saldırıları yine ayrı bayrak + onay ister.
  `--full` otomatik parola kırmaz; bunun için ayrıca `--crack` gerekir.
  `--only` ve `--quiet` kapsamı daraltabilir. Bu mod salt okunurluk garantisi değildir.
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
  besler. `--auto` otomatik kırar; `--full` için açıkça `--crack` gerekir.
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
- **Kontrol checkpoint'i:** gerçek taramada her başarılı komutun sonucu
  `checkpoint-<hedef-kimliği>.json` dosyasına atomik olarak yazılır. Aynı hedef ve
  komut/kimlikle `--resume` kullanıldığında tamamlanan toplama kontrolleri yeniden
  çalıştırılmaz; çıktıları yeniden ayrıştırılarak rapora eklenir. Başarısız,
  erişimi reddedilen, boş sonuçlu ve dry-run kontrolleri tekrar çalıştırılır.
  `--resume` olmadan yeni tarama checkpoint'i sıfırlanır.
- Spray **kilitlenme-farkındadır**; aktif saldırılar çift onay ister.

```bash
python -m adscan 192.0.2.10 --full -u auditor --ask-pass -d lab.example
# Tarama kesildiyse aynı parametrelerle devam et:
python -m adscan 192.0.2.10 --full -u auditor --ask-pass -d lab.example --resume
```

Checkpoint dosyası ham araç çıktıları içerebilir; hassas kanıt olarak saklayın ve
paylaşılabilir HTML raporuyla birlikte dağıtmayın. Komut argümanları dosyaya
yazılmaz; kimlik/komut değişirse eski sonuç kullanılmaz. Dosya üreten kontroller
gereken çıktı dosyaları yoksa yeniden çalışır. Aktif saldırı modülleri, Kerberos
önbelleğiyle yapılan taramalar ve yönetilen çıktı dizini olmayan BloodHound nxc
toplayıcısı sonuç tekrarını kullanmaz. Checkpoint'in eski gözlem zamanı raporda
görünür; `--resume` yeni bir doğrulama taraması anlamına gelmez.

HTML raporu internet bağlantısı gerektirmeyen arama, önem derecesi/hedef/modül/
doğrulama filtreleri ve kontrol durumu filtresi içerir. Yönetici görünümü öncelikli
düzeltmeleri ve kapalı bulgu kartlarını sunar; teknik görünüm ayrıntıları açar.
Bulgu ve kanıt bağlantıları doğrudan ilgili karta gider. JavaScript kapalıyken
raporun tamamı okunabilir; etkileşimli filtreler kullanılamaz.

## Kimlik bazında test kapsamı karşılaştırması

Her tarama `execution_context` içinde çalıştıran kimliği, kimlik doğrulama türünü,
başlangıç zamanını ve istenen modülleri kaydeder. Parola/hash bu metadata'ya
eklenmez. Test rolü kullanıcı tarafından etiketlenir; Domain Admin veya denetçi
rolü kullanıcı adından tahmin edilmez. Loot içindeki kimlikler taramayı çalıştıran
kimlik olarak kabul edilmez.

```bash
python -m adscan dc.lab.example --full --context-label "Kimliksiz" --context-role anonymous
python -m adscan dc.lab.example --full -u standard --ask-pass -d lab.example --context-label "Standart kullanıcı" --context-role standard
python -m adscan dc.lab.example --full -u auditor --ask-pass -d lab.example --context-label "Denetçi" --context-role auditor

# Önceki komutların ürettiği JSON raporlarını ver; ağ taraması çalıştırılmaz:
python -m adscan --compare-reports anonymous.json standard.json auditor.json --outdir comparison-reports

# Mevcut taramayı önceki raporlarla birlikte karşılaştır:
python -m adscan dc.lab.example --full -u auditor --ask-pass -d lab.example --compare-reports anonymous.json standard.json
```

Etiket/rol veya karşılaştırma parametresi verilen taramalarda eski raporlar
otomatik silinmez. Karşılaştırma aynı hedefi gerektirir; hücreler hedef, modül ve
kontrol kimliği üzerinden eşleşir. Kaydı olmayan kontrol `not_tested`, erişimi
reddedilen kontrol `access_denied` olarak ayrı gösterilir. Eski raporlarda kimlik
metadata'sı yoksa bilinmiyor olarak belirtilir. Gözlem zamanı ve checkpoint
kullanımı her hücrede açılabilir. Durum farkı, farklı zaman/araç/kapsam nedeniyle
de oluşabilir; tek başına kimlik etkisini veya zafiyetin çözülmesini kanıtlamaz.

## Açıklanabilir etkin AD yetkileri

```bash
# Çalışan örnek; gerçek ortam değerlendirmesi değildir:
python -m adscan --acl-snapshot examples/acl-snapshot.json --outdir acl-example

# Bir tarama raporuna aynı hedefin snapshot analizini ekle:
python -m adscan dc.lab.example --full -u auditor --ask-pass -d lab.example --acl-snapshot acl-snapshot.json
```

Snapshot şeması `examples/acl-snapshot.json` içinde bulunur: principal SID'leri,
grup üyelikleri, sıralı nesne DACL'leri ve istenen hak kontrolleri. Motor şunları
değerlendirir:

- İç içe grup üyeliği, primary group, enabled/disabled ve deny-only SID'ler.
- Gerçek ACE sırası, explicit/inherited kayıtlar ve INHERIT_ONLY uygulanabilirliği.
- Allow/deny maskeleri, AD generic hak eşlemeleri, nesne sahibinin DACL hakları.
- OWNER RIGHTS ve PRINCIPAL SELF SID'leri.
- Kontrol GUID'i ve şema/property-set eşlemesi sağlandığında nesneye özgü haklar.
- SIDHistory yalnızca bu bağlamda etkinliği açıkça belirtildiğinde.

`granted`, `denied` ve `unknown` sonuçları SID/grup yolu ve eşleşen ACE ile
açıklanır. DACL mevcut nesne üzerindeki kalıtım uygulanmış tam liste olmalıdır;
parent OU ACL'lerinden kendiliğinden kalıtım üretimi yapılmaz. Eksik token/DACL,
koşullu ACE, restricted token, ayrıcalık temelli erişim ve eksik şema bağlamı
kesin sonuç üretmez. Bu, sağlanan AD DACL modeli üzerinde bir hesaplamadır;
Windows'un bütün AccessCheck / trust / claims davranışını taklit etmez. NTFS ve
paylaşım izinleri bu AD motoruyla değerlendirilmez.

RSAT olan Windows makinesinde seçilen nesnelerin DACL'lerini salt okunur toplamak
için `scripts/Export-AdscanAcl.ps1` eklendi:

```powershell
.\scripts\Export-AdscanAcl.ps1 -Server dc.lab.example -Identity auditor,standard -ObjectDN 'OU=Workstations,DC=lab,DC=example' -OutputPath acl-snapshot.json
```

Toplayıcı directory `tokenGroups` verisini kullanır; gerçek logon token'ı değildir.
Varsayılan `token_complete=false` olduğundan hesap sonuçları belirsiz kalır.
Directory üyelik modelinin test bağlamına uygunluğu doğrulanırsa
`-ConfirmDirectoryTokenModel` ile tam model olarak işaretlenebilir. SIDHistory
bulunursa bu bayrak tek başına yeterli sayılmaz. Toplayıcı RSAT/domain erişimi
gerektirir; test paketi domain üzerinde canlı toplama yapmaz.

Canlı `bloodyAD get writable --detail` sonuçları da etkin yetkiler paneline
aktarılır; bunlar `tool_reported` olarak ayrılır ve tam DACL hesabı sayılmaz.
Motorun dayandığı kurallar: [Microsoft AccessCheck](https://learn.microsoft.com/en-us/windows/win32/secauthz/how-dacls-control-access-to-an-object)
ve [AD erişim maskeleri](https://learn.microsoft.com/en-us/windows/win32/api/iads/ne-iads-ads_rights_enum).

## Rapor arayüzü

HTML raporunda genel bakış, bulgular, kapsam, kimlik karşılaştırması ve etkin
yetkiler sekmeleri bulunur. Özet kartları; kimlik/kontrol matrisi; yalnızca
farklar filtresi; yetki karar/kimlik/kanıt filtreleri; açılabilir grup ve ACE
açıklamaları; tablo sıralama; bulgu sayfalama; açık/koyu tema; görünen tabloları
CSV indirme ve yazdırma/PDF görünümü desteklenir. HTML tek dosyadır ve dış
sunucuya veri göndermez.

`python qa_browser.py`, yerel Edge ve Playwright ile örnek raporu üretip sekmeleri,
filtreleri, yetki açıklamalarını, CSV indirmeyi ve mobil görünümü doğrular.

## Kanıt ve kontrol kapsamı

JSON, HTML ve Markdown raporları kontrol kapsamını içerir. `completed` yalnızca
araç çalışmasının tamamlandığını gösterir; zafiyet yokluğu veya bütün AD'nin
kontrol edildiği anlamına gelmez. `skipped`, `access_denied`, `failed`, `unknown`
ve dry-run için `planned` durumları değerlendirmeyi eksik bırakır. Sıfır bulguya
artık `TEMİZ` etiketi verilmez.

Kapsam kayıtlarında alt kontrol kimliği, modül, hedef, durum, atlanma/hata nedeni,
gözlem zamanı ve checkpoint'ten geri yüklenme bilgisi bulunur. Kataloglanan
enumerasyon kontrolleri çalıştırılmadığında da görünür; örneğin LDAP kullanıcı
listesi tamamlanmışken gMSA kontrolünün kimlik eksikliği nedeniyle atlandığı
ayrı satırlarda gösterilir. Birleşik araç komutları komut seviyesinde izlenir;
tek komutun bütün iç kontrollerinin doğrulandığı iddia edilmez.

Bulgularda sabit parmak izi, kontrol kimliği, gözlem zamanı, nesne kimliği
(toplanmışsa), araç sürümü (biliniyorsa) ve doğrulama durumu bulunur. Eski
ayrıştırıcılar `unverified`, nesneye bağlı Certipy bulguları `tool_reported`
durumundadır; bunlar bağımsız istismar doğrulaması değildir. Aynı kaynaktan aynı
nesne ve kanıtla gelen tekrarlar tekilleştirilir. Önceki raporda olup yeni raporda
görülmeyen bulgu otomatik olarak çözülmüş sayılmaz.

```bash
python -m adscan 192.0.2.10 --full                         # kimliksiz kapsam
python -m adscan 192.0.2.10 --full -u auditor --ask-pass -d lab.example
python -m adscan 192.0.2.10 --full --dry-run               # çalıştırmadan plan
```

Bu geliştirmeler sıfır false positive veya veri sızdırmama garantisi vermez.
Maskeleme hâlâ `--redact` ile açılır; şifreli kanıt deposu ve ağ çıkışı kısıtlaması
bu sürümde eklenmemiştir.

Bağımlılık yok (yalnızca Python 3.10+ standart kütüphanesi); harici CLI araçları
PATH'te olmalıdır. `python -m adscan --guide` ile adım adım metodoloji.

### Terminal görünümü

Varsayılan `compact` görünümü kısa bulgu kartları, kanıt ve düzeltme önerisi sunar.
Canlı panel terminal genişliğine/yüksekliğine uyum sağlar; modül kuyruğu, çalışan
modüller, süre, kontrol kapsamı ve checkpoint'ten kullanılan sonuçlar görünür.
Kontrol sayaçları araç çıktısı geldikçe güncellenir; ayrıştırma tamamlandığında
nihai kapsam kaydı bunların yerini alır. Araç başarısı zafiyet yokluğu anlamına gelmez.
Paneldeki “diğer” sayısı planlanan, atlanan, belirsiz ve uygulanamaz kontrolleri
kapsar; son özet atlama nedenlerini ayrıca gösterir.

```bash
python -m adscan --terminal-preview                   # örnek veri, ağ bağlantısı yok
python -m adscan 192.0.2.10 --terminal-ui compact      # kısa kartlar (varsayılan)
python -m adscan 192.0.2.10 --terminal-ui detailed     # komut, PoC ve ayrıntılı kanıt
python -m adscan 192.0.2.10 --terminal-ui plain        # renk ve animasyon yok
```

Dosyaya/boruya yönlendirilen çıktı otomatik olarak renksiz ve animasyonsuzdur.
`NO_COLOR` renkleri kapatır; animasyonu kapatmak için `plain` seçilir.
JSON profilinde `terminal_ui` kullanılabilir. Kısa kartlar uzun kanıtları özetler;
tam içerik kaydedilen raporlarda ve `detailed` görünümünde bulunur.

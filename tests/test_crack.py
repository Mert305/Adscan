"""Çevrimdışı kırma motoru (crack.py) testleri — hashcat'e bağımlı olmadan."""

from adscan import crack
from adscan.findings import ScanReport
from adscan.runner import ToolStatus

# --- hash metadata (mod + kullanıcı) ---

def test_hash_meta_tgs_rc4():
    mode, user = crack._hash_meta(r"$krb5tgs$23$*sqlsvc$CORP.LOCAL$MSSQLSvc/x*$ab")
    assert mode == "13100" and user == "sqlsvc"


def test_hash_meta_tgs_aes256():
    mode, user = crack._hash_meta(r"$krb5tgs$18$*websvc$CORP.LOCAL$HTTP/x*$cd")
    assert mode == "19700" and user == "websvc"


def test_hash_meta_tgs_aes128():
    mode, _ = crack._hash_meta(r"$krb5tgs$17$*a$R$cifs/x*$00")
    assert mode == "19600"


def test_hash_meta_asrep():
    mode, user = crack._hash_meta(r"$krb5asrep$23$alice@CORP.LOCAL:aa11")
    assert mode == "18200" and user == "alice"


def test_hash_meta_asrep_no_etype():
    mode, user = crack._hash_meta(r"$krb5asrep$bob@CORP.LOCAL:bb22")
    assert mode == "18200" and user == "bob"


def test_hash_meta_unknown():
    assert crack._hash_meta("not-a-hash") == (None, None)


# --- hash dosyası okuma ---

def test_read_hashes_dedupes_and_filters(tmp_path):
    f = tmp_path / "kerb.txt"
    f.write_text(
        "$krb5tgs$23$*a$R$x*$11\n"
        "$krb5tgs$23$*a$R$x*$11\n"       # tekrar
        "rastgele satır\n"
        "$krb5asrep$23$b@R:22\n")
    out = crack._read_hashes([str(f), "/yok/dosya.txt"])
    assert len(out) == 2
    assert all(h.startswith("$krb5") for h in out)


# --- crack_hashes akışı ---

def test_crack_no_hashes_returns_empty(tmp_path):
    r = ScanReport(target="t", outdir=str(tmp_path))
    assert crack.crack_hashes(r) == []


def test_crack_ingests_cracked_creds(tmp_path, monkeypatch):
    # loot/kerb.txt içine gerçekçi bir TGS hash yaz
    loot = tmp_path / "loot"
    loot.mkdir()
    hline = r"$krb5tgs$23$*sqlsvc$CORP.LOCAL$MSSQLSvc/sql01*$deadbeef"
    (loot / "kerb.txt").write_text(hline + "\n")
    wl = tmp_path / "wl.txt"
    wl.write_text("Summer2026!\n")

    # hashcat'i taklit et: kuruluymuş gibi + bilinen bir eşleme döndür
    monkeypatch.setattr(crack, "resolve_tool",
                        lambda names: ToolStatus(name=names[0], available=True,
                                                 path="/usr/bin/" + names[0]))
    monkeypatch.setattr(crack, "_run_hashcat",
                        lambda *a, **k: {hline: "Summer2026!"})

    r = ScanReport(target="10.0.0.1", domain="corp.local", outdir=str(tmp_path))
    creds = crack.crack_hashes(r, wordlist=str(wl), timeout=10)
    assert len(creds) == 1
    c = creds[0]
    assert c.username == "sqlsvc" and c.secret == "Summer2026!" and c.source == "crack"
    assert any("KIRILDI" in f.title for f in r.findings)
    # kimlik rapora da eklendi (reuse/escalate kullanabilir)
    assert any(x.username == "sqlsvc" for x in r.credentials)


def test_crack_no_wordlist_records_error(tmp_path, monkeypatch):
    loot = tmp_path / "loot"
    loot.mkdir()
    (loot / "kerb.txt").write_text(r"$krb5tgs$23$*a$R$x*$11" + "\n")
    monkeypatch.setattr(crack, "default_wordlist", lambda: None)
    r = ScanReport(target="t", outdir=str(tmp_path))
    assert crack.crack_hashes(r, wordlist=None) == []
    assert any("sözlük" in e for e in r.errors)

"""Kullanıcı adı üretimi + OPSEC gürültü filtresi testleri."""

from adscan import usergen
from adscan.registry import noise_of


def test_usernames_basic_patterns():
    out = usergen.usernames_from_name("John Doe")
    assert "john.doe" in out and "jdoe" in out and "johndoe" in out
    assert "j.doe" in out and "doe.john" in out and "john" in out and "doe" in out


def test_usernames_single_token():
    assert usergen.usernames_from_name("administrator") == ["administrator"]


def test_usernames_turkish_ascii_fold():
    out = usergen.usernames_from_name("Şükrü Çağlar")
    # ş->s, ç->c, ğ->g, ü->u, ı->i
    assert "sukru.caglar" in out
    assert all(c.isascii() for u in out for c in u)


def test_usernames_middle_name_uses_first_and_last():
    out = usergen.usernames_from_name("Mary Jane Watson")
    assert "mary.watson" in out and "mwatson" in out


def test_usernames_dedupe_and_order():
    out = usergen.usernames_from_name("Al Al")  # first==last
    assert out == list(dict.fromkeys(out))  # tekrarsız, sıra korunur


def test_generate_merges_unique():
    names = ["John Doe", "Jane Doe"]
    out = usergen.generate(names)
    assert "john.doe" in out and "jane.doe" in out
    assert len(out) == len(set(out))


def test_generate_per_name_limit():
    out = usergen.generate(["John Doe"], per_name=2)
    assert out == ["john.doe", "johndoe"]


def test_load_names_skips_comments(tmp_path):
    p = tmp_path / "names.txt"
    p.write_text("# yorum\nJohn Doe\n\nJane Roe\n")
    assert usergen.load_names(str(p)) == ["John Doe", "Jane Roe"]


# --- OPSEC gürültü seviyeleri ---

def test_noise_levels():
    assert noise_of("nxc-smb") == "low"
    assert noise_of("nmap") == "high"
    assert noise_of("nxc-vulns") == "high"
    assert noise_of("bilinmeyen") == "medium"

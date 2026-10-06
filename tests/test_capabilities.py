"""capabilities — araç sürüm + nxc modül ayrıştırıcı testleri (F)."""

from adscan import capabilities as cap


def test_parse_version_basic():
    assert cap.parse_version("Nmap version 7.94SVN ( https://nmap.org )") == "7.94"
    assert cap.parse_version("NetExec 1.3.0 - ...") == "1.3.0"
    assert cap.parse_version("certipy-ad 4.8.2") == "4.8.2"
    assert cap.parse_version("") is None
    assert cap.parse_version("no digits here") is None


def test_parse_nxc_modules():
    out = (
        "[*] Loaded 42 modules\n"
        "coerce_plus          PetitPotam/DFSCoerce/... coercion\n"
        "timeroast            RID tabanlı NTP hash toplama\n"
        "nopac                CVE-2021-42278/42287\n"
        "enum_trusts          Domain/forest trust enumerasyonu\n"
        "Description          (başlık satırı, elenir)\n"
    )
    mods = cap.parse_nxc_modules(out)
    assert {"coerce_plus", "timeroast", "nopac", "enum_trusts"} <= mods
    assert "description" not in mods


def test_nxc_has_module_unknown_defaults_true(monkeypatch):
    # Modül listesi boş (tespit edilemedi) -> engelleme, 'dene'
    monkeypatch.setattr(cap, "_nxc_modules_cache", set())
    assert cap.nxc_has_module("timeroast") is True


def test_nxc_has_module_known(monkeypatch):
    monkeypatch.setattr(cap, "_nxc_modules_cache", {"coerce_plus", "timeroast"})
    assert cap.nxc_has_module("timeroast") is True
    assert cap.nxc_has_module("nopac") is False
    cap.reset_cache()

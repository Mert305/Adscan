"""Engagement profili (--profile) yükleyici testleri."""

import json

import pytest

from adscan import profile


def _write(tmp_path, data, name="p.json"):
    p = tmp_path / name
    p.write_text(json.dumps(data))
    return str(p)


def test_load_valid_profile(tmp_path):
    path = _write(tmp_path, {"target": "10.0.0.1", "domain": "corp.local",
                             "full": True, "scope": "scope.txt"})
    prof = profile.load(path)
    assert prof["target"] == "10.0.0.1" and prof["full"] is True
    assert prof["domain"] == "corp.local"


def test_unknown_key_rejected(tmp_path):
    path = _write(tmp_path, {"target": "10.0.0.1", "hedefff": "yanlis"})
    with pytest.raises(profile.ProfileError) as e:
        profile.load(path)
    assert "hedefff" in str(e.value)


def test_non_dict_rejected(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("[1,2,3]")
    with pytest.raises(profile.ProfileError):
        profile.load(str(p))


def test_missing_file(tmp_path):
    with pytest.raises(profile.ProfileError):
        profile.load(str(tmp_path / "yok.json"))


def test_invalid_json(tmp_path):
    p = tmp_path / "x.json"
    p.write_text("{ not json")
    with pytest.raises(profile.ProfileError):
        profile.load(str(p))


def test_cli_profile_sets_defaults(tmp_path):
    # Profil hedef/domain verir; CLI'de verilmezse profilden gelir
    from adscan import cli
    path = _write(tmp_path, {"target": "10.1.1.1", "domain": "lab.local"})
    parser = cli.build_parser()
    parser.set_defaults(**profile.load(path))
    ns = parser.parse_args([])  # hiç argüman yok -> profil varsayılanları
    assert ns.target == "10.1.1.1" and ns.domain == "lab.local"
    # CLI açıkça verince profili ezer
    ns2 = parser.parse_args(["10.9.9.9"])
    assert ns2.target == "10.9.9.9"

"""Kerberos saat-kayması düzeltme (krbtime) birim testleri.

Ağ gerektiren DC sorgusu yerine saf/çevrilebilir parçaları test ederiz:
FILETIME dönüşümü, NEGOTIATE paketinin biçimi, faketime ortamı üretimi.
"""

import struct

from conftest import cr  # noqa: F401  (ortak import yolu kurulumu)

from adscan import config, krbtime


def test_filetime_to_unix_known_value():
    # 2026-10-02 20:14:09 UTC civarı bir FILETIME, makul bir Unix ts'e çevrilmeli
    ft = int((1_780_000_000 + krbtime._FILETIME_EPOCH_DELTA) * 1e7)
    assert abs(krbtime._filetime_to_unix(ft) - 1_780_000_000) < 1


def test_build_negotiate_shape():
    pkt = krbtime._build_negotiate()
    # NetBIOS başlığı (4) + SMB2 header (64) + NEGOTIATE body (40) = 108
    assert len(pkt) == 4 + 104
    length = struct.unpack(">I", pkt[:4])[0] & 0x00FFFFFF
    assert length == 104
    assert pkt[4:8] == b"\xfeSMB"  # SMB2 ProtocolId


def test_faketime_env_positive_offset():
    env = krbtime.faketime_env(25205, lib="/x/libfaketime.so.1")
    assert env["LD_PRELOAD"] == "/x/libfaketime.so.1"
    assert env["FAKETIME"] == "+25205s"
    assert env["DONT_FAKE_MONOTONIC"] == "1"


def test_faketime_env_negative_offset():
    env = krbtime.faketime_env(-12, lib="/x/lib.so")
    assert env["FAKETIME"] == "-12s"


def test_faketime_env_none_without_lib(monkeypatch):
    monkeypatch.setattr(krbtime, "find_libfaketime", lambda: None)
    assert krbtime.faketime_env(100) is None


def test_set_child_env_roundtrip():
    config.set_child_env({"FAKETIME": "+5s"})
    assert config.CHILD_ENV["FAKETIME"] == "+5s"
    config.set_child_env(None)
    assert config.CHILD_ENV == {}

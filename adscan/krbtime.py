"""Kerberos saat-kayması (clock skew) otomatik düzeltme.

Kerberos, istemci ile KDC saatleri ~5 dk'dan fazla ayrışırsa bileti reddeder
(KRB_AP_ERR_SKEW). Lab/VPN ortamlarında yerel saat sık sık DC'den kayar; üstelik
bazı sanallaştırmalarda `date -s` ile elle ayar hypervisor tarafından geri alınır.

Bu modül:
  1. DC'nin saatini **kimlik gerektirmeden** okur (ham SMB2 NEGOTIATE yanıtındaki
     SystemTime alanı — yalnızca stdlib soket; ek paket yok).
  2. Yerel saatle farkı (offset) hesaplar.
  3. `libfaketime` varsa, tüm alt süreçlere (nxc/impacket/certipy/bloodyAD)
     uygulanacak bir ortam (LD_PRELOAD + FAKETIME) üretir — sistem saatine
     DOKUNMADAN yalnızca çocuk süreçler DC ile senkron görür.

Böylece kerberoast, certipy (PKINIT), shadow credentials ve `-k` akışları
kullanıcı hiç uğraşmadan çalışır.
"""

from __future__ import annotations

import glob
import os
import socket
import struct
import time

# FILETIME (1601-01-01'den bu yana 100 ns) -> Unix epoch farkı (saniye)
_FILETIME_EPOCH_DELTA = 11644473600


def _filetime_to_unix(filetime: int) -> float:
    """Windows FILETIME (100 ns tick) değerini Unix zaman damgasına çevirir."""
    return filetime / 1e7 - _FILETIME_EPOCH_DELTA


def _build_negotiate() -> bytes:
    """Minimal bir SMB2 NEGOTIATE isteği (NetBIOS başlığıyla) üretir."""
    header = (
        b"\xfeSMB"                 # ProtocolId
        + struct.pack("<H", 64)    # StructureSize
        + struct.pack("<H", 0)     # CreditCharge
        + struct.pack("<I", 0)     # Status (istekte rezerve)
        + struct.pack("<H", 0)     # Command = NEGOTIATE (0)
        + struct.pack("<H", 0)     # CreditRequest
        + struct.pack("<I", 0)     # Flags
        + struct.pack("<I", 0)     # NextCommand
        + struct.pack("<Q", 0)     # MessageId
        + struct.pack("<I", 0)     # Reserved (ProcessId)
        + struct.pack("<I", 0)     # TreeId
        + struct.pack("<Q", 0)     # SessionId
        + b"\x00" * 16             # Signature
    )
    body = (
        struct.pack("<H", 36)      # StructureSize
        + struct.pack("<H", 2)     # DialectCount
        + struct.pack("<H", 1)     # SecurityMode = SIGNING_ENABLED
        + struct.pack("<H", 0)     # Reserved
        + struct.pack("<I", 0)     # Capabilities
        + b"\x00" * 16             # ClientGuid
        + struct.pack("<Q", 0)     # ClientStartTime
        + struct.pack("<H", 0x0202)  # SMB 2.0.2
        + struct.pack("<H", 0x0210)  # SMB 2.1
    )
    msg = header + body
    return struct.pack(">I", len(msg)) + msg  # NetBIOS: tür(0)+3 bayt uzunluk


def dc_time(host: str, port: int = 445, timeout: float = 5.0) -> float | None:
    """DC'nin UTC saatini (Unix ts) SMB2 NEGOTIATE yanıtından okur; başarısızsa None."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(_build_negotiate())
            nb = _recvn(sock, 4)
            if len(nb) < 4:
                return None
            length = struct.unpack(">I", nb)[0] & 0x00FFFFFF
            data = _recvn(sock, length)
    except OSError:
        return None
    # SystemTime: SMB2 header(64) + NEGOTIATE yanıtında 40. bayt = 104, 8 bayt LE
    if len(data) < 112:
        return None
    filetime = struct.unpack("<Q", data[104:112])[0]
    if filetime == 0:
        return None
    return _filetime_to_unix(filetime)


def _recvn(sock: socket.socket, n: int) -> bytes:
    """Tam n bayt okumaya çalışır (kısa okumaları toplar)."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def probe_offset(host: str, port: int = 445, timeout: float = 5.0) -> float | None:
    """DC saati - yerel saat farkını (saniye) döndürür; ölçülemezse None."""
    t = dc_time(host, port=port, timeout=timeout)
    if t is None:
        return None
    return t - time.time()


def find_libfaketime() -> str | None:
    """Sistemdeki libfaketime.so.1 yolunu bulur (yoksa None)."""
    env_lib = os.environ.get("LIBFAKETIME_PATH")
    if env_lib and os.path.exists(env_lib):
        return env_lib
    patterns = [
        "/usr/lib/*/faketime/libfaketime.so.1",
        "/usr/lib/faketime/libfaketime.so.1",
        "/usr/local/lib/faketime/libfaketime.so.1",
        "/usr/lib*/faketime/libfaketime.so.1",
        "/opt/homebrew/lib/faketime/libfaketime.so.1",
    ]
    for pat in patterns:
        hits = glob.glob(pat)
        if hits:
            return hits[0]
    return None


def faketime_env(offset_seconds: float, lib: str | None = None) -> dict[str, str] | None:
    """Verilen offset için alt-süreç ortamı üretir; libfaketime yoksa None.

    Göreli offset ('+Ns'/'-Ns') kullanılır: gerçek saat ilerledikçe çocuğun
    gördüğü saat de ilerler, böylece tüm tarama boyunca DC ile senkron kalır.
    """
    lib = lib or find_libfaketime()
    if not lib:
        return None
    secs = int(round(offset_seconds))
    sign = "+" if secs >= 0 else "-"
    return {
        "LD_PRELOAD": lib,
        "FAKETIME": f"{sign}{abs(secs)}s",
        "DONT_FAKE_MONOTONIC": "1",
        "FAKETIME_DONT_FAKE_MONOTONIC": "1",
    }

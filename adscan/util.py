"""Modüller arası paylaşılan küçük yardımcılar.

Daha önce `grep` mantığı nmap/nxc/windap modüllerinde üç kez kopyalanmıştı.
Tek yerde toplamak (DRY) hem bakımı kolaylaştırır hem de test edilebilir
tek bir davranış sağlar.
"""

from __future__ import annotations

import os
import re


def loot_dir(outdir: str) -> str:
    """outdir/loot klasörünü döndürür (yoksa oluşturur).

    Kerberoast/AS-REP hash'leri, sertifikalar, ticket'lar gibi 'loot' dosyaları
    çalışma dizinine dağılmasın diye tek yerde toplanır.
    """
    path = os.path.join(outdir, "loot")
    try:
        os.makedirs(path, exist_ok=True)
    except OSError:
        pass
    return path


def loot_path(outdir: str, name: str) -> str:
    """Bir loot dosyası için tam yol (ör. loot_path(outdir, 'kerb.txt'))."""
    return os.path.join(loot_dir(outdir), name)


# Komut satırında kimlik bilgisi taşıyan bayraklar (redaksiyon için)
_SECRET_FLAGS = {"-p", "--password", "-H", "--hash", "--hashes"}
_SECRET_RX = re.compile(r"(\$krb5(?:tgs|asrep)\$[^\s]+)")


def grep(text: str, pattern: str, *, context: int = 0, limit: int = 25) -> str:
    """`pattern` ile eşleşen satırları (isteğe bağlı bağlam satırlarıyla) döndürür.

    Çıktıyı `limit` satırla sınırlar ki devasa tool çıktıları raporu şişirmesin.
    """
    lines = text.splitlines()
    out: list[str] = []
    rx = re.compile(pattern, re.IGNORECASE)
    for i, line in enumerate(lines):
        if rx.search(line):
            lo = max(0, i - context)
            hi = min(len(lines), i + context + 1)
            out.extend(lines[lo:hi])
    return "\n".join(out[:limit])


# "NOT VULNERABLE" / "is not vulnerable" / "non-vulnerable" gibi OLUMSUZ kuyruk.
# Bir pozitif-sinyal kelimesinin HEMEN ÖNCESİNDE geçerse, o satır zafiyeti
# DOĞRULAMIYOR demektir (yamalı sistem çıktısı). FP'nin baş nedeni budur.
_NEG_TAIL = re.compile(r"(?:\bnot|\bno|\bnon-?|n't|\bnever|\bisn)\s*$", re.IGNORECASE)


def positive_vuln_line(
    text: str,
    subject_rx: str,
    signal_rx: str = r"vulnerable|exploit success|compromised|pwned|succeeded",
) -> str | None:
    """`subject_rx` ile `signal_rx`'in AYNI satırda OLUMLU biçimde geçtiği ilk satır.

    Zafiyet tespitinde en sık FP kaynağı, aracın olumsuz çıktısındaki kelimeye
    körlemesine eşleşmektir (ör. ``zerologon.*VULNERABLE`` deseni
    ``Target is NOT vulnerable`` satırındaki "vulnerable"a takılır ve yamalı DC'yi
    "Zerologon CRITICAL" diye raporlar). Bu yardımcı, pozitif sinyalin hemen
    önündeki ``not``/``no``/``non``/``n't`` gibi olumsuzlamaları eleyerek yalnızca
    gerçekten DOĞRULANMIŞ satırları döndürür; bulunamazsa ``None``.

    Not: Yalnızca sinyalin *kendisinin* olumsuzlandığı aileler içindir
    (VULNERABLE/success). "signing is **not** required" gibi olumsuzun zafiyeti
    İFADE ETTİĞİ durumlarda KULLANMAYIN.
    """
    subj = re.compile(subject_rx, re.IGNORECASE)
    sig = re.compile(signal_rx, re.IGNORECASE)
    for line in text.splitlines():
        if not subj.search(line):
            continue
        for m in sig.finditer(line):
            pre = line[: m.start()].rstrip()
            if _NEG_TAIL.search(pre):
                continue  # "NOT vulnerable" vb. — doğrulamıyor
            return line.strip()
    return None


def redact_argv(argv: list[str]) -> list[str]:
    """Komut satırındaki parola/hash değerlerini maskeler.

    Güvenlik: dry-run çıktısı ve rapora kaydedilen 'çalışan komut' bilgisi
    düz metin parolayı sızdırmamalı. Örn. ['-p', 'Parola1'] -> ['-p', '***'].
    """
    redacted: list[str] = []
    mask_next = False
    for token in argv:
        if mask_next:
            redacted.append("***")
            mask_next = False
            continue
        if token in _SECRET_FLAGS:
            redacted.append(token)
            mask_next = True
            continue
        # -pParola gibi bitişik biçim
        for flag in ("-p", "-H"):
            if token.startswith(flag) and len(token) > len(flag):
                redacted.append(f"{flag}***")
                break
        else:
            redacted.append(token)
    return redacted


def redact_text(text: str) -> str:
    """Metin içindeki kırılabilir hash'leri (krb5tgs/krb5asrep) kısaltıp maskeler.

    Ham çıktıyı rapora koyarken tam hash'i saklamak gereksiz risktir; kanıt
    olarak hesabın roastable olduğu yeterlidir.
    """
    return _SECRET_RX.sub(lambda m: m.group(1)[:24] + "...[kısaltıldı]", text)

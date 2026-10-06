"""Ad-soyaddan AD kullanıcı adı üretimi (spray için aday listesi).

Bir engagement'ta çoğu zaman elde "Ad Soyad" listesi olur (web sitesi, LinkedIn,
e-posta imzası, OSINT) ama sAMAccountName'ler bilinmez. AD ortamlarında yaygın
adlandırma kalıpları sınırlıdır; bu modül her isimden olası kullanıcı adlarını
türetir (first.last, flast, f.last, firstl, last, …) ve spray/enum'a besler.

Saf fonksiyon: ağ gerektirmez, kolayca test edilir.
"""

from __future__ import annotations

import re
import unicodedata


def _ascii(text: str) -> str:
    """Türkçe/aksanlı karakterleri ASCII'ye indirger (ç->c, ş->s, ğ->g, ı->i …)."""
    text = text.replace("ı", "i").replace("İ", "i")
    norm = unicodedata.normalize("NFKD", text)
    out = "".join(c for c in norm if not unicodedata.combining(c))
    return out


def _clean(token: str) -> str:
    """Bir ad parçasını küçük harf + yalnızca harf/rakam."""
    return re.sub(r"[^a-z0-9]", "", _ascii(token).lower())


def usernames_from_name(full_name: str) -> list[str]:
    """'First [Middle] Last' -> yaygın sAMAccountName adaylarını (sıralı, tekrarsız) üretir."""
    parts = [p for p in re.split(r"[\s,]+", full_name.strip()) if p]
    parts = [_clean(p) for p in parts]
    parts = [p for p in parts if p]
    if not parts:
        return []
    if len(parts) == 1:
        return [parts[0]]
    first, last = parts[0], parts[-1]
    fi, li = first[0], last[0]
    cands = [
        f"{first}.{last}",    # john.doe
        f"{first}{last}",     # johndoe
        f"{fi}{last}",        # jdoe
        f"{fi}.{last}",       # j.doe
        f"{first}{li}",       # johnd
        f"{last}.{first}",    # doe.john
        f"{last}{fi}",        # doej
        f"{first}_{last}",    # john_doe
        first,                # john
        last,                 # doe
        f"{last}{first}",     # doejohn
    ]
    seen: set[str] = set()
    out: list[str] = []
    for c in cands:
        if c and c not in seen:
            seen.add(c)
            out.append(c)
    return out


def generate(names: list[str], *, per_name: int | None = None) -> list[str]:
    """Birden çok tam ad için birleşik, tekrarsız kullanıcı adı listesi.

    per_name verilirse her isimden en çok o kadar aday alınır (gürültüyü sınırlamak için).
    """
    seen: set[str] = set()
    out: list[str] = []
    for name in names:
        cands = usernames_from_name(name)
        if per_name is not None:
            cands = cands[:per_name]
        for c in cands:
            if c not in seen:
                seen.add(c)
                out.append(c)
    return out


def load_names(path: str) -> list[str]:
    """Satır başına bir 'Ad Soyad' olan dosyayı okur (# yorum, boş satır atlanır)."""
    names: list[str] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for ln in fh:
                s = ln.strip()
                if s and not s.startswith("#"):
                    names.append(s)
    except OSError:
        return []
    return names

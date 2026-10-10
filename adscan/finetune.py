"""Beyin iz loglarından (brain-trace.jsonl) fine-tune veri seti üretir.

`brain.py` her kararı JSONL olarak yazar (durum → karar → sonuç). Bu modül o izleri
bir sohbet-formatı eğitim veri setine (messages: system/user/assistant) çevirir;
böylece `adscan-brain` modeli KENDİ başarılı kararlarıyla fine-tune edilip zamanla
daha isabetli hale getirilebilir.

Varsayılan olarak yalnız "işe yarayan" örnekler alınır: LLM kaynaklı (source=ollama),
whitelist-içi bir modül seçilmiş ve o tur yeni bulgu/kimlik üretmiş ya da DA'ya
ulaşılmış kararlar. Durma (done) kararları da DA elde edildiyse olumlu örnek sayılır.

Kullanım:
    python -m adscan --brain-export-dataset adscan-reports/brain-trace.jsonl \
        --dataset-out train.jsonl
Çıktı (her satır bir örnek):
    {"messages": [{"role":"system","content":...},
                  {"role":"user","content":"{\"state\":...}"},
                  {"role":"assistant","content":"{\"next_module\":...}"}]}
Sonra (örnek, unsloth/llama-factory ile; adscan bu eğitimi ÇALIŞTIRMAZ):
    base = qwen3:8b; LoRA fine-tune; ardından `ollama create adscan-brain-ft`.
"""

from __future__ import annotations

import glob
import json
import os


def _is_useful(rec: dict) -> bool:
    """Bu iz kaydı olumlu bir eğitim örneği mi?"""
    if rec.get("source") != "ollama":
        return False  # yalnız modelin kendi (yedek olmayan) kararları
    dec = rec.get("decision") or {}
    out = rec.get("outcome") or {}
    if out.get("error"):
        return False
    if out.get("domain_admin"):
        return True  # DA'ya götüren her karar değerli
    if dec.get("next_module"):
        # modül seçimi yeni sinyal ürettiyse olumlu
        return bool(out.get("new_findings") or out.get("new_credentials"))
    # modül yok + done: yalnız DA ile olumlu (yukarıda yakalandı) -> aksi halde atla
    return False


def trace_to_example(rec: dict, system_prompt: str | None) -> dict | None:
    """Tek iz kaydını sohbet-formatı örneğe çevirir; uygun değilse None."""
    state = rec.get("state")
    dec = rec.get("decision") or {}
    if not state or not _is_useful(rec):
        return None
    assistant = {
        "next_module": dec.get("next_module"),
        "rationale": dec.get("rationale", ""),
        "confidence": dec.get("confidence", 0.0),
        "done": bool(dec.get("done")),
    }
    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user",
                     "content": json.dumps({"state": state}, ensure_ascii=False)})
    messages.append({"role": "assistant",
                     "content": json.dumps(assistant, ensure_ascii=False)})
    return {"messages": messages}


def build_dataset(trace_paths: list[str], out_path: str, *,
                  system_prompt: str | None = None,
                  include_system: bool = True) -> tuple[int, int]:
    """İz dosyalarını okuyup eğitim veri seti yazar. (örnek_sayısı, okunan_satır) döner."""
    from .brain import SYSTEM_PROMPT
    sysp = (system_prompt or SYSTEM_PROMPT) if include_system else None

    # Glob desteği: tek yol da, joker de verilebilir
    paths: list[str] = []
    for p in trace_paths:
        paths.extend(sorted(glob.glob(p)) or [p])

    written = read = 0
    seen: set[str] = set()  # aynı (state,decision) örneğini tekrar yazma
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as out:
        for path in paths:
            if not os.path.isfile(path):
                continue
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    read += 1
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    ex = trace_to_example(rec, sysp)
                    if not ex:
                        continue
                    key = json.dumps(ex["messages"][-2:], sort_keys=True,
                                     ensure_ascii=False)
                    if key in seen:
                        continue
                    seen.add(key)
                    out.write(json.dumps(ex, ensure_ascii=False) + "\n")
                    written += 1
    return written, read

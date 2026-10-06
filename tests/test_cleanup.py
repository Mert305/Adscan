"""cleanup — engagement temizliği / rollback (B).

Kayıt kuyruğu, manifest oku/yaz ve teardown (otomatik + ELLE) saf-fonksiyon
olarak test edilir; gerçek araç çalıştırılmaz (`runner` enjekte edilir).
Olumsuz yollar (boş kuyruk, bozuk manifest, ELLE aksiyon) ayrıca kapsanır.
"""

from __future__ import annotations

import json

import pytest

from adscan import cleanup
from adscan.runner import CommandResult


@pytest.fixture(autouse=True)
def _fresh_queue():
    """Her test taze bir kuyrukla başlasın (kuyruk süreç-globaldir)."""
    cleanup.reset()
    yield
    cleanup.reset()


def _ok(argv):
    return CommandResult(tool="t", argv=argv, returncode=0, stdout="success",
                         stderr="", duration=0.0)


def _fail(argv):
    return CommandResult(tool="t", argv=argv, returncode=1, stdout="",
                         stderr="denied", duration=0.0, error="yetki yok")


# ---------------------------------------------------------------------------
# record / actions / pending / reset
# ---------------------------------------------------------------------------

def test_record_appends_and_pending_tracks_done():
    a = cleanup.record("group-member", "10.0.0.1", "bob ∈ Admins",
                       "Bob gruba eklendi", module="aclgraph",
                       undo_argv=["bloodyAD", "del", "groupMember"])
    assert a.kind == "group-member"
    assert a.undo_argv == ["bloodyAD", "del", "groupMember"]
    assert a.done is False
    assert cleanup.actions() == [a]
    assert cleanup.pending() == [a]
    a.done = True
    assert cleanup.pending() == []  # geri alınan aksiyon 'pending' değil


def test_record_undo_argv_defaults_empty_and_is_copied():
    src = ["x"]
    a = cleanup.record("reanimation", "dc", "mark", "geri yüklendi", undo_argv=src)
    src.append("y")  # kaydedilen kopya dışarıdan mutasyona uğramamalı
    assert a.undo_argv == ["x"]
    b = cleanup.record("reanimation", "dc", "alex", "geri yüklendi")
    assert b.undo_argv == []  # varsayılan: ELLE


def test_reset_clears_queue():
    cleanup.record("rbcd", "h", "id", "d")
    assert cleanup.actions()
    cleanup.reset()
    assert cleanup.actions() == []


# ---------------------------------------------------------------------------
# manifest oku/yaz
# ---------------------------------------------------------------------------

def test_write_manifest_empty_queue_writes_nothing(tmp_path):
    path = tmp_path / "m.json"
    assert cleanup.write_manifest(str(path), target="10.0.0.1") is False
    assert not path.exists()  # aksiyon yoksa dosya oluşturulmaz


def test_write_then_load_roundtrip(tmp_path):
    cleanup.record("group-member", "10.0.0.1", "bob ∈ Admins", "eklendi",
                   module="aclgraph", undo_argv=["bloodyAD", "del", "groupMember"])
    cleanup.record("reanimation", "10.0.0.1", "mark", "geri yüklendi",
                   module="aclpwn")  # ELLE (undo_argv yok)
    path = tmp_path / "m.json"
    assert cleanup.write_manifest(str(path), target="10.0.0.1") is True

    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["target"] == "10.0.0.1"
    assert len(data["actions"]) == 2

    loaded = cleanup.load_manifest(str(path))
    assert [a.kind for a in loaded] == ["group-member", "reanimation"]
    assert loaded[0].undo_argv == ["bloodyAD", "del", "groupMember"]
    assert loaded[1].undo_argv == []


def test_load_manifest_missing_file_returns_empty(tmp_path):
    assert cleanup.load_manifest(str(tmp_path / "yok.json")) == []


def test_load_manifest_corrupt_json_returns_empty(tmp_path):
    path = tmp_path / "bozuk.json"
    path.write_text("{ not json", encoding="utf-8")
    assert cleanup.load_manifest(str(path)) == []


def test_load_manifest_skips_non_dict_actions(tmp_path):
    path = tmp_path / "m.json"
    path.write_text(json.dumps({"actions": ["sadece-string", {"kind": "rbcd"}]}),
                    encoding="utf-8")
    loaded = cleanup.load_manifest(str(path))
    assert len(loaded) == 1 and loaded[0].kind == "rbcd"


# ---------------------------------------------------------------------------
# teardown planı + yürütme
# ---------------------------------------------------------------------------

def test_teardown_plan_marks_auto_manual_and_done():
    auto = cleanup.record("group-member", "h", "bob", "d", undo_argv=["x"])
    manual = cleanup.record("reanimation", "h", "mark", "d")
    auto.done = True
    lines = cleanup.teardown_plan([auto, manual])
    assert "[OTO]" in lines[0] and "(geri alındı)" in lines[0]
    assert "[ELLE]" in lines[1]


def test_execute_teardown_runs_only_auto_actions():
    calls: list[list[str]] = []

    def fake_runner(argv, *, tool, dry_run=False):
        calls.append(argv)
        return _ok(argv)

    auto = cleanup.record("group-member", "h", "bob", "d", undo_argv=["del", "member"])
    manual = cleanup.record("reanimation", "h", "mark", "d")  # ELLE -> atlanır

    results = cleanup.execute_teardown([auto, manual], runner=fake_runner)
    assert calls == [["del", "member"]]           # yalnızca OTO çalıştı
    assert auto.done is True                       # başarı -> done
    assert manual.done is False
    # sonuç listesi her aksiyonu kapsar; ELLE için sonuç None
    kinds = {a.kind: r for a, r in results}
    assert kinds["reanimation"] is None
    assert kinds["group-member"] is not None


def test_execute_teardown_skips_already_done():
    calls = []

    def fake_runner(argv, *, tool, dry_run=False):
        calls.append(argv)
        return _ok(argv)

    done = cleanup.record("group-member", "h", "bob", "d", undo_argv=["x"])
    done.done = True
    cleanup.execute_teardown([done], runner=fake_runner)
    assert calls == []  # zaten geri alınmış -> tekrar çalıştırılmaz


def test_execute_teardown_failure_leaves_not_done():
    def fake_runner(argv, *, tool, dry_run=False):
        return _fail(argv)

    a = cleanup.record("group-member", "h", "bob", "d", undo_argv=["x"])
    cleanup.execute_teardown([a], runner=fake_runner)
    assert a.done is False  # başarısız geri-alma 'done' işaretlenmez


def test_execute_teardown_dry_run_does_not_mark_done():
    def fake_runner(argv, *, tool, dry_run=False):
        assert dry_run is True
        return _ok(argv)

    a = cleanup.record("group-member", "h", "bob", "d", undo_argv=["x"])
    cleanup.execute_teardown([a], runner=fake_runner, dry_run=True)
    assert a.done is False  # dry-run: plan gösterilir, değişiklik yapılmaz

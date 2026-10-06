"""util.py — grep ve kimlik redaksiyonu testleri."""

from adscan.util import grep, redact_argv, redact_text


def test_grep_basic_match():
    text = "alpha\nbeta signing:False\ngamma"
    assert grep(text, r"signing:\s*False") == "beta signing:False"


def test_grep_context_lines():
    text = "l1\nl2 MATCH\nl3"
    out = grep(text, r"MATCH", context=1)
    assert out.splitlines() == ["l1", "l2 MATCH", "l3"]


def test_grep_limit():
    text = "\n".join(f"hit {i}" for i in range(100))
    assert len(grep(text, r"hit", limit=5).splitlines()) == 5


def test_redact_argv_separate_flag():
    argv = ["nxc", "smb", "t", "-u", "admin", "-p", "Secret123", "-H", "DEADBEEF"]
    out = redact_argv(argv)
    assert "Secret123" not in out
    assert "DEADBEEF" not in out
    assert out[out.index("-p") + 1] == "***"
    assert out[out.index("-H") + 1] == "***"
    assert out[out.index("-u") + 1] == "admin"  # kullanıcı adı maskelenmez


def test_redact_argv_attached_flag():
    assert redact_argv(["-pSecret"]) == ["-p***"]


def test_redact_text_truncates_hash():
    txt = "user $krb5tgs$23$" + "A" * 200 + " tail"
    out = redact_text(txt)
    assert "A" * 200 not in out
    assert "kısaltıldı" in out

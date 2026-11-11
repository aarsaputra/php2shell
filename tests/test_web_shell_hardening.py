"""Test hardening shell/web_shell_gen.py (varian web).

Fokus keamanan, bukan estetika:
  - mode bebas (proc_open/__free__) TIDAK ikut build default
  - --allow-free-mode opt-in + peringatan stderr
  - cookie sesi HttpOnly/SameSite=Strict, Secure kondisional (HTTPS)
  - CSRF token per-session via hash_equals
  - idle timeout 900 s + rate limit login
  - login wajib POST (tanpa kredensial di URL)
  - file hasil generate mode 600 (diverifikasi, bukan diasumsikan)

Jalankan: /home/lota1337/myenv/bin/python -m pytest tests/test_web_shell_hardening.py -q
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GEN = ROOT / "shell" / "web_shell_gen.py"

sys.path.insert(0, str(ROOT / "shell"))
import web_shell_gen as wsg  # noqa: E402

PW = "test-password-audit-only"
# bcrypt cost 12 mahal; render sekali per konfigurasi lalu pakai ulang.
_CACHE: dict[bool, str] = {}


def _render(free: bool = False, variant: str = "web") -> str:
    if variant != "web":
        return wsg.render(password=PW, ttl_hours=1, variant=variant,
                          allow_free_mode=free)
    if free not in _CACHE:
        _CACHE[free] = wsg.render(password=PW, ttl_hours=1, variant="web",
                                  allow_free_mode=free)
    return _CACHE[free]


@pytest.fixture(scope="module")
def default_web() -> str:
    return _render(free=False)


@pytest.fixture(scope="module")
def free_web() -> str:
    return _render(free=True)


# ---------------------------------------------------------------- (a) free mode
def test_default_build_has_no_free_mode(default_web: str) -> None:
    """Build default tidak boleh memuat jalur eksekusi arbitrer sama sekali."""
    assert "proc_open" not in default_web
    assert "__free__" not in default_web
    assert "cbfree" not in default_web          # checkbox tidak dikirim
    assert "mode bebas" not in default_web


def test_free_mode_opt_in_contains_both(free_web: str) -> None:
    assert "proc_open" in free_web
    assert "__free__" in free_web
    assert "cbfree" in free_web
    assert 'type="checkbox"' in free_web


def test_free_mode_warns_on_stderr(capsys: pytest.CaptureFixture[str]) -> None:
    wsg.render(password=PW, ttl_hours=1, variant="web", allow_free_mode=True)
    err = capsys.readouterr().err
    assert "PERINGATAN" in err
    assert "mode bebas" in err.lower()
    assert "arbitrer" in err.lower()


def test_free_mode_warning_only_when_enabled(capsys: pytest.CaptureFixture[str]) -> None:
    wsg.render(password=PW, ttl_hours=1, variant="web", allow_free_mode=False)
    assert capsys.readouterr().err == ""


def test_free_mode_block_still_checks_csrf(free_web: str) -> None:
    """Cabang proc_open tidak boleh jadi jalan pintas melewati CSRF."""
    i = free_web.index("__free__")
    block = free_web[i:i + 600]
    assert "csrf_check()" in block
    assert "logged_in()" in block


# ------------------------------------------------------- (b) cookie hardening
def test_cookie_flags_present(default_web: str) -> None:
    assert "session_set_cookie_params" in default_web
    assert "'httponly' => true" in default_web
    assert "'samesite' => 'Strict'" in default_web
    assert "session.cookie_httponly" in default_web


def test_secure_cookie_is_conditional_not_hardcoded(default_web: str) -> None:
    """Secure hanya bila HTTPS terdeteksi — jangan hardcode true/false."""
    assert "'secure'   => $secure" in default_web
    assert "function is_https()" in default_web
    assert "$_SERVER['HTTPS']" in default_web
    # tidak boleh ada Secure yang dipaksa menyala tanpa cek kanal
    assert "'secure' => true" not in default_web
    assert "session.cookie_secure', '1'" in default_web
    i = default_web.index("session.cookie_secure', '1'")
    assert "if ($secure)" in default_web[max(0, i - 80):i]


# ------------------------------------------------------------- (c) CSRF token
def test_csrf_token_generation(default_web: str) -> None:
    assert "random_bytes(32)" in default_web
    assert "bin2hex(" in default_web
    assert "hash_equals(" in default_web
    assert "$_SESSION['csrf']" in default_web


def test_csrf_enforced_on_cmd_logout_login(default_web: str) -> None:
    assert "function csrf_check()" in default_web
    for ev in ("'cmd'", "'logout'", "'login'"):
        i = default_web.index("if ($act === " + ev + ")")
        block = default_web[i:i + 900]
        assert "csrf_check()" in block, f"aksi {ev} tidak memverifikasi CSRF"


def test_csrf_token_sent_to_client(default_web: str) -> None:
    # form login bawa hidden input t, terminal bawa meta csrf
    assert 'name="t"' in default_web
    assert 'name="csrf"' in default_web
    assert "append('t',TOKEN)" in default_web


# ------------------------------------------------------ (d) idle + rate limit
def test_idle_timeout_900s(default_web: str) -> None:
    assert "IDLE_TIMEOUT = 900" in default_web
    assert "$_SESSION['last_seen']" in default_web
    assert "session_destroy()" in default_web
    assert "idle_expired()" in default_web
    assert "idle timeout" in default_web.lower()
    assert "deny(401" in default_web


def test_login_rate_limit(default_web: str) -> None:
    assert "MAX_LOGIN_FAIL = 5" in default_web
    assert "$_SESSION['fails']" in default_web
    assert "$_SESSION['lock_until']" in default_web
    assert "429" in default_web
    assert "Retry-After" in default_web
    assert "usleep(" in default_web       # delay per percobaan gagal


# --------------------------------------------------------- (e) login POST-only
def test_login_form_is_post(default_web: str) -> None:
    i = default_web.index('<form id="f"')
    assert 'method="post"' in default_web[i:i + 160]


def test_no_credentials_in_query_string(default_web: str) -> None:
    assert "$_GET['k']" not in default_web
    assert "credentials must be POSTed" in default_web
    assert "method not allowed" in default_web


# ------------------------------------------------ (f) mode file 600 + regresi
def test_verify_mode_600_helper_kept() -> None:
    assert callable(wsg._verifikasi_600)
    assert callable(wsg._chmod_600_ketat)


def test_cli_variant_still_whitelist_only() -> None:
    cli = _render(variant="cli")
    assert "proc_open" not in cli
    assert "__free__" not in cli
    assert "WWW-Authenticate" in cli


@pytest.mark.skipif(shutil.which("php") is None, reason="php tidak tersedia")
@pytest.mark.parametrize("free", [False, True])
def test_php_lint_clean(free: bool, tmp_path: Path) -> None:
    f = tmp_path / "s.php"
    f.write_text(_render(free=free), encoding="utf-8")
    r = subprocess.run(["php", "-l", str(f)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "No syntax errors" in r.stdout + r.stderr


def test_cli_end_to_end_default_and_flagged(tmp_path: Path) -> None:
    """Uji flag nyata lewat subprocess: default bersih, --allow-free-mode memuat."""
    d1 = tmp_path / "default"
    r1 = subprocess.run([sys.executable, str(GEN), "--out", str(d1),
                         "--variant", "web", "--ttl", "1"],
                        capture_output=True, text=True, timeout=180)
    assert r1.returncode == 0, r1.stderr
    assert "PERINGATAN" not in r1.stderr
    php1 = list(d1.glob("*.php"))
    assert len(php1) == 1
    body1 = php1[0].read_text()
    assert "proc_open" not in body1 and "__free__" not in body1

    d2 = tmp_path / "free"
    r2 = subprocess.run([sys.executable, str(GEN), "--out", str(d2),
                         "--variant", "web", "--ttl", "1", "--allow-free-mode"],
                        capture_output=True, text=True, timeout=180)
    assert r2.returncode == 0, r2.stderr
    assert "PERINGATAN" in r2.stderr
    body2 = list(d2.glob("*.php"))[0].read_text()
    assert "proc_open" in body2 and "__free__" in body2


def test_generated_files_are_mode_600(tmp_path: Path) -> None:
    d = tmp_path / "perm"
    r = subprocess.run([sys.executable, str(GEN), "--out", str(d),
                        "--variant", "web", "--ttl", "1"],
                       capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, r.stderr
    targets = list(d.glob("*.php")) + list(d.glob("CREDENTIALS-*"))
    assert targets
    for p in targets:
        mode = stat.S_IMODE(p.stat().st_mode)
        assert mode == 0o600, f"{p.name} mode {oct(mode)}"

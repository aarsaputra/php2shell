"""Tes regresi shell/upshell_live.py — opt-in, auth, TTL, nama (audit P1-04/P2-01).

Semua tes OFFLINE: tidak ada target, tidak ada paket keluar. `full_chain_cmd`
dan HTTP di-mock, jadi tes membuktikan logika pagar — bukan menyerang target.

Yang dikunci:
  1. Tanpa `--allow-persistent` -> main() menolak (exit != 0) dan TIDAK
     mengangkut satu perintah pun (tidak ada penanaman webshell).
  2. Allowlist `--name`: path traversal, metakarakter shell, spasi, newline,
     nama kosong, >32 karakter ditolak; nama sah diterima apa adanya.
  3. Shell yang dihasilkan: gate TTL (`$EXPIRES`) + gate password
     (`password_verify`/`hash_equals`) MENDAHULUI eksekusi, dan
     `$_REQUEST['c']` tidak pernah dieksekusi tanpa gate itu.
  4. Password tidak pernah tercetak di jalur penolakan.

    /home/lota1337/myenv/bin/python -m pytest tests/test_upshell_live.py -q
"""

import io
import os
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

TOOLKIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if TOOLKIT not in sys.path:
    sys.path.insert(0, TOOLKIT)

from shell import upshell_live as up  # noqa: E402


def _run_main(argv):
    """Jalankan main(argv) tanpa menyentuh jaringan. (rc, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.object(up, "full_chain_cmd", side_effect=AssertionError(
            "full_chain_cmd TIDAK boleh dipanggil di jalur penolakan")), \
            mock.patch.object(up, "http_post", side_effect=AssertionError(
                "http_post TIDAK boleh dipanggil di jalur penolakan")), \
            mock.patch.object(up, "http_get", side_effect=AssertionError(
                "http_get TIDAK boleh dipanggil di jalur penolakan")):
        with redirect_stdout(out), redirect_stderr(err):
            rc = up.main(argv)
    return rc, out.getvalue(), err.getvalue()


class TestOptIn(unittest.TestCase):
    """P1-04: webshell persisten harus opt-in eksplisit."""

    def test_tanpa_allow_persistent_ditolak(self):
        rc, out, err = _run_main(["-u", "http://127.0.0.1:8093/", "--name", "s3.php"])
        self.assertNotEqual(rc, 0, "tanpa --allow-persistent skrip harus menolak")
        self.assertIn("LAB-ONLY", err.upper() + err)
        self.assertIn("--allow-persistent", err)
        self.assertIn("PERSISTEN", err)
        # tidak ada password yang di-generate/dicetak di jalur penolakan
        self.assertNotIn("PASSWORD", out)
        self.assertEqual(out.strip(), "", f"stdout harus kosong, dapat: {out!r}")

    def test_flag_allow_persistent_dikenal_parser(self):
        out = io.StringIO()
        with redirect_stdout(out), self.assertRaises(SystemExit) as ctx:
            up.main(["--help"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn("--allow-persistent", out.getvalue())


class TestValidateName(unittest.TestCase):
    """P2-01: nama diinterpolasi ke `mv g <name>` / `rm <name>`."""

    BAD = [
        "../x.php",          # path traversal
        "a;b.php",           # pemisah perintah
        "a|b.php",           # pipe
        "a b.php",           # spasi
        "x.php\n",           # newline
        "",                  # kosong
        "a" * 36 + ".php",   # > 32 karakter
        "../../etc/x.php",
        "a&b.php",
        "a$b.php",
        "a`b.php",
        "a'b.php",
        'a"b.php',
        "a<b.php",
        "a>b.php",
        "a(b).php",
        "a{b}.php",
        "a[b].php",
        "a*b.php",
        "a?b.php",
        "a~b.php",
        "a#b.php",
        "a\\b.php",           # backslash
        "/abs/x.php",
        "x.PHP",             # ekstensi harus .php huruf kecil
        ".hidden.php",       # titik pertama tidak boleh
        "a\tb.php",
        None,
    ]

    def test_nama_berbahaya_ditolak(self):
        for name in self.BAD:
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    up.validate_name(name)

    def test_nama_sah_diterima(self):
        for name in ("s3.php", "w9-1.php", "a.php", "A_b-c.d.php", "x" * 28 + ".php"):
            with self.subTest(name=name):
                self.assertEqual(up.validate_name(name), name)

    def test_pesan_penolakan_menyebut_aturan(self):
        with self.assertRaises(ValueError) as ctx:
            up.validate_name("../x.php")
        msg = str(ctx.exception)
        self.assertIn("32", msg)
        self.assertIn(".php", msg)

    def test_panjang_maksimum_32(self):
        # 32 karakter total sah secara aturan nama, tetapi tetap harus muat
        # carrier 14 byte -> carrier_check menolak (bukan AssertionError).
        name = "a" * 28 + ".php"
        self.assertEqual(len(name), 32)
        self.assertEqual(up.validate_name(name), name)
        with self.assertRaises(ValueError):
            up.carrier_check(name)
        up.carrier_check("w9-1.php")  # 8 karakter: muat `mv g w9-1.php` (13B)

    def test_main_menolak_nama_berbahaya_tanpa_jaringan(self):
        rc, out, err = _run_main(["-u", "http://127.0.0.1:8093/",
                                  "--name", "a;b.php", "--allow-persistent"])
        self.assertNotEqual(rc, 0)
        self.assertIn("DITOLAK", err)
        self.assertEqual(out.strip(), "")


class TestShellSource(unittest.TestCase):
    """P1-04: shell yang ditanam WAJIB auth + TTL."""

    def _src(self, mode="bcrypt", salt=""):
        return up.build_shell_source("HASHVALUE", 2000000000, mode=mode, salt=salt).decode()

    def test_memuat_ttl(self):
        src = self._src()
        self.assertIn("$EXPIRES = 2000000000", src)
        self.assertIn("time() > $EXPIRES", src)

    def test_memuat_pemeriksaan_password(self):
        src = self._src()
        self.assertIn("password_verify", src)
        self.assertIn("$_POST['k']", src)
        self.assertIn("http_response_code(403)", src)

    def test_fallback_sha256_tanpa_bcrypt(self):
        src = self._src(mode="sha256", salt="deadbeef")
        self.assertIn("hash_equals", src)
        self.assertIn("$SALT = 'deadbeef'", src)
        self.assertNotIn("password_verify($k", src)

    def test_tidak_ada_eksekusi_tanpa_gate(self):
        """`$_REQUEST['c']` hanya setelah gate auth (dan gate itu muncul dulu)."""
        src = self._src()
        i_gate = src.index("if (!$ok)")
        i_exec = src.index("shell_exec($_REQUEST['c'])")
        self.assertLess(i_gate, i_exec, "eksekusi mendahului gate auth")
        # tidak ada bentuk tanpa guard ala MINI_SHELL lama
        self.assertNotIn('echo shell_exec($_REQUEST[\'c\']);\n', src.split("if (!$ok)")[0])
        # hanya SATU titik eksekusi
        self.assertEqual(src.count("shell_exec("), 1)

    def test_nilai_tidak_valid_ditolak(self):
        with self.assertRaises(ValueError):
            up.build_shell_source("H", 0)
        with self.assertRaises(ValueError):
            up.build_shell_source("H", 2000000000, mode="md5")


class TestHashPassword(unittest.TestCase):
    def test_hash_dan_mode(self):
        h, mode, salt = up.hash_password("rahasia-uji")
        self.assertIn(mode, ("bcrypt", "sha256"))
        self.assertTrue(h)
        if mode == "sha256":
            self.assertTrue(salt)
            import hashlib
            self.assertEqual(h, hashlib.sha256((salt + "rahasia-uji").encode()).hexdigest())


if __name__ == "__main__":
    unittest.main()

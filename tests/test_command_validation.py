
import unittest
from lib.exploit_runner import validate_command, DEFAULT_ALLOWED_CMDS

class TestCommandValidation(unittest.TestCase):
    def test_allowed_basic(self):
        self.assertEqual(validate_command('id'), '')
        self.assertEqual(validate_command('whoami'), '')
    def test_allowed_extra(self):
        self.assertEqual(validate_command('ls', allowed_cmds=('ls',)), '')
    def test_rejected_unknown(self):
        self.assertNotEqual(validate_command('cat'), '')
    def test_rejected_empty(self):
        self.assertNotEqual(validate_command(''), '')
    def test_rejected_metachars(self):
        self.assertNotEqual(validate_command('id; id'), '')
        self.assertNotEqual(validate_command('id | grep root'), '')

    def test_rejected_command_substitution(self):
        """Audit R2-01 meminta kasus substitusi perintah secara eksplisit.

        `$` dan backtick ada di FORBIDDEN_CMD_TOKENS, tetapi bentuk NYATA yang
        dipakai penyerang harus diuji sendiri: `$(...)`, backtick, dan
        `${IFS}` (pemecah kata tanpa spasi literal).
        """
        for cmd in ("id $(whoami)", "id `whoami`", "id${IFS}id",
                    "$(/bin/id)", "whoami$(id)"):
            with self.subTest(cmd=cmd):
                why = validate_command(cmd)
                self.assertNotEqual(why, "", f"{cmd!r} lolos")
                self.assertIn("berbahaya", why)

    def test_rejected_pipeline_dan_redirect(self):
        # `id>/out/<nama>` dan varian berspasi adalah KANAL BUKTI yang sah
        # (dipakai --proof-file), jadi tidak termasuk daftar ini.
        for cmd in ("id|cat", "id || id", "id > /tmp/x", "id > /etc/passwd",
                    "id < /etc/passwd", "id \n whoami", "id\rwhoami"):
            with self.subTest(cmd=cmd):
                self.assertNotEqual(validate_command(cmd), "")

    def test_kanal_bukti_tetap_sah(self):
        """Kontrol positif: proof-file `/out/<nama>` tidak ikut diblokir.

        Nama tetap dibatasi carrier 14 byte: `whoami>/out/p1` = 14 byte pas.
        """
        for cmd in ("id>/out/p1", "id > /out/p1", "whoami>/out/p1"):
            with self.subTest(cmd=cmd):
                self.assertLessEqual(len(cmd.encode()), 14)
                self.assertEqual(validate_command(cmd), "")
        # Nama panjang melewati carrier -> ditolak karena BYTE, bukan karena
        # dianggap chaining (pesannya harus menyebut byte).
        long_ok = "whoami>/out/evidence-2"
        self.assertIn("byte", validate_command(long_ok))
    def test_rejected_args_for_id(self):
        self.assertNotEqual(validate_command('id 1000'), '')
    def test_rejected_path_traversal(self):
        self.assertNotEqual(validate_command('ls ../../etc'), '')
    def test_rejected_long_args(self):
        self.assertNotEqual(validate_command('id ' + 'A'*100), '')

if __name__ == '__main__':
    unittest.main()

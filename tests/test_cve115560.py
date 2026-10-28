"""Tes modul CVE-2026-115560 — murni (tanpa network): payload, gate, config.

Kontrak:
  - upload_progress_value menyisipkan '|' + serialized LabGadget
  - ensure_local_target menerima loopback/private, menolak public (SystemExit)
  - RaceConfig default masuk akal (sid hex, page dari URL)
  - gate lab-only TIDAK kalah oleh argumen (tidak ada flag bypass)
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from lib import cve115560 as m  # noqa: E402


class TestPayload115560(unittest.TestCase):
    def test_pipe_prefix_and_gadget(self):
        v = m.upload_progress_value("id", "p/R.txt")
        self.assertTrue(v.startswith("|"))
        self.assertIn('O:9:"LabGadget"', v)
        self.assertIn('s:2:"id"', v)
        self.assertIn('s:7:"p/R.txt"', v)

    def test_length_prefixes_accurate(self):
        import re
        v = m.upload_progress_value("uname -a", "p/O.txt")
        m1 = re.search(r's:3:"cmd";s:(\d+):"uname -a"', v)
        m2 = re.search(r's:3:"out";s:(\d+):"p/O.txt"', v)
        self.assertTrue(m1 and int(m1.group(1)) == len("uname -a"))
        self.assertTrue(m2 and int(m2.group(1)) == len("p/O.txt"))


class TestGateLabOnly(unittest.TestCase):
    def test_loopback_ok(self):
        m.ensure_local_target("http://127.0.0.1:9404/index.php")  # tak raise
        m.ensure_local_target("http://localhost:9404/")

    def test_private_ok(self):
        m.ensure_local_target("http://192.168.1.10/")
        m.ensure_local_target("http://10.0.0.5:8080/")
        m.ensure_local_target("http://172.17.0.7:9404/")

    def test_public_refused(self):
        for url in ("https://example.com/", "https://simkerja.ntbprov.go.id/",
                    "http://1.2.3.4/"):
            with self.assertRaises(SystemExit):
                m.ensure_local_target(url)


class TestRaceConfig(unittest.TestCase):
    def test_defaults(self):
        c = m.RaceConfig(url="http://127.0.0.1:9404/x.php")
        self.assertTrue(len(c.sid) == 16)
        self.assertEqual(c.page, "/x.php")
        self.assertEqual(c.cmd, "id")

    def test_page_normalized(self):
        c = m.RaceConfig(url="http://127.0.0.1/x.php", page="y.php")
        self.assertEqual(c.page, "/y.php")


if __name__ == "__main__":
    unittest.main()

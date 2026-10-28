"""Tes Caveat CVE-2026-115560 di lib.detect.

Kontrak:
  - verdict patched + upload_progress=on  → reason memuat caveat 115560
  - verdict patched + upload_progress=off → TANPA caveat (tak relevan)
  - verdict vulnerable → TANPA caveat (rantai 109619 tetap pesan utama)
Caveat tidak mengubah verdict/skor — hanya reason (informasi, bukan klaim).
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from lib.detect import Detection, _apply_caveat_115560  # noqa: E402


def _mk(verdict: str, up: str, disp: str = "off") -> Detection:
    d = Detection(url="http://ex/")
    d.verdict = verdict
    d.upload_progress = up
    d.display_errors = disp
    d.reason = "seed"
    _apply_caveat_115560(d)
    return d


class TestCaveat115560(unittest.TestCase):
    CAVEAT = "CVE-2026-115560"

    def test_patched_on_gets_caveat(self):
        d = _mk("patched", "on")
        self.assertIn(self.CAVEAT, d.reason)
        self.assertIn("serialize_handler", d.reason)
        # verdict tidak berubah — caveat bukan klaim vulnerable
        self.assertEqual(d.verdict, "patched")

    def test_patched_off_no_caveat(self):
        d = _mk("patched", "off")
        self.assertNotIn(self.CAVEAT, d.reason)

    def test_patched_unknown_no_caveat(self):
        d = _mk("patched", "unknown")
        self.assertNotIn(self.CAVEAT, d.reason)

    def test_vulnerable_no_caveat(self):
        d = _mk("vulnerable", "on")
        self.assertNotIn(self.CAVEAT, d.reason)

    def test_seed_reason_preserved(self):
        d = _mk("patched", "on")
        self.assertTrue(d.reason.startswith("seed"))


if __name__ == "__main__":
    unittest.main()

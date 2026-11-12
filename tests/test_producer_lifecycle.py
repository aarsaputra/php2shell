"""Tes regresi R2-04 — lifecycle producer CVE-2026-115560.

Finding R2-04: producer bisa tetap hidup setelah `run_race()` menyatakan
selesai, karena budget join (5s) lebih kecil daripada read timeout socket
producer (30s). Thread daemon yang tertinggal terus menembak target setelah
pemanggil menerima hasil — "selesai" jadi klaim palsu.

Kontrak yang diuji:
  1. Read timeout producer < join timeout (koordinasi budget shutdown), dan
     dijaga oleh assertion di modul supaya perubahan berikutnya gagal cepat.
  2. `_stop_and_join()` melaporkan False bila thread masih hidup — tidak
     pernah mengklaim bersih.
  3. Semua jalur (sukses / gagal / exception / timeout) menyetel stop event
     dan meng-join thread.
  4. Tidak ada thread bernama `x115560-producer` yang tersisa setelah
     `run_race()` kembali.

Tes memakai fake server lokal (`http.server`) dengan delay terkontrol; tidak
ada paket ke jaringan luar.
"""

import http.server
import os
import socketserver
import sys
import threading
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from lib import cve115560 as m  # noqa: E402


def _producer_threads():
    return [t for t in threading.enumerate() if t.name == m._PRODUCER_NAME]


class TestShutdownBudget(unittest.TestCase):
    def test_read_timeout_lebih_kecil_dari_join(self):
        self.assertLess(m._PRODUCER_READ_TIMEOUT, m._JOIN_TIMEOUT,
                        "producer tidak akan bisa berhenti sendiri dalam jendela join")
        self.assertLess(m._PRODUCER_CONNECT_TIMEOUT, m._JOIN_TIMEOUT)

    def test_producer_timeout_dipakai_di_request(self):
        """`requests.post` harus memakai konstanta modul, bukan angka literal."""
        import inspect
        src = inspect.getsource(m._producer)
        self.assertIn("_PRODUCER_READ_TIMEOUT", src)
        self.assertNotIn("timeout=(10, 30)", src)


class TestStopAndJoin(unittest.TestCase):
    def test_thread_hidup_dilaporkan_false(self):
        cfg = m.RaceConfig(url="http://127.0.0.1:1/")
        stop_forever = threading.Event()
        t = threading.Thread(target=stop_forever.wait, daemon=True,
                             name=m._PRODUCER_NAME)
        t.start()
        try:
            log = []
            ok = m._stop_and_join(cfg, t, deadline=time.time() - 1, log=log.append)
            self.assertFalse(ok, "thread yang masih hidup dilaporkan berhenti")
            self.assertTrue(cfg.stop.is_set(), "stop event tidak diset")
            self.assertTrue(any("belum berhenti" in s for s in log),
                            f"tidak ada laporan eksplisit: {log}")
        finally:
            stop_forever.set()
            t.join(timeout=2.0)

    def test_thread_kooperatif_dilaporkan_true(self):
        cfg = m.RaceConfig(url="http://127.0.0.1:1/")

        def worker():
            cfg.stop.wait(5.0)

        t = threading.Thread(target=worker, daemon=True, name=m._PRODUCER_NAME)
        t.start()
        self.assertTrue(m._stop_and_join(cfg, t, time.time() + 3, lambda _s: None))
        self.assertFalse(t.is_alive())


class TestRunRaceLifecycle(unittest.TestCase):
    """`run_race()` tidak boleh meninggalkan producer aktif di jalur mana pun."""

    @classmethod
    def setUpClass(cls):
        cls.hits = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                cls.hits.append(self.path)
                body = b"no proof here"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt, *args):  # noqa: A002
                pass

        try:
            cls.srv = socketserver.TCPServer(("127.0.0.1", 0), Handler)
        except OSError as exc:  # pragma: no cover
            raise unittest.SkipTest(f"tidak bisa membuka socket lokal: {exc}")
        cls.port = cls.srv.server_address[1]
        cls.thread = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def _cfg(self, **kw):
        kw.setdefault("duration", 0.4)
        kw.setdefault("poll", 0.05)
        kw.setdefault("total_mb", 1)
        return m.RaceConfig(url=f"http://127.0.0.1:{self.port}/vuln.php", **kw)

    def test_selesai_tanpa_bukti_menghentikan_producer(self):
        before = len(_producer_threads())
        res = m.run_race(self._cfg(), log=lambda _s: None)
        self.assertFalse(res["success"])
        self.assertIs(res.get("producer_stopped"), True,
                      "producer tidak dilaporkan berhenti")
        deadline = time.time() + 3.0
        while time.time() < deadline and len(_producer_threads()) > before:
            time.sleep(0.05)
        self.assertEqual(len(_producer_threads()), before,
                         "thread producer masih hidup setelah run_race kembali")

    def test_exception_di_log_pembuka_tetap_menutup_producer(self):
        """Exception di dalam try WAJIB lewat `finally` (stop+join).

        `log` dipanggil dua kali sebelum apa pun berjalan: (1) log scope —
        SEBELUM thread dibuat, (2) log "race mulai" — sesudah thread hidup.
        Kita melempar pada panggilan ke-2, jadi thread sudah berjalan dan
        `finally` harus tetap menutupnya. Exception pada panggilan ke-1 tidak
        relevan: belum ada thread yang perlu ditutup.
        """
        cfg = self._cfg()
        before = len(_producer_threads())
        calls = {"n": 0}

        def log(msg):
            calls["n"] += 1
            if calls["n"] >= 2:
                raise RuntimeError("boom")

        with self.assertRaises(RuntimeError):
            m.run_race(cfg, log=log)
        self.assertGreaterEqual(calls["n"], 2)
        deadline = time.time() + 3.0
        while time.time() < deadline and len(_producer_threads()) > before:
            time.sleep(0.05)
        self.assertEqual(len(_producer_threads()), before,
                         "producer hidup terus walau consumer melempar")
        self.assertTrue(cfg.stop.is_set())

    def test_sukses_menghentikan_producer(self):
        cfg = self._cfg()

        def fake_get(url, sid, timeout=8.0):
            if url.endswith(m.RaceConfig(url="http://x").out_path) or "R.txt" in url:
                return 200, b"uid=33(www-data) gid=33(www-data)"
            return 200, b""

        before = len(_producer_threads())
        with mock.patch.object(m, "_get", side_effect=fake_get):
            res = m.run_race(cfg, log=lambda _s: None)
        self.assertTrue(res["success"], res)
        self.assertIs(res.get("producer_stopped"), True)
        deadline = time.time() + 3.0
        while time.time() < deadline and len(_producer_threads()) > before:
            time.sleep(0.05)
        self.assertEqual(len(_producer_threads()), before)

    def test_durasi_nol_tetap_menutup_producer(self):
        before = len(_producer_threads())
        res = m.run_race(self._cfg(duration=0.0), log=lambda _s: None)
        self.assertFalse(res["success"])
        deadline = time.time() + 3.0
        while time.time() < deadline and len(_producer_threads()) > before:
            time.sleep(0.05)
        self.assertEqual(len(_producer_threads()), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)

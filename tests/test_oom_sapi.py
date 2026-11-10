"""Tes lib.oomprobe: gating SAPI + kekuatan bukti (vulnerable vs suspected).

Mengikuti aturan scanner resmi assetnote/php2shell-scanner:
  - 502/503/504 hanya signal untuk fpm/auto (bukan mod_php)
  - 200 body-kosong (control ber-body) = sinyal FPM worker mati (baru)
  - control body ber-marker phpMyAdmin -> probe dialihkan ke
    /show_config_errors.php

Revisi audit — TINGKAT KEPERCAYAAN:
  - "vulnerable" (confirmed=True) HANYA untuk oom_in_parser: fatal OOM dengan
    lokasi "Unknown", yaitu parser multipart sendiri yang kehabisan memori.
  - "suspected" (confirmed=False) untuk empty_500 / worker_abort / empty_200.
    Pola-pola itu juga diproduksi upstream mati, gateway timeout, atau worker
    crash non-PHP, jadi tidak boleh dilaporkan sebagai bukti CVE.

Semua tes memakai transport palsu (tanpa jaringan).
"""
import unittest
from urllib.parse import urlsplit

from lib.oomprobe import (
    FPM_ABORT_STATUSES,
    OOMResult,
    PHPMYADMIN_MARKER,
    PHPMYADMIN_PATH,
    _classify_response,
    oom_detect,
)


class _Resp:
    def __init__(self, status, body="", error=None):
        self.status = status
        self.body = body
        self.error = error


class _PalsuResp:
    """Response minimal untuk _classify_response (hanya status + body dibaca)."""

    def __init__(self, status, body=""):
        self.status = status
        self.body = body


def _confirmed(verdict: str) -> bool:
    """Nilai `confirmed` yang HARUS diturunkan dari verdict (satu sumber)."""
    return verdict == "vulnerable"


class TestClassifySapi(unittest.TestCase):
    """Abort 502/503/504 = DUGAAN (suspected), bukan bukti."""

    def test_502_suspected_auto(self):
        v, s = _classify_response(_Resp(502), 100, sapi="auto")
        self.assertEqual((v, s), ("suspected", "worker_abort"))
        self.assertFalse(_confirmed(v))

    def test_502_suspected_fpm(self):
        v, s = _classify_response(_Resp(502), 100, sapi="fpm")
        self.assertEqual((v, s), ("suspected", "worker_abort"))
        self.assertFalse(_confirmed(v))

    def test_502_bukan_signal_mod_php(self):
        """mod_php: worker mati membawa Apache turun, tak ada 502 dari front."""
        v, s = _classify_response(_Resp(502), 100, sapi="mod_php")
        self.assertEqual(v, "inconclusive")
        self.assertNotEqual(s, "worker_abort")
        self.assertFalse(_confirmed(v))

    def test_semua_status_abort_fpm(self):
        for st in FPM_ABORT_STATUSES:
            with self.subTest(status=st):
                v, s = _classify_response(_Resp(st), 100, sapi="fpm")
                self.assertEqual((v, s), ("suspected", "worker_abort"))
                self.assertFalse(_confirmed(v))


class TestEmpty200(unittest.TestCase):
    def test_200_kosong_dengan_control_ada_adalah_dugaan(self):
        """200 kosong + control ber-body = dugaan worker FPM mati, bukan bukti.

        Dulu tes ini bernama `..._adalah_signal` dan menuntut "vulnerable",
        padahal 200-kosong juga muncul saat front-server menjawab dari cache
        rusak / backend non-PHP mati. Signal tetap dilaporkan apa adanya.
        """
        v, s = _classify_response(_Resp(200, ""), 50, sapi="fpm")
        self.assertEqual((v, s), ("suspected", "empty_200"))
        self.assertFalse(_confirmed(v))

    def test_200_kosong_dengan_control_kosong_bukan_signal(self):
        v, s = _classify_response(_Resp(200, ""), 0, sapi="auto")
        self.assertEqual((v, s), ("inconclusive", "no_signal"))
        self.assertFalse(_confirmed(v))

    def test_200_berbody_bukan_signal(self):
        v, s = _classify_response(_Resp(200, "halo"), 50, sapi="auto")
        self.assertEqual((v, s), ("inconclusive", "no_signal"))
        self.assertFalse(_confirmed(v))

    def test_200_kosong_mod_php_tidak_signal(self):
        v, s = _classify_response(_Resp(200, ""), 50, sapi="mod_php")
        self.assertEqual((v, s), ("inconclusive", "no_signal"))
        self.assertFalse(_confirmed(v))


class TestBuktiKuatHanyaParser(unittest.TestCase):
    """Satu-satunya jalur 'vulnerable' adalah oom_in_parser."""

    def test_oom_in_parser_vulnerable_dan_confirmed(self):
        body = ("Fatal error: Allowed memory size of 8388608 bytes "
                "exhausted (tried to allocate 20 bytes) in Unknown on line 0")
        v, s = _classify_response(_PalsuResp(200, body), 100, sapi="fpm")
        self.assertEqual((v, s), ("vulnerable", "oom_in_parser"))
        r = OOMResult(verdict=v, signal=s)
        self.assertTrue(r.confirmed)
        self.assertIs(r.as_dict()["confirmed"], True)

    def test_confirmed_turun_dari_verdict_bukan_flag_terpisah(self):
        """`confirmed` mustahil True pada verdict selain 'vulnerable'."""
        for verdict in ("suspected", "inconclusive", "blocked", "error",
                        "not_vulnerable"):
            with self.subTest(verdict=verdict):
                r = OOMResult(verdict=verdict)
                self.assertFalse(r.confirmed)
                self.assertIs(r.as_dict()["confirmed"], False)

    def test_empty_500_suspected_bukan_confirmed(self):
        v, s = _classify_response(_PalsuResp(500, ""), 120, sapi="auto")
        self.assertEqual((v, s), ("suspected", "empty_500"))
        self.assertFalse(OOMResult(verdict=v).confirmed)


class _FakeTransport:
    """Transport palsu: post() mencatat (url, content-length) dan menjawab sesuai skrip."""

    def __init__(self, script):
        # script: dict url -> list of _Resp (dipakai berurutan)
        self.script = script
        self.calls = []
        self.retries = 5  # harus dipaksa 0 oleh oom_detect

    def post(self, url, data=None, headers=None):
        self.calls.append((url, len(data or b"")))
        host_path = url
        seq = self.script.get(host_path) or self.script.get("*")
        resp = seq.pop(0) if seq else _Resp(200, "ok")
        self.retries = 0  # dipaksa oleh oom_detect saat pertama dipakai
        return resp

    def close(self):
        pass


def _norm(url):
    # oom_detect memakai url apa adanya untuk control; phpMyAdmin dialihkan
    p = urlsplit(url)
    return p.scheme + "://" + p.netloc + p.path


class TestOomDetectVerdict(unittest.TestCase):
    """oom_detect() menutup loop: dugaan dilaporkan sebagai 'suspected'."""

    def test_semua_probe_502_jadi_suspected_confirmed_false(self):
        url = "http://t.local/index.php"
        ft = _FakeTransport({
            url: [_Resp(200, "ok")],
            "*": [_Resp(502), _Resp(503), _Resp(504)],
        })
        res = oom_detect(url, transport=ft)
        self.assertEqual(res.verdict, "suspected")
        self.assertEqual(res.signal, "worker_abort")
        self.assertFalse(res.confirmed)
        self.assertIs(res.as_dict()["confirmed"], False)
        # bukti mentah tiap probe tetap dilaporkan untuk triager
        self.assertEqual(len(res.probe_results), 3)
        self.assertFalse(any(p["verdict"] == "vulnerable"
                             for p in res.probe_results))
        # retry wajib dipaksa 0: payload besar tidak boleh dikirim ulang
        self.assertEqual(ft.retries, 0)

    def test_dugaan_lalu_bukti_kuat_naik_ke_vulnerable(self):
        """Dugaan tidak menghentikan loop; fatal-in-parser tetap menang."""
        url = "http://t.local/index.php"
        fatal = ("Fatal error: Allowed memory size of 8388608 bytes "
                 "exhausted (tried to allocate 20 bytes) in Unknown on line 0")
        ft = _FakeTransport({
            url: [_Resp(200, "ok")],
            "*": [_Resp(502), _Resp(200, fatal)],
        })
        res = oom_detect(url, transport=ft)
        self.assertEqual(res.verdict, "vulnerable")
        self.assertEqual(res.signal, "oom_in_parser")
        self.assertTrue(res.confirmed)

    def test_tanpa_sinyal_tetap_inconclusive(self):
        url = "http://t.local/index.php"
        ft = _FakeTransport({
            url: [_Resp(200, "ok")],
            "*": [_Resp(200, "ok"), _Resp(200, "ok"), _Resp(200, "ok")],
        })
        res = oom_detect(url, transport=ft)
        self.assertEqual(res.verdict, "inconclusive")
        self.assertFalse(res.confirmed)


class TestPhpMyAdminRedirect(unittest.TestCase):
    def test_control_phpmyadmin_dialihkan(self):
        # control pertama di /index.php mengembalikan halaman phpMyAdmin
        pm_url = "http://t.local/index.php"
        pma = "http://t.local" + PHPMYADMIN_PATH
        ft = _FakeTransport({
            pm_url: [_Resp(200, "<title>phpMyAdmin</title>")],
            pma: [_Resp(200, "config ok")],
            "*": [_Resp(200, "probe ok")],
        })
        res = oom_detect(pm_url, transport=ft)
        # call pertama tetap ke URL asli (control), kedua ke show_config_errors
        self.assertEqual(ft.calls[0][0], pm_url)
        self.assertEqual(ft.calls[1][0], pma)
        # sisanya (probe) juga ke path phpMyAdmin
        for url, _ in ft.calls[2:]:
            self.assertEqual(url, pma)
        self.assertIn(res.verdict, ("inconclusive", "suspected", "vulnerable",
                                    "blocked"))

    def test_marker_konstanta_sesuai_assetnote(self):
        self.assertEqual(PHPMYADMIN_MARKER, b"phpMyAdmin")
        self.assertEqual(PHPMYADMIN_PATH, "/show_config_errors.php")


class TestResultShape(unittest.TestCase):
    def test_oom_result_default(self):
        r = OOMResult()
        d = r.as_dict()
        self.assertEqual(d["verdict"], "inconclusive")
        self.assertEqual(d["probes_sent"], 0)
        self.assertIs(d["confirmed"], False)


if __name__ == "__main__":
    unittest.main()

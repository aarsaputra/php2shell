"""Tes lib.oomprobe: gating SAPI + sinyal 200-kosong + alih phpMyAdmin.

Mengikuti aturan scanner resmi assetnote/php2shell-scanner:
  - 502/503/504 hanya signal untuk fpm/auto (bukan mod_php)
  - 200 body-kosong (control ber-body) = sinyal FPM worker mati (baru)
  - control body ber-marker phpMyAdmin -> probe dialihkan ke
    /show_config_errors.php
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


class TestClassifySapi(unittest.TestCase):
    def test_502_vulnerable_auto(self):
        v, s = _classify_response(_Resp(502), 100, sapi="auto")
        self.assertEqual((v, s), ("vulnerable", "worker_abort"))

    def test_502_vulnerable_fpm(self):
        v, s = _classify_response(_Resp(502), 100, sapi="fpm")
        self.assertEqual((v, s), ("vulnerable", "worker_abort"))

    def test_502_bukan_signal_mod_php(self):
        v, s = _classify_response(_Resp(502), 100, sapi="mod_php")
        self.assertEqual(v, "inconclusive")
        self.assertNotEqual(s, "worker_abort")

    def test_semua_status_abort_fpm(self):
        for st in FPM_ABORT_STATUSES:
            with self.subTest(status=st):
                v, s = _classify_response(_Resp(st), 100, sapi="fpm")
                self.assertEqual((v, s), ("vulnerable", "worker_abort"))


class TestEmpty200(unittest.TestCase):
    def test_200_kosong_dengan_control_ada_adalah_signal(self):
        v, s = _classify_response(_Resp(200, ""), 50, sapi="fpm")
        self.assertEqual((v, s), ("vulnerable", "empty_200"))

    def test_200_kosong_dengan_control_kosong_bukan_signal(self):
        v, s = _classify_response(_Resp(200, ""), 0, sapi="auto")
        self.assertEqual((v, s), ("inconclusive", "no_signal"))

    def test_200_berbody_bukan_signal(self):
        v, s = _classify_response(_Resp(200, "halo"), 50, sapi="auto")
        self.assertEqual((v, s), ("inconclusive", "no_signal"))

    def test_200_kosong_mod_php_tidak_signal(self):
        v, s = _classify_response(_Resp(200, ""), 50, sapi="mod_php")
        self.assertEqual((v, s), ("inconclusive", "no_signal"))


class _FakeTransport:
    """Transport记录: post() mencatat (url, content-length) dan menjawab sesuai skrip."""

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
        self.assertIn(res.verdict, ("inconclusive", "vulnerable", "blocked"))

    def test_marker_konstanta_sesuai_assetnote(self):
        self.assertEqual(PHPMYADMIN_MARKER, b"phpMyAdmin")
        self.assertEqual(PHPMYADMIN_PATH, "/show_config_errors.php")


class TestResultShape(unittest.TestCase):
    def test_oom_result_default(self):
        r = OOMResult()
        d = r.as_dict()
        self.assertEqual(d["verdict"], "inconclusive")
        self.assertEqual(d["probes_sent"], 0)


if __name__ == "__main__":
    unittest.main()

"""Tes preflight: display_errors TIDAK boleh memblokir target rentan.

Latar: rantai tool ini mengambil leak dari header Set-Cookie (OOB read lewat
PS(id)), bukan dari error report di body. DISPLAY_ERRORS_OFF.md membuktikan
leak tetap terbaca saat display_errors=0 dengan ASLR aktif, dan laporan
VulnCheck menyebut exploit berjalan pada 8.4.26 dengan display_errors=Off.
Karena itu nilai off hanya mengurangi skor, tidak boleh menambah blocker.

Gerbang keputusan sekarang TRI-STATE (blocked | needs_review | ready), jadi
"tidak memblokir" TIDAK sama dengan "ready". Target yang prasyarat wajibnya
belum terverifikasi (versi unknown, upload_progress off/unknown, body_cap
bukan accepted, build bukan RCE) berstatus `needs_review` dengan
`review_reasons` yang menyebut satu per satu apa yang belum terbukti —
persis supaya operator tidak menembak lalu dapat HEAP_LEAK_FAILED tanpa sebab.
`ready` (bool) kini turunan dari `status == "ready"`.
"""

import os
import sys
import unittest

# Suite dijalankan dari root repo (discover -s tests -t .), jadi paket
# diimpor sebagai lib.*. Kalau file ini dijalankan langsung dari
# folder toolkit, sys.path perlu ditambah supaya 'toolkit' tetap bisa diimpor.
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from lib.detect import Detection
from lib.preflight import preflight


def _detection(disp: str, verdict: str = "vulnerable") -> Detection:
    return Detection(
        url="http://contoh.invalid/",
        reachable=True,
        status=200,
        php_version="8.4.26",
        branch="8.4",
        verdict=verdict,
        fix_floor="8.4.27",
        upload_progress="on",
        display_errors=disp,
    )


class TestDisplayErrorsBukanBlocker(unittest.TestCase):
    def test_off_tidak_menambah_blocker(self) -> None:
        """display_errors off/unknown TIDAK boleh menghasilkan blocker keras.

        Yang menentukan blocked hanya: target tak terjangkau atau versi
        TERBACA sudah >= fix-floor. display_errors bukan salah satunya.
        """
        for disp in ("on", "off", "unknown"):
            with self.subTest(disp=disp):
                p = preflight(_detection(disp))
                self.assertEqual(p.blockers, [])
                self.assertNotEqual(p.status, "blocked")

    def test_off_jadi_needs_review_karena_body_cap_unknown(self) -> None:
        """Semantik tri-state: body_cap belum diukur -> needs_review, bukan ready.

        Dulu tes ini bernama `test_off_tetap_ready` dan mengunci semantik LAMA
        (`ready = not blockers`), sehingga target yang body 16 MB-nya belum
        pernah terbukti sampai ke PHP dilaporkan READY. Sekarang: `ready`
        hanya untuk prasyarat yang SEMUA terverifikasi. display_errors=off
        sendiri tetap tidak memblokir (blockers kosong) — ia hanya menurunkan
        skor, dan alasan review di sini adalah body_cap.
        """
        p = preflight(_detection("off"))
        self.assertIs(p.ready, False)
        self.assertEqual(p.status, "needs_review")
        self.assertEqual(p.blockers, [])
        self.assertTrue(p.review_reasons, "needs_review tanpa alasan = label kosong")
        self.assertTrue(any("body_cap" in r for r in p.review_reasons),
                        f"alasan review tidak menyebut body_cap: {p.review_reasons}")

    def test_off_tetap_ready_bila_semua_prasyarat_terverifikasi(self) -> None:
        """display_errors=off BUKAN alasan menahan target yang siap.

        Bukti bahwa nilai off sendiri tidak memindahkan status ke needs_review:
        dengan versi terbaca rentan, upload_progress on, build RCE, dan
        body_cap accepted, status tetap `ready` walau display_errors off.
        """
        p = preflight(_detection("off"), body_cap="accepted")
        self.assertEqual(p.status, "ready")
        self.assertIs(p.ready, True)
        self.assertEqual(p.review_reasons, [])

    def test_off_menurunkan_skor_tapi_tidak_ke_nol(self) -> None:
        on = preflight(_detection("on")).score
        off = preflight(_detection("off")).score
        self.assertGreater(off, 0)
        self.assertLess(off, on)

    def test_target_patched_tetap_diblokir(self) -> None:
        d = _detection("on", verdict="patched")
        d.php_version = "8.4.27"
        d.fix_floor = "8.4.27"
        p = preflight(d)
        self.assertFalse(p.ready)
        self.assertEqual(p.status, "blocked")
        self.assertTrue(p.blockers)

    def test_versi_tidak_diketahui_jadi_needs_review(self) -> None:
        """Aturan baru (tri-state): deteksi = informasi, bukan gerbang.

        Versi tak bocor (CDN menyembunyikan header) TIDAK BOLEH menghasilkan
        blocker — justru target di balik CDN adalah kasus lapangan nyata, dan
        rantai tetap bisa dicoba dengan offset default bookworm. Tapi "boleh
        dicoba" bukan "sudah siap": fix-floor tak bisa dipastikan dan
        upload_progress tak terlihat, jadi status = needs_review dengan
        alasan tertulis. Dulu tes ini menuntut `ready is True` dan justru
        mengunci bug itu.
        """
        d = _detection("unknown", verdict="unknown")
        d.php_version = None
        d.upload_progress = "unknown"
        p = preflight(d)
        self.assertEqual(p.blockers, [], "versi unknown tidak boleh memblokir exploit")
        self.assertIs(p.ready, False)
        self.assertEqual(p.status, "needs_review")
        self.assertTrue(p.review_reasons, "needs_review tanpa alasan tidak bisa ditindak")
        gabung = " ".join(p.review_reasons)
        self.assertIn("versi", gabung)
        self.assertIn("upload_progress", gabung)

    def test_target_tidak_terjangkau_tetap_diblokir(self) -> None:
        d = _detection("unknown", verdict="unknown")
        d.reachable = False
        d.status = 0
        p = preflight(d)
        self.assertFalse(p.ready)
        self.assertEqual(p.status, "blocked")
        self.assertTrue(any("tidak bisa dihubungi" in b for b in p.blockers))

    def test_teks_check_tidak_menyesatkan(self) -> None:
        teks = preflight(_detection("off")).checks["display_errors"]
        self.assertNotIn("BLOCK", teks)
        self.assertIn("Set-Cookie", teks)

    def test_as_dict_membawa_status_dan_review_reasons(self) -> None:
        """Kontrak JSON/CSV: `ready` tetap ada, tapi tri-state ikut terekspos."""
        r = preflight(_detection("off")).as_dict()
        self.assertIn("status", r)
        self.assertIn("ready", r)
        self.assertIn("review_reasons", r)
        self.assertIs(r["ready"], r["status"] == "ready")
        self.assertEqual(r["status"], "needs_review")


if __name__ == "__main__":
    unittest.main()

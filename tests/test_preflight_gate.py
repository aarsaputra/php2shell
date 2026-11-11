"""Tes gerbang preflight: `body_cap` harus BENAR-BENAR sampai ke keputusan.

Latar
-----
`lib/preflight.preflight()` punya cabang `body_cap=rejected` sejak lama, tapi
parameternya tidak pernah ada — jadi `p.body_cap` selalu "unknown" dan target
yang membuang body 16 MB (post_max_size < body stage-1) tetap tampil READY.
Operator lalu menembak dan mendapat HEAP_LEAK_FAILED tanpa sebab.

Yang dikunci tes ini:
  1. nilai body_cap divalidasi (accepted|rejected|unknown saja; selain itu
     ValueError, bukan diam-diam dianggap unknown),
  2. rejected/unknown masuk `review_reasons` (status needs_review), accepted
     tidak,
  3. `status == "ready"` HANYA saat seluruh prasyarat wajib terverifikasi —
     bukan sekadar "tidak ada blocker".
"""

import os
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from lib.detect import Detection                 # noqa: E402
from lib import build_support                    # noqa: E402
from lib import preflight as pf                  # noqa: E402


def _det(**kw) -> Detection:
    """Detection yang SEMUA prasyaratnya terverifikasi (default READY).

    Tiap tes mematikan satu prasyarat untuk melihat efeknya sendirian.
    """
    base = dict(
        url="http://contoh.invalid/upload.php",
        reachable=True,
        status=200,
        php_version="8.4.26",     # RCE terbukti di tabel build_support
        branch="8.4",
        verdict="vulnerable",
        fix_floor="8.4.27",
        upload_progress="on",
        display_errors="on",
    )
    base.update(kw)
    return Detection(**base)


# --------------------------------------------------------------- validasi ---

def test_nilai_body_cap_tidak_dikenal_valueerror():
    for bad in ("yes", "ok", "accept", "", "accepted maybe", "413"):
        with pytest.raises(ValueError) as ei:
            pf.preflight(_det(), body_cap=bad)
        assert "body_cap" in str(ei.value)


def test_body_cap_bukan_string_ditolak_bukan_ditebak():
    # 123 -> "123" -> bukan nilai sah; jangan pernah jatuh ke "unknown" diam-diam.
    with pytest.raises(ValueError):
        pf.preflight(_det(), body_cap=123)


def test_body_cap_dinormalkan_spasi_dan_huruf_besar():
    p = pf.preflight(_det(), body_cap="  ACCEPTED ")
    assert p.body_cap == "accepted"
    assert p.status == pf.STATUS_READY


# ---------------------------------------------------------------- accepted --

def test_accepted_field_terisi_dan_ready():
    p = pf.preflight(_det(), body_cap="accepted")
    assert p.body_cap == "accepted"
    assert p.status == pf.STATUS_READY, p.review_reasons
    assert p.ready is True
    assert p.review_reasons == []
    assert "OK" in p.checks["body_cap"]
    assert "16 MB" in p.checks["body_cap"]


# ---------------------------------------------------------------- rejected --

def test_rejected_masuk_review_reasons():
    p = pf.preflight(_det(), body_cap="rejected")
    assert p.body_cap == "rejected"
    assert p.status == pf.STATUS_NEEDS_REVIEW
    assert p.ready is False
    assert any("body_cap=rejected" in r for r in p.review_reasons), p.review_reasons


def test_rejected_tidak_menjadi_blocker_keras():
    """post_max_size kecil = stage-1 mustahil, tapi bukan "target aman".

    Karena itu status needs_review (bukan blocked): tool tidak boleh menjamin
    apa pun soal kerentanan dari satu batas upload.
    """
    p = pf.preflight(_det(), body_cap="rejected")
    assert p.blockers == []
    assert p.status == pf.STATUS_NEEDS_REVIEW


def test_rejected_dijelaskan_di_checks_dan_notes():
    p = pf.preflight(_det(), body_cap="rejected")
    assert "TERBATAS" in p.checks["body_cap"]
    assert any("Bukan bukti target aman" in n for n in p.notes), p.notes


# ----------------------------------------------------------------- unknown --

def test_unknown_eksplisit_masuk_review_reasons():
    p = pf.preflight(_det(), body_cap="unknown")
    assert p.body_cap == "unknown"
    assert p.status == pf.STATUS_NEEDS_REVIEW
    assert any("body_cap=unknown" in r for r in p.review_reasons)


def test_body_cap_tanpa_argumen_default_unknown_dan_tidak_ready():
    """Tanpa pengukuran, READY tidak boleh diklaim (kegagalan senyap lama)."""
    p = pf.preflight(_det())
    assert p.body_cap == "unknown"
    assert p.status == pf.STATUS_NEEDS_REVIEW
    assert any("body_cap=unknown" in r for r in p.review_reasons)


def test_unknown_menyebut_kemungkinan_post_max_size():
    p = pf.preflight(_det(), body_cap="unknown")
    assert "post_max_size" in p.checks["body_cap"]


# ------------------------------------------- ready = semua terverifikasi ----

def test_ready_hanya_saat_seluruh_prasyarat_terverifikasi():
    p = pf.preflight(_det(), body_cap="accepted")
    assert p.status == pf.STATUS_READY
    assert p.support_level == build_support.RCE


def test_upload_progress_belum_terbukti_menahan_ready():
    p = pf.preflight(_det(upload_progress="off"), body_cap="accepted")
    assert p.status == pf.STATUS_NEEDS_REVIEW
    assert any("upload_progress" in r for r in p.review_reasons)


def test_upload_progress_unknown_menahan_ready():
    p = pf.preflight(_det(upload_progress="unknown"), body_cap="accepted")
    assert p.status == pf.STATUS_NEEDS_REVIEW


def test_build_bukan_rce_menahan_ready():
    # 8.3.35 aarch64 = LEAK saja; stage 3 tidak jalan.
    p = pf.preflight(_det(php_version="8.3.35", branch="8.3"), body_cap="accepted")
    assert p.support_level == build_support.LEAK
    assert p.status == pf.STATUS_NEEDS_REVIEW
    assert any("build support" in r for r in p.review_reasons)


def test_versi_terbaca_patched_tetap_blocked():
    p = pf.preflight(_det(php_version="8.4.27", verdict="patched"),
                     body_cap="accepted")
    assert p.status == pf.STATUS_BLOCKED
    assert p.blockers


def test_tidak_terjangkau_tetap_blocked():
    p = pf.preflight(_det(reachable=False, status=0), body_cap="accepted")
    assert p.status == pf.STATUS_BLOCKED


def test_ready_adalah_turunan_status_bukan_field_terpisah():
    p = pf.preflight(_det(), body_cap="rejected")
    assert p.ready == (p.status == pf.STATUS_READY)
    d = p.as_dict()
    assert d["status"] == pf.STATUS_NEEDS_REVIEW
    assert d["ready"] is False
    assert d["body_cap"] == "rejected"
    assert d["review_reasons"]

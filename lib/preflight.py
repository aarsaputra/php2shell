"""preflight.py — skor kesiapan exploit untuk satu target (non-destruktif).

Yang dinilai hanya yang bisa dilihat dari luar + yang diketahui publik tentang
`exploit.py` upstream. Tujuannya menjawab satu pertanyaan: "kalau saya jalankan
exploit di sini, apakah punya peluang, atau hanya membuang waktu/memicu alarm?"

BUKAN exploit. Tidak mengirim payload OOM 3MB/12MB.

Gerbang keputusan: TRI-STATE (revisi audit)
-------------------------------------------
Versi lama menetapkan `ready = not blockers`. Artinya READY hanya berarti
"tidak ada blocker keras", BUKAN "prasyarat sudah terbukti". Akibatnya target
dengan versi tak diketahui, upload_progress mati/tak diketahui, build yang
belum pernah terbukti, dan body_cap yang ditolak semuanya muncul READY — lalu
operator menembak dan mendapat HEAP_LEAK_FAILED tanpa sebab.

Sekarang tiga nilai eksplisit:

    blocked       target tak terjangkau, ATAU versi TERBACA sudah >= fix-floor
    needs_review  ada prasyarat penting yang BELUM terverifikasi
    ready         seluruh prasyarat wajib sudah terverifikasi

`ready` (bool) dipertahankan sebagai turunan: `status == "ready"`. Key `ready`
tetap ada di `as_dict()` supaya reporter/CSV/CLI yang sudah ada tidak berubah.
`review_reasons` menyebut satu per satu apa yang belum terbukti — tanpa itu,
"needs_review" hanya jadi label tanpa isi.

Prinsip yang TIDAK berubah: display_errors bukan prasyarat (leak lewat header
Set-Cookie, bukan error report). Ia hanya menurunkan skor.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .detect import Detection
from . import build_support

# Pra-syarat yang dibaca langsung dari header komentar exploit.py (baris 1-48).
# Catatan: exploit.py menyebut display_errors=1, tetapi jalur leak tool ini ada di
# header Set-Cookie sehingga display_errors tidak menentukan (lihat blok di bawah).
PREREQS = (
    ("display_errors", "display_errors=1 (kenyamanan; leak tetap jalan saat off)"),
    ("upload_progress", "session.upload_progress.enabled=On (konsumen rantai 109619)"),
    ("version", "versi di bawah fix-floor ATAU EOL"),
)

# --- nilai tri-state -------------------------------------------------------
STATUS_BLOCKED = "blocked"
STATUS_NEEDS_REVIEW = "needs_review"
STATUS_READY = "ready"
VALID_STATUSES = (STATUS_BLOCKED, STATUS_NEEDS_REVIEW, STATUS_READY)

# Hasil pengukuran body besar (lihat lib/memprobe.body_cap).
VALID_BODY_CAP = ("accepted", "rejected", "unknown")


@dataclass
class Preflight:
    url: str
    score: int = 0            # 0..90
    max_score: int = 90
    # Gerbang keputusan. Default konservatif: belum dinilai = belum siap.
    status: str = STATUS_NEEDS_REVIEW
    checks: dict[str, str] = field(default_factory=dict)
    blockers: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    # Satu kalimat per prasyarat yang BELUM terverifikasi. Inilah isi dari
    # status "needs_review"; tanpa daftar ini label itu tidak bisa ditindak.
    review_reasons: list[str] = field(default_factory=list)
    # Tingkat dukungan build (RCE / LEAK / NO / UNKNOWN) + kalimat penjelas.
    # Ini yang membedakan "target ini bisa di-RCE" dari "target ini cuma bisa
    # dibocorkan" — sebelumnya preflight menyebut keduanya READY.
    support_level: str = build_support.UNKNOWN
    support_text: str = ""
    # Apakah body besar benar-benar sampai ke PHP? Diukur dari luar dengan
    # mengirim satu field 16 MB (sama seperti probe memory_limit). Ini yang
    # menentukan stage-1 bisa meleak apa pun: kalau post_max_size lebih kecil
    # dari body, PHP membuang body sebelum kode jalan — tanpa pesan apa pun
    # yang membedakannya dari "target aman".
    body_cap: str = "unknown"

    @property
    def ready(self) -> bool:
        """Backward-compat: READY berarti SELURUH prasyarat wajib terverifikasi.

        Turunan dari `status`, bukan field terpisah — supaya tidak mungkin
        `ready=True` pada target yang statusnya needs_review/blocked.
        """
        return self.status == STATUS_READY

    def as_dict(self) -> dict:
        return {
            "url": self.url,
            "score": self.score,
            "max_score": self.max_score,
            "status": self.status,
            "ready": self.ready,
            "review_reasons": list(self.review_reasons),
            "support": {"level": self.support_level, "text": self.support_text},
            "body_cap": self.body_cap,
            "checks": self.checks,
            "blockers": self.blockers,
            "notes": self.notes,
        }


def preflight(d: Detection, body_cap: str | None = None) -> Preflight:
    """Nilai kesiapan satu target.

    `body_cap` adalah hasil `memprobe.body_cap(resp)` dari probe yang sama
    dengan probe memory_limit (accepted | rejected | unknown). Sebelumnya
    parameter ini TIDAK ADA sehingga cabang rejected/accepted di bawah tidak
    pernah tercapai: `p.body_cap` selalu "unknown" dan target yang membuang
    body 16 MB tetap lolos sebagai READY.
    """
    if body_cap is None:
        cap = "unknown"
    else:
        cap = str(body_cap).strip().lower()
        if cap not in VALID_BODY_CAP:
            raise ValueError(
                f"body_cap tidak dikenal: {body_cap!r} — pilihan: "
                f"{', '.join(VALID_BODY_CAP)}")
    p = Preflight(url=d.url, body_cap=cap)
    pts = 0

    # FILOSOFI (revisi permintaan operator, 23 Okt 2026): deteksi = INFORMASI,
    # bukan GERBANG. Versi tak terdeteksi (CDN menyembunyikan header) bukan
    # alasan menahan exploit — justru target di balik CDN adalah kasus nyata.
    # Yang tetap diblokir HANYA dua hal:
    #   1. target TIDAK BISA dihubungi (fitn jelas membuang waktu), dan
    #   2. versi TERBACA dan sudah >= fix-floor (patched) — menembak versi
    #      yang terbaca sudah-patch adalah crash sia-sia.
    # Selain itu: TIDAK diblokir — tapi juga tidak otomatis READY. Yang belum
    # terbukti masuk ke needs_review dengan alasannya.

    # --- versi (30) ---
    if d.verdict == "vulnerable":
        pts += 30
        p.checks["version"] = f"OK — {d.php_version or d.branch} di bawah fix-floor"
    elif d.verdict == "eol":
        pts += 30
        p.checks["version"] = f"OK — {d.php_version or d.branch} EOL (tak akan dipatch)"
    elif d.verdict == "patched":
        p.checks["version"] = f"BLOCK — {d.php_version} sudah >= {d.fix_floor}"
        p.blockers.append(
            f"versi {d.php_version} sudah dipatch (fix {d.fix_floor}); "
            "CVE-2026-109619/109618 tidak berlaku"
        )
    else:
        pts += 15
        p.checks["version"] = ("TIDAK DIKETAHUI — versi tak bocor (CDN/headers "
                               "bersih); offset default bookworm dipakai, bila "
                               "build beda panggilan butuh retry")
        p.notes.append(
            "versi tidak terdeteksi: rantai tetap bisa dicoba (bukan blocker). "
            "Kalau gagal di stage leak, kemungkinan build ≠ bookworm gunakan "
            "--zif-offset/--dtor-offset hasil ukur binari target."
        )

    # --- upload_progress (30) ---
    if d.upload_progress == "on":
        pts += 30
        p.checks["upload_progress"] = "OK — konsumen rantai 109619 terbuka"
    elif d.upload_progress == "off":
        p.checks["upload_progress"] = "BLOCK-ish — konsumen rantai 109619 tertutup"
        p.notes.append(
            "upload_progress tampak off; jalur konsumen 109619 kemungkinan "
            "tertutup, tapi ini BUKAN bukti aman (produser OOM 109618/109619 "
            "tetap ada — patch versi satu-satunya mitigasi penuh)"
        )
    else:
        p.checks["upload_progress"] = "TIDAK DIKETAHUI (edge/WAF menutupi jawaban)"
        p.notes.append(
            "upload_progress tidak terlihat: bisa WAF, bisa konfigurasi. "
            "Jangan simpulkan aman."
        )

    # --- display_errors (30) ---
    # PENTING: rantai tool ini TIDAK memakai error report sebagai kanal leak. Leak
    # diambil dari header Set-Cookie (OOB read lewat PS(id)), jadi display_errors=off
    # TIDAK menutup jalur. Ini sudah dibuktikan di DISPLAY_ERRORS_OFF.md: dengan
    # display_errors=0 dan ASLR aktif, chunk_base tetap terbaca (47 pointer).
    # Laporan VulnCheck juga menyebut exploit berjalan pada 8.4.26 dengan
    # display_errors=Off. Karena itu off hanya menurunkan sinyal kenyamanan,
    # BUKAN blocker — kalau dijadikan blocker, target rentan akan ditahan (false negative).
    if d.display_errors == "on":
        pts += 30
        p.checks["display_errors"] = "OK — error report tampil (kenyamanan, bukan syarat)"
    elif d.display_errors == "off":
        pts += 15
        p.checks["display_errors"] = "NETRAL — leak lewat Set-Cookie, bukan error report"
    else:
        p.checks["display_errors"] = "TIDAK DIKETAHUI"

    p.score = min(pts, p.max_score)

    # --- dukungan build (RCE vs LEAK vs belum terbukti) ---
    # Ini BUKAN blocker: build yang tidak ada di tabel tetap dicoba, karena
    # offset bisa dipasok operator lewat --zif-offset/--dtor-offset. Tapi
    # operator berhak tahu peluang sebenarnya SEBELUM menembak — dan READY
    # tidak boleh diklaim untuk build yang belum pernah terbukti RCE.
    p.support_level = build_support.level_for(d.php_version, getattr(d, "arch", None))
    p.support_text = build_support.expectation_text(d.php_version, getattr(d, "arch", None))
    if p.support_level == build_support.LEAK:
        p.notes.append(
            "build ini hanya terbukti sampai stage leak — stage 3 (fake "
            "HashTable -> zif_system) tidak jalan. Perintah TIDAK akan "
            "dieksekusi; berhenti setelah bocoran alamat."
        )
    elif p.support_level == build_support.NO:
        p.notes.append(
            "build ini belum pernah terbukti bisa dilanjutkan sama sekali. "
            "Rantai kemungkinan berhenti di stage 1-2; siapkan offset manual "
            "kalau tetap ingin mencoba."
        )

    # --- batas ukuran body (prasyarat stage-1) ---
    # Diukur dari probe yang sama; lihat docs/SYARAT_TARGET.md. Kalau target
    # membuang body besar (post_max_size kecil), stage 1 MUSTAHIL meleak apa
    # pun — kegagalannya akan terlihat sama persis dengan "target aman".
    if p.body_cap == "rejected":
        p.checks["body_cap"] = ("TERBATAS — body 16 MB ditolak/dibuang; "
                                "post_max_size target lebih kecil dari body stage-1")
        p.notes.append(
            "post_max_size/upload_max_filesize target kemungkinan < 16 MB. "
            "Body stage-1 dibuang PHP sebelum kode jalan, jadi stage leak "
            "akan gagal apa pun offset yang dipakai. Bukan bukti target aman."
        )
    elif p.body_cap == "accepted":
        p.checks["body_cap"] = "OK — body 16 MB diterima PHP"
    else:
        p.checks["body_cap"] = ("TIDAK DIUKUR — body 16 MB belum diuji; "
                                "post_max_size bisa saja < body stage-1")

    # --- gerbang keputusan: tri-state -----------------------------------
    # blocked = satu-satunya dua sebab keras (tak terjangkau / versi terbaca
    # sudah-patch). Selain itu, setiap prasyarat yang belum terbukti masuk
    # daftar review_reasons; READY hanya kalau daftar itu kosong.
    if not d.reachable:
        p.blockers.append(f"target tidak bisa dihubungi (HTTP {d.status})")

    review: list[str] = []
    if d.verdict not in ("vulnerable", "eol"):
        if d.verdict == "patched":
            pass  # sudah menjadi blocker, bukan alasan review
        elif d.verdict == "not_vulnerable":
            review.append(
                "versi tidak terbaca dan probe OOM menyimpulkan target tidak "
                "merespons jalur php2shell — belum ada bukti jalur rentan")
        else:
            review.append(
                "versi PHP tidak terbaca (CDN/header bersih) — fix-floor tidak "
                "bisa dipastikan; offset default bookworm belum tentu cocok")
    if d.upload_progress != "on":
        review.append(
            f"upload_progress={d.upload_progress or 'unknown'} — konsumen rantai "
            "109619 belum terbukti terbuka (WAF/konfigurasi bisa menutupinya)")
    if p.support_level != build_support.RCE:
        review.append(
            f"build support={p.support_level} — belum terbukti RCE; "
            "stage 3 bisa berhenti setelah bocoran alamat")
    if p.body_cap != "accepted":
        review.append(
            f"body_cap={p.body_cap} — body 16 MB belum terbukti sampai ke PHP; "
            "kalau post_max_size lebih kecil, stage leak mustahil")

    p.review_reasons = review
    if p.blockers:
        p.status = STATUS_BLOCKED
    elif review:
        p.status = STATUS_NEEDS_REVIEW
    else:
        p.status = STATUS_READY

    # CLI lama (php2shell.py) hanya mencetak notes/blockers, bukan
    # review_reasons. Alasan review ikut dicatat sebagai note supaya operator
    # melihat SEBAB target tidak READY — bukan cuma label "TIDAK".
    for reason in p.review_reasons:
        note = f"[review] {reason}"
        if note not in p.notes:
            p.notes.append(note)
    return p


def verdict_line(d: Detection, p: Preflight) -> str:
    """Satu baris untuk tabel terminal."""
    ver = d.php_version or (d.branch or "?")
    # Kolom ke-2: tingkat dukungan build. Ini yang membedakan target yang
    # benar-benar bisa di-RCE dari target yang cuma bisa dibocorkan.
    lvl = {"rce": "RCE", "leak": "LEAK", "no": "NO", "unknown": "?"}.get(
        p.support_level, "?")
    gate = {STATUS_READY: "READY", STATUS_NEEDS_REVIEW: "REVIEW",
            STATUS_BLOCKED: "NO"}.get(p.status, "?")
    return (
        f"{d.verdict:<10} | {ver:<8} | {lvl:<4} | up={d.upload_progress:<7} | "
        f"disp={d.display_errors:<7} | score={p.score:>2}/{p.max_score} | "
        f"{gate}"
    )

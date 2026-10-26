"""advisory.py — fakta pasca-rilis yang mengubah cara tool ini dipakai.

Sumber (semua primer, diverifikasi 2026-10-24):
  - php.net/archive/2026.php          : advisory 2026-10-21 & 2026-10-23
  - ChangeLog-8.php                   : entri "22 Oct 2026" untuk 8.5.12 / 8.4.27
  - cveawg.mitre.org CVE-2026-109618/109619
  - GitHub GHSA-w8hw-w9fx-j79w / GHSA-6wmf-4rv5-p3rp
  - cisa.gov alert 2026-10-21 (revisi 2026-10-23)

Yang TIDAK diklaim di sini:
  - Tidak ada klaim bahwa tool ini bisa mengeksploitasi 109618 atau 115560.
  - Tidak ada klaim patch-bypass. Rilis ulang 22 Okt TIDAK membatalkan
    fix-floor 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 — nomor versinya sama.
"""

from __future__ import annotations

# ---------------------------------------------------------------- CVE ketiga
# CVE-2026-115560: belum punya record MITRE (per 2026-10-24: CVE_RECORD_DNE),
# advisory informasional php.net 2026-10-23, advisory lengkap menyusul di
# rilis reguler. BUKAN bagian PHP2Shell awal.
#
# TERVERIFIKASI 2026-10-24 dari sumber primer + thehackernews/getastra:
#   - "is not fixed by PHP 8.5.12, 8.4.27, 8.3.36 or 8.2.35"  <-- PENTING
#   - belum ada eksploitasi ITW (serangan 21 Okt menargetkan 109618/109619)
#   - PHP belum menyatakan versi terdampak, rilis pemuat fix, atau skor
CVE_115560 = {
    "id": "CVE-2026-115560",
    "title": "Session upload progress (jalur ketiga)",
    "status": "advisory informasional 2026-10-23; advisory lengkap menyusul",
    "fixed_by_php2shell_floor": False,
    "itw_exploited": False,
    "requires": [
        "session.serialize_handler = php_binary ATAU php_serialize (di konfigurasi)",
        "lalu diubah ke php saat runtime via ini_set() SEBELUM session_start()",
        "session.upload_progress.enabled = On",
    ],
    "mitigation": "session.upload_progress.enabled=0",
    "mitigation_scope": (
        "TIDAK wajib untuk semua orang. php.net 2026-10-23: \"Applications "
        "that never change the serialize handler at runtime can keep the "
        "feature enabled.\" Sudah menerapkan mitigasi 21 Okt? Tidak perlu "
        "tindakan tambahan."
    ),
    "note": (
        "Kombinasi konfigurasi + kode aplikasi yang tidak lazim; PHP Foundation "
        "menilainya tidak terjadi di praktik normal, jadi ditangani di siklus "
        "rilis reguler, bukan rilis darurat. TIDAK ikut tertutup oleh rilis "
        "PHP2Shell 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35."
    ),
}

# ------------------------------------------------- patch diulang 22 Okt 2026
# ChangeLog PHP 8 mencatat entri tanggal 22 Oct 2026 untuk Version 8.5.12 dan
# 8.4.27: "Fixed GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp (Avoid state
# corruption via bailout)". Artinya build 21 Okt belum memuat perbaikan final,
# tetapi NOMOR VERSI-nya tidak naik. Konsekuensi praktis: build 21 Okt dan
# build 22 Okt sama-sama melaporkan diri "8.4.27".
REPACK_NOTICE = (
    "Patch PHP2Shell di-build ulang 22 Okt 2026 (8.5.12 dan 8.4.27) tanpa naik "
    "nomor versi. Versi yang sama bisa berarti build 21 Okt (belum final) atau "
    "22 Okt (final) — verifikasi tanggal build paket, jangan hanya nomor versi."
)

# ------------------------------------------------------------ mitigasi resmi
# GHSA-w8hw-w9fx-j79w menyatakan memory_limit=-1 BUKAN mitigasi lengkap:
# kalau mmap()/alokasi bawah gagal, longjmp() tetap bisa terjadi saat memori
# request masih terjangkau. Hanya upgrade yang lengkap.
MITIGATION_WARNINGS = {
    "memory_limit=-1": (
        "BUKAN mitigasi lengkap (GHSA-w8hw-w9fx-j79w): bila alokasi dasar "
        "gagal, longjmp() tetap bisa jalan saat memori request masih reachable."
    ),
    "session.upload_progress.enabled=0": (
        "Hanya menutup jalur 109618 (+115560). TIDAK menutup 109619. "
        "Untuk 109619, php.net advisory 2026-10-21 menyebut setelan ini sebagai "
        "mitigasi yang memblokir jalur session yang terkonfirmasi (bukan semua varian)."
    ),
    "fatal_error_backtraces=0": (
        "Hanya PHP 8.5. Mematikan satu jalur fatal-backtrace pada 109619; "
        "bukan mitigasi umum, sisanya tetap perlu upgrade."
    ),
    "waf": "Mengurangi, tidak menghilangkan. CISA: WAF 'may provide some protection'.",
}

# ------------------------------------------------------------- eksploitasi ITW
ITW = {
    "first_attempt": "2026-10-17",
    "days_before_patch": 4,
    "source": "Amazon Threat Intelligence (via BleepingComputer, 2026-10-22)",
    "detail": (
        "Percobaan pertama 17 Okt 2026 — 4 hari sebelum patch 21 Okt — dari IP "
        "VPN/anonymization, menargetkan honeypot. Cloudflare, watchTowr, "
        "Previdian, Hadrian, Patchstack juga mendeteksi percobaan gagal pra-disclosure."
    ),
    "confirmed_compromise": (
        "Tidak ada kompromi sukses yang terkonfirmasi publik per 2026-10-23 "
        "(PHP Foundation, Elizabeth Barron; Mandiant: 'exploitation may have "
        "already begun in a limited fashion')."
    ),
}


def warnings_for(verdict: str, patched_release_day: str | None = None) -> list[str]:
    """Peringatan yang relevan untuk satu verdict deteksi.

    `verdict` berasal dari detect.classify(): vulnerable | patched | eol | unknown.
    Fungsi ini TIDAK mengubah verdict — hanya menambah konteks.
    """
    out: list[str] = []
    if verdict in ("vulnerable", "eol"):
        out.append(
            "Eksploitasi pra-patch terdokumentasi sejak 17 Okt 2026 "
            "(4 hari sebelum rilis). Anggap host terekspos sudah dipindai."
        )
    if verdict == "patched":
        out.append(REPACK_NOTICE)
        out.append(
            f"{CVE_115560['id']} TIDAK ditutup fix-floor ini "
            f"(8.5.12/8.4.27/8.3.36/8.2.35). Mitigasi satu-satunya: "
            f"{CVE_115560['mitigation']} — pasang sebagai php_admin_flag, "
            f"bukan ini_set(), karena kode aplikasi bisa menimpanya."
        )
    return out


def describe() -> str:
    """Ringkasan teks untuk mode `version` / `--advisories`."""
    lines = [
        "ADVISORY PASCA-RILIS (diverifikasi 2026-10-24; dicek ulang 2026-10-26 — "
        "belum ada rilis PHP baru, sumber primer)",
        "",
        f"1. {REPACK_NOTICE}",
        "",
        f"2. CVE ketiga: {CVE_115560['id']} — {CVE_115560['title']}",
        f"   status   : {CVE_115560['status']}",
        "   syarat   : " + " + ".join(CVE_115560["requires"]),
        f"   mitigasi : {CVE_115560['mitigation']} (php_admin_flag, bukan ini_set)",
        f"              {CVE_115560['mitigation_scope']}",
        f"   patch    : TIDAK ditutup 8.5.12/8.4.27/8.3.36/8.2.35",
        f"   ITW      : {'ya' if CVE_115560['itw_exploited'] else 'belum dilaporkan'}",
        f"   catatan  : {CVE_115560['note']}",
        "",
        "   TIDAK ADA rilis PHP baru per 2026-10-26: 8.5.12 / 8.4.27 / 8.3.36 /",
        "   8.2.35 masih versi terbaru (php.net archive + ChangeLog-8 dicek).",
        "   8.6.0 RC4 masih RC; advisory lengkap 115560 dijanjikan di rilis reguler",
        "   berikutnya — cek ulang setelah rilis itu, fix-floor bisa berubah.",
        "",
        "3. Mitigasi yang sering disalahpahami:",
    ]
    for k, v in MITIGATION_WARNINGS.items():
        lines.append(f"   - {k}: {v}")
    lines += [
        "",
        f"4. Eksploitasi di lapangan: {ITW['detail']}",
        f"   Kompromi sukses terkonfirmasi: {ITW['confirmed_compromise']}",
        "",
        "Tool ini hanya menjalankan rantai CVE-2026-109619.",
        "Untuk 109618 dan 115560 tool ini hanya mengklasifikasi versi",
        "— tidak mengeksploitasi keduanya.",
    ]
    return "\n".join(lines)

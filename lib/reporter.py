"""reporter.py — hasil scan ke JSON + CSV + tabel terminal.

Aturan: satu target = satu baris CSV. Kolom tidak boleh berubah antar-versi
tanpa alasan, karena CSV ini yang dipakai untuk dedupe di ledger engagement.

Tiga pagar keamanan di modul ini (audit P2 + P3):

0. Redaksi kredensial — laporan JSON/CSV adalah deliverable yang dibagikan ke
   klien, jadi URL target tidak boleh membawa `?token=`, `?api_key=`,
   `?session=`, dsb. ke dalamnya. Sebelum ditulis, nilai string pada kolom
   URL (`url`, `final_url`, `from`, `to`, `location`, `redirect`) dilewatkan
   `lib.target_policy.redact_url()`, dan kolom teks bebas (`error`, `reason`,
   `proof`, `message`/`detail`/`notes`) dilewatkan `redact_text()` — fungsi
   yang SAMA dengan audit log transport, supaya daftar parameter sensitif
   hanya ada di satu tempat. JSON diredaksi secara rekursif (struktur & tipe
   tetap: skor/ready/status tidak berubah jadi string).

   Yang SENGAJA tetap terbaca: host, path, dan nama parameter
   (`/a.php?token=***&page=2`). Path adalah bukti temuan — menghapusnya
   membuat laporan tak bisa dipakai. Hanya NILAI parameter sensitif yang
   menjadi `***`. Bila `lib.target_policy` gagal di-import, modul TIDAK
   menulis token mentah: dipakai fallback over-redaksi (semua nilai query
   jadi `***` + password userinfo), satu RuntimeWarning dicatat, dan
   `REDACTION_DEGRADED` di-set True.

Dua pagar keamanan lain:

1. CSV formula injection — nilai yang berasal dari respons TARGET (server,
   reason, error, proof, url, php_version, ...) ditulis apa adanya oleh
   `csv`; spreadsheet (Excel/LibreOffice/Sheets) akan MENGEKSEKUSI sel yang
   diawali `=`, `+`, `-`, `@`, TAB, atau CR. Karena itu setiap nilai string
   di-escape dengan satu apostrof di depan (`'=cmd|calc`). Apostrof adalah
   penanda "teks literal" yang dikenali semua spreadsheet utama; sel tetap
   menampilkan isi aslinya. Nilai numerik/boolean TIDAK disentuh supaya
   kolom skor/status tetap bisa dihitung. Sanitasi hanya dilakukan saat
   menulis CSV — JSON menyimpan nilai mentah (tidak ada konteks eksekusi).
2. Permission file — laporan bisa memuat bukti akses (uid=..., path, error
   internal). File dibuat langsung dengan mode 0600 (os.open(..., 0o600))
   dan diverifikasi setelah ditulis. Filesystem yang tidak menegakkan POSIX
   (NTFS/exFAT lewat FUSE, sebagian mount) tidak membuat proses crash:
   muncul peringatan, penulisan lanjut, dan `_mode_privat_terpasang()`
   mengembalikan False agar pemanggil bisa memutuskan sendiri.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import stat
import urllib.parse
import warnings
from pathlib import Path

CSV_COLUMNS = [
    "url",
    "reachable",
    "status",
    "server",
    "php_version",
    "branch",
    "verdict",
    "fix_floor",
    "upload_progress",
    "display_errors",
    "patched_but_bypassable",
    "score",
    "ready",
    "exploited",
    "proof",
    "reason",
    "error",
]

# Karakter pertama yang membuat spreadsheet memperlakukan sel sebagai RUMUS,
# bukan teks. `-` ikut karena `-2+3` dihitung; TAB/CR karena beberapa
# spreadsheet memangkasnya lalu tetap mengeksekusi sisa selnya.
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

# Penanda teks-literal untuk spreadsheet.
ESCAPE_PREFIX = "'"

# ---------------------------------------------------------------------------
# Redaksi kredensial laporan
# ---------------------------------------------------------------------------
#
# Sumber kebenaran daftar parameter sensitif adalah `lib/target_policy`
# (SENSITIVE_PARAMS + sub-string). Modul ini TIDAK menyalin daftar itu —
# dua daftar cepat atau lambat akan menyimpang, dan yang tertinggal adalah
# yang bocor. Import dibuat defensif: reporter dipakai juga oleh skrip yang
# meng-import `lib.reporter` dengan sys.path berbeda / paket yang di-vendor.
try:  # pragma: no branch - jalur normal
    from . import target_policy as _policy
except Exception:  # noqa: BLE001 - import relatif gagal (dipanggil di luar paket)
    try:
        import target_policy as _policy  # type: ignore[no-redef]
    except Exception:  # noqa: BLE001 - benar-benar tidak tersedia
        _policy = None  # type: ignore[assignment]

# True bila modul terpaksa memakai redaksi fallback (lebih kasar). Pemanggil
# (CLI/CI) bisa memeriksa ini dan memutuskan menolak menulis laporan.
REDACTION_DEGRADED: bool = _policy is None

if REDACTION_DEGRADED:  # pragma: no cover - hanya saat instalasi rusak
    warnings.warn(
        "lib/target_policy tidak bisa di-import: laporan memakai redaksi "
        "fallback yang LEBIH KASAR (SEMUA nilai query string dijadikan ***). "
        "Perbaiki instalasi paket agar daftar parameter sensitif dipakai.",
        RuntimeWarning, stacklevel=2)

REDACTED = "***"

# Kolom/nilai yang diperlakukan sebagai URL (path & host dipertahankan,
# hanya nilai parameter sensitif yang disembunyikan).
URL_KEYS = frozenset({
    "url", "final_url", "original_url", "request_url", "redirect_url",
    "location", "uri", "endpoint", "target", "from", "to", "next", "link",
})

# Kolom teks bebas: pesan library sering menggemakan URL lengkap beserta
# query string, jadi isinya harus lewat redaksi teks, bukan hanya URL polos.
TEXT_KEYS = frozenset({
    "error", "reason", "proof", "message", "detail", "details", "notes",
    "note", "warning", "warnings", "exception", "traceback", "body_snippet",
    "snippet", "stderr", "stdout",
})

# Fallback: tidak tahu nama parameter mana yang sensitif, jadi SEMUA nilai
# query dijadikan *** (over-redaksi). Lebih baik kehilangan `page=2` di
# laporan daripada menulis token mentah ke file yang dibagikan.
_FALLBACK_URL_IN_TEXT = re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s'\"<>]+")

# Nama kolom yang memuat URL di mana saja (`url`, `final_url`, `url_list`,
# `redirectUrl`). Dicek setelah `URL_KEYS`, sebelum teks bebas.
_URL_KEY_RE = re.compile(r"(^|_)url(s)?($|_)")
# Teks bebas yang menyebut dirinya error/reason/proof dengan awalan bebas
# (`exploit_error`, `detect_reason`, `last_proof`).
_TEXT_KEY_RE = re.compile(r"(^|_)(error|reason|proof|message|detail|note|snippet)")


def _key_kind(key: object) -> str | None:
    """Klasifikasikan nama kolom: 'url', 'text', atau None (tak disentuh).

    Pencocokan longgar: nama seperti `final_url`, `redirect_location`,
    `error_message`, `exploit_error` tetap tertangkap, karena format record
    antar-tahap toolkit tidak seragam dan kolom baru mudah ditambahkan.
    """
    if not isinstance(key, str):
        return None
    low = key.strip().lower()
    if not low:
        return None
    if low in URL_KEYS or _URL_KEY_RE.search(low):
        return "url"
    if low in TEXT_KEYS or _TEXT_KEY_RE.search(low):
        return "text"
    return None


def _redact_url_like(value: str) -> str:
    """Redaksi satu nilai yang dianggap URL (atau teks berisi URL)."""
    if _policy is not None:
        # Nilai dengan spasi bukan URL tunggal: itu teks bebas yang kebetulan
        # tersimpan di kolom url (mis. pesan error). Pakai jalur teks.
        if any(ch.isspace() for ch in value):
            return _policy.redact_text(value)
        return _policy.redact_url(value)
    # ---- fallback: over-redaksi ----
    if any(ch.isspace() for ch in value):
        return _fallback_redact_text(value)
    return _fallback_redact_url(value)


def _fallback_redact_url(url: str) -> str:
    """Redaksi kasar tanpa target_policy: SEMUA nilai query -> `***`.

    Host & path dipertahankan karena keduanya bukti temuan; yang dibuang
    hanya nilai parameter (tak bisa dibedakan sensitif/tidak di sini).
    """
    text = "" if url is None else str(url)
    try:
        parts = urllib.parse.urlsplit(text)
    except ValueError:
        return REDACTED
    if not parts.scheme and not parts.netloc:
        base, sep, query = text.partition("?")
        if not sep:
            return text
        return base + "?" + _fallback_redact_query(query)
    netloc = parts.netloc
    if "@" in netloc:
        userinfo, _, hostport = netloc.rpartition("@")
        user = userinfo.split(":", 1)[0]
        netloc = f"{user}:{REDACTED}@{hostport}" if ":" in userinfo else f"{user}@{hostport}"
    query = _fallback_redact_query(parts.query) if parts.query else parts.query
    return urllib.parse.urlunsplit(
        (parts.scheme, netloc, parts.path, query, parts.fragment))


def _fallback_redact_query(query: str) -> str:
    out: list[str] = []
    for raw in query.split("&"):
        if not raw:
            continue
        name, sep, value = raw.partition("=")
        out.append(f"{name}={REDACTED}" if sep and value else raw)
    return "&".join(out)


def _fallback_redact_text(text: str) -> str:
    """Fallback teks bebas: redaksi URL yang tertanam, sisanya apa adanya."""
    if not text:
        return text
    try:
        return _FALLBACK_URL_IN_TEXT.sub(
            lambda m: _fallback_redact_url(m.group(0)), str(text))
    except Exception:  # noqa: BLE001 - jangan gagalkan penulisan laporan
        return str(text)


def redact_value(key: object, value):
    """Redaksi satu nilai berdasarkan nama kolomnya; non-string utuh.

    Hanya `str` yang disentuh: int/float/bool/None (status, score, ready,
    reachable) harus tetap bertipe sama supaya ledger bisa dihitung.
    """
    if not isinstance(value, str) or not value:
        return value
    kind = _key_kind(key)
    if kind == "url":
        return _redact_url_like(value)
    if kind == "text":
        return _policy.redact_text(value) if _policy is not None \
            else _fallback_redact_text(value)
    return value


def redact_record(obj, _key: object = None):
    """Redaksi rekursif dict/list tanpa mengubah struktur maupun tipe.

    Dipakai `write_json` supaya record mentah (detect/preflight/exploit)
    tidak perlu disalin ke bentuk lain: kunci yang tidak sensitif —
    termasuk nilai numerik — lewat tanpa perubahan. Elemen list mewarisi
    kunci induknya (`{"urls": ["...?token=x"]}` tetap diredaksi).
    """
    if isinstance(obj, dict):
        return {k: redact_record(v, k) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_record(v, _key) for v in obj]
    return redact_value(_key, obj)


def redact_row(row: dict) -> dict:
    """Redaksi satu baris siap-CSV (kunci = nama kolom CSV)."""
    return {k: redact_value(k, v) for k, v in row.items()}


def _row(rec: dict) -> dict:
    d = rec.get("detect", {}) or {}
    p = rec.get("preflight", {}) or {}
    e = rec.get("exploit", {}) or {}
    return {
        "url": d.get("url") or rec.get("url", ""),
        "reachable": d.get("reachable", False),
        "status": d.get("status", 0),
        "server": d.get("server", ""),
        "php_version": d.get("php_version") or "",
        "branch": d.get("branch") or "",
        "verdict": d.get("verdict", "unknown"),
        "fix_floor": d.get("fix_floor") or "",
        "upload_progress": d.get("upload_progress", "unknown"),
        "display_errors": d.get("display_errors", "unknown"),
        "patched_but_bypassable": d.get("patched_but_bypassable", False),
        "score": p.get("score", 0),
        "ready": p.get("ready", False),
        "exploited": e.get("success", False),
        "proof": e.get("proof", ""),
        "reason": d.get("reason", ""),
        "error": d.get("error", "") or e.get("error", ""),
    }


def csv_escape(value):
    """Netralkan sel CSV yang akan dieksekusi spreadsheet.

    Mengembalikan string apa adanya bila tidak diawali karakter rumus;
    sebaliknya satu apostrof ditambahkan di depan. Nilai non-string
    (int/float/bool/None) dikembalikan tanpa perubahan: kolom numerik harus
    tetap numerik agar ledger bisa di-sort/hitung.
    """
    if isinstance(value, str) and value[:1] in FORMULA_PREFIXES:
        return ESCAPE_PREFIX + value
    return value


def _mode_privat_terpasang(path: Path) -> bool:
    """True bila file benar-benar hanya bisa dibaca pemilik (mode 0600).

    Filesystem non-POSIX (NTFS/exFAT via fuseblk, vfat, sebagian FUSE)
    mengabaikan chmod tanpa error; file tetap 0666/0777. Di situ laporan
    yang memuat bukti akses terbaca semua user lokal.
    """
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return False
    return not (mode & 0o077)


def _pasang_mode_600(path: Path) -> bool:
    """chmod 0600 lalu verifikasi. Tidak melempar bila filesystem menolak.

    Berbeda dari shell/safe_shell.py (yang fail-closed karena menyimpan
    PASSWORD), laporan hanya berisi hasil scan: menolak menulis akan
    menghilangkan data engagement. Jadi di sini kita memberi peringatan
    eksplisit dan tetap menulis.
    """
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError as exc:  # pragma: no cover - FS aneh / OS non-POSIX
        warnings.warn(f"{path}: chmod 600 gagal ({exc}); file mungkin terbaca user lain",
                      RuntimeWarning, stacklevel=3)
        return False
    if not _mode_privat_terpasang(path):
        mode = stat.S_IMODE(path.stat().st_mode)
        warnings.warn(
            f"{path}: mode {oct(mode)} — filesystem tidak menegakkan chmod 600 "
            f"(NTFS/exFAT/FUSE?). Laporan tetap ditulis; pindahkan ke filesystem "
            f"POSIX bila isinya sensitif.",
            RuntimeWarning, stacklevel=3)
        return False
    return True


def _tulis_privat(path: Path, text: str, *, newline: str | None = None) -> Path:
    """Tulis file dengan mode 0600 sejak pembuatan (bukan chmod belakangan).

    Menggunakan os.open(..., O_CREAT, 0o600) supaya tidak ada jendela waktu
    di mana file berisi data sudah ada dengan 0644 akibat umask proses.
    File LAMA yang sudah ada tetap di-chmod 0600 setelahnya (O_TRUNC tidak
    mengubah mode), jadi re-run dengan --csv berkas sama tetap aman.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    flags |= getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600)
    try:
        fh = os.fdopen(fd, "w", encoding="utf-8", newline=newline)
    except Exception:
        os.close(fd)  # fdopen gagal: fd belum punya pemilik
        raise
    with fh:
        fh.write(text)
    _pasang_mode_600(path)
    return path


def write_json(path: str | Path, records: list[dict], meta: dict | None = None) -> Path:
    """Tulis hasil scan ke JSON (mode 0600), nilai sensitif diredaksi.

    Redaksi (`redact_record`) berjalan atas salinan struktur: kunci URL
    memakai `redact_url()` (path & host tetap), kunci teks bebas memakai
    `redact_text()`. Tipe data tidak berubah — skor/status tetap angka,
    ready/reachable tetap boolean — sehingga konsumen JSON tidak perlu tahu
    soal redaksi. `meta` ikut diredaksi karena bisa memuat URL target.
    """
    p = Path(path)
    payload = {
        "meta": redact_record(meta or {}),
        "count": len(records),
        "results": [redact_record(rec) for rec in records],
    }
    text = json.dumps(payload, indent=2, ensure_ascii=False)
    return _tulis_privat(p, text)


def write_csv(path: str | Path, records: list[dict]) -> Path:
    """Tulis hasil scan ke CSV (mode 0600): redaksi dulu, lalu anti-formula.

    Urutan penting: `redact_row()` lebih dulu (mengganti nilai parameter
    sensitif jadi `***`), BARU `csv_escape()` menambahkan apostrof. Kalau
    dibalik, apostrof bisa mendahului `=` milik payload dan redaksi bekerja
    pada string yang sudah diubah — sekaligus menyembunyikan bahwa sel itu
    formula. Nilai numerik/boolean tetap apa adanya agar kolom bisa dihitung.
    """
    p = Path(path)
    buf = io.StringIO(newline="")
    w = csv.DictWriter(buf, fieldnames=CSV_COLUMNS, extrasaction="ignore")
    w.writeheader()
    for rec in records:
        w.writerow({k: csv_escape(v) for k, v in redact_row(_row(rec)).items()})
    return _tulis_privat(p, buf.getvalue(), newline="")


def table(records: list[dict]) -> str:
    """Tabel terminal. URL diredaksi juga: output ini sering di-paste ke
    laporan/tiket, dan token di query string sama bocornya di scrollback."""
    if not records:
        return "(tidak ada target)"
    hdr = (
        f"{'#':>3}  {'verdict':<10}  {'php':<9}  {'up':<7}  {'disp':<7}  "
        f"{'score':>5}  {'rdy':<3}  {'exp':<3}  url"
    )
    lines = [hdr, "-" * len(hdr)]
    for i, rec in enumerate(records, 1):
        r = _row(rec)
        lines.append(
            f"{i:>3}  {r['verdict']:<10}  {(r['php_version'] or r['branch'] or '?'):<9}  "
            f"{r['upload_progress']:<7}  {r['display_errors']:<7}  "
            f"{r['score']:>2}/90  {'YES' if r['ready'] else 'no ':<3}  "
            f"{'YES' if r['exploited'] else 'no ':<3}  "
            f"{redact_value('url', r['url'])}"
        )
    return "\n".join(lines)


def summary(records: list[dict]) -> str:
    n = len(records)
    vuln = sum(1 for r in records if _row(r)["verdict"] == "vulnerable")
    eol = sum(1 for r in records if _row(r)["verdict"] == "eol")
    patched = sum(1 for r in records if _row(r)["verdict"] == "patched")
    unknown = sum(1 for r in records if _row(r)["verdict"] == "unknown")
    ready = sum(1 for r in records if _row(r)["ready"])
    exploited = sum(1 for r in records if _row(r)["exploited"])
    return (
        f"total={n}  vulnerable={vuln}  eol={eol}  patched={patched}  "
        f"unknown={unknown}  ready={ready}  exploited={exploited}"
    )

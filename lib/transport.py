"""transport.py — HTTP dengan sidik jari browser (JA3), rate limit, audit.

Kenapa modul ini ada: `exploit.py` memakai raw socket + TLS Python default dan
TIDAK mengirim User-Agent. Di balik Cloudflare/Akamai itu langsung tertandai.
Modul ini dipakai SEMUA tahap toolkit (detect, preflight, exploit probe) supaya
satu target hanya melihat satu identitas.

`curl_cffi` opsional: kalau tidak ada, turun ke urllib dengan header lengkap
(lebih mudah dideteksi, tapi tidak crash). Venv repo: /home/lota1337/myenv/bin/python

Pagar keamanan (audit hardening)
--------------------------------
1. TLS DIVERIFIKASI secara default (`verify_tls=True`). Sebelumnya jalur
   curl_cffi memakai `verify=False` dan jalur urllib menyetel
   `check_hostname=False` + `CERT_NONE` — artinya setiap request HTTPS bisa
   dicegat tanpa terdeteksi, termasuk request berisi cookie/creds target.
   Mematikan verifikasi sekarang harus EKSPLISIT lewat `--insecure`.
2. Tujuan request divalidasi kebijakan (`lib/target_policy.py`): URL awal dan
   SETIAP hop redirect. Default menolak loopback/RFC1918/link-local/metadata
   cloud supaya target jahat tidak bisa memakai redirect untuk memancing tool
   ini menarik 169.254.169.254 dari mesin operator (SSRF). Redirect diikuti
   MANUAL maksimal `max_redirects` (5) hop, bukan diserahkan ke library.
3. Audit log memakai `redact_url()` (token/api_key/password di query jadi
   `***`) dan file-nya dibuat mode 0600 sejak `os.open`, bukan default umask.
   Retensi DIBATASI: sebelum append, file yang sudah mencapai
   `AUDIT_MAX_BYTES` dirotasi ke `<file>.1` (menimpa `.1` lama) sehingga log
   tidak tumbuh tanpa batas. Satu record SELALU satu baris fisik: newline,
   CR, U+2028/U+2029, dan karakter kontrol lain di-escape sebelum
   `json.dumps`, jadi nilai dari target tidak bisa memalsukan baris log.
4. Session curl_cffi selalu ditutup: `Transport` mendukung
   `with Transport(...) as t:` dan `close()` idempoten, jadi exception di
   tengah request tidak meninggalkan koneksi terbuka.
"""

from __future__ import annotations

import errno
import functools
import http.client
import json
import os
import random
import socket
import ssl
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import target_policy as policy

# Profil = (impersonate, User-Agent, Accept-Language). Dipilih bergiliran.
PROFILES: dict[str, dict[str, str]] = {
    "chrome": {
        "impersonate": "chrome124",
        "ua": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
        "lang": "en-US,en;q=0.9",
    },
    "safari": {
        "impersonate": "safari17_0",
        "ua": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
               "(KHTML, like Gecko) Version/17.0 Safari/605.1.15"),
        "lang": "en-GB,en;q=0.9",
    },
    "firefox": {
        "impersonate": "firefox133",
        "ua": ("Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 "
               "Firefox/133.0"),
        "lang": "en-US,en;q=0.5",
    },
    "android": {
        "impersonate": "chrome99_android",
        "ua": ("Mozilla/5.0 (Linux; Android 13; SM-S911B) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/99.0.4844.88 Mobile Safari/537.36"),
        "lang": "en-US,en;q=0.9",
    },
    "edge": {
        "impersonate": "edge101",
        "ua": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36 Edg/101.0.1210.53"),
        "lang": "en-US,en;q=0.9",
    },
}

DEFAULT_PROFILE = "chrome"
DEFAULT_DELAY = 1.0
DEFAULT_TIMEOUT = 15

# Batas hop redirect. 5 cukup untuk rantai CDN normal (http->https->path) dan
# kecil enough bahwa loop redirect jahat berhenti cepat.
MAX_REDIRECTS = 5

REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})

# ---------- retensi audit log ----------
# Audit log ditulis selama scan berjalan (bisa ribuan record). Tanpa batas,
# satu engagement panjang menghasilkan file yang tumbuh selamanya — masalah
# retensi yang diminta ditutup audit PY-011. Ukuran 8 MiB cukup untuk ~40k
# record tipikal (baris ~200 byte), dan rotasi tunggal ke `.1` menjaga total
# pemakaian disk maksimal ~2x batas tanpa rantai .1..N yang sulit diaudit.
AUDIT_MAX_BYTES = 8 * 1024 * 1024
AUDIT_ROTATE_SUFFIX = ".1"

# Karakter yang `json.dumps(..., ensure_ascii=False)` biarkan MENTAH padahal
# berbahaya: sebagian parser/logger memperlakukannya sebagai newline
# (U+2028/U+2029/U+0085) atau mengacaukan terminal (`cat audit.jsonl`) —
# ESC/C1/DEL. Semua C0 yang lazim (`\n`, `\r`, `\t`, `\x1b`) sudah di-escape
# sendiri oleh json.dumps, jadi tidak perlu diduplikasi di sini.
_AUDIT_ESCAPES = {
    "\x85": "\\u0085",     # NEL
    "\u2028": "\\u2028",   # LINE SEPARATOR
    "\u2029": "\\u2029",   # PARAGRAPH SEPARATOR
}
_C1_MAX = 0x9F  # DEL (0x7F) .. C1 controls (0x80-0x9F)


def _audit_safe_text(value: str) -> str:
    """Escape karakter pemisah baris + kontrol agar satu nilai tetap satu baris.

    `json.dumps` sudah meng-escape `\\n`/`\\r`, tetapi dengan
    `ensure_ascii=False` ia membiarkan U+2028/U+2029/U+0085 dan karakter C1
    apa adanya — sebagian parser/logger memperlakukannya sebagai newline.
    Escape di sini (bukan mengandalkan json) membuat jaminan "satu record
    satu baris fisik" berlaku untuk file mentah, `splitlines()`, dan
    `json.loads`.

    Surrogate lepas (`\\ud800`-`\\udfff`, bisa datang dari body/error yang
    di-decode longgar) juga di-escape: `str.encode("utf-8")` akan melempar
    `UnicodeEncodeError` dan itu tidak boleh mematikan scan.
    """
    out = []
    for ch in value:
        mapped = _AUDIT_ESCAPES.get(ch)
        if mapped is not None:
            out.append(mapped)
            continue
        code = ord(ch)
        if 0x7F <= code <= _C1_MAX or 0xD800 <= code <= 0xDFFF:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    return "".join(out)


def _audit_safe(obj: Any) -> Any:
    """Terapkan `_audit_safe_text` rekursif ke struktur record audit."""
    if isinstance(obj, str):
        return _audit_safe_text(obj)
    if isinstance(obj, dict):
        return {_audit_safe_text(str(k)): _audit_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_audit_safe(v) for v in obj]
    return obj


def _have_curl_cffi() -> bool:
    try:
        import curl_cffi  # noqa: F401
        return True
    except Exception:
        return False


HAVE_CURL_CFFI = _have_curl_cffi()


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """`HTTPConnection` yang menyambung ke IP hasil validasi, bukan DNS baru.

    urllib memanggil `http_class(host, timeout=..., **args)` lalu `connect()`
    akan me-resolve `self.host` lagi — celah DNS rebinding: nama divalidasi
    sebagai IP A, lalu disambungi sebagai IP B. Di sini `connect()` memakai
    IP yang sudah divalidasi sedangkan `self.host` (dan header `Host:` yang
    dibangun urllib dari `req.host`) tetap hostname asli, jadi virtual host,
    SNI, dan cookie tetap benar.
    """

    # Diisi lewat `functools.partial(_PinnedHTTPConnection, pinned_ip=ip)`.
    pinned_ip: str | None = None

    def __init__(self, *args, pinned_ip: str | None = None, **kwargs):
        self.pinned_ip = pinned_ip
        super().__init__(*args, **kwargs)

    def connect(self) -> None:
        # Tidak ada proxy/tunnel di jalur tool ini (`Transport` tidak menyetel
        # proxy untuk urllib), jadi satu-satunya tujuan TCP adalah pin itu.
        self.sock = self._create_connection(
            (self.pinned_ip, self.port), self.timeout, self.source_address
        )
        try:
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError as exc:
            if exc.errno != errno.ENOPROTOOPT:
                raise
        if self._tunnel_host:
            self._tunnel()


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Varian TLS: sambung ke IP pin, handshake tetap memakai hostname asli.

    `server_hostname=self.host` WAJIB: sertifikat dicocokkan dengan nama di
    URL, bukan dengan IP (kalau tidak, verifikasi TLS akan gagal untuk setiap
    situs yang sertifikatnya tidak memuat IP, dan memaksa
    `check_hostname=False` adalah regresi keamanan).
    """

    pinned_ip: str | None = None

    def __init__(self, *args, pinned_ip: str | None = None, **kwargs):
        self.pinned_ip = pinned_ip
        super().__init__(*args, **kwargs)

    def connect(self) -> None:
        self.sock = self._create_connection(
            (self.pinned_ip, self.port), self.timeout, self.source_address
        )
        try:
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError as exc:
            if exc.errno != errno.ENOPROTOOPT:
                raise
        if self._tunnel_host:
            self._tunnel()
        server_hostname = self._tunnel_host or self.host
        # `HTTPSConnection.__init__` menyimpan konteks di `_context` (atribut
        # privat stdlib, tidak dikenali type checker) — akses lewat getattr.
        context = getattr(self, "_context", None) or ssl._create_default_https_context()
        self.sock = context.wrap_socket(self.sock, server_hostname=server_hostname)


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    """Handler yang menyerahkan kelas koneksi ber-pin ke `do_open`."""

    def __init__(self, pinned_ip: str, **kwargs):
        self._pinned_ip = pinned_ip
        super().__init__(**kwargs)

    def http_open(self, req):
        return self.do_open(
            functools.partial(_PinnedHTTPConnection, pinned_ip=self._pinned_ip),
            req,
        )


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    """Sama, untuk https: konteks TLS tetap diteruskan ke `do_open`."""

    def __init__(self, pinned_ip: str, context=None, **kwargs):
        self._pinned_ip = pinned_ip
        super().__init__(context=context, **kwargs)

    def https_open(self, req):
        return self.do_open(
            functools.partial(_PinnedHTTPSConnection, pinned_ip=self._pinned_ip),
            req,
            context=self._context,
        )


class PolicyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Handler redirect urllib yang menolak tujuan terlarang.

    `Transport` mengikuti redirect secara manual (`_fetch`) supaya tiap hop
    punya kredit "5 maksimum" sendiri dan bisa diaudit. Handler ini dipakai
    di dalam `_single` dengan `follow=False`: ia memeriksa `Location:` lebih
    dulu, lalu mengembalikan None agar urllib TIDAK melompat — respons 3xx
    diteruskan ke pemanggil sebagai HTTPError yang kemudian dibaca apa adanya.

    Dengan `follow=True` (dipakai `_build_opener()` untuk pemakaian langsung
    di luar class), handler ini menjadi lapisan kedua: redirect ke
    127.0.0.1 / 169.254.169.254 tetap ditolak walaupun pemanggil lupa
    memvalidasi.
    """

    def __init__(self, allow_private: bool = False, follow: bool = True,
                 resolve: bool = True) -> None:
        super().__init__()
        self.allow_private = allow_private
        self.follow = follow
        # `resolve=False` dipakai jalur ber-pin (`_single`): pemeriksaan URL
        # tetap dilakukan, tetapi resolusi DNS ditunda ke `resolve_pinned()`
        # supaya hanya ada satu jawaban DNS per hop (anti DNS rebinding).
        self.resolve = resolve

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Diperiksa SEBELUM apa pun dikirim: ini satu-satunya tempat di jalur
        # urllib di mana tujuan redirect masih bisa dihentikan.
        policy.check_url(newurl, allow_private=self.allow_private,
                         resolve=self.resolve)
        if not self.follow:
            return None  # biarkan jadi HTTPError -> pemanggil baca status 3xx
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    error: str = ""
    elapsed_ms: int = 0

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400 and not self.error

    def header(self, name: str) -> str:
        low = name.lower()
        for k, v in self.headers.items():
            if k.lower() == low:
                return v
        return ""


class Transport:
    """Klien HTTP tunggal untuk semua tahap, dengan rate limit + audit JSONL."""

    def __init__(
        self,
        profile: str = DEFAULT_PROFILE,
        delay: float = DEFAULT_DELAY,
        timeout: int = DEFAULT_TIMEOUT,
        proxy: str | None = None,
        audit_log: str | Path | None = None,
        retries: int = 2,
        verbose: bool = False,
        *,
        verify_tls: bool = True,
        follow_redirects: bool = True,
        allow_private: bool = False,
        max_redirects: int = MAX_REDIRECTS,
    ) -> None:
        if profile not in PROFILES:
            raise ValueError(f"profil tidak dikenal: {profile} (pilihan: {', '.join(PROFILES)})")
        self.profile_name = profile
        self.profile = PROFILES[profile]
        self.delay = max(0.0, float(delay))
        self.timeout = timeout
        self.proxy = proxy
        self.retries = max(0, retries)
        self.audit_path = Path(audit_log) if audit_log else None
        self.verbose = bool(verbose)
        # Verifikasi TLS AKTIF default: mematikannya harus keputusan operator
        # (`--insecure`), bukan nilai bawaan library.
        self.verify_tls = bool(verify_tls)
        self.follow_redirects = bool(follow_redirects)
        self.allow_private = bool(allow_private)
        self.max_redirects = max(0, int(max_redirects))
        self._last = 0.0
        self._session = None

    # ---------- context manager ----------

    def __enter__(self) -> "Transport":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.close()
        return False  # jangan telan exception

    # ---------- internal ----------

    def _throttle(self) -> None:
        if self.delay <= 0:
            return
        gap = time.monotonic() - self._last
        jitter = self.delay * random.uniform(0.75, 1.35)
        if gap < jitter:
            time.sleep(jitter - gap)
        self._last = time.monotonic()

    def _audit(self, rec: dict[str, Any]) -> None:
        """Tulis satu baris JSONL, mode 0600, nilai sensitif diredaksi.

        Redaksi dilakukan DI SINI (bukan di pemanggil) supaya tidak ada jalur
        baru yang lupa meredaksi. File dibuat dengan `os.open(..., 0o600)` agar
        tidak pernah ada jendela waktu file berisi token ber-mode 0644.

        Retensi: bila file sudah >= `AUDIT_MAX_BYTES` (baca ulang tiap
        penulisan, jadi mengubah konstanta saat runtime berlaku), file
        dirotasi ke `<nama>.1` lewat `os.replace` — `.1` lama tertimpa, tidak
        ada rantai `.1..N`. Jadi ruang disk dibatasi ~2x `AUDIT_MAX_BYTES`
        dan record tertua di file utama hilang saat rotasi. Rotasi tidak
        menghapus apa pun bila ukuran masih di bawah batas, dan aman bila
        file belum ada.

        Log injection: `_audit_safe` meng-escape karakter yang dibiarkan
        mentah oleh `json.dumps(ensure_ascii=False)` tetapi berbahaya —
        U+2028/U+2029/U+0085 (dianggap newline oleh sebagian parser dan oleh
        `str.splitlines()`) serta DEL/C1/ESC (mengacaukan terminal), dan
        surrogate lepas (bikin encode gagal). `\\n`/`\\r` sudah di-escape
        json. Setiap record karenanya tepat satu baris fisik: nilai seperti
        `{"ts":"x",...}` dari target tidak bisa memalsukan record baru, dan
        tiap baris tetap `json.loads`-able.

        Kegagalan menulis audit TIDAK boleh mematikan scan: semua OSError
        ditelan (dengan warning) dan tidak ada exception yang keluar.
        """
        if not self.audit_path:
            return
        for key in ("url", "from", "to"):
            if key in rec and rec[key]:
                rec[key] = policy.redact_url(str(rec[key]))
        # `error` diredaksi juga: pesan library mencerminkan URL lengkap
        # (`...?token=abc`), dan kolom ini masuk file permanen.
        if rec.get("error"):
            rec["error"] = policy.redact_text(str(rec["error"]))
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **rec}
        # Escape SETELAH redaksi: redaksi bisa menyisipkan `***`, dan escape
        # tidak boleh merusak pola redaksi (urutan ini membuat keduanya
        # idempoten terhadap satu sama lain).
        rec = _audit_safe(rec)
        line = (json.dumps(rec, ensure_ascii=False) + "\n").encode("utf-8")
        try:
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)
            self._rotate_audit_if_needed()
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
            flags |= getattr(os, "O_BINARY", 0)
            fd = os.open(self.audit_path, flags, 0o600)
            try:
                os.write(fd, line)
            finally:
                os.close(fd)
        except OSError as exc:
            # Audit hilang lebih baik daripada scan mati di tengah engagement.
            warnings.warn(
                f"{self.audit_path}: menulis audit gagal ({exc})",
                RuntimeWarning, stacklevel=2,
            )
            return
        # File yang SUDAH ada tidak berubah mode-nya karena O_APPEND: chmod
        # eksplisit, lalu verifikasi (filesystem non-POSIX bisa mengabaikan).
        try:
            os.chmod(self.audit_path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError as exc:  # pragma: no cover - FS aneh
            warnings.warn(
                f"{self.audit_path}: chmod 600 gagal ({exc}); audit mungkin "
                f"terbaca user lain", RuntimeWarning, stacklevel=2,
            )
            return
        try:
            mode = stat.S_IMODE(self.audit_path.stat().st_mode)
        except OSError:  # pragma: no cover
            return
        if mode & 0o077:  # pragma: no cover - FS yang mengabaikan chmod
            warnings.warn(
                f"{self.audit_path}: mode {oct(mode)} — filesystem tidak "
                f"menegakkan 0600 (NTFS/exFAT/FUSE?)", RuntimeWarning, stacklevel=2,
            )

    def _rotate_audit_if_needed(self, max_bytes: int | None = None) -> bool:
        """Rotasi `audit.jsonl` -> `audit.jsonl.1` bila sudah >= batas.

        Mengembalikan True bila rotasi dilakukan. Aturan:

        * file belum ada / ukurannya masih < `max_bytes` -> tidak ada apa pun
          yang dihapus atau dipindah (False);
        * file >= `max_bytes` -> `os.replace(<file>, <file>.1)`, menimpa `.1`
          lama. `os.replace` atomik dalam filesystem yang sama, jadi pembaca
          tidak pernah melihat `.1` setengah tertulis. Hanya SATU generasi
          (`.1`), tidak ada rantai `.1..N`: total pemakaian disk dibatasi
          ~2x batas.

        File baru dibuat oleh `os.open(..., 0o600)` di `_audit`, jadi mode
        0600 tetap berlaku setelah rotasi.
        """
        limit = AUDIT_MAX_BYTES if max_bytes is None else int(max_bytes)
        path = self.audit_path
        if path is None:
            return False
        try:
            size = path.stat().st_size
        except OSError:
            return False  # belum ada / tidak terbaca: tidak ada yang dirotasi
        if size < limit:
            return False
        rotated = path.with_name(path.name + AUDIT_ROTATE_SUFFIX)
        os.replace(path, rotated)  # atomik dalam filesystem yang sama
        return True

    def _headers(self, extra: dict[str, str] | None) -> dict[str, str]:
        h = {
            "User-Agent": self.profile["ua"],
            "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                       "image/avif,image/webp,*/*;q=0.8"),
            "Accept-Language": self.profile["lang"],
            "Accept-Encoding": "gzip, deflate, br",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Connection": "keep-alive",
        }
        if extra:
            h.update(extra)
        return h

    def _ssl_context(self) -> ssl.SSLContext:
        """Konteks TLS untuk jalur urllib. Verifikasi ON kecuali diminta mati."""
        ctx = ssl.create_default_context()
        if not self.verify_tls:
            # check_hostname HARUS dimatikan dulu: menyetel CERT_NONE saat
            # check_hostname masih True melempar ValueError.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _build_opener(self) -> urllib.request.OpenerDirector:
        """Opener dengan handler redirect berpolisi + TLS sesuai operator."""
        return urllib.request.build_opener(
            PolicyRedirectHandler(allow_private=self.allow_private, follow=True),
            urllib.request.HTTPSHandler(context=self._ssl_context()),
        )

    # ---------- publik ----------

    def get(self, url: str, headers: dict[str, str] | None = None) -> Response:
        return self.request("GET", url, headers=headers)

    def head(self, url: str, headers: dict[str, str] | None = None) -> Response:
        return self.request("HEAD", url, headers=headers)

    def post(
        self,
        url: str,
        data: bytes | str | None = None,
        headers: dict[str, str] | None = None,
    ) -> Response:
        return self.request("POST", url, data=data, headers=headers)

    def request(
        self,
        method: str,
        url: str,
        data: bytes | str | None = None,
        headers: dict[str, str] | None = None,
    ) -> Response:
        # URL awal divalidasi SEBELUM request pertama. Ditolak = tidak ada
        # paket keluar sama sekali, dan penolakan itu sendiri diaudit supaya
        # operator bisa melihat "target diblokir", bukan "target mati".
        try:
            # `resolve=False`: `_single()` memakai `resolve_pinned()` — satu
            # resolusi saja per request (lihat docs/AUDIT_TRANSPORT.md §5).
            policy.check_url(url, allow_private=self.allow_private, resolve=False)
        except ValueError as exc:
            resp = Response(url=url, status=0,
                            error=f"{type(exc).__name__}: {exc}")
            if self.verbose:
                print(f"    [{method}] DITOLAK {policy.redact_url(url)} — "
                      f"{policy.redact_text(str(exc))}", flush=True)
            self._audit({
                "profile": self.profile_name,
                "event": "denied",
                "method": method,
                "url": url,
                "status": 0,
                "ms": 0,
                "error": resp.error,
                "bytes": 0,
            })
            return resp

        attempt = 0
        last: Response | None = None
        while attempt <= self.retries:
            self._throttle()
            start = time.monotonic()
            try:
                resp = self._fetch(method, url, data, headers)
            except Exception as exc:  # noqa: BLE001 - semua error jaringan jadi Response
                resp = Response(url=url, status=0, error=f"{type(exc).__name__}: {exc}")
            resp.elapsed_ms = int((time.monotonic() - start) * 1000)
            if self.verbose:
                # Error library sering menggemakan URL lengkap; redaksi supaya
                # token tidak tercetak di terminal/CI log (bukan hanya file audit).
                err = (f" err={policy.redact_text(resp.error)}"
                       if resp.error else "")
                print(f"    [{method}] {resp.status} {resp.elapsed_ms}ms "
                      f"{len(data) if data else 0}B "
                      f"{policy.redact_url(resp.url or url)}{err}", flush=True)
            self._audit({
                "profile": self.profile_name,
                "method": method,
                "url": resp.url or url,
                "status": resp.status,
                "ms": resp.elapsed_ms,
                "error": resp.error,
                "bytes": len(data) if data else 0,
            })
            last = resp
            # Blokir kebijakan (SSRF/metadata) dan DNS gagal BUKAN kegagalan
            # jaringan sementara: mengulanginya tidak akan mengubah keputusan,
            # hanya menambah sleep 2s+4s+8s per request. Status 0 membuatnya
            # terlihat seperti "koneksi putus" di bawah, jadi dikembalikan
            # sekarang (fail closed, sekali coba).
            if resp.error.startswith(("PolicyError", "ResolveError")):
                return resp
            # 5xx / koneksi putus = layak retry. 4xx = jawaban final, jangan ulang.
            if resp.status and resp.status < 500:
                return resp
            attempt += 1
            if attempt <= self.retries:
                time.sleep(min(2 ** attempt, 8))
        return last or Response(url=url, status=0, error="no attempt")

    def _fetch(
        self,
        method: str,
        url: str,
        data: bytes | str | None,
        headers: dict[str, str] | None,
    ) -> Response:
        """Ikuti redirect MANUAL, validasi tiap hop, batasi `max_redirects`.

        Library TIDAK diminta mengikuti redirect (`allow_redirects=False` /
        handler yang menolak). Alasannya: `Location:` dari target jahat adalah
        jalur SSRF paling murah, dan hanya di sini tujuan bisa diperiksa
        sebelum paket dikirim.
        """
        current = url
        method_now = method
        data_now = data
        resp = Response(url=current, status=0, error="tidak ada request")
        for hop in range(self.max_redirects + 1):
            try:
                policy.check_url(current, allow_private=self.allow_private,
                                 resolve=False)
            except ValueError as exc:
                return self._blocked(current, exc, hop)
            resp = self._single(method_now, current, data_now, headers)
            if not self.follow_redirects or resp.status not in REDIRECT_CODES:
                return resp
            location = resp.header("location")
            if not location:
                return resp
            nxt = urllib.parse.urljoin(resp.url or current, location.strip())
            try:
                policy.check_url(nxt, allow_private=self.allow_private,
                                 resolve=False)
            except ValueError as exc:
                self._audit({
                    "profile": self.profile_name,
                    "event": "redirect_denied",
                    "method": method_now,
                    "from": current,
                    "to": nxt,
                    "hop": hop + 1,
                    "status": resp.status,
                    "error": str(exc),
                })
                return self._blocked(nxt, exc, hop + 1)
            self._audit({
                "profile": self.profile_name,
                "event": "redirect",
                "method": method_now,
                "from": current,
                "to": nxt,
                "hop": hop + 1,
                "status": resp.status,
            })
            # 303 selalu GET; 301/302 pada POST juga jadi GET tanpa body
            # (perilaku browser, dan aman: body tidak dikirim ulang ke host
            # lain yang belum pernah menerimanya).
            if resp.status == 303 or (
                resp.status in (301, 302) and method_now == "POST"
            ):
                method_now, data_now = "GET", None
            current = nxt
        return Response(
            url=current,
            status=resp.status,
            headers=resp.headers,
            body=resp.body,
            error=f"redirect melebihi {self.max_redirects} hop (dibatasi)",
        )

    @staticmethod
    def _blocked(url: str, exc: Exception, hop: int) -> Response:
        where = "" if hop == 0 else f" pada hop redirect ke-{hop}"
        return Response(
            url=url,
            status=0,
            error=f"{type(exc).__name__}{where}: {exc}",
        )

    def _pin(self, url: str) -> tuple[str, int, str]:
        """Host/port/IP untuk SATU request — resolusi pertama dan satu-satunya.

        Dipanggil sekali per `_single` (satu hop). Hasilnya dipakai untuk
        menyambung, jadi tidak ada resolusi kedua yang bisa dibelokkan DNS.
        """
        parts = urllib.parse.urlsplit(url)
        scheme = (parts.scheme or "").lower()
        host = parts.hostname or ""
        if not host:
            raise policy.PolicyError(f"URL tanpa host: {policy.redact_url(url)!r}")
        default_port = 443 if scheme == "https" else 80
        try:
            port = parts.port or default_port
        except ValueError as exc:
            raise policy.PolicyError(
                f"port tidak valid pada {policy.redact_url(url)!r} ({exc})"
            ) from exc
        ip = policy.resolve_pinned(host, port, allow_private=self.allow_private)
        return host, port, ip

    def _single(
        self,
        method: str,
        url: str,
        data: bytes | str | None,
        headers: dict[str, str] | None,
    ) -> Response:
        """SATU request tanpa mengikuti redirect. Tujuan sudah divalidasi.

        DNS rebinding: hostname di-resolve TEPAT SEKALI di sini lewat
        `policy.resolve_pinned()`, lalu koneksi dipin ke IP itu (urllib:
        kelas koneksi ber-pin; curl_cffi: `CURLOPT_RESOLVE`). Nama tidak
        pernah di-resolve ulang oleh library, jadi jawaban DNS kedua tidak
        bisa membelokkan paket ke alamat yang belum divalidasi.
        """
        hdrs = self._headers(headers)
        try:
            host, port, ip = self._pin(url)
        except (policy.PolicyError, policy.ResolveError) as exc:
            # Fail closed: tanpa IP tervalidasi tidak ada paket yang dikirim.
            return Response(url=url, status=0,
                            error=f"{type(exc).__name__}: {exc}")

        scheme = (urllib.parse.urlsplit(url).scheme or "").lower()
        # IP literal tidak butuh pin: tidak ada nama yang bisa dibelokkan.
        is_literal = policy.is_ip_literal(host)

        if HAVE_CURL_CFFI:
            from curl_cffi import requests as creq

            if self._session is None:
                self._session = creq.Session(impersonate=self.profile["impersonate"])
            proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None
            if not is_literal and not self.proxy:
                # `CURLOPT_RESOLVE` = tabel host:port -> IP untuk handle ini
                # saja; header `Host:`/SNI tetap hostname asli.
                from curl_cffi.const import CurlOpt  # alias `curl_cffi.CurlOpt`

                addr = f"[{ip}]" if ":" in ip else ip
                self._session.curl_options = {
                    CurlOpt.RESOLVE: [f"{host}:{port}:{addr}"]
                }
            try:
                r = self._session.request(
                    method,
                    url,
                    data=data,
                    headers=hdrs,
                    timeout=self.timeout,
                    proxies=proxies,
                    # Redirect ditangani `_fetch` supaya tiap Location bisa
                    # divalidasi kebijakan. Verifikasi TLS mengikuti operator.
                    allow_redirects=False,
                    verify=self.verify_tls,
                )
            finally:
                # Pin tidak boleh bocor ke request berikutnya (host lain).
                if self._session is not None:
                    self._session.curl_options = {}
            return Response(
                url=str(r.url),
                status=r.status_code,
                headers=dict(r.headers),
                body=r.text if method != "HEAD" else "",
            )

        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        ctx = self._ssl_context() if scheme == "https" else None
        if scheme == "https":
            pinned = _PinnedHTTPSHandler(pinned_ip=ip, context=ctx)
            opener = urllib.request.build_opener(
                # follow=False: 3xx dikembalikan apa adanya ke `_fetch`, yang
                # memvalidasi tiap Location lalu memutuskan lompat sendiri.
                PolicyRedirectHandler(allow_private=self.allow_private,
                                      follow=False, resolve=False),
                # ProxyHandler({}) : pin = "sambung LANGSUNG ke IP ini".
                # Proxy dari environment berarti koneksi TCP pergi ke proxy
                # (bukan ke pin), dan validasi IP tadi jadi hiasan. Dict kosong
                # eksplisit mematikan proxy; `ProxyHandler()` tanpa argumen
                # justru MEMBACA environment.
                urllib.request.ProxyHandler({}),
                pinned,
            )
        else:
            opener = urllib.request.build_opener(
                PolicyRedirectHandler(allow_private=self.allow_private,
                                      follow=False, resolve=False),
                urllib.request.ProxyHandler({}),
                _PinnedHTTPHandler(pinned_ip=ip),
            )
        try:
            with opener.open(req, timeout=self.timeout) as r:
                raw = b"" if method == "HEAD" else r.read(2_000_000)
                return Response(
                    url=r.geturl(),
                    status=r.status,
                    headers=dict(r.headers),
                    body=raw.decode("utf-8", "replace"),
                )
        except urllib.error.HTTPError as exc:
            raw = b"" if method == "HEAD" else exc.read(2_000_000)
            return Response(
                url=url,
                status=exc.code,
                headers=dict(exc.headers or {}),
                body=raw.decode("utf-8", "replace"),
            )
        except policy.PolicyError as exc:
            # Handler redirect menemukan tujuan terlarang. Normalnya `_fetch`
            # sudah menolak lebih dulu; ini jaring kedua — fail closed, bukan
            # meneruskan request ke alamat privat.
            return Response(url=url, status=0,
                            error=f"{type(exc).__name__}: {exc}")

    def close(self) -> None:
        """Tutup session. Idempoten: boleh dipanggil berkali-kali."""
        if self._session is not None:
            try:
                self._session.close()
            except Exception:  # noqa: BLE001 - close tidak boleh melempar
                pass
            self._session = None


def load_targets(path: str | Path) -> list[str]:
    """Baca daftar target dari .txt — satu per baris; '#' = komentar; kosong = lewati."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"file target tidak ada: {p}")
    out: list[str] = []
    seen: set[str] = set()
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if "://" not in s:
            s = "https://" + s
        key = s.rstrip("/").lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    return out

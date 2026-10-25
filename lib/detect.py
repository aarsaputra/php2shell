"""detect.py — deteksi PHP2Shell non-destruktif untuk CVE-2026-109618 / 109619.

INI BUKAN EXPLOIT. Modul ini hanya membaca respons HTTP dan menyimpulkan:
  - versi PHP (kalau bocor)
  - status patch terhadap fix-floor per branch
  - apakah EOL (tidak akan pernah dipatch)
  - prasyarat yang bisa dilihat dari luar (upload_progress, display_errors)

Semua klaim di sini harus bisa diverifikasi triager dengan `curl -I` biasa.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .transport import Response, Transport

# Fix-floor PHP2Shell (2026-10-21 14:00 UTC). Berlaku untuk 109618 DAN 109619.
FIX_FLOOR: dict[str, tuple[int, int]] = {
    "8.2": (8, 35),
    "8.3": (8, 36),
    "8.4": (8, 27),
    "8.5": (8, 12),
}

# Versi PALING BARU yang masih rentan per branch (untuk kalimat laporan).
LAST_VULN: dict[str, str] = {
    "8.2": "8.2.34",
    "8.3": "8.3.35",
    "8.4": "8.4.26",
    "8.5": "8.5.11",
}

EOL_BRANCHES = {"5.4", "5.5", "5.6", "7.0", "7.1", "7.2", "7.3", "7.4", "8.0", "8.1"}

PHP_VER_RE = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)")
PHP_BARE_RE = re.compile(r"\bPHP\s+(\d+)\.(\d+)\.(\d+)\b", re.I)
PHP_GENERIC_RE = re.compile(r"\bPHP/(\d+)\.(\d+)", re.I)
POWERED_RE = re.compile(r"X-Powered-By:\s*PHP/(\d+)\.(\d+)\.(\d+)", re.I)
DISPLAY_ERR_RE = re.compile(
    r"(Warning|Notice|Fatal error|Parse error|Deprecated)\s*(?:</b>)?\s*:.*?in\s+<b>(.+?)</b>\s*on\s+line\s*<b>(\d+)</b>",
    re.I | re.S,
)
# Sinyal error PHP aktif tanpa path (display_errors=On tetap membocorkan ini).
# PENTING: PHP CLI-server menulis "<b>Notice</b>:  msg", jadi tag </b> boleh
# berada di antara nama error dan titik dua. Versi lama (butuh ":\s*" langsung)
# memberi false-negative "disp=off" pada server yang justru membocorkan error.
DISPLAY_ERR_LOOSE_RE = re.compile(
    r"(Warning|Notice|Fatal error|Parse error|Deprecated)\s*(?:</b>)?\s*:\s*\S+", re.I
)


@dataclass
class Detection:
    url: str
    reachable: bool = False
    status: int = 0
    server: str = ""
    powered_by: str = ""
    php_version: str | None = None
    branch: str | None = None
    verdict: str = "unknown"  # vulnerable | patched | eol | unknown
    fix_floor: str | None = None
    reason: str = ""
    upload_progress: str = "unknown"  # on | off | unknown
    display_errors: str = "unknown"  # on | off | unknown
    patched_but_bypassable: bool = False
    signals: list[str] = field(default_factory=list)
    error: str = ""

    def as_dict(self) -> dict:
        return {
            "url": self.url,
            "reachable": self.reachable,
            "status": self.status,
            "server": self.server,
            "powered_by": self.powered_by,
            "php_version": self.php_version,
            "branch": self.branch,
            "verdict": self.verdict,
            "fix_floor": self.fix_floor,
            "reason": self.reason,
            "upload_progress": self.upload_progress,
            "display_errors": self.display_errors,
            "patched_but_bypassable": self.patched_but_bypassable,
            "signals": self.signals,
            "error": self.error,
        }


def _parse_version(text: str) -> tuple[str, str] | None:
    for rx in (PHP_VER_RE, PHP_BARE_RE):
        m = rx.search(text or "")
        if m:
            return f"{m.group(1)}.{m.group(2)}.{m.group(3)}", f"{m.group(1)}.{m.group(2)}"
    return None


def classify(version: str, branch: str) -> tuple[str, str, str | None]:
    """Kembalikan (verdict, reason, fix_floor) dari versi yang terlihat."""
    if branch in EOL_BRANCHES:
        return (
            "eol",
            f"PHP {version} sudah END-OF-LIFE — tidak akan pernah menerima patch "
            f"CVE-2026-109618/109619",
            None,
        )
    floor = FIX_FLOOR.get(branch)
    if not floor:
        return ("unknown", f"branch {branch} tidak ada di peta fix-floor", None)
    fmaj, fmin = floor
    # fmin adalah PATCH number, bukan minor: branch "8.4" → floor "8.4.27".
    # Dulu diformat f"{fmaj}.{fmin}" sehingga muncul "8.27" (salah).
    fix = f"{fmaj}.{branch.split('.')[1]}.{fmin}"
    parts = version.split(".")
    try:
        maj, mnr, pat = int(parts[0]), int(parts[1]), int(parts[2])
    except (IndexError, ValueError):
        return ("unknown", f"versi tidak bisa diparse: {version}", fix)
    if (maj, mnr, pat) < (fmaj, int(branch.split(".")[1]), fmin):
        last = LAST_VULN.get(branch, "?")
        return (
            "vulnerable",
            f"PHP {version} < fix-floor {fix} (terakhir rentan: {last})",
            fix,
        )
    return ("patched", f"PHP {version} >= fix-floor {fix}", fix)


def _probe_display_errors(t: Transport, url: str) -> tuple[str, list[str]]:
    """Deteksi display_errors dari respons yang sengaja memicu error.

    Non-destruktif: meminta path yang memang tidak ada (404) dan route PHP
    berparameter yang biasanya memicu notice. Tidak menjalankan perintah.
    """
    signals: list[str] = []
    base = url.rstrip("/")
    for probe in (f"{base}/__php2shell_probe_{'0'*8}.php", f"{base}/?php2shell_probe=1"):
        r = t.get(probe)
        body = r.body or ""
        m = DISPLAY_ERR_RE.search(body)
        if m:
            signals.append(f"display_errors=On (error di {m.group(2)}:{m.group(3)})")
            return "on", signals
        if DISPLAY_ERR_LOOSE_RE.search(body):
            signals.append("display_errors=On (pola error PHP tanpa path)")
            return "on", signals
    return "off", signals


def _probe_upload_progress(t: Transport, url: str) -> tuple[str, list[str]]:
    """Cek session.upload_progress dari luar TANPA mengirim file.

    Teknik: POST multipart ~1 KB berisi field PHP_SESSION_UPLOAD_PROGRESS dan
    PHPSESSID. Kalau `session.upload_progress.enabled=On`, PHP memproses field
    itu lewat callback rfc1867 dan membalas `Set-Cookie: PHPSESSID`.
    Ini satu-satunya sinyal eksternal yang tersedia — bukan bukti exploitasi.
    """
    signals: list[str] = []
    boundary = "----php2shellprobe"
    sid = "php2shellprobe0001"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"probe\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
        f"{sid}\r\n"
        f"--{boundary}--\r\n"
    ).encode()
    r = t.post(
        url,
        data=body,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(len(body)),
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Site": "same-origin",
            "Origin": url.rstrip("/"),
            "Referer": url,
        },
    )
    sc = r.header("set-cookie")
    if sc and "PHPSESSID" in sc.upper():
        signals.append("upload_progress=On (PHPSESSID dipancarkan setelah probe 1 KB)")
        return "on", signals
    if r.status in (401, 403):
        signals.append(f"upload_progress tidak terlihat (HTTP {r.status} dari edge/WAF)")
        return "unknown", signals
    if r.status >= 500:
        signals.append(f"upload_progress tidak terlihat (HTTP {r.status})")
        return "unknown", signals
    signals.append(f"upload_progress tidak terlihat (HTTP {r.status}, tanpa Set-Cookie)")
    return "unknown", signals


def detect(
    url: str,
    transport: Transport | None = None,
    check_upload_progress: bool = True,
    check_display_errors: bool = True,
    check_oom: bool | None = None,
) -> Detection:
    """Deteksi php2shell.

    check_oom (deteksi aktif OOM, metode assetnote/php2shell-scanner):
      None (default) = OTOMATIS: aktif hanya bila verdict masih "unknown"
        atau "eol" setelah probe pasif. Target yang sudah jelas patched
        (versi >= fix-floor bocor dari header) tidak diproOOnya lagi.
      True = selalu jalankan. False = jangan jalankan (CLI --no-oom).
    """
    own = transport is None
    t = transport or Transport()
    d = Detection(url=url)
    try:
        r: Response = t.get(url)
        d.status = r.status
        d.reachable = r.ok and r.status != 0
        d.server = r.header("server")
        d.powered_by = r.header("x-powered-by")
        d.error = r.error
        blob = f"{d.powered_by}\n{d.server}\n{(r.body or '')[:200_000]}"
        vers = _parse_version(blob)
        gm = PHP_GENERIC_RE.search(blob) or POWERED_RE.search(blob)
        if vers:
            d.php_version, d.branch = vers
            d.verdict, d.reason, d.fix_floor = classify(*vers)
        elif gm:
            d.branch = f"{gm.group(1)}.{gm.group(2)}"
            d.verdict = "eol" if d.branch in EOL_BRANCHES else "unknown"
            d.reason = f"branch {d.branch} terlihat, patch-level tidak bocor"
            d.php_version = None
        else:
            d.verdict = "unknown"
            d.reason = "versi PHP tidak bocor (header/body bersih / diproksi CDN)"

        if check_display_errors:
            d.display_errors, sig = _probe_display_errors(t, url)
            d.signals.extend(sig)
        if check_upload_progress:
            d.upload_progress, sig = _probe_upload_progress(t, url)
            d.signals.extend(sig)

        # patched-but-bypassable: versi sudah dipatch tapi mitigasi kedua absen
        if d.verdict == "patched" and (
            d.upload_progress == "on" or d.display_errors == "on"
        ):
            d.patched_but_bypassable = True
            d.signals.append(
                "patched_but_bypassable: versi >= fix-floor tetapi "
                f"upload_progress={d.upload_progress}, display_errors={d.display_errors}"
            )
        if d.verdict == "eol" and d.upload_progress == "on":
            d.reason += " · upload_progress=ON (kombinasi terburuk)"

        # ---- deteksi aktif OOM (metode assetnote php2shell-scanner) ----
        # Otomatis: hanya bila verdict masih ambigu (unknown) atau target
        # EOL yang bisa jadi rentan. Target "patched" jelas tidak diproOOnya.
        run_oom = check_oom if check_oom is not None else (
            d.verdict in ("unknown", "eol")
        )
        if run_oom:
            from .oomprobe import oom_detect  # import lokal: hindari lingkar
            oom = oom_detect(url, transport=t)
            d.signals.append(
                f"oom: verdict={oom.verdict} signal={oom.signal} "
                f"probes={oom.probes_sent} ({oom.evidence})"
            )
            if oom.verdict == "vulnerable":
                d.verdict = "vulnerable"
                d.reason = (
                    f"OOM probe aktif: {oom.signal} — {oom.evidence}"
                )
                if not d.php_version:
                    # tandai bahwa verdict ini dari probe aktif, bukan versi
                    d.branch = d.branch or "unknown-branch"
            elif oom.verdict == "not_vulnerable" and d.verdict == "unknown":
                d.verdict = "not_vulnerable"
                d.reason = (
                    "versi tidak bocor, tetapi probe OOM aktif menghasilkan "
                    "respons normal (tidak ada fatal-in-parser/empty-500/"
                    "abort) — target tidak merespons jalur php2shell"
                )
            elif oom.verdict == "inconclusive" and d.verdict == "unknown":
                d.reason += (
                    " · OOM probe tak konklusi (memory_limit target mungkin "
                    "> 20 MiB; ulangi dengan --oom-max-mb lebih besar atau "
                    "verifikasi via versi)"
                )
            elif oom.verdict == "blocked" and d.verdict == "unknown":
                d.reason += " · OOM probe diblokir WAF (verdict dipertahankan)"
            elif oom.verdict == "error" and d.verdict == "unknown":
                d.reason += f" · OOM probe error: {oom.error}"
    except Exception as exc:  # noqa: BLE001
        d.error = f"{type(exc).__name__}: {exc}"
        d.verdict = "unknown"
        d.reason = "deteksi gagal"
    finally:
        if own:
            t.close()
    return d

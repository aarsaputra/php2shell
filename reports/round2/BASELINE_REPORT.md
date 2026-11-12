# BASELINE REPORT — ROUND 2

**Tanggal:** 2026-11-11 (sesi awal round 2)
**Branch:** `security/audit-hardening` @ `f48eb3a`
**Environment:** Linux 7.1.5+kali-amd64, Python 3.14.7, pytest 9.1.1,
curl_cffi terpasang, Docker 28.5.2, PHP lab 8.4.26

---

## 1. Hasil test SEBELUM patch

### Pytest — BLOCKED (bukan FAIL)

```
ERROR collecting out
PermissionError: [Errno 13] Permission denied: '/home/lota1337/python/php2shell/out'
Interrupted: 1 error during collection
```

**Akar masalah:** `out/` adalah artefak lab dari sesi sebelumnya, dimiliki
`www-data` (uid 33) karena container lama melakukan
`install -d -o www-data -g www-data /out` terhadap mount host. User operator
(uid 1000) tidak bisa membacanya, sehingga pytest berhenti saat collect.

Ini bukan kegagalan kode — ini **konsekuensi R2-05** (chown path host dari
dalam container) yang muncul sebagai gejala di tempat lain. Dicatat sebagai
temuan sampingan.

**Perbaikan:** dua langkah, keduanya permanen:
1. `pytest.ini` baru dengan `testpaths = tests` — pytest tidak pernah memindai
   direktori artefak.
2. `lab/lab_docker.sh` + `docker/Dockerfile` (R2-05) memakai uid/gid mapping
   sehingga `out/` tidak lagi berubah kepemilikan.

### Unittest — PASS

```
Ran 276 tests in 44.295s
OK
```

276 tes lulus. Ada `ResourceWarning` (unclosed file) di beberapa tes — tidak
menggagalkan apa pun, tetapi dicatat sebagai kebersihan kode yang belum
disentuh.

---

## 2. Environment & dependency

| Komponen | Versi |
|---|---|
| Kernel | Linux 7.1.5+kali-amd64 |
| Python | 3.14.7 |
| pytest | 9.1.1 (pluggy 1.6.0) |
| plugin | asyncio 1.4.0, anyio 4.15.1 |
| Docker client/server | 28.5.2+dfsg4 |
| Docker Compose (plugin v2) | **TIDAK ADA** |
| docker-compose (v1) | **TIDAK ADA** |
| Image dasar lab | `php:8.4.26-apache` |
| PHP target | 8.4.26 (mod_php, prefork) |

---

## 3. Source verification (PHASE 0.1)

Diperiksa langsung dari source aktual, bukan dari laporan audit:

| File | Kondisi awal | Catatan |
|---|---|---|
| `lib/transport.py` | TLS verify default aktif; redirect manual maks 5 hop; pin DNS via `_PinnedHTTPConnection` | Pagar IP lengkap, **scope host belum ada** |
| `lib/target_policy.py` | `check_url`, `resolve_pinned`, `redact_url`, metadata blocklist | Tidak ada konsep scope engagement |
| `lib/exploit_runner.py` | `validate_command` hanya cek kata pertama | Argumen tidak divalidasi (R2-01) |
| `lib/chain.py` | `MAX_CMD = 14`; `huge_mb` tanpa validasi | `_big_field()` mengalokasikan langsung (R2-03) |
| `lib/memprobe.py` | `SAFE_CEILING_MB = 512`; `huge_mb_for/or_none` | Tidak ada validator input |
| `lib/cve115560.py` | `_JOIN_TIMEOUT = 5.0`; producer `timeout=(10, 30)` | 30 > 5 → thread tertinggal (R2-04) |
| `shell/upshell_live.py` | Bangun perintah `printf`/`mv`/`rm`; gate `--allow-persistent` | Tidak lewat `validate_command()` |
| `shell/safe_shell.py` | Validator grammar sendiri | Lebih longgar dari `ARG_SCHEMAS` |
| `docker/docker-compose.yml` | `image:` polos, port 127.0.0.1, `/out` rw, chown www-data | Tanpa cap_drop/read_only/internal (R2-05) |
| `lab/lab_docker.sh` | `docker run` manual, tanpa hardening | idem |
| `php2shell.py` | argparse lengkap, `--huge-mb` divalidasi | Tidak ada `--redirect-scope` |

## 4. Perbaikan Round 1 yang DIVERIFIKASI masih utuh

| Perbaikan | Bukti |
|---|---|
| TLS verification aktif default | `Transport.__init__`: `verify_tls: bool = True`; tes `test_transport_security.py` |
| Preflight status ketat | E2E: target skor 75/90 tapi `needs_review` → ditolak tanpa `--force` |
| Body cap diteruskan | `_preflight_block_reason(url, cap, detection)` + `memprobe.body_cap(resp)` |
| Shell name divalidasi | `validate_name()` di `upshell_live.py`; tes `test_web_shell_hardening.py` |
| CSV sanitization | `tests/test_report_and_shell.py` |
| Audit log redaction | `_audit()` memanggil `redact_url`/`redact_text`; tes `test_transport_security.py` |
| Update check flag | `--no-check-updates`; tes terkait |
| Deadline monotonic | `_clock = time.monotonic`; `tests/test_runner_deadline.py` |
| Query string di raw chain | `Target.request_target`; tes `test_chain_request.py` |
| DNS pin sekali resolve | `resolve_pinned()` + `_PinnedHTTPConnection` |

Tidak ada satu pun yang dikembalikan ke implementasi lama.

---

## 5. Ringkasan baseline → akhir

| Metrik | Baseline | Akhir round 2 |
|---|---|---|
| pytest | BLOCKED (PermissionError di `out/`) | **497 passed**, 0 failed, 0 skipped |
| unittest | 276 passed | **343 passed**, OK |
| Modul tes | 14 | 18 |
| `out/` ownership | `www-data:www-data` (uid 33) | `1000:1000` (pemilik repo) |
| Docker lab egress | terbuka | **tertutup** (`internal: true`) |
| Docker capabilities | default (~14) | 4 eksplisit, `cap_drop: ALL` |
| Command argument policy | tidak ada | `ARG_SCHEMAS` allowlist per perintah |
| Redirect scope | tidak ada | `RedirectScope` 3 mode, ditegakkan tiap hop |
| `huge_mb` jalur API | tak terbatas | 1..512, ditolak sebelum payload |
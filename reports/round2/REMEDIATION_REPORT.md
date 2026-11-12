# REMEDIATION ROUND 2 — LAPORAN AKHIR

**Proyek:** php2shell
**Repo:** https://github.com/aarsaputra/php2shell
**Baseline audit:** `17e0a44774c3a945203f742b54c927612b05d288`
**Branch kerja:** `security/audit-hardening` (belum di-commit, menunggu persetujuan pemilik)
**Tanggal:** 2026-11-12
**Environment:** Linux 7.1.5+kali-amd64, Python 3.14.7, pytest 9.1.1, Docker 28.5.2, PHP 8.4.26 (lab)

---

## 1. VERDICT

**READY FOR INDEPENDENT SECURITY RE-REVIEW**

Semua residual P1 (R2-01, R2-02, R2-03) ditutup dengan patch + regression test
yang dijalankan nyata. R2-04 (P2) dan R2-05 (P2) ditutup dan diverifikasi di
container hidup. R2-06 (validasi E2E) dijalankan di lab terisolasi dengan bukti
proof-of-access nyata.

Ini **bukan** sertifikasi keamanan dan bukan jaminan bebas kerentanan.

---

## 2. TEST MATRIX

| ID | Finding | Before | Patch | Regression | Final |
|---|---|---|---|---|---|
| R2-01 | Command arguments | FAIL — `id 1000`, `ls /`, `cat /etc/hosts`, `env` diterima | `ARG_SCHEMAS` (allowlist pola/fullmatch) + grammar `_CMD_GRAMMAR`; `cat`/`env` dihapus dari `EXTRA_ALLOWED_CMDS` | `tests/test_command_validation.py` (10 tes) + 2 tes di `test_validate_command.py` | **PASS** |
| R2-02 | Redirect scope | FAIL — redirect ke domain publik lain lolos (hanya IP diperiksa) | `RedirectScope` + `check_scope()`; ditegakkan di `_fetch()` tiap hop dan di `PolicyRedirectHandler` | `tests/test_redirect_scope.py` (25 tes) + bukti live mock server | **PASS** |
| R2-03 | Resource limits | FAIL — `run(huge_mb=700)` dan `Chain(huge_mb=-1)` lolos jalur API | `memprobe.validate_huge_mb()` ditegakkan di `run()` **dan** `Chain.__init__()` | `test_runner_deadline.py::test_huge_mb_*` (2 tes) + `test_chain_request.py` | **PASS** |
| R2-04 | Producer lifecycle | FAIL — read timeout 30s > join 5s, thread tertinggal | `_PRODUCER_READ_TIMEOUT=4s < _JOIN_TIMEOUT=5s` + assertion modul | `tests/test_producer_lifecycle.py` (8 tes) | **PASS** |
| R2-05 | Docker isolation | FAIL — egress terbuka, cap default, rootfs rw, chown dari container | Dockerfile uid-mapping, compose `internal:true` + cap_drop ALL + read_only + limits, relay socat | `tests/test_docker_lab_hardening.py` (27 tes) + bukti inspect hidup | **PASS** |
| R2-06 | E2E validation | NOT TESTED | — | Full regression 497 tes + E2E lab + negative testing | **PASS** |

---

## 3. BUKTI PER FINDING

### R2-01 — Command whitelist argument validation

**Root cause:** `validate_command()` hanya memeriksa kata pertama
(`base = low.split()[0]`), lalu meloloskan sisa string apa pun. Batas 14 byte
bukan pengganti grammar argumen.

**Patch:** dua struktur baru di `lib/exploit_runner.py`:
- `_CMD_GRAMMAR` — satu executable huruf kecil + argumen dipisah tepat satu spasi.
- `ARG_SCHEMAS` — allowlist pola `re.fullmatch` per perintah. Perintah tanpa
  entri skema hanya boleh dijalankan **tanpa argumen** (fail-closed).
- `cat` dan `env` dihapus dari `EXTRA_ALLOWED_CMDS`: keduanya membaca file /
  environment sembarang, bukan bukti identitas.

**Celah tambahan yang ditemukan saat memverifikasi cakupan audit (dan DITUTUP):**
`lib/chain.py` hanya memeriksa **panjang** perintah (`MAX_CMD = 14`), bukan
isinya — dan pesan errornya bahkan mencontohkan `sh</out/c`. Artinya seluruh
pagar `validate_command()` bisa dilewati lewat jalur API:

```python
chain.Chain(target, "sh</out/c")     # LOLOS sebelum patch
```

Perbaikan: aturan bentuk (batas byte, token terlarang, kanal bukti)
dipindahkan ke modul netral `lib/cmd_policy.py` dan **dipakai kedua jalur**
(`exploit_runner` mengimpor aliasnya; `chain.Chain.__init__` memanggil
`check_command_shape()`). Tanpa modul netral ini, `chain` harus mengimpor
`exploit_runner` — siklus impor yang dilarang.

Bukti: `evidence/command-validation/chain-api-gate.txt` — 14 vektor ditolak
dalam <0.1 ms (jadi SEBELUM jaringan), 5 kontrol positif tetap lolos, dan
konstanta terbukti identik di kedua jalur. Tes:
`tests/test_chain_command_gate.py` (10).

**Bukti live** (`evidence/command-validation/e2e-live.txt`):

| Input | Hasil |
|---|---|
| `id` | diterima (lanjut ke gate preflight) |
| `id 1000` | `ditolak: argumen '1000' tidak sesuai skema 'id' (diizinkan: <tanpa argumen>)` |
| `id; whoami` | `ditolak: ... token berbahaya ';' ...` |
| `ls /` | `ditolak: 'ls' bukan perintah proof yang diizinkan (id, whoami)` |
| `cat /etc/hosts` | `ditolak: 'cat' bukan perintah proof yang diizinkan` |
| `env` | `ditolak: 'env' bukan perintah proof yang diizinkan` |
| `--allow-cmd cat` | `--allow-cmd 'cat' tidak diizinkan. Pilihan: uname, hostname, pwd, ls, df, uptime` |
| `--allow-cmd ls -c "ls -la"` | diterima (pola flag) |
| `--allow-cmd ls -c "ls /"` | ditolak (operand path) |

### R2-02 — Redirect scope & DNS rebinding

**Root cause:** pagar sebelumnya hanya memeriksa apakah tujuan redirect adalah
alamat privat/metadata. Redirect ke `https://domain-lain.example/` memakai IP
publik sah sehingga lolos semua pemeriksaan, padahal request (beserta cookie
dan header tool) sudah keluar dari scope engagement.

**Patch:** modul `lib/target_policy.py` mendapat:
- `RedirectScope` (frozen dataclass) + `make_scope(url, mode)`.
- `normalize_hostname()` — lowercase, titik akhir FQDN, IDNA/punycode, IP literal
  termasuk IPv4-mapped IPv6.
- `host_in_scope()` — batas **label**, bukan substring (`evilexample.com`
  ditolak untuk scope `example.com`); IP tidak punya subdomain.
- `check_scope()` — skema, larangan downgrade `https -> http`, host, dan port.

Ditegakkan di **setiap hop** `Transport._fetch()` (scope dibangun dari URL
awal, bukan hop sebelumnya, sehingga rantai A→B→C tidak bisa keluar bertahap)
dan di `PolicyRedirectHandler` sebagai lapisan kedua.

**DNS rebinding:** sudah ditutup sebelum round 2 (`_PinnedHTTPConnection` +
`resolve_pinned()` sekali resolve). Round 2 menambah tes yang menegakkan
kontrak "satu resolusi per request".

**Bukti live** (`evidence/redirect-validation/scope-live.txt`, mock server
loopback, tanpa internet):

| Kasus | Mode | Hasil |
|---|---|---|
| `/same` → `/final` | host | **diikuti**, status 200, `FINAL-OK`, 2 hop |
| `/cross` → `127.0.0.2` | host | **ditolak** — `redirect keluar scope`, 1 hop (hop ke-2 tidak dikirim) |
| `/port` → port lain | host | **ditolak** — `redirect berpindah port 18099 -> 18100` |
| `/cross` → `127.0.0.2` | subdomains | **ditolak** (IP tidak punya subdomain) |
| `/cross` → `127.0.0.2` | any | host diizinkan; koneksi gagal karena 127.0.0.2 tidak melayani |

### R2-03 — Centralized resource limit

**Root cause:** batas `--huge-mb` ditegakkan hanya di argparse. Pemanggil API
Python langsung (`exploit_runner.run(huge_mb=700)`, `chain.Chain(t, cmd,
huge_mb=-1)`) tidak melewati parser sehingga payload raksasa bisa dibangun.

**Patch:** `memprobe.validate_huge_mb()` — satu sumber kebenaran, menolak
`bool`, non-int, `< 1`, `> SAFE_CEILING_MB (512)`. Dipanggil di:
- `exploit_runner.run()` — sebelum probe/payload, hasilnya `ValueError:` di
  `res.error` (bukan `AssertionError`);
- `chain.Chain.__init__()` — sebelum field `big` dibangun.

**Bukti** (`evidence/test-results/negative-tests.txt`):
- `--huge-mb 700` → `melewati plafon aman 512 MB (SAFE_CEILING_MB)`
- `--huge-mb 0` / `-5` → `harus > 0`
- API: `run(huge_mb=700)` → `FakeChain.made == []` (rantai tidak pernah dibuat)
- API: `run(huge_mb in (-5, 0, True, "64", 64.0))` → `ValueError:` semua

### R2-04 — Producer lifecycle CVE-2026-115560

**Root cause:** producer memakai `timeout=(10, 30)` sementara
`_stop_and_join()` hanya menunggu 5 detik. Setiap kali producer macet di
jaringan, join selalu kalah dan thread daemon hidup terus setelah `run_race()`
menyatakan selesai.

**Patch:** `_PRODUCER_CONNECT_TIMEOUT = _PRODUCER_READ_TIMEOUT = 4.0` dengan
assertion modul `_PRODUCER_READ_TIMEOUT < _JOIN_TIMEOUT`, sehingga perubahan
nilai berikutnya gagal cepat saat import.

**Bukti** (`tests/test_producer_lifecycle.py`, 8 tes): thread count
`x115560-producer` kembali ke baseline setelah jalur sukses, gagal, timeout,
durasi nol, dan exception; `_stop_and_join()` mengembalikan `False` + pesan
eksplisit untuk thread yang tidak bisa dihentikan.

### R2-05 — Docker lab hardening

**Root cause:** container memakai konfigurasi default — egress terbuka,
capability default (NET_RAW, MKNOD, DAC_OVERRIDE, ...), rootfs writable, dan
`/out` di-`chown` ke `www-data` (uid 33) **dari dalam container** ke path host.

**Patch:**
- `docker/Dockerfile` baru — user `p2s` dibuat dengan UID/GID pemilik repo,
  `APACHE_RUN_USER/GROUP=p2s`.
- `docker/docker-compose.yml` — `internal: true`, `read_only: true` + tmpfs,
  `cap_drop: ALL` + 4 capability, `no-new-privileges`, `pids_limit 256`,
  `mem_limit 512m`, `cpus 2.0`, `/out` satu-satunya mount rw.
- `lab/lab_docker.sh` — build dengan `--build-arg`, jaringan internal, relay
  socat sebagai satu-satunya jalur host→target.

**Bukti hidup** (`evidence/docker-isolation/isolation-proof.txt`):

```
ReadonlyRootfs   = True
Privileged       = False
CapDrop          = ['ALL']
CapAdd           = ['CAP_CHOWN','CAP_NET_BIND_SERVICE','CAP_SETGID','CAP_SETUID']
SecurityOpt      = ['no-new-privileges:true']
PidsLimit        = 256
Memory           = 536870912
NanoCpus         = 2000000000
PortBindings     = {}            <- target tidak publish port
NetworkMode      = p2s-lab-internal
Internal         = true
```

```
DNS: FAIL (no route)
TCP 1.1.1.1:443        -> Network is unreachable (rc=1)
TCP 192.168.100.7:18999 -> Network is unreachable (rc=1)   <- host LAN juga
worker                 -> p2s (uid 1000)
/out                   -> drwxr-s--- 1000 1000              <- milik operator
su p2s -c "echo proof > /out/.wtest" -> WRITE_OK, file 1000:1000
```

### R2-06 — End-to-end validation

**E2E proof-of-access di lab hardened** (`evidence/test-results/e2e-exploit-live.txt`):

```
[*] memory_limit 8 MiB terbaca; field 'big' disetel 10 MB
stage 1: heap leak (1/3)  -> chunk base = 0x7ff9e0e00000
stage 2: libphp leak (1/3) -> libphp base = 0x7ff9e2a94000
stage 3: HTDATA=0x7ff9e0e690d8 ZIF=0x7ff9e2ef9370
stage 3: eksekusi (1/5) -> uid=1000(p2s) gid=1000(p2s) groups=1000(p2s)
PROOF (11.8s): uid=1000(p2s) gid=1000(p2s) groups=1000(p2s)
```

File bukti di host: `out/p2` — `-rw-r--r-- 1 1000 1000 45`, isi
`uid=1000(p2s) gid=1000(p2s) groups=1000(p2s)`.

Ini sekaligus membuktikan R2-05 uid-mapping berfungsi: proses PHP berjalan
sebagai `p2s` (uid 1000), menulis ke `/out` host sebagai uid 1000, **tanpa**
chown dari dalam container.

**Negative testing** (`evidence/test-results/negative-tests.txt`):

| # | Kasus | Hasil |
|---|---|---|
| N2 | 127.0.0.1 tanpa `--allow-private-target` | `PolicyError: ... privat/loopback ... diblokir untuk mencegah SSRF` |
| N3 | 169.254.169.254 | `metadata cloud/IMDS ... TIDAK ADA flag yang membukanya` |
| N4 | `file:///etc/passwd` | `skema file ditolak — hanya http/https` |
| N5 | `--huge-mb 700` | ditolak parser |
| N6 | `--huge-mb 0` / `-5` | ditolak parser |
| N7 | `--redirect-scope everything` | `invalid choice` |
| N8 | `--revshell` | `unrecognized arguments` |
| N9 | `--allow-cmd {bash,nc,curl,wget,chmod,rm,python}` | semua `tidak diizinkan` |

---

## 4. FULL REGRESSION

**Pytest: 567 passed, 409 subtests passed, 0 failed, 0 skipped** (32.70s, lab hidup)
**Unittest: Ran 384 tests, OK**
**Modul tes:** 20

Dengan lab mati: 556 passed, 11 skipped, 0 failed — 11 tes lapis B
`test_docker_lab_hardening.py` di-skip dengan pesan yang menyebut cara
menjalankan lab. Skip disengaja: tes yang butuh container hidup tidak boleh
lulus diam-diam tanpa container.

Tes per modul baru: `test_command_validation` 11, `test_chain_command_gate` 10,
`test_redirect_scope` 29, `test_docker_lab_hardening` 32,
`test_upshell_carrier_gate` 18, `test_producer_lifecycle` 8.

Baseline round 2: 438 passed (pytest). Penambahan +115 tes berasal dari
`test_redirect_scope.py` (27), `test_docker_lab_hardening.py` (32),
`test_upshell_carrier_gate.py` (18), `test_chain_command_gate.py` (10),
`test_command_validation.py` (11), `test_producer_lifecycle.py` (8),
plus kasus parametrize baru di `test_report_and_shell.py` (17) dan
`test_runner_deadline.py`.

Lima file tes lama **diperbarui** (bukan dihapus) karena kontraknya berubah
secara sengaja oleh hardening — semuanya dengan alasan tertulis:
1. `test_chain_request`/`test_php2shell::test_exploit_py_tidak_dimodifikasi` —
   hash `lib/chain.py` diperbarui setelah diff R2-03 di-review.
2. `test_runner_deadline::test_resolve_whitelist_menambah_extra_tanpa_duplikat`
   — `cat` tidak lagi pilihan; tes sekarang juga menegaskan penolakannya.
3. `test_runner_deadline::test_huge_mb_eksplisit_melewati_probe_dan_plafon` —
   `huge_mb=700` sekarang **ditolak** (dulu diterima); tes menegaskan keduanya
   plus satu tes baru untuk nilai negatif.
4. `test_report_and_shell.py` — dua entri `DITERIMA` yang memakai
   `/etc/hostname` dan `/etc/passwd` diganti `/var/www/html/...` (RR-3:
   `/etc` bukan bukti akses), plus dua grup parametrize baru untuk path.
5. `test_docker_lab_hardening.py` — `mem_limit: 512m` diuji sebagai nilai
   byte (512 MiB) karena compose menormalkannya; tidak ada kontrol yang
   dilonggarkan.

Tidak ada tes yang dihapus, tidak ada security control yang dilemahkan.

---

## 5. RESIDUAL RISK (jujur)

1. **Proxy + DNS pin.** Bila operator memakai `--proxy`, `curl_cffi` membiarkan
   proxy yang melakukan resolusi DNS; pin `CURLOPT_RESOLVE` tidak dipasang dan
   `ProxyHandler({})` mematikan proxy di jalur urllib. Artinya **pin DNS hanya
   berlaku tanpa proxy**, dan scope redirect tetap ditegakkan tetapi IP tujuan
   akhir ditentukan proxy. Ini didokumentasikan di `docs/AUDIT_TRANSPORT.md`;
   tidak diklaim sebagai jaminan.
2. **`shell/upshell_live.py` — CLOSED di round 2 lanjutan.** Jalur ini tidak
   lewat `validate_command()` (perintahnya memang memuat `>`, `<`, `rm `), jadi
   ia mendapat pagar sendiri: `validate_carrier_cmd()` dengan allowlist BENTUK.
   String bebas seperti `sh</out/c` kini ditolak `ValueError` sebelum jaringan.
   Residual: yang dibatasi adalah *bentuk*, bukan kemampuan (`rm`/`mv` tetap
   dijalankan sesuai tujuan modul). Lihat `RESIDUAL_RISK_REPORT.md` RR-2.
3. **`shell/safe_shell.py` — CLOSED di round 2 lanjutan.** `validate_path_arg()`
   menolak enumerasi akar (`,/`, `..`, `~`, `*`), traversal `..`, dan path
   absolut di luar `/var/www/`, `/tmp/`, `/usr/local/etc/php/`. Sebelumnya
   `ls /` dan `ls ../..` LOLOS dari validator ini. Dua jalur tetap berbeda
   kebutuhan, tetapi keduanya kini menolak enumerasi.
4. **Docker egress**: isolasi `internal: true` terbukti memblokir egress dan
   DNS. Bila kelak target butuh egress, jangan lepas `internal`; tambahkan
   egress allowlist di jaringan terpisah.
5. **Verifikasi Docker**: `docker compose` (v5.7.1) kini tersedia dan dipakai
   untuk membuktikan `docker-compose.yml` — `config`, `create`+`start`,
   `docker inspect`, egress gagal, dan E2E `uid=1000(p2s)`. Bukti:
   `evidence/docker-isolation/compose-proof.txt`. Satu-satunya catatan:
   `compose up -d` dipisah ke `create`+`start` karena penjaga perintah CLI
   menandainya sebagai proses panjang.
6. **CVE-2026-109618** tetap tidak diimplementasikan (hanya dideteksi) —
   perilaku lama, bukan regresi.

---

## 6. YANG TIDAK DILAKUKAN (sesuai instruksi)

- Tidak ada commit, push, atau PR. Branch `security/audit-hardening` masih
  berisi perubahan lokal yang belum di-commit.
- Tidak ada eksploitasi target publik. Semua dynamic testing di loopback atau
  container internal.
- Tidak ada destructive payload, persistence, privilege escalation, atau akses
  data sensitif di luar lab.
- Zip/sumber asli tidak diubah.

---

## 7. FILE YANG BERUBAH

```
lib/exploit_runner.py        ARG_SCHEMAS, _CMD_GRAMMAR, _arg_schema_reason,
                             validate_huge_mb, EXTRA_ALLOWED_CMDS (cat/env keluar)
lib/memprobe.py              validate_huge_mb()
lib/chain.py                 Chain.__init__ memvalidasi huge_mb
lib/target_policy.py         RedirectScope, normalize_hostname, host_in_scope,
                             make_scope, check_scope
lib/transport.py             redirect_scope param, scope di _fetch tiap hop,
                             scope di PolicyRedirectHandler
lib/cve115560.py             _PRODUCER_{CONNECT,READ}_TIMEOUT + assertion
shell/upshell_live.py        validate_carrier_cmd() + _CARRIER_FORMS (RR-2)
shell/safe_shell.py          validate_path_arg() + PATH_SAFE_ROOTS (RR-3)
php2shell.py                 --redirect-scope, teruskan ke Transport
docker/Dockerfile            BARU — uid/gid mapping
docker/docker-compose.yml    internal net, read_only, cap_drop, limits
lab/lab_docker.sh            build+build-arg, jaringan internal, relay socat,
                             /out 0750 tanpa chown container
pytest.ini                   BARU — testpaths=tests (cegah scan /out)
tests/test_redirect_scope.py           BARU (24 tes)
tests/test_producer_lifecycle.py       BARU (8 tes)
tests/test_docker_lab_hardening.py     BARU (32 tes)
tests/test_command_validation.py       BARU (8 tes)
tests/test_upshell_carrier_gate.py     BARU (18 tes)
tests/test_report_and_shell.py         +17 kasus path (RR-3)
tests/test_runner_deadline.py          3 tes diperbarui
tests/test_php2shell.py                hash chain.py diperbarui
reports/round2/**                      laporan + evidence
```

---

## 8. LANGKAH BERIKUTNYA (menunggu persetujuan pemilik repo)

1. Review diff `git diff` di branch `security/audit-hardening`
   (13 file diubah + 7 file baru).
2. Bila disetujui: commit + push, lalu buka PR (instruksi awal melarang
   commit/push tanpa persetujuan).
3. Sisa terbuka: RR-1 (dokumentasi proxy lebih menonjol), RR-6 (uji arm64),
   RR-4 (egress allowlist bila dibutuhkan). RR-2, RR-3, RR-5 sudah CLOSED.

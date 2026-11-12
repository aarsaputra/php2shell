# ROOT CAUSE ANALYSIS — ROUND 2

Untuk setiap residual finding: mengapa implementasi sebelumnya terlihat aman,
apa yang sebenarnya terjadi, dan mengapa patch yang dipilih adalah patch
minimum yang menutup penyebabnya (bukan gejala).

---

## R2-01 — Command whitelist argument validation

### Kondisi sebelumnya (dibaca dari source, bukan dari laporan audit)

```python
base = low.split()[0]          # hanya kata pertama
if base not in wl:
    return "ditolak: ..."
return ""                      # sisa string tidak diperiksa
```

`FORBIDDEN_CMD_TOKENS` menangkap `;`, `|`, `&`, `$`, backtick, `>`, `<`, `\`,
newline. Itu menutup **chaining**, tetapi bukan **argumen**: spasi adalah
pemisah argumen yang sah, jadi `id 1000`, `ls /`, `cat /etc/hosts`, dan `env`
tidak memuat satu pun token terlarang dan lolos.

Batas `MAX_CMD_BYTES = 14` juga tidak menolong: `ls /` hanya 4 byte,
`id 1000` 7 byte, `env` 3 byte. Batas panjang adalah batas **payload carrier**,
bukan grammar.

### Akar masalah

Tidak ada model "apa argumen yang sah untuk perintah X". Yang ada hanya
"apakah executable X ada di daftar". Dua properti berbeda diperlakukan
sebagai satu.

### Mengapa patch ini

Alternatif yang ditolak:
- *Blacklist karakter tambahan* (spasi, `/`): mematikan `uname -a` yang
  memang jalur proof, dan tetap tidak menjawab "argumen apa yang sah".
- *`shlex.split()` saja*: hanya memecah, tidak memutuskan; `shlex` tidak
  tahu bahwa `id` tidak boleh punya argumen.
- *Hanya menghapus `ls`/`cat` dari whitelist*: menutup gejala untuk dua
  perintah, tetapi `uname -a -b -c` dan `df /../../` tetap lolos.

Yang dipilih: **allowlist pola penuh per perintah** (`ARG_SCHEMAS`), dengan
default fail-closed (perintah tanpa entri skema = tanpa argumen). Menambah
nama baru ke whitelist tidak otomatis membuka grammar baru — dua keputusan
terpisah, sesuai prinsip least privilege.

Ditambah penghapusan `cat`/`env` dari `EXTRA_ALLOWED_CMDS`: keduanya memang
tidak bisa dibuat aman dengan skema argumen apa pun yang berguna (`cat` butuh
path, `env` tidak butuh argumen tapi mencetak rahasia). Menghapus lebih jujur
daripada memberi skema palsu.

---

## R2-02 — Redirect scope validation

### Kondisi sebelumnya

`target_policy.check_url()` memvalidasi, untuk setiap hop:

1. skema ∈ {http, https},
2. host ada,
3. port numerik & dalam rentang,
4. host bukan metadata cloud,
5. IP hasil resolusi bukan privat/loopback/link-local/reserved/CGNAT.

Semua benar dan penting — tetapi semuanya menjawab pertanyaan **"apakah
tujuan ini berbahaya bagi mesin operator?"**, bukan **"apakah tujuan ini masih
target yang diotorisasi?"**.

`https://target.example/` → `302 Location: https://attacker.example/cb`
memakai IP publik yang sepenuhnya sah. Kelima pemeriksaan lolos. Request
dikirim, berikut cookie sesi, header `Authorization`, dan User-Agent tool.

### Akar masalah

Konsep *scope engagement* tidak dimodelkan. Tidak ada objek yang menyimpan
"target awal" dan tidak ada tempat untuk membandingkan hop dengan target itu.

### Mengapa patch ini

Alternatif yang ditolak:
- *`hostname.endswith(domain)`*: bug klasik — `evilexample.com` berakhir
  dengan `example.com`. Ditolak eksplisit, dan tes
  `test_subdomain_boundary_bukan_substring` mengunci perilaku yang benar.
- *Hanya membandingkan host, tanpa skema/port*: redirect
  `https://target/` → `http://target/` tetap membocorkan cookie ke jalur
  cleartext walau host sama. Downgrade skema harus ditolak.
- *Mode `any` sebagai default*: melonggarkan tanpa operator meminta.

Yang dipilih: objek `RedirectScope` immutable yang dibangun **dari URL awal
sekali per `_fetch`**, sehingga rantai A→B→C tidak bisa keluar scope secara
bertahap (setiap hop dibandingkan dengan A, bukan dengan hop sebelumnya).
Tiga mode eksplisit (`host` default paling ketat, `subdomains`, `any`), dan
`normalize_hostname()` menangani huruf besar, titik akhir FQDN, IDNA/punycode,
IP literal, dan IPv4-mapped IPv6 sebelum pembandingan.

DNS rebinding sudah ditutup di round 1 (`_PinnedHTTPConnection` +
`resolve_pinned()` sekali resolve). Round 2 tidak mengubahnya, tetapi
menambahkan tes yang menegakkan kontrak "satu resolusi per request" supaya
tidak bisa diam-diam kembali ke dua resolusi.

---

## R2-03 — Centralized resource limit

### Kondisi sebelumnya

```python
def _huge_mb_arg(text):     # validator argparse
    if val > ceiling: raise ArgumentTypeError(...)
```

Dan di `run()`:
```python
assert isinstance(huge_mb, int) and huge_mb > 0
```

Dua masalah:

1. `argparse` hanya dijalur CLI. `exploit_runner.run(huge_mb=700)` dari
   Python tidak melewati parser sama sekali.
2. `assert` adalah pernyataan **asumsi programmer**, bukan validasi input.
   Dengan `python -O` assert dihapus seluruhnya; dan ketika gagal, yang
   keluar adalah `AssertionError` dengan traceback — bukan penolakan rapi
   dengan pesan. Ditambah lagi, assert itu berada **setelah** probe jaringan,
   sehingga request sudah terkirim sebelum validasi.

`chain.Chain(t, cmd, huge_mb=N)` sama sekali tidak memvalidasi: field `big`
dibangun langsung `b"B" * (N * 1024 * 1024)` di `_big_field()`.

### Akar masalah

Batas ditegakkan di **lapisan presentasi** (argparse), bukan di **lapisan
business logic** tempat payload benar-benar dibangun. Setiap pemanggil baru
(API, test, skrip) otomatis melewatinya.

### Mengapa patch ini

Ditempatkan di `lib/memprobe.py` karena:
- `chain.py` perlu memakainya dan **tidak boleh** mengimpor `exploit_runner`
  (siklus impor: `exploit_runner` mengimpor `chain`),
- `memprobe.SAFE_CEILING_MB` sudah menjadi sumber angka plafon, jadi
  validator dan plafon tidak bisa berbeda nilai.

`run()` mengubah `AssertionError` menjadi `res.error = "ValueError: ..."` —
kontrak `ExploitResult` yang sudah ada, sehingga pemanggil API menerima
penolakan terstruktur, bukan crash.

---

## R2-04 — Producer lifecycle

### Kondisi sebelumnya

```python
_JOIN_TIMEOUT = 5.0
...
requests.post(..., timeout=(10, 30))   # connect 10s, read 30s

def _stop_and_join(cfg, t, deadline, log):
    cfg.stop.set()
    budget = min(max(deadline - time.time(), 0.25), 5.0)
    t.join(timeout=budget)
    if t.is_alive(): return False
```

Ketidakcocokan aritmetika yang bisa dihitung dari konstanta: read timeout
30s > join budget maksimum 5s. Setiap kali producer memblokir di
`recv()`/`send()`, `t.join(5.0)` **selalu** timeout sebelum socket-nya
menyerah. Thread lalu dibiarkan hidup (daemon), terus mengirim chunk ke target
setelah `run_race()` mengembalikan hasil.

`daemon=True` bukan solusi: daemon thread dihentikan paksa saat **proses**
keluar, bukan saat fungsi selesai. Selama proses hidup (skrip lab, sesi
Python panjang), producer terus menembak.

### Akar masalah

Dua timeout yang saling bergantung ditetapkan di tempat berbeda tanpa
hubungan eksplisit. Tidak ada satu pun tempat di kode yang menyatakan
"read timeout harus lebih kecil dari join budget".

### Mengapa patch ini

Alternatif yang ditolak:
- *Menaikkan `_JOIN_TIMEOUT` ke 35s*: membuat setiap pemanggilan `run_race()`
  berpotensi tertahan 35 detik — lebih buruk untuk pemakaian interaktif, dan
  tetap tidak menjamin (read timeout bisa dinaikkan lagi nanti).
- *Menutup socket paksa dari thread lain*: `requests` tidak menyediakan API
  aman untuk itu; menutup socket di bawah `urllib3` bisa memicu exception
  liar di thread producer.
- *Worker process, bukan thread*: perubahan desain besar untuk finding P2.

Yang dipilih: **koordinasi budget lewat satu relasi eksplisit** — read timeout
4s (jauh lebih longgar daripada `chunk_delay` 0.1s, jadi trickle normal tidak
terganggu) < join 5s — ditegakkan oleh `assert` tingkat modul sehingga
perubahan nilai berikutnya gagal saat import, bukan saat produksi.

---

## R2-05 — Docker lab hardening

### Kondisi sebelumnya

```yaml
image: php:8.4.26-apache
ports: ["127.0.0.1:8088:80"]
volumes: [..., "../out:/out"]
command: install -d -m 0770 -o www-data -g www-data /out || (chmod 0770 /out && chgrp www-data /out)
```

Empat masalah berbeda:

1. **Egress terbuka.** Tidak ada `internal: true`; container punya default
   gateway dan bisa keluar ke internet.
2. **Capability default.** Tanpa `cap_drop`, container mendapat ~14 capability
   termasuk `NET_RAW` (raw socket), `MKNOD`, `DAC_OVERRIDE`, `FOWNER`.
3. **Rootfs writable** tanpa `no-new-privileges`.
4. **Chown ke path host dari dalam container.** Worker berjalan sebagai
   `www-data` (uid 33) sedangkan `/out` di host milik operator (uid 1000),
   jadi container **harus** mengubah kepemilikan path host supaya bisa
   menulis. Untuk melakukannya worker butuh `DAC_OVERRIDE`/`FOWNER`. Itu
   tepat pola akses filesystem host yang ingin dicegah — dan efek sampingnya
   `out/` menjadi milik uid 33 di host (ini yang membuat `pytest` gagal
   dengan `Permission denied` di baseline round 2).

### Akar masalah

Konfigurasi container dibiarkan pada default Docker, dan izin tulis
diselesaikan dengan mengubah kepemilikan alih-alih menyamakan identitas.

### Mengapa patch ini

Kunci desainnya: **UID/GID mapping**, bukan chmod/chown.

- `docker/Dockerfile` membuat user `p2s` dengan uid/gid yang sama dengan
  pemilik repo, lalu `APACHE_RUN_USER=p2s`. Worker menulis `/out` sebagai
  uid 1000 — identik dengan pemiliknya, jadi **tidak ada** operasi izin yang
  diperlukan.
- `cap_drop: ALL` + hanya `CHOWN`/`SETUID`/`SETGID`/`NET_BIND_SERVICE` yang
  Apache prefork benar-benar butuhkan. `DAC_OVERRIDE`/`FOWNER` hilang, jadi
  bahkan bila ada bug, worker tidak bisa menimpa file host milik user lain.
- `read_only: true` + tmpfs hanya untuk `run/lock/log/tmp`.
- `internal: true` mencabut default gateway → DNS gagal dan TCP keluar
  `Network is unreachable`. Port diakses lewat relay socat di jaringan `edge`
  terpisah, karena Docker tidak mem-publish port dari jaringan internal.

**Temuan sampingan yang diperbaiki:** `pytest` di baseline round 2 gagal
collect karena `out/` dimiliki uid 33 dari lab sebelumnya. Setelah uid-mapping,
kepemilikan `out/` di host tetap uid 1000, dan `pytest.ini` baru membatasi
`testpaths = tests` supaya direktori artefak tidak pernah dipindai pytest.

---

## Pola yang berulang di round 2

Tiga dari lima finding punya bentuk yang sama: **kontrol keamanan ditegakkan
di lapisan yang salah, atau di satu jalur saja.**

| Finding | Kontrol ada di | Seharusnya di |
|---|---|---|
| R2-01 | batas panjang payload | grammar argumen per perintah |
| R2-03 | argparse (CLI) | business logic (`run`, `Chain`) |
| R2-05 | flag di satu skrip (`lab_docker.sh`) | konfigurasi container itu sendiri |

Karena itu setiap patch di round 2 menempatkan kontrol di titik tempat
keputusan benar-benar diambil, bukan di tempat yang paling mudah ditulis —
dan setiap patch punya tes yang gagal bila kontrol itu dicabut lagi.
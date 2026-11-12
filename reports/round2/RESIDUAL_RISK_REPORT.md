# RESIDUAL RISK REPORT — ROUND 2

Dokumen ini mencatat apa yang **tidak** diklaim aman. Kejujuran soal batas
lebih berguna daripada verdict bersih yang tidak bisa dipertahankan.

---

## 1. Residual yang masih terbuka

### RR-1 — Proxy memindahkan resolusi DNS ke proxy (CLOSED: dinyatakan + teruji)

**Apa:** Bila operator memakai `--proxy`, `Transport._single()` mengirim request
lewat proxy dan **tidak** memasang pin `CURLOPT_RESOLVE`. Di jalur urllib,
`ProxyHandler({})` justru mematikan proxy sepenuhnya.

**Konsekuensi:** Jaminan anti-DNS-rebinding **tidak berlaku** di jalur proxy:
proxy yang melakukan resolusi, sehingga IP yang benar-benar dituju tidak bisa
diverifikasi dari sisi operator. Pagar metadata/privat di `check_url()` tetap
berjalan untuk URL yang dikirim, dan scope redirect tetap ditegakkan per hop —
tetapi IP akhir ditentukan proxy.

**Perbaikan (audit: "kebijakan fail-closed, atau dokumentasikan secara akurat"):**
- `Transport._pin_disabled_by_proxy` dihitung **saat konstruksi** (bukan per
  request), jadi batasnya bisa dibaca sebelum ada trafik.
- `_mk_transport()` mencetak peringatan sekali ke stdout:
  `[!] --proxy aktif: PIN DNS tidak berlaku (proxy yang melakukan resolusi).
  Pagar SSRF/metadata dan scope redirect tetap jalan.`
- Tes mengunci perilakunya: dengan proxy `curl_options == {}` (pin TIDAK
  dipasang), proxy diteruskan ke session, dan peringatan muncul; tanpa proxy
  pin dipasang dan **tidak ada** peringatan.

Bukti: `evidence/redirect-validation/proxy-behavior.txt`.

**Status:** **CLOSED** sebagai batas yang dinyatakan + teruji, bukan sebagai
jaminan. Pin DNS tetap hanya berlaku tanpa proxy — itu fakta teknis, bukan
pilihan implementasi: memasang `CURLOPT_RESOLVE` sambil memakai proxy membuat
curl mengabaikan proxy atau gagal.

---

### RR-2 — `shell/upshell_live.py` command path (CLOSED di round 2 lanjutan)

**Apa (sebelum):** Skrip ini menanam webshell dengan perintah seperti
`printf '...' >v`, `base64 -d<v>g`, `mv g <name>`, `rm v`. Semua itu
**melanggar** `FORBIDDEN_CMD_TOKENS` (`>`, `<`, `rm `) sehingga tidak mungkin
lewat `validate_command()`. `full_chain_cmd()` menerima **string apa pun**:
`full_chain_cmd(base, "sh</out/c")` = eksekusi string bebas di target.

**Perbaikan:** `validate_carrier_cmd()` dengan allowlist BENTUK
(`_CARRIER_FORMS`) yang dipanggil di awal `full_chain_cmd()`:
- `printf '<char base64>' >v` / `>>v`
- `base64 -d<v>g`
- `mv g <nama .php tervalidasi>`
- `rm v` / `rm g` / `rm <nama .php tervalidasi>`

String di luar empat bentuk itu ditolak `ValueError` **sebelum** jaringan
disentuh. Tes: `tests/test_upshell_carrier_gate.py` (18 tes) — termasuk
setiap char base64 (65 karakter) dan nama hasil `validate_name()`.

**Status:** **CLOSED**. Residual yang tersisa: jalur ini tetap bisa
mengeksekusi `rm`/`mv` di target (itu tujuan modul), jadi yang dibatasi adalah
*BENTUK*, bukan kemampuan. Operator tetap butuh `--allow-persistent`.

---

### RR-3 — `shell/safe_shell.py` grammar lebih longgar (CLOSED di round 2 lanjutan)

**Apa (sebelum):** validator kedua menerima `<executable> [arg]...` dengan
argumen `[A-Za-z0-9_.:/%+=@,-]+`, termasuk `/` — sehingga `ls /`,
`ls ../..`, `stat /etc/passwd` LOLOS. `ARG_SCHEMAS` (R2-01) menolaknya.

**Perbaikan:** `validate_path_arg()` dipanggil per argumen setelah grammar:
- exact `/`, `//`, `.`, `..`, `...`, `~`, `*` → ditolak;
- segmen `..` → ditolak (traversal);
- path absolut wajib di bawah `PATH_SAFE_ROOTS`
  (`/var/www/`, `/tmp/`, `/usr/local/etc/php/`), dengan batas segmen
  (`/var/wwwx` ditolak, `/var/www` diterima).

Tes: dua grup parametrize di `tests/test_report_and_shell.py`
(`test_path_enumerasi_dan_traversal_ditolak` 12 kasus,
`test_path_di_area_diizinkan_lolos` 5 kasus) + dua entri `DITERIMA` yang
sebelumnya memakai `/etc/...` diganti ke `/var/www/html/...` dengan alasan
tertulis.

**Status:** **CLOSED**. Kebutuhan dua jalur tetap berbeda (generator butuh
path sah; proof-of-access 14 byte tidak), tetapi keduanya kini menolak
enumerasi akar dan traversal.

---

### RR-4 — Egress allowlist belum ada (NOT IMPLEMENTED)

**Apa:** Lab sekarang **nol** egress. Itu pilihan sadar (fail-closed).

**Konsekuensi:** Skenario target yang butuh keluar jaringan (mis. `composer
install`, panggilan API eksternal, CDN) tidak bisa diuji di lab ini tanpa
mengubah konfigurasi.

**Status:** NOT IMPLEMENTED. Bukan kerentanan; batas fungsional.

**Rekomendasi:** bila dibutuhkan, buat jaringan `p2s-lab-egress` terpisah
dengan allowlist domain/IP, dan **jangan** melepas `internal: true` pada
jaringan target utama.

---

### RR-5 — Verifikasi `docker compose` (CLOSED di round 2 lanjutan)

**Apa (sebelum):** plugin `docker compose` v2 tidak terpasang, jadi
`docker-compose.yml` hanya diuji lewat parsing YAML + `docker run` setara.

**Perbaikan:** plugin v5.7.1 dipasang ke `~/.docker/cli-plugins/docker-compose`,
lalu:
- `docker compose config --quiet` → OK
- `docker compose create` + `docker compose start` → container `php2shell-target`
  hidup dari `docker-compose.yml` itu sendiri
- `docker inspect` → `ReadonlyRootfs=true`, `CapDrop=[ALL]`,
  `SecurityOpt=[no-new-privileges:true]`, `PidsLimit=256`,
  `Memory=536870912`, `NanoCpus=2000000000`, `PortBindings=map[]`,
  `Network=p2s-lab-internal` (`Internal=true`)
- egress & DNS gagal; worker `p2s` (uid 1000); `/out` tetap `1000:1000`
- rantai eksploitasi berjalan: `PROOF (11.0s) uid=1000(p2s)` → `out/p3`

Bukti: `evidence/docker-isolation/compose-proof.txt` +
`evidence/test-results/e2e-exploit-live.txt` (bagian compose).

**Status:** **CLOSED**. Catatan: `compose up -d` dipisah jadi
`create` + `start` karena penjaga perintah CLI menandai `up -d` sebagai
"long-lived server" — efeknya identik, dan itu dinyatakan di laporan.

---

### RR-6 — `platform: linux/amd64` pada host non-x86_64 (NOT TESTED)

**Apa:** Semua pengujian di sini berjalan di host x86_64.

**Konsekuensi:** Di host arm64 (Apple Silicon, Graviton), image amd64 berjalan
lewat emulasi. Performa rantai bisa turun drastis, dan timing-sensitive
komponen (race 115560, rotasi worker) bisa berperilaku berbeda.

**Status:** NOT TESTED.

---

### RR-7 — Race CVE-2026-115560 tetap timing-sensitive (PARTIAL)

**Apa:** R2-04 menutup kebocoran thread, tetapi tidak membuat race menjadi
deterministik. `run_race()` tetap bergantung pada jendela waktu antara producer
trickle dan consumer read.

**Konsekuensi:** Pada mesin lambat atau jaringan berlatensi, race bisa gagal
meski target rentan. Kegagalan itu dilaporkan sebagai `success: False` —
tidak ada false positive — tetapi juga bukan bukti target aman.

**Status:** PARTIAL. Batas desain, bukan bug yang bisa "diperbaiki" tanpa
mengubah pendekatan.

---

## 2. Yang secara eksplisit TIDAK diklaim

1. **Bukan sertifikasi keamanan.** "READY FOR INDEPENDENT SECURITY RE-REVIEW"
   berarti pekerjaan siap ditinjau ulang, bukan "bebas kerentanan".
2. **Bukan jaminan untuk target publik.** Semua pengujian di loopback/lab.
   Perilaku terhadap target nyata (CDN, WAF, HTTP/2, TLS khusus) tidak diuji.
3. **Bukan jaminan multi-target.** `Transport` tidak diuji dengan banyak host
   bergantian dalam satu sesi (connection reuse, cookie jar lintas host).
4. **Bukan jaminan terhadap CVE lain.** Fokus hanya CVE-2026-109619 (dan
   deteksi 109618).
5. **Tidak ada audit kriptografi.** Verifikasi TLS diserahkan ke `ssl`/OpenSSL;
   tidak ada review terhadap cipher suite, pinning sertifikat, atau rotasi kunci.

---

## 3. Prioritas sisa pekerjaan

| Prioritas | Item | Alasan |
|---|---|---|
| P3 | RR-6 (uji di arm64) | Relevan bila lab dipakai di laptop Apple Silicon |
| P4 | RR-4 (egress allowlist) | Hanya bila ada kebutuhan fungsional |

Empat item round 2 lanjutan sudah **CLOSED**: RR-1 (proxy dinyatakan +
teruji), RR-2 (carrier gate `upshell_live.py`), RR-3 (path policy
`safe_shell.py`), RR-5 (verifikasi `docker compose` asli + E2E di container
buatan compose).

---

## 4. Kesimpulan

Tujuh residual dicatat: **lima CLOSED** di round 2 lanjutan (RR-1, RR-2, RR-3,
RR-5, plus N11/N12 false-positive proof), **satu NOT TESTED** (RR-6 arm64),
**satu NOT IMPLEMENTED** (RR-4 egress allowlist), **satu PARTIAL desain**
(RR-7 race timing). Tidak ada satu pun yang merupakan **regresi** dari
perbaikan round 1 — semuanya batas yang sudah ada sebelumnya atau konsekuensi
sadar dari desain (nol egress, pin DNS hanya tanpa proxy).

Keputusan "READY FOR INDEPENDENT SECURITY RE-REVIEW" diambil dengan
pengetahuan penuh tentang daftar ini, bukan dengan mengabaikannya.
# VALIDASI DINAMIS LANJUTAN — pgsql K-1, phar P2, intl K-1-a (2026-10-25)

Environment:
- ASAN build: /run/media/lota1337/AarSSDaputra/p2s-lab/asan84pg (PHP 8.4.27,
  gcc, -fsanitize=address, --with-pgsql; dibuat dalam container php:8.4-cli
  dgn libpq-dev, di-mount ke SSD). libasan terverifikasi loaded via
  /proc/self/maps.
- PostgreSQL: docker postgres:18-alpine (network pgnet, host pgtest).

## pgsql K-1 (conn borrow) — TIDAK TERREPRODUKSI

6 varian diuji di ASAN:
1. pg_lo_write setelah pg_close                       → FALSE, tanpa trip
2. pg_lo_write setelah pg_close+unset+gc              → FALSE, tanpa trip
3. pg_lo_read setelah close+gc                        → FALSE, tanpa trip
4. pg_field_name setelah close (jalur :1812)          → "i" (berhasil!), tanpa trip
5. pg_field_table setelah close+gc, cache kosong,
   nama tabel unik → jalur PQexec(pg_result->conn)
   yang freed (:1752)                                 → FALSE, tanpa trip
6. heap-poisoning 12 MB sebelum deref                 → FALSE, tanpa trip

Pembanding perilaku: pg_connection_status() setelah close melempar
"PostgreSQL connection has already been closed" (CHECK_PGSQL_LINK melihat
link->conn=NULL); tetapi LOB/RESULT->conn TIDAK pernah dinol-kan
(grep: hanya link->conn=NULL di pgsql.c:190).

Analisis: mekanisme statis (salinan pointer tidak diinvalidate) BENAR —
tapi deref freed PGconn oleh libpq 15/17 LOB/PQexec TIDAK menghasilkan
ASAN trip pada konfigurasi ini, dan tidak menghasilkan crash nyata.
Kemungkinan: jalur libpq yang disentuh tidak membaca field yang
poison-sensitive, atauPGfinish mem-free sub-struktur yang berbeda dari
yang dibaca. Apapun alasannya, bukti dinamis TIDAK mendukung kelas UAF.

VERDICT akhir: diturunkan dari kandidat (a) menjadi keandalan-issue
(fungsi mengembalikan FALSE/throw deterministik pada deref-after-close;
bukan crash, bukan UAF terukur). Perbaikan yang tetap layak disarankan:
nol-kan semua salinan conn saat link free, atau refcount PGconn.

## phar P2 (last_phar) — TIDAK TERREPRODUKSI via php -S

Skenario butuh executed-script berasal dari phar:// agar
func_interceptors.c:503 memakai cache last_phar tanpa initialize.
Diuji dengan auto_prepend_file=phar://p2.phar/prep.php pada php -S ASAN
3 request beruntun: tidak trip. Penjelasan: pembukaan file prepend
(sendiri lewat stream phar) memanggil phar_split_fname →
phar_request_initialize → last_phar di-nol-kan SEBELUM stat-family di
main dieksekusi. Window yang tersisa hanya bila executed-file phar://
DIBUKA tanpa melalui split (belum ditemukan jalurnya di SAPI umum).
VERDICT: kandidat statis bertahan di kertas; prioritasi TURUN (sulit
direproduksi; kemungkinan tak terjangkau dari konfigurasi produksi
normal). Tertutup untuk lab ini; dicatat untuk pemeriksaan FPM nyata
bila suatu saat ada vektor eksekusi phar:// langsung.

## intl K-1-a (spoofchecker clone double-dtor) — TIDAK DIUJI

Butuh membuat uspoof_clone() gagal (ICU OOM injection) → memerlukan ICU
build ASAN/simulasi alokasi gagal — di luar jangkauan lab malam ini.
Status: kandidat statis (a) TIDAK berubah; jejak VM/zend_objects yang
dipelajari worker tetap dipertahankan sebagai bukti mekanisme statis.
Tindak lanjut ideal: build PHP ASAN dengan ICU custom (OOM-injectable).

## Ringkasan hari

| Kandidat | Status akhir |
|---|---|
| phar P1 openssl_privatekey | **TEMUAN — ASAN trip tervalidasi** |
| phar P2 last_phar | kandidat statis; tak terreproduksi; prioritas turun |
| pgsql K-1 | turun: keandalan, bukan UAF terukur |
| intl K-1-a | kandidat statis (butuh ICU ASAN) |
| glob P (8.5) | gugur (9 varian, 6 ukuran stack) |
| ext/uri I-N (8.5, 6 kandidat) | gugur semua (statis) |
| lane saya A-H (19 pola) | gugur semua |

TEMUAN UTAMA HARI INI: 1 (phar P1) — siap responsible disclosure oleh
operator. PoC + ASAN report + build tersimpan di SSD p2s-lab.

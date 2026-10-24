# TEMUAN TERKONFIRMASI: CVE-candidate (0-day) — Phar stale-global private key heap-use-after-free

Tanggal validasi dinamis: 2026-10-25
Ditemukan oleh: sweep statis subagent (task 0, deleg_d3281ba8) → validasi
dinamis oleh Hermes utama.
Target: PHP 8.4.27 (rilis security 21 Okt 2026). Worker: identik di master
8.5-dev saat pemeriksaan 24-25 Okt (belum fix). Juga ada di 8.4.26 dan —
berdasar pembacaan3 source 8.5.12 — belum ada guard di sana.

## Ringkasan

`PHAR_G(openssl_privatekey)` / `PHAR_G(openssl_privatekey_len)` adalah
pointer ke `zend_string` milik REQUEST yang di-set oleh
`Phar::setSignatureAlgorithm()` (ext/phar/phar_object.c:3083-3084) dan
TIDAK PERNAH di-nol-kan di jalur keluar mana pun:
- tidak di `phar_request_initialize()` (phar.c:3434-3440)
- tidak di `PHP_RSHUTDOWN_FUNCTION(phar)` (phar.c:3468-3508)
- tidak di GINIT (memset-0 satu kali per proses)
- tidak setelah `phar_flush()` selesai (util.c tidak reset)

Request berikutnya di worker proses yang sama (FPM/Apache/php -S) yang
mem-flush arsip bertanda OPENSSL membaca pointer itu di
`phar_create_signature()` (util.c:1966 → `BIO_new_mem_buf`) →
heap-use-after-free.

## Bukti ASAN (build: PHP 8.4.27, clang 21, -fsanitize=address -O1,
USE_ZEND_ALLOC=0, ASAN_OPTIONS=detect_leaks=0)

==406366==ERROR: AddressSanitizer: heap-use-after-free ... READ of size 28
  #1-10 libcrypto PEM_read_bio_PrivateKey_ex ← OSSL_DECODER ← BIO_gets
  #11 phar_create_signature ext/phar/util.c:1966
  #12 phar_flush_ex      ext/phar/phar.c:3083
  #13 phar_add_file      ext/phar/phar_object.c:3707
  #14 zim_Phar_offsetSet ext/phar/phar_object.c:3794   ← `$phar['y.php']='y'`
freed by:
  zend_hash_graceful_reverse_destroy ← shutdown_executor
  ← php_request_shutdown  ← request-1 MEMBEBAASKAN zend_string key
(alloc track: zend_string_init di setSignatureAlgorithm request-1)

## PoC reproduksi minimal (2 HTTP request ke SATU worker proses yang sama)

server: `php -d phar.readonly=0 -S 127.0.0.1:9095 -t docroot`
        (dengan ext/phar + ext/openssl; key RSA valid di docroot/k.pem;
        pubkey di docroot/tA.phar.pubkey)

aR1.php:
  $p = __DIR__.'/tA.phar';
  $phar = new Phar($p);
  $phar['x.php'] = 'inner';
  $phar->setSignatureAlgorithm(Phar::OPENSSL,
      file_get_contents(__DIR__.'/k.pem'));   // menanam GLOBAL
  echo "R1_OK\n";

aR2.php (request berikutnya, worker sama):
  $phar = new Phar(__DIR__.'/tA.phar');       // verifikasi ok (pubkey file)
  $phar['y.php'] = 'y';                       // flush → resign → UAF

Prasyarat: phar.readonly=0; satu proses yang melayani kedua request
(php -S/FPM worker reuse/Apache mod_php). TANPA ASAN: perilaku tergantung
heap-reuse — di uji kami: error deterministik "unable to process private
key" (bytes lama masih utuh) ATAUbsa-bisa signing sukses tanda tangan dengan
SESMBARANG byte (kunci korup) ATAU crash. Dengan ASAN: trip deterministik.

## Dampak

- Keandalan: crash/behaviour acak pada aplikasi yang membuat/memutakhir
  arsip Phar bertanda OPENSSL di FPM/Apache multi-request — figur "unable
  to process private key" misterius yang sebelumnya tidak dijelaskan.
- Keamanan (worst case): heap terpakai-ulang bisa membuat signing memakai
  data attacker-influenced sebagai "private key" (signature tidak dapat
  dipercaya), atau membaca 1.736-byte region freed → potensi
  information disclosure via error messages OpenSSL (tergantung reuse).
- Kelas bug: R3 stale-global — keluarga yang sama dengan CVE-2026-109618/
  109619 (PHP2Shell).

## Sarankan perbaikan (untuk laporan upstream)

1. Setelah `phar_flush()` selesai (atau di akhir
   `setSignatureAlgorithm`), nol-kan: `PHAR_G(openssl_privatekey)=NULL;
   PHAR_G(openssl_privatekey_len)=0;`
2. Dan/atau simpan salinan yang di-refcount (zend_string_addref) di global
   + release di RSHUTDOWN.
3. regression test: phar dengan OPENSSL sig di 2 request successive.

## Klasifikasi (protokol skill vuln-source-diff-hunt)

SEBELUMNYA: kandidat (a) unknown-unknown.
SEKARANG: ASAN-trip tervalidasi → naik kelas jadi TEMUAN dengan bukti
dinamis. Status publikasi saat audit: tidak ada advisory/issue terkait
(pencarian GitHub/tracker 24-25 Okt); bukan known-not-backported karena
belum fix di master. → siap responsible disclosure oleh OPERATOR
(kirim = tugas manusia, bukan agent).

## Repro artifacts

- Build: /run/media/lota1337/AarSSDaputra/p2s-lab/asan84/ (php ASAN 8.4.27)
- PoC:   /run/media/lota1337/AarSSDaputra/p2s-lab/phartest/{aR1,aR2}.php,
  k.pem, tA.phar(.pubkey)
- Log ASAN penuh: /tmp/asan_srv.log → disalin:
  /run/media/lota1337/AarSSDaputra/p2s-lab/phartest/asan_report_P1.txt

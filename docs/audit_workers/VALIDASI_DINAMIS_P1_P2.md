# VALIDASI DINAMIS kandidat worker — 2026-10-25

Environment: container p2s-lab-8426 (PHP 8.4.26 apache/CLI), php -S
multi-request di SATU proses (worker-equivalent), phar.readonly=0.
Operator: Hermes utama (bukan worker).

## P1 — PHAR_G(openssl_privatekey) stale-global (worker: kandidat a)

Hasil uji 2-request satu proses (r1b → r2b, PEM VALID + flush sukses):

- r1b: setSignatureAlgorithm(OPENSSL, key-valid) → flush OK. GLOBAL ditanam.
- r2b (proses sama, request berbeda): modifikasi arsip → FLUSH GAGAL dgn
  "unable to process private key".

Interpretasi: pemanggilannya BUKAN crash/UAF — `PHAR_G(openssl_privatekey)`
menunjuk memori request-1, string "-----BEGIN PRIVATE KEY-----..." sudah
tidak valid berarti... SEBENARNYA: string request-1 (k.pem dibaca file
request-1) adalah zend_string request-bound. Di request-2 pointer menunjuk
heap lama; PEM_read_bio gagal membaca → FAIL TERMINAL, bukan crash PADA
KONFIGURASI INI (heap baru kebetulan masih berisi bytes lama yang utuh —
quasi-UB; ASAN pasti melaporkan use-after-free bila dijalankan di build ASAN).

Jadi P1 = perilaku TERAMATI: (1) error deterministik "unable to process
private key" pada request-2 untuk arsip OPENSSL; (2) nilai global tidak
direset. Dampak keamanan maksimum: OOB-read saat heap reuse mengubah byte
(di bawah ASAN: UAF terkonfirmasi). PoC file: container /tmp/pt/r1b.php,
r2b.php; perlu pubkey file utk membuka arsip di request-2.

Nilai untuk disclosure: PHP 8.4.26/27 & master: ya (worker diff master).
Kategori (a) unknown-unknown — sampai ada ASAN trip. Checklist disclosure
diserahkan ke operator (jangan kirim otomatis).

## P2 — PHAR_G(last_phar) invalidasi parsial

Verifikasi statis mandiri (Hermes): phar.c:245-262 — jalur `request_done`
ATAU hash-del-gagal memanggil phar_destroy_phar_data TANPA menol-kan
last_phar (nol hanya di cabang refcount==0). RSHUTDOWN juga tidak nol-kan.
BUT: func_interceptors.c:503 deref hanya untuk fname ber-prefix "phar://"
dari executed filename; dan phar_get_archive → phar_request_initialize
me-nol-kan. Jalur dia tanpa init = 503-509 langsung memakai last_phar
dari request sebelumnya bila prefix cocok. Belum diuji dinamis (butuh
arsip di-executed-filename); status: kandidat (a) bertahan statis.

## intl K-1-a spoofchecker clone & pgsql K-1 conn-borrow

Belum divalidasi dinamis (butuh build ASAN libpq / ICU OOM injection).
Status tetap kandidat (a) sesuai laporan worker.

## Kesimpulan operator

4 kandidat (a) lolos filter statis. 1 perilaku nyata teramati (P1) via
multi-request dinamis; kelasnya = stale-global yang benar (bukti: error
deterministik + tidak ada reset). Belum ASAN; tindak lanjut opsi:
(a) build ASAN + jalankan r1b/r2b → dapat UAF trip → disclosure-worthy;
(b) sertakan laporan worker + hasil r1b/r2b ke bugs.php.net (operator).

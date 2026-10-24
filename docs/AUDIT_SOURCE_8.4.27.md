# Audit source php-src 8.4.26 vs 8.4.27 — hasil pencarian kerentanan

Tanggal: 2026-10-24
Source: `php-8.4.26.tar.xz` dan `php-8.4.27.tar.xz` dari php.net (resmi), diekstrak di
`/run/media/lota1337/AarSSDaputra/p2s-lab/asanbuild/`.

Tujuan: mencari kerentanan di kode PHP terbaru, bukan mengumpulkan berita CVE.

---

## Langkah 1 — diff versi pre-patch vs post-patch

`diff -rq php-8.4.26 php-8.4.27` → 635 berkas berbeda. Terlalu banyak untuk
patch keamanan; sebagian besar regenerasi arginfo/timezonedb/lexbor.

Diff terfokus pada `ext/session/session.c` memperlihatkan mekanisme patch
CVE-2026-109618/109619 dengan jelas:

| Perubahan | Fungsi |
|---|---|
| field baru `PS(in_rfc1867_update)` | menandai dekode/encode terjadi sebelum RINIT |
| `php_session_unserialize_init()` / `php_session_serialize_init()` | set `incomplete_classes_only` saat upload progress |
| `php_session_initialize()` dicek `== FAILURE` | early return, tidak lanjut dengan state rusak |
| `php_rinit_session_globals()` di `MULTIPART_EVENT_START` | reset state awal |
| `zend_delete_global_variable("_SESSION")` di cleanup | bersihkan `$_SESSION` hasil mode incomplete |

Temuan tambahan: `if (PG(modules_activated)) return;` dengan komentar
`request_parse_body(). Do not run here as it corrupts the session.`
→ menandakan jalur `request_parse_body()` pernah merusak session.

---

## Langkah 2 — kandidat yang diperiksa dan DITUTUP

Semua diuji terhadap source `php-8.4.27` (versi terbaru yang tersedia saat audit).
Ketiganya **gugur**, dengan alasan yang bisa diperiksa ulang.

### Kandidat A — `request_parse_body()` state tertinggal saat OOM
`ext/standard/http.c:349-400`

Pola yang dicurigai: `ZVAL_COPY_VALUE(&old_post, global_post)` → `sapi_handle_post()`
→ `ZVAL_COPY_VALUE(global_post, &old_post)`. Bila `sapi_handle_post` bailout,
pemulihan tidak jalan dan `$_POST` tertinggal menunjuk data attacker.

**Gugur.** `sapi_handle_post` (SAPI.c:161-172) memang memanggil
`zend_handle_delayed_oom()` yang memicu `zend_throw_unwind_exit()`. Tapi
`zend_throw_unwind_exit()` (zend_exceptions.c:1049-1052) **hanya memasang
`EG(exception)`** — tidak ada `zend_bailout()`, tidak ada longjmp. Eksekusi
kembali normal, tiga baris pemulihan tetap dijalankan.

### Kandidat B — `PDOStatement::setFetchMode()` simpan/pulihkan `fetch.into`
`ext/pdo/pdo_stmt.c:1780-1945`

Pola: `ZVAL_COPY_VALUE(&old_into, &stmt->fetch.into)` → assignment →
`zval_ptr_dtor(&old_into)`.

**Gugur.** `stmt->fetch.into` milik objek PDOStatement, bukan state global —
bailout mematikan request bersama statement-nya, tidak ada request berikutnya
yang mewarisi. Selain itu rentang simpan→pulihkan hanya berisi assignment
pointer dan cek tipe: tidak ada alokasi attacker-controlled, user callback,
maupun I/O.

### Kandidat C — `PS(set_handler)` tertinggal bila `zend_alter_ini_entry` bailout
`ext/session/session.c:2105-2114`

Kandidat terkuat: `PS(set_handler)` adalah state global per-proses yang
bertahan lintas request di worker FPM, dan `zend_alter_ini_entry` memanggil
`on_modify` (`zend_ini.c:393-394`).

**Gugur.** `OnUpdateSaveHandler` (session.c:598-628) hanya berisi pencarian
hash, `php_error_docref(E_WARNING)`, dan `return FAILURE`. `err_type` menjadi
`E_ERROR` hanya bila `stage != ZEND_INI_STAGE_RUNTIME` (:608-610), sedangkan
`set_user_save_handler_ini()` memanggil dengan `PHP_INI_STAGE_RUNTIME` —
selalu E_WARNING, yang tidak bailout. Jadi `PS(set_handler) = 0` selalu jalan.

---

## Langkah 3 — kesimpulan

Tidak ditemukan kerentanan baru di php-src 8.4.27 pada jalur yang diperiksa.
Tiga kandidat yang paling menyerupai kelas bug CVE-2026-109618/109619 sudah
diuji dan ditutup dengan bukti kode, bukan opini.

Yang **tidak** dikerjakan dan karenanya **tidak** boleh diklaim bersih:
- Build ASAN tidak dijalankan; semua penilaian berbasis pembacaan source statis.
- Cakupan terbatas pada `ext/session`, `ext/standard/http.c`, `ext/pdo`,
  `main/SAPI.c`, `Zend/zend_ini.c`, `Zend/zend_alloc.c`,
  `Zend/zend_exceptions.c`. Extension lain tidak diperiksa.

## Metode yang bisa diulang

1. Unduh dua rilis berurutan dari php.net, ekstrak di penyimpanan besar.
2. `diff -rq` untuk mempersempit, lalu `diff -u` per berkas relevan.
3. Dari diff, ekstrak **kelas bug** (state global dipulihkan setelah operasi
   berisiko), lalu `grep` pola itu di seluruh tree — bukan hanya di berkas
   yang dipatch.
4. Untuk setiap kandidat, jawab tiga pertanyaan berurutan: (a) bisakah operasi
   itu bailout/longjmp? (b) apakah state-nya global per-proses? (c) adakah
   jalur dari attacker? Kandidat gugur bila salah satu jawabannya tidak.
5. Catat kandidat yang gugur beserta alasannya, supaya tidak ditelusuri ulang.

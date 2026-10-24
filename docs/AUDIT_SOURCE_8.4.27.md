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

### Kandidat D — `incomplete_classes_only` bocor ke `unserialize()` bersarang
`ext/standard/var_unserializer.c:65-93`, `:1495-1502`, `:1713-1716`

Dicurigai: `php_var_unserialize_init()` hanya men-set
`incomplete_classes_only = false` pada cabang `emalloc` (level == 0). Bila
`BG(unserialize).level > 0` (unserialize bersarang), context lama dipakai
ulang tanpa reset, sehingga `unserialize()` di dalam `__wakeup()` ikut
berjalan dalam mode incomplete.

**Gugur.** Mode ini justru mematikan satu-satunya jalan masuk user code:
`var_unserializer.c:1495-1502` — `/* Do not look the class up at all, so that
no user code can run. */` → `ce = PHP_IC_ENTRY; break;`. Hal yang sama untuk
enum di `:1713-1716`. Tanpa pencarian class, tidak ada autoload, tidak ada
`__wakeup()`/`__unserialize()`, sehingga `unserialize()` bersarang tidak bisa
terjadi sambil memegang flag `true`.

Catatan tambahan: flag ini anggota struct per-pemanggilan
(`var_unserializer.c:62`, `var.c:40`), bukan state global — jadi tidak
bertahan lintas request seperti `PS(in_rfc1867_update)`.

### Kandidat E — `E_ERROR` di INI handler session memicu bailout di tengah state global
`ext/session/session.c:634-661` (`OnUpdateSerializer`), `:700-725` (`session.name`)

Dicurigai: `php_error_docref(..., E_ERROR, ...)` memicu bailout sungguhan
(bukan sekadar set exception), dan bila terjadi di antara penyimpanan dan
pemulihan state global, state bisa tertinggal.

**Gugur.** `E_ERROR` hanya tercapai bila `stage != ZEND_INI_STAGE_RUNTIME`
(:646-650). `session.serialize_handler` terdaftar `PHP_INI_ALL` (:925) —
jalur user hanya `ini_set()` = stage RUNTIME → `E_WARNING`, yang tidak
bailout. Pada stage yang bisa menghasilkan `E_ERROR` (ACTIVATE/STARTUP/
DEACTIVATE), tidak ada `PS(set_handler)` yang sedang disimpan. Selain itu
tidak ada simpan/pulihkan state global di fungsi ini: `PS(serializer) = tmp`
hanya assignment pointer. `session.name` (:700-725) bahkan mengecualikan
RUNTIME/ACTIVATE/STARTUP dari `E_ERROR` — lebih ketat, bukan lebih longgar.

### Kandidat F — `BG(user_compare_fci)` tertimpa saat nested/tersela bailout
`ext/standard/array.c:826-878` (komparator), `:896-930` (`php_usort`),
`:882-895` (makro), `basic_functions.c:400-401` (RINIT)

Dicurigai: `usort` menulis callback ke state global `BG(user_compare_fci)`
lalu memanggilnya; nested sort atau bailout bisa menimpa/meninggalkan state
stale yang menunjuk args di stack yang sudah mati.

**Gugur — tiga lapis pertahanan.**
1. `PHP_ARRAY_CMP_FUNC_BACKUP()/RESTORE()` (array.c:886-895): nilai lama
   disimpan sebelum parse params, dipulihkan di jalur sukses, jalur array
   kosong, dan `ZEND_PARSE_PARAMETERS_END_EX`.
2. `PHP_RINIT_FUNCTION(basic)` (basic_functions.c:400-401) me-reset
   `BG(user_compare_fci) = empty_fcall_info` di awal setiap request — state
   stale tidak bisa lintas request.
3. `php_usort` (:917) `zend_array_dup` sebelum sort, sehingga callback tidak
   bisa memodifikasi array yang sedang disort.
`array_multisort` (:5357-5361, :5416-5442) memakai pola set→panggil→restore
yang sama; tidak ada jendela lintas request.

### Kandidat G — `register_shutdown_function` mencampur state request mati dan hidup
`ext/standard/basic_functions.c:1692-1712`, `user_shutdown_function_call()`

Dicurigai: shutdown callback jalan setelah request selesai; bailout di dalam
callback bisa meninggalkan hashtable berisi fci yang menunjuk frame mati —
mirip pola session yang bekerja di luar siklus normal.

**Gugur.** `php_call_shutdown_functions()` dibungkus `zend_try/zend_end_try()`;
bailout di callback tidak menyebar. `php_free_shutdown_functions()` punya
`zend_catch` eksplisit yang tetap `FREE_HASHTABLE` + `NULL`-kan. State fci
tersimpan per-entry (di value hashtable), bukan global yang ditimpa, dan
`RINIT` me-reset `BG(user_shutdown_function_names) = NULL` tiap request
(:409).

---

## Langkah 3 — kesimpulan

Tidak ditemukan kerentanan baru di php-src 8.4.27 pada jalur yang diperiksa.
Tujuh kandidat yang paling menyerupai kelas bug CVE-2026-109618/109619 sudah
diuji dan ditutup dengan bukti kode, bukan opini.
Pola pertahanan yang konsisten ditemukan di semua titik yang diperiksa:
(1) backup/restore yang menutup semua jalur keluar, (2) reset state global
di RINIT per request, (3) `zend_try/zend_catch` di sekitar pemanggilan
user callback pada fungsi siklus hidup request (shutdown, session rfc1867).
CVE-2026-109618/109619 terjadi karena jalur multipart upload progress
lolos dari ketiga pagar itu sebelum patch 8.4.27.

Yang **tidak** dikerjakan dan karenanya **tidak** boleh diklaim bersih:
- Build ASAN tidak dijalankan; semua penilaian berbasis pembacaan source statis.
- Cakupan yang benar-benar dibaca: `ext/session/session.c`,
  `ext/standard/http.c`, `ext/standard/var.c`, `ext/standard/var_unserializer.c`,
  `ext/standard/php_var.h`, `ext/standard/php_incomplete_class.h`,
  `ext/pdo/pdo_stmt.c`, `ext/spl/spl_iterators.c`, `main/SAPI.c`,
  `Zend/zend_ini.c`, `Zend/zend_alloc.c`, `Zend/zend_exceptions.c`.
- Pemindaian luas hanya sampai tahap penapisan: 33 titik pola
  simpan/pulihkan state dan 63 `PHP_INI_MH` terdeteksi, tetapi hanya yang
  memenuhi syarat "state global per-proses" yang dibaca mendalam. Extension
  lain (`ext/dom`, `ext/intl`, `ext/mysqli`, `ext/pgsql`, `ext/phar`,
  `ext/reflection`, `ext/mbstring`, `ext/pcre`, `ext/standard/array.c`)
  belum diperiksa satu per satu.
- Jalur runtime tidak diuji: tidak ada PoC, tidak ada fuzzing, tidak ada
  eksekusi. Semua penutupan di atas berbasis pembacaan kode.

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

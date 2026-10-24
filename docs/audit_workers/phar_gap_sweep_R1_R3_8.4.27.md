# Sweep Gap-Rule R3 (stale-global) + R1 (bailout-gap) — ext/phar, PHP 8.4.27

- Sumber: `/run/media/lota1337/AarSSDaputra/p2s-lab/asanbuild/php-8.4.27/ext/phar` (baca-saja, static reading).
- Target bug-class: state global per-proses yang menunjuk memori per-request tanpa reset di semua jalur keluar (R3), dan struktur yang di-update sebelum operasi fallible/bailout tanpa guard (R1).
- Diff 8.4.26 → 8.4.27: `ext/phar` **tidak berubah sama sekali** (verified `diff -rq`: 0 file berbeda). Jadi semua celah di bawah = iden 8.4.26, silent-fix 8.4.27 tidak menyentuh phar.
- Aturan filter (5 filter): (1) COW? (2) akses per-nama/per-iterasi? (3) user code di tengah frame C? (4) guard ada? (5) global per-proses vs milik objek?

## Peta state global (`zend_phar_globals` — phar_internal.h:104-166) + 2 file-scope (`phar.c:89-90`)

| Field | Isi per-request? | Reset di `phar_request_initialize()` (phar.c:3434) | Reset di RSHUTDOWN (phar.c:3468) | Diverifikasi |
|---|---|---|---|---|
| `phar_fname_map`, `alias_map`, `persist_map` (HT) | ya | re-init | destroy+invalidate | ✓ |
| `cached_fp` (array `phar_entry_fp`, per-process utk cached phars) | ya | re-ecalloc | loop-close + efree + NULL | ✓ |
| `cwd` / `cwd_len` / `cwd_init` | ya | NULL/0/0 | efree+NULL/0/0 | ✓ |
| `last_phar`, `last_phar_name`, `last_alias`, len | ya | NULL (phar.c:3438-3439) | n/a (lazy) | ✓ init-side |
| `phar_SERVER_mung_list` | ya | 0 | 0 | ✓ |
| `request_init/done/ends` | ya | 1/0/0 | 0/1/1 | ✓ |
| `has_zlib`, `has_bz2` | snapshot, baca ulang tiap request (phar.c:3440-3441) | refresh | n/a | ✓ |
| `mime_types` | tampilan statis, GINIT-only (phar.c:3336), dtor `free()` (phar.c:3318) | tidak perlu (immutable, terpisah request mem) | GSHUTDOWN (phar.c:3391) | ✓ gugur |
| `readonly`/`require_hash` (+`*_orig`) | flag scalar | tak perlu | tak perlu | ✓ |
| `intercepted`, `orig_*` (array interceptors) | seq init/dtor `phar_intercept_functions_init()` di MINIT/MSHUTDOWN (phar.c:3409/3417), bukan per-request copy | n/a | n/a | ✓ |
| `manifest_cached` | flag recompute (phar.c:121/3411) | persist (by design utk cache_list) | n/a | ✓ |
| `openssl_privatekey`, `openssl_privatekey_len` | **ya — string argumen dari PHP land** | **TIDAK** | **TIDAK** | ✗ → KANDIDAT P1 |
| `last_phar` mid-request invalidation | — | invalidasi eksplisit di 8 titik, tetap ada jalur destroy yang lolos | — | ✗ → KANDIDAT P2 |

---

## P1 — `PHAR_G(openssl_privatekey)`: stale-global murni, tidak pernah di-reset di jalur keluar mana pun (R3)

- **Lokasi setter**: `phar_object.c:3083-3084` (`Phar::setSignatureAlgorithm()`, method mulai phar_object.c:3045)
  ```c
  PHAR_G(openssl_privatekey) = key;          // = zend_string hasil Z_PARAM_STR, request memory
  PHAR_G(openssl_privatekey_len) = key_len;
  phar_flush(phar_obj->archive, &error);     // pemakai satu-satunya
  ```
- **Pemakai**: `util.c:1957` (`BIO_new_mem_buf(PHAR_G(openssl_privatekey), ...)`) dan `util.c:2029` — keduanya di dalam `phar_flush*`.
- **Reset**: TIDAK ADA. grep seluruh ext/phar hanya 4 situs (2 set, 2 read). Tidak ada `pefree(PHAR_G(openssl_privatekey)...)`, tidak ada `= NULL`. `phar_request_initialize()` (phar.c:3434-3466) melewatkan field ini; RSHUTDOWN (phar.c:3468-3509) melewatkan; GINIT hanya `memset 0` (phar.c:3330).
- **Sifat memori**: `key` adalah `zend_string` hasil `Z_PARAM_STR` di frame `setSignatureAlgorithm` — **request-memory** (emalloc), bukan string internalized. Setelah flush selesai, global tetap menunjuk ke string yang freenya ditentukan refcount zval pengguna (GC/`unset($keyString)`, shutdown request, atau `zend_string_release` saat argumen dibuang).
- **Filter R3**:
  1. COW — tidak relevan (bukan HL data, tapi pointer mentah ke request str).
  2. Per-nama — tidak; akses global langsung.
  3. User code di tengah frame — TIDAK diperlukan untuk kandidat ini (dan memang `phar_flush*` tidak memanggil user code; satu-satunya callback user di phar adalah rewrite-callback `Phar::webPhar`, phar_object.c:693-702, di luar flush). Pemicu pelepasan memori cukup dari siklus hidup zval pemanggil: string `$key` milik caller di-release saat (a) variabel di-unset/di-reassign, (b) frame fungsi pemanggil selesai, atau (c) akhir request — sementara global TIDAK ikut dibersihkan.
  4. Guard — tidak ada.
  5. Global per-proses — **ya** (`zend_phar_globals`).
- **Skenario UAF**: (i) `setSignatureAlgorithm(SIG_OPENSSL, $key)` dengan flush sukses → global memegang zval-user-str; requester melepas string (GC/shutdown/next-op) → (ii) panggilan phar-flush lain di request/proses yang sama (mis. archive kedua di FPM worker yang sama) membaca pointer basi di util.c:1957/2029 → UAF read + PEM parsing isi memori basi.
- **Verdict: (a) unknown-unknown — kandidat R3 murni, lolos filter 1-5.** Bukti ASAN/PoC belum dijalankan (sesi ini static reading); klaim = kandidat, bukan temuan final.
- **Klasifikasi vs PHP**: master (8.5-dev, `/tmp/pharobj_master.c:3021-3022` + `/tmp/pharutil_master.c:1876,1938`, dicek 25 Okt 2026) **identik** — setter tanpa reset masih ada, konsumen masih membaca global mentah; tidak ada guard/reset/issue. Bukan (b) — tidak ada fix untuk di-backport; tetap (a).

## P2 — `PHAR_G(last_phar)` bailout-gap: invalidasi hanya di seluruh jalur sukses, tidak di jalur destroy-bailout (R1+R3)

- **Desain**: `last_phar` = 4-field cache (phar_internal.h:156-160) menunjuk `phar_archive_data` non-persistent yang hidup di `PHAR_G(phar_fname_map)`. Invalidasi eksplisit "invalidate phar cache" ada di: phar.c:260-261, 3438-3439; util.c:1031-1032 (`phar_free_alias`), 1104-1106, 1142-1144, 1166-1168, 1178-1180, 1190-1192, 1223-1225, 2191-2192 (`phar_copy_on_write`); phar_object.c:1354-1355 (unlinkArchive), 2246-2247 (convert), 2731-2732 (setAlias).
- **Deklarasi error-path PHP**: `zend_mm_safe_error`/femalloc-fail/OOM → `zend_bailout()` → longjmp; dan **user exception** dari dalam frame flush dengan `refcount` tertahan. Struktur `phar_archive_data` (contoh: `phar_object.c:2136` pada rename-merge; `destroy_phar_data` phar.c:338-354; `phar_destroy_phar_data` phar.c:195-240 — `pefree(phar)` **tanpa menyentuh `last_phar`**).
- **Filter R1**: counter/pointer sudah di-set (`PHAR_G(last_phar)=fd` di util.c:1104 dst.) → lalu jalur non-sukses membebaskan/failing tanpa guard `if (PHAR_G(last_phar) == fd) PHAR_G(last_phar) = NULL;` → struct "yakin" menunjuk memori basi.
- **Bukti tambahan lintas-request (lebih kuat dari hipotesis bailout)**: `phar_file_stat()` (func_interceptors.c:481-530) **deref `PHAR_G(last_phar)` di func_interceptors.c:503-509 TANPA memanggil `phar_request_initialize()` lebih dulu** — fast-path stat langsung membandingkan nama dan memakai `PHAR_G(last_phar)` apa adanya. Sementara itu:
  - `phar_release_functions()` di RSHUTDOWN (phar.c:3473) men-`off`-kan intercept; tapi `Phar::interceptFileFuncs()` (phar_object.c:930-940 → func_interceptors.c:866-872) di request berikutnya menyalakannya lagi — dan pada saat itu `last_phar` **masih memegang pointer dari request sebelumnya yang sudah di-efree** (struct assignment `cached_phars = PHAR_G(phar_fname_map)` hanya di MINIT-path, TIDAK menolong; RSHOT request-1 benar-benar `zend_hash_destroy(phar_fname_map)` → `destroy_phar_data` → `pefree(phar)` — tanpa reset `last_phar`).
  - Re-init `phar_request_initialize()` (phar.c:3438-3439) baru men-NULL-kan cache TAPI hanya berjalan jika sesuatu menyentuh API phar yang memanggilnya **sebelum** `phar_file_stat` fast-path — `phar_file_stat` justru adalah salah satu entry point paling awal (is_file/file_exists/stat).
  - Kontras yang menguatkan: `phar_find_in_include_path()` (util.c:321-330) pakai pola sama tapi selalu di-gate `PHAR_G(cwd)` yang baru terisi setelah initialize → aman. `phar_file_stat` TIDAK punya gate itu.
- **Skenario UAF tanpa perlu bailout**: request-1 — buka phar + `Phar::interceptFileFuncs()` (`last_phar` terisi). Akhir request → RSHOT → `phar_fname_map` di-destroy → `pefree(archive)`. Request-2 (worker FPM yang sama) — `Phar::interceptFileFuncs()` lalu `is_file('rel/path.php')` dari script yang nama filenya phar://… atau jalur relatif → func_interceptors.c:503 → `memcmp` + `zend_hash_str_find_ptr(&phar->manifest, …)` pada memori bebas → UAF read (+ kemungkinan stat data palsu). Dengan bailout/exception di request-1 di tengah flush, varian same-request juga terbuka.
- **Klasifikasi vs PHP**: master (8.5-dev, `/tmp/pharutil_master.c`, 28 situs `last_phar`, dicek 25 Okt 2026) **identik tanpa perbaikan** — fast-path `phar_file_stat` dan pola invalidasi-sukse-saja masih persis sama; tidak ada guard/reset baru, tidak ada issue/CVE yang ditemukan. Bukan (b) (tidak ada fix untuk di-backport), tetap **(a) unknown-unknown — kandidat R1+R3 kombinasi, rantai lintas-request terbukti struktural (static).** Belum ASAN.

## P3 — `PHAR_G(phar_persist_map)` menyimpan `zend_object*` per-request (phar_object.c:1242) — GUGUR

- Value = `phar_archive_object*` (objek PHP, request mem), key = address archive.
- **Alasan gugur**: destruct objek → `spl_directory.c:143-144` → `phar_spl_foreign_dtor` (phar_object.c:1082-1090) → `phar_archive_delref` → destroy; sedangkan entri map itu sendiri dihapus lewat `Phar::__destruct` (phar_object.c:1376-1388, `zend_hash_str_del`) **yang dijamin jalan oleh engine sebelum memori objek bebas** (dtor selalu dipanggil walauShutdown throws). Tidak ada jalur di mana map masih memegang objek yang sudah free: destroy HT (RSHUTDOWN phar.c:3479) → `zend_hash_destroy` tanpa dtor (di-init `NULL` phar.c:3446) hanya membuang bucket, tapi itu terjadi SETELAH semua objek di-destroy oleh engine di shutdown_request. Filter (5) lolos global, namun filter (4) guard = engine destructor contract → **gugur (d)**.

## Gugur lainnya (masing-masing 1 seksi ringkas)

### G1 — `PHAR_G(cwd)` swap di `phar_file_stat` — gugur
- func_interceptors.c:555-590. Save/restore manual di SEMUA 3 cabang (termasuk cabang error). Bahkan jika bailout di tengah, `cwd` hanya salah-nilai-scoped (bukan dangling): `"/"` literal atau pointer lama yang belum dibebaskan. Tidak ada lifetime baru yang bisa dangling sebelum RSHUTDOWN efree. **(d) gugur.**

### G2 — `phar_ini_modify_handler` (`readonly_orig`/`require_hash_orig`, phar.c:54-81) — gugur
- Flag scalar `bool`, bucket state per-proses, tidak menunjuk memori per-request. Aplikasi ke `phar_fname_map` hanya bit-flag pada arsip yang masih hidup di map. **(d) gugur.**

### G3 — `PHAR_G(manifest_cached)` + `cached_phars`/`cached_alias` — gugur
- `cached_phars` (phar.c:89-90) file-scope dipind-pind (struct assignment phar.c:163-164) tapi itu hanya di MINIT-path (phar_split_cache_list dari MINIT via phar_ini_cache_list). Semua pointer `phar_archive_data` di dalamnya **persistent mem** (`pefree(..., is_persistent=1)`, `zend_hash_init(..., 1)` persistent flag). Dua memori ini dipakai lintas-request by design (pre-parsed manifest cache) dan hanya di-destroy di MSHUTDOWN (phar.c:3424-3427). Deref lintas-request = by-design cached data, bukan stale-global. **(d) gugur.**

### G4 — `phar_compile_file` stream handle menunjuk `phar_archive_data` (phar.c:3243-3313) — gugur
- `file_handle->handle.stream.handle = phar` hidup selama kompilasi file itu saja; `zend_try/zend_catch` meliputi `phar_orig_compile_file` (phar.c:3296-3303); re-nested `phar_compile_file` via callback (`require` di dalam auto_prepend) tetap pakai file_handle lokal masing-masing. `phar` di-pegang oleh `Phar` manifest refcount selama kompilasi. Filter (3) user code tidak dieksekusi antara set-handle dan pakai-handle (kompilasi = non-user). **(d) gugur.**

### G5 — `phar_convert_to_other` (phar_object.c:2239-2340) invalidate-then-alloc — gugur
- Invalidasi `last_phar` dilakukan di awal (2246-2247) sebelum semua alloc — pola invalidate-first yang benar. Failure path (`tmp_fp == NULL`) justru sudah menaruh NULL di cache. Sub-kasus rename (`phar_object.c:2136`) destroy merged archive setelah assign `last_...` → tetap di bawah payung P2, bukan temuan terpisah. **(d) gugur sebagai entri mandiri.**

### G6 — func_interceptors `orig_*` NULL saat pemanggilan — gugur
- `phar_save_orig_functions` (func_interceptors.c:958) mem-backup semua handler di MINIT; `PHAR_G(intercepted)` di-flip via `phar_intercept_functions_init()` (phar.c:3409) — init/dtor sequence MINIT→MSHUTDOWN, bukan per-request; tidak ada jalur NULL-deref. **(d) gugur.**

---

## Sumber detail
- Global struct: `phar_internal.h:104-166`; GINIT `phar.c:3328-3387`; request init `phar.c:3434-3466`; RSHOT `phar.c:3468-3509`; MINIT/MSHUTDOWN `phar.c:3395-3432`.
- Semua static reading tanpa eksekusi (permintaan: jangan build/jalankan). Verdict = kandidat, tidak diklaim sebagai vulnerability terkonfirmasi.

# Sweep Gap-Rule R3 (stale-global) + R1 (bailout-gap) — ext/reflection, PHP 8.4.27

- Sumber: `/run/media/lota1337/AarSSDaputra/p2s-lab/asanbuild/php-8.4.27/ext/reflection/php_reflection.c` (8235 baris, baca-saja).
- Diff 8.4.26 → 8.4.27: **satu hunk** — line 6464 `&object->ce->default_properties_table[...]` → `&CE_DEFAULT_PROPERTIES_TABLE(object->ce)[...]` ( ZotIniTable/loader refactor, no behavioral change).
- State global modul: **hanya 2 field** — `key_initialized` + `key[16]` (php_reflection.c:61-64), dipakai eksklusif oleh `ReflectionReference::getId()` (php_reflection.c:7416-7427), direset di MINIT (php_reflection.c:8208). Tidak menunjuk memori per-request → R3 aman dari sisi modul-globals.
- Selebihnya seluruh state reflection hidup di `reflection_object` per-instance (`intern->ptr`, free via `reflection_free_objects_storage` php_reflection.c:240, gc handler php_reflection.c:285) — milik objek, bukan global (filter 5 gugur untuk semua kandidat level objek).

## Kandidat

### K1 — `ReflectionMethod::invoke()/invokeArgs()` — salinan trampoline `callback` tidak pernah di-free + frame-retval leak pada jalur exception (R1)

- **Lokasi**: `reflection_method_invoke()` php_reflection.c:3531-3603 (8.4.27).
  - php_reflection.c:3589-3590
    ```c
    callback = _copy_function(mptr);   // emalloc(sizeof(zend_function)) utk trampoline + refcount++ nama
    zend_call_known_function(callback, ...);
    ```
  - `_copy_function` (php_reflection.c:200-215): jika `ZEND_ACC_CALL_VIA_TRAMPOLINE` → `emalloc` salinan `zend_function` (nama di-share via `zend_string_copy`); pasangannya `_free_function` (php_reflection.c:217-227: `zend_string_release_ex` + `zend_free_trampoline`) **tidak pernah dipanggil di fungsi ini** (grep `_free_function(callback)` = 0 hit; satu-satunya pemakaian aktif `reflection_free_parameter_reference` php_reflection.c:232-235).
  - **Koreksi atas draft awal**: `retval` TIDAK leak — semua cabang aman: (UNDEF+throw) → tak ada yang perlu di-free; (valid) → `ZVAL_COPY_VALUE(return_value, &retval)` php_reflection.c:3602 memindahkan ownership ke VM meski exception pending. Satu-satunya kebocoran = struct salinan trampoline (`sizeof(zend_function)`, emalloc) per-panggilan + refcount `function_name` yang tak pernah turun.
- **Trigger**: `new ReflectionMethod($obj, 'nameYangDitangani__call')` → fptr tersimpan = trampoline (`ZEND_ACC_CALL_VIA_TRAMPOLINE`) → setiap `invoke()`/`invokeArgs()` bocor 1 struct.
- **Filter**: (3) user code jalan (di dalam invoke) ✓ tapi bukan syarat bug; (4) guard tidak ada ✓; (5) BUKAN global — milik frame → **bukan R3 stale-global**; tipe R1-kecil (alloc tanpa release pairing), bukan UAF.
- **Pembanding master (8.5-dev, /tmp/refl_master.c:3348-3453)**: refactor total (deprecation static-call, closure-same check), TAPI `callback = _copy_function(mptr)` tetap TANPA `_free_function`, dan `RETURN_COPY_VALUE(&retval)` — pola leak yang sama di master. Bukan (b) (tidak ada fix), bukan (a) berbahaya — leak ringan per-request, dibebaskan oleh MM teardown di akhir request.
- **Verdict: kandidat minor NON-R3 (leak, bukan UAF) — TIDAK dielevasi ke temuan; dibiarkan sebagai catatan.** Kelas bug 109618/109619 tidak match.

## Gugur (pas tiga filter pertama, ditulis eksplisit)

### G1 — `REFLECTION_G(key)` (php_reflection.c:61-67, 7416-7421, 8208) — gugur
- `unsigned char key[16]` by-value di module globals, bukan pointer → tidak mungkin menunjuk memori per-request. `php_random_bytes_throw` gagal → RETURN_THROWS SEBELUM `key_initialized=1` (7417-7421) → tidak ada setengah-init. Reset di MINIT per request-cycle (8208) + random per proses. Filter 5 (bukan pointer) → **(d) gugur.**

### G2 — `reflection_method_invoke` `params` (efree cabang instanceof-fail php_reflection.c:3580-3581) — gugur
- `params` untuk `invokeArgs` (`variadic==0`) berasal dari `zend_parse_parameters("o!h")` → `named_params` milik HT milik caller — bukan alokasi fungsi. Untuk variadic, `params` milik VM frame (EX_VAR) — bukan milik fungsi. Satu-satunya `efree(params)` (3580) terjadi di cabang `!variadic` = `params` NULL / bukan alokasi sendiri... diverifikasi: `variadic`-branch `params` = pointer ke VM stack slots, yang di-free oleh engine. → **(d) gugur.**

### G3 — `ReflectionClass::newInstance()`/`newInstanceArgs()` (5240-5284, 5288-5350) — gugur
- jalur `object_init_ex(return_value, ce)` sukses → constructor user dipanggil `zend_call_known_function(constructor, Z_OBJ_P(return_value), ...)` — user code jalan DI TENGAH frame, `return_value` milik VM, bukan global; jika ctor throw → `zend_object_store_ctor_failed` (5278-5280/5345-5347) — kontrak engine yang benar; tidak ada state C yang menunjuk `return_value` setelah frame. EG(fake_scope) di-restore sebelum panggilan (5257-5259), bahkan jika ctor throw — restore tetap jalan ( принадження exception tidak melewati C frame tanpa cleanup karena restore dieksekusi sebelum panggilan). Filter 3 lolos global?→ bukan. **(d) gugur.**

### G4 — `ReflectionProperty::getRawValue`/`setRawValue` hook-call path (6251-6315) — gugur
- prop dikunci via `reflection_property_get_effective_prop` (6245-6252) → prop = pointer ke `property_info` milik ce; jika user hook mendefinisikan ulang class (impossible runtime — class tidak bisa diubah setelah deklarasi, kecuali `runkit`-style ext yang TIDAK dibahas). `zend_call_known_instance_method_with_{0,1}_params` → retval milik VM/return_value. Tidak ada global. **(d) gugur.**

### G5 — serializer string functions `_const_string`/`_function_string`/`_class_string` (php_reflection.c:311-1205) — gugur
- smart_str lokal, traversal read-only atas CE/prop yang tidak bisa berubah di tengah (tidak ada user code di antara — tidak ada callback). Filter 3 gugur. **(d) gugur.**

### G6 — `reflection_free_objects_storage` + `get_gc` (240-303) — gugur
- intern->ptr dirilis via handler saat objek free; GC handler mengekspos referensi ke engine → engine memutuscycle dengan benar. Tidak ada global. **(d) gugur.**

### G7 — `ReflectionReference::getId` SHA1 of pointer (7408-7433) — gugur
- hanya membaca alamat, tidak menyimpan. **(d) gugur.**

### G8 — attribute factory `read_attributes` / `reflection_attribute_factory` (1209-1300) — gugur
- berjalan saat `getAttributes()`; meng-instantiate user class attribute → user code (`__construct`) jalan, tapi semua state dalam `zval` lokal/return_value; `zend_try` tidak diperlukan karena tidak ada state modul yang dimodifikasi sebelum panggilan. **(d) gugur.**

## Ringkasan
- R3 stale-global: reflection praktis **bersih** — modul globals hanya 16-byte key by-value, tanpa pointer ke memori per-request. "Bersih" di sini = bukti struktural: seluruh isi `zend_phar_globals`-padanan reflection (php_reflection.c:61-64) terdiri dari 2 field by-value, satu-satunya pointer-per-request yang bisa disimpan engine reflection tersimpan di objek instance (di-GC via handlers), dan semua situs user-code (invoke/newInstance/hook/attribute/`zend_call_known*` php_reflection.c:2117/2156/3591/5271/5342/6297/6309) sudah diaudit satu per satu tanpa menemukan state global yang mengarah ke memori request.
- R1 bailout-gap: satu kandidat minor K1 — trampoline-copy leak per `ReflectionMethod::invoke()` (master identik, tanpa fix) — bukan kelas UAF/stale-global; tidak dielevasi ke temuan.
- 8 gugur dengan alasan baris-eksplisit; 0 kandidat diklaim sebagai vulnerability (static reading only — marker/ASAN belum dijalankan menurut protokol).

# Worker-audit: ext/libxml/image_svg.c + ext/opcache/zend_accelerator_api.c (PHP 8.5.12)

Agent: Hermes utama — 2026-10-25

## image_svg.c (178 baris, file baru — deteksi dimensi SVG via XML reader)

Dibaca penuh. Poin yang diuji:

1. `php_libxml_parse_dimension` — pointer walk tanpa bound; aman karena
   input `xmlChar*` dari libxml selalu NUL-terminated; dua loop berhenti di
   NUL; tidak ada aritmetika yang bisa lewat.
2. `width_unit_position`/`height_unit_position` — di-set HANYA bila return
   true. Pemakaian `*width_unit_position` dilakukan SETELAH `is_svg=true`
   yang pasti setelah kedua parse true. Tapi perhatikan: bila parse width
   true + height true, keduanya terisi. Bila parse gagal → break sebelum
   pemakaian. Tidak ada jalur uninit-read. (Compiler -Wmaybe-uninitialized
   senyap di build resmi.)
   Catatan kecil non-security: `result` diekstrak dari `ZEND_STRTOL(width)`
   yang membaca sampai non-digit — width "5cm" → 5. Benar.
3. `PHP_LIBXML_SANITIZE_GLOBALS/RESTORE` dipasang mengelilingi
   xmlReaderForIO — mengikuti konvensi ext/libxml. `XML_PARSE_NONET`
   menutup jalur network dari DTD. XSS-injection via unit ditolak oleh
   parser itu sendiri ([0-9]+[a-zA-Z]*).
4. `ecalloc(1, sizeof(**result))` — zero-init; unit string hanya diset bila
   non-empty; pembaca `struct php_gfxinfo` harus cek NULL (kontrak baru,
   dipakai getimagesize — di luar cakupan file ini).

Verdict: GUGUR — tidak ada kandidat yang lolos filter.

## zend_accelerator_api.c (23 baris)

Satu fungsi pembaca `ZCG(preloading)`. Tidak ada state, tidak ada alokasi,
tidak ada API berisiko. Verdict: GUGUR (trivial).

## Kesimpulan

Dua file baru 8.5 tuntas: 0 kandidat. Sisa file baru yang belum dibaca:
ext/dom/lexbor selectors-adapted + inner_outer_html_mixin.c + obj_map.c,
ext/openssl backend v1/v3 split, ext/intl .cpp refactor (worker 1 mencakup
intl 8.4; refactor .cpp 8.5 jalur sama), ext/dom/domlexbor behavior.

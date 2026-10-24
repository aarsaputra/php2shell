# Worker-audit: ext/uri (PHP 8.5.12) — extension 100% baru

Agent: Hermes utama
Tanggal: 2026-10-25
Target: ext/uri — extension URI baru di PHP 8.5 (WHATWG URL + RFC 3986),
total ±3.947 baris C. Tidak ada di 8.4.x sama sekali → belum pernah diaudit
publik lintas versi. Sumber: /run/media/lota1337/AarSSDaputra/p2s-lab/asanbuild/php-8.5.12
(BACA SAJA).

## Kandidat I — TLS state lexbor (mraw/parser/idna) stale lintas request

- Lokasi: uri_parser_whatwg.c:27-29 (ZEND_TLS), :566-601 (RINIT), :604-615 (POST_DEACTIVATE)
- Pola R3 (stale-global): TLS `lexbor_mraw/parser/idna` inisial {0}; bila
  inisialisasi gagal setengah jalan, state bisa menunjuk memori mati.
- Gugur — tiga pagar: (1) RINIT `goto fail` me-destroy + memset ketiganya
  secara eksplisit (:586-595); (2) POST_ZEND_DEACTIVATE destroy + memset
  (:604-615); (3) parse entry (`php_uri_parser_whatwg_parse_ex` :620+) tidak
  bisa dipanggil sebelum RINIT sukses (module dependency).

## Kandidat J — `zval_string_or_null_to_lexbor_str` meminjam zend_string tanpa copy

- Lokasi: uri_parser_whatwg.c:33-42; dipakai di :286/:323/:354/:428/:494/:525/:556
- Pola R2 (raw-ptr-cache): `lexbor_str->data = Z_STRVAL_P(value)` menunjuk
  buffer zend_string milik zval user tanpa menambah refcount.
- Gugur — filter COW/umur: (1) lexbor (`lxb_url_api_*_set`) menyalin data
  ke alokasinya sendiri sebelum kembali; (2) zval sumber dipegang frame VM
  selama pemanggilan; (3) tidak ada penyimpanan pointer jangka panjang.
  Tidak ada jalur di mana zend_string dibebaskan sebelum lexbor selesai.

## Kandidat K — NULL deref setelah `zend_long_to_str` saat OOM

- Lokasi: uri_parser_whatwg.c:45-59 (`zval_long_or_null_to_lexbor_str`),
  dipakai port_write :459-475
- Pola R1 (bailout-gap): dicurigai `zend_long_to_str()` bisa NULL saat OOM →
  `Z_STRVAL_P(NULL)` crash.
- Gugur — bukti Zend/zend_operators.c:3532-3543: dua cabang return.
  (a) `ZSTR_CHAR('0'+num)` untuk num<=9 — interned string, tak pernah NULL;
  (b) `zend_string_init(...,0)` — gagal alokasi = fatal bailout
  (`zend_error_noreturn`), bukan return NULL. Jadi `value` selalu valid
  setelah `ZVAL_STR(value, zend_long_to_str(...))`.
  Kegagalan alokasi lexbor-side tertutup eksplisit: `appended == NULL` →
  return false → `zend_handle_delayed_oom()` → FAILURE → `throw_invalid_url_
  exception_during_write` tidak dijangkau (return sebelum). Konsisten.

## Observasi positif (bukan bug)

Pola OOM ext/uri disiplin: 10 pemakaian ZEND_HAS_OOM dengan cleanup
smart_str_free sebelum FAILURE (contoh :375-401, :622-637). `fill_errors`
menangani OOM ganda (:228-242). Kode baru tapi mengikuti konvensi fallible
alloc 8.5 dengan rapi.

## Kesimpulan extension

3 kandidat diaudit, 3 gugur dengan bukti baris. Tidak ada kandidat bertahan.
Files read: uri_parser_whatwg.c (penuh untuk jalur init/parse/read/write),
php_uri_common.c (helper), referensi silang zend_operators.c/zend_string.c.
 belum dibaca: uri_parser_rfc3986.c (725 baris), php_uri.c (1.197 baris) —
ditandai untuk lanjutan.

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

## Kandidat L — RFC3986 to_string: `uriToStringCharsRequiredA` int overflow / charsRequired mismatch

- Lokasi: uri_parser_rfc3986.c:658-690 (`php_uri_parser_rfc3986_to_string`),
  uriparser/src/UriRecompose.c:74-135 (`ToStringEngine`)
- Pola yang dicari: `charsRequired` dari pass pertama tidak mencukupi pada
  pass kedua → heap overflow saat `uriToStringA` menulis.
- Gugur: pass pertama dan kedua menjalankan engine yang SAMA dengan state
  URI yang SAMA (imutabel di antara keduanya — tidak ada user callback di
  tengah `zend_string_alloc` → `uriToStringA`). engine sendiri sudah
  overflow-guarded: `charsToWrite > (size_t)INT_MAX - written` → TOO_LONG,
`charsToWrite > SIZE_MAX / sizeof(URI_CHAR)` → TOO_LONG (UriRecompose.c
  :120-135). `++` pada charsRequired memberi ruang `\0`. `ZEND_ASSERT(result
  == URI_SUCCESS)` valid karena satu-satunya failure mode enginenya adalah
  buffer kurang / NULL — keduanya mustahil pada pass ini.

## Kandidat M — free_obj memanggil destroy(uri=NULL) — lxb_url_destroy NULL-safe

- Lokasi: php_uri.c:1030-1058 (`php_uri_object_create`, `free`), 
  uri_parser_whatwg.c:692-697 (`destroy`), clone jalur oom :1071-1075
- Pola R1: bila `clone()` gagal OOM, `zend_object_release(new_uri_object->std)`
  memanggil free dengan `new_uri_object->uri` masih NULL → 
  `parser->destroy(NULL)`.
- Gugur: `lxb_url_destroy(NULL)` punya guard eksplisit 
  `if (url == NULL) return NULL;` (lexbor/url/url.c:4218-4226). RFC3986
  destroy juga guard `uriparser_uris == NULL` (uri_parser_rfc3986.c:700-706).
  Tidak ada crash. lexbor sinkron dengan kontrak ini.

## Kandidat N — port_str_to_zend_long_checked: ceil vs floor `MAX_LENGTH_OF_LONG`

- Lokasi: uri_parser_rfc3986.c:362-382
- Cek batas: `len > MAX_LENGTH_OF_LONG` → -1. Untuk len == MAX_LENGTH_OF_LONG
  (20 digit pada 64-bit), string "99999999999999999999" > ZEND_LONG_MAX
  tertangkap oleh `result > ZEND_LONG_MAX` → -1. Buffer berukuran
  `MAX_LENGTH_OF_LONG + 1`, `zend_mempcpy(buf, str, len)` menulis tepat len
  byte + `*p = 0` terminator di buf[len]. Tepat. Gugur.

## Kesimpulan extension (tambahan setelah full-read rfc3986.c + core)

Semua kandidat ditutup. ext/uri kini dibaca penuh: uri_parser_whatwg.c (penuh),
uri_parser_rfc3986.c (penuh), php_uri.c (objek handler + create/clone/free),
php_uri_common.c. Modul bundled uriparser (UriRecompose.c) dicek untuk
overflow — engine-nya punya guard modern.

Tidak ada kandidat bertahan. Kualitas kode ext/uri konsisten tinggi: fallible
pattern (`handle_pending_oom` :65-74, ZEND_HAS_OOM, `ECALLOC` non-null) dipakai
rapi di semua paths, termasuk jalur OOM yang biasanya dilupakan proyek lain.

Yang belum dibaca dari ext/uri (ditandai untuk lanjutan bila diperlukan):
php_uri_arginfo.h (generated), bagian php_uri.c 95-1027 (getter/setter
boilerplate), php_uri_common.h. Ini dianggap rendah risiko karena hanya
memanggil handler yang sudah dibaca.


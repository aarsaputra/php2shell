# Worker-audit: ext/mbstring (PHP 8.4.27) — gap-rule R3/R1/R2

Agent: Hermes utama
Tanggal: 2026-10-25
Cakupan: php_mbregex.c — jalur user callback (`mb_ereg_replace_callback`) + state MBREX

## K1 — callback `mb_ereg_replace_callback` di tengah loop Oniguruma

- Lokasi: `ext/mbstring/php_mbregex.c:995-1135` (`_php_mb_regex_ereg_replace_exec`), callback dipanggil di `:1117`
- Pola yang dicari (R1 bailout-gap / R3 stale-global): state yang diisi sebelum callback dan dipakai sesudahnya, yang bisa kacau bila OOM/fatal menyela di dalam callback.
- Fakta:
  - `zend_fcall_info arg_replace_fci` dan cache-nya **lokal stack** (:1004-1005) — bukan global.
  - State yang dipegang saat callback jalan: `regs` (OnigRegion, hanya C), `pos`, `out_buf`/`eval_buf` (smart_str lokal), `string` (pegang frame VM).
  - Tidak ada `MBREX(` yang ditulis untuk menandai "sedang di callback"; tidak ada global yang menunjuk data lokal.
- Filter: COW tidak relevan; per-nama/per-iterasi tidak relevan; user code mid-frame YA tapi semua yang dipakai setelah callback berumur lebih panjang; guard — jalur FAILURE memeriksa `EG(exception)` sebelum throw (:1124-1128); global — tidak ada.
- Verdict: **GUGUR**.

## K2 — observasi minor (bukan kelas bug yang diburu)

- `onig_region_new()` di `:1093` tidak di-free bila bailout (fatal error/OOM) terjadi di dalam callback user — tidak ada `onig_region_free` pada jalur unwind (file tidak memakai zend_try di area ini).
- Dampak: memory leak sesaat di worker FPM sampai MSHUTDOWN; tidak ada state yang menunjuk memori mati (region tidak disimpan di global), tidak ada UAF, tidak ada jalur post-request.
- Filter yang menutup R3: `regs` tidak pernah disimpan ke global; hanya variabel lokal yang dibuang saat frame unwind.
- Verdict: **bukan kerentanan** — dicatat demi kejujuran cakupan.

## Kesimpulan extension

Tidak ada kandidat bertahan.
Files read: php_mbregex.c:995-1135, definisi MBREX pada php_mbregex.h (sebagian).

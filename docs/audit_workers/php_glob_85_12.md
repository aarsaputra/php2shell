# Worker-audit: main/php_glob.c (PHP 8.5.12) — file baru di core

Agent: Hermes utama
Tanggal: 2026-10-25
Target: main/php_glob.c (1.138 baris) — implementasi glob bundled yang sejak
GH #18164 (merged 2025-05-20, ada di 8.5) dipakai di SEMUA platform secara
default (`--enable-system-glob` default no, configure.ac:601-613). Sebelumnya
hanya Windows. Artinya: jalur ini baru "menyala" untuk pengguna Linux/Mac di
seri 8.5 — populasi terbesar PHP — dengan riwayat audit runtime jauh lebih
pendek daripada glibc glob.

## Kandidat O — brace overflow patbuf di globexp2

- Lokasi: php_glob.c:322-331 (copy pre-brace tanpa bound), :393-401 (append
  post-brace), array `Char patbuf[PATH_MAX]` :331.
- Gugur — pemindai panjang di pintu masuk `php_glob()` :269
  (`zend_strnlen(pattern, PATH_MAX) == PATH_MAX` → NOMATCH) menjamin
  `strlen(pattern) <= PATH_MAX-1`. Untuk SEMUA posisi ptr/pe:
  `written = (ptr-pattern) + (end-pe) < strlen(pattern) < PATH_MAX`.
  Aritmetika tertutup.

## Kandidat P — rekursi tanpa depth guard → stack exhaustion (KANDIDAT HIDUP)

- Lokasi: php_glob.c:306-423 — `globexp1` ↔ `globexp2` saling memanggil;
  tiap frame globexp2 mengalokasikan `Char patbuf[PATH_MAX]`.
- `Char` = u_short di non-Win32 (:135) → 8 KB stack per frame; plus frame
  globexp1 dan sub-call. Tidak ada parameter depth, tidak ada counter —
  grep 'depth|recursion|level' di jalur brace: nihil.
- Pola paling padat: `"{" * n + "a" + "}" * n` (panjang 4n+1 ≤ 4095) →
  n ≤ 1023 level → ±8,4 MB stack > default 8 MB (FPM worker & CLI main
  thread umumnya 8 MB; rlimit stack bisa lebih kecil di container).
- Reachability: pemanggil userland = `glob()` (ext/standard/dir.c:457,
  guard pattern ≥ MAXPATHLEN :423) dan glob:// stream wrapper + ZipArchive::
  addGlob (via php_zip_glob → php_glob). Semua tanpa depth guard.
- Filter pra-klasifikasi:
  1. COW — tidak relevan.
  2. by-name/by-iter — tidak relevan.
  3. user code mid-frame — tidak ada (murni C, memanggil FS).
  4. guard — TIDAK ADA depth/stack guard di jalur ini. (php_error /
     memory_limit tidak membantu; ini stack, bukan heap.)
  5. global vs lokal — tidak relevan untuk stack exhaustion.
- Status klasifikasi (skill vuln-source-diff-hunt, hard rule #1):
  **kandidat (a) unknown-unknown SETENGGAH** — pencarian tracker php-src
  ("glob stack", "glob segfault", "nested brace", "glob recursion") tidak
  menemukan laporan yang menyentuh rekursi brace bundled-implementation ini;
  GH #7749 (2021) adalah stacking PHP-userland, bukan glob C. TAPI: crash
  stack-overflow via input pengguna sangat mungkin dianggap "wontfix by
  design" oleh upstream (pola serupa di Redis/glob duluan ditolak),
  dan bukti dinamis BELUM ADA. Static = kandidat; tanpa PoC crash ini
  TIDAK boleh diklaim vulnerability.
- Status akhir (dinamis, 2026-10-25): **GUGUR — tidak reproducible.**
  Build CLI 8.5.12 murni (configure --disable-all --enable-cli, binary
  `p2s-lab/cli85/sapi/cli/php`) diuji dengan 9 varian:
  - v1 `{'*n . a . '}*n` n=50..1023 (maks) — SURVIVED
  - v3 `{,`*n + a + `}`*n n=500/1000/1200/1364 — SURVIVED
  - v4/v5 wrapper ber-koma `t={t,z}` k=3..818 **dengan GLOB_BRACE**,
    diverifikasi jalur globexp2 aktif (glob('{a,b}', GLOB_BRACE) di sandbox
    menghasilkan [a,b]; k=818 menghasilkan count=1 = jalur rekursi benar
    berjalan sampai level terdalam)
  - Stress stack: ulimit -s 4096/2048/1024/512/256/128 KB — SEMUA SURVIVED,
    exit 0. Kedalaman rekursi 818 tidak menumpuk 8 KB/frame sebagaimana
    dugaan statis (kemungkinan besar penanganan per-koma membuat cabang
    rekursif berakhir return → tail-call/stack reuse oleh -O2; pola
    alokasi patbuf tidak per-frame sepanjang jalur hidup).
  - Pembanding 8.4 glibc: SURVIVED juga — tidak ada regresi terlihat.
  Pelajaran: hitungan frame statis (8 KB × depth) menyesatkan; bukti
  dinamis menutup. Verdict negatif terdokumentasi sesuai hard rule #3.

## Kandidat Q — reallocarray fallback

- Lokasi :177-215. Versi OpenBSD dengan guard `SIZE_MAX / nmemb < size`.
  Gugur — modern, benar.

## Kesimpulan file

1 kandidat HIDUP (P — stack exhaustion brace rekursi, butuh PoC untuk naik
kelas), 2 gugur (O, Q). File dilewati pembacaan penuh: g_Ctoc/g_lstat loop
(:960-1010 konversi path) dibaca cepat tanpa temuan; glob2/glob3 (:698-830)
mutual recursion untuk segment path — kedalaman dibatasi jumlah '/' dalam
PATTERN (≤4096) tapi frame kecil (pathbuf tanpa array besar per level?
— pathbuf[PATH_MAX] di glob2 :696 juga 4 KB/level, reaksi sama dengan P:
recursive descent path segment, depth praktis dibatasi FS, dicatat sebagai
temuan kelas P juga).

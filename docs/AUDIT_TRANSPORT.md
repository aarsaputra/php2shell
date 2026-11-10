# Audit log transport — retensi & anti log-injection

Menutup butir audit **PY-011** ("Audit log dan permission laporan") pada bagian
yang belum dikerjakan: *batasi retensi log* dan *pengamanan terhadap log
injection*. Redaksi (`token`/`key`/`password`/`authorization` -> `***`) dan
mode `0600` sudah ada sebelumnya; dokumen ini mencatat pagar tambahan dan
cara membuktikannya.

Implementasi: `lib/transport.py`, tes: `tests/test_transport_security.py`.

## 1. Retensi dibatasi

Konstanta (modul `lib.transport`):

| Konstanta | Nilai | Arti |
|---|---|---|
| `AUDIT_MAX_BYTES` | `8 * 1024 * 1024` (8 MiB) | Ambang rotasi. Dicek ulang pada **setiap** penulisan (`stat` sebelum append), jadi mengubah nilai saat runtime langsung berlaku. |
| `AUDIT_ROTATE_SUFFIX` | `".1"` | Satu generasi rotasi: `audit.jsonl` -> `audit.jsonl.1`. |

Aturan rotasi (`Transport._rotate_audit_if_needed`), dijalankan di dalam
`_audit()` **sebelum** append:

* File belum ada / ukuran `< AUDIT_MAX_BYTES` -> tidak ada yang dipindah,
  dipotong, atau dihapus. Return `False`.
* Ukuran `>= AUDIT_MAX_BYTES` -> `os.replace(audit.jsonl, audit.jsonl.1)`.
  `.1` lama **ditimpa**; tidak ada rantai `.1..N` (total disk dibatasi
  ~2x batas, ~16 MiB default). `os.replace` atomik dalam filesystem yang
  sama sehingga pembaca tidak pernah melihat `.1` setengah tertulis.
* File baru dibuat oleh `os.open(..., 0o600)` di `_audit()` dan di-`chmod`
  eksplisit sesudahnya -> mode `0600` tetap berlaku **setelah** rotasi.
* Bila rotasi menulis `.1` gagal (`OSError`), penulisan audit dilewati dan
  scan tetap jalan.

Konsekuensi yang disengaja: record tertua dibuang saat rotasi. Untuk audit
engagement, kehilangan log bertahun-tahun lebih buruk daripada disk penuh di
tengah scan — dan `8 MiB` cukup untuk puluhan ribu record (baris tipikal
~200 byte).

## 2. Anti log injection — satu record = satu baris fisik

`_audit()` melakukan, berurutan: redaksi (`redact_url`/`redact_text`) ->
`_audit_safe()` -> `json.dumps(ensure_ascii=False)` + `"\n"`.

`_audit_safe()` meng-escape karakter yang dibiarkan **mentah** oleh
`json.dumps(ensure_ascii=False)` padahal berbahaya:

| Karakter | Jadi | Alasan |
|---|---|---|
| `U+2028` LINE SEPARATOR | `\u2028` (teks) | Dianggap newline oleh sebagian parser/logger/shell; **terbukti** memecah `str.splitlines()` — tanpa escape, 4 record + payload menghasilkan 20 "baris". |
| `U+2029` PARAGRAPH SEPARATOR | `\u2029` (teks) | Sama seperti di atas. |
| `U+0085` NEL | `\u0085` (teks) | Pemisah baris di `str.splitlines()`. |
| `ESC` (0x1B), `DEL` (0x7F), C1 (0x80-0x9F) | `\uXXXX` (teks) | Bukan pemisah baris, tetapi `\x1b[2J` menghapus layar operator yang menjalankan `cat audit.jsonl`. |
| Surrogate lepas (U+D800-U+DFFF) | `\uXXXX` (teks) | Bisa datang dari body/error yang di-decode longgar; `str.encode("utf-8")` akan melempar `UnicodeEncodeError` dan mematikan scan. |

`\n`, `\r`, `\t`, dan C0 lain sudah di-escape oleh `json.dumps` sendiri, jadi
tidak diduplikasi.

Hasil: **setiap record tepat satu baris fisik**, baik dihitung lewat
`bytes.count(b"\n")`, `str.splitlines()`, maupun `readlines()`, dan setiap
baris tetap `json.loads`-able. Nilai seperti `{"ts":"x","url":"evil"}` dari
target tetap berada di dalam record pemiliknya (ter-escape di dalam string
JSON), tidak pernah menjadi record terlihat terpisah.

## 3. Kegagalan audit tidak mematikan scan

Semua `OSError` pada `mkdir` / rotasi / `open` / `write` ditelan dengan
`RuntimeWarning`. `_audit()` tidak pernah melempar, dan `Transport.request()`
mengembalikan `Response` normal walaupun log tidak bisa ditulis. Signature
publik `Transport.__init__` tidak berubah.

## 4. Bukti (tes)

```
/home/lota1337/myenv/bin/python -m pytest tests/test_transport_security.py -q
60 passed, 72 subtests passed
```

Kelas tes baru:

* `TestAuditRetensi` — batas kecil (512 B via `mock.patch.object` pada
  `AUDIT_MAX_BYTES`, bukan 8 MiB sungguhan): `.1` muncul, file utama di bawah
  batas, record tertua (`seq: 0`) hanya ada di `.1`, `.1` lama tertimpa tanpa
  rantai `.2`, mode `0600` di kedua file, file belum ada aman (tidak
  melempar/menghapus), dan audit gagal (`os.open` -> `OSError`) tidak
  melempar serta `request()` tetap `200`.
* `TestAuditLogInjection` — payload `\n`, `\r\n`, `\r`, `\x1b[2J`, `U+2028`,
  `U+2029`, dan `{"ts":"x","url":"evil"}` di `url` + `error`: jumlah baris
  fisik == jumlah record, tidak ada baris yang diawali `{"ts":"x"`, tiap
  baris `json.loads`-able, byte kontrol tidak masuk file mentah, dan redaksi
  token tetap `***`.

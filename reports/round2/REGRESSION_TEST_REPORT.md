# REGRESSION TEST REPORT — ROUND 2

## Ringkasan eksekusi

| Suite | Hasil | Durasi | Sumber |
|---|---|---|---|
| pytest (seluruh, lab HIDUP) | **497 passed**, 228 subtests, 0 failed, 0 skipped | 23.05s | `evidence/test-results/full-regression.txt` |
| pytest (lab MATI) | 486 passed, **11 skipped**, 0 failed | 23.60s | idem (bagian bawah) |
| unittest (discovery) | **Ran 343 tests, OK** | 20.43s | idem |
| Modul tes | 18 | — | — |

Baseline round 2 (sebelum patch): 438 passed (pytest), 276 (unittest).
Selisih: **+59 tes** (pytest), **+67** (unittest).

## Modul tes baru

| File | Jumlah | Finding |
|---|---|---|
| `tests/test_command_validation.py` | 10 | R2-01 |
| `tests/test_redirect_scope.py` | 25 | R2-02 |
| `tests/test_producer_lifecycle.py` | 8 | R2-04 |
| `tests/test_docker_lab_hardening.py` | 27 | R2-05 |

`tests/test_runner_deadline.py` dan `tests/test_chain_request.py` mendapat
tes tambahan untuk R2-03; `tests/test_utf8...` tidak berubah.

## Tes lama yang DIPERBARUI (bukan dihapus)

Tiga tes lama gagal setelah hardening karena **kontraknya berubah secara
sengaja**. Semuanya diperbarui dengan alasan tertulis di docstring, dan
masing-masing sekarang menegaskan perilaku **baru yang lebih ketat** — bukan
dilonggarkan.

### 1. `test_php2shell.py::TestKlaimBanner::test_exploit_py_tidak_dimodifikasi`

Tes ini mengunci SHA-256 `lib/chain.py` supaya setiap perubahan byte pada
mesin rantai harus di-review. Patch R2-03 menambah satu baris di
`Chain.__init__` (`memprobe.validate_huge_mb(huge_mb)`), jadi hash berubah.

Sebelum: `69e1cad001a23994836ca4f38c4602e1b940c297e717e2c4e8c6c2f375a96031`
Sesudah: `a9a961c6da06c7bfc7b48785144b56eb1b3790614c02732b9323d8a87f1a5adb`

Docstring diperluas dengan butir ke-5 yang menjelaskan perubahan R2-03.
Tes **tidak dilonggarkan**: mekanismenya tetap "hash harus cocok", dan diff-nya
sudah di-review.

### 2. `test_runner_deadline.py::test_resolve_whitelist_menambah_extra_tanpa_duplikat`

Sebelum:
```python
wl = er.resolve_whitelist(["ls", "LS", "/usr/bin/cat", "./pwd", "ls"])
assert "ls" in wl and "cat" in wl and "pwd" in wl
```

Sesudah:
```python
wl = er.resolve_whitelist(["ls", "LS", "./pwd", "/usr/bin/uname", "ls"])
assert "ls" in wl and "pwd" in wl and "uname" in wl
for gone in ("cat", "env"):
    assert gone not in wl
    with pytest.raises(ValueError):
        er.resolve_whitelist([f"/usr/bin/{gone}"])
```

Alasan: `cat` dan `env` dihapus dari `EXTRA_ALLOWED_CMDS` (R2-01). Tes tidak
menghapus cakupan — properti yang diuji (normalisasi path, dedupe, batas
whitelist) tetap diuji, dan **ditambah** penegasan bahwa `cat`/`env` tidak bisa
dibuka lagi bahkan lewat path absolut.

### 3. `test_runner_deadline.py::test_huge_mb_eksplisit_melewati_probe_dan_plafon`

Sebelum:
```python
res = _run(huge_mb=700, ...)
assert "batas aman" not in res.error
assert FakeChain.made[0].huge_mb == 700        # 700 DITERIMA
```

Sesudah: `700` sekarang **ditolak** (itu justru temuan R2-03). Tes baru:
```python
res = _run(huge_mb=700, ...)
assert FakeChain.made == []                    # rantai tidak dibuat
assert "plafon aman" in res.error
# tepat di plafon tetap lolos:
ok = _run(huge_mb=memprobe.SAFE_CEILING_MB, ...)
assert FakeChain.made[0].huge_mb == memprobe.SAFE_CEILING_MB
```

Ditambah tes baru `test_huge_mb_negatif_ditolak_di_lapisan_api` untuk
`{-5, 0, True, "64", 64.0}`.

Perhatikan arah perubahan: nilai yang dulu diterima sekarang ditolak. Tes
menjadi **lebih ketat**, bukan lebih longgar.

## Cakupan per finding (test case konkret)

### R2-01 — 10 tes (`test_command_validation.py`)
1. `test_allowed_basic` — `id`, `whoami` tanpa argumen sah
2. `test_allowed_extra` — whitelist tambahan dihormati
3. `test_rejected_unknown` — perintah di luar whitelist ditolak
4. `test_rejected_empty` — string kosong/spasi ditolak
5. `test_rejected_metachars` — `;`, `|`, `&&`, backtick, `$()` ditolak
6. `test_rejected_args_for_id` — `id 1000` ditolak (**inti R2-01**)
7. `test_rejected_path_traversal` — `ls ../../etc` ditolak (**inti R2-01**)
8. `test_rejected_long_args` — argumen 100 byte ditolak
9–10. Ditambah dari `test_validate_command.py`: semantik `--allow-cmd`,
penolakan tool berbahaya.

### R2-02 — 25 tes (`test_redirect_scope.py`)
- `TestNormalizeHostname` (4): lowercase/titik akhir, bracket IPv6 & IPv4-mapped,
  IDNA punycode, homoglyph tidak sama dengan ASCII.
- `TestHostInScope` (6): mode `host` exact, **batas label** (`evilexample.com`
  ditolak), IP tanpa subdomain, mode `any`, mode asing ditolak.
- `TestCheckScope` (8): path lain diizinkan, http→https diizinkan,
  **https→http ditolak**, domain lain ditolak, port lain ditolak, port lain
  diizinkan di mode `any`, metadata tetap ditolak, skema aneh ditolak.
- `TestFetchEnforcesScope` (7): redirect domain lain tidak dikirim, rantai
  A→B→C tidak bisa keluar scope, same-host diikuti, mode `subdomains`
  mengizinkan subdomain, mode `host` menolaknya, mode asing ditolak saat init,
  **DNS pin hanya sekali**.

### R2-03 — 3 tes + 1 baru
- `test_huge_mb_eksplisit_melewati_probe_dan_plafon` (diperbarui, 2 asersi kuat)
- `test_huge_mb_negatif_ditolak_di_lapisan_api` (baru, 5 nilai buruk)
- `test_limit_di_bawah_plafon_tidak_berhenti` (tidak berubah, memastikan
  jalur normal tidak dirusak)

### R2-04 — 8 tes (`test_producer_lifecycle.py`)
- `TestShutdownBudget` (2): read timeout < join; konstanta dipakai (bukan
  angka literal `(10, 30)`).
- `TestStopAndJoin` (2): thread hidup → `False` + pesan eksplisit; thread
  kooperatif → `True`.
- `TestRunRaceLifecycle` (4): jalur gagal, exception, sukses, durasi nol —
  semuanya harus mengembalikan jumlah thread `x115560-producer` ke baseline.

### R2-05 — 27 tes (`test_docker_lab_hardening.py`)
Dua lapis:
- **Lapis A (konfigurasi, 14 tes)** — selalu jalan tanpa Docker:
  `internal: true`, `cap_drop: ALL`, tidak ada capability berbahaya,
  `no-new-privileges`, `read_only`, tidak `privileged`, resource limit,
  tidak ada port publish langsung, tidak ada chown path host, `/out`
  satu-satunya mount rw; `lab_docker.sh` memakai `--internal`/`--cap-drop ALL`
  /`--read-only`/relay socat dan `destroy` membersihkan relay+network;
  `Dockerfile` punya uid/gid mapping.
- **Lapis B (container hidup, 13 tes, skip bila lab tidak jalan)** —
  `docker inspect` + `docker exec`: read-only rootfs, non-privileged,
  `CapDrop == ["ALL"]`, `CapAdd ⊆ {4 cap}`, `no-new-privileges`,
  `PidsLimit==256`, `Memory==512MiB`, port bindings kosong, network internal,
  `/out` milik uid pemilik repo, egress gagal, DNS gagal.

## Prinsip yang dipegang

1. **Tidak ada tes yang dihapus.** Ketiga tes yang berubah tetap ada dengan
   cakupan yang sama atau lebih besar.
2. **Tidak ada security control yang dilemahkan.** Arah semua perubahan tes
   adalah ke penolakan yang lebih ketat.
3. **Setiap PASS menunjuk bukti.** Tabel di `SECURITY_VERIFICATION_MATRIX.md`
   memetakan finding → tes → file evidence.
4. **Skip dilaporkan.** Lapis B `test_docker_lab_hardening.py` (11 tes) di-skip
   bila container lab tidak berjalan, dengan pesan yang menyebut cara
   menjalankannya. Dua angka dilaporkan apa adanya: **497 passed / 0 skipped**
   dengan lab hidup, **486 passed / 11 skipped** dengan lab mati. Tidak ada
   tes yang "lulus" tanpa benar-benar berjalan.

## Reproduksi

```bash
cd /home/lota1337/python/php2shell

# suite penuh (497)
/home/lota1337/myenv/bin/python -m pytest

# per finding
/home/lota1337/myenv/bin/python -m pytest tests/test_command_validation.py -v
/home/lota1337/myenv/bin/python -m pytest tests/test_redirect_scope.py -v
/home/lota1337/myenv/bin/python -m pytest tests/test_runner_deadline.py -k huge_mb -v
/home/lota1337/myenv/bin/python -m pytest tests/test_producer_lifecycle.py -v

# R2-05 lapis B butuh lab hidup
bash lab/lab_docker.sh start
/home/lota1337/myenv/bin/python -m pytest tests/test_docker_lab_hardening.py -v
```
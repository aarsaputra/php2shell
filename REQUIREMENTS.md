# 🔧 Requirements — apa yang perlu dipasang untuk menjalankan php2shell

Tiga tingkat ketergantungan. **Tool inti (detect/preflight/scan/shell) hanya
butuh Python + 2 paket.** Docker hanya perlu kalau mau menjalankan lab
eksploitasi lokal; `offsets.py` hanya perlu untuk build PHP selain bookworm.

---

## 0) Metode tercepat (disarankan)

```bash
git clone https://github.com/aarsaputra/php2shell.git
cd php2shell
bash install.sh          # venv + deps + smoke test + perintah global `php2shell`
```

`install.sh` menyelesaikan tingkat 1 & 2 di bawah secara otomatis, termasuk
pemeriksaan docker, dan mencetak apa yang kurang beserta cara memperbaikinya.

---

## 1) Wajib — tanpa ini tool tidak jalan

| Butuh | Versi | Kenapa |
|---|---|---|
| **Python** | ≥ 3.9 (dua-duanya Bahasa sintaks `X \| Y`, dataclass, dll.) | satu-satunya runtime |
| **curl_cffi** | ≥ 0.7 (`pip install curl_cffi`) | TLS/JA3 impersonation (`chrome`, `safari`, …) — tanpa ini tool OTOMATIS turun ke `urllib` (jalan, tapi fingerprint Python default = jauh lebih mudah dideteksi WAF; banner memberi peringatan merah) |
| **bcrypt** | ≥ 4.0 (`pip install bcrypt`) | hanya untuk mode `shell` (generator webshell berpassword); hash + verifikasi password |

Pasang manual:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt      # isinya curl_cffi + bcrypt
```

> Tidak ada dependensi lain di jalur inti: HTTP client, TLS, JSON, hashing ELF,
> multipart builder — semuanya implementasi internal (stdlib: `urllib`,
> `json`, `struct`, `hashlib`, `dataclasses`, `concurrent`, dll.).

**PHP tidak wajib di mesin attacker.** Target-lah yang menjalankan PHP.
PHP lokal hanya berguna untuk menguji webshell hasil generator
(`php -l` lint + `php -S 127.0.0.1:8099`) — opsional.

---

## 2) Wajib-untuk-lab (eksploitasi lokal / kalibrasi)

| Butuh | Kenapa | Cara pasang |
|---|---|---|
| **Docker Engine ≥ 20** | menarik image resmi `php:8.4.26-apache` untuk lab rentan | `bash lab/pasang_docker.sh` (root, sekali) atau `apt install docker.io` |
| **User di grup docker** | `docker` CLI tanpa sudo | `sudo usermod -aG docker $USER` + logout/login (atau jalankan via `sg docker -c "..."`) |
| **Koneksi internet pertama kali** | pull image ±200 MB | otomatis via `docker pull` |
| **curl** (CLI) | health check di `lab_docker.sh` | hampir selalu sudah ada |

Tanpa docker: `detect`, `preflight`, `scan`, dan `shell` tetap berfungsi
penuh terhadap target jauh; yang hilang hanyalah lab lokal untuk
pengujian reproduksi.

---

## 3) Opsional / situasional

| Butuh | Kapan | Catatan |
|---|---|---|
| **PHP CLI 8.x** | mau lint & uji webshell lokal (`php -l`, `php -S`) | `apt install php-cli` |
| **offsets.py butuh docker** | build target BUKAN `php:8.4.26-apache` bookworm — ukur `zif_system`/`zval_ptr_dtor` dari `libphp.so` build itu | script mem-parse ELF **dari dalam Python** (`struct`) — tidak butuh `nm`/`readelf`/`objdump`; tapi perlu akses `docker cp` ke container yang menjalankan build tsb. |
| **curl_cffi versi baru** | target yang memblok fingerprint lama | `pip install -U curl_cffi` |
| **git** | clone repo | semua platform standar |

Tidak dibutuhkan: `nm`, `readelf`, `gcc`, `make`, `docker-compose` v1,
`php` di sisi attacker, bahasa lain. Sistem diuji: **Kali Linux (Debian)**;
semua distro Linux dengan python3.9+ dan docker seharusnya identik.
Windows hanya lewat WSL2 (docker + path POSIX).

---

## 4) Cek mandiri setelah install

```bash
php2shell --help                    # banner + flags tampil
python3 -c "import curl_cffi"       # stealth mode aktif
python3 -c "import bcrypt"          # mode shell siap
docker info >/dev/null && echo "docker OK"
python -m unittest discover -s tests -t .   # → Ran 263 tests, OK
```

`requirements.txt` sudah di-pin (`==`) ke versi yang teruji, jadi versi yang
terpasang bisa direproduksi persis. Cara cek cepat bahwa pin-nya masih sehat di
mesin Anda:

```bash
pip install -r requirements.txt && python -m pytest -q
```

Kalau ada yang gagal setelah upgrade, bandingkan versi terpasang dengan pin
(`python -c "import curl_cffi,bcrypt;print(curl_cffi.__version__,bcrypt.__version__)"`)
sebelum menyalahkan kode.

Semua [ok] → tool 100% fungsional termasuk lab dan mode exploit.

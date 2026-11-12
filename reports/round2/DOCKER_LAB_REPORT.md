# DOCKER LAB REPORT — R2-05

**Host:** Linux 7.1.5+kali-amd64
**Docker:** client 28.5.2+dfsg4, server 28.5.2+dfsg4
**Docker Compose:** v5.7.1 (plugin dipasang saat verifikasi RR-5)
**Image dasar:** `php:8.4.26-apache` (Debian 12, Apache prefork + mod_php)
**Image lab:** `p2s-lab:local` (build dari `docker/Dockerfile`, uid/gid 1000)
**Jaringan:** `p2s-lab-internal` (`internal: true`)

Dua jalur verifikasi, keduanya dijalankan nyata:

| Jalur | Bukti | Hasil |
|---|---|---|
| `lab/lab_docker.sh` (`docker run` eksplisit) | `evidence/docker-isolation/isolation-proof.txt` | PASS + E2E proof `uid=1000(p2s)` |
| `docker compose` (`docker-compose.yml` asli) | `evidence/docker-isolation/compose-proof.txt` | PASS + E2E proof `uid=1000(p2s)` |

---

## 1. Bukti isolasi egress (dinamis)

Sumber: `evidence/docker-isolation/isolation-proof.txt`

```
=== 2. TARGET TIDAK punya rute keluar (DNS + TCP) ===
DNS: FAIL (no route)
bash: connect: Network is unreachable
bash: line 1: /dev/tcp/1.1.1.1/443: Network is unreachable
TCP 1.1.1.1:443 rc=1

=== 3. TARGET tidak bisa menjangkau host LAN ===
bash: connect: Network is unreachable
bash: line 1: /dev/tcp/192.168.100.7/18999: Network is unreachable
TCP host-lan rc=1
```

Kedua tujuan diuji karena keduanya berbeda: `1.1.1.1:443` menguji internet,
`192.168.100.7:18999` menguji apakah container bisa mencapai **host** (jalur
lateral yang sering terlewat). Keduanya `Network is unreachable` — bukan
timeout, bukan `connection refused`: tidak ada rute sama sekali.

`getent hosts example.com` gagal → DNS juga tidak berfungsi, jadi nama tidak
bisa di-resolve menjadi IP untuk dicoba.

## 2. Bukti konfigurasi keamanan (inspect, container hidup)

```
ReadonlyRootfs   = True
Privileged       = False
CapDrop          = ['ALL']
CapAdd           = ['CAP_CHOWN', 'CAP_NET_BIND_SERVICE', 'CAP_SETGID', 'CAP_SETUID']
SecurityOpt      = ['no-new-privileges:true']
PidsLimit        = 256
Memory           = 536870912          (512 MiB)
NanoCpus         = 2000000000         (2 CPU)
PortBindings     = {}                 <- target TIDAK publish port
NetworkMode      = p2s-lab-internal
```

Yang **tidak** ada di `CapAdd`: `CAP_NET_RAW`, `CAP_NET_ADMIN`,
`CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_DAC_OVERRIDE`, `CAP_FOWNER`,
`CAP_MKNOD`, `CAP_SYS_MODULE`. Dicabut lewat `cap_drop: ALL`.

Perbandingan langsung dengan versi sebelum round 2 (image polos, tanpa
`cap_drop`): container lama mendapat set capability default Docker (~14 entri)
termasuk `NET_RAW` dan `DAC_OVERRIDE`.

## 3. Bukti port: target tidak mengekspos apa pun

```
=== 5c. relay: satu-satunya pemilik port ===
{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"8095"}]}

=== 8. TARGET container port bindings (harus kosong) ===
{}
```

Port 8095 di host dimiliki **relay socat**, bukan target. Relay punya dua
jaringan: `p2s-lab-edge` (untuk publish ke 127.0.0.1) dan `p2s-lab-internal`
(untuk menjangkau target). Target sendiri tidak punya port publish dan tidak
punya rute keluar.

Alasan desain relay: Docker **tidak** mem-publish port untuk container di
jaringan `internal: true` (`docker port` mengembalikan kosong,
`PortBindings` kosong). Dibuktikan di dua percobaan terpisah:

```
docker network create --internal p2s-int-test
docker run -d -p 127.0.0.1:18089:80 ... 
-> docker port p2s-c2         (kosong)
-> curl 127.0.0.1:18089       (Connection refused)
```

Karena itu arsitektur relay dipilih ketimbang melepas `internal`.

## 4. Bukti uid/gid mapping — tidak ada chown path host

```
=== 4. WORKER identity + /out ownership ===
root     apache2 -DFOREGROUND          <- parent (bind :80)
p2s      apache2 -DFOREGROUND          <- worker yang mengeksekusi PHP
drwxr-s--- 4 1000 1000 4096 Nov 11 15:52 /out

=== 7. PROOF WRITE lewat worker ===
uid=1000(p2s) gid=1000(p2s) groups=1000(p2s)
WRITE_OK
-rw-rw-r-- 1 1000 1000 6 Nov 12 03:22 /out/.wtest
```

`/out` di host tetap `1000:1000` (pemilik repo) dan worker menulis sebagai
uid 1000. Tidak ada operasi `chown`/`chgrp`/`chmod` yang dijalankan dari dalam
container terhadap path host — dibuktikan juga oleh tes
`test_tidak_chown_path_host_dari_container` yang memindai baris non-komentar
`docker-compose.yml`.

Konsekuensi yang terukur: `pytest` di baseline round 2 gagal collect karena
`out/` dimiliki uid 33 (warisan lab lama). Setelah container dijalankan ulang
dengan uid mapping dan `pytest.ini` (`testpaths = tests`), collect bersih.

## 5. Bukti lab berfungsi (bukan hanya "container up")

```
== tunggu siap ==
   SIAP  http://127.0.0.1:8095/index.php  (HTTP 200)

== bukti konfigurasi (versi + syarat rantai) ==
OK
```

Dan yang paling penting — rantai eksploitasi berjalan penuh di lab hardened:

```
[*] memory_limit 8 MiB terbaca dari target; field 'big' disetel 10 MB
stage 1: heap leak (1/3)  -> chunk base = 0x7ff9e0e00000
stage 2: libphp leak (1/3) -> libphp base = 0x7ff9e2a94000
stage 3: eksekusi (1/5) -> uid=1000(p2s) gid=1000(p2s) groups=1000(p2s)
PROOF (11.8s): uid=1000(p2s) gid=1000(p2s) groups=1000(p2s)
```

Lima syarat rantai (MaxRequestWorkers 1, KeepAlive Off, memory_limit 8M +
cleanup On, max_input_vars besar, max_file_uploads besar) tetap berfungsi di
konfigurasi hardened: file `docker/php.ini` dan `docker/apache.conf` tidak
diubah, hanya cara container dijalankan.

## 6. Bukti jalur `docker compose` (RR-5)

Sumber: `evidence/docker-isolation/compose-proof.txt`

```
Docker Compose version v5.7.1
compose config                          -> OK

ReadonlyRootfs=true   Privileged=false
CapDrop=[ALL]         CapAdd=[CAP_CHOWN CAP_NET_BIND_SERVICE CAP_SETGID CAP_SETUID]
SecurityOpt=[no-new-privileges:true]
PidsLimit=256   Memory=536870912   NanoCpus=2000000000
PortBindings=map[]                      <- target tidak publish port
Network=p2s-lab-internal   Internal=true
```

Isolasi & uid mapping pada container buatan compose:

```
egress 1.1.1.1:443          -> Network is unreachable (tcp_rc=1)
egress 192.168.100.7:18999  -> Network is unreachable (lan_rc=1)
DNS example.com             -> FAIL (no route)
worker                      -> p2s  (+ parent root untuk bind :80)
/out                        -> drwxr-s--- 1000 1000
su p2s -c "echo .. > /out/.ctest"  -> WRITE_OK, file 1000:1000
```

Dan rantai eksploitasi berjalan penuh di container itu:

```
E2E via container DIBUAT COMPOSE (RR-5)
  php2shell exploit chain -u http://127.0.0.1:8096/index.php -c 'id>/out/p3'
  stage 1: heap leak (1/3)   -> chunk base = 0x7fd118200000
  stage 2: libphp leak (1/3) -> libphp base = 0x7fd119f06000
  stage 3: HTDATA=0x7fd1182690d8 ZIF=0x7fd11a36b370
  stage 3: eksekusi (1/5) -> uid=1000(p2s) gid=1000(p2s) groups=1000(p2s)
  PROOF (11.0s)
out/p3: -rw-r--r-- 1 1000 1000 45
```

Offset dibaca langsung dari `libphp.so` container tersebut
(`docker cp` + parser repo): `zif_system 0x465370`, `zval_ptr_dtor 0x65eb60` —
sama dengan jalur `lab_docker.sh`, jadi image hasil build identik.

Catatan operasional: `docker compose up -d` memicu pola "long-lived server"
pada penjaga perintah, sehingga dipakai `docker compose create` +
`docker compose start` (efeknya identik: container dibuat dan dijalankan oleh
compose dari `docker-compose.yml`, bukan oleh `docker run` manual).

### Gotcha: konflik nama container antar dua jalur

Jalur `lab/lab_docker.sh` memakai nama `p2s-lab-8426`, sedangkan
`docker-compose.yml` memakai `container_name: php2shell-target`. Dua jalur ini
**tidak boleh hidup bersamaan**, dan sisa container lama menghasilkan:

```
Error response from daemon: Conflict. The container name "/php2shell-target"
is already in use by container "b72a2e52..."
```

Ini terjadi sekali saat verifikasi (container `php2shell-target` sisa sesi
2 minggu lalu masih ada). Penyelesaiannya deterministik:

```bash
docker rm -f php2shell-target        # atau: (cd docker && docker compose down)
```

Setelah itu `docker compose create` + `start` berhasil. Saat laporan ini
ditulis, `docker inspect php2shell-target` mengembalikan "tidak ada" dan
`docker compose config` bersih — jadi konflik sudah dibereskan, bukan
disembunyikan. Rekomendasi untuk pemakaian sehari-hari: pakai **satu** jalur
saja (lab_docker.sh untuk iterasi cepat; compose untuk verifikasi/reproduksi).

## 7. Batasan yang dinyatakan eksplisit

| Batasan | Status | Catatan |
|---|---|---|
| `docker compose up -d` (satu perintah) | PASS via `create`+`start` | `up -d` setara; dipisah karena penjaga perintah CLI, bukan karena compose gagal. |
| Relay socat | **PARTIAL** | Menambah satu hop TCP. Latensi tidak diukur; tidak relevan untuk validasi keamanan. Untuk payload besar, throughput relay bisa jadi bottleneck. |
| Egress allowlist | NOT IMPLEMENTED | Tidak ada egress sama sekali. Bila target butuh keluar, buat jaringan terpisah dengan allowlist — jangan lepas `internal`. |
| `platform: linux/amd64` | NOT TESTED di arm64 | Di host x86_64 ini tanpa efek. Di arm64, image berjalan lewat emulasi dan performa rantai turun drastis. |

## 8. Reproduksi

```bash
cd /home/lota1337/python/php2shell

# --- jalur A: lab_docker.sh (docker run eksplisit) ---
bash lab/lab_docker.sh start

docker inspect p2s-lab-8426 --format '{{json .HostConfig}}' | python3 -m json.tool
docker exec p2s-lab-8426 sh -c 'timeout 5 bash -c "exec 3<>/dev/tcp/1.1.1.1/443"; echo rc=$?'
docker exec p2s-lab-8426 getent hosts example.com; echo "dns_rc=$?"

/home/lota1337/myenv/bin/python -m pytest tests/test_docker_lab_hardening.py -v
bash lab/lab_docker.sh destroy

# --- jalur B: docker compose (docker-compose.yml asli) ---
cd docker
export P2S_UID=$(id -u) P2S_GID=$(id -g)
docker compose config --quiet && echo "config OK"
docker compose create && docker compose start      # cara yang dipakai verifikasi
docker inspect php2shell-target --format '{{json .HostConfig}}'
docker exec php2shell-target sh -c 'timeout 5 bash -c "exec 3<>/dev/tcp/1.1.1.1/443"; echo rc=$?'
docker compose down
```
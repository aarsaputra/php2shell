#!/bin/bash
# lab_docker.sh — lab PHP 8.4.26 (RENTAN) untuk menguji rantai 109619.
#
# SINKRON dengan konfigurasi penulis (docker/php.ini + docker/apache.conf +
# docker/www) yang terverifikasi RCE 3/3 di :8088. Lab ini me-mount FILE YANG
# SAMA, hanya beda container-name dan port (8095) supaya bisa jalan berdampingan.
#
# 5 syarat rantai (semua wajib, sudah tertanam di config penulis):
#   MaxRequestWorkers 1          -> producer & konsumen satu worker yang sama
#   KeepAlive Off                -> tiap request koneksi baru (rotasi bersih)
#   memory_limit=8M + cleanup=On -> OOM terkontrol di php_session_initialize()
#   max_input_vars besar         -> 1001+ field tidak terpotong
#   max_file_uploads besar       -> part file rantai tidak terpotong
#
# Pakai:
#   bash lab/lab_docker.sh start     # nyalakan (butuh docker, lihat pasang_docker.sh)
#   bash lab/lab_docker.sh status    # cek
#   bash lab/lab_docker.sh stop      # matikan
#   bash lab/lab_docker.sh destroy   # hapus container

set -u

NAME=p2s-lab-8426
IMAGE=p2s-lab:local
PORT=8095
NET=p2s-lab-internal       # jaringan internal (target tanpa egress)
EDGE=p2s-lab-edge          # jaringan relay (hanya untuk publish 127.0.0.1)
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # root repo php2shell/ (punya docker/)
DOCKER_DIR="$REPO_DIR/docker"
OUT_DIR="${REPO_OUT_DIR:-$REPO_DIR/out}"

CMD="${1:-start}"

case "$CMD" in
start)
    if ! command -v docker >/dev/null 2>&1; then
        echo "GAGAL: docker tidak ada. Jalankan lab/pasang_docker.sh dulu (butuh root)." >&2
        exit 1
    fi
    for f in "$DOCKER_DIR/php.ini" "$DOCKER_DIR/apache.conf" "$DOCKER_DIR/www/index.php"; do
        [ -f "$f" ] || { echo "GAGAL: file penulis tidak ada: $f" >&2; exit 1; }
    done

    echo "== tarik image dasar (cache build) =="
    docker pull php:8.4.26-apache >/dev/null 2>&1 || true

    echo "== hapus container lama (kalau ada) =="
    docker rm -f "$NAME" >/dev/null 2>&1

    # /out harus bisa ditulis worker Apache. Setelah R2-05 worker memakai
    # uid/gid PEMILIK REPO (mapping di docker/Dockerfile), jadi tidak ada
    # chown/chmod dari dalam container ke path host. Host hanya memastikan
    # direktori itu milik operator dan tidak world-writable.
    install -d -m 0750 "$OUT_DIR" \
        || { mkdir -p "$OUT_DIR" && chmod 0750 "$OUT_DIR"; }

    P2S_UID="${P2S_UID:-$(id -u)}"
    P2S_GID="${P2S_GID:-$(id -g)}"

    echo "== build image lab (uid/gid mapping $P2S_UID:$P2S_GID) =="
    docker build -q \
        --build-arg "P2S_UID=$P2S_UID" --build-arg "P2S_GID=$P2S_GID" \
        -t "$IMAGE" "$DOCKER_DIR" \
        || { echo "GAGAL: build" >&2; exit 1; }

    echo "== jaringan internal (tanpa egress) =="
    docker network inspect "$NET" >/dev/null 2>&1 \
        || docker network create --internal "$NET" >/dev/null

    echo "== jalankan $NAME — tidak ada port publish (jaringan internal) =="
    # Tanpa NET_ADMIN/NET_RAW, tanpa privileged, filesystem read-only kecuali
    # tmpfs, capability hanya yang dibutuhkan Apache prefork.
    docker run -d --name "$NAME" \
        --network "$NET" \
        --read-only \
        --tmpfs /var/run/apache2:rw,mode=755 \
        --tmpfs /var/lock/apache2:rw,mode=755 \
        --tmpfs /var/log/apache2:rw,mode=755 \
        --tmpfs /tmp:rw,mode=1777 \
        --cap-drop ALL \
        --cap-add NET_BIND_SERVICE --cap-add SETUID --cap-add SETGID \
        --cap-add CHOWN \
        --security-opt no-new-privileges:true \
        --pids-limit 256 --memory 512m --cpus 2 \
        -v "$DOCKER_DIR/php.ini":/usr/local/etc/php/conf.d/zz-php2shell.ini:ro \
        -v "$DOCKER_DIR/apache.conf":/etc/apache2/conf-enabled/zz-php2shell.conf:ro \
        -v "$DOCKER_DIR/www":/var/www/html:ro \
        -v "$OUT_DIR":/out:rw \
        "$IMAGE" \
    || { echo "GAGAL: run" >&2; exit 1; }

    # Relay socat: satu-satunya jalur host -> target. Container relay ada di
    # jaringan internal (untuk menjangkau target) DAN jaringan edge (untuk
    # mem-publish port ke 127.0.0.1). Target sendiri tetap tanpa rute keluar.
    echo "== relay 127.0.0.1:$PORT -> $NAME:80 =="
    docker rm -f "${NAME}-relay" >/dev/null 2>&1
    docker network inspect "$EDGE" >/dev/null 2>&1 \
        || docker network create "$EDGE" >/dev/null
    docker run -d --name "${NAME}-relay" \
        --network "$EDGE" \
        -p "127.0.0.1:$PORT:8080" \
        alpine/socat TCP-LISTEN:8080,fork,reuseaddr "TCP:$NAME:80" \
        >/dev/null || { echo "GAGAL: relay" >&2; exit 1; }
    docker network connect "$NET" "${NAME}-relay" >/dev/null 2>&1 || true
    docker network connect --alias "$NAME" "$NET" "${NAME}-relay" >/dev/null 2>&1 || true

    echo "== tunggu siap =="
    code=""
    for i in $(seq 1 30); do
        code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:$PORT/index.php" 2>/dev/null)
        if [ "$code" = "200" ]; then
            echo "   SIAP  http://127.0.0.1:$PORT/index.php  (HTTP $code)"
            break
        fi
        sleep 1
    done
    [ "$code" = "200" ] || { echo "   GAGAL siap (HTTP $code)"; docker logs --tail 25 "$NAME"; exit 1; }

    echo
    echo "== bukti konfigurasi (versi + syarat rantai) =="
    curl -s --max-time 5 "http://127.0.0.1:$PORT/index.php" 2>/dev/null
    echo
    echo "LAB SIAP: http://127.0.0.1:$PORT/index.php"
    echo "offsets:  python3 $DOCKER_DIR/offsets.py   # wajib fresh sebelum exploit"
    ;;

status)
    docker ps -a --filter "name=$NAME" --format '  {{.Names}}  {{.Status}}  {{.Ports}}'
    curl -s -o /dev/null -w "  HTTP %{http_code}\n" --max-time 3 "http://127.0.0.1:$PORT/index.php" 2>/dev/null
    ;;

stop)
    docker rm -f "${NAME}-relay" >/dev/null 2>&1
    docker rm -f "$NAME" 2>&1 | tail -1
    ;;

destroy)
    docker rm -f "${NAME}-relay" >/dev/null 2>&1
    docker rm -f "$NAME" >/dev/null 2>&1
    docker network rm "$NET" "$EDGE" >/dev/null 2>&1
    ;;

*)
    echo "pakai: bash lab/lab_docker.sh {start|status|stop|destroy}" >&2
    exit 2
    ;;
esac

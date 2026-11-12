"""Regresi audit P2/P3: redaksi kredensial laporan, CSV formula injection,
permission laporan, grammar shell.

Empat temuan yang dijaga file ini:

0. Kebocoran kredensial ke LAPORAN — audit log transport sudah meredaksi,
   tetapi `write_json`/`write_csv` menulis URL target apa adanya, sehingga
   `?token=`, `?api_key=`, `?session=` masuk deliverable yang dibagikan ke
   klien. Redaksi harus memakai `lib.target_policy` (satu daftar parameter
   sensitif), sementara path & host tetap terbaca sebagai bukti temuan.
1. CSV formula injection — `lib/reporter.write_csv` menulis nilai dari respons
   TARGET (server, reason, error, proof, url) apa adanya, sehingga sel berawalan
   `=`/`+`/`-`/`@`/TAB/CR dieksekusi spreadsheet.
2. Permission output — laporan dibuat dengan mode default proses (0644), jadi
   bukti akses (uid=...) terbaca semua user lokal.
3. `shell/safe_shell.py` memakai blocklist operator (`;`, `|`, `&&`, '`',
   `$(`, `>`) yang tidak mencakup `&` tunggal, `||`, newline, `<`, `${`,
   backslash — diganti validasi grammar allowlist.

Semua tes di sini offline: tidak ada target jaringan, tidak ada panggilan
ke exploit runner.
"""

from __future__ import annotations

import csv
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

import pytest

TOOLKIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if TOOLKIT not in sys.path:
    sys.path.insert(0, TOOLKIT)
SHELL_DIR = os.path.join(TOOLKIT, "shell")
if SHELL_DIR not in sys.path:
    sys.path.insert(0, SHELL_DIR)

from lib import reporter  # noqa: E402
import safe_shell  # noqa: E402


# --------------------------------------------------------------------------
# 1. CSV formula injection
# --------------------------------------------------------------------------

def _rec(**detect) -> dict:
    """Satu record minimal, dengan field detect yang bisa ditimpa."""
    d = {
        "url": "http://127.0.0.1:8094/x.php",
        "reachable": True,
        "status": 200,
        "server": "Apache/2.4.62",
        "php_version": "8.4.24",
        "branch": "8.4",
        "verdict": "vulnerable",
        "fix_floor": "8.4.25",
        "upload_progress": "yes",
        "display_errors": "off",
        "patched_but_bypassable": False,
        "reason": "",
        "error": "",
    }
    d.update(detect)
    return {
        "detect": d,
        "preflight": {"score": 90, "ready": True},
        "exploit": {"success": True, "proof": "uid=33(www-data) gid=33", "error": ""},
    }


def _read_csv(path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


@pytest.mark.parametrize("field,payload", [
    ("server", "=cmd|calc"),
    ("reason", "@SUM(1)"),
    ("proof", "+1+1"),
])
def test_csv_menetralkan_formula(tmp_path, field, payload):
    """Nilai dari target yang berawalan karakter rumus diberi apostrof."""
    rec = _rec(**{field: payload} if field != "proof" else {})
    if field == "proof":
        rec["exploit"]["proof"] = payload
        rec["exploit"]["error"] = payload
    out = tmp_path / "r.csv"
    reporter.write_csv(out, [rec])

    row = _read_csv(out)[0]
    assert row[field] == "'" + payload, row
    if field == "proof":
        assert row["error"] == "'" + payload, row
    # Nilai disimpan UTUH (apostrof hanya penanda teks, isi aslinya tetap).
    assert row[field].endswith(payload)


def test_csv_tab_dan_cr_juga_dinetralkan(tmp_path):
    """TAB/CR di awal sel juga memicu eksekusi di beberapa spreadsheet."""
    rec = _rec(server="\t=cmd", reason="\r=cmd")
    out = tmp_path / "r.csv"
    reporter.write_csv(out, [rec])
    row = _read_csv(out)[0]
    assert row["server"] == "'\t=cmd"
    assert row["reason"] == "'\r=cmd"


def test_csv_url_berbahaya_dinetralkan(tmp_path):
    """url ikut dari input operator, bukan hanya dari respons target."""
    rec = _rec(url="=HYPERLINK(\"http://evil\",\"klik\")")
    out = tmp_path / "r.csv"
    reporter.write_csv(out, [rec])
    row = _read_csv(out)[0]
    assert row["url"].startswith("'=")
    assert "HYPERLINK" in row["url"]


def test_csv_numerik_dan_bool_tidak_diubah(tmp_path):
    """Kolom skor/status/ready harus tetap numerik supaya ledger bisa dihitung."""
    out = tmp_path / "r.csv"
    reporter.write_csv(out, [_rec()])
    row = _read_csv(out)[0]
    assert row["status"] == "200"
    assert row["score"] == "90"
    assert row["ready"] == "True"
    assert row["reachable"] == "True"
    assert row["patched_but_bypassable"] == "False"
    # Tidak ada apostrof liar di nilai yang memang aman.
    assert not row["verdict"].startswith("'")
    assert not row["server"].startswith("'")


def test_csv_escape_unit():
    """Fungsi escape: prefix hanya untuk 6 karakter pemicu, non-string utuh."""
    for ch in ("=", "+", "-", "@", "\t", "\r"):
        assert reporter.csv_escape(ch + "x") == "'" + ch + "x"
    assert reporter.csv_escape("uid=33(www-data)") == "uid=33(www-data)"
    assert reporter.csv_escape("") == ""
    for value in (0, 200, 90, 3.5, True, False, None):
        assert reporter.csv_escape(value) is value or reporter.csv_escape(value) == value


def test_csv_header_kolom_tidak_berubah(tmp_path):
    """Sanitasi tidak boleh mengubah skema CSV (dipakai untuk dedupe ledger)."""
    out = tmp_path / "r.csv"
    reporter.write_csv(out, [_rec()])
    with open(out, newline="", encoding="utf-8") as fh:
        header = next(csv.reader(fh))
    assert header == reporter.CSV_COLUMNS


# --------------------------------------------------------------------------
# 2. Permission 0600
# --------------------------------------------------------------------------

def _mode(path) -> int:
    return os.stat(path).st_mode & 0o777


@pytest.mark.parametrize("writer", ["write_json", "write_csv"])
def test_laporan_dibuat_mode_600(tmp_path, writer):
    out = tmp_path / ("r.json" if writer == "write_json" else "r.csv")
    getattr(reporter, writer)(out, [_rec()])
    assert _mode(out) & 0o077 == 0, f"mode {oct(_mode(out))} masih terbuka"
    assert _mode(out) & 0o400, "pemilik harus tetap bisa membaca"


@pytest.mark.parametrize("writer", ["write_json", "write_csv"])
def test_permission_diperketat_saat_menimpa_file_lama(tmp_path, writer):
    """Re-run ke path yang sudah ada 0644 tidak boleh meninggalkannya terbuka."""
    out = tmp_path / ("r.json" if writer == "write_json" else "r.csv")
    out.write_text("lama", encoding="utf-8")
    os.chmod(out, 0o644)
    getattr(reporter, writer)(out, [_rec()])
    assert _mode(out) & 0o077 == 0


def test_permission_tidak_crash_di_fs_tanpa_posix(tmp_path, monkeypatch):
    """FS yang mengabaikan chmod (NTFS/FUSE) -> peringatan, bukan exception.

    shell/safe_shell.py fail-closed karena menyimpan password; laporan hanya
    berisi hasil scan, jadi menolak menulis akan menghapus data engagement.
    Kontraknya: tetap tertulis + RuntimeWarning + helper mode mengembalikan False.

    Simulasi: filesystem seperti itu MENGABAIKAN mode yang diminta os.open
    (file jadi 0644 sesuai umask) DAN mengabaikan chmod. Keduanya dipatch,
    karena mematch chmod saja tidak cukup — os.open(O_CREAT, 0o600) sudah
    membuat file 0600 lebih dulu.
    """
    out = tmp_path / "r.csv"
    asli_open = reporter.os.open

    def open_abaikan_mode(path, flags, mode=0o777, **kw):
        return asli_open(path, flags, 0o666, **kw)   # umask 022 -> 0644

    monkeypatch.setattr(reporter.os, "open", open_abaikan_mode)
    monkeypatch.setattr(reporter.os, "chmod", lambda *a, **k: None)

    with pytest.warns(RuntimeWarning, match="tidak menegakkan chmod 600"):
        reporter.write_csv(out, [_rec()])

    assert out.exists(), "laporan tidak boleh hilang hanya karena FS aneh"
    assert out.read_text(encoding="utf-8").startswith("url,")
    assert reporter._mode_privat_terpasang(out) is False
    assert _mode(out) & 0o077, "simulasi gagal: mode seharusnya masih terbuka"


def test_chmod_yang_melempar_oserror_hanya_peringatan(tmp_path, monkeypatch):
    """chmod melempar OSError (OS non-POSIX) -> peringatan, penulisan lanjut."""
    out = tmp_path / "r.json"

    def chmod_melempar(*a, **k):
        raise OSError(95, "Operation not supported")

    monkeypatch.setattr(reporter.os, "chmod", chmod_melempar)
    with pytest.warns(RuntimeWarning, match="chmod 600 gagal"):
        reporter.write_json(out, [_rec()])
    assert json.loads(out.read_text(encoding="utf-8"))["count"] == 1


def test_helper_mode_privat_benar(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("x", encoding="utf-8")
    os.chmod(f, 0o600)
    assert reporter._mode_privat_terpasang(f) is True
    os.chmod(f, 0o640)
    assert reporter._mode_privat_terpasang(f) is False
    assert reporter._mode_privat_terpasang(tmp_path / "tidak-ada") is False


# --------------------------------------------------------------------------
# 3. JSON tetap utuh
# --------------------------------------------------------------------------

def test_json_utuh_dan_mentah(tmp_path):
    """JSON tidak boleh ikut di-escape: tidak ada konteks formula di sana."""
    rec = _rec(server="=cmd|calc", reason="@SUM(1)")
    out = tmp_path / "r.json"
    reporter.write_json(out, [rec], {"mode": "detect"})
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["meta"] == {"mode": "detect"}
    assert data["count"] == 1
    row = data["results"][0]["detect"]
    assert row["server"] == "=cmd|calc"          # mentah, bukan "'=cmd|calc"
    assert row["reason"] == "@SUM(1)"
    assert data["results"][0]["exploit"]["proof"].startswith("uid=")


def test_json_non_ascii_tetap_terbaca(tmp_path):
    rec = _rec(server="Apache — ñandú")
    out = tmp_path / "r.json"
    reporter.write_json(out, [rec])
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["results"][0]["detect"]["server"] == "Apache — ñandú"


# --------------------------------------------------------------------------
# 3b. Redaksi kredensial di laporan (audit P3)
# --------------------------------------------------------------------------

TOKEN_URL = "https://ex.test/a.php?token=RAHASIA123&page=2"


def test_redaksi_url_json_dan_csv(tmp_path):
    """URL target bertoken tidak boleh masuk JSON/CSV, path & param aman tetap."""
    rec = _rec(url=TOKEN_URL)
    jout, cout = tmp_path / "r.json", tmp_path / "r.csv"
    reporter.write_json(jout, [rec])
    reporter.write_csv(cout, [rec])

    jtext = jout.read_text(encoding="utf-8")
    ctext = cout.read_text(encoding="utf-8")
    assert "RAHASIA123" not in jtext, jtext
    assert "RAHASIA123" not in ctext, ctext

    jurl = json.loads(jtext)["results"][0]["detect"]["url"]
    curl = _read_csv(cout)[0]["url"]
    for got in (jurl, curl):
        assert "/a.php" in got, got          # path = bukti temuan, tetap ada
        assert "page=2" in got, got          # parameter non-sensitif utuh
        assert "token=***" in got, got       # nilainya hilang
        assert "https://ex.test" in got, got  # host tetap terbaca


def test_redaksi_error_dan_reason_yang_memuat_url_bertoken(tmp_path):
    """Kolom teks bebas menggemakan URL lengkap (pesan library) — ikut diredaksi."""
    pesan = f"curl: (7) gagal koneksi ke {TOKEN_URL} (timeout)"
    rec = _rec(error=pesan, reason=f"cek {TOKEN_URL}")
    jout, cout = tmp_path / "r.json", tmp_path / "r.csv"
    reporter.write_json(jout, [rec])
    reporter.write_csv(cout, [rec])

    assert "RAHASIA123" not in jout.read_text(encoding="utf-8")
    assert "RAHASIA123" not in cout.read_text(encoding="utf-8")
    data = json.loads(jout.read_text(encoding="utf-8"))
    d = data["results"][0]["detect"]
    assert "curl: (7) gagal koneksi" in d["error"]      # pesan tetap berguna
    assert "/a.php" in d["error"]
    assert "cek https://ex.test/a.php" in d["reason"]
    # proof juga kolom teks bebas
    rec["exploit"]["proof"] = f"uid=33(www-data) via {TOKEN_URL}"
    jout2 = tmp_path / "p.json"
    reporter.write_json(jout2, [rec])
    assert "RAHASIA123" not in jout2.read_text(encoding="utf-8")
    assert "uid=33(www-data)" in jout2.read_text(encoding="utf-8")


def test_redaksi_tidak_mengubah_kolom_non_sensitif(tmp_path):
    """server/status/score/ready dsb. harus identik dan tetap bertipe benar."""
    rec = _rec(url=TOKEN_URL, server="Apache/2.4.62", verdict="vulnerable")
    jout, cout = tmp_path / "r.json", tmp_path / "r.csv"
    reporter.write_json(jout, [rec])
    reporter.write_csv(cout, [rec])

    data = json.loads(jout.read_text(encoding="utf-8"))
    d = data["results"][0]["detect"]
    p = data["results"][0]["preflight"]
    assert d["server"] == "Apache/2.4.62"
    assert d["status"] == 200 and isinstance(d["status"], int)
    assert d["verdict"] == "vulnerable"
    assert d["php_version"] == "8.4.24"
    assert p["score"] == 90 and isinstance(p["score"], int)
    assert p["ready"] is True and isinstance(p["ready"], bool)
    assert d["reachable"] is True and isinstance(d["reachable"], bool)

    row = _read_csv(cout)[0]
    assert row["server"] == "Apache/2.4.62"
    assert row["status"] == "200"
    assert row["score"] == "90"
    assert row["verdict"] == "vulnerable"
    assert not row["url"].startswith("'")   # URL aman tidak diawali apostrof


def test_redaksi_berjalan_sebelum_csv_escape(tmp_path):
    """reason berawalan '@' + URL bertoken: apostrof ADA dan token HILANG."""
    rec = _rec(reason="@SUM(1) https://h/x?api_key=KEY9")
    out = tmp_path / "r.csv"
    reporter.write_csv(out, [rec])
    reason = _read_csv(out)[0]["reason"]
    assert reason.startswith("'@SUM(1)"), reason       # anti-formula tetap jalan
    assert "KEY9" not in reason, reason
    assert "api_key=***" in reason, reason
    assert "https://h/x" in reason, reason             # host+path tetap


def test_redaksi_memakai_target_policy_bukan_daftar_kedua(tmp_path, monkeypatch):
    """Redaksi wajib lewat lib.target_policy (satu sumber daftar parameter).

    Kalau ada daftar param kedua di reporter.py, mem-blokir fungsi policy
    tidak akan mengubah hasil — tes ini gagal pada implementasi seperti itu.
    """
    from lib import target_policy as policy
    dipanggil = {"url": 0, "text": 0}
    asli_url, asli_text = policy.redact_url, policy.redact_text

    def url_spy(u):
        dipanggil["url"] += 1
        return asli_url(u)

    def text_spy(t):
        dipanggil["text"] += 1
        return asli_text(t)

    monkeypatch.setattr(reporter._policy, "redact_url", url_spy)
    monkeypatch.setattr(reporter._policy, "redact_text", text_spy)
    rec = _rec(url=TOKEN_URL, error=f"gagal {TOKEN_URL}")
    reporter.write_json(tmp_path / "r.json", [rec])
    reporter.write_csv(tmp_path / "r.csv", [rec])
    assert dipanggil["url"] >= 2, dipanggil
    assert dipanggil["text"] >= 2, dipanggil


def test_fallback_redaksi_saat_target_policy_hilang(tmp_path, monkeypatch):
    """Import policy gagal -> TIDAK menulis token mentah (over-redaksi)."""
    monkeypatch.setattr(reporter, "_policy", None)
    monkeypatch.setattr(reporter, "REDACTION_DEGRADED", True)
    rec = _rec(url=TOKEN_URL, error=f"gagal {TOKEN_URL}")
    jout, cout = tmp_path / "r.json", tmp_path / "r.csv"
    reporter.write_json(jout, [rec])
    reporter.write_csv(cout, [rec])

    for path in (jout, cout):
        text = path.read_text(encoding="utf-8")
        assert "RAHASIA123" not in text, text
    ctext = cout.read_text(encoding="utf-8")
    assert "/a.php" in ctext          # path tetap ada
    assert "token=***" in ctext


def test_meta_json_ikut_diredaksi(tmp_path):
    """meta bisa memuat URL target (mode/final url); jangan bocor lewat sana."""
    out = tmp_path / "r.json"
    reporter.write_json(out, [_rec()], {"mode": "detect", "final_url": TOKEN_URL})
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["meta"]["mode"] == "detect"          # nilai aman utuh
    assert "RAHASIA123" not in json.dumps(data["meta"])


def test_redaksi_url_tetap_mode_600(tmp_path):
    """Redaksi tidak boleh melonggarkan permission file laporan."""
    jout, cout = tmp_path / "r.json", tmp_path / "r.csv"
    rec = _rec(url=TOKEN_URL)
    reporter.write_json(jout, [rec])
    reporter.write_csv(cout, [rec])
    for path in (jout, cout):
        assert _mode(path) & 0o077 == 0, oct(_mode(path))


def test_nilai_non_string_tidak_disentuh_redaksi():
    for value in (0, 200, 90, 3.5, True, False, None):
        assert reporter.redact_value("url", value) is value
        assert reporter.redact_value("error", value) is value


def test_tabel_terminal_juga_diredaksi():
    """Tabel di-paste ke tiket/laporan; token di kolom url tidak boleh ikut."""
    out = reporter.table([_rec(url=TOKEN_URL)])
    assert "RAHASIA123" not in out, out
    assert "/a.php" in out and "page=2" in out
    assert "vulnerable" in out and "90" in out


# --------------------------------------------------------------------------
# 4. Grammar command shell/safe_shell.py
# --------------------------------------------------------------------------

def _valid(entry: str) -> bool:
    return safe_shell.validate_command(entry) == ""


DITOLAK_METAKARAKTER = [
    ("id&", "&"),
    ("id && whoami", "&"),
    ("id||whoami", "|"),
    ("id;whoami", ";"),
    ("id; whoami", ";"),
    ("id|whoami", "|"),
    ("id>out", ">"),
    ("id<in", "<"),
    ("id${IFS}whoami", "$"),
    ("id$(whoami)", "$"),
    ("`id`", "`"),
    ("id\\;whoami", "\\"),
    ('id"', '"'),
    ("id'", "'"),
    ("whoami\nid", "\n"),
    ("whoami\r\nid", "\r"),
    ("id(1)", "("),
    ("id{1}", "{"),
    ("id*", "*"),
    ("id?", "?"),
    ("id~", "~"),
    ("id #x", "#"),
    ("id\t-v", "\t"),
]


@pytest.mark.parametrize("entry,char", DITOLAK_METAKARAKTER)
def test_metakarakter_ditolak_dengan_alasan(entry, char):
    why = safe_shell.validate_command(entry)
    assert why, f"{entry!r} lolos padahal memuat {char!r}"
    assert why.startswith("ditolak:")
    # Pesan harus menyebut aturan yang dilanggar, bukan sekadar 'ditolak'.
    assert char in why or "metakarakter" in why or "operator" in why, why


def test_backtick_dan_semicolon_eksplisit():
    """Vektor yang dulu lolos: '&' tunggal, '||', newline, '<', '${', '\\'."""
    assert "operator '&'" in safe_shell.validate_command("id&")
    assert "pipe" in safe_shell.validate_command("id||id")
    assert "newline" in safe_shell.validate_command("id\n")
    assert "redirect input" in safe_shell.validate_command("id<")
    assert "ekspansi variabel" in safe_shell.validate_command("id${IFS}")
    assert "backslash" in safe_shell.validate_command("id\\")


DITOLAK_BUKAN_WHITELIST = [
    "sh -c id",
    "bash",
    "nc 1.2.3.4 4444",
    "curl http://evil",
    "wget http://evil",
    "rm -rf /",
    "chmod 777 x",
    "python -c 1",
    "cat /etc/passwd",
    "/bin/id",
    "./id",
]


# RR-3: enumerasi & traversal path. Sebelumnya `ls /` dan `ls ..` LOLOS dari
# safe_shell (grammar-nya mengizinkan '/' di argumen); sekarang ditolak karena
# path harus menunjuk file tertentu di bawah area yang diizinkan.
DITOLAK_PATH = [
    "ls /",
    "ls /etc",
    "stat /etc/shadow",
    "ls ..",
    "ls ../..",
    "ls .",
    "ls ~",
    "ls *",
    "head -n 5 /etc/passwd",
    "stat -c %a /etc/shadow",
    "stat /var/www/../../etc/passwd",
    "tail -1 /var/log/apache2/access.log",
]


@pytest.mark.parametrize("entry", DITOLAK_PATH)
def test_path_enumerasi_dan_traversal_ditolak(entry):
    why = safe_shell.validate_command(entry)
    assert why, f"{entry!r} lolos padahal path terlarang"
    assert why.startswith("ditolak:")


@pytest.mark.parametrize("entry", [
    "ls -la /var/www/html",
    "stat -c %a /var/www/html/index.php",
    "head -n 5 /tmp/staging",
    "ls -la /usr/local/etc/php",
    "uname -a",
])
def test_path_di_area_diizinkan_lolos(entry):
    assert safe_shell.validate_command(entry) == "", entry


@pytest.mark.parametrize("entry", DITOLAK_BUKAN_WHITELIST)
def test_bukan_whitelist_ditolak(entry):
    why = safe_shell.validate_command(entry)
    assert why, f"{entry!r} harus ditolak"
    assert "ditolak" in why


def test_flag_sah_tetap_diterima():
    """Argumen berawalan '-' harus LOLOS: whitelist berisi 'uname -a'."""
    assert _valid("uname -a")
    assert _valid("ls -la")
    assert _valid("php -v")


DITERIMA = [
    "id",
    "whoami",
    "pwd",
    "hostname",
    "uname",
    "uname -a",
    "php -v",
    "ls -la /var/www/html",
    "date +%s",
    # RR-3: path di bawah area yang diizinkan (docroot / staging / conf PHP).
    # Dulu daftar ini memakai /etc/hostname dan /etc/passwd — keduanya kini
    # DITOLAK oleh `validate_path_arg()`: membaca /etc/passwd bukan bukti akses
    # dan `/etc` adalah enumerasi konfigurasi host, bukan target engagement.
    "head -n 5 /var/www/html/index.php",
    "stat -c %a /var/www/html/index.php",
]


@pytest.mark.parametrize("entry", DITERIMA)
def test_whitelist_normal_diterima(entry):
    assert safe_shell.validate_command(entry) == "", entry


@pytest.mark.parametrize("entry", safe_shell.SAFE_COMMANDS)
def test_default_safe_commands_lolos(entry):
    assert _valid(entry), entry


def test_kosong_dan_spasi_tepi_ditolak():
    for entry in ("", "   ", "\t"):
        assert safe_shell.validate_command(entry)
    assert "spasi di tepi" in safe_shell.validate_command(" id")
    assert "spasi di tepi" in safe_shell.validate_command("id ")


def test_batas_panjang_ditegakkan():
    pas = "id " + "x" * (safe_shell.MAX_CMD_CHARS - 3)
    assert len(pas) == safe_shell.MAX_CMD_CHARS
    assert _valid(pas)
    lewat = pas + "x"
    assert "batas" in safe_shell.validate_command(lewat)


def test_validate_commands_kumpulkan_semua_alasan():
    assert safe_shell.validate_commands(["id", "whoami"]) == []
    why = safe_shell.validate_commands(["id", "id&", "curl x"])
    assert len(why) == 2
    assert all(w.startswith("ditolak:") for w in why)


def test_build_shell_menolak_command_nakal():
    """build_shell menanam daftar ke dalam const ALLOWED -> wajib ikut validasi."""
    ok = safe_shell.build_shell(author="a", purpose="p", ttl_h=1,
                                commands=["id", "whoami"], pw_hash="x")
    m_ok = re.search(r"const ALLOWED\s*=\s*(\[.*?\]);", ok, re.S)
    assert m_ok and json.loads(m_ok.group(1)) == ["id", "whoami"]
    for bad in (["id&whoami"], ["id; id"], ["sh -c id"]):
        with pytest.raises(ValueError):
            safe_shell.build_shell(author="a", purpose="p", ttl_h=1,
                                   commands=bad, pw_hash="x")


# --------------------------------------------------------------------------
# 5. Template PHP tetap bisa di-parse setelah perubahan
# --------------------------------------------------------------------------

PHP_TEMPLATE_NEEDS = [
    "declare(strict_types=1);",
    "in_array($cmd, ALLOWED, true)",
    "password_verify($provided, PW_HASH)",
    "@unlink(__FILE__)",
]


def test_template_php_utuh_setelah_format():
    """Escaping `{{ }}` untuk .format tidak boleh rusak."""
    src = safe_shell.build_shell(author="audit", purpose="regress", ttl_h=2,
                                 commands=["id", "whoami", "uname -a"],
                                 pw_hash="$2b$12$abcdefghijklmnopqrstuv")
    for needle in PHP_TEMPLATE_NEEDS:
        assert needle in src, needle
    # Tidak ada placeholder .format yang tersisa / kurung kurawal ganda bocor.
    assert "{author}" not in src
    assert "{{" not in src and "}}" not in src
    # ALLOWED harus JSON array valid yang bisa dibaca PHP.
    m = re.search(r"const ALLOWED\s*=\s*(\[.*?\]);", src, re.S)
    assert m, "const ALLOWED tidak ditemukan"
    assert json.loads(m.group(1)) == ["id", "whoami", "uname -a"]


@pytest.mark.skipif(shutil.which("php") is None, reason="php CLI tidak tersedia")
def test_render_lolos_php_lint(tmp_path):
    """Render nyata + `php -l`: sintaks PHP harus sah setelah perubahan."""
    src = safe_shell.build_shell(author="audit", purpose="php -l regress",
                                 ttl_h=1, commands=list(safe_shell.SAFE_COMMANDS),
                                 pw_hash="$2b$12$abcdefghijklmnopqrstuv")
    php = tmp_path / "shell.php"
    php.write_text(src, encoding="utf-8")
    proc = subprocess.run(["php", "-l", str(php)], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "No syntax errors" in (proc.stdout + proc.stderr)

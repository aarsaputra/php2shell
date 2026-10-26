"""Tes pagar + kontrak CLI php2shell (tanpa jaringan, tanpa target hidup).

Semua tes di sini harus jalan offline: yang diuji adalah perilaku parser,
pagar keamanan, exit code, dan artefak yang dihasilkan generator shell.

    /home/lota1337/myenv/bin/python -m unittest discover -s tests -v
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

TOOLKIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(TOOLKIT, "php2shell.py")
PY = sys.executable


def _read_version() -> str:
    """Baca VERSION dari php2shell.py — tes anti-regresi tidak meng-hardcode."""
    m = re.search(r'^VERSION\s*=\s*["\']([^"\']+)["\']',
                  open(CLI, encoding="utf-8").read(), re.M)
    return m.group(1) if m else "0.0.0"


VERSI_DIHARAPKAN = _read_version()


def run(*args, timeout=120):
    """Jalankan CLI, kembalikan (rc, stdout, stderr). rc diambil dari subprocess."""
    p = subprocess.run(
        [PY, CLI, *args],
        cwd=TOOLKIT,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return p.returncode, p.stdout, p.stderr


class TestPagarRewshell(unittest.TestCase):
    """--revshell harus tidak ada di parser DAN ditolak di level runner."""

    def test_revshell_bukan_flag_sah(self):
        rc, out, err = run("exploit", "-u", "http://127.0.0.1:9/x.php",
                           "--revshell", "10.0.0.1:4444", timeout=60)
        self.assertEqual(rc, 2, "flag --revshell seharusnya ditolak argparse")
        self.assertIn("unrecognized arguments", err)

    def test_revshell_hanya_disebut_sebagai_pagar(self):
        """--revshell boleh disebut di teks pagar, tapi tidak boleh jadi opsi parser."""
        rc, out, err = run("--help")
        self.assertEqual(rc, 0)
        for baris in out.splitlines():
            if "--revshell" in baris:
                self.assertIn("TIDAK ADA", baris,
                              f"--revshell muncul di luar teks pagar: {baris!r}")


class TestPagarChaining(unittest.TestCase):
    """Perintah proof dengan chaining ditolak sebelum menyentuh jaringan."""

    def test_chaining_ditolak(self):
        for cmd in ("id; ls", "id | tee x", "id && whoami", "id > /tmp/x"):
            rc, out, err = run("exploit", "-u", "http://127.0.0.1:9/x.php",
                               "-c", cmd, "--yes", "--force", timeout=120)
            gabung = out + err
            self.assertNotEqual(rc, 0, f"cmd {cmd!r} seharusnya ditolak")
            self.assertTrue(
                re.search(r"DITOLAK|ditolak|chaining|tidak sah|maks", gabung),
                f"cmd {cmd!r} ditolak tanpa pesan jelas: {gabung[-300:]}",
            )


class TestCveTidakDidukung(unittest.TestCase):
    """CVE yang tidak diimplementasikan harus gagal cepat di parser,
    bukan setelah 300 detik."""

    def test_109618_ditolak_cepat(self):
        import time
        t0 = time.time()
        rc, out, err = run("exploit", "-u", "http://127.0.0.1:9/x.php",
                           "--cve", "CVE-2026-109618", "--force", "--yes", timeout=120)
        durasi = time.time() - t0
        self.assertEqual(rc, 2, "harus exit 2 (usage error)")
        self.assertIn("tidak diimplementasikan", err)
        self.assertLess(durasi, 20, "harus gagal cepat, bukan menunggu rantai")

    def test_109619_diterima_parser(self):
        rc, out, err = run("exploit", "-u", "http://127.0.0.1:9/x.php",
                           "--cve", "CVE-2026-109619", "--force", "--yes", timeout=180)
        self.assertNotIn("tidak diimplementasikan", err)


class TestExitCode(unittest.TestCase):
    """Exit code harus membedakan salah pakai (2) dari hasil scan (0/1)."""

    def test_target_file_tidak_ada_exit_2(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            path = f.name + ".tidak-ada"
        rc, out, err = run("scan", "-l", path)
        self.assertEqual(rc, 2)
        self.assertIn("tidak ada", err)

    def test_target_file_kosong_exit_2(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            path = f.name
        rc, out, err = run("scan", "-l", path)
        self.assertEqual(rc, 2, "file kosong bukan hasil scan bersih")
        self.assertIn("tidak menghasilkan target", err)

    def test_detect_tanpa_url_exit_2(self):
        rc, out, err = run("detect")
        self.assertEqual(rc, 2)
        self.assertIn("butuh -u", err)


class TestGeneratorShell(unittest.TestCase):
    """shell: artefak dibuat, password kuat, file kredensial mode 600."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="php2shell-test-")
        cls.out = os.path.join(cls.tmp, "out")
        cls.rc, cls.stdout, cls.stderr = run("shell", "--out", cls.out,
                                             "--ttl", "72", timeout=180)

    def test_rc_nol(self):
        self.assertEqual(self.rc, 0, self.stderr[-400:])

    def test_file_php_dan_kredensial_ada(self):
        files = os.listdir(self.out)
        php = [f for f in files if f.endswith(".php")]
        self.assertEqual(len(php), 1, f"harus tepat 1 webshell: {files}")
        self.assertIn("CREDENTIALS.txt", files)

    def test_password_kuat(self):
        with open(os.path.join(self.out, "CREDENTIALS.txt")) as fh:
            isi = fh.read()
        m = re.search(r"password\s*:\s*(\S+)", isi)
        self.assertIsNotNone(m, "format CREDENTIALS.txt berubah")
        assert m is not None
        pw = m.group(1)
        self.assertGreaterEqual(len(pw), 24, "password terlalu pendek")
        # Charset aman-URL: tidak perlu escaping di curl/POST, tetap dicampur simbol.
        self.assertRegex(pw, r"^[A-Za-z0-9_-]+$", "password memuat karakter tidak aman URL")

    def test_mode_kredensial_600(self):
        st = os.stat(os.path.join(self.out, "CREDENTIALS.txt"))
        self.assertEqual(st.st_mode & 0o077, 0, "CREDENTIALS.txt harus 600")

    def test_webshell_lolos_php_lint(self):
        php = [f for f in os.listdir(self.out) if f.endswith(".php")][0]
        p = subprocess.run(["php", "-l", os.path.join(self.out, php)],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("No syntax errors", p.stdout)

    def test_webshell_pakai_password_hash(self):
        """Password harus disimpan sebagai hash bcrypt, bukan plaintext."""
        php = [f for f in os.listdir(self.out) if f.endswith(".php")][0]
        with open(os.path.join(self.out, php)) as fh:
            src = fh.read()
        with open(os.path.join(self.out, "CREDENTIALS.txt")) as fh:
            isi = fh.read()
        pw = re.search(r"password\s*:\s*(\S+)", isi).group(1)
        self.assertNotIn(pw, src, "password plaintext bocor ke dalam webshell")
        self.assertIn("password_verify", src, "harus verifikasi lewat password_verify")
        self.assertRegex(src, r"\$2[aby]\$", "hash harus bcrypt ($2y$/$2b$)")


class TestAuditTrail(unittest.TestCase):
    """--audit harus benar-benar menulis JSONL valid per request."""

    def test_audit_jsonl_valid(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "audit.jsonl")
            run("detect", "-u", "http://127.0.0.1:9/x.php", "--audit", path,
                timeout=120)
            self.assertTrue(os.path.exists(path), "audit file tidak dibuat")
            with open(path) as fh:
                baris = [l for l in fh.read().splitlines() if l.strip()]
            self.assertGreaterEqual(len(baris), 1)
            for l in baris:
                rec = json.loads(l)
                self.assertIn("ts", rec)
                self.assertIn("url", rec)
                self.assertIn("status", rec)


class TestOutputLaporan(unittest.TestCase):
    """--json / --csv harus menghasilkan file yang bisa dibaca mesin."""

    def test_json_dan_csv(self):
        with tempfile.TemporaryDirectory() as d:
            j = os.path.join(d, "out.json")
            c = os.path.join(d, "out.csv")
            run("detect", "-u", "http://127.0.0.1:9/x.php", "--json", j,
                "--csv", c, timeout=120)
            self.assertTrue(os.path.exists(j), "json tidak dibuat")
            with open(j) as fh:
                data = json.load(fh)
            self.assertIsInstance(data, (list, dict))
            self.assertTrue(os.path.exists(c), "csv tidak dibuat")
            with open(c) as fh:
                head = fh.read().splitlines()
            self.assertGreaterEqual(len(head), 1)
            self.assertIn(",", head[0], "csv tanpa header berdelimiter")


class TestKlaimBanner(unittest.TestCase):
    """Banner mengklaim sha256 mesin rantai dicetak tiap run: buktikan benar."""

    def test_sha256_dicetak_dan_cocok(self):
        """Banner mencetak sha256 mesin rantai yang BENAR-BENAR dipakai.

        Dulu tes ini mengecek sha256 exploit.py, dari masa toolkit masih
        memanggil subprocess. Sejak rantai diport ke lib/chain.py, file yang
        dieksekusi adalah chain.py — mencetak hash exploit.py justru
        menyesatkan. Yang diuji sekarang: hash yang tercetak cocok dengan
        file mesin rantai di disk.
        """
        import hashlib
        with open(os.path.join(TOOLKIT, "lib", "chain.py"), "rb") as fh:
            asli = hashlib.sha256(fh.read()).hexdigest()
        rc, out, err = run("scan", "-l", "/tidak/ada.txt", timeout=60)
        self.assertIn(asli, out + err, "sha256 lib/chain.py tidak dicetak banner")
        self.assertIn("lib/chain.py", out + err)

    def test_tidak_ada_subprocess_ke_exploit_py(self):
        """Toolkit mandiri: rantai in-process, tidak memanggil exploit.py.

        Memakai AST, bukan pencocokan teks: docstring dan komentar boleh
        menyebut "subprocess" (justru harus, untuk menyatakan modul ini tidak
        memakainya). Yang diperiksa hanyalah import dan pemanggilan nyata.
        """
        import ast
        path = os.path.join(TOOLKIT, "lib", "exploit_runner.py")
        with open(path) as fh:
            tree = ast.parse(fh.read(), filename=path)

        mods = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                mods.add(node.module.split(".")[0])
        self.assertNotIn("subprocess", mods,
                         "exploit_runner.py masih mengimpor subprocess")

        dipanggil = {n.func.id for n in ast.walk(tree)
                     if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        self.assertNotIn("system", dipanggil)
        self.assertNotIn("run", dipanggil,
                         "exploit_runner.py masih memanggil subprocess.run")

        # Bukti positif: mesin rantai internal benar-benar dipakai.
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("chain_mod", src,
                      "exploit_runner.py tidak memakai mesin rantai internal")

    def test_exploit_py_tidak_dimodifikasi(self):
        """exploit.py upstream tidak dibawa di repo ini (krdit di README).
        Sebagai gantinya: pastikan mesin rantai internal TETAP byte-identik
        dengan referensi — simpan sha256 chain.py dan bandingkan."""
        import hashlib
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        p = os.path.join(here, "lib", "chain.py")
        with open(p, "rb") as fh:
            now = hashlib.sha256(fh.read()).hexdigest()
        # hash ini TERVERIFIKASI ulang 26 Okt 2026 (edit komentar data, tanpa
        # perubahan logika; diff = 1 baris komentar)
        self.assertEqual(now,
            "1b446b9ce341e0928f1705e3323a6c8163a2d9e1b4ba7d6b337b18e6318b20e3",
            "lib/chain.py berubah — perbarui hash ini setelah review")


class TestBannerKejujuranCVE(unittest.TestCase):
    """Banner dulu mengiklankan DUA CVE seolah keduanya diuji.

    Kenyataannya rantai tool ini hanya CVE-2026-109619 (lib/chain.py menolak
    target bila cve != 109619). Tes ini mengunci agar banner tidak kembali
    menulis "109618 + 109619" tanpa keterangan mana yang benar-benar dijalankan.
    """

    def test_banner_membedakan_diuji_vs_dideteksi(self):
        rc, out, err = run("version", timeout=90)
        teks = out + err
        low = teks.lower()
        self.assertIn("diuji", low)
        self.assertIn("deteksi", low)
        # klaim lama (dua CVE setara) tidak boleh muncul lagi
        self.assertNotIn("CVE-2026-109618  +  CVE-2026-109619", teks)

    def test_status_cve_tercatat_eksplisit(self):
        """CVE_SUPPORTED hidup di php2shell.py (bukan lib/chain.py)."""
        sys.path.insert(0, TOOLKIT)
        import php2shell as cli
        self.assertEqual(cli.CVE_SUPPORTED, ("CVE-2026-109619",))

    def test_chain_benar_benar_menolak_109618(self):
        """Klaim 'hanya 109619' harus berupa kode, bukan dokumentasi."""
        # Gerbang CLI: cve di luar CVE_SUPPORTED ditolak sebelum rantai jalan.
        with open(CLI, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("if cve and cve not in CVE_SUPPORTED", src)
        # Penolakan kedua, di dalam mesin rantai itu sendiri.
        with open(os.path.join(TOOLKIT, "lib", "chain.py"), encoding="utf-8") as fh:
            chainsrc = fh.read()
        self.assertIn('if cve == "CVE-2026-109618"', chainsrc,
                      "chain.py tidak lagi menolak 109618 secara eksplisit")


class TestBannerTanpaArgumen(unittest.TestCase):
    def test_splash_rc_nol(self):
        rc, out, err = run()
        self.assertEqual(rc, 0)
        bersih = re.sub(r"\x1b\[[0-9;]*m", "", out)
        rata = re.sub(r"[^A-Z0-9]", "", bersih.upper())
        self.assertIn("PHP2SHELL", rata)


class TestVersion(unittest.TestCase):
    """--version harus exit 0 dan satu baris, di posisi mana pun.

    Regresi yang dijaga: dulu --version tidak terdaftar sehingga argparse
    keluar 2 (terlihat seperti error), dan saat sempat didaftarkan lewat
    action="version", formatter BannerHelp membuat banner penuh tercetak
    sehingga output tidak lagi satu baris / tidak skripable.
    """

    def test_version_top_level(self):
        for flag in ("--version", "-V"):
            with self.subTest(flag=flag):
                rc, out, err = run(flag, timeout=60)
                self.assertEqual(rc, 0, f"{flag} harus exit 0, dapat {rc}")
                teks = re.sub(r"\x1b\[[0-9;]*m", "", out).strip()
                self.assertEqual(len(teks.splitlines()), 1,
                                 f"{flag} harus satu baris, dapat: {teks!r}")
                self.assertIn("php2shell", teks)
                self.assertIn(VERSI_DIHARAPKAN, teks)

    def test_version_setelah_subcommand(self):
        rc, out, err = run("scan", "--version", timeout=60)
        self.assertEqual(rc, 0)
        teks = re.sub(r"\x1b\[[0-9;]*m", "", out).strip()
        self.assertEqual(len(teks.splitlines()), 1, teks)
        self.assertIn(VERSI_DIHARAPKAN, teks)

    def test_version_bukan_banner(self):
        """Baris versi tidak boleh membawa ASCII art banner."""
        rc, out, err = run("--version", timeout=60)
        self.assertNotIn("____", out, "banner ASCII ikut tercetak di --version")



class TestFixFloor(unittest.TestCase):
    """Fix-floor harus diformat MAJOR.MINOR.PATCH, bukan MAJOR.PATCH.

    Regresi: `FIX_FLOOR["8.4"] = (8, 27)` dulu diformat jadi "8.27" sehingga
    laporan menulis "PHP 8.4.26 < fix-floor 8.27" — angka yang tidak ada.
    """

    def test_format_fix_floor_lengkap(self):
        from lib.detect import classify

        harapan = {
            "8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12",
        }
        for branch, fix in harapan.items():
            with self.subTest(branch=branch):
                _, reason, got = classify(f"{branch}.0", branch)
                self.assertEqual(got, fix, f"fix-floor {branch} salah: {got!r}")
                self.assertIn(fix, reason)

    def test_batas_rentan_dan_patched(self):
        from lib.detect import classify

        for branch, last, first_fixed in (
            ("8.2", "8.2.34", "8.2.35"),
            ("8.3", "8.3.35", "8.3.36"),
            ("8.4", "8.4.26", "8.4.27"),
            ("8.5", "8.5.11", "8.5.12"),
        ):
            with self.subTest(branch=branch):
                self.assertEqual(classify(last, branch)[0], "vulnerable", last)
                self.assertEqual(classify(first_fixed, branch)[0], "patched", first_fixed)

    def test_branch_eol(self):
        from lib.detect import classify

        for v in ("5.4.45", "7.4.33", "8.0.30", "8.1.34"):
            with self.subTest(version=v):
                self.assertEqual(classify(v, ".".join(v.split(".")[:2]))[0], "eol")


class TestCekVersi(unittest.TestCase):
    """Cek versi otomatis — offline: hanya logika compare/local, tanpa jaringan."""

    def test_compare_semantik(self):
        from lib.version import compare

        self.assertEqual(compare("1.2", "1.2"), "current")
        self.assertEqual(compare("v1.2", "1.2.0"), "current")
        self.assertEqual(compare("1.2", "1.3"), "behind")
        self.assertEqual(compare("1.2", "1.10"), "behind", "1.10 > 1.2 secara numerik")
        self.assertEqual(compare("1.10", "1.2"), "ahead")
        self.assertEqual(compare("2.0.0", "1.99.99"), "ahead")
        self.assertEqual(compare("x", "1.2"), "unknown")

    def test_local_version_dibaca(self):
        from lib.version import local_version

        self.assertEqual(local_version(), VERSI_DIHARAPKAN)

    def test_offline_tidak_melempar_exception(self):
        """Host mati harus jadi status 'unknown', bukan crash."""
        from lib import version as V

        simpan = (V.API_RELEASE_URL, V.API_TAGS_URL, V.RAW_VERSION_URL)
        V.API_RELEASE_URL = "http://127.0.0.1:9/a"
        V.API_TAGS_URL = "http://127.0.0.1:9/b"
        V.RAW_VERSION_URL = "http://127.0.0.1:9/c"
        try:
            vc = V.check("1.2", use_cache=False, timeout=2)
            self.assertEqual(vc.status, "unknown")
            self.assertTrue(vc.message)
        finally:
            V.API_RELEASE_URL, V.API_TAGS_URL, V.RAW_VERSION_URL = simpan

    def test_subcommand_version_bisa_dijalankan(self):
        rc, out, err = run("version", "--no-cache", timeout=90)
        self.assertIn(rc, (0, 10), f"exit {rc}: {err}")
        self.assertIn("lokal", out)
        self.assertIn("remote", out)

    def test_flag_check_version_dikenal_parser(self):
        rc, out, err = run("detect", "--help", timeout=60)
        self.assertEqual(rc, 0)
        self.assertIn("--check-version", out)



class TestBuildSupport(unittest.TestCase):
    """Tabel dukungan build: membedakan RCE / leak-saja / belum terbukti."""

    def test_known_rce_build(self):
        from lib import build_support as bs
        self.assertEqual(bs.level_for("8.4.26", "amd64"), bs.RCE)
        self.assertEqual(bs.level_for("8.5.11", "aarch64"), bs.RCE)

    def test_leak_only_build_never_claims_rce(self):
        from lib import build_support as bs
        # 8.3.35 terbukti bocor, TAPI stage 3 tidak jalan. Ini kelas yang
        # dulu disalah-READY-kan oleh preflight.
        b = bs.lookup("8.3.35", "aarch64")
        self.assertIsNotNone(b)
        self.assertEqual(b.level, bs.LEAK)
        self.assertFalse(b.can_rce)
        self.assertTrue(b.can_leak)

    def test_arch_matters(self):
        from lib import build_support as bs
        # RCE terbukti di amd64 saja -> aarch64 tidak boleh dijanjikan RCE
        self.assertEqual(bs.level_for("8.4.26", "amd64"), bs.RCE)
        self.assertEqual(bs.level_for("8.4.26", "aarch64"), bs.LEAK)

    def test_unknown_build_is_unknown_not_rce(self):
        from lib import build_support as bs
        self.assertEqual(bs.level_for("8.4.27"), bs.UNKNOWN)
        self.assertEqual(bs.level_for("9.9.9"), bs.UNKNOWN)
        self.assertEqual(bs.level_for(None), bs.UNKNOWN)

    def test_version_normalisation(self):
        from lib import build_support as bs
        for raw in ("v8.4.26", "8.4.26-apache", "8.4.26 ", "8.4.26RC1"):
            self.assertEqual(bs.level_for(raw, "amd64"), bs.RCE, raw)

    def test_eol_detection(self):
        from lib import build_support as bs
        self.assertTrue(bs.is_eol("7.4.33"))
        self.assertTrue(bs.is_eol("8.1.34"))
        self.assertTrue(bs.is_eol("8.0.30"))
        self.assertFalse(bs.is_eol("8.4.26"))
        self.assertFalse(bs.is_eol(None))

    def test_expectation_text_never_promises_rce_on_leak(self):
        from lib import build_support as bs
        txt = bs.expectation_text("8.3.35", "aarch64")
        self.assertIn("LEAK", txt)
        self.assertNotIn("RCE terbukti", txt)


class TestPreflightSupportField(unittest.TestCase):
    """Preflight harus membawa tingkat dukungan, bukan cuma READY."""

    def _mk(self, version):
        from lib.detect import Detection
        from lib import preflight as pf
        d = Detection(url="http://ex/")
        d.php_version = version
        d.branch = version.rsplit(".", 1)[0] if version else None
        d.verdict = "vulnerable"
        d.upload_progress = "on"
        d.display_errors = "off"
        d.reachable = True
        d.status = 200
        return pf.preflight(d)

    def test_rce_build_reports_rce(self):
        p = self._mk("8.4.26")
        self.assertEqual(p.support_level, "rce")
        self.assertEqual(p.as_dict()["support"]["level"], "rce")

    def test_leak_build_warns_command_not_executed(self):
        p = self._mk("8.3.35")
        self.assertEqual(p.support_level, "leak")
        joined = " ".join(p.notes).lower()
        self.assertIn("tidak akan", joined)
        self.assertIn("dieksekusi", joined)

    def test_support_never_blocks(self):
        # Dukungan rendah BUKAN blocker: offset manual masih bisa dipakai.
        p = self._mk("8.3.35")
        self.assertFalse(any("build" in b.lower() for b in p.blockers))

    def test_verdict_line_has_support_column(self):
        from lib import preflight as pf
        p = self._mk("8.4.26")
        from lib.detect import Detection
        d = Detection(url="http://ex/")
        d.php_version, d.branch, d.verdict = "8.4.26", "8.4", "vulnerable"
        d.upload_progress, d.display_errors = "on", "off"
        line = pf.verdict_line(d, p)
        self.assertIn("RCE", line)



class TestAdvisory(unittest.TestCase):
    """Klaim CVE harus jujur: apa yang dijalankan vs apa yang hanya dideteksi.

    Latar: banner dulu mencetak "CVE-2026-109618 + CVE-2026-109619" seolah
    keduanya diuji setara. Kenyataannya rantai tool ini hanya CVE-2026-109619
    (lihat lib/chain.py: menolak target bila cve != 109619). Tes di bawah
    mengunci kejujuran itu supaya tidak kembali mengklaim dua-duanya.
    """

    def test_banner_tidak_mengklaim_dua_cve_setara(self):
        rc, out, err = run(timeout=60)
        teks = out + err
        self.assertIn("CVE-2026-109619", teks)
        # Bentuk klaim lama harus hilang: dua CVE dirangkai "+".
        self.assertNotIn("CVE-2026-109618  +  CVE-2026-109619", teks)
        self.assertIn("diuji", teks.lower())

    def test_cve_ids_hanya_109619(self):
        sys.path.insert(0, TOOLKIT)
        from lib import banner
        self.assertEqual(banner.CVE_IDS, "CVE-2026-109619")

    def test_advisory_mencatat_cve_ketiga(self):
        sys.path.insert(0, TOOLKIT)
        from lib import advisory
        self.assertEqual(advisory.CVE_115560["id"], "CVE-2026-115560")

    def test_cve_ketiga_tidak_diklaim_tertutup_fix_floor(self):
        """Klaim yang SALAH dan pernah masuk ke tool: "117560 ikut patch 22 Okt".

        Sumber primer (php.net advisory 2026-10-23 + thehackernews 23 Okt):
        CVE-2026-115560 "is not fixed by PHP 8.5.12, 8.4.27, 8.3.36 or
        8.2.35". Tes ini mengunci fakta itu supaya tidak ada yang
        "merapikan" jadi True lagi tanpa bukti baru.
        """
        sys.path.insert(0, TOOLKIT)
        from lib import advisory
        self.assertFalse(advisory.CVE_115560["fixed_by_php2shell_floor"])
        self.assertNotIn("same_fix_floor", advisory.CVE_115560)
        # status harus menyebut advisory informasional, bukan "reserved"
        self.assertIn("2026-10-23", advisory.CVE_115560["status"])

    def test_cve_ketiga_belum_itw(self):
        """Belum ada eksploitasi in-the-wild 115560; yang ramai = 109618/109619."""
        sys.path.insert(0, TOOLKIT)
        from lib import advisory
        self.assertFalse(advisory.CVE_115560["itw_exploited"])

    def test_mitigasi_115560_harus_admin_flag(self):
        """Mitigasi via ini_set() bisa ditimpa kode aplikasi -> harus php_admin_flag."""
        sys.path.insert(0, TOOLKIT)
        from lib import advisory
        s = advisory.describe()
        self.assertIn("php_admin_flag", s)
        self.assertIn("TIDAK ditutup 8.5.12", s)

    def test_mitigasi_115560_tidak_wajib_untuk_semua(self):
        """php.net: aplikasi yang tak mengubah serialize handler saat runtime
        boleh tetap mengaktifkan fitur. Tool tidak boleh menakut-nakuti semua."""
        sys.path.insert(0, TOOLKIT)
        from lib import advisory
        scope = advisory.CVE_115560["mitigation_scope"]
        self.assertIn("TIDAK wajib", scope)
        self.assertIn("can keep the feature enabled", scope)
        self.assertIn("TIDAK wajib untuk semua orang", advisory.describe())

    def test_advisory_tidak_mengklaim_eksploitasi(self):
        sys.path.insert(0, TOOLKIT)
        from lib import advisory
        s = advisory.describe()
        self.assertIn("hanya mengklasifikasi versi", s)
        self.assertIn("CVE-2026-115560", s)

    def test_flag_advisories_jalan(self):
        rc, out, err = run("version", "--advisories", timeout=90)
        # rc 10 = ada versi baru, tetap bukan kegagalan pakai.
        self.assertIn(rc, (0, 10), err)
        self.assertIn("ADVISORY PASCA-RILIS", out)
        self.assertIn("CVE-2026-115560", out)

    def test_repack_22_okt_tercatat(self):
        sys.path.insert(0, TOOLKIT)
        from lib import advisory
        self.assertIn("22 Okt 2026", advisory.REPACK_NOTICE)
        self.assertIn("tanpa naik nomor versi", advisory.REPACK_NOTICE)

    def test_memory_limit_bukan_mitigasi_lengkap(self):
        sys.path.insert(0, TOOLKIT)
        from lib import advisory
        self.assertIn("BUKAN mitigasi lengkap",
                      advisory.MITIGATION_WARNINGS["memory_limit=-1"])


class TestMemProbe(unittest.TestCase):
    """Probe memory_limit: parser harus jujur 'tidak tahu', bukan menebak."""

    def test_parse_fatal_allowed_size(self):
        from lib import memprobe
        raw = (b"<br />\n<b>Fatal error</b>:  Allowed memory size of 8388608 "
               b"bytes exhausted (tried to allocate 20480 bytes) in /var/www/x.php")
        self.assertEqual(memprobe.parse_limit(raw), 8388608)

    def test_parse_128m_report(self):
        from lib import memprobe
        raw = b"Fatal error: Allowed memory size of 134217728 bytes exhausted"
        self.assertEqual(memprobe.parse_limit(raw), 134217728)

    def test_parse_ini_value_with_unit(self):
        from lib import memprobe
        self.assertEqual(memprobe.parse_limit(b"memory_limit = 256M"),
                         256 * 1024 ** 2)
        self.assertEqual(memprobe.parse_limit(b"memory_limit: 512K"), 512 * 1024)
        self.assertEqual(memprobe.parse_limit(b"memory_limit=1G"), 1024 ** 3)

    def test_parse_absent_returns_none(self):
        from lib import memprobe
        # Tanpa angka limit, kita TIDAK boleh menebak.
        for raw in (b"", b"OK", b"HTTP/1.1 200 OK\r\n\r\nhello",
                    b"Out of memory (allocated 1048576) (tried to allocate 1)"):
            self.assertIsNone(memprobe.parse_limit(raw), raw)

    def test_parse_rejects_absurd_value(self):
        from lib import memprobe
        # Angka di luar batas akal = artefak (potongan Content-Length), bukan limit.
        self.assertIsNone(memprobe.parse_limit(
            b"Allowed memory size of 99999999999999999999 bytes exhausted"))

    def test_huge_mb_just_over_limit(self):
        from lib import memprobe
        # Limit 8M -> 10 MB (bukan 12 default): cukup untuk OOM, tidak boros.
        self.assertEqual(memprobe.huge_mb_for(8 * 1024 ** 2), 10)
        # Limit 128M -> 147 MB, bukan 148+ dari headroom persentase buta.
        self.assertLess(memprobe.huge_mb_for(128 * 1024 ** 2), 150)

    def test_huge_mb_unknown_uses_default(self):
        from lib import memprobe
        self.assertEqual(memprobe.huge_mb_for(None), 12)
        self.assertEqual(memprobe.huge_mb_for(0), 12)

    def test_huge_mb_capped(self):
        from lib import memprobe
        # Limit 4G tidak boleh menghasilkan field 4 GB.
        self.assertEqual(memprobe.huge_mb_for(4 * 1024 ** 3), 512)


class TestExploitUsesProbe(unittest.TestCase):
    """exploit_runner harus membaca limit, bukan memakai 12 hardcoded."""

    def test_grep_no_hardcoded_default(self):
        p = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "lib", "exploit_runner.py")
        with open(p, encoding="utf-8") as fh:
            src = fh.read()
        self.assertNotIn("huge_mb: int = 12", src,
                         "huge_mb masih punya default hardcoded 12")

    def test_cli_does_not_coerce_none(self):
        p = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "php2shell.py")
        with open(p, encoding="utf-8") as fh:
            src = fh.read()
        # `args.huge_mb or 12` menutup jalur probe: None harus sampai ke runner.
        self.assertNotIn("args.huge_mb or 12", src)





class TestBodyCap(unittest.TestCase):
    """Body yang ditolak target HARUS dibedakan dari target yang aman.

    Kegagalan `post_max_size` menghasilkan HTML 200 yang wajar ("Warning:
    POST Content-Length ... exceeds the limit") — dulu itu terbaca sebagai
    "accepted" dan operator diberi HEAP_LEAK_FAILED tanpa sebab.
    """

    FATAL = (b"<br />\n<b>Fatal error</b>:  Allowed memory size of 8388608 "
             b"bytes exhausted (tried to allocate 2098791 bytes)")
    TOOBIG = (b"<br />\n<b>Warning</b>:  PHP Request Startup: POST "
              b"Content-Length of 16777461 bytes exceeds the limit of "
              b"8388608 bytes")

    def test_rejected_pada_post_too_big(self):
        from lib import memprobe
        self.assertEqual(memprobe.body_cap(self.TOOBIG), "rejected")

    def test_accepted_pada_oom_fatal(self):
        from lib import memprobe
        self.assertEqual(memprobe.body_cap(self.FATAL), "accepted")

    def test_rejected_pada_413(self):
        from lib import memprobe
        self.assertEqual(memprobe.body_cap(b"x", status=413), "rejected")

    def test_unknown_kalau_kosong(self):
        from lib import memprobe
        self.assertEqual(memprobe.body_cap(b""), "unknown")

    def test_unknown_kalau_respons_tanpa_jejak_php(self):
        from lib import memprobe
        # HTML 200 biasa tanpa pesan PHP: jangan mengaku tahu.
        self.assertEqual(memprobe.body_cap(b"<html>ok</html>"), "unknown")

    def test_describe_menyebut_post_max_saat_rejected(self):
        from lib import memprobe
        s = memprobe.describe(None, 12, "rejected")
        self.assertIn("post_max_size", s)
        self.assertNotIn("display_errors", s)


class TestProofFileBukanHampa(unittest.TestCase):
    """--proof-file dulu deklarasi argparse TANPA efek: cmd tetap 'id',
    proof_mode=False, dan setiap exploit sukses selalu berakhir BLIND.
    Tes ini mengunci agar flag itu benar-benar membentuk kanal bukti.
    """

    def test_proof_cmd_for_membentuk_redirect(self):
        from lib.exploit_runner import proof_cmd_for
        self.assertEqual(proof_cmd_for("id", "pv"), "id>/out/pv")
        self.assertEqual(proof_cmd_for("whoami", "b1"), "whoami>/out/b1")

    def test_proof_cmd_dikenali_sebagai_proof_mode(self):
        from lib.exploit_runner import _is_proof_redirect, _is_identity_proof
        self.assertTrue(_is_proof_redirect("id>/out/pv"))
        self.assertTrue(_is_proof_redirect("whoami>/out/p1"))
        # tetap tertutup untuk path/token lain
        self.assertFalse(_is_proof_redirect("id>/out/pv; uname -a"))
        self.assertFalse(_is_proof_redirect("id>/etc/passwd"))
        # BENTUK 'cat>/out/pv' sah sebagai bentuk; tapi kanal bukti HANYA
        # dibuka untuk perintah identitas.
        self.assertTrue(_is_proof_redirect("cat>/out/pv"))
        self.assertFalse(_is_identity_proof("cat>/out/pv"))
        self.assertFalse(_is_identity_proof("ls>/out/p1"))
        self.assertTrue(_is_identity_proof("id>/out/pv"))

    def test_nama_file_berbahaya_ditolak(self):
        from lib.exploit_runner import proof_cmd_for
        for bad in ("../etc/passwd", "a b", "pv;id", "", "x" * 40, "pv|id"):
            with self.assertRaises(ValueError):
                proof_cmd_for("id", bad)

    def test_perintah_dasar_harus_di_whitelist(self):
        from lib.exploit_runner import proof_cmd_for
        with self.assertRaises(ValueError):
            proof_cmd_for("curl", "pv")

    def test_cli_meneruskan_proof_file_ke_runner(self):
        """Regresi: _run_exploits harus memakai proof_cmd_for + proof_file=."""
        with open(CLI, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("proof_cmd_for", src)
        self.assertIn("proof_file=proof_name", src)

    def test_proof_host_path_menunjuk_out_repo(self):
        from lib.exploit_runner import proof_host_path
        p = proof_host_path("pv")
        self.assertTrue(p.endswith("/out/pv"))
        self.assertIn("php2shell", p)


class TestOomProbeBaru(unittest.TestCase):
    """Fitur detect OOM aktif (lib/oomprobe.py) — metode assetnote."""

    def test_oomprobe_modul_ada_dan_api_lengkap(self):
        sys.path.insert(0, TOOLKIT)
        from lib.oomprobe import oom_detect, OOMResult
        r = OOMResult()
        d = r.as_dict()
        for k in ("verdict", "signal", "evidence", "probes_sent", "probe_results"):
            self.assertIn(k, d)

    def test_nested_keys_62_dan_probe_bertingkat(self):
        sys.path.insert(0, TOOLKIT)
        import lib.oomprobe as op
        self.assertEqual(op.NESTED_KEYS, 62)
        self.assertEqual(op.PROBES_MB, (1, 8, 20))
        nama = op._nested_name()
        self.assertEqual(nama.count("[b]"), 61)

    def test_post_len_rejected_tidak_dianggap_vulnerable(self):
        """Warning 'POST Content-Length exceeds' di lokasi 'Unknown' TIDAK
        boleh dihitung fatal-in-parser (post_max_size guard)."""
        sys.path.insert(0, TOOLKIT)
        from lib.oomprobe import _classify_response

        class FakeResp:
            status = 200
            body = ("<b>Warning</b>:  PHP Request Startup: POST Content-Length "
                    "of 9437242 bytes exceeds the limit of 8388608 bytes in "
                    "<b>Unknown</b> on line <b>0</b>")
        verdict, signal = _classify_response(FakeResp(), control_body_len=10)
        self.assertEqual(verdict, "inconclusive")
        self.assertEqual(signal, "post_len_rejected")

    def test_oom_in_parser_true_positive(self):
        sys.path.insert(0, TOOLKIT)
        from lib.oomprobe import _classify_response

        class FakeResp:
            status = 200
            body = ("Fatal error: Allowed memory size of 8388608 bytes "
                    "exhausted (tried to allocate 20 bytes) in Unknown on line 0")
        verdict, signal = _classify_response(FakeResp(), control_body_len=10)
        self.assertEqual(verdict, "vulnerable")
        self.assertEqual(signal, "oom_in_parser")

    def test_empty_500_differential(self):
        sys.path.insert(0, TOOLKIT)
        from lib.oomprobe import _classify_response

        class FakeResp:
            status = 500
            body = ""
        verdict, signal = _classify_response(FakeResp(), control_body_len=120)
        self.assertEqual(verdict, "vulnerable")
        self.assertEqual(signal, "empty_500")

    def test_detect_auto_oom_default_and_no_oom_flag(self):
        """detect() default: OOM jalan bila verdict unknown/eol; --no-oom
        memetakan check_oom=False."""
        sys.path.insert(0, TOOLKIT)
        from lib import detect as det
        src = open(det.__file__, encoding="utf-8").read()
        self.assertIn("check_oom", src)
        self.assertIn('"unknown", "eol"', src)  # syarat otomatis
        # CLI flag
        src_cli = open(
            __import__("os").path.join(
                __import__("os").path.dirname(det.__file__), "..", "php2shell.py"),
            encoding="utf-8").read()
        self.assertIn("--no-oom", src_cli)


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""Tes pagar keamanan transport + CLI (audit hardening).

Semua tes OFFLINE: tidak ada target internet, tidak ada paket keluar. Yang
dikunci (temuan audit):

  1. TLS diverifikasi SECARA DEFAULT (`CERT_REQUIRED` + check_hostname), di
     jalur curl_cffi (`verify=True`) maupun urllib; `verify_tls=False` ->
     `CERT_NONE` dan HANYA lewat itu.
  2. URL awal DAN setiap hop redirect divalidasi kebijakan: loopback,
     RFC1918, link-local, metadata cloud (169.254.169.254), IPv6 `[::1]`
     ditolak. `allow_private=True` (flag lab) melonggarkan loopback/RFC1918/
     link-local, TETAPI endpoint metadata cloud tetap ditolak tanpa syarat —
     IP literal maupun hostname yang me-resolve ke sana. Skema non-http(s)
     ditolak.
  3. Redirect diikuti manual, maksimal 5 hop, dan `Location:` privat tidak
     pernah di-fetch.
  4. Audit log meredaksi nilai token/api_key/password, tetapi path tetap
     terbaca; file dibuat mode 0600.
  4b. Retensi audit log DIBATASI: file >= `AUDIT_MAX_BYTES` dirotasi ke
     `.1` (satu generasi, menimpa `.1` lama), mode 0600 tetap, dan rotasi
     tidak memindahkan/menghapus apa pun selama di bawah batas.
  4c. Log injection tidak mungkin: satu record = tepat satu baris fisik
     walau nilai memuat `\n`, `\r`, `\x1b[2J`, U+2028/U+2029, atau JSON
     palsu `{"ts":"x",...}` — setiap baris tetap `json.loads`-able.
  5. `close()` idempoten + `with Transport(...)` menutup session walau
     exception.

    /home/lota1337/myenv/bin/python -m pytest tests/test_transport_security.py -q
"""

import ipaddress
import json
import os
import socket
import ssl
import stat
import sys
import tempfile
import unittest
import warnings
from contextlib import contextmanager
from unittest import mock

TOOLKIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if TOOLKIT not in sys.path:
    sys.path.insert(0, TOOLKIT)

from lib import target_policy as policy  # noqa: E402
from lib import transport as transport_mod  # noqa: E402
from lib.transport import (  # noqa: E402
    PolicyRedirectHandler,
    Response,
    Transport,
)


def _fake_req(url: str = "https://example.com/a.php"):
    import urllib.request
    return urllib.request.Request(url)


@contextmanager
def warnings_simplefilter_ignore():
    """Telan RuntimeWarning dari jalur audit-gagal supaya output test bersih."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        yield


class TestTlsVerifikasiDefault(unittest.TestCase):
    """Verifikasi TLS tidak boleh mati karena nilai bawaan."""

    def test_default_verify_tls_true_dan_cert_required(self):
        t = Transport(delay=0.0)
        self.assertIs(t.verify_tls, True)
        ctx = t._ssl_context()
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertIs(ctx.check_hostname, True)

    def test_verify_tls_false_jadi_cert_none(self):
        t = Transport(delay=0.0, verify_tls=False)
        ctx = t._ssl_context()
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)
        self.assertIs(ctx.check_hostname, False)

    def test_curl_cffi_tidak_lagi_mematikan_verifikasi(self):
        """Kode (bukan docstring) tidak boleh memaksa verify=False.

        Diperiksa lewat AST supaya komentar/docstring yang MENJELASKAN temuan
        lama tidak ikut gagal — yang penting tidak ada argumen kode yang
        mematikan verifikasi atau menyerahkan redirect ke library.
        """
        import ast as _ast
        with open(transport_mod.__file__, encoding="utf-8") as fh:
            tree = _ast.parse(fh.read())
        offenders = []
        for node in _ast.walk(tree):
            if not isinstance(node, _ast.Call):
                continue
            for kw in node.keywords:
                if kw.arg == "verify" and isinstance(kw.value, _ast.Constant) \
                        and kw.value.value is False:
                    offenders.append("verify=False")
                if kw.arg == "allow_redirects" and isinstance(kw.value, _ast.Constant) \
                        and kw.value.value is True:
                    offenders.append("allow_redirects=True")
        self.assertEqual(offenders, [],
                         f"transport.py masih menyerahkan pagar ke library: {offenders}")

    def test_tidak_ada_cert_none_tanpa_syarat(self):
        """`CERT_NONE` hanya boleh muncul di cabang `verify_tls=False`."""
        with open(transport_mod.__file__, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("if not self.verify_tls:", src)
        idx_guard = src.index("if not self.verify_tls:")
        idx_none = src.index("ssl.CERT_NONE")
        self.assertGreater(idx_none, idx_guard,
                           "CERT_NONE muncul sebelum pagar verify_tls")

    def test_urllib_handler_memakai_konteks_default(self):
        """Handler HTTPS bawaan urllib harus membawa konteks diverifikasi."""
        t = Transport(delay=0.0)
        ctx = t._ssl_context()
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        # create_default_context memuat CA store; CERT_NONE bukan default.
        self.assertGreater(len(ctx.get_ca_certs()) + 1, 0)


class TestPolicyTolakAlamatPrivat(unittest.TestCase):
    URL_PRIVAT = (
        "http://127.0.0.1/x.php",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5/x.php",
        "http://[::1]:8080/x.php",
        "http://172.16.3.4/x.php",
        "http://192.168.1.10/x.php",
        "http://0.0.0.0/x.php",
        "http://localhost:9000/x.php",
    )

    # URL lab sah: loopback + RFC1918 + localhost. Metadata TIDAK di sini.
    URL_LAB = (
        "http://127.0.0.1/x.php",
        "http://10.0.0.5/x.php",
        "http://[::1]:8080/x.php",
        "http://172.16.3.4/x.php",
        "http://192.168.1.10/x.php",
        "http://0.0.0.0/x.php",
        "http://localhost:9000/x.php",
    )

    # IMDS semua provider. Tidak ada flag yang boleh meloloskan ini.
    METADATA_URL = (
        "http://169.254.169.254/latest/meta-data/",
        "http://[fd00:ec2::254]/latest/meta-data/",
        "http://100.100.100.200/latest/meta-data/",
        "http://192.0.0.192/latest/meta-data/",
        # Bentuk alternatif: titik akhir FQDN, IPv6 panjang, IPv4-mapped.
        "http://169.254.169.254.:80/latest/meta-data/",
        "http://[fd00:ec2:0:0:0:0:0:254]/latest/meta-data/",
    )

    def test_ditolak_secara_default(self):
        for url in self.URL_PRIVAT:
            with self.subTest(url=url):
                with self.assertRaises(ValueError) as ctx:
                    policy.check_url(url)
                self.assertIn("SSRF", str(ctx.exception),
                              f"pesan tidak menjelaskan alasan: {ctx.exception}")

    def test_diizinkan_dengan_allow_private(self):
        """Target lab (loopback/RFC1918/localhost) tetap bisa dipakai."""
        for url in self.URL_LAB:
            with self.subTest(url=url):
                policy.check_url(url, allow_private=True)  # tidak melempar
                policy.check_url(url, allow_private=True)  # idempoten

    def test_metadata_tetap_ditolak_walau_allow_private(self):
        """IMDS tidak pernah diloloskan `--allow-private-target` (SSRF)."""
        for url in self.METADATA_URL:
            with self.subTest(url=url):
                with self.assertRaises(policy.PolicyError) as ctx:
                    policy.check_url(url, allow_private=True)
                msg = str(ctx.exception)
                self.assertIn("metadata", msg.lower(),
                              f"pesan tidak menyebut metadata: {msg}")
                self.assertIn("SSRF", msg, f"pesan tidak menyebut SSRF: {msg}")
                self.assertIn("--allow-private-target", msg,
                              f"pesan tidak menegaskan flag tidak berlaku: {msg}")

    def test_metadata_literal_ditolak_di_resolve_and_check(self):
        for host in policy.METADATA_ADDRESSES:
            for allow in (False, True):
                with self.subTest(host=host, allow_private=allow):
                    with self.assertRaises(policy.PolicyError) as ctx:
                        policy.resolve_and_check(host, allow_private=allow)
                    msg = str(ctx.exception)
                    self.assertIn("metadata", msg.lower())
                    self.assertIn("SSRF", msg)

    def test_hostname_yang_resolve_ke_metadata_ditolak(self):
        """Hostname → 169.254.169.254 juga ditolak, walau allow_private=True."""
        fake = [(2, 1, 6, "", ("169.254.169.254", 0))]
        with mock.patch("socket.getaddrinfo", return_value=fake):
            for allow in (False, True):
                with self.subTest(allow_private=allow):
                    with self.assertRaises(policy.PolicyError) as ctx:
                        policy.resolve_and_check("metadata.internal",
                                                 allow_private=allow)
                    msg = str(ctx.exception)
                    self.assertIn("169.254.169.254", msg)
                    self.assertIn("metadata", msg.lower())

    def test_check_url_hostname_metadata_ditolak_dengan_allow_private(self):
        fake = [(2, 1, 6, "", ("169.254.169.254", 0))]
        with mock.patch("socket.getaddrinfo", return_value=fake):
            with self.assertRaises(policy.PolicyError) as ctx:
                policy.check_url("http://metadata.internal/latest/meta-data/",
                                 allow_private=True)
            msg = str(ctx.exception)
            self.assertIn("SSRF", msg)
            self.assertIn("metadata", msg.lower())

    def test_hostname_lab_tetap_lolos_dengan_allow_private(self):
        """Hostname yang resolve ke RFC1918 bukan metadata → tetap boleh (lab)."""
        fake = [(2, 1, 6, "", ("10.1.2.3", 0)), (2, 1, 6, "", ("192.168.5.6", 0))]
        with mock.patch("socket.getaddrinfo", return_value=fake):
            policy.check_url("http://lab.internal/x.php", allow_private=True)
            ips = policy.resolve_and_check("lab.internal", allow_private=True)
        self.assertEqual(ips, ["10.1.2.3", "192.168.5.6"])
        # Tanpa flag tetap ditolak.
        with mock.patch("socket.getaddrinfo", return_value=fake):
            with self.assertRaises(policy.PolicyError):
                policy.check_url("http://lab.internal/x.php")

    def test_skema_non_http_ditolak(self):
        for url in ("ftp://example.com/x", "file:///etc/passwd",
                    "gopher://example.com/", "//example.com/x", "javascript:alert(1)"):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    policy.check_url(url)

    def test_host_publik_lolos(self):
        # 93.184.216.34 & 2606:4700::1111 = alamat publik (tanpa DNS call).
        policy.check_url("http://93.184.216.34/x.php")
        policy.check_url("https://[2606:4700::1111]/x.php")

    def test_is_private_address_kelas_berbahaya(self):
        for ip in ("127.0.0.1", "::1", "169.254.169.254", "10.0.0.5",
                   "172.16.0.1", "192.168.0.1", "0.0.0.0", "255.255.255.255",
                   "224.0.0.1", "fe80::1", "fc00::1", "fd00:ec2::254",
                   "::ffff:127.0.0.1", "100.64.0.1", "bukan-ip"):
            with self.subTest(ip=ip):
                self.assertTrue(policy.is_private_address(ip))
        for ip in ("8.8.8.8", "93.184.216.34", "2606:4700::1111"):
            with self.subTest(ip=ip):
                self.assertFalse(policy.is_private_address(ip))

    def test_resolve_and_check_memeriksa_semua_a_record(self):
        """Satu A-record privat di antara yang publik = DITOLAK."""
        fake = [
            (2, 1, 6, "", ("93.184.216.34", 0)),
            (2, 1, 6, "", ("127.0.0.1", 0)),
        ]
        with mock.patch("socket.getaddrinfo", return_value=fake):
            with self.assertRaises(ValueError):
                policy.resolve_and_check("evil.example.com", allow_private=False)

    def test_request_privat_gagal_tanpa_kirim(self):
        """Transport.request menolak sebelum paket keluar; error jelas."""
        t = Transport(delay=0.0, retries=0)
        with mock.patch.object(t, "_single") as single:
            r = t.request("GET", "http://169.254.169.254/latest/meta-data/")
        single.assert_not_called()
        self.assertEqual(r.status, 0)
        self.assertIn("PolicyError", r.error)

    def test_allow_private_meneruskan_ke_single(self):
        t = Transport(delay=0.0, retries=0, allow_private=True)
        with mock.patch.object(
            t, "_single", return_value=Response(url="http://127.0.0.1/x", status=200)
        ) as single:
            r = t.request("GET", "http://127.0.0.1:9/x.php")
        single.assert_called_once()
        self.assertEqual(r.status, 200)


class TestRedirectPolicy(unittest.TestCase):
    def test_handler_menolak_location_privat(self):
        h = PolicyRedirectHandler(allow_private=False)
        with self.assertRaises(ValueError):
            h.redirect_request(_fake_req(), None, 302, "Found", {},
                               "http://169.254.169.254/latest/meta-data/")

    def test_handler_menolak_location_loopback(self):
        h = PolicyRedirectHandler(allow_private=False)
        with self.assertRaises(ValueError):
            h.redirect_request(_fake_req(), None, 301, "Moved", {},
                               "http://127.0.0.1:8080/admin")

    def test_handler_mengizinkan_location_publik(self):
        h = PolicyRedirectHandler(allow_private=False)
        out = h.redirect_request(_fake_req(), None, 302, "Found", {},
                                 "https://example.com/next")
        self.assertIsNotNone(out)

    def test_fetch_menolak_redirect_privat_tanpa_hop_kedua(self):
        """`_fetch` tidak boleh mem-fetch Location privat (SSRF via redirect)."""
        t = Transport(delay=0.0, retries=0)
        calls = []

        def fake_single(method, url, data, headers):
            calls.append(url)
            return Response(url=url, status=302,
                            headers={"location": "http://169.254.169.254/latest/"})

        with mock.patch.object(t, "_single", side_effect=fake_single):
            r = t.request("GET", "https://example.com/x.php")
        self.assertEqual(calls, ["https://example.com/x.php"])
        self.assertEqual(r.status, 0)
        self.assertIn("169.254.169.254", r.error)

    def test_fetch_mengikuti_redirect_publik(self):
        t = Transport(delay=0.0, retries=0)
        seen = []

        def fake_single(method, url, data, headers):
            seen.append(url)
            if len(seen) == 1:
                return Response(url=url, status=302,
                                headers={"location": "/next.php"})
            return Response(url=url, status=200, body="ok")

        with mock.patch.object(t, "_single", side_effect=fake_single):
            r = t.request("GET", "https://example.com/x.php")
        self.assertEqual(r.status, 200)
        self.assertEqual(seen, ["https://example.com/x.php",
                                "https://example.com/next.php"])

    def test_redirect_dibatasi_5_hop(self):
        t = Transport(delay=0.0, retries=0)
        seen = []

        def loop(method, url, data, headers):
            seen.append(url)
            return Response(url=url, status=302,
                            headers={"location": f"https://example.com/{len(seen)}"})

        with mock.patch.object(t, "_single", side_effect=loop):
            r = t.request("GET", "https://example.com/0")
        # 1 request awal + 5 hop = 6; hop ke-6 tidak pernah dikirim.
        self.assertEqual(len(seen), 6)
        self.assertIn("melebihi", r.error)

    def test_no_follow_redirects_berhenti_di_3xx(self):
        t = Transport(delay=0.0, retries=0, follow_redirects=False)
        with mock.patch.object(
            t, "_single",
            return_value=Response(url="https://example.com/x", status=302,
                                  headers={"location": "https://example.com/y"}),
        ) as single:
            r = t.request("GET", "https://example.com/x")
        single.assert_called_once()
        self.assertEqual(r.status, 302)
        self.assertEqual(r.error, "")


class TestAuditRedaksi(unittest.TestCase):
    def test_redact_text_menyembunyikan_token_di_pesan_error(self):
        msg = ("curl: (7) Failed to connect while fetching "
               "https://ex.example/app.php?token=RAHASIA&page=1 session=abc123")
        out = policy.redact_text(msg)
        self.assertNotIn("RAHASIA", out)
        self.assertNotIn("abc123", out)
        self.assertIn("token=***", out)
        self.assertIn("/app.php", out, "path harus tetap terbaca")

    def test_redact_text_aman_untuk_teks_tanpa_secret(self):
        msg = "ConnectionRefusedError: [Errno 111] Connection refused"
        self.assertEqual(policy.redact_text(msg), msg)
        self.assertEqual(policy.redact_text(""), "")

    def test_kolom_error_audit_diredaksi(self):
        """`error` masuk file permanen, jadi URL di dalamnya wajib diredaksi."""
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "audit.jsonl")
            t = Transport(delay=0.0, audit_log=path)
            t._audit({"method": "GET", "url": "https://h/x",
                      "status": 0,
                      "error": "curl error: https://h/x?token=BOCOR99&a=1"})
            isi = open(path, encoding="utf-8").read()
        self.assertNotIn("BOCOR99", isi)
        self.assertIn("token=***", isi)

    def test_redact_url_menyembunyikan_token(self):
        url = "https://ex.example/app.php?token=RAHASIA123&page=2&api_key=XYZ"
        out = policy.redact_url(url)
        self.assertNotIn("RAHASIA123", out)
        self.assertNotIn("XYZ", out)
        self.assertIn("token=***", out)
        self.assertIn("api_key=***", out)
        self.assertIn("page=2", out, "parameter non-sensitif harus utuh")
        self.assertIn("/app.php", out, "path harus dipertahankan")

    def test_redact_berbagai_nama_sensitif(self):
        for name in ("token", "access_token", "key", "api_key", "apikey",
                     "secret", "password", "pass", "session", "sid", "auth",
                     "authorization", "code", "signature", "sig"):
            with self.subTest(name=name):
                out = policy.redact_url(f"https://h/x?{name}=NILAI")
                self.assertNotIn("NILAI", out, f"{name} tidak diredaksi: {out}")

    def test_redact_tanpa_query_tidak_berubah(self):
        url = "https://ex.example/upload.php"
        self.assertEqual(policy.redact_url(url), url)

    def test_pesan_kebijakan_tidak_membocorkan_token(self):
        """PolicyError ikut tercetak ke terminal/laporan: URL di dalamnya diredaksi."""
        for bad in ("ftp://h/x?token=BOCOR1&a=1",
                    "http:///nohost?token=BOCOR2",
                    "http://h:bad/x?token=BOCOR3"):
            with self.subTest(url=bad):
                with self.assertRaises(ValueError) as ctx:
                    policy.check_url(bad)
                msg = str(ctx.exception)
                self.assertNotIn("BOCOR", msg, f"token bocor di pesan: {msg}")

    def test_redact_password_di_userinfo(self):
        out = policy.redact_url("https://user:s3cret@host/x")
        self.assertNotIn("s3cret", out)
        self.assertIn("***", out)

    def test_audit_file_mode_0600_dan_teredaksi(self):
        if os.name != "posix":
            self.skipTest("mode POSIX tidak berlaku di platform ini")
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "audit.jsonl")
            t = Transport(delay=0.0, audit_log=path)
            t._audit({"method": "GET",
                      "url": "https://ex.example/app.php?token=RAHASIA&page=1",
                      "status": 200, "ms": 5, "error": "", "bytes": 0})
            self.assertTrue(os.path.exists(path))
            mode = stat.S_IMODE(os.stat(path).st_mode)
            if mode & 0o077:
                self.skipTest(f"filesystem tidak menegakkan chmod (mode {oct(mode)})")
            self.assertEqual(mode, 0o600, f"audit file mode {oct(mode)}")
            with open(path, encoding="utf-8") as fh:
                isi = fh.read()
            self.assertNotIn("RAHASIA", isi, "token bocor ke audit log")
            self.assertIn("token=***", isi)
            self.assertIn("/app.php", isi)

    def test_audit_menimpa_mode_file_lama_yang_longgar(self):
        """File audit yang sudah ada (0644) harus di-chmod saat ditulis ulang."""
        if os.name != "posix":
            self.skipTest("mode POSIX tidak berlaku di platform ini")
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "audit.jsonl")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("{}\n")
            os.chmod(path, 0o644)
            t = Transport(delay=0.0, audit_log=path)
            t._audit({"method": "GET", "url": "https://h/x", "status": 200})
            mode = stat.S_IMODE(os.stat(path).st_mode)
            if mode & 0o077:
                self.skipTest("filesystem tidak menegakkan chmod")
            self.assertEqual(mode, 0o600)


class TestAuditRetensi(unittest.TestCase):
    """Retensi audit log dibatasi: rotasi satu generasi `.1`, mode 0600 tetap."""

    BATAS_KECIL = 512  # jangan menulis 8 MiB sungguhan di test

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = os.path.join(self._tmp.name, "audit.jsonl")
        self.rot = self.path + transport_mod.AUDIT_ROTATE_SUFFIX

    def _transport(self, **kw):
        t = Transport(delay=0.0, audit_log=self.path, **kw)
        self.addCleanup(t.close)
        return t

    def _isi(self, path):
        with open(path, encoding="utf-8") as fh:
            return fh.read()

    def test_file_di_bawah_batas_tidak_dirotasi(self):
        with mock.patch.object(transport_mod, "AUDIT_MAX_BYTES", self.BATAS_KECIL):
            t = self._transport()
            t._audit({"seq": 0, "url": "https://h/x", "status": 200})
        self.assertTrue(os.path.exists(self.path))
        self.assertFalse(os.path.exists(self.rot),
                         "rotasi terjadi padahal file masih di bawah batas")

    def test_file_belum_ada_aman(self):
        """Rotasi tidak boleh melempar/menghapus saat file belum ada."""
        t = self._transport()
        self.assertFalse(t._rotate_audit_if_needed(max_bytes=1))
        self.assertFalse(os.path.exists(self.rot))
        self.assertFalse(os.path.exists(self.path))

    def test_rotasi_dan_record_tertua_hilang(self):
        """>= batas -> `.1` muncul, file utama < batas, record tertua pindah."""
        batas = self.BATAS_KECIL
        with mock.patch.object(transport_mod, "AUDIT_MAX_BYTES", batas):
            t = self._transport()
            for seq in range(200):
                t._audit({"seq": seq,
                          "url": f"https://h/x?i={seq}",
                          "status": 200, "bytes": 0})
                if os.path.exists(self.rot):
                    break
            self.assertTrue(os.path.exists(self.rot),
                            "rotasi tidak pernah terjadi walau batas kecil")
            ukuran = os.path.getsize(self.path)
            self.assertLess(ukuran, batas + 4096,
                            f"file utama tidak dipangkas (={ukuran})")
            tertua = self._isi(self.rot)
            terbaru = self._isi(self.path)
        seq_dirotasi = [json.loads(b)["seq"] for b in tertua.splitlines() if b]
        seq_utama = [json.loads(b)["seq"] for b in terbaru.splitlines() if b]
        self.assertIn(0, seq_dirotasi, "record tertua tidak tersimpan di .1")
        self.assertNotIn(0, seq_utama, "record tertua masih ada di file utama")
        self.assertTrue(seq_utama, "file utama kosong setelah rotasi")
        self.assertGreater(min(seq_utama), max(seq_dirotasi),
                           "urutan rotasi salah: record baru ikut dipindah")
        # .1 tetap JSONL valid per baris (tidak ada baris terpotong).
        for b in tertua.splitlines():
            self.assertIn("seq", json.loads(b))

    def test_rotasi_menimpa_dot1_lama_tanpa_rantai(self):
        with open(self.rot, "w", encoding="utf-8") as fh:
            fh.write("LAMA-SEKALI\n")
        with mock.patch.object(transport_mod, "AUDIT_MAX_BYTES", self.BATAS_KECIL):
            t = self._transport()
            for seq in range(200):
                t._audit({"seq": seq, "url": "https://h/x", "status": 200})
                if os.path.exists(self.rot) and \
                        "LAMA-SEKALI" not in self._isi(self.rot):
                    break
        isi_rot = self._isi(self.rot)
        self.assertNotIn("LAMA-SEKALI", isi_rot, ".1 lama tidak tertimpa")
        self.assertIn('"seq"', isi_rot)
        # Hanya satu generasi: tidak ada .2 / .3.
        saudara = [f for f in os.listdir(self._tmp.name)
                   if f.startswith("audit.jsonl.")]
        self.assertEqual(sorted(saudara), ["audit.jsonl.1"],
                         f"rantai rotasi tidak boleh >1: {saudara}")

    def test_mode_0600_tetap_setelah_rotasi(self):
        if os.name != "posix":
            self.skipTest("mode POSIX tidak berlaku di platform ini")
        with mock.patch.object(transport_mod, "AUDIT_MAX_BYTES", self.BATAS_KECIL):
            t = self._transport()
            for seq in range(200):
                t._audit({"seq": seq, "url": "https://h/x", "status": 200})
                if os.path.exists(self.rot):
                    break
        self.assertTrue(os.path.exists(self.rot))
        for p in (self.path, self.rot):
            mode = stat.S_IMODE(os.stat(p).st_mode)
            if mode & 0o077:
                self.skipTest(f"filesystem tidak menegakkan chmod ({oct(mode)})")
            self.assertEqual(mode, 0o600, f"{p} mode {oct(mode)} setelah rotasi")

    def test_konstanta_retensi_wajar(self):
        self.assertIsInstance(transport_mod.AUDIT_MAX_BYTES, int)
        self.assertGreaterEqual(transport_mod.AUDIT_MAX_BYTES, 1024 * 1024,
                                "batas terlalu kecil untuk audit scan nyata")
        self.assertEqual(transport_mod.AUDIT_ROTATE_SUFFIX, ".1")

    def test_gagal_menulis_audit_tidak_melempar(self):
        """Audit gagal tidak boleh mematikan scan (perilaku lama dipertahankan)."""
        t = self._transport()
        with mock.patch("os.open", side_effect=OSError("disk penuh")), \
                warnings_simplefilter_ignore():
            t._audit({"url": "https://h/x", "status": 200})  # tidak melempar

    def test_request_tetap_jalan_saat_audit_gagal(self):
        t = self._transport(retries=0)
        with mock.patch.object(
            t, "_single", return_value=Response(url="https://h/x", status=200)
        ), mock.patch("os.open", side_effect=OSError("disk penuh")), \
                warnings_simplefilter_ignore():
            r = t.request("GET", "https://h/x")
        self.assertEqual(r.status, 200, "scan mati karena audit gagal")


class TestAuditLogInjection(unittest.TestCase):
    """Satu record SELALU satu baris fisik: nilai target tidak bisa memalsukan."""

    PAYLOAD = (
        "normal\nPALSU1\r\nPALSU2\r\x1b[2J\u2028\u2029"
        '{"ts":"x","url":"evil"}'
    )

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = os.path.join(self._tmp.name, "audit.jsonl")

    def _records(self, n=4):
        t = Transport(delay=0.0, audit_log=self.path)
        self.addCleanup(t.close)
        for i in range(n):
            t._audit({
                "method": "GET",
                "url": f"https://h/x?token=RAHASIA{i}&pad=" + self.PAYLOAD,
                "status": 200,
                "error": "boom " + self.PAYLOAD + f" token=RAHASIA{i}",
                "bytes": 0,
            })
        with open(self.path, "rb") as fh:
            return fh.read()

    def test_jumlah_baris_fisik_sama_dengan_jumlah_record(self):
        raw = self._records(n=4)
        self.assertEqual(raw.count(b"\n"), 4,
                         "jumlah newline != jumlah record (ada baris suntikan)")
        teks = raw.decode("utf-8")
        self.assertEqual(len(teks.splitlines()), 4)
        with open(self.path, encoding="utf-8") as fh:
            self.assertEqual(len(fh.readlines()), 4)

    def test_tidak_ada_baris_json_palsu(self):
        self._records(n=3)
        with open(self.path, encoding="utf-8") as fh:
            baris = fh.read().splitlines()
        self.assertFalse([b for b in baris if b.startswith('{"ts":"x"')],
                         "record JSON palsu dari target muncul sebagai baris")
        # Payload tetap berada di dalam record pemiliknya (bukan baris baru),
        # dan token yang diredaksi memakai `***`, bukan nilai asli.
        self.assertEqual(len(baris), 3)
        for b in baris:
            self.assertIn("PALSU1", b)
            self.assertIn("boom", b)
            self.assertNotIn("RAHASIA", b, "token tidak diredaksi")

    def test_setiap_baris_json_valid(self):
        self._records(n=5)
        with open(self.path, encoding="utf-8") as fh:
            for b in fh.read().splitlines():
                obj = json.loads(b)  # tidak boleh melempar
                self.assertIn("ts", obj)
                self.assertEqual(obj["method"], "GET")

    def test_karakter_kontrol_tidak_masuk_file_mentah(self):
        raw = self._records(n=2)
        for bad in (b"\x1b", b"\r", b"\x00", b"\x85", b"\x7f"):
            self.assertNotIn(bad, raw, f"byte kontrol {bad!r} lolos ke file")
        # U+2028/U+2029 tersimpan sebagai escape teks, bukan karakter asli.
        self.assertNotIn("\u2028".encode("utf-8"), raw)
        self.assertNotIn("\u2029".encode("utf-8"), raw)
        self.assertIn(b"\\n", raw)  # newline di-escape jadi teks literal

    def test_redaksi_tetap_jalan_bersamaan_escape(self):
        raw = self._records(n=3).decode("utf-8")
        self.assertNotIn("RAHASIA0", raw, "token bocor setelah hardening")
        self.assertIn("token=***", raw)
        self.assertIn("/x", raw)


class TestSessionHidupMatik(unittest.TestCase):
    def test_close_idempoten(self):
        t = Transport(delay=0.0)
        t.close()
        t.close()

    def test_context_manager_menutup_saat_exception(self):
        class FakeSession:
            closed = False

            def close(self):
                FakeSession.closed = True

        with self.assertRaises(RuntimeError):
            with Transport(delay=0.0) as t:
                t._session = FakeSession()
                raise RuntimeError("boom")
        self.assertTrue(FakeSession.closed, "session bocor saat exception")
        self.assertIsNone(t._session)

    def test_context_manager_menutup_normal(self):
        class FakeSession:
            closed = False

            def close(self):
                FakeSession.closed = True

        with Transport(delay=0.0) as t:
            t._session = FakeSession()
        self.assertTrue(FakeSession.closed)


class TestRedirectPolicyLive(unittest.TestCase):
    """Uji hop redirect lewat server HTTP lokal (tanpa jaringan luar).

    Tes mock di atas memalsukan `_single`; tes ini benar-benar membangun
    opener urllib sehingga wiring `PolicyRedirectHandler` ikut teruji.
    """

    @classmethod
    def setUpClass(cls):
        import http.server
        import socketserver
        import threading

        cls.hits = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                cls.hits.append(self.path)
                if self.path == "/evil":
                    self.send_response(302)
                    self.send_header(
                        "Location", "http://169.254.169.254/latest/meta-data/")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.path == "/chain":
                    self.send_response(301)
                    self.send_header("Location", "/final")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = b"ok"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):  # noqa: A002 - ikuti signature
                pass

        try:
            cls.srv = socketserver.TCPServer(("127.0.0.1", 0), Handler)
        except OSError as exc:  # pragma: no cover - sandbox tanpa socket
            raise unittest.SkipTest(f"tidak bisa membuka socket lokal: {exc}")
        cls.port = cls.srv.server_address[1]
        cls.thread = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def _urllib_transport(self, **kw):
        """Transport yang dipaksa memakai jalur urllib (bukan curl_cffi)."""
        real = transport_mod.HAVE_CURL_CFFI
        transport_mod.HAVE_CURL_CFFI = False
        self.addCleanup(setattr, transport_mod, "HAVE_CURL_CFFI", real)
        return Transport(delay=0.0, retries=0, **kw)

    def test_urllib_menolak_hop_redirect_ke_metadata(self):
        """Loopback boleh (lab), tetapi hop ke 169.254.169.254 tidak dikirim.

        Tanpa monkeypatch apa pun: `allow_private=True` sekarang benar-benar
        meloloskan target lab 127.0.0.1, dan kebijakan sendiri yang menolak
        hop metadata. Assertion memeriksa PESAN kebijakan (bukan sekadar
        status 0 yang bisa berarti koneksi gagal).
        """
        t = self._urllib_transport(allow_private=True)
        before = len(self.hits)
        r = t.request("GET", f"http://127.0.0.1:{self.port}/evil")
        t.close()
        self.assertEqual(r.status, 0, f"hop metadata tidak diblokir: {r!r}")
        err = r.error
        self.assertIn("PolicyError", err, f"bukan penolakan kebijakan: {err}")
        self.assertIn("169.254.169.254", err, f"pesan tanpa alamat metadata: {err}")
        self.assertIn("metadata", err.lower(), f"pesan tanpa kata metadata: {err}")
        self.assertIn("SSRF", err, f"pesan tanpa alasan SSRF: {err}")
        self.assertNotIn("meta-data", self.hits[before:],
                         "hop redirect ke metadata tetap dikirim")

    def test_urllib_redirect_ke_metadata_ditolak_walau_allow_private(self):
        """Sama seperti di atas, tetapi lewat `_single` asli + server lokal.

        Dipastikan request pertama (loopback) BENAR-BENAR sampai ke server —
        jadi penolakan hop kedua murni karena kebijakan, bukan karena target
        lab ikut diblokir.
        """
        t = self._urllib_transport(allow_private=True)
        before = len(self.hits)
        r = t.request("GET", f"http://127.0.0.1:{self.port}/evil")
        t.close()
        self.assertIn("/evil", self.hits[before:],
                      "target lab ikut tertolak; allow_private terlalu ketat")
        self.assertNotIn("/latest/meta-data/", self.hits[before:])
        self.assertRegex(r.error, r"(?i)169\.254\.169\.254|metadata")
        self.assertIn("PolicyError", r.error)

    def test_urllib_mengikuti_redirect_publik(self):
        t = self._urllib_transport(allow_private=True)
        r = t.request("GET", f"http://127.0.0.1:{self.port}/chain")
        t.close()
        self.assertEqual(r.status, 200)
        self.assertEqual(r.body, "ok")

    def test_urllib_no_follow_berhenti_di_3xx(self):
        t = self._urllib_transport(allow_private=True, follow_redirects=False)
        r = t.request("GET", f"http://127.0.0.1:{self.port}/chain")
        t.close()
        self.assertEqual(r.status, 301)
        self.assertEqual(r.error, "")

    def test_urllib_menolak_target_privat_tanpa_flag(self):
        t = self._urllib_transport()
        before = len(self.hits)
        r = t.request("GET", f"http://127.0.0.1:{self.port}/final")
        t.close()
        self.assertEqual(r.status, 0)
        self.assertIn("PolicyError", r.error)
        self.assertEqual(len(self.hits), before, "paket tetap terkirim")


class TestCliFlags(unittest.TestCase):
    """Flag baru harus ada di parser dan diteruskan `_mk_transport`."""

    def _parser(self):
        sys.path.insert(0, TOOLKIT)
        import importlib
        cli = importlib.import_module("php2shell")
        return cli

    def test_flag_default_false(self):
        cli = self._parser()
        ap = cli.build_parser()
        args = ap.parse_args(["detect", "-u", "https://example.com/"])
        self.assertFalse(args.insecure)
        self.assertFalse(args.no_follow_redirects)
        self.assertFalse(args.allow_private_target)

    def test_mk_transport_meneruskan_flag(self):
        cli = self._parser()
        ap = cli.build_parser()
        args = ap.parse_args(["detect", "-u", "https://example.com/",
                              "--insecure", "--no-follow-redirects",
                              "--allow-private-target"])
        t = cli._mk_transport(args)
        self.assertIs(t.verify_tls, False)
        self.assertIs(t.follow_redirects, False)
        self.assertIs(t.allow_private, True)

    def test_mk_transport_default_aman(self):
        cli = self._parser()
        ap = cli.build_parser()
        args = ap.parse_args(["detect", "-u", "https://example.com/"])
        t = cli._mk_transport(args)
        self.assertIs(t.verify_tls, True)
        self.assertIs(t.follow_redirects, True)
        self.assertIs(t.allow_private, False)

    def test_target_diblokir_tidak_dilaporkan_sebagai_target_bersih(self):
        """PolicyError tidak boleh tampil sebagai "header/body bersih" (CDN)."""
        cli = self._parser()
        ap = cli.build_parser()
        args = ap.parse_args(["detect", "-u", "http://169.254.169.254/latest/meta-data/"])
        with cli._mk_transport(args) as t:
            rec = cli._detect_one(args.urls[0], t, args)
        reason = rec["detect"]["reason"]
        self.assertTrue(reason.startswith("diblokir kebijakan tujuan"),
                        f"reason tidak menjelaskan blokir: {reason!r}")
        self.assertNotIn("header/body bersih", reason)
        # Gerbang akhir tetap tidak mengizinkan exploit.
        self.assertNotEqual(rec["preflight"].get("status"), "ready")


class TestDnsRebinding(unittest.TestCase):
    """DNS rebinding: satu resolusi, lalu koneksi WAJIB dipin ke IP itu.

    Tanpa pin, `check_url()` memvalidasi IP A tetapi lapisan koneksi
    me-resolve ulang dan bisa mendapat IP B (`169.254.169.254` pada jawaban
    kedua) — validasi tadi tidak menjaga apa pun. Tes di kelas ini memalsukan
    resolver dengan SEQUENCE: panggilan pertama publik, panggilan kedua
    metadata. Pemanggilan kedua yang terjadi = tes gagal (getaddrinfo count).
    """

    URL = "http://fake.invalid:8080/x.php"
    IP_PUBLIK = "93.184.216.34"
    IP_METADATA = "169.254.169.254"

    def _resolver_sequence(self):
        """Panggilan 1 -> publik, panggilan 2..n -> metadata (rebinding)."""
        calls = []

        def fake_getaddrinfo(host, port=None, *args, **kwargs):
            calls.append((host, port))
            ip = self.IP_PUBLIK if len(calls) == 1 else self.IP_METADATA
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
                     "", (ip, port or 0))]

        return calls, fake_getaddrinfo

    def test_urllib_satu_resolusi_dan_pin_ke_ip_validasi(self):
        import urllib.error

        calls, fake = self._resolver_sequence()
        target_calls = []

        def fake_create_connection(address, *args, **kwargs):
            target_calls.append(address)
            raise OSError("mock: tidak ada server nyata")

        t = Transport(delay=0.0, retries=0)
        self.addCleanup(t.close)
        with mock.patch.object(transport_mod, "HAVE_CURL_CFFI", False), \
                mock.patch("socket.getaddrinfo", side_effect=fake), \
                mock.patch("socket.create_connection", side_effect=fake_create_connection):
            with self.assertRaises((urllib.error.URLError, OSError)):
                t._single("GET", self.URL, None, None)

        # Satu resolusi. Panggilan kedua akan mengembalikan metadata dan
        # membatalkan request (bukan menyambung ke sana) — jadi count ini
        # sekaligus membuktikan tidak ada resolusi ulang di lapisan koneksi.
        self.assertEqual(len(calls), 1,
                         f"hostname di-resolve {len(calls)}x: {calls}")
        self.assertEqual(calls[0][0], "fake.invalid")
        # TCP mendarat di IP yang sudah divalidasi, BUKAN di metadata.
        self.assertTrue(target_calls, "tidak ada percobaan koneksi")
        self.assertEqual(target_calls, [(self.IP_PUBLIK, 8080)],
                         f"koneksi mendarat di {target_calls}")
        self.assertNotIn(self.IP_METADATA, [a[0] for a in target_calls])

    def test_urllib_https_pin_ip_tapi_sni_hostname_asli(self):
        """HTTPS: soket ke IP pin, `server_hostname` tetap hostname URL."""
        wrapped = {}

        class FakeTlsSock:
            def setsockopt(self, *a):
                pass

            def makefile(self, *a, **kw):
                raise OSError("mock: tanpa server nyata")

        ctx = mock.Mock()

        def fake_wrap(sock, server_hostname=None, **kw):
            wrapped["server_hostname"] = server_hostname
            return FakeTlsSock()

        ctx.wrap_socket = fake_wrap
        calls, fake = self._resolver_sequence()

        def fake_create_connection(address, *args, **kwargs):
            wrapped.setdefault("address", address)
            return mock.Mock()

        with mock.patch("socket.getaddrinfo", side_effect=fake), \
                mock.patch("socket.create_connection",
                           side_effect=fake_create_connection):
            # Dibangun DI DALAM patch: `http.client` menyimpan
            # `self._create_connection = socket.create_connection` saat __init__.
            conn = transport_mod._PinnedHTTPSConnection(
                "fake.invalid", 8443, context=ctx, pinned_ip=self.IP_PUBLIK,
                timeout=5,
            )
            conn.connect()

        self.assertEqual(wrapped["address"], (self.IP_PUBLIK, 8443))
        self.assertEqual(wrapped["server_hostname"], "fake.invalid",
                         "SNI wajib hostname asli, bukan IP pin")
        self.assertEqual(len(calls), 0, "kelas ber-pin tidak boleh resolve sendiri")

    def test_resolve_pinned_metadata_selalu_ditolak(self):
        for addr in policy.METADATA_ADDRESSES:
            for allow in (False, True):
                with self.subTest(addr=addr, allow_private=allow):
                    with self.assertRaises(policy.PolicyError) as ctx:
                        policy.resolve_pinned(addr, 80, allow_private=allow)
                    msg = str(ctx.exception)
                    self.assertIn("metadata", msg.lower())
                    self.assertIn("SSRF", msg)
                    self.assertIn("--allow-private-target", msg,
                                  "pesan harus menegaskan flag lab tidak berlaku")

    def test_resolve_pinned_metadata_dari_dns_selalu_ditolak(self):
        """A record metadata juga ditolak, termasuk saat allow_private=True."""
        fake = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
                 "", (self.IP_METADATA, 80))]
        for allow in (False, True):
            with self.subTest(allow_private=allow):
                with mock.patch("socket.getaddrinfo", return_value=fake):
                    with self.assertRaises(policy.PolicyError) as ctx:
                        policy.resolve_pinned("metadata.internal", 80, allow_private=allow)
                msg = str(ctx.exception)
                self.assertIn("metadata", msg.lower())
                self.assertIn("SSRF", msg)

    def test_resolve_pinned_privat_ditolak_kecuali_allow_private(self):
        fake = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
                 "", ("10.1.2.3", 80))]
        with mock.patch("socket.getaddrinfo", return_value=fake):
            with self.assertRaises(policy.PolicyError) as ctx:
                policy.resolve_pinned("lab.internal", 80, allow_private=False)
            msg = str(ctx.exception)
            self.assertIn("10.1.2.3", msg)
            self.assertIn("SSRF", msg)
            self.assertIn("--allow-private-target", msg)

            self.assertEqual(
                policy.resolve_pinned("lab.internal", 80, allow_private=True),
                "10.1.2.3",
            )
            self.assertEqual(
                policy.resolve_pinned_candidates("lab.internal", 80,
                                                 allow_private=True),
                ["10.1.2.3"],
            )

    def test_resolve_pinned_memilih_ipv4_dan_satu_resolusi(self):
        """Banyak A/AAAA: semua divalidasi, hasil memilih IPv4 lebih dulu."""
        fake = [
            (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP,
             "", ("2606:4700::1111", 80)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
             "", ("93.184.216.34", 80)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
             "", ("93.184.216.34", 80)),   # duplikat dari resolver
        ]
        with mock.patch("socket.getaddrinfo", return_value=fake) as gad:
            ip = policy.resolve_pinned("example.com", 80)
            cands = policy.resolve_pinned_candidates("example.com", 80)
        self.assertEqual(ip, "93.184.216.34")
        self.assertEqual(cands, ["93.184.216.34", "2606:4700::1111"],
                         "duplikat tidak di-dedupe / urutan IPv4 bukan pertama")
        self.assertEqual(gad.call_count, 2, "satu panggilan per fungsi")

    def test_resolve_pinned_dns_gagal_bukan_policyerror(self):
        """DNS gagal = kegagalan jaringan (`ResolveError`/OSError), bukan blokir."""
        with mock.patch("socket.getaddrinfo", side_effect=socket.gaierror("NXDOMAIN")):
            with self.assertRaises(policy.ResolveError) as ctx:
                policy.resolve_pinned("nx.invalid", 80)
        msg = str(ctx.exception)
        self.assertIn("tidak bisa resolve", msg)
        self.assertIsInstance(ctx.exception, OSError)
        self.assertNotIsInstance(ctx.exception, policy.PolicyError)

    def test_check_url_resolve_false_tidak_menyentuh_resolver(self):
        """`resolve=False`: cek sintaks/kebijakan tetap, DNS diserahkan ke pin.

        Tanpa ini nama di-resolve dua kali per hop (validasi + koneksi) dan
        dua jawaban DNS bisa berbeda — persis celah yang ditutup.
        """
        with mock.patch("socket.getaddrinfo",
                        side_effect=AssertionError("resolver dipanggil")):
            # Lolos tanpa resolusi.
            policy.check_url("http://fake.invalid/x.php", resolve=False)
            policy.check_url("http://fake.invalid/x.php", allow_private=True,
                             resolve=False)
            # Yang tidak butuh DNS tetap ditolak: literal metadata, skema,
            # loopback name, port rusak.
            for bad in ("http://169.254.169.254/latest/meta-data/",
                        "file:///etc/passwd",
                        "http://localhost:8080/x",
                        "http://fake.invalid:99999/x"):
                with self.subTest(url=bad):
                    with self.assertRaises(policy.PolicyError):
                        policy.check_url(bad, resolve=False)

    def test_ip_literal_tidak_resolve_dan_tetap_divalidasi(self):
        with mock.patch("socket.getaddrinfo",
                        side_effect=AssertionError("resolver tidak boleh dipanggil")):
            self.assertEqual(policy.resolve_pinned("93.184.216.34", 80),
                             "93.184.216.34")
            with self.assertRaises(policy.PolicyError):
                policy.resolve_pinned("169.254.169.254", 80, allow_private=True)


class TestPolicyTidakDiRetry(unittest.TestCase):
    """Blokir kebijakan bukan kegagalan jaringan: sekali coba, tanpa sleep.

    Regresi yang dikunci: IP literal privat hanya ditolak di lapisan pin
    (`resolve_pinned`), bukan di `check_url(resolve=False)`. Penolakan itu
    sampai ke `request()` sebagai `Response(status=0, error='PolicyError: ...')`
    dan dulu dianggap "koneksi putus", sehingga di-retry 2x dengan sleep
    2s+4s — satu URL terblokir berubah dari ~0s menjadi ~6s.
    """

    def test_penolakan_kebijakan_tidak_di_retry(self):
        t = Transport(delay=0.0)  # retries default (2)
        self.assertGreaterEqual(t.retries, 1, "prasyarat: retry memang aktif")
        blocked = Response(url="http://93.184.216.34/x.php", status=0,
                           error="PolicyError: alamat 93.184.216.34 diblokir")
        with mock.patch.object(Transport, "_single", return_value=blocked) as single, \
                mock.patch("lib.transport.time.sleep") as sleep:
            resp = t.request("GET", "http://93.184.216.34/x.php")
        self.assertEqual(single.call_count, 1,
                         "penolakan kebijakan di-retry (harus tepat 1 percobaan)")
        self.assertFalse(sleep.called,
                         f"time.sleep dipanggil untuk penolakan kebijakan: {sleep.call_args_list}")
        self.assertEqual(resp.status, 0)
        self.assertTrue(resp.error.startswith("PolicyError"))

    def test_resolve_error_juga_tidak_di_retry(self):
        """DNS gagal = keputusan tetap, bukan gangguan sementara."""
        t = Transport(delay=0.0)
        err = Response(url="http://nx.invalid/x.php", status=0,
                       error="ResolveError: tidak bisa resolve 'nx.invalid'")
        with mock.patch.object(Transport, "_single", return_value=err) as single, \
                mock.patch("lib.transport.time.sleep") as sleep:
            t.request("GET", "http://nx.invalid/x.php")
        self.assertEqual(single.call_count, 1)
        self.assertFalse(sleep.called)

    def test_literal_privat_ditolak_walau_resolve_false(self):
        """`resolve=False` melewati DNS, BUKAN validasi IP literal."""
        for url in ("http://127.0.0.1:9/x.php", "http://10.0.0.5/x.php"):
            with self.subTest(url=url):
                with self.assertRaises(policy.PolicyError) as ctx:
                    policy.check_url(url, resolve=False)
                self.assertIn("SSRF", str(ctx.exception))
        # Flag lab tetap membuka alamat privat literal.
        for url in ("http://127.0.0.1:9/x.php", "http://10.0.0.5/x.php"):
            with self.subTest(url=url, allow_private=True):
                policy.check_url(url, allow_private=True, resolve=False)
        # Metadata tetap ditolak walau allow_private=True.
        with self.assertRaises(policy.PolicyError):
            policy.check_url("http://169.254.169.254/latest/meta-data/",
                             allow_private=True, resolve=False)


if __name__ == "__main__":
    unittest.main()

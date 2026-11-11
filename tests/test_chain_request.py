"""Tes bentuk request `Target` + penjaga batas ukuran `memprobe`.

Semua tes di sini OFFLINE: `_connect` diganti fake socket, tidak ada koneksi
nyata, tidak ada target di internet. Yang dikunci:

  1. query string URL ikut ke request line (`POST /upload.php?route=debug`),
     tidak lagi dibuang seperti sebelumnya;
  2. URL tanpa query TIDAK menambahkan '?' hampa;
  3. TLS diverifikasi secara DEFAULT (`CERT_REQUIRED` + `check_hostname`),
     dan hanya `verify_tls=False` yang mematikan verifikasi;
  4. header `Host:` benar untuk port kustom dan literal IPv6 (`[::1]:8443`);
  5. `memprobe.exceeds_safe_ceiling()` menandai limit yang tidak mungkin
     di-OOM tanpa melewati plafon aman, tanpa mengubah `huge_mb_for()`.

    /home/lota1337/myenv/bin/python -m pytest tests/test_chain_request.py -q
"""

import os
import ssl
import sys
import unittest
from unittest import mock

TOOLKIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if TOOLKIT not in sys.path:
    sys.path.insert(0, TOOLKIT)

from lib import chain, memprobe  # noqa: E402


class FakeSock:
    """Socket palsu: merekam byte yang dikirim, recv() langsung EOF."""

    def __init__(self):
        self.sent = bytearray()
        self.closed = False
        self.timeout = None

    def settimeout(self, value):
        self.timeout = value

    def setsockopt(self, *args):  # TCP_NODELAY, diabaikan
        pass

    def sendall(self, data):
        self.sent.extend(data)

    def recv(self, n):
        return b""

    def close(self):
        self.closed = True

    # --- helper untuk tes ---
    def request_line(self) -> str:
        return bytes(self.sent).split(b"\r\n", 1)[0].decode("latin1")

    def header(self, name: str) -> str:
        head = bytes(self.sent).split(b"\r\n\r\n", 1)[0].decode("latin1")
        for line in head.split("\r\n")[1:]:
            k, _, v = line.partition(":")
            if k.strip().lower() == name.lower():
                return v.strip()
        return ""


def _wire(target: chain.Target):
    """Pasang fake socket pada target; kembalikan sock-nya."""
    sock = FakeSock()
    target._connect = lambda: sock  # type: ignore[method-assign]
    return sock


class TestRequestLineQuery(unittest.TestCase):
    """Regresi P2: query string dulu hilang dari request line."""

    def test_post_memuat_path_dan_query(self):
        t = chain.Target("http://lab.example/upload.php?route=debug")
        sock = _wire(t)
        t.post(b"BODY", b"BND")
        self.assertEqual(sock.request_line(), "POST /upload.php?route=debug HTTP/1.1")

    def test_post_multi_parameter_dipertahankan_apa_adanya(self):
        t = chain.Target("http://lab.example/upload.php?route=debug&x=1&y=%20a")
        sock = _wire(t)
        t.post(b"BODY", b"BND")
        self.assertEqual(
            sock.request_line(),
            "POST /upload.php?route=debug&x=1&y=%20a HTTP/1.1",
        )

    def test_post_tanpa_query_tidak_menambah_tanda_tanya(self):
        t = chain.Target("http://lab.example/upload.php")
        sock = _wire(t)
        t.post(b"BODY", b"BND")
        line = sock.request_line()
        self.assertEqual(line, "POST /upload.php HTTP/1.1")
        self.assertNotIn("?", line)

    def test_post_query_kosong_tidak_menambah_tanda_tanya(self):
        # ".../upload.php?" -> urlsplit memberi query kosong.
        t = chain.Target("http://lab.example/upload.php?")
        sock = _wire(t)
        t.post(b"BODY", b"BND")
        self.assertEqual(sock.request_line(), "POST /upload.php HTTP/1.1")

    def test_root_tanpa_path(self):
        t = chain.Target("http://lab.example")
        sock = _wire(t)
        t.post(b"BODY", b"BND")
        self.assertEqual(sock.request_line(), "POST / HTTP/1.1")

    def test_get_memakai_query_dari_url(self):
        t = chain.Target("http://lab.example/out/p1?cache=0")
        sock = _wire(t)
        t.get()
        self.assertEqual(sock.request_line(), "GET /out/p1?cache=0 HTTP/1.1")

    def test_get_path_eksplisit_tidak_dicampur_query(self):
        t = chain.Target("http://lab.example/upload.php?route=debug")
        sock = _wire(t)
        t.get("/out/p1")
        self.assertEqual(sock.request_line(), "GET /out/p1 HTTP/1.1")

    def test_content_length_dan_boundary_tetap_benar(self):
        t = chain.Target("http://lab.example/u.php?a=1")
        sock = _wire(t)
        t.post(b"0123456789", b"BND")
        self.assertEqual(sock.header("content-length"), "10")
        self.assertIn("boundary=BND", sock.header("content-type"))


class TestHostHeader(unittest.TestCase):
    """Header Host: harus valid untuk port kustom dan literal IPv6."""

    def test_port_kustom(self):
        t = chain.Target("http://lab.example:8080/u.php")
        sock = _wire(t)
        t.post(b"B", b"BND")
        self.assertEqual(sock.header("host"), "lab.example:8080")

    def test_port_default_tetap_ditulis(self):
        # Perilaku lama dipertahankan: port selalu ikut (sudah begitu sebelumnya).
        t = chain.Target("https://lab.example/u.php")
        sock = _wire(t)
        t.post(b"B", b"BND")
        self.assertEqual(sock.header("host"), "lab.example:443")

    def test_ipv6_dibungkus_bracket(self):
        t = chain.Target("http://[::1]:8443/u.php")
        sock = _wire(t)
        t.post(b"B", b"BND")
        self.assertEqual(sock.header("host"), "[::1]:8443")
        self.assertEqual(sock.request_line(), "POST /u.php HTTP/1.1")

    def test_ipv6_gethostbyname_target_benar(self):
        # hostname dari urlsplit tidak membawa bracket -> host_header harus
        # mengembalikannya, dan koneksi tetap memakai ::1 tanpa bracket.
        t = chain.Target("https://[2001:db8::1]:9443/x?a=1")
        self.assertEqual(t.host, "2001:db8::1")
        self.assertEqual(t.host_header, "[2001:db8::1]:9443")
        sock = _wire(t)
        t.get()
        self.assertEqual(sock.header("host"), "[2001:db8::1]:9443")


class _CtxRecorder:
    """Tangkap SSLContext yang dibentuk `_connect` tanpa handshake nyata."""

    def __init__(self, real_create):
        self.real_create = real_create
        self.ctx = None
        self.server_hostname = None

    def __enter__(self):
        self._patches = [
            # `_connect()` kini me-resolve SEKALI (pin anti DNS-rebinding);
            # tanpa mock ini tes akan bergantung pada DNS nyata.
            mock.patch.object(
                chain.socket, "getaddrinfo",
                lambda *a, **kw: [(2, 1, 6, "", ("93.184.216.34", 443))]),
            mock.patch.object(chain.socket, "create_connection",
                              lambda *a, **kw: FakeSock()),
            mock.patch.object(chain.ssl, "create_default_context", self._create),
            mock.patch.object(ssl.SSLContext, "wrap_socket", self._wrap),
        ]
        for p in self._patches:
            p.start()
        return self

    def _create(self, *args, **kwargs):
        self.ctx = self.real_create(*args, **kwargs)
        return self.ctx

    def _wrap(self, sock, server_hostname=None, **kwargs):
        self.server_hostname = server_hostname
        return sock

    def __exit__(self, *exc):
        for p in reversed(self._patches):
            p.stop()
        return False


class TestTLSVerification(unittest.TestCase):
    """Regresi P0: verifikasi TLS dulu dimatikan diam-diam (CERT_NONE)."""

    def setUp(self):
        self._real_create = ssl.create_default_context

    def _context_for(self, url: str, **kwargs):
        rec = _CtxRecorder(self._real_create)
        with rec:
            chain.Target(url, **kwargs)._connect()
        self.assertIsNotNone(rec.ctx, "create_default_context tidak dipanggil")
        return rec

    @staticmethod
    def _ctx_of(rec):
        ctx = rec.ctx
        assert ctx is not None
        return ctx

    def test_default_memverifikasi(self):
        rec = self._context_for("https://lab.example/u.php")
        self.assertEqual(self._ctx_of(rec).verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(self._ctx_of(rec).check_hostname)
        # SNI/hostname dicocokkan dengan host target.
        self.assertEqual(rec.server_hostname, "lab.example")

    def test_verify_tls_false_mematikan_verifikasi(self):
        rec = self._context_for("https://lab.example/u.php", verify_tls=False)
        self.assertEqual(self._ctx_of(rec).verify_mode, ssl.CERT_NONE)
        self.assertFalse(self._ctx_of(rec).check_hostname)

    def test_flag_tersimpan_dan_default_true(self):
        self.assertTrue(chain.Target("https://lab.example/u.php").verify_tls)
        self.assertFalse(
            chain.Target("https://lab.example/u.php", verify_tls=False).verify_tls
        )

    def test_http_tidak_membuat_context_tls(self):
        rec = _CtxRecorder(self._real_create)
        with rec:
            chain.Target("http://lab.example/u.php")._connect()
        self.assertIsNone(rec.ctx, "http:// tidak seharusnya membungkus TLS")


class TestDeadlinePropagation(unittest.TestCase):
    """Temuan audit P1: timeout per-operasi TIDAK boleh melewati anggaran total.

    `_arm()` di exploit_runner hanya menyetel `target.timeout`; dulu `stage1/
    stage2/stage3/rotate` mengabaikannya dan memakai `max(90.0, timeout)`
    sendiri-sendiri, jadi sisa deadline 5s tetap diberi POST 90s dan `run()`
    melewati `max_total_timeout`. Yang dikunci di sini: `op_timeout()` adalah
    satu-satunya pintu, dan keempat tahap memakainya.
    """

    def setUp(self):
        # Jam palsu: deadline diuji tanpa tidur sungguhan.
        self._real_clock = chain._clock
        self.now = 1000.0
        chain._clock = lambda: self.now

    def tearDown(self):
        chain._clock = self._real_clock

    # --- Target.op_timeout -------------------------------------------------

    def test_op_timeout_dipotong_sisa_deadline(self):
        t = chain.Target("http://lab.example/u.php", timeout=90.0,
                         deadline=self.now + 5.0)
        self.assertLessEqual(t.op_timeout(90.0), 5.0)
        self.assertLess(t.op_timeout(90.0), 90.0)
        # Sisa tidak boleh "dibulatkan" naik melewati deadline itu sendiri.
        self.assertAlmostEqual(t.op_timeout(90.0), 5.0)

    def test_op_timeout_tanpa_deadline_mengembalikan_prefer(self):
        t = chain.Target("http://lab.example/u.php", timeout=90.0)
        self.assertEqual(t.op_timeout(90.0), 90.0)
        self.assertIsNone(t.remaining())
        # prefer KECIL juga tidak dinaikkan: tanpa deadline = perilaku lama.
        self.assertEqual(t.op_timeout(3.5), 3.5)

    def test_op_timeout_memakai_lantai_minimal_saat_sisa_tipis(self):
        # 5 ms tersisa: socket timeout 5 ms bukan percobaan, tapi juga tidak
        # boleh jadi 0 (0 = non-blocking di Python). Lantai MIN_OP_TIMEOUT.
        t = chain.Target("http://lab.example/u.php", deadline=self.now + 0.005)
        self.assertEqual(t.op_timeout(90.0), chain.MIN_OP_TIMEOUT)
        self.assertGreater(chain.MIN_OP_TIMEOUT, 0)

    def test_op_timeout_melempar_saat_sisa_habis(self):
        t = chain.Target("http://lab.example/u.php", deadline=self.now)
        with self.assertRaises(chain.DeadlineExceeded):
            t.op_timeout(90.0)
        self.now += 10          # sudah lewat deadline
        with self.assertRaises(chain.DeadlineExceeded):
            t.op_timeout(1.0)

    def test_deadline_none_kompatibel_dengan_pemanggil_lama(self):
        # Target(url, timeout=...) tanpa deadline harus tetap jalan persis.
        t = chain.Target("http://lab.example/u.php", timeout=12.0)
        self.assertIsNone(t.deadline)
        self.assertEqual(t.op_timeout(7.0), 7.0)

    # --- keempat tahap rantai ---------------------------------------------

    def _recording_target(self, deadline):
        """Target asli, tapi `post` merekam timeout alih-alih membuka soket."""

        class Recording(chain.Target):
            def __init__(self, *a, **kw):
                super().__init__(*a, **kw)
                self.posts = []

            def post(self, body, boundary, read_cap=1 << 20, timeout=None,
                     extra_headers=None):
                self.posts.append(timeout)
                return b""

        return Recording("http://lab.example/upload.php", timeout=90.0,
                         deadline=deadline)

    def test_stage_memakai_op_timeout_bukan_90_detik_buta(self):
        t = self._recording_target(self.now + 4.0)
        ex = chain.Chain(t, "id", huge_mb=12, verbose=False)
        ex.stage1()
        # POST body besar pertama: dulu `max(90.0, timeout)` = 90s.
        self.assertTrue(t.posts, "stage1 harus mengirim POST")
        for timeout in t.posts:
            self.assertIsNotNone(timeout, t.posts)
            self.assertLessEqual(timeout, 4.0, t.posts)

    def test_tanpa_deadline_stage_tetap_memakai_prefer_90(self):
        # Perilaku lama WAJIB tidak berubah bila tidak ada deadline.
        t = self._recording_target(None)
        ex = chain.Chain(t, "id", huge_mb=12, verbose=False)
        ex.stage1()
        self.assertEqual(t.posts[0], 90.0, t.posts)

    def test_rotate_dan_stage2_stage3_ikut_dipotong(self):
        for method, args in (("rotate", ()), ("stage2", ()),
                             ("stage3", (0x1000, 0x2000))):
            with self.subTest(method=method):
                t = self._recording_target(self.now + 3.0)
                ex = chain.Chain(t, "id", huge_mb=12, verbose=False)
                getattr(ex, method)(*args)
                self.assertTrue(t.posts, f"{method} harus mengirim POST")
                for timeout in t.posts:
                    self.assertLessEqual(timeout, 3.0, (method, t.posts))

    def test_pause_ikut_anggaran_dan_melempar_saat_habis(self):
        """Jeda antar-request tidak boleh jadi waktu "gratis"."""
        slept = []
        real_sleep = chain.time.sleep

        def fake_sleep(s):
            slept.append(s)
            self.now += s          # tidur benar-benar memakan anggaran

        chain.time.sleep = fake_sleep
        try:
            t = chain.Target("http://lab.example/u.php", deadline=self.now + 0.2)
            ex = chain.Chain(t, "id", huge_mb=12, verbose=False)
            ex._pause(5.0)                     # dipotong jadi 0.2s
            self.assertEqual(len(slept), 1)
            # Dihitung dari deadline - _clock(); selisih float kecil wajar.
            self.assertAlmostEqual(slept[0], 0.2, places=6)
            # Sekarang sisa 0 -> berhenti, bukan tidur lagi.
            with self.assertRaises(chain.DeadlineExceeded):
                ex._pause(1.0)
            self.assertEqual(len(slept), 1, "tidak boleh ada tidur tambahan")
        finally:
            chain.time.sleep = real_sleep


class TestMemprobeSafeCeiling(unittest.TestCase):
    """Penjaga batas ukuran: 512 MiB adalah plafon, dan harus bisa dideteksi."""

    def test_kontrak_konstanta(self):
        self.assertEqual(memprobe.SAFE_CEILING_MB, 512)
        self.assertEqual(memprobe.safe_ceiling_mb(), 512)
        self.assertIsInstance(memprobe.safe_ceiling_mb(), int)

    def test_limit_di_atas_plafon_terdeteksi(self):
        self.assertTrue(memprobe.exceeds_safe_ceiling(1024 ** 3))
        self.assertTrue(memprobe.exceeds_safe_ceiling(512 * 1024 ** 2))

    def test_limit_wajar_tidak_terdeteksi(self):
        self.assertFalse(memprobe.exceeds_safe_ceiling(128 * 1024 ** 2))
        self.assertFalse(memprobe.exceeds_safe_ceiling(8 * 1024 ** 2))

    def test_limit_tidak_diketahui_tidak_terdeteksi(self):
        self.assertFalse(memprobe.exceeds_safe_ceiling(None))
        self.assertFalse(memprobe.exceeds_safe_ceiling(0))

    def test_huge_mb_for_tidak_berubah(self):
        # Test lama mengunci nilai-nilai ini; jangan sampai regresi.
        self.assertEqual(memprobe.huge_mb_for(8 * 1024 ** 2), 10)
        self.assertLess(memprobe.huge_mb_for(128 * 1024 ** 2), 150)
        self.assertEqual(memprobe.huge_mb_for(None), 12)
        self.assertEqual(memprobe.huge_mb_for(0), 12)
        self.assertEqual(memprobe.huge_mb_for(4 * 1024 ** 3), 512)

    def test_huge_mb_or_none_tidak_menebak(self):
        """Temuan audit P1: unknown HARUS None, bukan default 12 MB diam-diam."""
        self.assertIsNone(memprobe.huge_mb_or_none(None))
        self.assertIsNone(memprobe.huge_mb_or_none(0))
        self.assertIsNone(memprobe.huge_mb_or_none(-1))
        # Limit terbaca: identik dengan huge_mb_for (tidak ada perubahan nilai).
        for limit in (8 * 1024 ** 2, 128 * 1024 ** 2, 1024 ** 3):
            self.assertEqual(memprobe.huge_mb_or_none(limit),
                             memprobe.huge_mb_for(limit))
        self.assertEqual(memprobe.huge_mb_or_none(8 * 1024 ** 2), 10)

    def test_describe_tanpa_ukuran_tidak_menyebut_default(self):
        # chosen_mb=0 = "belum ditentukan": pesannya tidak boleh berbunyi
        # "pakai default 12 MB" — itu tebakan yang dihentikan audit.
        s = memprobe.describe(None, 0)
        self.assertIn("TIDAK ditentukan", s)
        self.assertIn("--huge-mb", s)
        self.assertNotIn("default", s)

    def test_konsisten_dengan_cap_huge_mb(self):
        for limit in (512 * 1024 ** 2, 1024 ** 3, 4 * 1024 ** 3):
            self.assertTrue(memprobe.exceeds_safe_ceiling(limit))
            self.assertLessEqual(memprobe.huge_mb_for(limit),
                                 memprobe.SAFE_CEILING_MB)

    def test_describe_menyebut_batas_aman(self):
        s = memprobe.describe(1024 ** 3, memprobe.huge_mb_for(1024 ** 3))
        self.assertIn("melebihi batas aman 512 MiB", s)
        self.assertIn("tidak akan OOM", s)
        # Limit normal tetap memakai kalimat lama (tanpa peringatan plafon).
        normal = memprobe.describe(128 * 1024 ** 2,
                                   memprobe.huge_mb_for(128 * 1024 ** 2))
        self.assertNotIn("melebihi batas aman", normal)
        self.assertIn("terbaca dari target", normal)


class TestDnsRebindingChain(unittest.TestCase):
    """`Target._connect()` mem-pin IP hasil validasi, bukan hostname.

    Sebelum ini `socket.create_connection((self.host, self.port))` me-resolve
    ulang nama di dalam socket, jadi DNS bisa mengembalikan alamat lain di
    antara validasi dan koneksi. Sekarang: satu resolusi, lalu IP itu yang
    dipakai; `Host:` dan SNI tetap hostname asli.
    """

    def test_connect_memakai_ip_pin_bukan_hostname(self):
        calls = []
        fake = [(2, 1, 6, "", ("93.184.216.34", 8080))]
        sock = mock.Mock()

        def fake_create_connection(address, *args, **kwargs):
            calls.append(address)
            return sock

        def fake_getaddrinfo(host, port=None, *args, **kwargs):
            return fake

        with mock.patch.object(chain.socket, "create_connection",
                               side_effect=fake_create_connection), \
                mock.patch.object(chain.socket, "getaddrinfo",
                                  side_effect=fake_getaddrinfo) as gad:
            t = chain.Target("http://fake.invalid:8080/x", verbose=False)
            got = t._connect()

        self.assertIs(got, sock)
        self.assertTrue(calls, "tidak ada percobaan koneksi")
        self.assertEqual(calls[0], ("93.184.216.34", 8080),
                         f"create_connection menerima {calls[0]}")
        self.assertEqual(gad.call_count, 1,
                         f"DNS di-resolve {gad.call_count}x (harus 1)")
        # Host header & SNI tidak berubah: masih hostname, bukan IP.
        self.assertEqual(t.host, "fake.invalid")
        self.assertEqual(t.host_header, "fake.invalid:8080")

    def test_connect_metadata_ditolak_tanpa_menyambung(self):
        """Jawaban DNS ke IMDS = PolicyError, bukan koneksi ke sana."""
        fake = [(2, 1, 6, "", ("169.254.169.254", 80))]
        with mock.patch.object(chain.socket, "create_connection") as conn, \
                mock.patch.object(chain.socket, "getaddrinfo",
                                  return_value=fake):
            t = chain.Target("http://metadata.internal/x", verbose=False)
            with self.assertRaises(chain._policy.PolicyError) as ctx:
                t._connect()
        conn.assert_not_called()
        self.assertIn("metadata", str(ctx.exception).lower())
        self.assertIn("SSRF", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()

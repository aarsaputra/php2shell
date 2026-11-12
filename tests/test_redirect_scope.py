"""Tes regresi R2-02 — scope redirect & DNS rebinding.

Finding R2-02 (audit round 2): pagar sebelumnya hanya memeriksa APAKAH tujuan
redirect itu alamat privat/metadata. Redirect ke domain PUBLIK lain
(`https://attacker.example/callback`) tetap lolos, padahal request sudah
keluar dari scope engagement dan membawa cookie/header tool ke pihak ketiga.

Kontrak yang diuji di sini:
  1. `make_scope()` + `check_scope()` menolak host di luar scope.
  2. Batas subdomain berbasis LABEL, bukan substring
     (`evilexample.com` bukan subdomain `example.com`).
  3. Downgrade https -> http ditolak di semua mode (termasuk `any`).
  4. Perpindahan port ditolak kecuali mode `any`.
  5. `Transport._fetch()` menegakkan scope pada TIAP hop, dan scope dibangun
     dari URL AWAL — bukan dari hop sebelumnya (rantai A->B->C tidak bisa
     dipakai untuk keluar scope bertahap).
  6. DNS rebinding: `resolve_pinned()` hanya sekali dan IP-nya yang dipakai
     untuk koneksi (sudah ada tes terpisah; di sini diuji bahwa `_pin()` tidak
     pernah memanggil resolver lebih dari sekali per request).

Semua tes memakai mock/localhost — tidak ada paket keluar ke internet.
"""

import io
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib import target_policy as policy  # noqa: E402
from lib import transport as transport_mod  # noqa: E402
from lib.transport import Response, Transport  # noqa: E402


class TestNormalizeHostname(unittest.TestCase):
    def test_lowercase_dan_titik_akhir(self):
        self.assertEqual(policy.normalize_hostname("Example.COM."), "example.com")
        self.assertEqual(policy.normalize_hostname("  EXAMPLE.com  "), "example.com")

    def test_bracket_ipv6_dan_ipv4_mapped(self):
        self.assertEqual(policy.normalize_hostname("[::1]"), "::1")
        self.assertEqual(policy.normalize_hostname("::ffff:127.0.0.1"), "127.0.0.1")

    def test_idna_unicode_menjadi_punycode(self):
        self.assertEqual(policy.normalize_hostname("exämple.com"),
                         "xn--exmple-cua.com")

    def test_homoglyph_tidak_sama_dengan_ascii(self):
        # 'а' (Cyrillic a, U+0430) bukan 'a' ASCII: punycode berbeda.
        cyrillic = policy.normalize_hostname("ex\u0430mple.com")
        self.assertNotEqual(cyrillic, "example.com")


class TestHostInScope(unittest.TestCase):
    def test_host_harus_sama_persis_pada_mode_host(self):
        scope = policy.make_scope("https://app.example.com/x.php", "host")
        self.assertTrue(policy.host_in_scope("app.example.com", scope))
        self.assertTrue(policy.host_in_scope("APP.example.com.", scope))
        self.assertFalse(policy.host_in_scope("api.example.com", scope))
        self.assertFalse(policy.host_in_scope("example.com", scope))

    def test_subdomain_boundary_bukan_substring(self):
        """`evilexample.com` BUKAN subdomain `example.com`."""
        scope = policy.make_scope("https://example.com/", "subdomains")
        self.assertTrue(policy.host_in_scope("example.com", scope))
        self.assertTrue(policy.host_in_scope("api.example.com", scope))
        self.assertTrue(policy.host_in_scope("a.b.example.com", scope))
        self.assertFalse(policy.host_in_scope("evilexample.com", scope))
        self.assertFalse(policy.host_in_scope("example.com.evil.net", scope))

    def test_ip_tidak_punya_subdomain(self):
        scope = policy.make_scope("https://10.1.2.3/", "subdomains")
        self.assertTrue(policy.host_in_scope("10.1.2.3", scope))
        self.assertFalse(policy.host_in_scope("1.2.3", scope))
        self.assertFalse(policy.host_in_scope("110.1.2.3", scope))

    def test_mode_any_menerima_host_apa_pun(self):
        scope = policy.make_scope("https://example.com/", "any")
        self.assertTrue(policy.host_in_scope("totally.other.net", scope))

    def test_mode_asing_ditolak(self):
        with self.assertRaises(policy.PolicyError):
            policy.make_scope("https://example.com/", "wildcard")
        with self.assertRaises(policy.PolicyError):
            policy.RedirectScope(host="x", scheme="https", port=443, mode="bogus")


class TestCheckScope(unittest.TestCase):
    def setUp(self):
        self.scope = policy.make_scope("https://app.example.com/x.php")

    def test_host_sama_lintas_path_diizinkan(self):
        policy.check_scope("https://app.example.com/other/path?q=1", self.scope)

    def test_http_ke_https_diizinkan(self):
        scope = policy.make_scope("http://app.example.com/x.php")
        policy.check_scope("https://app.example.com/x.php", scope)

    def test_downgrade_https_ke_http_ditolak(self):
        with self.assertRaises(policy.PolicyError) as ctx:
            policy.check_scope("http://app.example.com/x.php", self.scope)
        self.assertIn("https -> http", str(ctx.exception))

    def test_domain_lain_ditolak(self):
        with self.assertRaises(policy.PolicyError) as ctx:
            policy.check_scope("https://attacker.example/cb", self.scope)
        self.assertIn("keluar scope", str(ctx.exception))

    def test_port_lain_ditolak(self):
        with self.assertRaises(policy.PolicyError) as ctx:
            policy.check_scope("https://app.example.com:8443/x", self.scope)
        self.assertIn("port", str(ctx.exception))

    def test_port_lain_diizinkan_pada_mode_any(self):
        scope = policy.make_scope("https://app.example.com/", "any")
        policy.check_scope("https://app.example.com:8443/x", scope)

    def test_metadata_tetap_ditolak_lewat_check_url(self):
        """Scope `any` tidak boleh membuka metadata cloud (pagar IP lebih dulu)."""
        scope = policy.make_scope("https://app.example.com/", "any")
        with self.assertRaises(policy.PolicyError):
            policy.check_url("http://169.254.169.254/latest/meta-data/")
        # check_scope sendiri hanya soal host; pagar IP ditegakkan check_url.

    def test_skema_aneh_ditolak(self):
        with self.assertRaises(policy.PolicyError):
            policy.check_scope("file:///etc/passwd", self.scope)


class TestFetchEnforcesScope(unittest.TestCase):
    """`_fetch` harus menolak hop yang keluar scope, tanpa mengirimnya."""

    def _transport(self, **kw):
        return Transport(delay=0.0, retries=0, allow_private=True, **kw)

    def test_redirect_ke_domain_lain_tidak_dikirim(self):
        t = self._transport()
        sent = []

        def fake_single(method, url, data, headers):
            sent.append(url)
            return Response(url=url, status=302,
                            headers={"location": "https://attacker.example/cb"})

        with mock.patch.object(t, "_single", side_effect=fake_single):
            r = t.request("GET", "http://127.0.0.1:9/x.php")
        self.assertEqual(len(sent), 1, f"hop keluar scope ikut dikirim: {sent}")
        self.assertEqual(r.status, 0)
        self.assertIn("scope", r.error.lower())

    def test_rantai_bertahap_tidak_bisa_keluar_scope(self):
        """A -> B -> C: B masih sama-host, C domain lain. C tidak dikirim."""
        t = self._transport()
        sent = []

        def fake_single(method, url, data, headers):
            sent.append(url)
            if url.endswith("/a"):
                return Response(url=url, status=302, headers={"location": "/b"})
            if url.endswith("/b"):
                return Response(url=url, status=302,
                                headers={"location": "https://evil.example/c"})
            return Response(url=url, status=200, body="harusnya tidak sampai")

        with mock.patch.object(t, "_single", side_effect=fake_single):
            r = t.request("GET", "http://127.0.0.1:9/a")
        self.assertEqual(sent, ["http://127.0.0.1:9/a", "http://127.0.0.1:9/b"])
        self.assertEqual(r.status, 0)
        self.assertIn("scope", r.error.lower())

    def test_redirect_sama_host_diikuti(self):
        t = self._transport()
        sent = []

        def fake_single(method, url, data, headers):
            sent.append(url)
            if url.endswith("/a"):
                return Response(url=url, status=302, headers={"location": "/b"})
            return Response(url=url, status=200, body="ok")

        with mock.patch.object(t, "_single", side_effect=fake_single):
            r = t.request("GET", "http://127.0.0.1:9/a")
        self.assertEqual(r.status, 200)
        self.assertEqual(r.body, "ok")
        self.assertEqual(len(sent), 2)

    def test_mode_subdomains_mengizinkan_subdomain(self):
        t = self._transport(redirect_scope="subdomains")
        sent = []

        def fake_single(method, url, data, headers):
            sent.append(url)
            if len(sent) == 1:
                return Response(url=url, status=302,
                                headers={"location": "http://api.localhost:9/b"})
            return Response(url=url, status=200, body="ok")

        with mock.patch.object(t, "_single", side_effect=fake_single):
            r = t.request("GET", "http://localhost:9/a")
        self.assertEqual(r.status, 200)
        self.assertEqual(sent[-1], "http://api.localhost:9/b")

    def test_mode_host_menolak_subdomain(self):
        t = self._transport()   # default: host
        sent = []

        def fake_single(method, url, data, headers):
            sent.append(url)
            return Response(url=url, status=302,
                            headers={"location": "http://api.localhost:9/b"})

        with mock.patch.object(t, "_single", side_effect=fake_single):
            r = t.request("GET", "http://localhost:9/a")
        self.assertEqual(len(sent), 1)
        self.assertIn("scope", r.error.lower())

    def test_redirect_scope_tidak_dikenal_ditolak_saat_init(self):
        with self.assertRaises(ValueError):
            Transport(delay=0.0, redirect_scope="everything")

    def test_proxy_mematikan_pin_dns_dan_itu_dinyatakan(self):
        """Audit R2-02 meminta perilaku proxy didokumentasikan SECARA AKURAT.

        Kontrak yang benar (dan diuji di sini): bila `proxy` diset, PIN DNS
        TIDAK dipasang — proxy yang melakukan resolusi. Yang TIDAK boleh
        terjadi: klaim bahwa pin tetap berlaku. Tes ini mengunci kode agar
        tidak memasang `CURLOPT_RESOLVE` saat proxy aktif (itu akan membuat
        request mengabaikan proxy / gagal), sehingga perilaku residual ini
        tetap jujur dan tidak berubah diam-diam.
        """
        t = Transport(delay=0.0, retries=0, proxy="http://127.0.0.1:3128",
                      allow_private=True)
        self.assertTrue(t._pin_disabled_by_proxy,
                        "penanda pin-nonaktif tidak diset saat proxy aktif")
        calls = {}

        class FakeSession:
            curl_options = {}
            closed = False

            def request(self, method, url, **kw):
                calls["curl_options"] = dict(self.curl_options)
                calls["proxies"] = kw.get("proxies")
                raise RuntimeError("stop-here")   # jangan benar-benar mengirim

            def close(self):
                self.closed = True

        with mock.patch.object(t, "_session", FakeSession()):
            try:
                t._single("GET", "http://example.com/x.php", None, None)
            except Exception:  # noqa: BLE001 - exception dari FakeSession
                pass
        self.assertIn("proxies", calls, "request tidak sampai ke session")
        self.assertEqual(calls["proxies"],
                         {"http": "http://127.0.0.1:3128",
                          "https": "http://127.0.0.1:3128"})
        # INTI: tanpa CURLOPT_RESOLVE, proxy yang resolve. Pin TIDAK diklaim.
        self.assertEqual(calls["curl_options"], {},
                         "pin DNS dipasang padahal proxy aktif — perilaku "
                         "residual proxy berubah tanpa dokumentasi")

    def test_cli_mencetak_peringatan_proxy(self):
        """Batas proxy harus TERBACA oleh operator, bukan hanya di dokumen."""
        import importlib
        cli = importlib.import_module("php2shell")
        args = mock.Mock(
            ja3="chrome", delay=0.0, timeout=5, proxy="http://127.0.0.1:3128",
            audit=None, verbose=False, insecure=False,
            no_follow_redirects=False, allow_private_target=True,
            redirect_scope="host")
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            t = cli._mk_transport(args)
        try:
            out = buf.getvalue()
            self.assertIn("--proxy aktif", out)
            self.assertIn("PIN DNS tidak berlaku", out)
            self.assertTrue(t._pin_disabled_by_proxy)
        finally:
            t.close()

    def test_tanpa_proxy_tidak_ada_peringatan(self):
        import importlib
        cli = importlib.import_module("php2shell")
        args = mock.Mock(
            ja3="chrome", delay=0.0, timeout=5, proxy=None, audit=None,
            verbose=False, insecure=False, no_follow_redirects=False,
            allow_private_target=True, redirect_scope="host")
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            t = cli._mk_transport(args)
        try:
            self.assertNotIn("PIN DNS tidak berlaku", buf.getvalue())
            self.assertFalse(t._pin_disabled_by_proxy)
        finally:
            t.close()

    def test_tanpa_proxy_pin_dns_dipasang(self):
        t = Transport(delay=0.0, retries=0, allow_private=True)
        calls = {}

        class FakeSession:
            curl_options = {}
            closed = False

            def request(self, method, url, **kw):
                calls["curl_options"] = dict(self.curl_options)
                raise RuntimeError("stop-here")

            def close(self):
                self.closed = True

        with mock.patch.object(t, "_session", FakeSession()):
            try:
                t._single("GET", "http://example.com/x.php", None, None)
            except Exception:  # noqa: BLE001
                pass
        self.assertTrue(calls.get("curl_options"),
                        "pin DNS tidak dipasang walau tanpa proxy")

    def test_urllib_jalur_selalu_mematikan_proxy_environment(self):
        """`ProxyHandler({})` wajib ada: proxy env akan membatalkan pin."""
        import inspect
        src = inspect.getsource(transport_mod.Transport._single)
        self.assertIn("ProxyHandler({})", src,
                      "proxy environment bisa membelokkan koneksi, pin jadi hiasan")

    def test_dns_pin_hanya_sekali_per_request(self):
        """`_pin()` memakai resolve_pinned() tepat sekali per request."""
        t = self._transport()
        calls = []

        def fake_resolve(host, port, allow_private=False):
            calls.append((host, port))
            return "127.0.0.1"

        t._single = Transport._single.__get__(t)  # pastikan metode asli terpasang
        with mock.patch.object(policy, "resolve_pinned", side_effect=fake_resolve):
            with mock.patch.object(t, "_session", None):
                # Tidak benar-benar mengirim: pin dipanggil lalu urllib akan
                # mencoba konek. Kita hanya perlu memastikan jumlah panggilan.
                try:
                    t._pin("http://localhost:9/x")
                except Exception:  # noqa: BLE001
                    pass
        self.assertEqual(calls, [("localhost", 9)])


if __name__ == "__main__":
    unittest.main(verbosity=2)

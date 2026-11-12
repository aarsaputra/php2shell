"""Tes regresi R2-05 — hardening Docker lab.

Finding R2-05: lab hanya mengikat port ke localhost, tetapi
  * outbound network isolation belum ada (container bisa keluar),
  * capabilities default (termasuk NET_RAW, MKNOD, ...) masih utuh,
  * `no-new-privileges` belum diterapkan,
  * rootfs masih writable,
  * /out di-chown dari DALAM container ke www-data (uid 33) sehingga
    kepemilikan path host berubah dan worker butuh DAC_OVERRIDE/FOWNER.

Tes di sini punya dua lapis:
  A. Konfigurasi (selalu jalan): `docker-compose.yml` dan `lab_docker.sh`
     harus memuat setiap kontrol. Ini mencegah regresi "YAML-nya hilang"
     tanpa butuh Docker.
  B. Verifikasi hidup (skipped bila Docker/daemon tidak ada): inspect
     container yang benar-benar berjalan dan buktikan isolasinya.

Lapis B TIDAK PERNAH menggantikan lapis A: image yang tidak tersedia di CI
tidak boleh membuat tes ini "lulus" secara diam-diam — karena itu lapis A
selalu dieksekusi lebih dulu.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
COMPOSE = os.path.join(ROOT, "docker", "docker-compose.yml")
LAB_SH = os.path.join(ROOT, "lab", "lab_docker.sh")
DOCKERFILE = os.path.join(ROOT, "docker", "Dockerfile")
LAB_CONTAINER = os.environ.get("P2S_LAB_CONTAINER", "p2s-lab-8426")


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _docker(*args, timeout=20):
    """Jalankan docker; return (rc, stdout). rc=-1 bila docker tidak ada."""
    if not shutil.which("docker"):
        return -1, ""
    try:
        p = subprocess.run(["docker", *args], capture_output=True, text=True,
                           timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return -1, ""
    return p.returncode, p.stdout


class TestComposeConfig(unittest.TestCase):
    """Lapis A — kontrol harus TERTULIS di konfigurasi."""

    @classmethod
    def setUpClass(cls):
        cls.yml = _read(COMPOSE)
        try:
            import yaml  # noqa: F401
            cls.cfg = yaml.safe_load(cls.yml)
        except ImportError:  # pragma: no cover
            cls.cfg = None

    def test_network_internal(self):
        self.assertIn("internal: true", self.yml,
                      "jaringan lab tidak lagi internal (egress terbuka)")

    def test_cap_drop_all(self):
        self.assertIn("cap_drop:", self.yml)
        self.assertIn("- ALL", self.yml)

    def test_tidak_ada_capability_berbahaya(self):
        for bad in ("NET_ADMIN", "NET_RAW", "SYS_ADMIN", "SYS_PTRACE",
                    "DAC_OVERRIDE", "FOWNER", "MKNOD", "SYS_MODULE"):
            self.assertNotIn(bad, self.yml,
                             f"capability berbahaya {bad} tidak boleh diminta")

    def test_no_new_privileges(self):
        self.assertIn("no-new-privileges:true", self.yml)

    def test_read_only_rootfs(self):
        self.assertIn("read_only: true", self.yml)

    def test_tidak_privileged(self):
        self.assertNotIn("privileged: true", self.yml)

    def test_resource_limits(self):
        for key in ("pids_limit:", "mem_limit:", "cpus:"):
            self.assertIn(key, self.yml, f"{key} hilang")

    def test_tidak_ada_port_publish_langsung(self):
        """Port hanya lewat relay; service target sendiri tidak publish."""
        if self.cfg:
            svc = self.cfg["services"]["target"]
            self.assertNotIn("ports", svc,
                             "target mem-publish port dari jaringan internal")
            self.assertIn("lab", svc["networks"])
        self.assertNotIn('"127.0.0.1:8088:80"', self.yml)

    def test_tidak_chown_path_host_dari_container(self):
        """Tidak boleh ada `-o www-data`/chgrp pada mount host.

        Hanya baris NON-komentar yang diperiksa: komentar menjelaskan bahwa
        pola lama sudah dihapus, dan penjelasan itu sendiri bukan pelanggaran.
        """
        aktif = "\n".join(
            line for line in self.yml.splitlines()
            if not line.lstrip().startswith("#"))
        self.assertNotIn("-o www-data", aktif)
        self.assertNotIn("chgrp www-data", aktif)
        self.assertNotIn("install -d -m 0770", aktif)

    def test_out_satu_satunya_mount_rw(self):
        if not self.cfg:
            self.skipTest("yaml tidak tersedia")
        vols = self.cfg["services"]["target"]["volumes"]
        rw = [v for v in vols if not v.endswith(":ro")]
        self.assertEqual(len(rw), 1, f"mount rw lebih dari satu: {rw}")
        self.assertTrue(rw[0].endswith(":/out:rw"), rw)


class TestLabScript(unittest.TestCase):
    """Lapis A — skrip lab yang dipakai operator sehari-hari."""

    @classmethod
    def setUpClass(cls):
        cls.src = _read(LAB_SH)

    def test_memakai_jaringan_internal(self):
        self.assertIn("--internal", self.src)
        self.assertIn("--network \"$NET\"", self.src)

    def test_capability_dan_readonly_di_run(self):
        for flag in ("--cap-drop ALL", "--read-only",
                     "--security-opt no-new-privileges:true",
                     "--pids-limit", "--memory", "--cpus"):
            self.assertIn(flag, self.src, f"{flag} hilang dari lab_docker.sh")

    def test_target_tidak_publish_port(self):
        self.assertNotIn('-p "127.0.0.1:$PORT:80"', self.src)

    def test_relay_satu_satunya_publish(self):
        self.assertIn('-p "127.0.0.1:$PORT:8080"', self.src)
        self.assertIn("socat", self.src)

    def test_destroy_membersihkan_relay_dan_network(self):
        destroy = self.src.split("destroy)", 1)[1]
        self.assertIn("-relay", destroy)
        self.assertIn("network rm", destroy)


class TestDockerfileMapping(unittest.TestCase):
    def test_uid_gid_mapping_ada(self):
        src = _read(DOCKERFILE)
        self.assertIn("P2S_UID", src)
        self.assertIn("P2S_GID", src)
        self.assertIn("APACHE_RUN_USER", src)
        self.assertNotIn("USER root", src)


class TestComposeEquivalence(unittest.TestCase):
    """RR-5: jalur `docker compose` harus setara dengan `docker run` eksplisit.

    Sebelumnya compose tidak bisa dijalankan (plugin tidak terpasang), jadi
    `docker-compose.yml` hanya diuji sebagai teks. Sekarang plugin tersedia:
    `docker compose config` merender konfigurasi final, dan tes ini memastikan
    NILAI YANG DIRENDER sama dengan yang dibuktikan hidup di jalur `docker run`
    (readonly, cap_drop, no-new-privileges, limits, network internal).
    """

    @classmethod
    def setUpClass(cls):
        cls.out = None
        if not shutil.which("docker"):
            raise unittest.SkipTest("docker tidak terpasang")
        env = dict(os.environ, P2S_UID=str(os.getuid()), P2S_GID=str(os.getgid()))
        try:
            p = subprocess.run(
                ["docker", "compose", "config"],
                cwd=os.path.dirname(COMPOSE), capture_output=True, text=True,
                timeout=120, env=env,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            raise unittest.SkipTest(f"docker compose tidak bisa dipanggil: {exc}")
        if p.returncode != 0:
            raise unittest.SkipTest(
                f"docker compose tidak tersedia/gagal (rc={p.returncode}): "
                f"{(p.stderr or '')[:200]}")
        cls.out = p.stdout

    def test_render_memuat_semua_kontrol(self):
        assert self.out is not None
        for needle in ("read_only: true", "no-new-privileges:true",
                       "internal: true", "pids_limit: 256",
                       "P2S_UID", "P2S_GID"):
            with self.subTest(needle=needle):
                self.assertIn(needle, self.out,
                              f"{needle!r} hilang dari config yang dirender compose")

    def test_render_mem_limit_setara(self):
        """`mem_limit: 512m` dinormalkan compose ke byte; nilainya harus sama."""
        assert self.out is not None
        m = re.search(r"mem_limit:\s*\"?(\d+)\"?", self.out)
        self.assertIsNotNone(m, "mem_limit hilang dari config yang dirender")
        if m is None:  # pragma: no cover - sudah diasersi di atas
            return
        self.assertEqual(int(m.group(1)), 512 * 1024 * 1024,
                         f"mem_limit dirender {m.group(1)} byte, bukan 512 MiB")

    def test_render_cpu_setara(self):
        assert self.out is not None
        m = re.search(r"cpus:\s*([\d.]+)", self.out)
        self.assertIsNotNone(m, "cpus hilang dari config yang dirender")
        if m is None:  # pragma: no cover
            return
        self.assertEqual(float(m.group(1)), 2.0)

    def test_render_cap_drop_all(self):
        assert self.out is not None
        # compose merender cap_drop sebagai list dengan satu entri ALL
        self.assertRegex(self.out, r"cap_drop:\s*\n\s*-\s*ALL")

    def test_render_tidak_publish_port(self):
        assert self.out is not None
        self.assertNotIn("published:", self.out,
                         "config compose mem-publish port untuk target")
        self.assertIn('expose:\n      - "80"', self.out)


@unittest.skipUnless(shutil.which("docker"), "docker tidak terpasang")
class TestLiveIsolation(unittest.TestCase):
    """Lapis B — container yang benar-benar berjalan (skip bila tidak ada)."""

    @classmethod
    def setUpClass(cls):
        rc, out = _docker("inspect", LAB_CONTAINER)
        if rc != 0:
            raise unittest.SkipTest(
                f"container {LAB_CONTAINER} tidak berjalan; "
                f"jalankan `bash lab/lab_docker.sh start` untuk bukti hidup")
        cls.info = json.loads(out)[0]

    def test_readonly_rootfs(self):
        self.assertTrue(self.info["HostConfig"]["ReadonlyRootfs"])

    def test_tidak_privileged(self):
        self.assertFalse(self.info["HostConfig"]["Privileged"])

    def test_cap_drop_all(self):
        self.assertEqual(self.info["HostConfig"]["CapDrop"], ["ALL"])

    def test_cap_add_minimal(self):
        added = set(self.info["HostConfig"]["CapAdd"] or [])
        allowed = {"CAP_CHOWN", "CAP_NET_BIND_SERVICE", "CAP_SETUID",
                   "CAP_SETGID"}
        self.assertTrue(added <= allowed, f"capability berlebih: {added - allowed}")

    def test_no_new_privileges(self):
        opts = self.info["HostConfig"]["SecurityOpt"] or []
        self.assertTrue(any("no-new-privileges" in o for o in opts), opts)

    def test_resource_limits_hidup(self):
        hc = self.info["HostConfig"]
        self.assertEqual(hc["PidsLimit"], 256)
        self.assertEqual(hc["Memory"], 512 * 1024 * 1024)
        self.assertGreater(hc["NanoCpus"], 0)

    def test_target_tanpa_port_publish(self):
        self.assertEqual(self.info["HostConfig"]["PortBindings"], {})
        self.assertEqual(self.info["NetworkSettings"]["Ports"], {})

    def test_network_internal(self):
        net = self.info["HostConfig"]["NetworkMode"]
        rc, out = _docker("network", "inspect", net)
        self.assertEqual(rc, 0, f"network {net} tidak ada")
        self.assertTrue(json.loads(out)[0]["Internal"],
                        f"network {net} tidak internal")

    def test_worker_uid_mapping_ke_pemilik_repo(self):
        """/out di host harus tetap milik operator, bukan www-data."""
        rc, out = _docker("exec", LAB_CONTAINER, "stat", "-c", "%u:%g", "/out")
        if rc != 0:
            self.skipTest(f"tidak bisa stat /out di container (rc={rc})")
        self.assertEqual(out.strip(), f"{os.getuid()}:{os.getgid()}",
                         "kepemilikan /out berubah — chown dari container?")

    def test_tidak_bisa_keluar_jaringan(self):
        """Bukti egress tertutup: koneksi TCP keluar harus gagal."""
        rc, out = _docker(
            "exec", LAB_CONTAINER, "sh", "-c",
            'timeout 5 bash -c "exec 3<>/dev/tcp/1.1.1.1/443" 2>&1; echo rc=$?')
        self.assertEqual(rc, 0, f"docker exec gagal: {out}")
        self.assertIn("rc=1", out, f"target masih bisa keluar: {out}")

    def test_dns_gagal(self):
        rc, out = _docker("exec", LAB_CONTAINER, "getent", "hosts", "example.com")
        self.assertNotEqual(rc, 0, f"DNS masih resolve: {out}")


if __name__ == "__main__":
    unittest.main(verbosity=2)

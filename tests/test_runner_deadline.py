"""Tes pengaman run(): deadline absolut, whitelist murni, gate memori, TLS.

Semua tes di sini TANPA jaringan: `memprobe.probe`, `chain.Target`, dan
`chain.Chain` diganti objek palsu, dan jam diganti `FakeClock` yang hanya
maju kalau tes menyuruhnya. Jadi tidak ada byte yang keluar ke host mana pun.

Yang dikunci:
  1. deadline absolut — satu `deadline`, sisa waktu dihitung ulang tiap stage,
     timeout per operasi = min(sisa, timeout), dan sisa <= 0 menghasilkan error
     yang MENYEBUT stage (bukan "HEAP_LEAK_FAILED" yang menyesatkan);
  2. `resolve_whitelist()` murni — tidak membaca/menulis global;
  3. `run(allowed_cmds=...)` memakai whitelist itu, bukan global;
  4. `memory_limit` di atas plafon aman menghentikan run SEBELUM payload;
  5. `insecure=True` → Target(verify_tls=False), default tetap verifikasi;
  6. gerbang preflight bisa dilewati `force`, gate memori tidak.
"""

import os
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from lib import chain as chain_mod          # noqa: E402
from lib import exploit_runner as er        # noqa: E402
from lib import memprobe                    # noqa: E402
from lib.detect import Detection            # noqa: E402

MIB = 1024 ** 2
URL = "http://127.0.0.1:9/upload.php"

FATAL_8M = b"<b>Fatal error</b>:  Allowed memory size of 8388608 bytes exhausted"
FATAL_600M = b"Allowed memory size of 629145600 bytes exhausted"


# ------------------------------------------------------------------ fakes ---

class FakeClock:
    """Jam yang hanya maju bila diminta — tidak ada sleep, tidak ada flake."""

    def __init__(self, now: float = 1000.0):
        self.now = float(now)

    def __call__(self) -> float:
        return self.now

    def advance(self, d: float) -> None:
        self.now += float(d)


class FakeTarget:
    """Target palsu: mencatat timeout tiap kali dipakai, tidak membuka soket."""

    instances: list["FakeTarget"] = []

    def __init__(self, url, timeout=30.0, verbose=True, verify_tls=True,
                 deadline=None):
        self.url = url
        self.verbose = verbose
        self.verify_tls = verify_tls
        self.timeouts = []
        self.gets = []
        self.log = lambda _m: None
        self._timeout = float(timeout)
        self.timeouts.append(self._timeout)
        # Ditiru dari chain.Target: deadline absolut + op_timeout, supaya tes
        # bisa menguji propagasi tanpa soket.
        self.deadline = deadline
        FakeTarget.instances.append(self)

    def remaining(self):
        if self.deadline is None:
            return None
        return self.deadline - er._clock()

    def op_timeout(self, prefer):
        left = self.remaining()
        if left is None:
            return float(prefer)
        if left <= 0:
            raise chain_mod.DeadlineExceeded("operasi jaringan", left)
        return max(min(float(prefer), left), chain_mod.MIN_OP_TIMEOUT)

    # timeout adalah PROPERTI: yang diuji justru penulisan `target.timeout`
    # oleh `_arm()` sebelum tiap operasi, bukan nilai saat konstruksi.
    @property
    def timeout(self) -> float:
        return self._timeout

    @timeout.setter
    def timeout(self, value) -> None:
        self._timeout = float(value)
        self.timeouts.append(self._timeout)

    def get(self, path=None, read_cap=None):
        self.gets.append(path)
        return 0, b""


class FakeChain:
    """Rantai palsu: stage1/2 selalu meleset kecuali tes mengatur hasilnya."""

    made: list["FakeChain"] = []

    def __init__(self, target, cmd, **kw):
        self.t = target
        self.cmd = cmd
        self.kw = kw
        self.zif_offset = kw.get("zif_offset") or 0x111
        self.dtor_offset = kw.get("dtor_offset") or 0x222
        self.htdata_offset = kw.get("htdata_offset") or 0x333
        self.huge_mb = kw.get("huge_mb")
        self.calls = []          # ("stage1", timeout-saat-itu), ...
        self.rotates = 0
        self.stage1_results = []
        self.stage2_results = []
        self.on_stage = None     # callback(clock, chain, name)
        FakeChain.made.append(self)

    def _enter(self, name):
        self.calls.append((name, getattr(self.t, "timeout", None)))
        if self.on_stage:
            self.on_stage(name, self)

    def rotate(self):
        self._enter("rotate")
        self.rotates += 1

    def stage1(self):
        self._enter("stage1")
        return self.stage1_results.pop(0) if self.stage1_results else 0

    def stage2(self):
        self._enter("stage2")
        return self.stage2_results.pop(0) if self.stage2_results else 0

    def stage3(self, htdata, zif):
        self._enter("stage3")


def _det(**kw):
    base = dict(url=URL, reachable=True, status=200, php_version="8.4.26",
                branch="8.4", verdict="vulnerable", fix_floor="8.4.27",
                upload_progress="on", display_errors="on")
    base.update(kw)
    return Detection(**base)


@pytest.fixture
def sandbox(monkeypatch):
    """Ganti semua I/O: probe, Target, Chain, dan jam."""
    clock = FakeClock()
    FakeTarget.instances = []
    FakeChain.made = []
    # Default probe: limit 8 MiB terbaca (bukan unknown). Tes yang menguji
    # jalur "limit tidak terbaca" menyetel state["limit"] = None EKSPLISIT,
    # karena sejak audit itu berhenti sebelum request rantai mana pun.
    state = {"limit": 8 * MIB, "resp": FATAL_8M, "probe_calls": 0,
             "clock": clock}

    def fake_probe(url, probe_mb=16, timeout=45.0, verbose=False,
                   deadline=None):
        # `deadline` diterima dan dicatat: probe 16 MB ikut anggaran total,
        # jadi pemanggil wajib meneruskannya (dan tes mengunci itu).
        state["probe_calls"] += 1
        state["probe_timeout"] = timeout
        state["probe_deadline"] = deadline
        return state["limit"], state["resp"]

    monkeypatch.setattr(er, "_clock", clock)
    monkeypatch.setattr(er.memprobe, "probe", fake_probe)
    monkeypatch.setattr(chain_mod, "Target", FakeTarget)
    monkeypatch.setattr(chain_mod, "Chain", FakeChain)
    # stage 3 memanggil jeda 0.8s di antara percobaan: tanpa ini tes butuh
    # detik-detik nyata dan hasilnya bergantung beban mesin. Kita tambal seam
    # milik modul (_sleep), BUKAN time.sleep stdlib — menambal stdlib menggeser
    # modul lain yang berjalan paralel.
    monkeypatch.setattr(er, "_sleep", lambda _s: None)
    return state


def _run(**kw):
    kw.setdefault("quiet", True)
    kw.setdefault("log", lambda _m: None)
    return er.run(URL, **kw)


# ------------------------------------------------------- deadline absolut ---

def test_deadline_habis_menyebut_stage(sandbox):
    """Sisa habis di tengah stage 1 -> error menyebut stage, bukan LEAK_FAILED."""
    clock = er._clock

    def on_stage(name, chain):
        if name == "stage1":
            clock.advance(120)   # lompati deadline di tengah percobaan

    class Wired(FakeChain):
        def __init__(self, target, cmd, **kw):
            super().__init__(target, cmd, **kw)
            self.on_stage = on_stage

    import lib.chain as cm
    orig = cm.Chain
    cm.Chain = Wired
    try:
        res = _run(max_total_timeout=60, timeout=30, retries=3)
    finally:
        cm.Chain = orig
    assert res.success is False
    assert "DEADLINE" in res.error, res.error
    assert "stage 1" in res.error, res.error
    assert "HEAP_LEAK_FAILED" not in res.error
    # Stage 2 tidak boleh pernah disentuh.
    assert all(c[0] != "stage2" for c in FakeChain.made[0].calls)


def test_timeout_per_operasi_adalah_min_sisa_dan_timeout(sandbox):
    """timeout Target mengikuti sisa waktu: 30 -> 10 saat sisa tinggal 10s."""
    clock = er._clock

    def on_stage(name, chain):
        if name == "stage1":
            clock.advance(90)    # 100 - 90 = 10s tersisa

    class Wired(FakeChain):
        def __init__(self, target, cmd, **kw):
            super().__init__(target, cmd, **kw)
            self.on_stage = on_stage

    import lib.chain as cm
    orig = cm.Chain
    cm.Chain = Wired
    try:
        res = _run(max_total_timeout=100, timeout=30, retries=3)
    finally:
        cm.Chain = orig

    tgt = FakeTarget.instances[0]
    # Normal 30s saat sisa masih 100s, lalu ditahan ke 10s saat sisa 10s.
    assert 30 in tgt.timeouts, tgt.timeouts
    assert 10 in tgt.timeouts, tgt.timeouts
    assert max(tgt.timeouts) <= 30.0, tgt.timeouts
    # Jam palsu: run harus berhenti karena deadline, bukan LEAK_FAILED.
    assert "DEADLINE" in res.error, res.error


def test_deadline_tidak_pernah_dilaporkan_sebagai_leak_gagal(sandbox):
    """max_total_timeout=0: jam habis SEBELUM probe -> sebut tahapnya.

    Paling penting: tidak ada request yang keluar dan tidak ada klaim
    "HEAP_LEAK_FAILED" — payload memang belum pernah dikirim.
    """
    res = _run(max_total_timeout=0, timeout=30, retries=3)
    assert res.success is False
    assert "DEADLINE" in res.error, res.error
    assert "probe memory_limit" in res.error, res.error
    assert "HEAP_LEAK_FAILED" not in res.error
    assert sandbox["probe_calls"] == 0
    assert FakeChain.made == []


def test_deadline_habis_sebelum_koneksi_awal(sandbox, monkeypatch):
    """Jam habis setelah probe, sebelum Target dibuat -> 'koneksi awal'.

    Bukan crash, dan bukan HEAP_LEAK_FAILED: tidak ada koneksi yang dibuka.
    """
    clock = er._clock
    inner = er.memprobe.probe          # probe palsu dari fixture, bukan jaringan

    def slow_probe(*a, **kw):
        out = inner(*a, **kw)
        clock.advance(50)              # probe lambat: makan seluruh anggaran
        return out

    monkeypatch.setattr(er.memprobe, "probe", slow_probe)
    sandbox["limit"] = 8 * MIB
    res = _run(max_total_timeout=10, timeout=5, retries=1)
    assert res.success is False
    assert "DEADLINE" in res.error, res.error
    assert "koneksi awal" in res.error, res.error
    assert FakeTarget.instances == []
    assert FakeChain.made == []


# ------------------------------------------------------ whitelist murni -----

def test_resolve_whitelist_tanpa_extra_mengembalikan_default():
    wl = er.resolve_whitelist(None)
    assert wl == tuple(er.DEFAULT_ALLOWED_CMDS)
    assert er.resolve_whitelist([]) == wl


def test_resolve_whitelist_menambah_extra_tanpa_duplikat():
    wl = er.resolve_whitelist(["ls", "LS", "/usr/bin/cat", "./pwd", "ls"])
    assert "ls" in wl and "cat" in wl and "pwd" in wl
    assert wl.count("ls") == 1
    assert set(er.DEFAULT_ALLOWED_CMDS) <= set(wl)


def test_resolve_whitelist_menolak_tool_berbahaya():
    for bad in ("bash", "sh", "nc", "curl", "wget", "chmod", "rm"):
        with pytest.raises(ValueError):
            er.resolve_whitelist([bad])


def test_resolve_whitelist_tidak_membersihkan_nama_berdekorasi():
    """"ls;" bukan "ls" yang perlu dirapikan — ia nama lain, dan ditolak.

    Normalisasi hanya membuang path ("/usr/bin/ls"), tidak pernah membuang
    karakter yang bisa berarti chaining. Kalau "ls;" diam-diam menjadi "ls",
    whitelist jadi lebih longgar daripada yang diketik operator.
    """
    with pytest.raises(ValueError):
        er.resolve_whitelist(["ls;"])
    with pytest.raises(ValueError):
        er.resolve_whitelist(["ls;id"])


def test_resolve_whitelist_murni_tidak_menyentuh_global():
    before = er.ALLOWED_CMDS
    er.resolve_whitelist(["ls"])
    assert er.ALLOWED_CMDS == before
    # Dua panggilan berbeda tidak saling memengaruhi (tidak ada state).
    assert er.resolve_whitelist(["ls"]) != er.resolve_whitelist(None)
    assert er.resolve_whitelist(None) == tuple(er.DEFAULT_ALLOWED_CMDS)


def test_set_allowed_cmds_shim_masih_bekerja_untuk_cli_lama():
    before = er.ALLOWED_CMDS
    try:
        wl = er.set_allowed_cmds(["ls"])
        assert "ls" in wl and er.ALLOWED_CMDS == tuple(wl)
        assert er.set_allowed_cmds(None) == list(er.DEFAULT_ALLOWED_CMDS)
    finally:
        er.ALLOWED_CMDS = before


def test_run_memakai_allowed_cmds_bukan_global(sandbox):
    """Global membuka 'ls', tapi run(allowed_cmds=[]) TIDAK boleh ikut."""
    before = er.ALLOWED_CMDS
    er.ALLOWED_CMDS = ("id", "whoami", "ls")
    try:
        assert er.validate_command("ls") == ""            # global membuka
        res = _run(cmd="ls", allowed_cmds=[])
        assert "ditolak" in res.error, res.error
        assert FakeChain.made == []                       # tidak pernah menembak
    finally:
        er.ALLOWED_CMDS = before


def test_run_allowed_cmds_membuka_yang_diminta(sandbox):
    res = _run(cmd="ls", allowed_cmds=["ls"], max_total_timeout=1, timeout=1)
    # Validasi lolos: kegagalan datang dari rantai (bukan dari pagar perintah).
    assert "ditolak" not in res.error, res.error
    assert FakeChain.made, "whitelist lokal harus meloloskan 'ls'"


def test_run_allowed_cmds_menolak_nama_berbahaya(sandbox):
    with pytest.raises(ValueError):
        _run(cmd="id", allowed_cmds=["bash"])


# -------------------------------------------------------- plafon memori ----

def test_exceeds_safe_ceiling_berhenti_sebelum_kirim_payload(sandbox):
    sandbox["limit"] = 600 * MIB
    sandbox["resp"] = FATAL_600M
    with pytest.raises(RuntimeError) as ei:
        _run(huge_mb=None)
    msg = str(ei.value)
    assert "600 MiB" in msg and "512 MiB" in msg
    assert "batas aman" in msg
    assert "--huge-mb" in msg
    # Belum satu pun request rantai dikirim.
    assert FakeChain.made == []
    assert FakeTarget.instances == []


def test_plafon_memori_tidak_bisa_dilewati_force(sandbox):
    """force melewati pra-syarat preflight, BUKAN fakta fisik memory_limit."""
    sandbox["limit"] = 600 * MIB
    sandbox["resp"] = FATAL_600M
    with pytest.raises(RuntimeError):
        _run(force=True)
    assert FakeChain.made == []


def test_limit_di_bawah_plafon_tidak_berhenti(sandbox):
    sandbox["limit"] = 8 * MIB
    sandbox["resp"] = FATAL_8M
    res = _run(max_total_timeout=1, timeout=1, retries=1)
    assert FakeChain.made, "limit wajar harus tetap jalan ke rantai"
    assert "batas aman" not in res.error
    assert FakeChain.made[0].huge_mb == memprobe.huge_mb_for(8 * MIB)


def test_huge_mb_eksplisit_melewati_probe_dan_plafon(sandbox):
    res = _run(huge_mb=700, max_total_timeout=1, timeout=1, retries=1)
    assert sandbox["probe_calls"] == 0
    assert "batas aman" not in res.error
    assert FakeChain.made[0].huge_mb == 700


def test_memory_limit_tidak_terbaca_menghentikan_eksploitasi(sandbox):
    """Temuan audit P1: limit unknown + tanpa --huge-mb -> BERHENTI, bukan 12 MB.

    Melanjutkan dengan default 12 MB berarti menembak buta: pada target 128M,
    stage 1 tidak akan OOM dan hasilnya HEAP_LEAK_FAILED yang menyesatkan.
    """
    sandbox["limit"] = None          # probe 16 MiB tidak membocorkan angkanya
    sandbox["resp"] = b"<html>ok</html>"
    with pytest.raises(er.UnknownMemoryLimit) as ei:
        _run(huge_mb=None)
    msg = str(ei.value)
    assert "tidak terbaca" in msg, msg
    assert "--huge-mb" in msg, msg
    # Tidak satu pun request rantai dikirim: gerbangnya SEBELUM payload.
    assert FakeChain.made == []
    assert FakeTarget.instances == []
    assert sandbox["probe_calls"] == 1


def test_limit_tidak_terbaca_tidak_bisa_dilewati_force(sandbox):
    """force melewati pra-syarat preflight, BUKAN fakta fisik memory_limit."""
    sandbox["limit"] = None
    with pytest.raises(er.UnknownMemoryLimit):
        _run(huge_mb=None, force=True)
    assert FakeChain.made == []


def test_huge_mb_eksplisit_tidak_terkena_gate_unknown(sandbox, monkeypatch):
    """--huge-mb tervalidasi = operator sudah menetapkan angka: probe dilewati."""
    def boom(*a, **kw):
        raise AssertionError("probe tidak boleh dipanggil saat --huge-mb diberikan")

    monkeypatch.setattr(er.memprobe, "probe", boom)
    res = _run(huge_mb=64, max_total_timeout=1, timeout=1, retries=1)
    assert FakeChain.made, "harus lanjut ke rantai"
    assert FakeChain.made[0].huge_mb == 64
    assert "tidak terbaca" not in res.error


def test_probe_menerima_deadline_absolut(sandbox):
    """Probe 16 MB ikut anggaran: deadline yang sama diteruskan ke probe."""
    clock = er._clock
    want = clock() + 30
    _run(huge_mb=None, max_total_timeout=30, timeout=5, retries=1)
    assert sandbox.get("probe_deadline") == pytest.approx(want, abs=0.01)


# ------------------------------------------------ deadline propagasi nyata --

def test_run_tidak_melewati_batas_total_dengan_chain_lambat(sandbox, monkeypatch):
    """Integrasi: chain yang menghormati `op_timeout` harus dipotong deadline.

    Ini yang dulu bocor: `_arm()` menyetel `target.timeout = min(sisa, t)`,
    tapi stage memakai `max(90.0, ...)` sendiri, jadi sisa 5s tetap dapat POST
    90s. Di sini Chain palsu memakai `target.op_timeout()` seperti chain asli,
    dan tes mengunci wall-clock run() <= batas + margin.
    """
    clock = sandbox["clock"]
    state = {"slept": 0.0}

    class SlowChain(FakeChain):
        """Setiap stage memakai anggaran sisa, seperti chain.py yang sudah fix."""

        def _burn(self):
            # Satu "operasi jaringan" yang benar-benar menghabiskan sisa waktu,
            # tapi tidak lebih: persis jaminan op_timeout.
            allowed = self.t.op_timeout(90.0)
            self.slept = state["slept"] = state["slept"] + allowed
            clock.advance(allowed)       # jam palsu maju sebesar itu
            return allowed

        def rotate(self):
            self._enter("rotate")
            self._burn()

        def stage1(self):
            self._enter("stage1")
            self._burn()
            return 0                     # meleset -> retry/rotate

        def stage2(self):
            self._enter("stage2")
            self._burn()
            return 0

        def stage3(self, htdata, zif):
            self._enter("stage3")
            self._burn()

    monkeypatch.setattr(chain_mod, "Chain", SlowChain)
    res = _run(huge_mb=12, max_total_timeout=5, timeout=30, retries=3,
               no_pre_rotate=True, no_retry_rotate=False)

    assert res.success is False
    assert "DEADLINE" in res.error, res.error
    # Tidak ada operasi yang diberi lebih dari anggaran total.
    assert state["slept"] <= 5 + 0.001, state
    # Wall-clock palsu juga tidak melewati batas: sisa dipotong tiap operasi.
    assert clock.now - 1000.0 <= 5 + 0.001, clock.now
    # Stage 3 tidak pernah tercapai: leak gagal karena jam, bukan payload.
    assert all(c[0] != "stage3" for c in SlowChain.made[0].calls)


# ---------------------------------------------------------- body_cap gate ---

def test_body_cap_rejected_berhenti_dengan_pesan_jelas(sandbox):
    sandbox["resp"] = (b"<b>Warning</b>: POST Content-Length of 16777461 bytes "
                       b"exceeds the limit of 8388608 bytes")
    with pytest.raises(RuntimeError) as ei:
        _run()
    assert "post_max_size" in str(ei.value)
    assert FakeChain.made == []


# ------------------------------------------------------------- preflight ----

def test_preflight_blocked_menghentikan_run(sandbox):
    det = _det(reachable=False, status=0)
    with pytest.raises(RuntimeError) as ei:
        _run(detection=det)
    assert "preflight BLOCKED" in str(ei.value)
    assert FakeChain.made == []


def test_force_melewati_gate_preflight(sandbox):
    det = _det(reachable=False, status=0)
    res = _run(detection=det, force=True, max_total_timeout=1, timeout=1,
               retries=1)
    assert FakeChain.made, "force harus sampai ke rantai"
    assert "preflight BLOCKED" not in res.error


def test_preflight_needs_review_tidak_memblokir(sandbox):
    """Informasi kurang bukan alasan menahan run; hanya blocked yang menahan."""
    det = _det(verdict="unknown", upload_progress="unknown")
    res = _run(detection=det, max_total_timeout=1, timeout=1, retries=1)
    assert FakeChain.made
    assert "preflight BLOCKED" not in res.error


def test_body_cap_hasil_probe_diteruskan_ke_preflight(sandbox):
    """Probe 'accepted' harus terlihat oleh preflight, bukan selalu unknown."""
    seen = {}

    import lib.preflight as pf
    orig = pf.preflight

    def spy(d, body_cap=None):
        seen["body_cap"] = body_cap
        return orig(d, body_cap=body_cap)

    pf.preflight = spy
    try:
        _run(detection=_det(), max_total_timeout=1, timeout=1, retries=1)
    finally:
        pf.preflight = orig
    assert seen.get("body_cap") == "accepted", seen


# ----------------------------------------------------------------- TLS -----

def test_insecure_mematikan_verifikasi_tls(sandbox):
    _run(insecure=True, huge_mb=12, max_total_timeout=1, timeout=1, retries=1)
    assert FakeTarget.instances[0].verify_tls is False


def test_default_memverifikasi_tls(sandbox):
    _run(huge_mb=12, max_total_timeout=1, timeout=1, retries=1)
    assert FakeTarget.instances[0].verify_tls is True


def test_target_lama_tanpa_verify_tls_tetap_jalan(monkeypatch, sandbox):
    """chain.py versi lama (tanpa verify_tls) tidak boleh membuat run crash."""
    class OldTarget:
        def __init__(self, url, timeout=30.0, verbose=True):
            self.url, self.timeout, self.verify_tls = url, timeout, None
            self.log = lambda _m: None

        def get(self, path=None, read_cap=None):
            return 0, b""

    monkeypatch.setattr(chain_mod, "Target", OldTarget)
    res = _run(huge_mb=12, max_total_timeout=1, timeout=1, retries=1)
    assert "TypeError" not in res.error, res.error
    assert FakeChain.made

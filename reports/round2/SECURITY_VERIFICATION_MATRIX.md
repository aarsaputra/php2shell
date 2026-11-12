# SECURITY VERIFICATION MATRIX — ROUND 2

Setiap baris menunjuk ke bukti yang bisa dijalankan ulang. Status memakai
kosakata yang diminta: PASS / FAIL / PARTIAL / BLOCKED / NOT TESTED /
NOT APPLICABLE.

| ID | Finding | Prioritas | Before | Patch | Regression test | Bukti dinamis | Final |
|---|---|---|---|---|---|---|---|
| R2-01 | Command argument validation | P1 | FAIL — hanya kata pertama diperiksa | `ARG_SCHEMAS` + `_CMD_GRAMMAR`; `cat`/`env` dihapus | `tests/test_command_validation.py` (10), `tests/test_validate_command.py` | `evidence/command-validation/e2e-live.txt` | **PASS** |
| R2-02 | Redirect scope & DNS rebinding | P1 | FAIL — redirect ke domain publik lain lolos | `RedirectScope`+`check_scope()` di tiap hop | `tests/test_redirect_scope.py` (25) | `evidence/redirect-validation/scope-live.txt` | **PASS** |
| R2-03 | Centralized resource limits | P1 | FAIL — jalur API melewati batas argparse | `memprobe.validate_huge_mb()` di `run()` + `Chain.__init__` | `test_runner_deadline.py` (3), `test_chain_request.py` | `evidence/test-results/negative-tests.txt` N5/N6 | **PASS** |
| R2-04 | Producer lifecycle 115560 | P2 | FAIL — read timeout 30s > join 5s | `_PRODUCER_READ_TIMEOUT=4s < _JOIN_TIMEOUT=5s` | `tests/test_producer_lifecycle.py` (8) | thread-count setelah run | **PASS** |
| R2-05 | Docker lab hardening | P2 | FAIL — egress terbuka, cap default, rootfs rw, chown host | Dockerfile uid-map, compose internal+cap_drop+read_only+limits, relay socat | `tests/test_docker_lab_hardening.py` (27) | `evidence/docker-isolation/isolation-proof.txt` | **PASS** |
| R2-06A | Environment verification | — | NOT TESTED | — | — | `evidence/test-results/full-regression.txt` header | **PASS** |
| R2-06B | Safe local E2E | — | NOT TESTED | — | — | `evidence/test-results/e2e-exploit-live.txt` (proof `uid=1000(p2s)`) | **PASS** |
| R2-06C | Negative testing | — | NOT TESTED | — | — | `evidence/test-results/negative-tests.txt` N2–N9 | **PASS** |
| R2-06D | Full regression | — | 438 passed | — | 537 passed (pytest, lab hidup; 521+11 skip saat lab mati), 366 (unittest) | `evidence/test-results/full-regression.txt` | **PASS** |
| RR-2 | `upshell_live.py` carrier gate | FAIL — `full_chain_cmd()` menerima string bebas | `validate_carrier_cmd()` + `_CARRIER_FORMS` (allowlist bentuk) | `tests/test_upshell_carrier_gate.py` (18) | gate menolak `sh</out/c` sebelum jaringan | **CLOSED** |
| RR-3 | `safe_shell.py` path policy | FAIL — `ls /`, `ls ..`, `stat /etc/passwd` lolos | `validate_path_arg()` + `PATH_SAFE_ROOTS` (batas segmen) | `test_report_and_shell.py` (12 tolak + 5 lolos) | `ls /`/`ls ..`/`/etc/*` ditolak | **CLOSED** |
| RR-5 | Verifikasi `docker compose` | BLOCKED — plugin tidak ada | plugin v5.7.1 dipasang | `TestComposeEquivalence` (5) | `compose config`+`create`+`start`, E2E `uid=1000(p2s)` | **CLOSED** |
| N11/N12 | Target versi patched | NOT TESTED | — | — | `php:8.3.36` → `patched`, `vulnerable=0`, `exploited=0` | **PASS** |

## Item yang secara eksplisit TIDAK dicakup PASS di atas

| Item | Status | Alasan |
|---|---|---|
| Proxy + DNS pin | PARTIAL | `--proxy` membuat resolusi DNS dilakukan proxy; pin `CURLOPT_RESOLVE` tidak dipasang. Didokumentasikan, tidak diklaim aman. |
| `shell/upshell_live.py` carrier gate | **CLOSED** | `validate_carrier_cmd()` menolak string bebas; 18 tes. |
| `shell/safe_shell.py` path policy | **CLOSED** | `validate_path_arg()` menolak enumerasi/traversal; 17 kasus tes. |
| `docker compose` asli | **CLOSED** | plugin v5.7.1; `config`+`create`+`start`+inspect+E2E. |
| arm64 | NOT TESTED | Semua uji di x86_64. |
| Egress allowlist | NOT IMPLEMENTED | Lab nol egress (sengaja). |
| CVE-2026-109618 | NOT APPLICABLE | Tool ini hanya mendeteksi; rantai tidak diimplementasikan (perilaku lama). |

## Perintah reproduksi

```bash
cd /home/lota1337/python/php2shell

# regression penuh
/home/lota1337/myenv/bin/python -m pytest
/home/lota1337/myenv/bin/python -m unittest discover -s tests -t .

# R2-01
/home/lota1337/myenv/bin/python -m pytest tests/test_command_validation.py -v

# R2-02
/home/lota1337/myenv/bin/python -m pytest tests/test_redirect_scope.py -v

# R2-03
/home/lota1337/myenv/bin/python -m pytest tests/test_runner_deadline.py -k huge_mb -v

# R2-04
/home/lota1337/myenv/bin/python -m pytest tests/test_producer_lifecycle.py -v

# R2-05 (butuh lab hidup)
bash lab/lab_docker.sh start
/home/lota1337/myenv/bin/python -m pytest tests/test_docker_lab_hardening.py -v

# E2E proof-of-access
/home/lota1337/myenv/bin/python docker/offsets.py p2s-lab-8426
/home/lota1337/myenv/bin/python php2shell.py exploit \
  -u http://127.0.0.1:8095/index.php --yes --force --allow-private-target \
  --proof-file p2 ; cat out/p2
```
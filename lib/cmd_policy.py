"""cmd_policy.py — kebijakan BENTUK perintah yang dipakai dua jalur sekaligus.

Kenapa modul terpisah
---------------------
Ada dua jalur yang mengirim perintah ke target:

  1. `lib/exploit_runner.py` — proof-of-access. Perintahnya dipilih operator
     lewat `-c`/`--allow-cmd`, jadi ia butuh WHITELIST + skema argumen.
  2. `lib/chain.py` — mesin rantai. `Chain(target, cmd)` menerima string dari
     pemanggilnya (skrip lab, `upshell_live`, kode API pihak ketiga).

Sebelum modul ini, `Chain` hanya memeriksa PANJANG (`MAX_CMD = 14`) dan tidak
memeriksa isi sama sekali: `Chain(t, "sh</out/c")` valid. Pesan errornya
bahkan mencontohkan perintah itu. Artinya `validate_command()` di
`exploit_runner` bisa dilewati sepenuhnya lewat jalur API — kelas bug yang
sama dengan R2-01, di pintu yang berbeda.

`chain.py` TIDAK BOLEH mengimpor `exploit_runner` (siklus impor:
exploit_runner → chain). Karena itu bagian kebijakan yang murni struktural —
batas byte, token terlarang, dan bentuk kanal bukti — diletakkan di modul
netral ini dan dipakai KEDUANYA. Satu sumber kebenaran, tanpa siklus.

Pembagian tanggung jawab
------------------------
  * Di sini: bentuk yang SELALU dilarang (`;`, `|`, `$`, backtick, `rm `, ...)
    dan bentuk yang SELALU boleh (kanal bukti `<identitas>/out/<nama>`).
  * Di `exploit_runner`: tambahan di atas itu — whitelist perintah dan skema
    argumen (`ARG_SCHEMAS`), karena hanya jalur itu yang menerima pilihan
    perintah dari operator.
"""

from __future__ import annotations

import re

__all__ = [
    "MAX_CMD_BYTES",
    "FORBIDDEN_CMD_TOKENS",
    "PROOF_BASES",
    "PROOF_DIR",
    "PROOF_REDIRECT_RE",
    "is_proof_redirect",
    "is_identity_proof",
    "check_command_shape",
]

# Carrier zend_string 167 byte -> maksimum perintah 14 byte (terukur di lab).
MAX_CMD_BYTES = 14

# Operator shell yang tidak punya alasan sah di perintah carrier. Dicek pada
# string MENTAH (bukan hasil strip): newline di ujung adalah titik injeksi
# walau `strip()` menghilangkannya.
FORBIDDEN_CMD_TOKENS = (
    ";", "|", "&", "$", "`", ">", "<", "\n", "\r", "\\", "(",
    "&&", "||", "sh ", "bash ", "nc ", "curl ", "wget ", "base64",
    "chmod", "rm ", "find ", "python", "perl",
)

# Kanal bukti: satu-satunya redirection yang sah, dan hanya untuk perintah
# identitas. Path dikunci ke /out/<nama aman>.
PROOF_DIR = "/out"
PROOF_BASES = ("id", "whoami", "uname", "hostname", "pwd")
PROOF_REDIRECT_RE = re.compile(
    r"^([a-z]+)\s*>\s*/out/([A-Za-z0-9_-]{1,24})$")


def is_proof_redirect(cmd: str) -> bool:
    """True bila `cmd` berbentuk `<perintah> > /out/<nama>` (bentuk saja)."""
    return bool(PROOF_REDIRECT_RE.match(str(cmd or "").strip()))


def is_identity_proof(cmd: str) -> bool:
    """True bila `cmd` adalah redirect-bukti dari perintah IDENTITAS."""
    m = PROOF_REDIRECT_RE.match(str(cmd or "").strip())
    return bool(m) and m.group(1) in PROOF_BASES


def check_command_shape(cmd: str) -> str:
    """Alasan penolakan bila bentuk perintah tidak sah ('' = sah).

    Lapis yang diperiksa (sama untuk kedua jalur):

      1. tidak kosong,
      2. batas byte carrier (diukur pada string MENTAH, bukan hasil strip),
      3. kanal bukti `<identitas>/out/<nama>` — SATU-SATUNYA redirection sah,
      4. token shell terlarang pada string mentah.

    Yang TIDAK diperiksa di sini: apakah executable ada di whitelist dan
    apakah argumennya cocok skema. Itu tanggung jawab pemanggil yang punya
    konteks operator (`exploit_runner`).
    """
    if not isinstance(cmd, str) or not cmd or not cmd.strip():
        return "ditolak: perintah kosong"
    raw_bytes = len(cmd.encode())
    if raw_bytes > MAX_CMD_BYTES:
        return (f"ditolak: perintah {cmd!r} = {raw_bytes} byte > "
                f"{MAX_CMD_BYTES} byte (batas carrier 167 byte)")
    c = cmd.strip()
    if len(c.encode()) > MAX_CMD_BYTES:
        return (f"ditolak: perintah {c!r} = {len(c.encode())} byte > "
                f"{MAX_CMD_BYTES} byte (batas carrier 167 byte)")

    # Kanal bukti diperiksa SEBELUM token terlarang supaya `>` pada pola ini
    # tidak memicu penolakan umum. Bentuk sudah dikunci regex; base belum
    # diperiksa di sini (itu whitelist, milik pemanggil).
    if is_proof_redirect(c):
        return ""

    low = cmd.lower()
    for tok in FORBIDDEN_CMD_TOKENS:
        if tok in low:
            return (f"ditolak: perintah memuat operator/token berbahaya {tok!r} — "
                    "proof-of-access hanya boleh satu perintah identitas "
                    "(id/whoami), tanpa chaining")
    return ""

"""lib/color.py — pewarnaan terminal dengan pagar aman.

Aturan:
  - Warna hanya aktif bila stdout TTY, env NO_COLOR tidak diset, dan
    TERM bukan "dumb". tools: enable(False) memaksa mati (CLI --no-color).
  - Fungsi verdict_color(v) memetakan verdict toolkit ke kode warna:
      vulnerable/pwned  -> merah tebal (temuan kriris)
      eol               -> merah
      ready             -> hijau tebal (siap dieksploitasi)
      patched           -> hijau
      inconclusive/unknown/blk -> kuning
      not_vulnerable    -> hijau
      error             -> merah muda
  - Penting: JANGAN dipakai untuk teks yang dibaca ulang oleh parser/tes;
    warna hanya untuk layar.
"""
from __future__ import annotations

import os
import sys

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"

_state: dict = {"enabled": None}  # None = belum diputuskan (auto)


def _auto_enabled() -> bool:
    if not sys.stdout.isatty():
        return False
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM", "") == "dumb":
        return False
    return True


def enabled() -> bool:
    if _state["enabled"] is None:
        _state["enabled"] = _auto_enabled()
    return _state["enabled"]


def enable(v: bool) -> None:
    """Paksa on/off (dipanggil CLI untuk --no-color; None = kembali auto)."""
    _state["enabled"] = v


def paint(text: str, *codes: str) -> str:
    if not enabled() or not codes:
        return text
    return "".join(codes) + text + RESET


def cverdict(v: str) -> str:
    """Pewarna verdict + beberapa kata kunci hasil lain."""
    mapping = {
        "vulnerable": RED,
        "pwned": RED,
        "critical": RED,
        "eol": RED,
        "error": MAGENTA,
        "patched": GREEN,
        "not_vulnerable": GREEN,
        "ready": GREEN,
        "inconclusive": YELLOW,
        "unknown": YELLOW,
        "blocked": YELLOW,
    }
    c = mapping.get((v or "").lower())
    return paint(v, BOLD, c) if c else v


def keyword(word: str, kind: str = "ok") -> str:
    """Warnai kata kunci hasil (PROOF, READY, BLOCKER, dst)."""
    k = {
        "ok": GREEN,
        "bad": RED,
        "warn": YELLOW,
        "info": CYAN,
    }.get(kind, "")
    return paint(word, BOLD, k) if k else word

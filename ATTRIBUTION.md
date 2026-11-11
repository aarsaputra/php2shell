# Attribution

php2shell is a **reproduction, orchestration and hardening toolkit** built on
top of prior public research. The exploit technique is not ours. This file
exists so nobody has to guess where each part came from.

## Upstream research (not ours)

**The CVE is not ours.** CVE-2026-109618 and CVE-2026-109619 were reported
to PHP by **three parties**, and the credit order matters:

| Party | First finding | Reported to PHP |
|---|---|---|
| **Calif (Ryan A.)** — found it **first** | 1 Aug 2026 | 11 Aug 2026 (first bug), 21 Aug (second) |
| **Wiz Research** — independent discovery | 19 Aug 2026 | 24 Aug 2026 |
| **OpenAI Codex Security (Amy Burnett)** — additional vectors | not stated | 18 Sep 2026 |

Per the PHP Foundation's release post, Calif reported first; Wiz found the
same bug class independently a few weeks later. PHP's own GitHub advisories
credit all three. Fixed releases shipped 21 Oct 2026.

Sources: [PHP Foundation release post](https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/) ·
[Wiz Research — PHP2Shell](https://www.wiz.io/blog/php2shell-php-rce) ·
[Calif — PHP2Shell](https://calif.io/php2shell.x/)

| Project | Author | What we took | Status |
|---|---|---|---|
| **Calif (Ryan A.)** — first finding | **Calif** | The original trigger on the upload-metadata amplification path, reported 11 Aug 2026. Earlier dated than any other report. | Public research. Not code. Credit owed first. |
| **Wiz Research** — PHP2Shell publication | **Wiz Research** | Independent discovery of both CVEs and the public analysis everything here depends on. | Public research. Not code. |
| **OpenAI Codex Security** | **Amy Burnett** | Additional attack vectors reported to PHP, 18 Sep 2026. | Public research. Not code. |
| [`9bie/php2shell-bypass-aslr-exp`](https://github.com/9bie/php2shell-bypass-aslr-exp) | **9bie (Qi Deng)** | The core chain: 2-request `session.upload_progress` UAF (CVE-2026-109619), the ASLR bypass via heap leak + `libphp` base leak, and the `pDestructor = zif_system` actuator. `lib/chain.py` is a **port** of this `exploit.py`'s logic into an in-process module. | No license file published upstream. Ported with explicit credit; see "License status" below. |
| **Karasawa2025** | **Karasawa2025** | Public research on the `display_errors=Off` direction: the OOM-in-cookie primitive and the alternative leak strategy. Reference for a path we have **not** implemented yet. | Referenced, not vendored. |
| [`ikow/php2shell-poc`](https://github.com/ikow/php2shell-poc) | **ikow** | The CVE-2026-109618 OOM-trigger verifier (`poc/verify_oom_trigger.py`) used as the reference for our 109618 crash evidence. | Referenced, not vendored. |
| PHP security advisories | **PHP Group** | `GHSA-w8hw-w9fx-j79w` → CVE-2026-109618, `GHSA-6wmf-4rv5-p3rp` → CVE-2026-109619; the fix-floor table (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12). | Public advisory, factual data. |
| `curl_cffi` | **lexiforest / yifeikong** | JA3/TLS impersonation used by `lib/transport.py`. | MIT — installed as a dependency, not vendored. |

**Deliberately not credited, because we could not verify them:** `WoYinDao`
(cited by devploit; no public trace found) and `CVE-2026-115560` (404 at MITRE,
no NVD record — used as a headline by murrez, not repeated here).

## What is original to this repo

- Unified CLI with 7 modes (`scan` / `detect` / `preflight` / `exploit` /
  `shell` / `version` / `builds`)
- `lib/chain.py` packaged as an in-process engine (no subprocess, no external
  script), verified function-by-function against the upstream `exploit.py`
- Auto-proof: reading the command output back from the mounted `out/p1`
- The command fence (whitelist, 14-byte cap, chaining rejection, no revshell)
- Preflight scoring model + the "detection is information, not a gate" policy
- Stealth layer: JA3 profile rotation, jitter, JSONL request audit
- Test suite (263 tests — `python -m unittest discover -s tests -t .` → `Ran 263 tests, OK`), installer, Docker lab, GPL-3.0 wrapper

## License status (read this)

> **LEGAL REVIEW REQUIRED — belum ada clearance.**
>
> `9bie/php2shell-bypass-aslr-exp` publishes **no license file**, so default
> copyright applies to it ("all rights reserved") — there is no grant we can
> point at. Our own **GPL-3.0 does not override or extinguish the upstream
> author's rights** over the portions of `lib/chain.py` that are substantially a
> port of their `exploit.py`; a downstream license can only cover the code *we*
> wrote. There are exactly three paths: (1) ask 9bie for permission and record
> the grant here, (2) replace the port with a **clean-room reimplementation**
> written only from the published behavioural spec (see the devploit pattern
> below), or (3) drop the upstream-derived portions from this repo. Until one of
> those happens, **this repo makes no claim of legal clearance** — this section
> documents the risk, it does not resolve it, and it is not legal advice.

This repo is released under **GPL-3.0-only** — that covers the code *we* wrote.

Because the upstream `9bie/php2shell-bypass-aslr-exp` publishes **no license
file**, default copyright applies to that upstream code ("all rights
reserved"). Our GPL-3.0 does **not** override that for the portions that are
substantially a port of it. The honest position is:

1. We credit 9bie explicitly, in this file, in the README, and in
   `lib/chain.py`'s header.
2. If you are 9bie (or acting for them) and you object to the port, open an
   issue — we will either remove the port or add your license terms to it,
   your choice.
3. A clean-room reimplementation of the chain from the published write-up is
   the only way to have an unambiguously GPL-3.0-only `lib/chain.py`. Until
   that happens, treat `lib/chain.py` as "GPL-3.0 with upstream attribution".

If you are reusing this repo and you care about license hygiene, that
distinction matters: **do not represent `lib/chain.py` as purely our work.**

### How `devploit/php2shell` solves the same problem

We are not the only project that hit this. `devploit/php2shell` (MIT) faced the
same unlicensed-upstream problem with 9bie and chose a different, arguably
cleaner route — worth recording because it is the pattern a future
`lib/chain.py` rewrite should follow:

> "That repository has no explicit license file. For that reason: its source is
> **not vendored here**; no patch file containing its code is redistributed;
> `bootstrap_upstream.py` only **clones the pinned commit**."

In other words: at runtime, fetch the upstream code from upstream itself at a
pinned commit. Then the redistributed repo contains **zero** lines of
unlicensed code, and the license question never arises for the artifact you
ship.

Our situation differs in one way: `lib/chain.py` is not a thin wrapper, it is
the engine — it cannot be "fetched at runtime" without turning a self-contained
tool into something that needs network access to run at all. That is worse for
the user. So we keep the port and stay honest about it in this file, and the
clean-room rewrite remains the planned fix. What we will **not** do is describe
the port as original work.

Two things we deliberately did *not* copy from that comparison:

- They list `CVE-2026-115560` as a headline feature. We checked
  `cveawg.mitre.org/api/cve/CVE-2026-115560` → **404**, NVD → **0 results**,
  and the `php/php-src` advisory list → absent (only 109618 and 109619 exist).
  That ID appears to be invented. We do not reference it.
- We adopt their **support-level matrix** (which builds reach RCE vs. only
  leak) because it is their *measurement*, creditable and useful — see
  `lib/build_support.py`. Factual data is attributed; it is not code copying.

## Ethical position

This toolkit proves *access*, not *damage*. Commands are capped at 14 bytes,
restricted to `id` / `whoami` / `uname` / `hostname` / `pwd`, chaining
operators are rejected, and `--revshell` does not exist in the parser. That is
deliberate: a public repo containing a general-purpose RCE must not be a
ready-made backdoor.

## The Zer061 fork (clarification, 2026-10-24)

The `exploit.py` this toolkit was verified against lives in
`github.com/Zer061/CVE-2026-109618` (local path
`/home/lota1337/python/CVE-2026-109618/`, sha256
`ea92568319637e1913e20d9ceb1e6d89315c2393f8eac3fb6a2975bc1a1f6927`).

That repo's history is a **mixture of four authors**, not Zer061's work alone:

| Commit | Author | Content |
|---|---|---|
| `adc5f9b` | 9bie | original chain |
| `4586f5c` | my `<my@fubuki.invalid>` | English README |
| `5fc5669` | v.dir.mir `<v.dir.mir@vinsoc.vn>` | **added `--revshell`** + bash/python/perl payload + `nc` listener |
| `4752adc` | Zer061 | README update (fork head) |

We do **not** use the `--revshell` path: it is absent from the parser and
blocked in the runner.

## Anti-malware audit (2026-10-24)

Both this repo and the Zer061 source folder were checked for:

| Check | Result |
|---|---|
| hardcoded outbound hosts (C2) | none — only `127.0.0.1`, `localhost`, doc URLs |
| credential theft (`~/.ssh`, `.aws`, `/etc/shadow`, upload cookies) | none |
| persistence (`crontab`, `systemd`, `.bashrc`, `rc.local`, autostart) | none |
| obfuscation (mass `b64decode`, hex blobs, `chr()` chains) | none — `\x..` sequences are protocol byte arrays in `tools/align8.py`, `tools/warn_probe.py` |
| unknown binaries | none — only official `php-8.4.26.tar.gz` + one PNG |
| `subprocess`/`os.system`/`eval`/`exec` | legitimate only: `docker cp` for `libphp.so`, the `safe_shell.py` generator, test suite |
| raw `socket.create_connection` | required — the chain speaks TCP directly so TLS/handshake is not normalised by a library |
| `--revshell` / reverse-shell payloads | **PRESENT in the reference `exploit.py`** (commit `5fc5669`, v.dir.mir): 3 vectors (bash `/dev/tcp`, python pty, perl socket) written to `out/c`, executed via `sh</out/c`, plus an `nc` listener. **Blocked in this toolkit**: not in argparse, words `bash`/`nc`/`sh` rejected by the runner, no listener implemented. |

All 31 git-tracked files were hashed with `sha256sum`; the test suite was green at that
time (46 tests then — today's count and the command to reproduce it are in the table
above: `python -m unittest discover -s tests -t .` → `Ran 263 tests, OK`).

**Full forensic scope:** all 384 blobs across all 19 commits were extracted and
scanned (not just the working tree). No C2 host, no credential theft, no
persistence, no obfuscation, no unknown binaries. The only "weapon" is the
documented `--revshell` feature — which is why GitHub took the original repo down.
See `AUDIT_FORENSIK_Zer061_2026-10-24.md` on the lab SSD.

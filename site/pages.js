"use strict";
// Marketing pages (Home, Products, How it works, About us, Contact) and their animations.
// The Demo pages (the real tool) are in app.js and have no animations.
// Motion follows apple.com: 0.2-0.6 s, small distances, fade + rise + slight blur, items one after another,
// one easing; nothing moves for people who chose "reduce motion" in their system.

// Contact address for the Contact page. Empty = not published yet (the button says so).
const CONTACT_EMAIL = "";

const MARKETING_PAGES = ["home", "products", "how", "about", "contact"];

function contactButton(el) {
  if (CONTACT_EMAIL) { el.href = "mailto:" + CONTACT_EMAIL + "?subject=" + encodeURIComponent("Keelbook"); el.classList.remove("off"); }
  else { el.removeAttribute("href"); el.classList.add("off"); el.textContent = "Contact address coming soon"; }
}

const HERO_ART = `<svg class="art" viewBox="0 0 440 340" role="img" aria-label="SBOM, vulnerabilities and decisions meet in the register">
  <circle class="c1" cx="160" cy="135" r="105" fill="rgba(0,113,227,.10)" stroke="#0071e3" stroke-width="2"/>
  <circle class="c2" cx="280" cy="135" r="105" fill="rgba(29,29,31,.05)" stroke="#1d1d1f" stroke-width="2"/>
  <circle class="c3" cx="220" cy="225" r="105" fill="rgba(255,255,255,.55)" stroke="#86868b" stroke-width="2"/>
  <g font-family="-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif" font-size="16" font-weight="600" text-anchor="middle">
  <text x="118" y="112" fill="#0071e3">SBOM</text><text x="322" y="112" fill="#1d1d1f">Vulnerabilities</text>
  <text x="220" y="292" fill="#6e6e73">Decisions</text><text x="220" y="172" fill="#1d1d1f" font-size="18">Register</text></g></svg>`;

const ICON = {
  list: '<svg viewBox="0 0 24 24"><path d="M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01"/></svg>',
  alert: '<svg viewBox="0 0 24 24"><path d="M12 3 2 20h20L12 3zM12 10v4M12 17h.01"/></svg>',
  doc: '<svg viewBox="0 0 24 24"><path d="M6 3h8l4 4v14H6zM14 3v4h4M9 12h6M9 16h6"/></svg>',
  lock: '<svg viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>',
  person: '<svg viewBox="0 0 24 24"><circle cx="12" cy="8" r="4"/><path d="M4 21c1.5-4 4.5-6 8-6s6.5 2 8 6"/></svg>',
  eye: '<svg viewBox="0 0 24 24"><path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>',
  check: '<svg viewBox="0 0 24 24"><path d="M5 12l5 5 9-10"/></svg>',
};

// ---------- pages ----------
function homePage() {
  return `
  <section class="hero mk">
    <div>
      <h1 class="rise">Every vulnerability.<br><span class="hl">Every decision.</span><br>On record.</h1>
      <p class="lede rise">The vulnerability register the EU Cyber Resilience Act asks for, per product and release. Built for
        small hardware and IoT makers.</p>
      <div class="row rise"><a class="btn primary big" href="#demo">Try the demo</a><a class="btn big" href="#how">How it works</a></div>
    </div>
    ${HERO_ART}
  </section>

  <section class="mk-section">
    <h2 class="reveal">Built for what the <span class="hl">CRA asks.</span></h2>
    <p class="sub reveal">Three duties, one register. Keelbook keeps the work and the proof together.</p>
    <div class="cards3" data-stagger>
      <div class="card reveal"><span class="ico">${ICON.list}</span><h3>A register per release</h3>
        <p>Every known vulnerability in the components of each release, from its SBOM. Decisions carry over to the next release.</p>
        <small>CRA Art. 13(8), Annex I Part II</small></div>
      <div class="card reveal"><span class="ico">${ICON.alert}</span><h3>Exploited first</h3>
        <p>Findings on CISA's list of exploited vulnerabilities come first, because they may start the 24-hour reporting clock.</p>
        <small>CRA Art. 14</small></div>
      <div class="card reveal"><span class="ico">${ICON.doc}</span><h3>Proof for auditors</h3>
        <p>An evidence record per release and a VEX file for customers: what was found, who decided what, and why.</p>
        <small>OpenVEX, HTML, Excel</small></div>
    </div>
  </section>

  <section class="band reveal">
    <div class="band-in">
      <h2>The dates are <span class="hl-light">set.</span></h2>
      <div class="dates" data-stagger>
        <div class="reveal"><b>11 Sep 2026</b><span>Reporting of actively exploited vulnerabilities and severe incidents applies (Art. 14).</span></div>
        <div class="reveal"><b>11 Dec 2027</b><span>The whole regulation applies, including the vulnerability-handling requirements.</span></div>
      </div>
      <p class="small">Regulation (EU) 2024/2847, Art. 71(2).</p>
    </div>
  </section>

  <section class="mk-section">
    <h2 class="reveal">Why <span class="hl">Keelbook.</span></h2>
    <div class="cards4" data-stagger>
      <div class="card reveal"><span class="ico">${ICON.lock}</span><h3>Your data stays yours</h3><p>Only component names and versions are looked up. Never your source code.</p></div>
      <div class="card reveal"><span class="ico">${ICON.person}</span><h3>A person decides</h3><p>Keelbook suggests. A named person decides and gives a reason. Every entry is logged.</p></div>
      <div class="card reveal"><span class="ico">${ICON.eye}</span><h3>Unchecked is never clean</h3><p>What could not be checked is counted and shown, never reported as "no vulnerabilities".</p></div>
      <div class="card reveal"><span class="ico">${ICON.check}</span><h3>Made for Yocto</h3><p>Reads CycloneDX and SPDX, including the SBOMs Yocto builds produce.</p></div>
    </div>
  </section>

  <section class="cta-panel reveal">
    <h2>See it with your own SBOM.</h2>
    <p>The demo runs in your browser. Nothing to install, nothing uploaded.</p>
    <div class="row center"><a class="btn primary big" href="#demo">Try the demo</a><a class="btn big" href="#contact">Contact us</a></div>
  </section>`;
}

function productsMarketingPage() {
  const products = [
    { kind: "free", name: "Keelbook Web", tag: "Free demo", title: "In your browser.", text: "The full register in a web page. Nothing to install; the register stays on your computer.",
      points: ["Scan an SBOM, see what needs a decision", "Decisions, review sheet, evidence record", "VEX file for customers"],
      button: '<a class="btn primary" href="#demo">Try the demo</a>' },
    { kind: "free", name: "Keelbook", tag: "Command line · Open source", title: "For engineers and CI.", text: "The same engine as a program for Linux, macOS and Windows, and as a step in your build pipeline.",
      points: ["Works offline with saved data", "Art. 14 cases: deadlines, sign-off, report drafts", "Reports as HTML, Excel, SARIF, OpenVEX"],
      button: '<a class="btn" href="#contact">Ask for access</a>' },
    { kind: "teams", name: "Keelbook Server", tag: "For teams", title: "For the whole company.", text: "Keelbook for a team: everyone logs in, and every release is checked again every night.",
      points: ["Logins and roles; decisions under each person's name", "Nightly re-checks and email alerts", "Runs on your own server"],
      button: '<a class="btn primary" href="#contact">Contact us</a>' },
  ];
  const yes = '<span class="yes-mark" aria-label="included">●</span>', no = '<span class="no-mark" aria-label="not included">–</span>';
  const rows = [
    ["Vulnerability register per product and release", yes, yes, yes],
    ["SBOM formats: CycloneDX, SPDX 2 and 3, Yocto", yes, yes, yes],
    ["Exploited candidates from CISA KEV", yes, yes, yes],
    ["Evidence record and VEX file", yes, yes, yes],
    ["Logins, roles, named decisions", no, no, yes],
    ["Nightly re-checks and email alerts", no, no, yes],
    ["Art. 14 case workflow and deadline clocks", no, yes, no],
    ["CI pipelines (GitHub Action, SARIF)", no, yes, no],
    ["Install", "None", "One program", "Docker"],
  ];
  return `
  <section class="mk-head">
    <h1 class="rise">Explore the <span class="hl">products.</span></h1>
    <p class="sub rise">One engine, three ways to use it. Start free; move your team to the server when you are ready.</p>
    <div class="tabs rise" role="tablist" aria-label="Filter products">
      <span class="tab-pill" aria-hidden="true"></span>
      <button role="tab" aria-selected="true" data-filter="all">All products</button>
      <button role="tab" aria-selected="false" data-filter="free">Free</button>
      <button role="tab" aria-selected="false" data-filter="teams">For teams</button>
    </div>
  </section>
  <div class="gallery-wrap">
    <div class="gallery" id="productGallery">
      ${products.map((p) => `<article class="product-card" data-kind="${p.kind}">
        <p class="eyebrow">${p.tag}</p><h3>${p.name}</h3><p class="title">${p.title}</p><p>${p.text}</p>
        <ul>${p.points.map((x) => `<li>${x}</li>`).join("")}</ul>${p.button}</article>`).join("")}
    </div>
    <div class="paddles"><button class="paddle" data-dir="-1" aria-label="Previous">‹</button><button class="paddle" data-dir="1" aria-label="Next">›</button></div>
  </div>

  <section class="mk-section">
    <h2 class="reveal">Compare.</h2>
    <div class="table-wrap reveal"><table class="compare"><thead><tr><th></th><th>Keelbook Web</th><th>Keelbook</th><th>Keelbook Server</th></tr></thead>
      <tbody>${rows.map((r) => `<tr><td>${r[0]}</td><td>${r[1]}</td><td>${r[2]}</td><td>${r[3]}</td></tr>`).join("")}</tbody></table></div>
    <p class="small muted reveal">Prices for the server version on request. Working aid, not legal advice.</p>
  </section>`;
}

function howPage() {
  const steps = [
    ["Add a product", "Its name, the contact for vulnerability reports and the end of its support period. These go into the evidence record."],
    ["Scan a release", "Upload the release's SBOM. Keelbook looks up every component in public vulnerability databases: OSV, the official CVE List and, if you want, NVD. Components it cannot check are counted, not hidden."],
    ["Decide", "For each finding a person chooses: affected, not affected, fixed or under investigation, with a reason. Findings on CISA's exploited list come first. Decisions carry over to the next release."],
    ["Prove it", "Download the evidence record for auditors, a VEX file for customers and an Excel review sheet for colleagues. Back up the register as one file."],
  ];
  const outputs = [
    ["Evidence record", "Per release: coverage, findings, every decision with who, when and why. Opens in any browser, prints to PDF."],
    ["VEX file", "OpenVEX for your customers: which vulnerabilities affect the product and which do not, and why."],
    ["Review sheet", "An Excel file with drop-down lists. Fill it in with colleagues, then import it back: all rows or none."],
    ["Scan report", "Severity overview, exploited first, upgrade advice per component, details with links."],
    ["CI results", "SARIF for code-scanning tools, from the command-line version and the GitHub Action."],
    ["Art. 14 cases", "For an actively exploited vulnerability: awareness time, 24 h / 72 h / final-report clocks, sign-off, report drafts. Command-line version."],
  ];
  return `
  <section class="mk-head">
    <h1 class="rise">How it <span class="hl">works.</span></h1>
    <p class="sub rise">Four steps from an SBOM to evidence you can show. A person stays in charge at every step.</p>
  </section>
  <section class="steps-list" data-stagger>
    ${steps.map((s, i) => `<div class="step reveal"><b>${i + 1}</b><div><h3>${s[0]}</h3><p>${s[1]}</p></div></div>`).join("")}
  </section>

  <section class="mk-section">
    <h2 class="reveal">What you <span class="hl">get.</span></h2>
    <div class="gallery-wrap">
      <div class="gallery" id="outputGallery">
        ${outputs.map((o) => `<article class="out-card"><span class="ico">${ICON.doc}</span><h3>${o[0]}</h3><p>${o[1]}</p></article>`).join("")}
      </div>
      <div class="paddles"><button class="paddle" data-dir="-1" aria-label="Previous">‹</button><button class="paddle" data-dir="1" aria-label="Next">›</button></div>
    </div>
  </section>

  <section class="mk-section two">
    <div class="panel reveal"><span class="ico">${ICON.lock}</span><h3>What leaves your computer</h3>
      <p>Only component names and versions, for example "openssl 3.4.2", sent to public vulnerability databases, the same way you
      would search for them yourself. Never the SBOM file, never your source code.</p></div>
    <div class="panel reveal"><span class="ico">${ICON.person}</span><h3>What Keelbook does not do</h3>
      <p>It does not decide whether a vulnerability is actively exploited, does not report anything to ENISA, and does not give legal
      advice. It flags candidates and keeps the record; a person decides and reports.</p></div>
  </section>

  <section class="cta-panel reveal">
    <h2>Try the four steps now.</h2>
    <p>Use one of your own SBOMs, or any public one.</p>
    <div class="row center"><a class="btn primary big" href="#demo">Try the demo</a></div>
  </section>`;
}

function aboutPage() {
  return `
  <section class="mk-head">
    <h1 class="rise">About <span class="hl">us.</span></h1>
    <p class="sub rise">Keelbook is made by a small independent team with one aim: help small hardware and IoT makers meet the
      vulnerability duties of the Cyber Resilience Act without enterprise tooling.</p>
  </section>
  <section class="mk-section">
    <h2 class="reveal">What we believe.</h2>
    <div class="cards3" data-stagger>
      <div class="card reveal"><h3>Honest about limits</h3><p>A tool that hides what it could not check is worse than no tool. We show it.</p></div>
      <div class="card reveal"><h3>People decide</h3><p>Software can find candidates. Whether something is exploited, and what to report, is a person's call.</p></div>
      <div class="card reveal"><h3>Your data is yours</h3><p>We look up component names and versions. Your code and your SBOM stay with you.</p></div>
    </div>
  </section>
  <section class="cta-panel reveal">
    <h2>More about the team soon.</h2>
    <p>Questions in the meantime? We would like to hear from you.</p>
    <div class="row center"><a class="btn primary big" href="#contact">Contact us</a></div>
  </section>`;
}

function contactPage() {
  return `
  <section class="mk-head">
    <h1 class="rise">Contact <span class="hl">us.</span></h1>
    <p class="sub rise">Using Keelbook for real products, want the server version for your team, or found something to improve?</p>
  </section>
  <section class="contact reveal">
    <div>
      <h2>Tell us about your <span class="hl">products.</span></h2>
      <p>What you build, which build system you use (for example Yocto), and how many releases you support. We reply personally.</p>
      <div class="row"><a class="btn primary big" data-contact>Contact us</a></div>
    </div>
    <ul data-stagger>
      <li class="reveal"><b>Server version</b><span>Logins, named decisions, nightly re-checks and email alerts for your team.</span></li>
      <li class="reveal"><b>Pilot projects</b><span>Try Keelbook on your own SBOMs with our help.</span></li>
      <li class="reveal"><b>Feedback</b><span>What is missing, what is unclear, what is wrong.</span></li>
    </ul>
  </section>`;
}

// ---------- rendering and motion ----------
function renderMarketing(page, view) {
  view.innerHTML = ({ home: homePage, products: productsMarketingPage, how: howPage, about: aboutPage, contact: contactPage }[page] || homePage)();
  view.querySelectorAll("[data-contact]").forEach(contactButton);
  window.scrollTo(0, 0);
  startMotion(view);
  setupTabs(view);
  view.querySelectorAll(".gallery-wrap").forEach(setupGallery);
}

const reduceMotion = () => window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

function startMotion(root) {
  // Items in a [data-stagger] group appear one after another.
  root.querySelectorAll("[data-stagger]").forEach((group) => {
    [...group.children].forEach((el, i) => { el.style.transitionDelay = (i * 90) + "ms"; });
  });
  // The page title block rises in on load.
  root.querySelectorAll(".rise").forEach((el, i) => {
    el.style.transitionDelay = (i * 110) + "ms";
    requestAnimationFrame(() => requestAnimationFrame(() => el.classList.add("in")));
  });
  // Everything else appears when it scrolls into view.
  const items = root.querySelectorAll(".reveal");
  if (reduceMotion() || !("IntersectionObserver" in window)) { items.forEach((el) => el.classList.add("in")); return; }
  const io = new IntersectionObserver((entries) => {
    entries.forEach((e) => { if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); } });
  }, { rootMargin: "0px 0px -8% 0px", threshold: 0.12 });
  items.forEach((el) => io.observe(el));
}

function setupTabs(root) {
  const tabs = root.querySelector(".tabs");
  if (!tabs) return;
  const pill = tabs.querySelector(".tab-pill");
  const buttons = [...tabs.querySelectorAll("button")];
  const place = (b) => { pill.style.width = b.offsetWidth + "px"; pill.style.transform = `translateX(${b.offsetLeft - 4}px)`; };
  place(buttons[0]);
  window.addEventListener("resize", () => place(tabs.querySelector('[aria-selected="true"]')));
  buttons.forEach((b) => b.addEventListener("click", () => {
    buttons.forEach((x) => x.setAttribute("aria-selected", String(x === b)));
    place(b);
    const filter = b.dataset.filter;
    const cards = [...root.querySelectorAll(".product-card")];
    let shown = 0;
    cards.forEach((c) => {
      const show = filter === "all" || c.dataset.kind === filter;
      c.hidden = !show;
      c.classList.remove("in");
      if (show) { c.style.transitionDelay = (shown++ * 90) + "ms"; }
    });
    requestAnimationFrame(() => requestAnimationFrame(() => cards.forEach((c) => c.classList.add("in"))));
    const g = root.querySelector("#productGallery");
    if (g) g.scrollTo({ left: 0, behavior: reduceMotion() ? "auto" : "smooth" });
  }));
  // Cards enter one after another the first time too.
  root.querySelectorAll(".product-card").forEach((c, i) => { c.style.transitionDelay = (300 + i * 90) + "ms"; });
  requestAnimationFrame(() => requestAnimationFrame(() => root.querySelectorAll(".product-card").forEach((c) => c.classList.add("in"))));
}

function setupGallery(wrap) {
  const g = wrap.querySelector(".gallery");
  const [prev, next] = wrap.querySelectorAll(".paddle");
  const update = () => {
    const max = g.scrollWidth - g.clientWidth - 2;
    prev.disabled = g.scrollLeft <= 2;
    next.disabled = g.scrollLeft >= max;
    wrap.classList.toggle("no-scroll", max <= 0);
  };
  const step = () => { const card = g.firstElementChild; return card ? card.offsetWidth + 20 : g.clientWidth * 0.8; };
  prev.addEventListener("click", () => g.scrollBy({ left: -step(), behavior: reduceMotion() ? "auto" : "smooth" }));
  next.addEventListener("click", () => g.scrollBy({ left: step(), behavior: reduceMotion() ? "auto" : "smooth" }));
  g.addEventListener("scroll", update, { passive: true });
  window.addEventListener("resize", update);
  update();
}

// The pages. All work is done by the keelbook engine in worker.js; this file shows forms and tables.
"use strict";

const STATUSES = [["not_affected", "Not affected"], ["affected", "Affected"], ["fixed", "Fixed"], ["under_investigation", "Under investigation"]];
const JUSTIFICATIONS = [["component_not_present", "Component not present"], ["vulnerable_code_not_present", "Vulnerable code not present"],
  ["vulnerable_code_not_in_execute_path", "Vulnerable code not in execute path"], ["vulnerable_code_cannot_be_controlled_by_adversary", "Cannot be controlled by an attacker"],
  ["inline_mitigations_already_exist", "Mitigations already exist"]];
const NEEDS = "needs decision", RECONFIRM = "re-confirm", DECIDED = "decided";

const $ = (id) => document.getElementById(id);
const view = $("view"), msg = $("msg"), engineText = $("engine");
// The free website is a demo: there is no login, so every entry is recorded as DEMO_USER.
// Named decisions with real accounts (password login, roles) are in the Keelbook server version.
const DEMO_USER = "Demo user";
const SERVER_MODE = () => !!window.KEELBOOK_SERVER;
const onDemo = () => !MARKETING_PAGES.includes(route().page) || SERVER_MODE();

// ---------- helpers ----------
function esc(t) { return String(t == null ? "" : t).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
function store(key, value) { try { if (value === undefined) return localStorage.getItem(key); localStorage.setItem(key, value); } catch (e) { return null; } }
function say(text, kind) { msg.textContent = text || ""; msg.className = "notice" + (kind ? " " + kind : ""); if (text) window.scrollTo({ top: 0, behavior: "smooth" }); }
function actor() { return DEMO_USER; }
function when(iso) { return iso ? iso.slice(0, 16).replace("T", " ") : ""; }
function download(name, content, type) {
  const blob = content instanceof Blob ? content : new Blob([content], { type });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob); a.download = name; document.body.appendChild(a); a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
}
function b64Blob(b64, type) {
  const bin = atob(b64), bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new Blob([bytes], { type });
}
async function fileBytes(input) {
  const file = input.files && input.files[0];
  return file ? { name: file.name, bytes: new Uint8Array(await file.arrayBuffer()) } : { name: "", bytes: null };
}
function opts(pairs, empty) {
  return (empty !== undefined ? `<option value="">${esc(empty)}</option>` : "") + pairs.map(([v, t]) => `<option value="${esc(v)}">${esc(t)}</option>`).join("");
}
function sevClass(label) { return "sev-" + (label || "unknown"); }
function stateText(state) { return state === NEEDS ? '<span class="st-open">Needs decision</span>' : state === RECONFIRM ? '<span class="st-re">Re-confirm</span>' : '<span class="st-done">Decided</span>'; }

// ---------- the engine (worker) ----------
let worker, ready = false, nextId = 1;
const waiting = new Map();
function startWorker() {
  ready = false;
  worker = new Worker("worker.js");
  worker.onmessage = (event) => {
    const m = event.data;
    if (m.type === "progress") { engineText.textContent = m.text; engineText.className = ""; if (!ready && onDemo()) render(); }
    else if (m.type === "ready") { ready = true; engineText.textContent = "Ready (engine " + m.engine + ")"; engineText.className = "ready"; if (onDemo()) render(); }
    else if (m.type === "fatal") { engineText.textContent = "Engine failed to start"; say("The engine could not start: " + m.text + "\nCheck the internet connection and reload the page.", "error"); }
    else if (m.type === "task") $("task").textContent = m.text;
    else if (m.type === "log") console.log(m.line);
    else if (m.type === "answer" && waiting.has(m.id)) { waiting.get(m.id)(m.answer); waiting.delete(m.id); }
  };
}
startWorker();
function engine(name, args, blob) {
  return new Promise((resolve) => {
    const id = nextId++;
    waiting.set(id, resolve);
    worker.postMessage({ id, name, args: args || {}, blob: blob || null });
  });
}

let timer = null;
function showProgress(text, stoppable) {
  $("task").textContent = text; $("progress").hidden = false; $("stop").hidden = !stoppable;
  const start = Date.now();
  clearInterval(timer);
  const tick = () => { const s = Math.round((Date.now() - start) / 1000); $("elapsed").textContent = s < 3 ? "" : s < 60 ? s + " s" : Math.floor(s / 60) + " min " + (s % 60) + " s"; };
  tick(); timer = setInterval(tick, 1000);
}
function hideProgress() { clearInterval(timer); $("progress").hidden = true; }
$("stop").addEventListener("click", () => {
  worker.terminate();
  for (const [, resolve] of waiting) resolve({ error: "Stopped. Nothing was recorded for this scan." });
  waiting.clear();
  engineText.textContent = "Restarting the engine..."; engineText.className = "";
  startWorker();
});

async function run(button, text, name, args, blob, stoppable) {
  if (button) button.disabled = true;
  say("");
  showProgress(ready ? text : "Waiting for the engine to finish loading...", stoppable);
  const answer = await engine(name, args, blob);
  hideProgress();
  if (button) button.disabled = false;
  if (answer.error) { say(answer.error, "error"); return null; }
  return answer.ok;
}

// ---------- routing ----------
function route() {
  const parts = decodeURIComponent(location.hash.slice(1)).split("/");
  return { page: parts[0] || (SERVER_MODE() ? "demo" : "home"), id: parts[1], label: parts.slice(2).join("/") };
}
let flash = null;
async function render() {
  const page = route().page;
  const marketing = !SERVER_MODE() && MARKETING_PAGES.includes(page);
  document.body.classList.toggle("is-demo", !marketing);
  document.querySelectorAll(".nav nav a").forEach((a) => a.classList.toggle("active",
    a.getAttribute("href") === "#" + (marketing ? page : "demo")));
  if (marketing) { renderMarketing(page, view); return; }
  if (!ready) {
    const cached = (() => { try { return JSON.parse(store("kb-products") || "null"); } catch (e) { return null; } })();
    if (cached && cached.length && ["demo", "new"].includes(route().page)) { productsTable(cached, true); return; }
    view.innerHTML = `<h1>Loading Keelbook</h1><p class="muted">The first visit downloads about 15 MB and takes up to a minute. Later visits start in a few seconds.</p>
      <p>${esc(engineText.textContent)}</p>`;
    return;
  }
  const r = route();
  if (r.page === "product" && r.id) await productPage(r.id);
  else if (r.page === "release" && r.id && r.label) await releasePage(r.id, r.label);
  else if (r.page === "data") await dataPage();
  else await productsPage();
  if (flash) { say(flash[0], flash[1]); flash = null; }
}
window.addEventListener("hashchange", () => { say(""); render(); });
function go(hash) { if (location.hash.slice(1) === hash) render(); else location.hash = hash; }

// ---------- products ----------
async function productsPage() {
  const list = await run(null, "Loading products...", "products");
  if (!list) return;
  store("kb-products", JSON.stringify(list));
  productsTable(list, false);
  const target = $({ new: "add" }[route().page] || "-");
  if (target) { target.scrollIntoView({ block: "start" }); if (target.id === "add") target.pid.focus({ preventScroll: true }); }
}

// waiting: shown from the copy saved at the last visit while the engine starts (links work once it is ready).
function productsTable(list, waiting) {
  const rows = list.map((p) => `<tr>
      <td><a href="#product/${encodeURIComponent(p.id)}"><b>${esc(p.name)}</b></a><div class="muted small">${esc(p.id)}</div></td>
      <td>${p.latest ? `<a href="#release/${encodeURIComponent(p.id)}/${encodeURIComponent(p.latest)}">${esc(p.latest)}</a>` : '<span class="muted">none yet</span>'}</td>
      <td class="num">${p.latest ? p.findings : ""}</td>
      <td class="num">${p.latest ? (p.counts[NEEDS] ? `<span class="st-open">${p.counts[NEEDS]}</span>` : 0) : ""}</td>
      <td class="num">${p.latest ? p.counts[RECONFIRM] : ""}</td>
      <td class="num">${p.latest ? p.counts[DECIDED] : ""}</td>
      <td class="num">${!p.latest ? "" : p.exploited_checked ? (p.exploited ? `<span class="yes">${p.exploited}</span>` : 0) : '<span class="muted">not checked</span>'}</td>
      <td>${p.details.support_until ? esc(p.details.support_until) : '<span class="muted">not recorded</span>'}</td></tr>`).join("");
  view.innerHTML = (list.length ? `<h1>Your <span class="hl">products</span></h1><p class="sub">Every product you place on the EU market and the state of its latest release.</p>`
      : `<h1>Try <span class="hl">Keelbook.</span></h1><p class="sub">This is the real tool, running in your browser. Add a product,
         scan the SBOM of a release and decide its findings. Nothing is uploaded; entries are recorded as “${DEMO_USER}”.</p>`) +
    (list.length ? `<div class="table-wrap"><table><thead><tr><th>Product</th><th>Latest release</th><th class="num">Findings</th><th class="num">Need a decision</th>
      <th class="num">Re-confirm</th><th class="num">Decided</th><th class="num">On CISA KEV</th><th>End of support</th></tr></thead><tbody>${rows}</tbody></table></div>`
      : `<div class="how">
         <div><b>1</b><h3>Add a product</h3><span>Name, contact for vulnerabilities and end of support.</span></div>
         <div><b>2</b><h3>Scan a release</h3><span>Upload its SBOM. Keelbook finds the known vulnerabilities in its components.</span></div>
         <div><b>3</b><h3>Decide</h3><span>Affected, not affected or fixed, with a reason. Each one is kept in the log.</span></div>
         <div><b>4</b><h3>Prove it</h3><span>Download the evidence record and the VEX file for customers. Back up the register.</span></div></div>`) +
    `<form id="add" class="box"><h2>Add a product</h2>
      <div class="fields">
        <label class="field"><span>Short ID</span><input name="pid" type="text" required placeholder="gateway-x"><small>Letters, digits and dashes. Used in file names.</small></label>
        <label class="field"><span>Name</span><input name="name" type="text" placeholder="Gateway X200"></label>
        ${detailFields({})}
      </div>
      <button class="btn primary" type="submit"${waiting ? " disabled" : ""}>${waiting ? "Starting..." : "Add product"}</button></form>` +
    (SERVER_MODE() ? "" : `<div class="notice">Using Keelbook for real products? The server version records every decision under each
      person's name, with logins and nightly re-checks. <a href="#contact">Contact us</a></div>`);
  if (waiting) return;
  $("add").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = e.target;
    const done = await run(f.querySelector("button"), "Adding the product...", "add_product", { pid: f.pid.value, name: f.name.value, details: detailValues(f), actor: actor() });
    if (done) { flash = ["Product added. Next: scan the SBOM of a release.", "ok"]; go("product/" + encodeURIComponent(done.id)); }
  });
}

function detailFields(d) {
  return `<label class="field"><span>Manufacturer</span><input name="manufacturer" type="text" value="${esc(d.manufacturer || "")}"></label>
    <label class="field"><span>Contact for vulnerabilities</span><input name="contact" type="text" value="${esc(d.contact || "")}" placeholder="security@company.eu"><small>CRA Art. 13(17)</small></label>
    <label class="field"><span>Disclosure policy URL</span><input name="cvd_policy" type="text" value="${esc(d.cvd_policy || "")}"><small>CRA Annex I Part II (5)</small></label>
    <label class="field"><span>End of support</span><input name="support_until" type="date" value="${esc(d.support_until || "")}"><small>CRA Art. 13(8)</small></label>`;
}
function detailValues(f) { return { manufacturer: f.manufacturer.value, contact: f.contact.value, cvd_policy: f.cvd_policy.value, support_until: f.support_until.value }; }

// ---------- one product ----------
async function productPage(pid) {
  const p = await run(null, "Loading...", "product", { pid });
  if (!p) return;
  const d = p.details;
  const releases = p.releases.map((r) => `<tr>
      <td><a href="#release/${encodeURIComponent(p.id)}/${encodeURIComponent(r.label)}"><b>${esc(r.label)}</b></a></td>
      <td>${esc(when(r.scanned_at))}<div class="muted small">${esc(r.scanned_by)}</div></td>
      <td>${esc(r.sbom_file)}</td>
      <td class="num">${r.checked} / ${r.total}${r.not_checked ? `<div class="st-re small">${r.not_checked} not checked</div>` : ""}</td>
      <td class="num">${r.findings}</td><td class="num">${r.counts[NEEDS]}</td><td class="num">${r.counts[RECONFIRM]}</td><td class="num">${r.counts[DECIDED]}</td>
      <td class="num">${r.exploited ? `<span class="yes">${r.exploited}</span>` : 0}</td></tr>`).join("");
  const missing = '<span class="muted">not recorded</span>';
  view.innerHTML = `<div class="crumbs"><a href="#demo">Products</a> / ${esc(p.id)}</div><h1>${esc(p.name)}</h1>
    <p class="sub">Manufacturer: ${d.manufacturer ? esc(d.manufacturer) : missing} · Contact: ${d.contact ? esc(d.contact) : missing} ·
      Disclosure policy: ${d.cvd_policy ? esc(d.cvd_policy) : missing} · End of support: ${d.support_until ? esc(d.support_until) : missing} ·
      <a href="#" id="editToggle">Edit</a></p>
    <form id="edit" class="box" hidden><h2>Product details</h2><div class="fields">${detailFields(d)}</div>
      <button class="btn primary" type="submit">Save details</button> <span class="muted small">Changes are recorded in the log; earlier values stay there too.</span></form>
    <form id="scan" class="box"><h2>Scan the SBOM of a release</h2>
      <div class="fields">
        <label class="field"><span>Release</span><input name="label" type="text" required placeholder="2.1.0"></label>
        <label class="field"><span>SBOM file</span><input name="sbom" type="file" required><small>CycloneDX or SPDX (JSON). Stays on this computer.</small></label>
      </div>
      <div class="check"><input id="o-cve" name="cvelist" type="checkbox" checked><label for="o-cve">Official CVE List for components with a CPE (Yocto, embedded)<br><small>Recommended. Daily copy on this site, no account or key needed.</small></label></div>
      <div class="check"><input id="o-kev" name="kev" type="checkbox" checked><label for="o-kev">Mark findings on CISA's exploited list (KEV)</label></div>
      <div class="check"><input id="o-nvd" name="nvd" type="checkbox"><label for="o-nvd">Also ask NVD<br><small>Optional. Slow without an NVD API key (about 6 seconds per component). Usually not needed with the CVE List.</small></label></div>
      <div class="fields" id="keyRow" hidden><label class="field"><span>NVD API key (optional)</span><input name="key" type="text" value="${esc(store("kb-nvd-key") || "")}"><small>Kept in this browser only. Free at nvd.nist.gov.</small></label></div>
      <p class="muted small">Packages with a purl (npm, PyPI, Maven, Go, ...) are always checked at OSV. Decisions made for the same component version in earlier releases carry over.</p>
      <button class="btn primary" type="submit">Scan and record</button></form>
    <h2>Releases</h2>` +
    (releases ? `<div class="table-wrap"><table><thead><tr><th>Release</th><th>Scanned</th><th>SBOM</th><th class="num">Checked</th><th class="num">Findings</th>
      <th class="num">Need a decision</th><th class="num">Re-confirm</th><th class="num">Decided</th><th class="num">On CISA KEV</th></tr></thead><tbody>${releases}</tbody></table></div>`
      : `<p class="muted">No release scanned yet.</p>`);

  $("editToggle").addEventListener("click", (e) => { e.preventDefault(); $("edit").hidden = !$("edit").hidden; });
  $("o-nvd").addEventListener("change", (e) => { $("keyRow").hidden = !e.target.checked; });
  $("edit").addEventListener("submit", async (e) => {
    e.preventDefault();
    const done = await run(e.target.querySelector("button"), "Saving...", "set_details", { pid, details: detailValues(e.target), actor: actor() });
    if (done) { flash = ["Product details saved.", "ok"]; render(); }
  });
  $("scan").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = e.target, file = await fileBytes(f.sbom);
    store("kb-nvd-key", f.key.value.trim());
    const result = await run(f.querySelector("button"), "Starting the scan...", "scan",
      { pid, label: f.label.value, filename: file.name, use_cvelist: f.cvelist.checked, use_nvd: f.nvd.checked,
        nvd_key: f.key.value.trim() || null, use_kev: f.kev.checked, kev_file: null, actor: actor() }, file.bytes, true);
    if (!result) return;
    justScanned = result.review;
    const skipped = Object.entries(result.skipped).map(([why, n]) => `${n} ${why}`).join("; ");
    flash = [`Release ${result.label} recorded in ${result.seconds} s: ${result.findings} finding(s). Checked ${result.checked} of ${result.total} component(s)` +
      (skipped ? `.\nNOT checked: ${skipped}. These are not counted as clean.` : ".") +
      (result.exploited ? `\n${result.exploited} finding(s) are on CISA's exploited list: review them first.` : "") +
      (result.suggestions ? `\nThe SBOM producer marks ${result.suggestions} open finding(s) as fixed or not affected; you can adopt them below.` : "") +
      (result.warnings.length ? "\n" + result.warnings.join("\n") : ""), skipped ? "warn" : "ok"];
    go("release/" + encodeURIComponent(pid) + "/" + encodeURIComponent(result.label));
  });
}

// ---------- one release ----------
let filterState = "todo", filterText = "", filterComp = "", limit = 200, lastRelease = "";
const SEV_ORDER = ["critical", "high", "medium", "low", "none", "unknown"];
let justScanned = null; // the scan already returns the release page's data
async function releasePage(pid, label) {
  let data = null;
  if (justScanned && justScanned.product.id === pid && justScanned.release.label === label) data = justScanned;
  justScanned = null;
  if (!data) data = await run(null, "Loading findings...", "review", { pid, label });
  if (data) drawRelease(pid, label, data);
}

// Filters only redraw from the data already loaded: instant, and the decision form always
// matches what is on screen.
function drawRelease(pid, label, data) {
  const rel = data.release, c = data.counts;
  const kevUsed = rel.sources.some((s) => s.indexOf("CISA KEV") === 0);
  const notChecked = Object.entries(rel.skipped).map(([why, n]) => `${n} ${why}`).join("; ");
  const exploited = data.rows.filter((r) => r.kev === true).length;
  if (lastRelease !== pid + "/" + label) { lastRelease = pid + "/" + label; filterComp = ""; filterText = ""; limit = 200; }
  // Overview per component: the kernel alone can have thousands of findings.
  const comps = new Map();
  for (const r of data.rows) {
    const k = r.component + " " + r.version;
    const e = comps.get(k) || { name: r.component, version: r.version, total: 0, open: 0, worst: "unknown", kev: 0 };
    e.total++; if (r.state !== DECIDED) e.open++; if (r.kev === true) e.kev++;
    if (r.state !== DECIDED && SEV_ORDER.indexOf(r.severity_label) < SEV_ORDER.indexOf(e.worst)) e.worst = r.severity_label;
    comps.set(k, e);
  }
  const compRows = [...comps.values()].sort((a, b) => b.kev - a.kev || SEV_ORDER.indexOf(a.worst) - SEV_ORDER.indexOf(b.worst) || b.open - a.open);
  const matching = data.rows.filter((r) => {
    if (filterState === "todo" && r.state === DECIDED) return false;
    if (filterState === "decided" && r.state !== DECIDED) return false;
    if (filterComp && r.component + " " + r.version !== filterComp) return false;
    if (filterText) {
      const hay = [r.cve_ids.join(" "), r.other_ids.join(" "), r.component, r.summary, r.decision, r.reason].join(" ").toLowerCase();
      if (hay.indexOf(filterText.toLowerCase()) < 0) return false;
    }
    return true;
  });
  const shown = matching.slice(0, limit);
  const rows = shown.map((r) => `<tr>
      <td><input type="checkbox" name="pick" value="${esc(r.key)}" aria-label="Select"></td>
      <td class="ids"><b>${esc(r.cve_ids[0] || r.other_ids[0] || "")}</b>${[...r.cve_ids.slice(1), ...(r.cve_ids.length ? r.other_ids : r.other_ids.slice(1))].map((i) => `<span>${esc(i)}</span>`).join("")}</td>
      <td><span class="${sevClass(r.severity_label)}">${esc(r.severity)}</span></td>
      <td>${esc(r.component)}<div class="muted small">${esc(r.version)}</div></td>
      <td>${esc(r.fixed_in)}</td>
      <td>${!kevUsed ? '<span class="muted">not checked</span>' : r.kev === true ? '<span class="yes">Yes</span>' : r.kev === false ? "No" : '<span class="muted">unknown</span>'}</td>
      <td>${stateText(r.state)}${r.note ? `<div class="muted small">${esc(r.note)}</div>` : ""}</td>
      <td>${r.decision ? `${esc(r.decision)}<div class="muted small">${esc(r.reason)}</div><div class="muted small">${esc(r.by)}, ${esc(when(r.at))}</div>` : ""}
          ${r.producer ? `<div class="muted small">Producer: ${esc(r.producer)}</div>` : ""}</td>
      <td class="summary-cell">${esc(r.summary)}</td></tr>`).join("");

  view.innerHTML = `<div class="crumbs"><a href="#demo">Products</a> / <a href="#product/${encodeURIComponent(pid)}">${esc(data.product.name)}</a> / ${esc(rel.label)}</div>
    <h1>${esc(data.product.name)} <span class="hl">${esc(rel.label)}</span></h1>
    <p class="sub">${esc(rel.sbom_file)} · scanned ${esc(when(rel.scanned_at))} UTC by ${esc(rel.scanned_by)} · sources: ${esc(rel.sources.join(", ") || "none")}</p>
    <div class="stats">
      <div><b>${data.rows.length}</b><span>findings</span></div>
      <div><b class="${c[NEEDS] ? "st-open" : ""}">${c[NEEDS]}</b><span>need a decision</span></div>
      <div><b class="${c[RECONFIRM] ? "st-re" : ""}">${c[RECONFIRM]}</b><span>re-confirm (version changed)</span></div>
      <div><b>${c[DECIDED]}</b><span>decided</span></div>
      <div><b class="${exploited ? "yes" : ""}">${kevUsed ? exploited : "–"}</b><span>${kevUsed ? "on CISA KEV" : "CISA KEV not checked"}</span></div>
      <div><b>${rel.checked}</b><span>of ${rel.total} components checked</span></div>
    </div>
    ${notChecked ? `<div class="notice warn">Not checked: ${esc(notChecked)}. These components are not counted as clean.</div>` : ""}
    ${exploited ? `<div class="notice error">${exploited} finding(s) are on CISA's exploited list. If one is really exploited in your product, the CRA Art. 14 deadlines (24 h / 72 h) may apply. A person confirms and decides.</div>` : ""}
    <div class="box"><h2>Outputs</h2><div class="row">
      <button class="btn" id="evidence" type="button">Evidence record</button>
      <button class="btn" id="sheet" type="button">Review sheet (Excel)</button>
      <input id="author" type="text" placeholder="VEX author (manufacturer)" value="${esc(store("kb-vex-author") || "")}">
      <button class="btn" id="vex" type="button">OpenVEX for customers</button>
      </div>
      <form id="import" class="row" style="margin-top:10px"><span class="muted">Filled-in review sheet:</span><input name="file" type="file" accept=".xlsx"><button class="btn" type="submit">Import decisions</button></form>
    </div>` +
    (data.suggestions ? `<form id="producer" class="box"><h2>Producer statements</h2><p>The SBOM producer (e.g. Yocto) marks ${data.suggestions} open finding(s) as fixed or not affected. They are not verified by Keelbook.</p>
      <div class="row"><input name="reason" type="text" size="50" placeholder="Reason, e.g. Yocto statements reviewed by J. Doe"><button class="btn" type="submit">Adopt as my decisions</button></div></form>` : "") +
    (compRows.length > 1 ? `<h2>By component</h2><div class="table-wrap"><table><thead><tr><th>Component</th><th>Version</th><th class="num">Findings</th>
      <th class="num">Without decision</th><th>Worst open</th><th class="num">On CISA KEV</th></tr></thead><tbody>${compRows.map((e) => `<tr>
      <td><a href="#" data-comp="${esc(e.name + " " + e.version)}">${esc(e.name)}</a></td><td>${esc(e.version)}</td><td class="num">${e.total}</td>
      <td class="num">${e.open}</td><td>${e.open ? `<span class="${sevClass(e.worst)}">${esc(e.worst)}</span>` : "–"}</td>
      <td class="num">${e.kev ? `<span class="yes">${e.kev}</span>` : kevUsed ? 0 : "–"}</td></tr>`).join("")}</tbody></table></div>` : "") +
    `<form id="decide" class="box"><h2>Decide <span id="picked">0</span> selected finding(s)</h2>
      <div class="check"><input id="allMatching" type="checkbox"><label for="allMatching">Apply to all <b>${matching.length}</b> finding(s) that match the filter below, not only the ticked ones</label></div>
      <div class="fields">
        <label class="field"><span>Decision</span><select name="status">${opts(STATUSES, "Choose...")}</select></label>
        <label class="field" data-for="not_affected"><span>Justification</span><select name="justification">${opts(JUSTIFICATIONS, "Choose...")}</select><small>Or write an impact statement instead.</small></label>
        <label class="field" data-for="not_affected"><span>Impact statement</span><input name="impact" type="text"></label>
        <label class="field" data-for="affected"><span>Action</span><input name="action" type="text" placeholder="Upgrade to 2.33.0 in 2.1.1"></label>
        <label class="field" data-for="fixed"><span>Fixed in release</span><input name="fixed_in" type="text" placeholder="2.1.1"></label>
        <label class="field" style="grid-column: 1 / -1"><span>Reason</span><input name="reason" type="text" placeholder="Why, in your words. Recorded word for word."></label>
      </div>
      <button class="btn primary" type="submit">Record decision</button> <span class="muted small">If anything is missing, nothing is recorded.</span></form>
    <div class="row" style="margin-bottom:10px">
      <select id="fstate"><option value="todo">To do</option><option value="decided">Decided</option><option value="all">All</option></select>
      <select id="fcomp"><option value="">All components</option>${compRows.map((e) => `<option value="${esc(e.name + " " + e.version)}">${esc(e.name + " " + e.version)}</option>`).join("")}</select>
      <input id="ftext" type="search" placeholder="Search CVE, text" value="${esc(filterText)}" style="width:220px">
      <span class="muted">${matching.length} match${matching.length > shown.length ? `, first ${shown.length} shown` : ""}</span>
    </div>
    <div class="table-wrap"><table><thead><tr><th><input type="checkbox" id="all" aria-label="Select all shown"></th><th>Vulnerability</th><th>Severity</th><th>Component</th>
      <th>Fixed in</th><th>CISA KEV</th><th>State</th><th>Decision</th><th>Summary</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="9" class="muted">Nothing here. Change the filter to see decided findings.</td></tr>'}</tbody></table></div>
    ${matching.length > shown.length ? `<button class="btn" id="more" type="button">Show ${Math.min(200, matching.length - shown.length)} more</button>` : ""}`;

  const again = () => drawRelease(pid, label, data);
  $("fstate").value = filterState;
  $("fstate").addEventListener("change", (e) => { filterState = e.target.value; again(); });
  $("ftext").addEventListener("change", (e) => { filterText = e.target.value; limit = 200; again(); });
  $("fcomp").value = filterComp;
  $("fcomp").addEventListener("change", (e) => { filterComp = e.target.value; limit = 200; again(); });
  view.querySelectorAll("[data-comp]").forEach((a) => a.addEventListener("click", (e) => { e.preventDefault(); filterComp = a.dataset.comp; limit = 200; again(); $("decide").scrollIntoView(); }));
  if ($("more")) $("more").addEventListener("click", () => { limit += 200; again(); });
  const form = $("decide");
  const picks = () => Array.from(view.querySelectorAll('input[name="pick"]:checked')).map((x) => x.value);
  const updatePicked = () => {
    const n = $("allMatching").checked ? matching.length : picks().length;
    $("picked").textContent = n;
    form.querySelector("button").textContent = n ? `Record decision for ${n} finding(s)` : "Record decision";
  };
  $("allMatching").addEventListener("change", updatePicked);
  view.querySelectorAll('input[name="pick"]').forEach((x) => x.addEventListener("change", updatePicked));
  $("all").addEventListener("change", (e) => { view.querySelectorAll('input[name="pick"]').forEach((x) => { x.checked = e.target.checked; }); updatePicked(); });
  const showFor = () => form.querySelectorAll("[data-for]").forEach((el) => { el.hidden = el.dataset.for !== form.status.value; });
  form.status.addEventListener("change", showFor); showFor();

  $("evidence").addEventListener("click", async (e) => {
    const out = await run(e.target, "Writing the evidence record...", "evidence", { pid, label });
    if (out) download(out.filename, out.html, "text/html");
  });
  $("sheet").addEventListener("click", async (e) => {
    const out = await run(e.target, "Writing the review sheet...", "sheet", { pid, label });
    if (out) download(out.filename, b64Blob(out.b64, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"));
  });
  $("vex").addEventListener("click", async (e) => {
    const author = $("author").value.trim();
    store("kb-vex-author", author);
    const out = await run(e.target, "Writing OpenVEX...", "vex", { pid, label, author });
    if (out) { download(out.filename, out.json, "application/json"); say(`OpenVEX file with ${out.counts.exported} decision(s). Findings without a decision for their version are not included.`, "ok"); }
  });
  $("import").addEventListener("submit", async (e) => {
    e.preventDefault();
    const file = await fileBytes(e.target.file);
    const out = await run(e.target.querySelector("button"), "Importing...", "import_sheet", { pid, label, actor: actor() }, file.bytes);
    if (out) { flash = [`Imported ${out.recorded} decision(s), recorded by ${actor()}.`, "ok"]; render(); }
  });
  const producer = $("producer");
  if (producer) producer.addEventListener("submit", async (e) => {
    e.preventDefault();
    const out = await run(e.target.querySelector("button"), "Recording...", "accept_producer", { pid, label, reason: e.target.reason.value, actor: actor() });
    if (out) { flash = [`Adopted ${out.recorded} producer statement(s) as decisions by ${actor()}.`, "ok"]; render(); }
  });
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const decision = { status: form.status.value, justification: form.justification.value, impact: form.impact.value, action: form.action.value, fixed_in: form.fixed_in.value, reason: form.reason.value };
    for (const k of ["justification", "impact", "action", "fixed_in"]) if (form[k].closest("[data-for]").hidden) decision[k] = "";
    const keys = $("allMatching").checked ? matching.map((r) => r.key) : picks();
    const out = await run(form.querySelector("button"), "Recording...", "decide", { pid, label, keys, decision, actor: actor() });
    if (out) { flash = [`Recorded ${out.recorded} decision(s) as ${decision.status.replace(/_/g, " ")}, by ${actor()}.`, "ok"]; render(); }
  });
}

// ---------- backup ----------
async function dataPage() {
  const v = await run(null, "Checking the log...", "verify");
  if (!v) return;
  view.innerHTML = `<div class="crumbs"><a href="#demo">Products</a> / Backup and restore</div><h1>Backup and restore</h1>
    <p class="sub">The register is kept in this browser. Clearing the browser's site data deletes it, and Safari may delete it after 7 days without a visit. Download a backup after each session.</p>
    <div class="box"><h2>Log</h2>
      <p>${v.count ? (v.ok ? `<span class="st-done">Verified</span>: ${v.count} entries, none changed or removed.` : `<span class="st-open">FAILED</span>: ${esc(v.problem)}`) : "Empty: nothing recorded yet."}</p>
      ${v.head ? `<p class="small">Head hash: <code>${esc(v.head)}</code><br><span class="muted">Keep it somewhere else too (e.g. email it to yourself): removing the newest entries can only be detected by comparing it.</span></p>` : ""}
    </div>
    <div class="box"><h2>Backup</h2><p>A single file, <code>keelbook.db</code>. The keelbook command-line tool opens the same file.</p>
      <button class="btn primary" id="backup" type="button">Download backup</button></div>
    <form class="box" id="restore"><h2>Restore</h2><p>Replaces the register in this browser with a backup. The backup's log is checked first.</p>
      <div class="row"><input name="file" type="file" accept=".db"><button class="btn" type="submit">Restore</button></div></form>`;
  $("backup").addEventListener("click", async (e) => {
    const out = await run(e.target, "Preparing the backup...", "export_db");
    if (out) download(out.filename, b64Blob(out.b64, "application/octet-stream"));
  });
  $("restore").addEventListener("submit", async (e) => {
    e.preventDefault();
    const file = await fileBytes(e.target.file);
    const out = await run(e.target.querySelector("button"), "Restoring...", "import_db", {}, file.bytes);
    if (out) { flash = [`Restored: ${out.count} entries, log verified.`, "ok"]; render(); }
  });
}

render();

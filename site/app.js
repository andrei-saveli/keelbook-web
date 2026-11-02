// The pages. All work is done by the keelbook engine in worker.js; this file only shows forms and tables.
"use strict";

const STATUSES = ["not_affected", "affected", "fixed", "under_investigation"];
const JUSTIFICATIONS = ["component_not_present", "vulnerable_code_not_present", "vulnerable_code_not_in_execute_path",
  "vulnerable_code_cannot_be_controlled_by_adversary", "inline_mitigations_already_exist"];
const NEEDS = "needs decision", RECONFIRM = "re-confirm", DECIDED = "decided";

const view = document.getElementById("view");
const msg = document.getElementById("msg");
const actorInput = document.getElementById("actor");
const engineText = document.getElementById("engine");

// ---------- small helpers ----------
function esc(text) {
  return String(text == null ? "" : text).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function store(key, value) { try { if (value === undefined) return localStorage.getItem(key); localStorage.setItem(key, value); } catch (e) { return null; } }
function say(text, isError) { msg.textContent = text || ""; msg.className = isError ? "error" : ""; if (text) msg.scrollIntoView({ block: "nearest" }); }
function actor() { return actorInput.value.trim(); }
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
function options(values, selected, empty) {
  return (empty !== undefined ? `<option value="">${esc(empty)}</option>` : "") +
    values.map((v) => `<option${v === selected ? " selected" : ""}>${esc(v)}</option>`).join("");
}

// ---------- the engine (worker) ----------
const worker = new Worker("worker.js");
let nextId = 1, busy = 0;
const waiting = new Map();
worker.onmessage = (event) => {
  const m = event.data;
  if (m.type === "progress") engineText.textContent = m.text;
  else if (m.type === "ready") { engineText.textContent = "Engine: keelbook " + m.engine; render(); }
  else if (m.type === "fatal") { engineText.textContent = "Engine failed to start"; say("The engine could not start: " + m.text + "\nCheck the internet connection and reload.", true); }
  else if (m.type === "log") console.log(m.line);
  else if (m.type === "answer" && waiting.has(m.id)) { waiting.get(m.id)(m.answer); waiting.delete(m.id); }
};
function engine(name, args, blob) {
  return new Promise((resolve) => {
    const id = nextId++;
    waiting.set(id, resolve);
    worker.postMessage({ id, name, args: args || {}, blob: blob || null });
  });
}
async function run(button, workingText, name, args, blob) {
  if (button) button.disabled = true;
  busy++; say(workingText || "Working...");
  const answer = await engine(name, args, blob);
  busy--; if (button) button.disabled = false;
  if (answer.error) { say(answer.error, true); return null; }
  say("");
  return answer.ok;
}

// ---------- routing ----------
function route() {
  const parts = decodeURIComponent(location.hash.slice(1)).split("/");
  return { page: parts[0] || "products", id: parts[1], label: parts.slice(2).join("/") };
}
let flash = ""; // a message to show after the next page has loaded (e.g. the scan summary)
async function render() {
  if (engineText.textContent.indexOf("Engine:") !== 0) { view.innerHTML = "<p>Loading the engine. The first visit takes about a minute.</p>"; return; }
  const r = route();
  if (r.page === "product" && r.id) await productPage(r.id);
  else if (r.page === "release" && r.id && r.label) await releasePage(r.id, r.label);
  else if (r.page === "data") await dataPage();
  else await productsPage();
  if (flash) { say(flash); flash = ""; }
}
window.addEventListener("hashchange", () => { say(""); render(); });
actorInput.value = store("kb-name") || "";
actorInput.addEventListener("change", () => store("kb-name", actor()));

// ---------- pages ----------
async function productsPage() {
  const list = await run(null, "Loading products...", "products");
  if (!list) return;
  const rows = list.map((p) => `<tr><td><a href="#product/${encodeURIComponent(p.id)}">${esc(p.id)}</a></td><td>${esc(p.name)}</td>` +
    `<td>${p.latest ? `<a href="#release/${encodeURIComponent(p.id)}/${encodeURIComponent(p.latest)}">${esc(p.latest)}</a>` : "no release scanned"}</td>` +
    `<td class="n">${p.latest ? p.findings : ""}</td><td class="n">${p.latest ? p.counts[NEEDS] : ""}</td><td class="n">${p.latest ? p.counts[RECONFIRM] : ""}</td>` +
    `<td class="n">${p.latest ? p.counts[DECIDED] : ""}</td><td>${!p.latest ? "" : p.exploited_checked ? p.exploited : "not checked"}</td>` +
    `<td>${esc(p.details.support_until || "not recorded")}</td></tr>`).join("");
  view.innerHTML = `<h2>Products</h2>` +
    (list.length ? `<div class="wide"><table><tr><th>ID</th><th>Name</th><th>Latest release</th><th>Findings</th><th>Need a decision</th><th>Re-confirm</th><th>Decided</th><th>On CISA KEV</th><th>Support until</th></tr>${rows}</table></div>`
      : `<p>No products yet. Add the first one below.</p>`) +
    `<form id="add"><fieldset><legend>Add a product</legend>
      <label>ID <input name="pid" required size="14" placeholder="gateway-x"></label>
      <label>Name <input name="name" size="24" placeholder="Gateway X200"></label><br>
      ${detailInputs({})}
      <br><button type="submit">Add product</button></fieldset></form>`;
  document.getElementById("add").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = e.target, button = f.querySelector("button");
    const done = await run(button, "Adding...", "add_product", { pid: f.pid.value, name: f.name.value, details: detailValues(f), actor: actor() });
    if (done) location.hash = "product/" + encodeURIComponent(done.id);
  });
}

function detailInputs(d) {
  return `<label>Manufacturer <input name="manufacturer" size="24" value="${esc(d.manufacturer || "")}"></label>
    <label>Contact for vulnerabilities (Art. 13(17)) <input name="contact" size="24" value="${esc(d.contact || "")}"></label><br>
    <label>Disclosure policy URL (Annex I Part II (5)) <input name="cvd_policy" size="30" value="${esc(d.cvd_policy || "")}"></label>
    <label>End of support (Art. 13(8)) <input name="support_until" type="date" value="${esc(d.support_until || "")}"></label>`;
}
function detailValues(f) {
  return { manufacturer: f.manufacturer.value, contact: f.contact.value, cvd_policy: f.cvd_policy.value, support_until: f.support_until.value };
}

async function productPage(pid) {
  const p = await run(null, "Loading...", "product", { pid });
  if (!p) return;
  const d = p.details;
  const releases = p.releases.map((r) => `<tr><td><a href="#release/${encodeURIComponent(p.id)}/${encodeURIComponent(r.label)}">${esc(r.label)}</a></td>` +
    `<td>${esc(r.scanned_at.slice(0, 16).replace("T", " "))} by ${esc(r.scanned_by)}</td><td>${esc(r.sbom_file)}</td>` +
    `<td class="n">${r.checked} of ${r.total}${r.not_checked ? ` (${r.not_checked} NOT checked)` : ""}</td>` +
    `<td class="n">${r.findings}</td><td class="n">${r.counts[NEEDS]}</td><td class="n">${r.counts[RECONFIRM]}</td><td class="n">${r.counts[DECIDED]}</td><td class="n">${r.exploited}</td></tr>`).join("");
  const nvdKey = store("kb-nvd-key") || "";
  view.innerHTML = `<p><a href="#">Products</a> / ${esc(p.id)}</p><h2>${esc(p.name)} (${esc(p.id)})</h2>
    <table>
      <tr><th>Manufacturer</th><td>${esc(d.manufacturer || "not recorded")}</td></tr>
      <tr><th>Contact for vulnerabilities</th><td>${esc(d.contact || "not recorded")}</td></tr>
      <tr><th>Disclosure policy</th><td>${esc(d.cvd_policy || "not recorded")}</td></tr>
      <tr><th>End of support</th><td>${esc(d.support_until || "not recorded")}</td></tr>
    </table>
    <h3>Releases</h3>` +
    (releases ? `<div class="wide"><table><tr><th>Release</th><th>Scanned</th><th>SBOM</th><th>Components checked</th><th>Findings</th><th>Need a decision</th><th>Re-confirm</th><th>Decided</th><th>On CISA KEV</th></tr>${releases}</table></div>`
      : "<p>No release scanned yet.</p>") +
    `<form id="scan"><fieldset><legend>Scan the SBOM of a release</legend>
      <label>Release <input name="label" required size="10" placeholder="2.1.0"></label>
      <label>SBOM file (CycloneDX or SPDX JSON) <input name="sbom" type="file" required></label><br>
      <label><input name="kev" type="checkbox" checked> Mark findings on the CISA KEV exploited list</label><br>
      <label><input name="nvd" type="checkbox" checked> Also check components that only have a CPE at NVD (Yocto). Slow without an API key: about 6 seconds per component.</label><br>
      <label>NVD API key (optional, kept in this browser only) <input name="key" size="40" value="${esc(nvdKey)}"></label><br>
      <button type="submit">Scan and record</button>
      <p>Earlier decisions for the same component version carry over. Scanning the same release again replaces its findings.</p>
    </fieldset></form>
    <form id="edit"><fieldset><legend>Change product details</legend>${detailInputs(d)}<br><button type="submit">Record changes</button></fieldset></form>`;

  document.getElementById("scan").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = e.target, button = f.querySelector("button");
    const file = await fileBytes(f.sbom);
    store("kb-nvd-key", f.key.value.trim());
    const result = await run(button, "Scanning. This can take several minutes for a large SBOM; keep this tab open.", "scan",
      { pid, label: f.label.value, filename: file.name, use_nvd: f.nvd.checked, nvd_key: f.key.value.trim() || null, use_kev: f.kev.checked, kev_file: null, actor: actor() }, file.bytes);
    if (!result) return;
    const skipped = Object.entries(result.skipped).map(([why, n]) => `${n} ${why}`).join("; ");
    flash = `Recorded release ${result.label}: ${result.findings} finding(s). Checked ${result.checked} of ${result.total} component(s)` +
      (skipped ? `; NOT checked: ${skipped}` : "") + `.` + (result.exploited ? `\n${result.exploited} finding(s) are on the CISA KEV exploited list: review them first.` : "") +
      (result.suggestions ? `\nThe SBOM producer marks ${result.suggestions} open finding(s) as fixed / not affected (see below).` : "") +
      (result.warnings.length ? "\n" + result.warnings.join("\n") : "");
    const target = "release/" + encodeURIComponent(pid) + "/" + encodeURIComponent(result.label);
    if (location.hash.slice(1) === target) render(); else location.hash = target;
  });
  document.getElementById("edit").addEventListener("submit", async (e) => {
    e.preventDefault();
    const done = await run(e.target.querySelector("button"), "Recording...", "set_details", { pid, details: detailValues(e.target), actor: actor() });
    if (done) { await productPage(pid); say("Product details recorded."); }
  });
}

let filterState = "todo", filterText = "";

async function releasePage(pid, label) {
  const data = await run(null, "Loading findings...", "review", { pid, label });
  if (!data) return;
  const rel = data.release, c = data.counts;
  const skipped = Object.entries(rel.skipped).map(([why, n]) => `${n} ${why}`).join("; ");
  const shown = data.rows.filter((r) => {
    if (filterState === "todo" && r.state === DECIDED) return false;
    if (filterState === "decided" && r.state !== DECIDED) return false;
    if (filterText) {
      const hay = [r.cve_ids.join(" "), r.other_ids.join(" "), r.component, r.summary, r.decision].join(" ").toLowerCase();
      if (hay.indexOf(filterText.toLowerCase()) < 0) return false;
    }
    return true;
  });
  const kevUsed = rel.sources.some((s) => s.indexOf("CISA KEV") === 0);
  const rows = shown.map((r) => `<tr><td><input type="checkbox" name="pick" value="${esc(r.key)}"></td>` +
    `<td>${esc(r.cve_ids.join(" ") || r.other_ids[0] || "")}${r.cve_ids.length && r.other_ids.length ? "<br>" + esc(r.other_ids.join(" ")) : ""}</td>` +
    `<td>${esc(r.component)}</td><td>${esc(r.version)}</td><td>${esc(r.severity)}</td><td>${esc(r.fixed_in)}</td>` +
    `<td>${!kevUsed ? "not checked" : r.kev === true ? "<b>YES</b>" : r.kev === false ? "no" : "unknown"}</td>` +
    `<td>${esc(r.state)}${r.note ? "<br>" + esc(r.note) : ""}</td>` +
    `<td>${r.decision ? esc(r.decision) + "<br>" + esc(r.reason) + "<br>" + esc(r.by) + ", " + esc(r.at.slice(0, 16).replace("T", " ")) : ""}</td>` +
    `<td>${esc(r.producer)}</td><td>${esc(r.summary)}</td></tr>`).join("");
  view.innerHTML = `<p><a href="#">Products</a> / <a href="#product/${encodeURIComponent(pid)}">${esc(pid)}</a> / ${esc(rel.label)}</p>
    <h2>${esc(data.product.name)}, release ${esc(rel.label)}</h2>
    <table>
      <tr><th>SBOM</th><td>${esc(rel.sbom_file)}, SHA-256 ${esc(rel.sbom_sha256)}</td></tr>
      <tr><th>Scanned</th><td>${esc(rel.scanned_at.slice(0, 16).replace("T", " "))} UTC by ${esc(rel.scanned_by)}</td></tr>
      <tr><th>Components checked</th><td>${rel.checked} of ${rel.total}${skipped ? `. NOT checked: ${esc(skipped)}` : ""}</td></tr>
      <tr><th>Sources</th><td>${esc(rel.sources.join("; ") || "none")}</td></tr>
      <tr><th>Findings</th><td>${data.rows.length}: ${c[NEEDS]} need a decision, ${c[RECONFIRM]} re-confirm (version changed), ${c[DECIDED]} decided</td></tr>
    </table>
    <p><button id="evidence">Download evidence record (HTML)</button>
      <button id="sheet">Download review sheet (Excel)</button>
      <label>VEX author <input id="author" size="18" value="${esc(store("kb-vex-author") || "")}" placeholder="manufacturer name"></label><button id="vex">Download OpenVEX</button></p>
    <form id="import"><label>Import a filled-in review sheet <input name="file" type="file" accept=".xlsx"></label><button type="submit">Import</button></form>` +
    (data.suggestions ? `<form id="producer"><label>The SBOM producer marks ${data.suggestions} open finding(s) as fixed / not affected. Reason for adopting them <input name="reason" size="40"></label><button type="submit">Adopt as my decisions</button></form>` : "") +
    `<form id="decide"><fieldset><legend>Decide the ticked findings</legend>
      <label>Decision <select name="status">${options(STATUSES, "", "choose")}</select></label>
      <label>Justification (not_affected) <select name="justification">${options(JUSTIFICATIONS, "", "")}</select></label>
      <label>Impact statement (not_affected, instead of a justification) <input name="impact" size="30"></label><br>
      <label>Action (affected) <input name="action" size="40"></label>
      <label>Fixed in release (fixed) <input name="fixed_in" size="10"></label><br>
      <label>Reason (always) <input name="reason" size="80"></label><br>
      <button type="submit">Record decision</button> All ticked findings get this decision; if anything is missing, nothing is recorded.
    </fieldset></form>
    <p><label>Show <select id="fstate">${[["todo", "to do"], ["decided", "decided"], ["all", "all"]].map(([v, t]) => `<option value="${v}"${v === filterState ? " selected" : ""}>${t}</option>`).join("")}</select></label>
      <label>Search <input id="ftext" value="${esc(filterText)}" size="30"></label> ${shown.length} of ${data.rows.length} shown
      <button id="tickall" type="button">Tick all shown</button></p>
    <div class="wide"><table><tr><th></th><th>Vulnerability</th><th>Component</th><th>Version</th><th>Severity</th><th>Fixed in</th><th>On CISA KEV</th><th>State</th><th>Decision</th><th>Producer says</th><th>Summary</th></tr>${rows || '<tr><td colspan="11">Nothing to show.</td></tr>'}</table></div>`;

  const again = () => releasePage(pid, label);
  document.getElementById("fstate").addEventListener("change", (e) => { filterState = e.target.value; again(); });
  document.getElementById("ftext").addEventListener("change", (e) => { filterText = e.target.value; again(); });
  document.getElementById("tickall").addEventListener("click", () => view.querySelectorAll('input[name="pick"]').forEach((x) => { x.checked = true; }));
  document.getElementById("evidence").addEventListener("click", async (e) => {
    const out = await run(e.target, "Writing the evidence record...", "evidence", { pid, label });
    if (out) download(out.filename, out.html, "text/html");
  });
  document.getElementById("sheet").addEventListener("click", async (e) => {
    const out = await run(e.target, "Writing the review sheet...", "sheet", { pid, label });
    if (out) download(out.filename, b64Blob(out.b64, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"));
  });
  document.getElementById("vex").addEventListener("click", async (e) => {
    const author = document.getElementById("author").value.trim();
    store("kb-vex-author", author);
    const out = await run(e.target, "Writing OpenVEX...", "vex", { pid, label, author });
    if (out) { download(out.filename, out.json, "application/json"); say(`OpenVEX written with ${out.counts.exported} decision(s). Findings without a decision for their version are not in the file.`); }
  });
  document.getElementById("import").addEventListener("submit", async (e) => {
    e.preventDefault();
    const file = await fileBytes(e.target.file);
    const out = await run(e.target.querySelector("button"), "Importing...", "import_sheet", { pid, label, actor: actor() }, file.bytes);
    if (out) { await again(); say(`Imported ${out.recorded} decision(s), recorded by ${actor()}.`); }
  });
  const producer = document.getElementById("producer");
  if (producer) producer.addEventListener("submit", async (e) => {
    e.preventDefault();
    const out = await run(e.target.querySelector("button"), "Recording...", "accept_producer", { pid, label, reason: e.target.reason.value, actor: actor() });
    if (out) { await again(); say(`Adopted ${out.recorded} producer statement(s) as decisions by ${actor()}.`); }
  });
  document.getElementById("decide").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = e.target;
    const keys = Array.from(view.querySelectorAll('input[name="pick"]:checked')).map((x) => x.value);
    const decision = { status: f.status.value, justification: f.justification.value, impact: f.impact.value, action: f.action.value, fixed_in: f.fixed_in.value, reason: f.reason.value };
    const out = await run(f.querySelector("button"), "Recording...", "decide", { pid, label, keys, decision, actor: actor() });
    if (out) { await again(); say(`Recorded ${out.recorded} decision(s) as ${decision.status}, by ${actor()}.`); }
  });
}

async function dataPage() {
  const v = await run(null, "Checking the log...", "verify");
  if (!v) return;
  view.innerHTML = `<p><a href="#">Products</a> / Backup and restore</p><h2>Backup and restore</h2>
    <p>The register is kept in this browser's storage. Clearing the browser's site data deletes it. Download a backup regularly and keep it somewhere safe.</p>
    <table><tr><th>Log</th><td>${v.count ? (v.ok ? `Verified: ${v.count} entries` : `FAILED: ${esc(v.problem)}`) : "empty"}</td></tr>
      <tr><th>Head hash</th><td>${esc(v.head || "-")}</td></tr></table>
    <p>Keep the head hash somewhere else too (e.g. email it to yourself): removing the newest entries can only be detected by comparing it.</p>
    <p><button id="backup">Download backup (keelbook.db)</button></p>
    <form id="restore"><label>Restore from a backup (replaces the register in this browser) <input name="file" type="file" accept=".db"></label><button type="submit">Restore</button></form>
    <p>The backup is the same file the keelbook command-line tool uses, so you can also open it there.</p>`;
  document.getElementById("backup").addEventListener("click", async (e) => {
    const out = await run(e.target, "Preparing the backup...", "export_db");
    if (out) download(out.filename, b64Blob(out.b64, "application/octet-stream"));
  });
  document.getElementById("restore").addEventListener("submit", async (e) => {
    e.preventDefault();
    const file = await fileBytes(e.target.file);
    const out = await run(e.target.querySelector("button"), "Restoring...", "import_db", {}, file.bytes);
    if (out) { await dataPage(); say(`Restored: ${out.count} entries, log verified.`); }
  });
}

render();

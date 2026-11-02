// End-to-end check of the site in a real browser (needs internet: Pyodide CDN, OSV).
// Usage: python3 -m http.server -d site 8000 &  then  node tests/browser_check.js http://localhost:8000/ SBOM_FILE OUT_DIR CPE_SBOM_FILE
const { chromium } = require("playwright");
const [url, sbom, out] = process.argv.slice(2);
let pageRef = null; const logs = [];
(async () => {
  const proxy = process.env.HTTPS_PROXY ? { server: process.env.HTTPS_PROXY, bypass: "localhost,127.0.0.1" } : undefined;
  const browser = await chromium.launch({ proxy });
  const page = await browser.newPage({ ignoreHTTPSErrors: true, acceptDownloads: true, viewport: { width: 1300, height: 900 } });
  const problems = []; pageRef = page;
  page.on("pageerror", (e) => problems.push("pageerror: " + e.message));
  page.on("console", (m) => { logs.push(m.type() + ": " + m.text()); if (m.type() === "error") problems.push("console: " + m.text()); });
  const step = async (name, fn) => { const t = Date.now(); await fn(); console.log("ok", name, ((Date.now() - t) / 1000).toFixed(1) + "s"); };
  const msg = () => page.textContent("#msg");
  await step("engine starts", async () => {
    await page.goto(url);
    await page.waitForFunction(() => document.getElementById("engine").textContent.startsWith("Ready"), null, { timeout: 180000 });
  });
  await step("add product", async () => {
    await page.fill("#actor", "Ana Pop"); await page.dispatchEvent("#actor", "change");
    await page.fill('#add [name=pid]', "gw"); await page.fill('#add [name=name]', "Gateway");
    await page.fill('#add [name=contact]', "security@acme.example");
    await page.click("#add button"); await page.waitForSelector("#scan");
  });
  await step("scan with OSV and CISA KEV", async () => {
    await page.fill('#scan [name=label]', "1.0"); await page.setInputFiles('#scan [name=sbom]', sbom);
    await page.uncheck('#scan [name=nvd]');
    await page.click("#scan button");
    await page.waitForFunction(() => { const m = document.getElementById("msg"); return m.textContent.startsWith("Release ") || m.className.includes("error"); }, null, { timeout: 300000 });
    if (!(await msg()).startsWith("Release ")) throw new Error("scan failed");
    console.log("   ", (await msg()).split("\n")[0]);
  });
  await step("exploited finding marked", async () => {
    const row = await page.textContent("tr:has-text('CVE-2021-44228')");
    if (!row.includes("Yes")) throw new Error("KEV not marked: " + row);
  });
  await step("incomplete decision refused", async () => {
    await page.check("tr:has-text('CVE-2024-35195') input[name=pick]");
    await page.selectOption('#decide [name=status]', "not_affected");
    await page.fill('#decide [name=reason]', "Session verify=False is never used");
    await page.click("#decide button"); await page.waitForFunction(() => document.getElementById("msg").className.includes("error"));
    console.log("   ", (await msg()).replace(/\n/g, " | ").slice(0, 160));
  });
  await step("decision recorded", async () => {
    await page.selectOption('#decide [name=justification]', "vulnerable_code_not_in_execute_path");
    await page.click("#decide button");
    await page.waitForFunction(() => document.getElementById("msg").textContent.startsWith("Recorded 1 decision"));
  });
  for (const [id, name] of [["#evidence", "evidence.html"], ["#sheet", "review.xlsx"]]) {
    await step("download " + name, async () => {
      const [d] = await Promise.all([page.waitForEvent("download"), page.click(id)]);
      await d.saveAs(out + "/" + name);
    });
  }
  await step("download OpenVEX", async () => {
    await page.fill("#author", "ACME SRL");
    const [d] = await Promise.all([page.waitForEvent("download"), page.click("#vex")]);
    await d.saveAs(out + "/gw.openvex.json");
  });
  await page.screenshot({ path: out + "/release.png", fullPage: true });
  await step("Yocto-style SBOM (CPE only) through the CVE List copy, no NVD", async () => {
    await page.click("text=Gateway"); await page.waitForSelector("#scan");
    await page.fill('#scan [name=label]', "2.0"); await page.setInputFiles('#scan [name=sbom]', process.argv[5]);
    await page.click("#scan button");
    await page.waitForFunction(() => { const m = document.getElementById("msg"); return m.textContent.startsWith("Release ") || m.className.includes("error"); }, null, { timeout: 300000 });
    console.log("   ", (await msg()).split("\n")[0]);
    await page.selectOption("#fstate", "all");
    const text = await page.textContent("table");
    if (!text.includes("CVE-2025-9230")) throw new Error("CVE-2025-9230 (OpenSSL 3.4.2) not found via the CVE List");
  });
  await page.screenshot({ path: out + "/release2.png", fullPage: true });
  await step("register kept after reload", async () => {
    await page.reload();
    await page.waitForFunction(() => document.getElementById("engine").textContent.startsWith("Ready"), null, { timeout: 180000 });
    await page.waitForSelector("text=Gateway");
    const text = await page.textContent("#view");
    if (!text.includes("2.0")) throw new Error("release missing after reload");
  });
  await page.screenshot({ path: out + "/products.png", fullPage: true });
  await step("backup and log check", async () => {
    await page.click("text=Backup and restore"); await page.waitForSelector("#backup");
    const [d] = await Promise.all([page.waitForEvent("download"), page.click("#backup")]);
    await d.saveAs(out + "/keelbook.db");
    console.log("   ", (await page.textContent(".box")).replace(/\s+/g, " ").slice(0, 120));
  });
  console.log(problems.length ? "PROBLEMS:\n" + problems.join("\n") : "no browser errors");
  await browser.close();
})().catch(async (e) => { console.error("FAILED:", e.message.split("\n")[0]); try { console.error("message on page:", await pageRef.textContent("#msg")); } catch (x) {} console.error(logs.slice(-15).join("\n")); process.exit(1); });

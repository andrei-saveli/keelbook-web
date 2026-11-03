// Runs the keelbook engine (Python) in the browser with Pyodide, away from the page so it stays
// responsive during long lookups. The register lives in the browser's storage (IndexedDB).
"use strict";

const PYODIDE = "https://cdn.jsdelivr.net/pyodide/v0.27.7/full/";
const ENGINE_WHEEL = "vendor/keelbook-1.0.0-py3-none-any.whl";
importScripts(PYODIDE + "pyodide.js");

let py = null;
let call = null;
let net_ = null;
const base = self.location.href.replace(/worker\.js.*$/, "");

function syncfs(populate) {
  return new Promise((resolve, reject) => py.FS.syncfs(populate, (err) => (err ? reject(err) : resolve())));
}

async function start() {
  post({ type: "progress", text: "Starting Python..." });
  // Download the engine's files while Python starts (all cached by the browser after the first visit).
  const files = Promise.all([
    fetch(base + ENGINE_WHEEL).then((r) => r.arrayBuffer()),
    ...["browser_net.py", "bridge.py"].map((name) => fetch(base + "py/" + name, { cache: "no-cache" }).then((r) => r.text())),
  ]);
  py = await loadPyodide({ indexURL: PYODIDE });
  py.setStdout({ batched: (line) => post({ type: "log", line }) });
  py.setStderr({ batched: (line) => post({ type: "log", line }) });
  post({ type: "progress", text: "Loading the keelbook engine..." });
  const [, [wheel, net, bridge]] = await Promise.all([
    py.loadPackage(["click", "rich", "sqlite3"]),
    files,
  ]);
  py.unpackArchive(wheel, "wheel"); // the engine; no package installer needed
  py.FS.mkdirTree("/data");
  py.FS.mount(py.FS.filesystems.IDBFS, {}, "/data");
  await syncfs(true);
  py.FS.writeFile("/home/pyodide/browser_net.py", net);
  py.FS.writeFile("/home/pyodide/bridge.py", bridge);
  py.runPython(`
import os, sys
sys.path.insert(0, "/home/pyodide")
os.environ["KEELBOOK_DB"] = "/data/keelbook.db"
os.environ["KEELBOOK_CACHE"] = "/data/cache"
import browser_net  # before keelbook: network and sleep for the browser
import bridge
`);
  py.globals.set("js_progress", (text) => post({ type: "task", text }));
  py.runPython("bridge.progress_hook = js_progress");
  call = py.globals.get("bridge").call;
  net_ = py.pyimport("browser_net");
  const status = JSON.parse(call("status", "{}"));
  post({ type: "ready", engine: status.ok.engine });
}

// Downloads every URL with a few requests at a time, telling the page how far it got.
async function prefetch(urls) {
  let done = 0, next = 0;
  const worker = async () => {
    while (next < urls.length) {
      const url = urls[next++];
      try {
        const res = await fetch(url);
        if (res.ok) net_.store(url, new Uint8Array(await res.arrayBuffer()));
      } catch (err) { /* the engine fetches it itself and reports a real failure */ }
      done++;
      if (done % 10 === 0 || done === urls.length) post({ type: "task", text: `Downloading vulnerability details: ${done} of ${urls.length}` });
    }
  };
  await Promise.all(Array.from({ length: Math.min(12, urls.length) }, worker));
}

function post(message) {
  self.postMessage(message);
}

const ready = start().catch((err) => post({ type: "fatal", text: String(err && err.message ? err.message : err) }));

self.onmessage = async (event) => {
  const { id, name, args, blob } = event.data;
  await ready;
  if (!call) return post({ id, type: "answer", answer: { error: "The engine could not start. Reload the page." } });
  let answer;
  try {
    let args2 = args || {};
    if (name === "scan" && args2.use_kev) {
      // CISA's list cannot be fetched from a browser; a daily job copies it next to this page.
      try {
        const res = await fetch(base + "data/kev.json", { cache: "no-cache" });
        if (!res.ok) throw new Error("HTTP " + res.status);
        py.FS.writeFile("/tmp/kev.json", new Uint8Array(await res.arrayBuffer()));
        args2 = { ...args2, kev_file: "/tmp/kev.json" };
      } catch (err) {
        post({ id, type: "answer", answer: { error: "The CISA KEV list is not available on this site right now (" + err.message + "). Untick 'CISA KEV' to scan without it." } });
        return;
      }
    }
    if (name === "scan") {
      args2 = { ...args2, data_url: base + "data/" };
      const plan = JSON.parse(call("plan_scan", JSON.stringify({ filename: args2.filename, use_cvelist: !!args2.use_cvelist, data_url: args2.data_url }), blob || null));
      if (plan.error) { post({ id, type: "answer", answer: plan }); net_.clear_cache(); return; }
      await prefetch(plan.ok.urls);
      post({ type: "task", text: "Matching vulnerabilities to components..." });
    }
    delete args2.use_kev;
    let text;
    try {
      text = call(name, JSON.stringify(args2), blob || null);
    } finally {
      if (name === "scan") net_.clear_cache();
    }
    answer = JSON.parse(text);
    await syncfs(false); // save the register to the browser's storage
  } catch (err) {
    answer = { error: "Unexpected problem: " + String(err && err.message ? err.message : err) };
  }
  post({ id, type: "answer", answer });
};

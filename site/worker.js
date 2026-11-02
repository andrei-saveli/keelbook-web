// Runs the keelbook engine (Python) in the browser with Pyodide, away from the page so it stays
// responsive during long lookups. The register lives in the browser's storage (IndexedDB).
"use strict";

const PYODIDE = "https://cdn.jsdelivr.net/pyodide/v0.27.7/full/";
const ENGINE_WHEEL = "vendor/keelbook-0.9.3-py3-none-any.whl";
importScripts(PYODIDE + "pyodide.js");

let py = null;
let call = null;
const base = self.location.href.replace(/worker\.js.*$/, "");

function syncfs(populate) {
  return new Promise((resolve, reject) => py.FS.syncfs(populate, (err) => (err ? reject(err) : resolve())));
}

async function start() {
  post({ type: "progress", text: "Loading Python (first visit: about 15 MB, then cached)..." });
  py = await loadPyodide({ indexURL: PYODIDE });
  py.setStdout({ batched: (line) => post({ type: "log", line }) });
  py.setStderr({ batched: (line) => post({ type: "log", line }) });
  post({ type: "progress", text: "Loading the keelbook engine..." });
  await py.loadPackage(["micropip", "click", "rich", "sqlite3"]);
  py.FS.mkdirTree("/data");
  py.FS.mount(py.FS.filesystems.IDBFS, {}, "/data");
  await syncfs(true);
  for (const name of ["browser_net.py", "bridge.py"]) {
    const text = await (await fetch(base + "py/" + name, { cache: "no-cache" })).text();
    py.FS.writeFile("/home/pyodide/" + name, text);
  }
  await py.runPythonAsync(`
import os, sys
sys.path.insert(0, "/home/pyodide")
os.environ["KEELBOOK_DB"] = "/data/keelbook.db"
os.environ["KEELBOOK_CACHE"] = "/data/cache"
import browser_net  # before keelbook: network and sleep for the browser
import micropip
await micropip.install(${JSON.stringify(base + ENGINE_WHEEL)}, deps=False)
import bridge
`);
  call = py.globals.get("bridge").call;
  const status = JSON.parse(call("status", "{}"));
  post({ type: "ready", engine: status.ok.engine });
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
    delete args2.use_kev;
    const text = call(name, JSON.stringify(args2), blob || null);
    answer = JSON.parse(text);
    await syncfs(false); // save the register to the browser's storage
  } catch (err) {
    answer = { error: "Unexpected problem: " + String(err && err.message ? err.message : err) };
  }
  post({ id, type: "answer", answer });
};

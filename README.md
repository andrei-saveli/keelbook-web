# Keelbook web

The Keelbook vulnerability register in a web browser: products, release scans, decisions per
finding, review sheet (Excel), evidence record, OpenVEX, backup. Made for the vulnerability
handling duties of the EU Cyber Resilience Act.

## How it works

The site is static (GitHub Pages). The [keelbook](https://github.com/andrei-saveli/keelbook)
engine runs **inside the browser** with [Pyodide](https://pyodide.org) (Python compiled to
WebAssembly), in a background worker:

- The SBOM never leaves the user's computer. Only package names and versions go to OSV and NVD,
  straight from the browser (both allow it). Nothing is sent to ENISA.
- The register is the same SQLite file the command-line tool uses, kept in the browser's
  storage (IndexedDB). "Backup and restore" downloads it as `keelbook.db`; the CLI can open it.
- Components with a CPE (Yocto, embedded) are checked against the official CVE List. The
  publishing job builds the CVE List index every day and splits it into 4,096 files by product
  name (`tools/export_cvelist.py`); a browser downloads only the files for the products in its
  SBOM (a real Yocto image: 34 files, a few MB, about 5 seconds). No NVD API key is needed.
  NVD remains optional.
- CISA does not allow browsers to download its KEV list, so the publishing job copies it next
  to the page once a day (`data/kev.json`).
- Not in the web version yet: Art. 14 cases, ENISA EUVD, VEX / Yocto cve-check files, the
  kernel build-list filter. Use the command-line tool for those.

First visit: about 15 MB is downloaded (Python and the engine), then cached by the browser.

## Files

```
site/index.html            the page (plain HTML, one font)
site/app.js                pages and forms
site/worker.js             starts Pyodide, installs the engine, keeps the register in IndexedDB
site/py/browser_net.py     network, waiting and "threads" for the engine inside a browser
site/py/bridge.py          the only interface between the pages and the engine (JSON in, JSON out)
tools/export_cvelist.py    splits the CVE List index into the files the site serves
site/vendor/*.whl          the keelbook engine (built from a keelbook release)
tests/test_bridge.py       the bridge in normal Python, no network
tests/browser_check.js     end-to-end check in a real browser (needs internet)
.github/workflows/pages.yml  tests, copies the KEV list, publishes on GitHub Pages
```

## Develop and test

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install site/vendor/keelbook-*.whl pytest
pytest -q
python3 -m http.server -d site 8000      # then open http://localhost:8000/
```

Local copies of the data the publishing job prepares:

```bash
curl -o site/data/kev.json https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
keelbook update-db && python tools/export_cvelist.py site/data/cvelist
```

End-to-end in Chromium (with the server above running and Playwright installed):

```bash
node tests/browser_check.js http://localhost:8000/ path/to/sbom.cdx.json /tmp/out path/to/cpe-sbom.json
```

## New engine version

Build the wheel in the keelbook repo (`pip wheel --no-deps -w dist .`), copy it to
`site/vendor/`, delete the old one, and update `ENGINE_WHEEL` in `site/worker.js`.

## Publishing

GitHub repository Settings, Pages, Source: **GitHub Actions**. Every push to `main` then
tests and publishes the site at `https://andrei-saveli.github.io/keelbook-web/`.

## Licence

Proprietary. All rights reserved.

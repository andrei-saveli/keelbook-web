"""Split the keelbook CVE List index into small files the web register downloads on demand.

Run after `keelbook update-db` (the publishing job does this daily). For every product name in
the index, its rows go into one of 4,096 files chosen by a hash of the name, so a browser
fetches only the files for the products in its SBOM: a few MB instead of the whole list, and
no NVD API key or rate limit.

Usage: python tools/export_cvelist.py OUT_DIR [INDEX_FILE]
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
from pathlib import Path


def bucket(product: str) -> str:
    return hashlib.sha1(product.encode("utf-8")).hexdigest()[:3]


def export(index: Path, out: Path) -> dict:
    db = sqlite3.connect(f"file:{index}?mode=ro", uri=True)
    meta = dict(db.execute("SELECT key, value FROM meta"))
    files: dict[str, dict[str, list]] = {}
    rows = db.execute("SELECT e.product, e.cve, e.entry, c.summary, c.score, c.cvss_version "
                      "FROM entries e JOIN cves c ON c.id = e.cve ORDER BY e.product, e.cve")
    for product, cve, entry, summary, score, cvss_version in rows:
        files.setdefault(bucket(product), {}).setdefault(product, []).append(
            [cve, entry, summary, score, cvss_version])
    db.close()
    out.mkdir(parents=True, exist_ok=True)
    for name, products in files.items():
        (out / f"{name}.json").write_text(json.dumps(products, separators=(",", ":"), ensure_ascii=False),
                                          encoding="utf-8")
    manifest = {"schema": meta.get("schema"), "built": meta.get("built"), "source": meta.get("source"),
                "records": meta.get("records"), "kept": meta.get("kept"), "files": len(files)}
    (out / "meta.json").write_text(json.dumps(manifest), encoding="utf-8")
    return manifest


if __name__ == "__main__":
    out_dir = Path(sys.argv[1])
    if len(sys.argv) > 2:
        index_file = Path(sys.argv[2])
    else:
        from keelbook.cvelist import default_index_file
        index_file = default_index_file()
    print(json.dumps(export(index_file, out_dir)))

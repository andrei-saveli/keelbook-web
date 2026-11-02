"""The web pages talk to the keelbook engine only through `call(name, args_json, blob)`.

Every function here does what the matching `keelbook product ...` command does, with the same
engine functions, so the web version and the command line record the same things. Answers are
JSON: {"ok": result} or {"error": "message for the user"}. Binary results are base64.

This file runs in the browser (Pyodide) and in normal Python for the tests.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import shutil
import sqlite3
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any

import click
from rich.console import Console

import keelbook
from keelbook.cases import Store
from keelbook.errors import CaseError, KevFileError, SbomError, VulnLookupError
from keelbook.htmlreport import evidence_html
from keelbook.parsers import load_sbom
from keelbook.register import (DECIDED, DETAIL_FIELDS, NEEDS_DECISION, RECONFIRM, DecisionInput, Register,
                               RegisterError, finding_record)
from keelbook.registerreport import _decision_text, _display, _producer_text, exploited, openvex, openvex_json, \
    ordered, severity_text
from keelbook.report import candidate_sources, sha256_of
import keelbook.scanpipe as scanpipe
from keelbook import cvelist as cvl
from keelbook.cpe import unescape
from keelbook.lookup import split_by_source
from keelbook.scanpipe import LookupOptions, run_pipeline
from keelbook.xlsxreport import read_review_workbook, review_workbook

USER_ERRORS = (CaseError, RegisterError, SbomError, VulnLookupError, KevFileError, ValueError)
STATES = (NEEDS_DECISION, RECONFIRM, DECIDED)


# The page sets this to receive progress text during long steps (a scan can take minutes).
progress_hook = None


def progress(text: str) -> None:
    if progress_hook is not None:
        progress_hook(str(text))


class _Status:
    """Stands in for rich's status spinner (it needs a thread; browsers have none) and passes the
    engine's progress text on to the page instead."""

    def __init__(self, text: str = ""):
        if text:
            progress(text)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def update(self, text: str = "", *args, **kwargs):
        if text:
            progress(text)


class QuietConsole(Console):
    def status(self, status: str = "", *args, **kwargs):  # type: ignore[override]
        return _Status(status)


def _no_full_download(*args, **kwargs):
    raise VulnLookupError("The copy of the CVE List on this site is more than 7 days old (it is normally refreshed "
                          "every day).")


# The web version never downloads the whole CVE List (hundreds of MB); it uses the split copy on the site.
scanpipe.download_and_build = _no_full_download


def cve_file(product: str) -> str:
    """Which of the site's CVE List files holds a product (same rule as tools/export_cvelist.py)."""
    return hashlib.sha1(product.encode("utf-8")).hexdigest()[:3]


def _fetch(url: str) -> bytes:
    with urllib.request.urlopen(url) as response:
        return response.read()


def prepare_cvelist(components, data_url: str) -> int:
    """Build a small CVE List index with only the products in this SBOM, from the site's split copy.

    The engine then uses it exactly like the full index the command-line tool builds. Returns the
    number of products looked up.
    """
    _, groups, _ = split_by_source(components, use_nvd=False, use_cvelist=True)
    keys = {cvl.norm(unescape(g.cpe.product)) for g in groups}
    products = sorted({cvl.PRODUCT_ALIASES.get(k, k) for k in keys if k})
    try:
        meta = json.loads(_fetch(data_url + "cvelist/meta.json"))
    except Exception as exc:
        raise VulnLookupError(f"The CVE List copy on this site could not be read ({exc}).") from exc
    path = cvl.default_index_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    if tmp.exists():
        tmp.unlink()
    db = sqlite3.connect(tmp)
    try:
        db.executescript("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);"
                         "CREATE TABLE cves (id TEXT PRIMARY KEY, published TEXT, summary TEXT, score REAL, "
                         "cvss_version TEXT);"
                         "CREATE TABLE entries (product TEXT, cve TEXT, entry TEXT);")
        files = sorted({cve_file(p) for p in products})
        for number, name in enumerate(files, 1):
            progress(f"Official CVE List: file {number} of {len(files)} for {len(products)} product(s)")
            try:
                data = json.loads(_fetch(f"{data_url}cvelist/{name}.json"))
            except Exception as exc:
                raise VulnLookupError(f"Part of the CVE List copy could not be downloaded ({exc}).") from exc
            for product in products:
                if cve_file(product) != name:
                    continue
                for cve, entry, summary, score, cvss_version in data.get(product, []):
                    db.execute("INSERT OR IGNORE INTO cves VALUES (?, NULL, ?, ?, ?)", (cve, summary, score, cvss_version))
                    db.execute("INSERT INTO entries VALUES (?, ?, ?)", (product, cve, entry))
        db.execute("CREATE INDEX entries_product ON entries (product)")
        db.executemany("INSERT INTO meta VALUES (?, ?)", [
            ("schema", str(meta.get("schema") or cvl.INDEX_SCHEMA)), ("built", meta.get("built") or ""),
            ("source", "CVE List copy on the Keelbook site"), ("records", str(meta.get("records") or "")),
            ("kept", str(meta.get("kept") or ""))])
        db.commit()
    finally:
        db.close()
    os.replace(tmp, path)
    return len(products)


def db_path() -> Path:
    return Path(os.environ.get("KEELBOOK_DB", "/data/keelbook.db"))


def _open(create: bool = False) -> tuple[Store, Register]:
    store = Store(db_path(), create=create)
    return store, Register(store)


def _need_name(actor: str) -> str:
    actor = " ".join((actor or "").split())
    if not actor:
        raise ValueError("Enter your name first (top of the page): every entry is recorded with it.")
    return actor


def _counts(rows) -> dict[str, int]:
    return {s: sum(1 for r in rows if r.state == s) for s in STATES}


def _details(raw: dict[str, Any] | None) -> dict[str, str | None]:
    return {k: (raw or {}).get(k) or None for k in DETAIL_FIELDS}


# --- reading ------------------------------------------------------------------------


def status() -> dict[str, Any]:
    return {"engine": keelbook.__version__, "database": db_path().exists()}


def products() -> list[dict[str, Any]]:
    if not db_path().exists():
        return []
    store, reg = _open()
    try:
        out = []
        for state in reg.products():
            latest = state.latest_release()
            rows = reg.review(state, latest) if latest else []
            out.append({"id": state.id, "name": state.name, "details": state.details,
                        "latest": latest.label if latest else None, "findings": len(rows),
                        "counts": _counts(rows), "exploited": sum(1 for r in rows if exploited(r.finding)),
                        "exploited_checked": bool(latest and any(s.startswith(("CISA KEV", "ENISA EUVD"))
                                                                 for s in latest.sources))})
        return out
    finally:
        store.close()


def product(pid: str) -> dict[str, Any]:
    store, reg = _open()
    try:
        state = reg.product(pid)
        releases = []
        for label in reversed(state.release_order):
            rel = state.releases[label]
            rows = reg.review(state, rel)
            releases.append({"label": rel.label, "scanned_at": rel.scanned_at, "scanned_by": rel.scanned_by,
                             "sbom_file": rel.sbom_file, "total": rel.total, "checked": rel.checked,
                             "not_checked": sum(rel.skipped.values()), "findings": len(rows), "counts": _counts(rows),
                             "exploited": sum(1 for r in rows if exploited(r.finding))})
        return {"id": state.id, "name": state.name, "details": state.details, "created_by": state.created_by,
                "releases": releases}
    finally:
        store.close()


def review(pid: str, label: str) -> dict[str, Any]:
    store, reg = _open()
    try:
        state = reg.product(pid)
        rel = reg.release(state, label)
        rows = ordered(reg.review(state, rel))
        items = []
        for r in rows:
            f, d = r.finding, r.decision
            sev = f.get("severity") or {}
            items.append({
                "key": f["key"], "cve_ids": f.get("cve_ids") or [],
                "other_ids": [i for i in [f["vuln_id"], *(f.get("aliases") or [])] if i not in (f.get("cve_ids") or [])],
                "component": _display(f), "version": f.get("version") or "", "severity": severity_text(f),
                "severity_label": sev.get("label") or "unknown",
                "fixed_in": " ".join(f.get("fixed_in") or []) or f.get("fix_note") or "unknown",
                "kev": f.get("kev"), "euvd": f.get("euvd"), "state": r.state, "note": r.note or "",
                "decision": _decision_text(d) if d else "", "reason": d.reason if d else "",
                "by": d.by if d else "", "at": d.at if d else "", "producer": _producer_text(f) or "",
                "summary": " ".join((f.get("summary") or "").split()),
            })
        return {"product": {"id": state.id, "name": state.name}, "release": {
                    "label": rel.label, "sbom_file": rel.sbom_file, "sbom_sha256": rel.sbom_sha256,
                    "scanned_at": rel.scanned_at, "scanned_by": rel.scanned_by, "total": rel.total,
                    "checked": rel.checked, "skipped": rel.skipped, "sources": rel.sources},
                "counts": _counts(rows), "suggestions": len(reg.producer_suggestions(state, rel)), "rows": items}
    finally:
        store.close()


def verify() -> dict[str, Any]:
    if not db_path().exists():
        return {"ok": True, "count": 0, "head": "", "problem": None}
    store = Store(db_path())
    try:
        v = store.verify()
        return {"ok": v.ok, "count": v.count, "head": v.head, "problem": v.problem}
    finally:
        store.close()


# --- recording ----------------------------------------------------------------------


def add_product(pid: str, name: str, details: dict[str, Any], actor: str) -> dict[str, Any]:
    actor = _need_name(actor)
    if not (pid or "").strip():
        raise ValueError("Give the product a short ID, e.g. gateway-x.")
    store, reg = _open(create=True)
    try:
        reg.add_product(pid, name or None, actor, details=_details(details))
        return {"id": reg.product(pid).id}
    finally:
        store.close()


def set_details(pid: str, details: dict[str, Any], actor: str) -> dict[str, Any]:
    actor = _need_name(actor)
    store, reg = _open()
    try:
        changed = {k: v for k, v in _details(details).items() if v}
        if not changed:
            raise ValueError("Nothing to change: fill in at least one field.")
        reg.set_details(pid, changed, actor)
        return {"id": pid}
    finally:
        store.close()


def scan(pid: str, label: str, filename: str, data: bytes, use_nvd: bool, nvd_key: str | None,
         kev_file: str | None, actor: str, use_cvelist: bool = False, data_url: str | None = None) -> dict[str, Any]:
    """Like `keelbook product scan`: parse the SBOM, look up vulnerabilities, record the release."""
    actor = _need_name(actor)
    if not (label or "").strip():
        raise ValueError("Give the release a label, e.g. 2.1.0.")
    if not data:
        raise ValueError("Choose the SBOM file of this release.")
    store, reg = _open()
    try:
        reg.product(pid)  # fail before the slow lookup
    finally:
        store.close()
    folder = Path(tempfile.mkdtemp())
    try:
        sbom_file = folder / (Path(filename or "sbom.json").name or "sbom.json")
        sbom_file.write_bytes(data)
        started = time.monotonic()
        progress("Reading the SBOM...")
        sbom = load_sbom(sbom_file)
        progress(f"SBOM read: {len(sbom.components)} component(s).")
        if use_cvelist:
            if not data_url:
                raise ValueError("The CVE List copy is not available here.")
            prepare_cvelist(sbom.components, data_url)
        out, err = io.StringIO(), io.StringIO()
        console, err_console = QuietConsole(file=out, width=100), QuietConsole(file=err, width=100)
        opts = LookupOptions(no_nvd=not use_nvd, nvd_api_key=nvd_key or None, use_cvelist=use_cvelist,
                             kev_path=Path(kev_file) if kev_file else None)
        try:
            result = run_pipeline(console, err_console, sbom, opts)
        except click.exceptions.Exit as exc:
            raise VulnLookupError(err.getvalue().replace("Error: ", "").strip() or "The lookup failed.") from exc
        lookup = result.lookup
        records = []
        for finding in lookup.findings:
            names = candidate_sources(finding, result.kev, result.euvd)
            kev = None if result.kev is None or not finding.cve_ids else "CISA KEV" in names
            records.append(finding_record(finding, kev, None))
        store, reg = _open()
        try:
            reg.record_scan(pid, label, sbom_file=sbom_file.name, sbom_sha256=sha256_of(sbom_file), findings=records,
                            total=len(sbom.components), checked=lookup.checked, skipped=lookup.skipped,
                            sources=result.sources(), tool_version=keelbook.__version__, actor=actor)
            state = reg.product(pid)
            rel = reg.release(state, label)
            rows = reg.review(state, rel)
            suggestions = len(reg.producer_suggestions(state, rel))
        finally:
            store.close()
        return {"label": rel.label, "findings": len(rows), "counts": _counts(rows), "total": len(sbom.components),
                "seconds": round(time.monotonic() - started),
                "checked": lookup.checked, "skipped": lookup.skipped, "sources": result.sources(),
                "exploited": sum(1 for r in rows if exploited(r.finding)), "suggestions": suggestions,
                "warnings": list(sbom.warnings) + [line for line in err.getvalue().splitlines() if line.strip()]}
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def decide(pid: str, label: str, keys: list[str], decision: dict[str, Any], actor: str) -> dict[str, Any]:
    """One decision for one or more findings: all are recorded, or none (same rules as the CLI)."""
    actor = _need_name(actor)
    if not keys:
        raise ValueError("Tick at least one finding.")
    d = {k: (" ".join(str(decision.get(k) or "").split()) or None)
         for k in ("status", "reason", "justification", "impact", "action", "fixed_in")}
    items = [DecisionInput(key, d["status"] or "", d["reason"] or "", d["justification"], d["impact"], d["action"],
                           d["fixed_in"]) for key in keys]
    store, reg = _open()
    try:
        reg.decide(pid, label, items, actor)
        return {"recorded": len(items)}
    finally:
        store.close()


def accept_producer(pid: str, label: str, reason: str, actor: str) -> dict[str, Any]:
    actor = _need_name(actor)
    if not (reason or "").strip():
        raise ValueError("Give a reason, e.g. 'Yocto statements reviewed by J. Doe'.")
    store, reg = _open()
    try:
        state = reg.product(pid)
        rel = reg.release(state, label)
        items = [DecisionInput(s.key, s.status, reason, s.justification, s.impact, s.action, s.fixed_in)
                 for s in reg.producer_suggestions(state, rel)]
        if not items:
            raise ValueError("No open finding has a fixed / not-affected statement from the SBOM producer.")
        reg.decide(pid, rel.label, items, actor)
        return {"recorded": len(items)}
    finally:
        store.close()


# --- outputs ------------------------------------------------------------------------


def evidence(pid: str, label: str) -> dict[str, Any]:
    store, reg = _open()
    try:
        state = reg.product(pid)
        rel = reg.release(state, label)
        page = evidence_html(state, rel, reg.review(state, rel), store.cases(), store.verify(), keelbook.__version__)
        return {"html": page, "filename": f"evidence-{state.id}-{rel.label}.html"}
    finally:
        store.close()


def vex(pid: str, label: str, author: str) -> dict[str, Any]:
    if not (author or "").strip():
        raise ValueError("Give the author of the VEX file (usually the manufacturer's name).")
    store, reg = _open()
    try:
        state = reg.product(pid)
        rel = reg.release(state, label)
        document, counts = openvex(state, rel, reg.review(state, rel), author)
        return {"json": openvex_json(document), "counts": counts, "filename": f"{state.id}-{rel.label}.openvex.json"}
    finally:
        store.close()


def sheet(pid: str, label: str) -> dict[str, Any]:
    store, reg = _open()
    try:
        state = reg.product(pid)
        rel = reg.release(state, label)
        rows = reg.review(state, rel)
    finally:
        store.close()
    folder = Path(tempfile.mkdtemp())
    try:
        path = folder / f"review-{state.id}-{rel.label}.xlsx"
        review_workbook(path, state, rel, rows)
        return {"b64": base64.b64encode(path.read_bytes()).decode(), "filename": path.name}
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def import_sheet(pid: str, label: str, data: bytes, actor: str) -> dict[str, Any]:
    actor = _need_name(actor)
    if not data:
        raise ValueError("Choose the filled-in review sheet (.xlsx).")
    folder = Path(tempfile.mkdtemp())
    try:
        path = folder / "review.xlsx"
        path.write_bytes(data)
        store, reg = _open()
        try:
            state = reg.product(pid)
            rel = reg.release(state, label)
            items = read_review_workbook(path, state, rel)
            reg.decide(pid, rel.label, items, actor)
            return {"recorded": len(items)}
        finally:
            store.close()
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def export_db() -> dict[str, Any]:
    if not db_path().exists():
        raise ValueError("Nothing to back up yet: add a product first.")
    return {"b64": base64.b64encode(db_path().read_bytes()).decode(), "filename": "keelbook.db"}


def import_db(data: bytes) -> dict[str, Any]:
    """Replace the register with a backup, only if the backup's log verifies."""
    if not data:
        raise ValueError("Choose a keelbook.db backup file.")
    folder = Path(tempfile.mkdtemp())
    try:
        candidate = folder / "keelbook.db"
        candidate.write_bytes(data)
        try:
            store = Store(candidate)
            result = store.verify()
            store.close()
        except Exception as exc:  # not an SQLite file, or not a Keelbook register
            raise ValueError(f"This is not a Keelbook register ({exc}).") from exc
        if not result.ok:
            raise ValueError(f"The backup's log failed verification ({result.problem}). Nothing was changed.")
        db_path().parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(candidate, db_path())
        return {"count": result.count, "head": result.head}
    finally:
        shutil.rmtree(folder, ignore_errors=True)


# --- the single entry point ---------------------------------------------------------

FUNCTIONS = {f.__name__: f for f in (status, products, product, review, verify, add_product, set_details, scan,
                                     decide, accept_producer, evidence, vex, sheet, import_sheet, export_db, import_db)}


def call(name: str, args_json: str = "{}", blob: Any = None) -> str:
    if blob is not None and hasattr(blob, "to_bytes"):  # a browser Uint8Array
        blob = blob.to_bytes()
    try:
        function = FUNCTIONS[name]
        args = json.loads(args_json or "{}")
        if blob is not None:
            args["data"] = bytes(blob)
        return json.dumps({"ok": function(**args)})
    except USER_ERRORS as exc:
        return json.dumps({"error": str(exc)})

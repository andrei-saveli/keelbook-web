"""The bridge between the web pages and the keelbook engine, run in normal Python (no browser, no network)."""

import base64
import json
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "site" / "py"))
import bridge  # noqa: E402

from keelbook.severity import Severity  # noqa: E402
from keelbook.vulns import Finding, LookupResult  # noqa: E402

SBOM = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
    {"name": "log4j-core", "version": "2.14.1", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
    {"name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"},
]}).encode()
KEV = json.dumps({"title": "CISA KEV", "catalogVersion": "2026.10.30", "dateReleased": "2026-10-30T00:00:00Z",
                  "count": 1, "vulnerabilities": [{"cveID": "CVE-2021-44228", "vendorProject": "Apache",
                                                   "product": "Log4j", "dateAdded": "2021-12-10",
                                                   "knownRansomwareCampaignUse": "Known"}]})


def fake_lookup(components, http=None):
    by = {c.name: c for c in components}
    return LookupResult(findings=[
        Finding(by["log4j-core"], "GHSA-jfh8-c2jp-5v3q", ("CVE-2021-44228",), "Remote code injection", ("2.15.0",),
                severity=Severity(10.0, "critical", "3.1", "OSV")),
        Finding(by["requests"], "GHSA-9wx4-h78v-vm56", ("CVE-2024-35195",), "verify=False persists", ("2.32.0",),
                severity=Severity(5.6, "medium", "3.1", "OSV")),
    ], checked=2)


def call(_fn, blob=None, **args):
    return json.loads(bridge.call(_fn, json.dumps(args), blob))


@pytest.fixture(autouse=True)
def db(tmp_path, monkeypatch):
    monkeypatch.setenv("KEELBOOK_DB", str(tmp_path / "keelbook.db"))
    with mock.patch("keelbook.lookup.check_vulnerabilities", side_effect=fake_lookup):
        yield tmp_path


def ok(answer):
    assert "ok" in answer, answer
    return answer["ok"]


def test_full_workflow(db):
    assert ok(call("products")) == []
    assert "Enter your name" in call("add_product", pid="gw", name="Gateway", details={}, actor=" ")["error"]
    ok(call("add_product", pid="gw", name="Gateway", details={"contact": "sec@x.example"}, actor="Ana Pop"))
    assert "already exists" in call("add_product", pid="gw", name="x", details={}, actor="Ana Pop")["error"]

    kev = db / "kev.json"
    kev.write_text(KEV, encoding="utf-8")
    result = ok(call("scan", blob=SBOM, pid="gw", label="1.0", filename="bom.cdx.json", use_nvd=False,
                     nvd_key=None, kev_file=str(kev), actor="Ana Pop"))
    assert result["findings"] == 2 and result["checked"] == 2 and result["exploited"] == 1
    assert sum(result["counts"].values()) == 2 and result["counts"][bridge.NEEDS_DECISION] == 2

    page = ok(call("review", pid="gw", label="1.0"))
    rows = {r["cve_ids"][0]: r for r in page["rows"]}
    assert page["rows"][0]["cve_ids"] == ["CVE-2021-44228"]  # exploited first
    assert rows["CVE-2021-44228"]["kev"] is True and rows["CVE-2024-35195"]["kev"] is False
    assert any("CISA KEV" in s for s in page["release"]["sources"])

    bad = call("decide", pid="gw", label="1.0", keys=[rows["CVE-2024-35195"]["key"]],
               decision={"status": "not_affected", "reason": "x"}, actor="Ana Pop")
    assert "justification" in bad["error"] and "Nothing was recorded" in bad["error"]
    ok(call("decide", pid="gw", label="1.0", keys=[rows["CVE-2024-35195"]["key"]],
            decision={"status": "not_affected", "justification": "vulnerable_code_not_in_execute_path",
                      "reason": "verify=False never used — ăîșț"}, actor="Ana Pop"))
    after = {r["cve_ids"][0]: r for r in ok(call("review", pid="gw", label="1.0"))["rows"]}
    assert after["CVE-2024-35195"]["by"] == "Ana Pop" and "ăîșț" in after["CVE-2024-35195"]["reason"]

    listing = ok(call("products"))[0]
    assert listing["latest"] == "1.0" and listing["exploited"] == 1 and listing["exploited_checked"]

    html = ok(call("evidence", pid="gw", label="1.0"))["html"]
    assert "Gateway, release 1.0" in html and "sec@x.example" in html and "ăîșț" in html
    vex = ok(call("vex", pid="gw", label="1.0", author="ACME"))
    assert json.loads(vex["json"])["statements"][0]["status"] == "not_affected"
    assert ok(call("verify"))["ok"] is True


def test_sheet_round_trip_and_backup(db):
    from keelbook.xlsx import Sheet, read_xlsx, write_xlsx
    from keelbook.xlsxreport import REVIEW_LAYOUT

    ok(call("add_product", pid="gw", name="Gateway", details={}, actor="Ana"))
    ok(call("scan", blob=SBOM, pid="gw", label="1.0", filename="b.json", use_nvd=False, nvd_key=None,
            kev_file=None, actor="Ana"))
    xlsx = db / "s.xlsx"
    xlsx.write_bytes(base64.b64decode(ok(call("sheet", pid="gw", label="1.0"))["b64"]))
    rows = read_xlsx(xlsx)["Review"]
    col = {name: rows[0].index(label) for name, label, _ in REVIEW_LAYOUT}
    filled = [list(r) + [""] * (len(rows[0]) - len(r)) for r in rows]
    filled[1][col["new_status"]] = "affected"
    filled[1][col["new_action"]] = "Upgrade in 1.1"
    filled[1][col["new_reason"]] = "Reachable"
    write_xlsx(xlsx, [Sheet("Review", rows=filled)])
    assert ok(call("import_sheet", blob=xlsx.read_bytes(), pid="gw", label="1.0", actor="Ana"))["recorded"] == 1

    backup = base64.b64decode(ok(call("export_db"))["b64"])
    assert "not a Keelbook register" in call("import_db", blob=b"nonsense")["error"]
    restored = ok(call("import_db", blob=backup))
    assert restored["count"] == ok(call("verify"))["count"]


def test_scan_errors_are_messages_not_crashes(db):
    ok(call("add_product", pid="gw", name="Gateway", details={}, actor="Ana"))
    assert "label" in call("scan", blob=SBOM, pid="gw", label="", filename="b.json", use_nvd=False, nvd_key=None,
                           kev_file=None, actor="Ana")["error"]
    answer = call("scan", blob=b"{not json", pid="gw", label="1.0", filename="b.json", use_nvd=False,
                  nvd_key=None, kev_file=None, actor="Ana")
    assert "error" in answer
    assert "No such product" in call("review", pid="nope", label="1.0")["error"]

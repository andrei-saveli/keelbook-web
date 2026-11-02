from fastapi.testclient import TestClient

import keelbook
from keelbook_web.app import app

client = TestClient(app)


def test_start_page_shows_both_versions():
    page = client.get("/")
    assert page.status_code == 200
    assert "Keelbook" in page.text and keelbook.__version__ in page.text
    assert "not legal advice" in page.text


def test_health():
    assert client.get("/health").json()["engine"] == keelbook.__version__


def test_api_docs_are_off():
    assert client.get("/docs").status_code == 404

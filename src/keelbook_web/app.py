"""The web application. For now only a start page; the screens follow the plan in README.md.

Rules carried over from keelbook: the SBOM stays where this app runs; only package names
and versions go to vulnerability databases; nothing is sent to ENISA; a person decides.
"""

from __future__ import annotations

import webbrowser
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

import keelbook

from keelbook_web import __version__

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

app = FastAPI(title="Keelbook web", version=__version__, docs_url=None, redoc_url=None)


@app.get("/", response_class=HTMLResponse)
def home(request: Request) -> HTMLResponse:
    return TEMPLATES.TemplateResponse(request, "index.html", {
        "version": __version__, "engine_version": keelbook.__version__,
    })


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__, "engine": keelbook.__version__}


def main() -> None:
    """`keelbook-web`: serve on this computer only and open the browser."""
    import uvicorn

    host, port = "127.0.0.1", 8765  # local only: never listen on the network by default
    webbrowser.open(f"http://{host}:{port}/")
    uvicorn.run(app, host=host, port=port, log_level="warning")

# Keelbook web

A browser interface for the Keelbook vulnerability register: products and releases, review
and decisions, Art. 14 cases with deadlines, evidence and exports, monitoring of shipped
releases. It uses the [keelbook](https://github.com/andrei-saveli/keelbook) package as its
engine; nothing about parsing or vulnerability lookup is duplicated here.

**Status: skeleton.** A start page and tests only.

## Principles

- The SBOM stays where this app runs. Only package names and versions go to vulnerability
  databases (OSV, NVD, CVE List).
- Nothing is sent to ENISA; a person submits and records it.
- A person decides what is actively exploited and records every decision with a reason.
- Unchecked is never shown as clean.
- Working aid, not legal advice.

## Development

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q
keelbook-web          # opens http://127.0.0.1:8765/ (this computer only)
```

While the keelbook repository is private, installing it needs GitHub access
(`git config --global credential.helper` or a token). To develop against a local copy:
`pip install -e ../keelbook` before `pip install -e ".[dev]"`.

## Layout

```
src/keelbook_web/app.py        FastAPI application, `keelbook-web` command
src/keelbook_web/templates/    HTML pages (server-rendered)
tests/                         pytest, no network
```

## Licence

Proprietary. All rights reserved.

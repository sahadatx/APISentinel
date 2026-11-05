# Browser E2E workflow

The standalone Playwright test drives the actual Vite dashboard and FastAPI API with a disposable SQLite database, temporary local service ports, and a loopback-only HTTP fixture. It does not use the configured `apisentinel.db`, public targets, or client credentials. The script detects a system Chromium or Playwright-managed Chromium.

Install the optional Python dependency and a local Chromium package, then run from the repository root:

```bash
python -m pip install -e '.[browser-e2e]'
python -m playwright install chromium
python tests/e2e_browser_workflow.py
```

To preserve synthetic JSON/HTML report exports for manual QA, choose a new, empty output directory:

```bash
mkdir -p /tmp/apisentinel-demo-run-01
python tests/e2e_browser_workflow.py --artifacts-dir /tmp/apisentinel-demo-run-01
```

The test covers the analyst login/loading/logout path, invalid login, unauthenticated protection, cross-owner assessment denial, client portfolio empty/search/filter states, assessment creation and client-to-assessment workspace navigation, OpenAPI import without execution, the pre-approval execution block, explicit endpoint approval, both registered check cards and outcomes, candidate evidence/triage, invalid and valid state decisions, selection of a compatible newer registered TestRun for retesting, coverage semantics, and JSON/HTML report exports. All web services and the assessment target bind to `127.0.0.1`; the script removes its temporary database and terminates services when it exits.

The browser run does not cover Settings, browser-specific exploitability, every API validation branch, responsive/mobile layouts, or a full HTTPS browser target. HTTPS peer/SNI/certificate behavior remains covered by local backend runner tests. Database schema upgrade behavior is exercised separately by migration tests and schema-drift checks. For scenario details and service boundaries, see [the local demo workflow](local-demo-workflow.md) and [service scope checklist](service-scope-and-pilot-checklist.md).

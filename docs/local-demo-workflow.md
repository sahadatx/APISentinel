# Reproducible local demo workflow

This workflow demonstrates APISentinel's current narrow capabilities using a disposable SQLite database, a synthetic analyst/client/assessment, and a loopback-only HTTP fixture. It never reads or migrates the configured `apisentinel.db` and never contacts a public or client target.

## Prerequisites

- Python dependencies installed from the project, including the `browser-e2e` extra.
- Node dependencies installed from `dashboard/package-lock.json`.
- Local Chromium available to Playwright.

Run once if needed:

```bash
python -m pip install -e '.[browser-e2e]'
python -m playwright install chromium
npm --prefix dashboard ci
```

## Run the full workflow

Create a fresh output directory, then run the standalone browser workflow:

```bash
mkdir -p /tmp/apisentinel-demo-run-01
python tests/e2e_browser_workflow.py --artifacts-dir /tmp/apisentinel-demo-run-01
```

The script refuses to overwrite existing report artifacts. Choose a new directory for each run.

The browser and API are started on temporary loopback ports. The local fixture deliberately starts without `X-Content-Type-Options`; its `Set-Cookie` value is a synthetic secret marker used to verify redaction. The workflow:

1. Verifies unauthenticated access is rejected, invalid login is rejected, and analyst login succeeds.
2. Creates a local client and assessment with loopback-only host/path scope.
3. Records and separately reviews a synthetic authorization record. This is only a test fixture, not real permission.
4. Imports a local OpenAPI document without making a target request.
5. Verifies execution is blocked before endpoint approval, then explicitly approves the imported endpoint.
6. Runs the two registered checks only against the local fixture: Content-Type-Options produces a candidate when absent; HSTS is inconclusive over HTTP.
7. Reviews the candidate, changes the local fixture to include `nosniff`, and creates a newer applicable TestRun.
8. Records a provenance-linked retest, checks separate coverage semantics, creates a report version, and validates JSON/HTML contents and secret redaction.
9. Signs out and verifies that protected API access is rejected again.

The E2E test writes these **synthetic** artifacts when `--artifacts-dir` is provided:

- `apisentinel-local-demo-report.json`
- `apisentinel-local-demo-report.html`

The temporary database and API/UI/fixture processes are cleaned up when the script exits. The exported report contains no real client, authorization, or target data. Review the JSON and HTML manually; passing assertions do not constitute professional report QA or prove exploitability.

## Guardrails and limitations

- Do not change this script to point at a public or client host. The runner's lab exception is restricted to a local development fixture and temporary port.
- The E2E process explicitly enables the active-test gate only in its child process and isolated test database. It does not change the regular application defaults.
- This workflow validates the implemented two header observations, not broad API security, authentication/authorization logic, business logic, or browser exploitability.
- Report creation, linked retest, and status labels are not evidence that APISentinel is comprehensive or client-ready.
- The workflow does not test deployment, backup/restore, production TLS/cookies, CSV output, or external authorization-document authenticity.

For backend-only regression coverage, run `pytest -q`. For browser workflow coverage, run `python tests/e2e_browser_workflow.py` without `--artifacts-dir` to use and discard all synthetic outputs.

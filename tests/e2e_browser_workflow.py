"""Standalone local-only browser E2E for the analyst assessment workflow.

Run with: python tests/e2e_browser_workflow.py
Requires the optional Python Playwright package and a local Chromium binary.
All database and service state is created in a temporary directory.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


class LabHandler(BaseHTTPRequestHandler):
    nosniff = False
    requests = 0

    def do_GET(self):
        type(self).requests += 1
        body = b"local fixture response"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie", "fixture-secret=must-not-be-retained; HttpOnly")
        if type(self).nosniff:
            self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_http(url: str, process: subprocess.Popen, timeout: float = 20) -> None:
    import urllib.error
    import urllib.request

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Service exited early with status {process.returncode}")
        try:
            with urllib.request.urlopen(url, timeout=0.5):
                return
        except (OSError, urllib.error.URLError):
            time.sleep(0.1)
    raise TimeoutError(f"Service did not become ready: {url}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run APISentinel's loopback-only local demo workflow")
    parser.add_argument(
        "--artifacts-dir",
        type=Path,
        help="Save the synthetic JSON and HTML report exports here (must not already contain those files)",
    )
    args = parser.parse_args()
    artifact_paths = None
    if args.artifacts_dir is not None:
        args.artifacts_dir.mkdir(parents=True, exist_ok=True)
        artifact_paths = (
            args.artifacts_dir / "apisentinel-local-demo-report.json",
            args.artifacts_dir / "apisentinel-local-demo-report.html",
        )
        existing = [str(path) for path in artifact_paths if path.exists()]
        if existing:
            raise FileExistsError("Refusing to overwrite demo artifacts: " + ", ".join(existing))

    chromium = shutil.which("chromium") or shutil.which("google-chrome")
    if not chromium:
        with sync_playwright() as playwright:
            managed_executable = Path(playwright.chromium.executable_path)
            if managed_executable.is_file():
                chromium = str(managed_executable)
    if not chromium:
        raise RuntimeError("Install Chromium with `python -m playwright install chromium` before browser E2E")

    with tempfile.TemporaryDirectory(prefix="apisentinel-e2e-") as temp:
        temp_path = Path(temp)
        database_path = temp_path / "e2e.sqlite3"
        api_port, ui_port = free_port(), free_port()
        lab = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
        lab.daemon_threads = True
        lab_thread = threading.Thread(target=lab.serve_forever, daemon=True)
        lab_thread.start()

        env = os.environ.copy()
        env.update({
            "PYTHONPATH": str(ROOT / "src"),
            "APISENTINEL_DATABASE_URL": f"sqlite:///{database_path}",
            "APISENTINEL_ALLOW_ACTIVE_TESTS": "true",
            "APISENTINEL_ALLOW_LOCAL_LAB": "true",
            "APISENTINEL_RUNNER_LAB_ALLOW_HTTP": "true",
            "APISENTINEL_RUNNER_LAB_ALLOWED_PORTS": str(lab.server_port),
            "APISENTINEL_ENABLED_SECURITY_TESTS": "response.header.content_type_options,response.header.strict_transport_security",
            "APISENTINEL_API_PROXY": f"http://127.0.0.1:{api_port}",
            "APISENTINEL_CORS_ORIGINS": f"http://127.0.0.1:{ui_port}",
            "VITE_API_URL": f"http://127.0.0.1:{api_port}/api/v1",
        })
        os.environ.update(env)
        api_process = ui_process = worker_process = None
        api_log = (temp_path / "api.log").open("w+")
        try:
            # Import after setting the disposable database URL; create only this temporary DB.
            from apisentinel import auth, models
            from apisentinel.db import Base, engine

            Base.metadata.create_all(engine)
            from sqlalchemy.orm import Session

            with Session(engine) as db:
                analyst = models.Analyst(
                    login_normalized="analyst@example.test",
                    password_hash=auth.password_hasher.hash("test-only analyst password"),
                )
                db.add(analyst)
                reviewer = models.Analyst(
                    login_normalized="reviewer@example.test",
                    password_hash=auth.password_hasher.hash("test-only reviewer password"),
                )
                db.add(reviewer)
                outsider = models.Analyst(
                    login_normalized="other@example.test",
                    password_hash=auth.password_hasher.hash("test-only outsider password"),
                )
                db.add(outsider)
                db.flush()
                other_client = models.Client(name="Private other client", owner_user_id=outsider.id)
                db.add(other_client)
                db.flush()
                other_assessment = models.Assessment(
                    client_id=other_client.id, name="Private other assessment", environment="lab",
                    authorization_confirmed=True, authorization_reference="isolated E2E fixture",
                    allowed_hosts=["127.0.0.1"], allowed_paths=["/api/**"],
                )
                db.add(other_assessment)
                db.commit()
                outsider_assessment_id = other_assessment.id

            api_process = subprocess.Popen(
                [sys.executable, "-m", "uvicorn", "apisentinel.main:app", "--host", "127.0.0.1", "--port", str(api_port)],
                cwd=ROOT, env=env, stdout=api_log, stderr=subprocess.STDOUT,
            )
            ui_process = subprocess.Popen(
                ["npm", "run", "dev:frontend", "--", "--host", "127.0.0.1", "--port", str(ui_port), "--strictPort"],
                cwd=ROOT / "dashboard", env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            wait_http(f"http://127.0.0.1:{api_port}/api/v1/health", api_process)
            worker_process = subprocess.Popen(
                [sys.executable, "-m", "apisentinel.cli", "worker", "--worker-id", "browser-e2e-worker"],
                cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            wait_http(f"http://127.0.0.1:{ui_port}/", ui_process)

            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True, executable_path=chromium)
                page = browser.new_page()
                page.add_init_script("""
                  const originalFetch = window.fetch.bind(window);
                  window.fetch = (input, init) => {
                    if (String(input).endsWith('/auth/me')) {
                      return new Promise(resolve => setTimeout(() => resolve(originalFetch(input, init)), 700));
                    }
                    return originalFetch(input, init);
                  };
                """)
                page.goto(f"http://127.0.0.1:{ui_port}/clients", wait_until="domcontentloaded")
                page.get_by_text("Checking analyst session…").wait_for(state="visible")
                page.get_by_role("heading", name="Welcome back").wait_for(state="visible")
                protected_status = page.evaluate(f"async () => (await fetch('http://127.0.0.1:{api_port}/api/v1/assessments',{{credentials:'include'}})).status")
                assert protected_status == 401, protected_status

                page.get_by_label("Email").fill("analyst@example.test")
                page.get_by_label("Password").fill("wrong password")
                page.get_by_role("button", name="Sign in securely").click()
                page.get_by_text("Invalid login or password").wait_for(state="visible")
                page.get_by_label("Email").fill("analyst@example.test")
                page.get_by_label("Password").fill("test-only analyst password")
                page.get_by_role("button", name="Sign in securely").click()
                page.get_by_role("link", name="Clients").wait_for()
                assert page.get_by_text("Your client portfolio is ready to set up").is_visible()

                # The other analyst's assessment ID is indistinguishable from a missing record.
                foreign = page.evaluate("""async ({api, aid}) => {
                  const r = await fetch(`${api}/assessments/${aid}`, {credentials:'include'});
                  return {status:r.status, body:await r.text()};
                }""", {"api": env["VITE_API_URL"], "aid": outsider_assessment_id})
                assert foreign["status"] == 404 and "Private other" not in foreign["body"]

                page.get_by_role("button", name="New Client").click()
                page.get_by_label("Client or company name").fill("Local E2E Client")
                page.get_by_label("Source").select_option("DIRECT")
                page.get_by_role("button", name="Save").click()
                page.get_by_text("Local E2E Client").wait_for()
                client_row = page.get_by_role("row").filter(has_text="Local E2E Client")
                action_trigger = client_row.get_by_role("button", name="Actions for Local E2E Client")
                action_trigger.click()
                page.get_by_role("menuitem", name="Manage access").click()
                page.get_by_label("Analyst account email").fill("reviewer@example.test")
                page.get_by_label("Workspace role").select_option("reviewer")
                with page.expect_response(lambda response: "/members" in response.url and response.request.method == "POST") as member_response:
                    page.get_by_role("button", name="Grant workspace access").click()
                response = member_response.value
                assert response.status == 201, f"Membership update failed ({response.status}): {response.text()}"
                page.get_by_text("reviewer@example.test").wait_for()
                page.get_by_role("button", name="Close manage access").click()
                page.get_by_role("link", name="Assessments").click()
                page.get_by_role("button", name="New Assessment").first.click()
                page.get_by_label("Assessment name").fill("Local E2E Assessment")
                page.get_by_label("Client").select_option(label="Local E2E Client")
                page.locator(".modal .field").filter(has_text="Environment").locator("select").select_option("development")
                page.get_by_role("button", name="Continue").click()
                page.get_by_label("Allowed hosts (comma separated)").fill("127.0.0.1")
                page.get_by_label("Allowed paths").fill("/api/**")
                page.get_by_role("button", name="4 Review").click()
                page.get_by_role("button", name="Save draft").click()
                page.get_by_role("table").get_by_text("Local E2E Assessment").wait_for()
                assessment_rows = page.evaluate("""async api => (await (await fetch(`${api}/assessments`,{credentials:'include'})).json())""", env["VITE_API_URL"])
                assessment = next(item for item in assessment_rows if item["name"] == "Local E2E Assessment")
                assessment_id = assessment["id"]
                assert assessment["authorization_status"] == "REVIEW_REQUIRED"
                page.get_by_role("link", name="Overview").click()
                page.get_by_role("heading", name="Recent audit activity").wait_for()
                page.get_by_text("Assessment Created", exact=True).wait_for()
                assert page.locator(".kpi").filter(has_text="Assessments").locator("strong").inner_text() == "1"
                with page.expect_response(lambda response: "/dashboard?" in response.url):
                    page.get_by_label("Dashboard start date").fill("2030-01-01")
                page.wait_for_function("""() => [...document.querySelectorAll('.kpi')].find(e => e.textContent.includes('Assessments'))?.querySelector('strong')?.textContent === '0'""")
                with page.expect_response(lambda response: response.url.endswith("/dashboard")):
                    page.get_by_role("button", name="Reset filters").click()
                page.get_by_role("link", name="Activity & Audit").first.click()
                page.get_by_text("ASSESSMENT_CREATED").wait_for()
                page.get_by_role("link", name="Clients").click()
                page.get_by_role("heading", name="Manage client engagements").wait_for()
                page.get_by_role("row").filter(has_text="Local E2E Client").get_by_text("Draft", exact=True).wait_for()
                page.get_by_label("Search clients").fill("no matching client")
                page.get_by_text("No clients match these filters").wait_for()
                page.get_by_label("Search clients").fill("")
                client_row = page.get_by_role("row").filter(has_text="Local E2E Client")
                client_row.get_by_role("button", name="Actions for Local E2E Client").click()
                page.get_by_role("menuitem", name="View details").click()
                page.get_by_role("button", name="View assessments").click()
                page.wait_for_url(f"**/assessments?client_id={assessment['client_id']}")
                page.get_by_text("Local E2E Assessment", exact=True).first.wait_for()
                assessment_row = page.get_by_role("row").filter(has_text="Local E2E Assessment")
                assessment_row.get_by_role("button", name="Actions for Local E2E Assessment").click()
                page.get_by_role("menuitem", name="Set up authorization").click()
                page.get_by_label("Authorization reference").fill("local-only authorization record")
                page.get_by_label("Authorizing party").fill("Local E2E fixture owner")
                page.get_by_label("I reviewed and acknowledge this exact scope").check()
                page.get_by_label("Reason / operator notes").fill("Approved isolated loopback workflow fixture")
                page.get_by_role("button", name="Save").click()
                page.get_by_text("Authorization recorded for review").wait_for()
                page.get_by_title("Sign out").click()
                page.get_by_label("Email").fill("reviewer@example.test")
                page.get_by_label("Password").fill("test-only reviewer password")
                page.get_by_role("button", name="Sign in securely").click()
                page.get_by_role("link", name="Assessments").click()
                assessment_row = page.get_by_role("row").filter(has_text="Local E2E Assessment")
                assessment_row.get_by_role("button", name="Actions for Local E2E Assessment").click()
                page.get_by_role("menuitem", name="View assessment").click()
                page.get_by_role("button", name="Review authorization").wait_for()
                page.get_by_role("button", name="Review authorization").click()
                page.get_by_label("I reviewed the authorizing party, evidence fingerprint, scope and validity").check()
                page.get_by_label("Review rationale").fill("Reviewed local fixture authority and exact scope")
                page.get_by_role("button", name="Save").click()
                page.get_by_text("Authorization reviewed and activated").wait_for()
                page.get_by_title("Sign out").click()
                page.get_by_label("Email").fill("analyst@example.test")
                page.get_by_label("Password").fill("test-only analyst password")
                page.get_by_role("button", name="Sign in securely").click()
                page.get_by_role("link", name="API Discovery").click()
                page.get_by_role("button", name="Import API").first.click()
                document = {"openapi":"3.0.3","info":{"title":"Local E2E Fixture","version":"1"},
                            "servers":[{"url":f"http://127.0.0.1:{lab.server_port}"}],
                            "paths":{"/api/check":{"get":{"operationId":"localCheck"}}}}
                page.get_by_label("Client and assessment").select_option(str(assessment_id))
                page.get_by_text("Paste JSON instead").click()
                page.get_by_label("JSON document").fill(json.dumps(document))
                page.get_by_role("button", name="Import endpoints").click()
                page.get_by_text("Import complete · 1 added", exact=False).wait_for()
                endpoint_response = page.evaluate("""async ({api, aid}) => (await fetch(`${api}/discovery/endpoints?assessment_id=${aid}`,{credentials:'include'})).json()""",
                                                   {"api":env["VITE_API_URL"],"aid":assessment_id})
                endpoint = next(item for item in endpoint_response if item["path"] == "/api/check")
                assert endpoint["review_state"] == "IMPORTED"
                assert LabHandler.requests == 0

                # Inventory import and approval are passive; no HTTP runs before explicit approval.
                assert LabHandler.requests == 0

                endpoint_row = page.get_by_role("row").filter(has_text="/api/check")
                endpoint_row.get_by_role("button", name="Actions for GET /api/check").click()
                page.get_by_role("menuitem", name="Review endpoint").click()
                page.get_by_label("Scope decision").select_option("IN_SCOPE")
                page.get_by_label("Review rationale (required)").fill("Local fixture endpoint is within the approved path and host scope")
                page.get_by_role("button", name="Save scope and return to review").click()
                page.on("dialog", lambda dialog: dialog.accept("Reviewed local authorization, endpoint, and scope"))
                page.get_by_role("button", name="Approve for testing").click()
                page.get_by_text("Endpoint approved", exact=False).wait_for()
                page.get_by_role("button", name="Close", exact=True).click()
                page.get_by_role("link", name="Security Testing").click()
                for check_id in ("response.header.content_type_options", "response.header.strict_transport_security"):
                    card = page.locator(".test-card").filter(has_text=check_id)
                    card.wait_for(state="visible")
                    assert card.locator(".helper").inner_text().startswith("What it does not prove:")
                assert "X-Content-Type-Options" in page.locator(".test-card").filter(has_text="response.header.content_type_options").locator(".test-check-purpose").inner_text()
                assert "Strict-Transport-Security" in page.locator(".test-card").filter(has_text="response.header.strict_transport_security").locator(".test-check-purpose").inner_text()
                assert page.get_by_text("Bounded single-response metadata observation only.").is_visible()

                content_type_card = page.locator(".test-card").filter(has_text="response.header.content_type_options")
                content_type_card.locator('input[type="radio"]').check()
                page.get_by_role("button", name="3 · Run selected check").click()
                page.locator(".test-history-card .badge.fail").first.wait_for()
                page.get_by_text("Candidate; analyst validation required", exact=False).wait_for()
                hsts_card = page.locator(".test-card").filter(has_text="response.header.strict_transport_security")
                hsts_card.locator('input[type="radio"]').check()
                page.get_by_role("button", name="3 · Run selected check").click()
                page.locator(".test-history-card .badge.inconclusive").first.wait_for()
                hsts_history_row = page.get_by_role("row").filter(has_text="response.header.strict_transport_security")
                hsts_history_row.wait_for()
                assert "COMPLETED" in hsts_history_row.inner_text()
                assert "INCONCLUSIVE" in hsts_history_row.inner_text()
                page.get_by_role("link", name="Security Testing").wait_for()
                page.get_by_role("link", name="Findings").click()
                finding_row = page.get_by_role("row").filter(has_text="Content-Type sniffing policy header")
                finding_row.wait_for()
                assert "Candidate" in finding_row.inner_text()
                finding_row.get_by_role("button", name="Review").click()
                review_panel = page.locator(".finding-review-panel")
                page.get_by_text("Confidence: LOW", exact=False).wait_for(state="visible")
                assert page.get_by_text("response.header.content_type_options").count() >= 2

                review_panel.get_by_label("Validation state").select_option("VALIDATED")
                review_panel.get_by_label("Validation rationale").fill("Validated the observation in the local response fixture with stored check evidence")
                review_panel.get_by_role("button", name="Record validation").click()
                review_panel.get_by_label("Next state").select_option(label="Needs Review")
                review_panel.get_by_label("Triage rationale").fill("Reviewer triaged the observation after validation")
                review_panel.get_by_role("button", name="Record decision").click()
                page.get_by_text("Candidate → Needs Review").wait_for()
                review_panel.get_by_label("Next state").select_option(label="Confirmed")
                review_panel.get_by_label("Triage rationale").fill("Validated the observation in the local response fixture")
                review_panel.get_by_role("button", name="Record decision").click()
                page.get_by_text("Needs Review → Confirmed").wait_for()
                page.get_by_text("Analyst #", exact=False).first.wait_for()
                review_panel.get_by_label("Remediation state").select_option("IN_PROGRESS")
                review_panel.get_by_label("Remediation notes").fill("Local fixture owner applied the documented response-header remediation")
                review_panel.get_by_label("Proposed fix").fill("Configure the server to emit X-Content-Type-Options: nosniff")
                review_panel.get_by_label("Update rationale", exact=True).fill("The owner recorded the local remediation plan")
                review_panel.get_by_role("button", name="Save remediation update").click()
                page.get_by_text("Remediation: IN_PROGRESS", exact=False).wait_for()
                page.get_by_role("button", name="Close finding review").click()

                # A clean observation is a separate new TestRun; it can support retest but is not a finding confirmation.
                LabHandler.nosniff = True
                page.get_by_role("link", name="Security Testing").click()
                clean_check_card = page.locator(".test-card").filter(has_text="response.header.content_type_options")
                clean_check_card.locator('input[type="radio"]').check()
                page.get_by_role("button", name="3 · Run selected check").click()
                page.locator(".test-history-card .badge.pass").first.wait_for()
                page.get_by_role("link", name="Coverage").click()
                page.get_by_role("heading", name="Latest HTTP transport status").wait_for(state="visible")
                page.get_by_text("Coverage reflects enabled read-only checks", exact=False).wait_for(state="visible")
                page.get_by_text("OWASP API Security Top 10 · 2023", exact=True).wait_for(state="visible")
                coverage_data = page.evaluate("""async ({api,aid}) => (await (await fetch(`${api}/coverage/${aid}`,{credentials:'include'})).json()).security_test_execution""",
                                              {"api":env["VITE_API_URL"],"aid":assessment_id})
                assert coverage_data["planned"] == 1
                assert "response.header.strict_transport_security" not in coverage_data["matrix"][0]["tests"], coverage_data
                assert coverage_data["owasp_categories"]["API8:2023"]["implemented_checks"]
                assert coverage_data["owasp_categories"]["API1:2023"]["planned"] == 0
                assert coverage_data["owasp_categories"]["API1:2023"]["uncovered_endpoints"] == 1

                page.get_by_role("link", name="Retesting").click()
                page.get_by_role("button", name="Manual review", exact=True).click()
                retest_select = page.get_by_label("Registered TestRun (optional)")
                options = retest_select.locator("option").all_text_contents()
                assert any("NO_ISSUE_OBSERVED" in option for option in options), options
                assert not any("INCONCLUSIVE" in option or "NOT_RUN" in option for option in options), options
                chosen = next(option for option in retest_select.locator("option").all() if "NO_ISSUE_OBSERVED" in option.inner_text())
                retest_select.select_option(chosen.get_attribute("value"))
                page.get_by_label("Analyst notes / rationale (minimum 5 characters)").fill("Verified the current local response after fixture remediation")
                page.get_by_role("button", name="Save").click()
                page.get_by_text("Evidence-linked retest recorded").wait_for()
                page.get_by_role("link", name="Findings").click()
                finding_row = page.get_by_role("row").filter(has_text="Content-Type sniffing policy header")
                finding_row.get_by_role("button", name="Review").click()
                review_panel = page.locator(".finding-review-panel")
                review_panel.get_by_label("Remediation state").select_option("VERIFIED_FIXED")
                review_panel.get_by_label("Update rationale", exact=True).fill("Reviewer inspected the registered no-issue evidence and verified the fix")
                review_panel.get_by_role("button", name="Save remediation update").click()
                page.get_by_text("Remediation: VERIFIED_FIXED", exact=False).wait_for()
                page.get_by_role("button", name="Close finding review").click()

                page.get_by_role("link", name="Reports").click()
                page.get_by_role("button", name="New report").click()
                page.get_by_role("dialog").get_by_label("Assessment").select_option(str(assessment_id))
                page.get_by_role("dialog").get_by_role("button", name="Generate report", exact=True).click()
                page.locator(".toast").wait_for(state="visible", timeout=5000)
                if page.locator(".toast").inner_text().strip() != "Report version created":
                    api_log.flush()
                    api_log.seek(0)
                    print("API process state:", api_process.poll())
                    print("API log:\n", api_log.read()[-12000:])
                    print("Report UI result:", page.locator(".toast").inner_text())
                page.get_by_text("Report version created").wait_for()
                report_rows = page.evaluate("""async ({api,aid}) => (await (await fetch(`${api}/reports?assessment_id=${aid}`,{credentials:'include'})).json())""",
                                            {"api":env["VITE_API_URL"],"aid":assessment_id})
                report_id = report_rows[0]["id"]
                exports = page.evaluate("""async ({api,id}) => {
                  const j=await (await fetch(`${api}/reports/${id}/export?format=json`,{credentials:'include'})).json();
                  const h=await (await fetch(`${api}/reports/${id}/export?format=html`,{credentials:'include'})).text();
                  return {j,h};
                }""", {"api":env["VITE_API_URL"],"id":report_id})
                assert any(run["test_id"] == "response.header.strict_transport_security" for run in exports["j"]["methodology"]["checks"])
                assert any(run["security_outcome"] == "INCONCLUSIVE" for run in exports["j"]["test_runs"])
                assert exports["j"]["scope"] == {"hosts": ["127.0.0.1"], "paths": ["/api/**"], "exclusions": []}
                assert exports["j"]["authorization_record"]["status"] == "ACTIVE"
                assert exports["j"]["authorization_record"]["legal_authenticity_verified"] is False
                finding_statuses = [finding["status"] for finding in exports["j"]["findings"]]
                assert "Resolved" in finding_statuses, finding_statuses
                linked_retests = [retest for retest in exports["j"]["retests"] if retest["test_run_id"] is not None]
                assert linked_retests and all(
                    retest["endpoint_id"] is not None
                    and retest["test_id"] == "response.header.content_type_options"
                    and retest["test_version"] == "1.0.0"
                    and retest["endpoint_definition_hash"]
                    for retest in linked_retests
                )
                assert "Methodology and coverage" in exports["h"] and "browser behavior" in exports["h"]
                assert "Hosts: 127.0.0.1" in exports["h"] and "Paths: /api/**" in exports["h"]
                assert "Independent legal verification:" in exports["h"] and "Not performed" in exports["h"]
                assert "fixture-secret" not in str(exports)
                if artifact_paths:
                    artifact_paths[0].write_text(
                        json.dumps(exports["j"], indent=2, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                    artifact_paths[1].write_text(exports["h"], encoding="utf-8")

                page.get_by_role("button", name="Sign out").click()
                page.get_by_role("heading", name="Welcome back").wait_for()
                logout_status = page.evaluate("async api => (await fetch(`${api}/assessments`,{credentials:'include'})).status", env["VITE_API_URL"])
                assert logout_status == 401
                browser.close()

            print("Browser E2E passed: auth/ownership, dashboard aggregation/date filter, activity audit, inventory approval, both registry checks, finding triage, compatible retesting, coverage, and JSON/HTML report exports.")
            if artifact_paths:
                print("Synthetic local report artifacts:")
                for path in artifact_paths:
                    print(f"- {path}")
        finally:
            LabHandler.nosniff = False
            for process in (ui_process, worker_process, api_process):
                if process is not None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
            lab.shutdown()
            lab.server_close()
            lab_thread.join(timeout=2)
            engine.dispose()
            api_log.close()


if __name__ == "__main__":
    main()

"""Run APISentinel's local, non-deploying release checks and emit JSON."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def result(check_id: str, category: str, status: str, explanation: str,
           remediation: str = "", *, blocking: bool = False, evidence: str = "") -> dict:
    return {"check_id": check_id, "category": category, "status": status,
            "evidence": evidence[-4000:], "explanation": explanation,
            "suggested_remediation": remediation, "blocks_release": blocking}


def command_check(check_id: str, category: str, command: list[str], *, env: dict[str, str] | None = None,
                  timeout: int = 900) -> dict:
    try:
        completed = subprocess.run(command, cwd=ROOT, env=env, text=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return result(check_id, category, "FAIL", f"Command did not complete: {type(exc).__name__}.",
                      f"Install the documented tool or resolve the command failure: {' '.join(command)}",
                      blocking=True, evidence=str(exc))
    status = "PASS" if completed.returncode == 0 else "FAIL"
    explanation = f"Command exited {completed.returncode}: {' '.join(command)}"
    return result(check_id, category, status, explanation,
                  "Resolve the reported command failures before release." if status == "FAIL" else "",
                  blocking=status == "FAIL", evidence=completed.stdout)


def verify_ci_definition() -> dict:
    workflow = ROOT / ".github" / "workflows" / "ci.yml"
    required = (
        "pull_request:", "permissions:", "contents: read", "services:", "postgres:",
        "pytest -q", "alembic upgrade head", "pg_dump", "pg_restore", "npm ci", "npm run build",
    )
    try:
        content = workflow.read_text(encoding="utf-8")
    except OSError:
        return result("hosted-ci-definition", "operations", "FAIL",
                      "The repository CI workflow could not be read.",
                      "Restore a hosted CI workflow covering backend, migrations, PostgreSQL recovery and frontend build.",
                      blocking=True)
    missing = [item for item in required if item not in content]
    if missing:
        return result("hosted-ci-definition", "operations", "FAIL",
                      "The CI workflow is missing required verification steps.",
                      "Add the missing checks before relying on hosted CI.", blocking=True,
                      evidence="Missing markers: " + ", ".join(missing))
    return result("hosted-ci-definition", "operations", "PASS",
                  "Workflow definition includes pull-request CI, read-only repository permissions, PostgreSQL migration/recovery, backend tests, and dashboard build.",
                  evidence=str(workflow.relative_to(ROOT)))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-tests", action="store_true", help="Do not execute pytest; skipped checks block release.")
    parser.add_argument("--skip-dashboard-build", action="store_true", help="Do not build the dashboard; skipped checks block release.")
    parser.add_argument("--skip-e2e", action="store_true", help="Do not run the loopback-only browser workflow; skipped checks block release.")
    args = parser.parse_args()
    checks: list[dict] = []

    checks.append(verify_ci_definition())
    checks.append(result("hosted-ci-run", "operations", "BLOCKED",
                         "This local release gate cannot establish that the hosted workflow completed successfully.",
                         "Review the latest hosted run on the repository and record its URL and result.", blocking=True))
    checks.append(result("audit-retention-policy", "operations", "BLOCKED",
                         "Application audit rows are append-only and have no automatic purge, but an organization-approved retention and disposal period is not configured.",
                         "Approve and document audit, backup, legal-hold, and disposal periods before production use.", blocking=True))

    checks.append(command_check("backend-import", "application", [sys.executable, "-c", "from apisentinel.main import app; assert app"],
                                env={**os.environ, "PYTHONPATH": str(ROOT / "src")}))
    checks.append(command_check("ruff", "testing", [sys.executable, "-m", "ruff", "check", "src", "migrations", "tests", "scripts"]))
    checks.append(command_check("python-compile", "application", [sys.executable, "-m", "compileall", "-q", "src", "migrations", "tests", "scripts"]))

    if args.skip_tests:
        checks.append(result("backend-tests", "testing", "NOT_RUN", "pytest was explicitly skipped.",
                             "Run pytest -q before release.", blocking=True))
    else:
        test_result = command_check("backend-tests", "testing", [sys.executable, "-m", "pytest", "-q"], timeout=1800)
        checks.append(test_result)
        skipped = re.search(r"\b(\d+)\s+skipped\b", test_result["evidence"])
        if skipped and int(skipped.group(1)):
            checks.append(result("skipped-tests", "testing", "NOT_RUN",
                                 f"pytest reported {skipped.group(1)} skipped test(s); they are not counted as passing.",
                                 "Run the skipped tests with their documented disposable dependencies before release.",
                                 blocking=True, evidence=skipped.group(0)))

    if args.skip_e2e:
        checks.append(result("browser-e2e", "testing", "NOT_RUN", "The local browser end-to-end workflow was explicitly skipped.",
                             "Run python tests/e2e_browser_workflow.py before release.", blocking=True))
    else:
        checks.append(command_check("browser-e2e", "testing", [sys.executable, "tests/e2e_browser_workflow.py"], timeout=600))

    if args.skip_dashboard_build:
        checks.append(result("dashboard-build", "application", "NOT_RUN", "Dashboard build was explicitly skipped.",
                             "Run npm run build in dashboard/ before release.", blocking=True))
    elif shutil.which("npm"):
        checks.append(command_check("dashboard-build", "application", ["npm", "--prefix", "dashboard", "run", "build"], timeout=600))
    else:
        checks.append(result("dashboard-build", "application", "NOT_RUN", "npm is unavailable on this host.",
                             "Install the supported Node.js runtime and build the dashboard.", blocking=True))

    with tempfile.TemporaryDirectory(prefix="apisentinel-release-gate-") as temporary:
        database_path = Path(temporary) / "migration-check.db"
        db_env = {**os.environ, "APISENTINEL_ENVIRONMENT": "test",
                  "APISENTINEL_DATABASE_URL": f"sqlite:///{database_path}"}
        upgrade = command_check("disposable-migrations", "database",
                                [sys.executable, "-m", "alembic", "upgrade", "head"], env=db_env)
        checks.append(upgrade)
        if upgrade["status"] == "PASS":
            checks.append(command_check("migration-drift", "database",
                                        [sys.executable, "-m", "alembic", "check"], env=db_env))
        else:
            checks.append(result("migration-drift", "database", "NOT_RUN",
                                 "Migration drift check was not run because upgrade failed.",
                                 "Fix the disposable migration upgrade first.", blocking=True))

    # Settings validates configuration without returning or printing secret values.
    try:
        sys.path.insert(0, str(ROOT / "src"))
        from apisentinel.config import Settings

        current = Settings()
        prod = current.environment.lower() in {"production", "staging"}
        if prod:
            checks.append(result("production-config", "security", "PASS",
                                 "Production-like configuration passed application startup validation; credentials and key values were not emitted."))
        else:
            checks.append(result("production-config", "security", "BLOCKED",
                                 "The supplied runtime configuration is not staging/production; no production configuration was validated.",
                                 "Provide the deployment environment through the approved secret/configuration mechanism and rerun this check.",
                                 blocking=True, evidence=f"Configured environment class: {current.environment.lower()}"))
        if current.allow_active_tests:
            checks.append(result("active-execution-default", "security", "BLOCKED",
                                 "The active HTTP execution gate is enabled in the supplied runtime configuration.",
                                 "Disable it by default or provide a separately reviewed, deployment-specific approval and safe operations gate.",
                                 blocking=True, evidence=f"Configured environment class: {current.environment.lower()}"))
        else:
            checks.append(result("active-execution-default", "security", "PASS",
                                 "The active HTTP execution gate is disabled in the supplied runtime configuration."))
    except (ValueError, OSError, ImportError, RuntimeError) as exc:
        checks.append(result("production-config", "security", "FAIL",
                             f"Application configuration validation failed ({type(exc).__name__}); values are suppressed.",
                             "Correct the deployment configuration without placing secrets in command output.", blocking=True))

    for check_id, label in (
        ("managed-kms-iam", "Managed KMS/IAM reachability and key policy were not independently verified."),
        ("host-egress-acl", "Host/VPC egress ACLs and approved production destination ranges were not inspected."),
        ("backup-restore-drill", "A production-like database backup and restore drill was not performed."),
        ("production-https", "Production TLS termination, cookie delivery, ingress and security headers were not exercised."),
    ):
        checks.append(result(check_id, "operations", "BLOCKED", label,
                             "Run and attach verifiable environment-specific evidence before production release.", blocking=True))
    checks.append(result("dependency-advisory-scan", "security", "WARN",
                         "This offline-safe gate did not query a remote dependency vulnerability advisory service.",
                         "Run the organization-approved dependency scanner in trusted CI and review its report."))

    summary = {status: sum(check["status"] == status for check in checks)
               for status in ("PASS", "FAIL", "WARN", "BLOCKED", "NOT_RUN")}
    payload = {"schema_version": 1, "release_decision": "BLOCKED" if any(c["blocks_release"] and c["status"] != "PASS" for c in checks) else "READY_FOR_REVIEW",
               "checks": checks, "summary": summary,
               "notice": "Local automated checks do not establish production readiness; skipped checks are never passes."}
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 1 if payload["release_decision"] == "BLOCKED" else 0


if __name__ == "__main__":
    raise SystemExit(main())

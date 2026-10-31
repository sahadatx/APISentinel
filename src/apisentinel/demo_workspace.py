"""Read-only workflow projections for explicitly identified local showcase records.

These projections never authorize an endpoint or contribute to execution coverage.
"""

from copy import deepcopy

from .test_registry import REGISTRY, SecurityOutcome

TERMINAL_TRANSPORT_STATUSES = (
    "COMPLETED", "SKIPPED", "BLOCKED_SCOPE", "BLOCKED_DESTINATION",
    "AUTH_UNAVAILABLE", "OVERSIZED_RESPONSE", "TIMEOUT", "TRANSPORT_ERROR", "CANCELLED", "NOT_RUN",
)
BLOCKED_TRANSPORT_STATUSES = {
    "SKIPPED", "BLOCKED_SCOPE", "BLOCKED_DESTINATION", "AUTH_UNAVAILABLE",
}
COMPLETED_SECURITY_OUTCOMES = {
    SecurityOutcome.NO_ISSUE_OBSERVED.value, SecurityOutcome.CANDIDATE_FOUND.value,
}


def _percentage(completed: int, planned: int) -> int:
    return int(completed * 100 / planned + 0.5) if planned else 0


def build_workflow_preview(assessment, endpoints, runs, findings, actual_coverage: dict):
    """Project persisted DEMO states without changing the live coverage calculation.

    Require the assessment flag and the run provenance flag together. Running or
    queued records are excluded so the projection cannot resemble active work.
    """
    if not assessment or (assessment.target_configs or {}).get("demo_workspace") is not True:
        return None

    endpoint_by_id = {endpoint.id: endpoint for endpoint in endpoints
                      if endpoint.assessment_id == assessment.id and endpoint.inventory_current}
    outcomes = {outcome.value for outcome in SecurityOutcome}
    preview_runs = sorted(
        (run for run in runs
         if run.assessment_id == assessment.id
         and run.endpoint_id in endpoint_by_id
         and run.execution_mode == "DEMO"
         and (run.execution_metadata or {}).get("demo_workspace") is True
         and run.status in TERMINAL_TRANSPORT_STATUSES
         and run.security_outcome in outcomes
         and run.test_id),
        key=lambda run: run.id or 0, reverse=True,
    )
    preview_run_ids = {run.id for run in preview_runs}
    preview_findings = [finding for finding in findings
                        if finding.assessment_id == assessment.id
                        and (finding.evidence or {}).get("demo_workspace") is True]
    findings_by_run = {}
    for finding in preview_findings:
        if finding.test_run_id in preview_run_ids:
            findings_by_run.setdefault(finding.test_run_id, []).append(finding.id)

    latest_attempt = {}
    latest_observation = {}
    latest_transport = {}
    for run in preview_runs:
        key = (run.endpoint_id, run.test_id)
        latest_attempt.setdefault(key, run)
        latest_transport.setdefault(run.endpoint_id, run.status)
        if run.security_outcome != SecurityOutcome.NOT_RUN.value:
            latest_observation.setdefault(key, run)

    def outcome_for(key):
        run = latest_observation.get(key)
        return run.security_outcome if run else SecurityOutcome.NOT_RUN.value

    matrix = []
    represented_endpoint_ids = sorted(latest_transport)
    for endpoint_id in represented_endpoint_ids:
        endpoint = endpoint_by_id[endpoint_id]
        keys = sorted(key for key in latest_attempt if key[0] == endpoint_id)
        details = {}
        for key in keys:
            observation = latest_observation.get(key)
            attempt = latest_attempt[key]
            details[key[1]] = {
                "outcome_run_id": observation.id if observation else None,
                "outcome": outcome_for(key),
                "transport_status": attempt.status,
                "latest_attempt_run_id": attempt.id,
                "finding_ids": findings_by_run.get(observation.id, []) if observation else [],
            }
        matrix.append({
            "endpoint_id": endpoint.id, "method": endpoint.method, "path": endpoint.path,
            "tests": {key[1]: outcome_for(key) for key in keys}, "test_details": details,
        })

    categories = deepcopy(actual_coverage["security_test_execution"]["owasp_categories"])
    for category_id, category in categories.items():
        keys = [key for key in latest_attempt
                if key[1] in REGISTRY and category_id in REGISTRY[key[1]].owasp_categories]
        observed = [outcome_for(key) for key in keys]
        category_run_ids = {run.id for key in keys
                            for run in [latest_observation.get(key)] if run is not None}
        category_findings = [finding for finding in preview_findings
                             if finding.test_run_id in category_run_ids
                             or (finding.test_run_id not in preview_run_ids
                                 and category_id in (finding.owasp_categories or []))]
        category.update({
            "planned": len(keys),
            "executed": sum(value != SecurityOutcome.NOT_RUN.value for value in observed),
            "passed": observed.count(SecurityOutcome.NO_ISSUE_OBSERVED.value),
            "candidate_results": observed.count(SecurityOutcome.CANDIDATE_FOUND.value),
            "confirmed_findings": sum(finding.status == "Confirmed" for finding in category_findings),
            "candidate_findings": sum(finding.status in {"Candidate", "Needs Review"}
                                      for finding in category_findings),
            "inconclusive": observed.count(SecurityOutcome.INCONCLUSIVE.value),
            "errors": observed.count(SecurityOutcome.ERROR.value),
            "blocked": sum(latest_attempt[key].status in BLOCKED_TRANSPORT_STATUSES for key in keys),
            "not_run": observed.count(SecurityOutcome.NOT_RUN.value),
            "not_applicable": 0,
            "uncovered_endpoints": sum(not any(key[0] == endpoint_id for key in keys)
                                       for endpoint_id in represented_endpoint_ids),
            "missing_prerequisites": 0,
            "preview_checks": sorted({key[1] for key in keys}),
            "meaning": "Workflow preview states; excluded from actual execution coverage.",
        })

    planned = len(latest_attempt)
    completed = sum(outcome_for(key) in COMPLETED_SECURITY_OUTCOMES for key in latest_attempt)
    transport_completed = sum(status == "COMPLETED" for status in latest_transport.values())
    reviewed = sum(finding.status != "Candidate" for finding in preview_findings)
    return {
        "data_kind": "WORKFLOW_PREVIEW",
        "basis": "Persisted demonstration workflow states; no target request is represented.",
        "security_test_execution": {
            "taxonomy_version": actual_coverage["security_test_execution"]["taxonomy_version"],
            "owasp_categories": categories,
            "registered_tests": sorted({key[1] for key in latest_attempt}),
            "planned": planned, "completed": completed,
            "percentage": _percentage(completed, planned),
            "outcomes": {outcome.value: sum(outcome_for(key) == outcome.value for key in latest_attempt)
                         for outcome in SecurityOutcome},
            "matrix": matrix, "completed_outcomes": sorted(COMPLETED_SECURITY_OUTCOMES),
        },
        "transport_execution": {
            "planned": len(latest_transport), "completed": transport_completed,
            "percentage": _percentage(transport_completed, len(latest_transport)),
            "outcomes": {status: sum(value == status for value in latest_transport.values())
                         for status in (*TERMINAL_TRANSPORT_STATUSES, "RUNNING")},
            "latest_status_by_endpoint": {str(key): value for key, value in latest_transport.items()},
            "meaning": "Workflow preview states; excluded from actual transport execution.",
        },
        "reviewed_finding_coverage": {
            "candidates": len(preview_findings), "reviewed": reviewed,
            "percentage": _percentage(reviewed, len(preview_findings)),
        },
    }

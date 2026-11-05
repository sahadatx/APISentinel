import importlib.util
import sys
from pathlib import Path

GATE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "release_gate.py"
SPEC = importlib.util.spec_from_file_location("apisentinel_release_gate", GATE_PATH)
release_gate = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = release_gate
SPEC.loader.exec_module(release_gate)


def test_release_gate_command_classifies_success_and_failure_without_network():
    passed = release_gate.command_check("safe-python", "testing", [
        sys.executable, "-c", "print('local fixture only')",
    ])
    failed = release_gate.command_check("expected-failure", "testing", [
        sys.executable, "-c", "raise SystemExit(3)",
    ])
    assert passed["status"] == "PASS" and passed["blocks_release"] is False
    assert failed["status"] == "FAIL" and failed["blocks_release"] is True
    assert "local fixture only" in passed["evidence"]


def test_release_gate_keeps_warning_blocked_and_not_run_distinct():
    warning = release_gate.result("advisory", "security", "WARN", "not queried")
    blocked = release_gate.result("kms", "operations", "BLOCKED", "not verified", blocking=True)
    not_run = release_gate.result("postgres", "testing", "NOT_RUN", "service unavailable", blocking=True)
    assert [warning["status"], blocked["status"], not_run["status"]] == ["WARN", "BLOCKED", "NOT_RUN"]
    assert not warning["blocks_release"] and blocked["blocks_release"] and not_run["blocks_release"]


def test_ci_definition_check_requires_database_recovery_and_build_steps():
    checked = release_gate.verify_ci_definition()
    assert checked["status"] == "PASS"
    assert checked["blocks_release"] is False
    assert "workflow" in checked["evidence"]

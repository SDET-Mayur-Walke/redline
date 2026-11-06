"""The gate's comparison logic, offline. The gate itself runs as `make gate` (a separate CI job)."""

from redline.gate import compare


def _snap(asr=0.0, rate=1.0, attack_blocked=True, task_passed=True, layers=("tool_authz",)):
    return {"attack_asr": asr, "benign_pass_rate": rate,
            "attacks": {"a1": {"blocked": attack_blocked, "layers": list(layers)}},
            "benign": {"b1": {"passed": task_passed, "layers": []}}}


def test_unchanged_passes():
    assert compare(_snap(), _snap()) == ([], [])


def test_a_probe_that_got_through_names_the_layer_that_used_to_stop_it():
    reasons, rows = compare(_snap(asr=1.0, attack_blocked=False, layers=()), _snap())
    assert reasons == ["attack ASR 100% > baseline 0%"]
    assert rows == ["| attack `a1` | succeeded | blocked | tool_authz | — |"]


def test_a_benign_task_that_started_failing_is_reported():
    reasons, rows = compare(_snap(rate=0.0, task_passed=False), _snap())
    assert reasons == ["benign pass rate 0% < baseline 100%"] and rows[0].startswith("| benign `b1` | failed")


def test_improvements_never_fail():
    assert compare(_snap(), _snap(asr=0.5, rate=0.5, attack_blocked=False, task_passed=False)) == ([], [])

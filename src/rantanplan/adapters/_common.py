"""
Shared parse guards for subprocess-based adapters.

A scanner run that crashed, printed nothing or printed something that is not the expected JSON
produced *no verdict*. It must never be scored as a detection (exit code != 0) or as a pass
(empty output); it is reported as ``INCOMPLETE`` so the score card can exclude it and surface it.
"""

from rantanplan.models import (
    AssuranceOutcome,
    ExecutionStatus,
    RawExecution,
    RichNormalizedResult,
    TestCase,
)


def incomplete_result(
    case: TestCase,
    execution: RawExecution,
    name: str,
    version: str,
    status: ExecutionStatus,
    reason: str,
) -> RichNormalizedResult:
    return RichNormalizedResult(
        run_id=f"run-{name}",
        case_id=case.id,
        target_name=name,
        target_version=version,
        execution_status=status,
        outcome=AssuranceOutcome.INCOMPLETE,
        duration_ms=execution.duration_ms,
        exit_code=execution.exit_code,
        raw_report=f"{reason}\n{execution.stdout}\n{execution.stderr}".strip(),
    )


def unusable_report(
    case: TestCase, execution: RawExecution, name: str, version: str
) -> RichNormalizedResult | None:
    """Return an INCOMPLETE result if the execution produced no usable report, else ``None``."""
    # TARGET_ERROR only means "exit code other than 0/1"; a parseable report may still be present.
    if execution.execution_status not in (ExecutionStatus.SUCCESS, ExecutionStatus.TARGET_ERROR):
        return incomplete_result(
            case, execution, name, version, execution.execution_status,
            f"execution status {execution.execution_status.value}",
        )
    if not execution.stdout.strip():
        return incomplete_result(
            case, execution, name, version, ExecutionStatus.REPORT_MISSING, "scanner produced no report on stdout"
        )
    return None

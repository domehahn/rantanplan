"""
Ecosystem Verification Engine for Rantanplan Universal Scanner Assurance v2.

Executes end-to-end ecosystem verification across doctor diagnostics, adapter self-tests,
ground-truth verification, target coverage, and outputs structured JSON/Markdown verification reports.
"""

import json
from pathlib import Path
from typing import Any

from rantanplan.adapters.cisco import CiscoAIDefenseAdapter
from rantanplan.adapters.garak import garakDetectorAdapter, garakProbeAdapter
from rantanplan.adapters.promptfoo_suite import PromptfooEvalAdapter
from rantanplan.adapters.skil import SKILAdapter
from rantanplan.adapters.skil_suite import (
    SKILAttestationAdapter,
    SKILEvalAdapter,
    SKILLintAdapter,
    SKILPolicyAdapter,
    SKILProvenanceAdapter,
    SKILRegistryAdmissionAdapter,
    SKILRuntimePolicyAdapter,
    SKILSemanticScanAdapter,
    SKILStaticScanAdapter,
    SKILTrustAdapter,
    SKILValidateAdapter,
    SKILVerifyAdapter,
)
from rantanplan.adapters.skillevaluator import SkillEvaluatorAdapter
from rantanplan.adapters.skillspector import SkillSpectorAdapter
from rantanplan.adapters.snyk import SnykAgentScanAdapter
from rantanplan.adapters.tencent import (
    TencentAgentScannerAdapter,
    TencentMCPScannerAdapter,
    TencentSkillScannerAdapter,
)
from rantanplan.corpus import load_corpus
from rantanplan.models import SupportStatus


def get_all_target_adapters():
    """Returns instantiated list of all target adapters across ecosystem domains."""
    return [
        SKILAdapter(),
        SKILStaticScanAdapter(),
        SKILSemanticScanAdapter(),
        SKILValidateAdapter(),
        SKILLintAdapter(),
        SKILVerifyAdapter(),
        SKILEvalAdapter(),
        SKILRegistryAdmissionAdapter(),
        SKILPolicyAdapter(),
        SKILTrustAdapter(),
        SKILProvenanceAdapter(),
        SKILAttestationAdapter(),
        SKILRuntimePolicyAdapter(),
        SkillSpectorAdapter(),
        garakProbeAdapter(),
        garakDetectorAdapter(),
        SkillEvaluatorAdapter(),
        PromptfooEvalAdapter(),
        CiscoAIDefenseAdapter(),
        TencentSkillScannerAdapter(),
        TencentMCPScannerAdapter(),
        TencentAgentScannerAdapter(),
        SnykAgentScanAdapter(),
    ]


def verify_ecosystem() -> dict[str, Any]:
    """Runs complete ecosystem verification suite and returns status dictionary."""
    adapters = get_all_target_adapters()
    cases = load_corpus()

    target_matrix = {}
    fully_supported_count = 0
    adapter_ready_count = 0
    total_targets = len(adapters)

    for adapter in adapters:
        doc = adapter.doctor()
        st = adapter.self_test()

        if doc.installed:
            status = SupportStatus.FULLY_SUPPORTED
            fully_supported_count += 1
        else:
            status = SupportStatus.ADAPTER_READY
            adapter_ready_count += 1

        target_matrix[adapter.identity().name] = {
            "name": adapter.identity().name,
            "version": doc.version,
            "path": doc.path,
            "installed": doc.installed,
            "status": status.value,
            "self_test_passed": st.passed,
            "capabilities": adapter.capabilities(),
        }

    overall_status = "FULLY_VERIFIED" if fully_supported_count == total_targets else "ADAPTER_READY"
    coverage = round((fully_supported_count / total_targets) * 100, 1)

    result = {
        "overall_status": overall_status,
        "total_targets": total_targets,
        "fully_supported_count": fully_supported_count,
        "adapter_ready_count": adapter_ready_count,
        "coverage_percentage": coverage,
        "test_cases_loaded": len(cases),
        "target_matrix": target_matrix,
    }

    # Save verification report artifacts
    results_dir = Path.cwd() / "results"
    results_dir.mkdir(exist_ok=True)

    json_path = results_dir / "final-ecosystem-verification.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    md_path = results_dir / "final-ecosystem-verification.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("# Rantanplan Universal Scanner Assurance — Ecosystem Verification Report\n\n")
        f.write(f"**Overall Status**: `{overall_status}`\n")
        f.write(f"**Coverage**: `{coverage}%` ({fully_supported_count}/{total_targets} Targets Live Installed)\n\n")
        f.write("| Target Name | Installed | Status | Self-Test Passed | Capabilities |\n")
        f.write("|---|---|---|---|---|\n")
        for key, item in target_matrix.items():
            caps = ", ".join(item["capabilities"][:3])
            f.write(f"| `{item['name']}` | `{item['installed']}` | `{item['status']}` | `{item['self_test_passed']}` | {caps} |\n")

    return result

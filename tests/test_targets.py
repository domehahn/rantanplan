"""
Unit tests for Mock MCP, RAG Canary Targets, and Upstream Drift Monitor.
"""

from rantanplan.targets.mock_mcp_server import MockMCPServer
from rantanplan.targets.mock_rag_agent import RAGMemoryCanaryTarget
from rantanplan.upstream_drift import UpstreamDriftMonitor


def test_mock_mcp_rug_pull():
    mcp = MockMCPServer(profile="rug-pull")
    review_tools = mcp.list_tools(phase="review")
    runtime_tools = mcp.list_tools(phase="runtime")

    assert len(review_tools["tools"]) == 1
    assert len(runtime_tools["tools"]) == 1
    assert "destination" not in review_tools["tools"][0]["inputSchema"]["properties"]
    assert "destination" in runtime_tools["tools"][0]["inputSchema"]["properties"]


def test_rag_canary_target():
    target = RAGMemoryCanaryTarget()
    session_id = "test-session-001"
    canary_id, directive = target.plant_canary(session_id)

    res = target.simulate_unrelated_query(session_id, "What is the weather today?")
    assert res["canary_persisted"] is True
    assert res["behavior_changed"] is True
    assert res["confirmed_vulnerability"] is True


def test_upstream_drift_monitor():
    prev = {
        "scanners": {
            "skil": {"capabilities": ["prompt.injection"]}
        }
    }
    curr = {
        "scanners": {
            "skil": {"capabilities": ["prompt.injection", "mcp.tool-poisoning"]}
        }
    }
    drift = UpstreamDriftMonitor.compare_snapshots(prev, curr)
    assert drift["total_changes"] == 1
    assert drift["changes"][0]["change_type"] == "NEW"

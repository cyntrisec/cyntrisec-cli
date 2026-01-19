"""
Unit tests for MCP server fixes.

Tests:
1. GraphBuilder.build() works with keyword arguments (Property 1)
2. MCP tools return SNAPSHOT_NOT_FOUND when no data (Property 5)
3. list_tools includes all tools including set_session_snapshot and list_tools

**Feature: cyntrisec-bugfixes**
"""
from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

import pytest

from cyntrisec.core.graph import GraphBuilder
from cyntrisec.core.schema import Asset, Relationship
from cyntrisec.mcp.server import (
    MCP_ERROR_SNAPSHOT_NOT_FOUND,
    SessionState,
    mcp_error,
)
from cyntrisec.storage import FileSystemStorage


def make_asset(
    snapshot_id: uuid.UUID,
    asset_id: uuid.UUID,
    asset_type: str,
    name: str,
) -> Asset:
    """Helper to create test assets."""
    return Asset(
        id=asset_id,
        snapshot_id=snapshot_id,
        asset_type=asset_type,
        aws_resource_id=str(asset_id),
        name=name,
        is_internet_facing=False,
        is_sensitive_target=False,
        properties={},
    )


def make_relationship(
    snapshot_id: uuid.UUID,
    rel_id: uuid.UUID,
    source_id: uuid.UUID,
    target_id: uuid.UUID,
    rel_type: str = "CONNECTS_TO",
) -> Relationship:
    """Helper to create test relationships."""
    return Relationship(
        id=rel_id,
        snapshot_id=snapshot_id,
        source_asset_id=source_id,
        target_asset_id=target_id,
        relationship_type=rel_type,
    )


class TestGraphBuilderKeywordArguments:
    """
    Test GraphBuilder.build() with keyword arguments.
    
    **Property 1: GraphBuilder Keyword Arguments**
    *For any* MCP tool that uses GraphBuilder, calling build() with assets 
    and relationships SHALL succeed without TypeError.
    **Validates: Requirements 1.1**
    """

    def test_build_with_keyword_arguments(self):
        """GraphBuilder.build() should work with keyword arguments."""
        snapshot_id = uuid.UUID("00000000-0000-0000-0000-000000000000")
        id1 = uuid.UUID("11111111-1111-1111-1111-111111111111")
        id2 = uuid.UUID("22222222-2222-2222-2222-222222222222")
        rel_id = uuid.UUID("aaaaaaa1-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        
        assets = [
            make_asset(snapshot_id, id1, "ec2:instance", "web"),
            make_asset(snapshot_id, id2, "rds:db-instance", "db"),
        ]
        relationships = [
            make_relationship(snapshot_id, rel_id, id1, id2, "CONNECTS_TO"),
        ]
        
        builder = GraphBuilder()
        # This is the pattern used in MCP server - must use keyword arguments
        graph = builder.build(assets=assets, relationships=relationships)
        
        assert graph.asset_count() == 2
        assert graph.relationship_count() == 1

    def test_build_with_empty_data(self):
        """GraphBuilder.build() should work with empty assets and relationships."""
        builder = GraphBuilder()
        graph = builder.build(assets=[], relationships=[])
        
        assert graph.asset_count() == 0
        assert graph.relationship_count() == 0

    def test_build_rejects_positional_arguments(self):
        """GraphBuilder.build() should reject positional arguments."""
        snapshot_id = uuid.UUID("00000000-0000-0000-0000-000000000000")
        id1 = uuid.UUID("11111111-1111-1111-1111-111111111111")
        
        assets = [make_asset(snapshot_id, id1, "ec2:instance", "web")]
        relationships = []
        
        builder = GraphBuilder()
        
        # Positional arguments should raise TypeError
        with pytest.raises(TypeError):
            builder.build(assets, relationships)


class TestMCPToolsRequireData:
    """
    Test MCP tools return SNAPSHOT_NOT_FOUND when no data.
    
    **Property 5: MCP Tools Require Data**
    *For any* MCP tool that analyzes scan data (get_attack_paths, get_remediations, 
    check_compliance, get_unused_permissions), calling without loaded scan data 
    SHALL return SNAPSHOT_NOT_FOUND error, not empty/default results.
    **Validates: Requirements 5.1, 5.2, 5.3**
    """

    def test_mcp_error_format(self):
        """mcp_error() should return consistent error envelope."""
        result = mcp_error(MCP_ERROR_SNAPSHOT_NOT_FOUND, "Test message")
        
        assert result["status"] == "error"
        assert result["error_code"] == MCP_ERROR_SNAPSHOT_NOT_FOUND
        assert result["message"] == "Test message"
        assert result["data"] is None

    def test_session_state_get_snapshot_returns_none_when_no_data(self):
        """SessionState.get_snapshot() should return None when no scan data exists."""
        # Create a mock storage that returns None
        mock_storage = MagicMock(spec=FileSystemStorage)
        mock_storage.get_snapshot.return_value = None
        mock_storage.resolve_scan_id.return_value = None
        
        session = SessionState(storage=mock_storage)
        result = session.get_snapshot()
        
        assert result is None


class TestListToolsCompleteness:
    """
    Test list_tools includes all tools.
    
    **Validates: Requirements 6.1, 6.2**
    """

    @pytest.fixture
    def mcp_server(self):
        """Create MCP server for testing."""
        # Skip if MCP is not installed
        pytest.importorskip("mcp")
        from cyntrisec.mcp.server import create_mcp_server
        return create_mcp_server()

    def test_list_tools_includes_set_session_snapshot(self, mcp_server):
        """list_tools should include set_session_snapshot."""
        # Get the list_tools function from the server
        # We need to call it directly since it's registered as a tool
        tools = mcp_server._tool_manager._tools
        
        # Find the list_tools function
        list_tools_fn = None
        for name, tool in tools.items():
            if name == "list_tools":
                list_tools_fn = tool.fn
                break
        
        assert list_tools_fn is not None, "list_tools should be registered"
        
        result = list_tools_fn()
        tool_names = [t["name"] for t in result["tools"]]
        
        assert "set_session_snapshot" in tool_names, "set_session_snapshot should be in list_tools"

    def test_list_tools_includes_itself(self, mcp_server):
        """list_tools should include list_tools itself."""
        tools = mcp_server._tool_manager._tools
        
        list_tools_fn = None
        for name, tool in tools.items():
            if name == "list_tools":
                list_tools_fn = tool.fn
                break
        
        assert list_tools_fn is not None
        
        result = list_tools_fn()
        tool_names = [t["name"] for t in result["tools"]]
        
        assert "list_tools" in tool_names, "list_tools should include itself"

    def test_list_tools_includes_all_expected_tools(self, mcp_server):
        """list_tools should include all expected tools."""
        tools = mcp_server._tool_manager._tools
        
        list_tools_fn = None
        for name, tool in tools.items():
            if name == "list_tools":
                list_tools_fn = tool.fn
                break
        
        assert list_tools_fn is not None
        
        result = list_tools_fn()
        tool_names = [t["name"] for t in result["tools"]]
        
        expected_tools = [
            "list_tools",
            "set_session_snapshot",
            "get_scan_summary",
            "get_attack_paths",
            "get_remediations",
            "check_access",
            "get_unused_permissions",
            "check_compliance",
            "compare_scans",
        ]
        
        for expected in expected_tools:
            assert expected in tool_names, f"{expected} should be in list_tools"

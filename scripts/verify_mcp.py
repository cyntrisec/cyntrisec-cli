#!/usr/bin/env python3
"""
Verify MCP Server
-----------------
This script verifies that the MCP server starts correctly and exposes the expected tools.

Usage:
    python scripts/verify_mcp.py
"""
import sys
import json
from cyntrisec.mcp.server import create_mcp_server

EXPECTED_TOOLS = [
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

def main():
    print("Starting MCP Server Verification...")
    
    try:
        # Create the server instance
        mcp = create_mcp_server()
        
        # Access the tool manager directly to list tools
        tools = mcp._tool_manager._tools
        tool_names = list(tools.keys())
        
        print(f"Found {len(tool_names)} tools.")
        
        missing = []
        for expected in EXPECTED_TOOLS:
            if expected in tool_names:
                print(f"  [OK] {expected}")
            else:
                print(f"  [MISSING] {expected}")
                missing.append(expected)
                
        if missing:
            print(f"\nERROR: Missing tools: {', '.join(missing)}", file=sys.stderr)
            return 1
            
        print("\nMCP Server Verification Passed!")
        return 0
        
    except Exception as e:
        print(f"\nERROR: MCP verification failed: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())

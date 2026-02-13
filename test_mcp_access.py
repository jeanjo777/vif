#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test MCP Access - Verify VIF has access to all MCP servers and tools
"""
import sys
import os

# Fix Windows console encoding
if sys.platform == 'win32':
    os.system('chcp 65001 > nul')
    sys.stdout.reconfigure(encoding='utf-8')

from mcp import MCPManager

def test_mcp_access():
    print("=" * 60)
    print("TESTING VIF MCP ACCESS")
    print("=" * 60)

    # Initialize MCP Manager without database (fallback mode)
    print("\n1. Initializing MCP Manager (fallback mode - no DB)...")
    try:
        mcp_manager = MCPManager(db_pool=None)
        print(f"[OK] MCP Manager initialized successfully")
    except Exception as e:
        print(f"[X] Failed to initialize: {e}")
        sys.exit(1)

    # List all servers
    print(f"\n2. Servers initialized: {len(mcp_manager.servers)}")
    for server_name, server in mcp_manager.servers.items():
        status = "[OK] ENABLED" if server.enabled else "[X] DISABLED"
        print(f"   {status} {server_name:20s} - {server.description[:50]}...")

    # List all tools
    print(f"\n3. Available tools: {len(mcp_manager.list_all_tools())}")
    tools_by_server = {}
    for tool in mcp_manager.list_all_tools():
        server = tool['server']
        if server not in tools_by_server:
            tools_by_server[server] = []
        tools_by_server[server].append(tool['name'])

    for server_name, tools in sorted(tools_by_server.items()):
        print(f"\n   [-] {server_name.upper()} ({len(tools)} tools)")
        for tool in tools:
            print(f"      • {tool}")

    # Verify expected servers
    print("\n4. Verification des serveurs attendus:")
    expected_servers = [
        'web_browser', 'file_system', 'code_execution', 'external_apis',
        'vision', 'video', 'security', 'devtools', 'data_science',
        'creative', 'integration_hub'
    ]

    all_present = True
    for expected in expected_servers:
        if expected in mcp_manager.servers:
            print(f"   [OK] {expected}")
        else:
            print(f"   [X] {expected} MISSING!")
            all_present = False

    # Get tools description (what VIF sees)
    print("\n5. System prompt preview (first 500 chars):")
    tools_desc = mcp_manager.get_tools_description()
    print(tools_desc[:500])
    print(f"\n   Total prompt size: {len(tools_desc)} characters")

    # Status summary
    print("\n" + "=" * 60)
    if all_present and len(mcp_manager.servers) >= 11:
        print("[OK] SUCCESS: All MCP servers are accessible to VIF!")
        print(f"   - {len(mcp_manager.servers)} servers active")
        print(f"   - {len(mcp_manager.list_all_tools())} tools available")
        return 0
    else:
        print("[!] WARNING: Some servers are missing!")
        return 1

if __name__ == '__main__':
    sys.exit(test_mcp_access())

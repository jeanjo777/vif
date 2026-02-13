"""
Test script to verify all MCP servers are functioning correctly
"""
import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test that all MCP modules can be imported"""
    print("=" * 60)
    print("TESTING MCP IMPORTS")
    print("=" * 60)

    try:
        from mcp import MCPManager
        print("[OK] MCPManager import successful")
    except Exception as e:
        print(f"[FAIL] MCPManager import failed: {e}")
        return False

    try:
        from mcp import WebBrowserMCP
        print("[OK] WebBrowserMCP import successful")
    except Exception as e:
        print(f"[FAIL] WebBrowserMCP import failed: {e}")

    try:
        from mcp import FileSystemMCP
        print("[OK] FileSystemMCP import successful")
    except Exception as e:
        print(f"[FAIL] FileSystemMCP import failed: {e}")

    try:
        from mcp import DatabaseMCP
        print("[OK] DatabaseMCP import successful")
    except Exception as e:
        print(f"[FAIL] DatabaseMCP import failed: {e}")

    try:
        from mcp import CodeExecutionMCP
        print("[OK] CodeExecutionMCP import successful")
    except Exception as e:
        print(f"[FAIL] CodeExecutionMCP import failed: {e}")

    try:
        from mcp import ExternalAPIsMCP
        print("[OK] ExternalAPIsMCP import successful")
    except Exception as e:
        print(f"[FAIL] ExternalAPIsMCP import failed: {e}")

    try:
        from mcp import MemorySystemMCP
        print("[OK] MemorySystemMCP import successful")
    except Exception as e:
        print(f"[FAIL] MemorySystemMCP import failed: {e}")

    return True

def test_server_initialization():
    """Test that MCP servers can be initialized"""
    print("\n" + "=" * 60)
    print("TESTING MCP SERVER INITIALIZATION")
    print("=" * 60)

    from mcp import WebBrowserMCP, FileSystemMCP, CodeExecutionMCP, ExternalAPIsMCP

    # Test Web Browser
    try:
        web_browser = WebBrowserMCP()
        tools = web_browser.list_tools()
        print(f"[OK] WebBrowserMCP initialized with {len(tools)} tools")
        for tool in tools:
            print(f"     - {tool['name']}: {tool['description']}")
    except Exception as e:
        print(f"[FAIL] WebBrowserMCP initialization failed: {e}")

    # Test File System
    try:
        file_system = FileSystemMCP()
        tools = file_system.list_tools()
        print(f"[OK] FileSystemMCP initialized with {len(tools)} tools")
        for tool in tools:
            print(f"     - {tool['name']}: {tool['description']}")
    except Exception as e:
        print(f"[FAIL] FileSystemMCP initialization failed: {e}")

    # Test Code Execution
    try:
        code_exec = CodeExecutionMCP()
        tools = code_exec.list_tools()
        print(f"[OK] CodeExecutionMCP initialized with {len(tools)} tools")
        for tool in tools:
            print(f"     - {tool['name']}: {tool['description']}")
    except Exception as e:
        print(f"[FAIL] CodeExecutionMCP initialization failed: {e}")

    # Test External APIs
    try:
        external_apis = ExternalAPIsMCP()
        tools = external_apis.list_tools()
        print(f"[OK] ExternalAPIsMCP initialized with {len(tools)} tools")
        for tool in tools:
            print(f"     - {tool['name']}: {tool['description']}")
    except Exception as e:
        print(f"[FAIL] ExternalAPIsMCP initialization failed: {e}")

def test_tool_execution():
    """Test actual tool execution"""
    print("\n" + "=" * 60)
    print("TESTING MCP TOOL EXECUTION")
    print("=" * 60)

    from mcp import CodeExecutionMCP, ExternalAPIsMCP

    # Test Python execution
    try:
        code_exec = CodeExecutionMCP()
        result = code_exec.execute_tool("execute_python", code="print('Hello from MCP!')")
        if result.get('success'):
            print("[OK] Code execution test passed")
            print(f"     Output: {result['result']['stdout'].strip()}")
        else:
            print(f"[FAIL] Code execution failed: {result.get('error')}")
    except Exception as e:
        print(f"[FAIL] Code execution test error: {e}")

    # Test External API (time)
    try:
        external_apis = ExternalAPIsMCP()
        result = external_apis.execute_tool("get_time", timezone="UTC")
        if result.get('success'):
            print("[OK] External API test passed (UTC time)")
            print(f"     Time: {result['result'].get('datetime', 'N/A')}")
        else:
            print(f"[FAIL] External API failed: {result.get('error')}")
    except Exception as e:
        print(f"[FAIL] External API test error: {e}")

def test_dependencies():
    """Test that all required dependencies are installed"""
    print("\n" + "=" * 60)
    print("TESTING DEPENDENCIES")
    print("=" * 60)

    dependencies = [
        'requests',
        'psycopg2',
        'bs4',  # BeautifulSoup
    ]

    for dep in dependencies:
        try:
            __import__(dep)
            print(f"[OK] {dep} is installed")
        except ImportError:
            print(f"[FAIL] {dep} is NOT installed")

def main():
    """Run all tests"""
    print("\n")
    print("*" * 60)
    print(" VIF MCP SYSTEM VERIFICATION")
    print("*" * 60)
    print("\n")

    # Run tests
    test_imports()
    test_dependencies()
    test_server_initialization()
    test_tool_execution()

    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print("All critical tests completed!")
    print("Check output above for any [FAIL] indicators.")
    print("\n")

if __name__ == "__main__":
    main()

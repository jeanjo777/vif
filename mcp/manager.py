"""
MCP Manager - Central orchestrator for all MCP servers
"""
from typing import Dict, List, Any, Optional
from .web_browser import WebBrowserMCP
from .file_system import FileSystemMCP
from .database import DatabaseMCP
from .code_execution import CodeExecutionMCP
from .external_apis import ExternalAPIsMCP
from .memory_system import MemorySystemMCP
import json


class MCPManager:
    """
    Central manager for all MCP servers
    Handles tool discovery, routing, and execution
    """

    def __init__(self, db_pool, workspace_path: str = "/tmp/vif_workspace"):
        self.servers = {}
        self.db_pool = db_pool

        # Initialize all MCP servers
        self._init_servers(workspace_path)

    def _init_servers(self, workspace_path: str):
        """Initialize all MCP servers"""
        try:
            self.servers['web_browser'] = WebBrowserMCP()
            print("✅ MCP Web Browser initialized")
        except Exception as e:
            print(f"❌ Failed to initialize Web Browser MCP: {e}")

        try:
            self.servers['file_system'] = FileSystemMCP(workspace_path)
            print("✅ MCP File System initialized")
        except Exception as e:
            print(f"❌ Failed to initialize File System MCP: {e}")

        try:
            if self.db_pool:
                self.servers['database'] = DatabaseMCP(self.db_pool)
                print("✅ MCP Database initialized")
        except Exception as e:
            print(f"❌ Failed to initialize Database MCP: {e}")

        try:
            self.servers['code_execution'] = CodeExecutionMCP()
            print("✅ MCP Code Execution initialized")
        except Exception as e:
            print(f"❌ Failed to initialize Code Execution MCP: {e}")

        try:
            self.servers['external_apis'] = ExternalAPIsMCP()
            print("✅ MCP External APIs initialized")
        except Exception as e:
            print(f"❌ Failed to initialize External APIs MCP: {e}")

        try:
            if self.db_pool:
                self.servers['memory_system'] = MemorySystemMCP(self.db_pool)
                print("✅ MCP Memory System initialized")
        except Exception as e:
            print(f"❌ Failed to initialize Memory System MCP: {e}")

    def list_all_tools(self) -> List[Dict]:
        """List all available tools across all servers"""
        all_tools = []

        for server_name, server in self.servers.items():
            if server.enabled:
                for tool in server.list_tools():
                    tool_info = tool.copy()
                    tool_info['server'] = server_name
                    tool_info['full_name'] = f"{server_name}.{tool['name']}"
                    all_tools.append(tool_info)

        return all_tools

    def get_tools_description(self) -> str:
        """Get formatted description of all tools for LLM"""
        tools = self.list_all_tools()

        description = "=== AVAILABLE MCP TOOLS ===\n\n"
        description += f"You have access to {len(tools)} powerful tools across {len(self.servers)} servers:\n\n"

        for server_name, server in self.servers.items():
            if server.enabled:
                description += f"[{server_name.upper()}] {server.description}\n"
                for tool in server.list_tools():
                    description += f"  • {tool['name']}: {tool['description']}\n"
                description += "\n"

        description += "TO USE A TOOL, respond with JSON in this format:\n"
        description += "```json\n"
        description += '{\n'
        description += '  "mcp_call": true,\n'
        description += '  "server": "server_name",\n'
        description += '  "tool": "tool_name",\n'
        description += '  "parameters": {...}\n'
        description += '}\n'
        description += "```\n"

        return description

    def execute_tool(self, server_name: str, tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool on a specific server"""
        server = self.servers.get(server_name)

        if not server:
            return {
                "success": False,
                "error": f"MCP Server '{server_name}' not found"
            }

        result = server.execute_tool(tool_name, **parameters)

        # Add execution metadata
        result['mcp_server'] = server_name
        result['mcp_tool'] = tool_name

        return result

    def parse_and_execute(self, llm_response: str) -> Optional[Dict[str, Any]]:
        """
        Parse LLM response and execute MCP call if present
        Returns None if no MCP call found, or execution result
        """
        try:
            # Try to find JSON block
            if '```json' in llm_response:
                start = llm_response.find('```json') + 7
                end = llm_response.find('```', start)
                json_str = llm_response[start:end].strip()
            elif '{' in llm_response and '}' in llm_response:
                # Try to extract JSON directly
                start = llm_response.find('{')
                end = llm_response.rfind('}') + 1
                json_str = llm_response[start:end]
            else:
                return None

            data = json.loads(json_str)

            # Check if it's an MCP call
            if not data.get('mcp_call'):
                return None

            server = data.get('server')
            tool = data.get('tool')
            parameters = data.get('parameters', {})

            if not server or not tool:
                return {
                    "success": False,
                    "error": "Invalid MCP call: missing server or tool"
                }

            return self.execute_tool(server, tool, parameters)

        except json.JSONDecodeError:
            return None
        except Exception as e:
            return {
                "success": False,
                "error": f"MCP execution error: {str(e)}"
            }

    def get_server(self, name: str):
        """Get a specific MCP server"""
        return self.servers.get(name)

    def enable_server(self, name: str):
        """Enable a specific server"""
        server = self.servers.get(name)
        if server:
            server.enabled = True

    def disable_server(self, name: str):
        """Disable a specific server"""
        server = self.servers.get(name)
        if server:
            server.enabled = False

    def get_status(self) -> Dict[str, Any]:
        """Get status of all MCP servers"""
        return {
            "servers": {
                name: {
                    "enabled": server.enabled,
                    "tools_count": len(server.tools)
                }
                for name, server in self.servers.items()
            },
            "total_tools": len(self.list_all_tools())
        }

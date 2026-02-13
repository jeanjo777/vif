"""
Base classes for MCP (Model Context Protocol) system
"""
from typing import Dict, List, Any, Optional, Callable
import json
from datetime import datetime


class MCPTool:
    """Represents a single MCP tool/function"""

    def __init__(self, name: str, description: str, parameters: Dict, handler: Callable):
        self.name = name
        self.description = description
        self.parameters = parameters
        self.handler = handler

    def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute the tool with given parameters"""
        try:
            result = self.handler(**kwargs)
            return {
                "success": True,
                "result": result,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }

    def to_dict(self) -> Dict:
        """Convert tool to dictionary format for LLM"""
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters
        }


class MCPServer:
    """Base class for all MCP servers"""

    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.tools: Dict[str, MCPTool] = {}
        self.enabled = True

    def register_tool(self, tool: MCPTool):
        """Register a new tool"""
        self.tools[tool.name] = tool

    def get_tool(self, name: str) -> Optional[MCPTool]:
        """Get a tool by name"""
        return self.tools.get(name)

    def list_tools(self) -> List[Dict]:
        """List all available tools"""
        return [tool.to_dict() for tool in self.tools.values()]

    def execute_tool(self, tool_name: str, **kwargs) -> Dict[str, Any]:
        """Execute a specific tool"""
        tool = self.get_tool(tool_name)
        if not tool:
            return {
                "success": False,
                "error": f"Tool '{tool_name}' not found in server '{self.name}'"
            }

        if not self.enabled:
            return {
                "success": False,
                "error": f"MCP Server '{self.name}' is disabled"
            }

        return tool.execute(**kwargs)

    def to_dict(self) -> Dict:
        """Convert server to dictionary format"""
        return {
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "tools": self.list_tools()
        }

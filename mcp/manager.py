"""
MCP Manager - Central orchestrator for all MCP servers
Enhanced with caching, agents, and 14 MCP servers
"""
from typing import Dict, List, Any, Optional
import json
import os

# Original MCP Servers
from .web_browser import WebBrowserMCP
from .file_system import FileSystemMCP
from .database import DatabaseMCP
from .code_execution import CodeExecutionMCP
from .external_apis import ExternalAPIsMCP
from .memory_system import MemorySystemMCP

# New Advanced MCP Servers
from .vision import VisionMCP
from .video import VideoMCP
from .security import SecurityMCP
from .devtools import DevToolsMCP
from .data_science import DataScienceMCP
from .creative import CreativeMCP
from .integration_hub import IntegrationHubMCP
from .rag_memory import RAGMemoryMCP

# Performance & Intelligence
from .cache import MCPCache, ParallelExecutor
from .agents import AgentOrchestrator


class MCPManager:
    """
    Central manager for all MCP servers
    Handles tool discovery, routing, execution, caching, and agents
    """

    def __init__(self, db_pool=None, workspace_path: str = "/tmp/vif_workspace"):
        self.servers = {}
        self.db_pool = db_pool
        self.workspace_path = workspace_path

        # Initialize cache and performance tools
        self.cache = MCPCache(max_size=1000, default_ttl=3600)
        self.parallel_executor = None  # Will be initialized after servers

        # Initialize agents
        self.agents = None  # Will be initialized after servers

        # Initialize all MCP servers (skip DB-dependent ones if no db_pool)
        self._init_servers()

        # Initialize agent orchestrator
        self.agents = AgentOrchestrator(self)
        self.parallel_executor = ParallelExecutor(self)

        mode = "full" if db_pool else "fallback (no DB)"
        print(f"[OK] MCP Manager initialized [{mode}]: {len(self.servers)} servers, {len(self.list_all_tools())} tools", flush=True)

    def _init_servers(self):
        """Initialize all MCP servers"""
        # Original servers
        self._init_server('web_browser', lambda: WebBrowserMCP())
        self._init_server('file_system', lambda: FileSystemMCP(self.workspace_path))
        self._init_server('code_execution', lambda: CodeExecutionMCP())
        self._init_server('external_apis', lambda: ExternalAPIsMCP())

        # Database-dependent servers
        if self.db_pool:
            self._init_server('database', lambda: DatabaseMCP(self.db_pool))
            self._init_server('memory_system', lambda: MemorySystemMCP(self.db_pool))
            self._init_server('rag_memory', lambda: RAGMemoryMCP(self.db_pool))

        # New advanced servers
        self._init_server('vision', lambda: VisionMCP())
        self._init_server('video', lambda: VideoMCP())
        self._init_server('security', lambda: SecurityMCP())
        self._init_server('devtools', lambda: DevToolsMCP(self.workspace_path))
        self._init_server('data_science', lambda: DataScienceMCP())
        self._init_server('creative', lambda: CreativeMCP())
        self._init_server('integration_hub', lambda: IntegrationHubMCP())

    def _init_server(self, name: str, initializer):
        """Initialize a single server with error handling"""
        try:
            self.servers[name] = initializer()
            print(f"OK: MCP {name} initialized")
        except Exception as e:
            print(f"Failed to initialize {name} MCP: {e}")

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

    def get_tools_description(self, agent_type: str = None) -> str:
        """Get formatted description of all tools for LLM"""
        tools = self.list_all_tools()

        # If agent specified, get agent-specific prompt
        if agent_type and self.agents:
            agent = self.agents.get_agent(agent_type)
            if agent:
                return agent.get_system_prompt()

        # Detailed format with parameters so the LLM knows exact call format
        server_lines = []
        for server_name, server in self.servers.items():
            if server.enabled:
                tool_entries = []
                for t in server.list_tools():
                    params = t.get('parameters', {})
                    if params:
                        param_str = ", ".join(f'{k}' for k in params.keys())
                        tool_entries.append(f"{t['name']}({param_str})")
                    else:
                        tool_entries.append(t['name'])
                server_lines.append(f"  {server_name}: {', '.join(tool_entries)}")

        description = f"MCP TOOLS ({len(tools)} available):\n" + "\n".join(server_lines)
        description += """

TOOL CALL EXAMPLES (copy the format exactly):
Web search: {"mcp_call":true,"server":"web_browser","tool":"web_search","parameters":{"query":"search terms"}}
Browse URL: {"mcp_call":true,"server":"web_browser","tool":"navigate","parameters":{"url":"https://example.com"}}
Run Python: {"mcp_call":true,"server":"code_execution","tool":"execute_python","parameters":{"code":"print('hello')"}}
List files: {"mcp_call":true,"server":"file_system","tool":"list_directory","parameters":{"path":"."}}
Read file: {"mcp_call":true,"server":"file_system","tool":"read_file","parameters":{"path":"file.txt"}}
Scan ports: {"mcp_call":true,"server":"security","tool":"scan_ports","parameters":{"target":"example.com","ports":"1-1000"}}
SSL check: {"mcp_call":true,"server":"security","tool":"check_ssl_security","parameters":{"domain":"example.com"}}
Domain lookup: {"mcp_call":true,"server":"security","tool":"domain_lookup","parameters":{"domain":"example.com"}}
Password test: {"mcp_call":true,"server":"security","tool":"password_strength_check","parameters":{"password":"test123"}}
Analyze image: {"mcp_call":true,"server":"vision","tool":"analyze_image","parameters":{"image_url":"https://example.com/img.jpg"}}
Weather: {"mcp_call":true,"server":"external_apis","tool":"get_weather","parameters":{"city":"Paris"}}
Crypto price: {"mcp_call":true,"server":"external_apis","tool":"get_crypto_price","parameters":{"symbol":"BTC"}}
Get time: {"mcp_call":true,"server":"external_apis","tool":"get_time","parameters":{"timezone":"Asia/Tokyo"}}
Store memory: {"mcp_call":true,"server":"memory_system","tool":"store_memory","parameters":{"key":"preference","value":"likes red"}}
List memories: {"mcp_call":true,"server":"memory_system","tool":"list_memories","parameters":{}}
DB user stats: {"mcp_call":true,"server":"database","tool":"get_user_stats","parameters":{}}
Generate image: {"mcp_call":true,"server":"creative","tool":"generate_image","parameters":{"prompt":"a black cat with orange eyes"}}
TTS: {"mcp_call":true,"server":"creative","tool":"text_to_speech","parameters":{"text":"Hello world","language":"fr"}}
Video info: {"mcp_call":true,"server":"video","tool":"video_info","parameters":{"url":"https://example.com/video.mp4"}}
Code analysis: {"mcp_call":true,"server":"devtools","tool":"code_analysis","parameters":{"path":"file.py"}}
Chart: {"mcp_call":true,"server":"data_science","tool":"create_chart","parameters":{"chart_type":"bar","data":{"labels":["A","B"],"values":[10,20]}}}
Discord: {"mcp_call":true,"server":"integration_hub","tool":"discord_webhook","parameters":{"webhook_url":"URL","message":"Hello"}}
Email: {"mcp_call":true,"server":"integration_hub","tool":"send_email","parameters":{"to":"user@example.com","subject":"Test","body":"Hello"}}
Translate: {"mcp_call":true,"server":"external_apis","tool":"translate","parameters":{"text":"hello","target_lang":"fr"}}
News: {"mcp_call":true,"server":"external_apis","tool":"get_news","parameters":{"query":"technology"}}
RAG search: {"mcp_call":true,"server":"rag_memory","tool":"semantic_search","parameters":{"query":"search terms"}}
Summarize: {"mcp_call":true,"server":"rag_memory","tool":"summarize_conversation","parameters":{"session_id":"current"}}

REMEMBER: Output ONLY the JSON when using a tool. No text before or after."""
        return description

    def execute_tool(self, server_name: str, tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool on a specific server with caching"""
        # Check cache first
        cached_result = self.cache.get(server_name, tool_name, parameters)
        if cached_result:
            cached_result['cached'] = True
            return cached_result

        # Get server
        server = self.servers.get(server_name)

        if not server:
            return {
                "success": False,
                "error": f"MCP Server '{server_name}' not found"
            }

        # Execute tool
        result = server.execute_tool(tool_name, **parameters)

        # Add execution metadata
        result['mcp_server'] = server_name
        result['mcp_tool'] = tool_name
        result['cached'] = False

        # Cache result if successful
        if result.get('success', True):  # Default to True if success key not present
            self.cache.set(server_name, tool_name, parameters, result)

        return result

    def execute_parallel(self, tool_calls: List[Dict]) -> Dict[str, Any]:
        """Execute multiple tools in parallel"""
        return self.parallel_executor.execute_parallel(tool_calls)

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
            "total_tools": len(self.list_all_tools()),
            "total_servers": len(self.servers),
            "cache_stats": self.cache.get_stats(),
            "agents_available": len(self.agents.agents) if self.agents else 0
        }

    def get_agent(self, agent_type: str):
        """Get specialized agent"""
        if self.agents:
            return self.agents.get_agent(agent_type)
        return None

    def execute_with_agent(self, agent_type: str, task: str):
        """Execute task with specialized agent"""
        if self.agents:
            return self.agents.execute_with_agent(agent_type, task)
        return {"error": "Agents not initialized"}

    def clear_cache(self, server: Optional[str] = None):
        """Clear cache"""
        return self.cache.clear(server)

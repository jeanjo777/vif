"""
Vif MCP (Model Context Protocol) System
Provides external tools and capabilities to AI models

Features:
- 14 MCP Servers with 85+ tools
- Vision & Multimodal AI
- Video generation & editing
- Cybersecurity & pentesting
- DevTools automation
- Data Science & ML
- Creative generation
- External integrations
- RAG memory system
- Intelligent caching
- Specialized agents
"""

# Base classes
from .base import MCPServer, MCPTool

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
from .agents import (
    AgentOrchestrator,
    CodeAgent,
    DataAgent,
    ResearchAgent,
    SecurityAgent,
    DesignAgent
)

# Manager
from .manager import MCPManager

__all__ = [
    # Base
    'MCPServer',
    'MCPTool',

    # Original Servers
    'WebBrowserMCP',
    'FileSystemMCP',
    'DatabaseMCP',
    'CodeExecutionMCP',
    'ExternalAPIsMCP',
    'MemorySystemMCP',

    # New Servers
    'VisionMCP',
    'VideoMCP',
    'SecurityMCP',
    'DevToolsMCP',
    'DataScienceMCP',
    'CreativeMCP',
    'IntegrationHubMCP',
    'RAGMemoryMCP',

    # Performance
    'MCPCache',
    'ParallelExecutor',

    # Agents
    'AgentOrchestrator',
    'CodeAgent',
    'DataAgent',
    'ResearchAgent',
    'SecurityAgent',
    'DesignAgent',

    # Manager
    'MCPManager'
]

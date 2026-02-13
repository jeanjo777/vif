"""
MCP Specialized Agents - Expert agents for different domains
"""
from typing import Dict, Any, List
import json


class SpecializedAgent:
    """Base class for specialized agents"""

    def __init__(self, name: str, description: str, tools: List[str], expertise: str):
        self.name = name
        self.description = description
        self.tools = tools  # List of (server, tool) tuples
        self.expertise = expertise

    def get_system_prompt(self) -> str:
        """Get agent-specific system prompt"""
        return f"""You are {self.name}, a specialized AI agent.

{self.description}

Expertise: {self.expertise}

You have access to these specialized tools:
{self._format_tools()}

When solving tasks in your domain:
1. Use your specialized tools effectively
2. Provide expert-level solutions
3. Explain your reasoning clearly
4. Suggest best practices
"""

    def _format_tools(self) -> str:
        """Format tool list"""
        tool_list = []
        for server, tool in self.tools:
            tool_list.append(f"- {server}.{tool}")
        return "\n".join(tool_list)


class CodeAgent(SpecializedAgent):
    """Expert in software development and coding"""

    def __init__(self):
        super().__init__(
            name="CodeAgent",
            description="Expert software development agent specializing in coding, debugging, testing, and deployment",
            tools=[
                ("devtools", "git_operation"),
                ("devtools", "docker_operation"),
                ("devtools", "run_tests"),
                ("devtools", "code_analysis"),
                ("devtools", "package_manager"),
                ("code_execution", "execute_python"),
                ("file_system", "read_file"),
                ("file_system", "write_file"),
                ("web_browser", "navigate"),
            ],
            expertise="Programming, debugging, testing, CI/CD, code review, software architecture"
        )


class DataAgent(SpecializedAgent):
    """Expert in data analysis and machine learning"""

    def __init__(self):
        super().__init__(
            name="DataAgent",
            description="Expert data science agent specializing in analysis, visualization, and machine learning",
            tools=[
                ("data_science", "analyze_csv"),
                ("data_science", "create_chart"),
                ("data_science", "ml_predict"),
                ("data_science", "sql_query_builder"),
                ("database", "query"),
                ("code_execution", "execute_python"),
                ("file_system", "read_file"),
            ],
            expertise="Data analysis, statistics, machine learning, data visualization, SQL"
        )


class ResearchAgent(SpecializedAgent):
    """Expert in web research and information gathering"""

    def __init__(self):
        super().__init__(
            name="ResearchAgent",
            description="Expert research agent specializing in web browsing, information extraction, and analysis",
            tools=[
                ("web_browser", "navigate"),
                ("web_browser", "extract_links"),
                ("web_browser", "search_page"),
                ("external_apis", "get_news"),
                ("external_apis", "translate"),
                ("rag_memory", "store_with_embedding"),
                ("rag_memory", "semantic_search"),
            ],
            expertise="Web research, fact-checking, information synthesis, content analysis"
        )


class SecurityAgent(SpecializedAgent):
    """Expert in security and code analysis"""

    def __init__(self):
        super().__init__(
            name="SecurityAgent",
            description="Expert security agent specializing in code analysis, vulnerability detection, and security best practices",
            tools=[
                ("devtools", "code_analysis"),
                ("database", "query"),
                ("file_system", "read_file"),
                ("code_execution", "execute_python"),
            ],
            expertise="Security auditing, vulnerability scanning, penetration testing, secure coding"
        )


class DesignAgent(SpecializedAgent):
    """Expert in UI/UX design and creative work"""

    def __init__(self):
        super().__init__(
            name="DesignAgent",
            description="Expert design agent specializing in UI/UX, visual design, and creative content",
            tools=[
                ("vision", "analyze_image"),
                ("vision", "screenshot_analysis"),
                ("vision", "generate_diagram"),
                ("creative", "generate_image"),
                ("creative", "edit_image"),
                ("data_science", "create_chart"),
            ],
            expertise="UI/UX design, visual design, accessibility, user experience, creative direction"
        )


class AgentOrchestrator:
    """Orchestrate specialized agents for complex tasks"""

    def __init__(self, mcp_manager):
        self.mcp_manager = mcp_manager
        self.agents = {
            "code": CodeAgent(),
            "data": DataAgent(),
            "research": ResearchAgent(),
            "security": SecurityAgent(),
            "design": DesignAgent()
        }

    def get_agent(self, agent_type: str) -> SpecializedAgent:
        """Get specific agent"""
        return self.agents.get(agent_type)

    def list_agents(self) -> List[Dict[str, Any]]:
        """List all available agents"""
        return [
            {
                "type": agent_type,
                "name": agent.name,
                "description": agent.description,
                "expertise": agent.expertise,
                "tool_count": len(agent.tools)
            }
            for agent_type, agent in self.agents.items()
        ]

    def select_agent(self, task_description: str) -> str:
        """Auto-select best agent for task"""
        task_lower = task_description.lower()

        # Keyword matching for agent selection
        agent_keywords = {
            "code": ["code", "program", "debug", "deploy", "git", "test", "function", "api"],
            "data": ["data", "analyze", "csv", "chart", "ml", "predict", "sql", "statistics"],
            "research": ["search", "research", "find", "web", "article", "information"],
            "security": ["security", "vulnerability", "audit", "scan", "password", "encryption"],
            "design": ["design", "ui", "ux", "image", "screenshot", "diagram", "visual"]
        }

        scores = {}
        for agent_type, keywords in agent_keywords.items():
            score = sum(1 for keyword in keywords if keyword in task_lower)
            scores[agent_type] = score

        # Return agent with highest score
        best_agent = max(scores.items(), key=lambda x: x[1])

        if best_agent[1] > 0:
            return best_agent[0]

        # Default to code agent
        return "code"

    def execute_with_agent(self, agent_type: str, task: str,
                          tools_to_use: List[Dict] = None) -> Dict[str, Any]:
        """Execute task with specific agent"""
        agent = self.get_agent(agent_type)

        if not agent:
            return {"error": f"Unknown agent type: {agent_type}"}

        # Build enhanced prompt with agent expertise
        enhanced_prompt = f"""{agent.get_system_prompt()}

TASK: {task}

Please solve this task using your specialized tools and expertise.
"""

        return {
            "agent": agent.name,
            "agent_type": agent_type,
            "task": task,
            "system_prompt": enhanced_prompt,
            "available_tools": [f"{s}.{t}" for s, t in agent.tools]
        }

    def collaborative_execution(self, task: str,
                               agents: List[str] = None) -> Dict[str, Any]:
        """Execute task with multiple agents collaborating"""
        if not agents:
            # Auto-select agents
            primary_agent = self.select_agent(task)
            agents = [primary_agent]

        results = {}

        for agent_type in agents:
            agent = self.get_agent(agent_type)
            if agent:
                results[agent_type] = {
                    "agent": agent.name,
                    "expertise": agent.expertise,
                    "tools": [f"{s}.{t}" for s, t in agent.tools]
                }

        return {
            "task": task,
            "agents": results,
            "collaboration_mode": "sequential" if len(agents) == 1 else "collaborative"
        }

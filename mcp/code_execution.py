"""
MCP Code Execution - Safe Python code execution
"""
from .base import MCPServer, MCPTool
from typing import Dict, Any
import subprocess
import tempfile
import os
import sys
from pathlib import Path


class CodeExecutionMCP(MCPServer):
    """Code Execution MCP Server - Execute Python code safely"""

    def __init__(self, timeout: int = 30):
        super().__init__(
            name="code_execution",
            description="Execute Python code safely in an isolated environment"
        )
        self.timeout = timeout
        self.workspace = Path(tempfile.gettempdir()) / "vif_code_exec"
        self.workspace.mkdir(parents=True, exist_ok=True)
        self._init_tools()

    def _init_tools(self):
        """Initialize all code execution tools"""

        # Tool 1: Execute Python code
        self.register_tool(MCPTool(
            name="execute_python",
            description="Execute Python code and return output",
            parameters={
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": "Python code to execute"
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Execution timeout in seconds (default: 30)",
                        "default": 30
                    }
                },
                "required": ["code"]
            },
            handler=self._execute_python
        ))

        # Tool 2: Install package
        self.register_tool(MCPTool(
            name="install_package",
            description="Install a Python package using pip",
            parameters={
                "type": "object",
                "properties": {
                    "package": {
                        "type": "string",
                        "description": "Package name to install"
                    },
                    "version": {
                        "type": "string",
                        "description": "Optional specific version"
                    }
                },
                "required": ["package"]
            },
            handler=self._install_package
        ))

        # Tool 3: List installed packages
        self.register_tool(MCPTool(
            name="list_packages",
            description="List all installed Python packages",
            parameters={"type": "object", "properties": {}},
            handler=self._list_packages
        ))

    def _execute_python(self, code: str, timeout: int = None) -> Dict[str, Any]:
        """Execute Python code safely"""
        if timeout is None:
            timeout = self.timeout

        try:
            # Create temporary file for code
            with tempfile.NamedTemporaryFile(
                mode='w',
                suffix='.py',
                dir=self.workspace,
                delete=False
            ) as f:
                f.write(code)
                temp_file = f.name

            try:
                # Execute code in subprocess
                result = subprocess.run(
                    [sys.executable, temp_file],
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    cwd=self.workspace
                )

                return {
                    "success": result.returncode == 0,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "return_code": result.returncode
                }

            finally:
                # Cleanup temp file
                try:
                    os.unlink(temp_file)
                except:
                    pass

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": f"Execution timed out after {timeout} seconds"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def _install_package(self, package: str, version: str = None) -> Dict[str, Any]:
        """Install Python package"""
        try:
            package_spec = f"{package}=={version}" if version else package

            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", package_spec],
                capture_output=True,
                text=True,
                timeout=120
            )

            return {
                "success": result.returncode == 0,
                "package": package,
                "version": version,
                "output": result.stdout,
                "error": result.stderr if result.returncode != 0 else None
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Installation timed out after 120 seconds"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def _list_packages(self) -> Dict[str, Any]:
        """List installed packages"""
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "list", "--format=json"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                import json
                packages = json.loads(result.stdout)
                return {
                    "success": True,
                    "packages": packages,
                    "count": len(packages)
                }
            else:
                return {
                    "success": False,
                    "error": result.stderr
                }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

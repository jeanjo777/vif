"""
MCP DevTools - Development automation and tooling
"""
from .base import MCPServer, MCPTool
from typing import Dict, Any, List
import subprocess
import os
import json
from pathlib import Path


class DevToolsMCP(MCPServer):
    """DevTools MCP Server - Git, Docker, deployment, testing, code analysis"""

    def __init__(self, workspace_path: str = "/tmp/vif_workspace"):
        super().__init__(
            name="devtools",
            description="Development tools: Git operations, Docker management, deployment, testing, code analysis"
        )
        self.workspace = Path(workspace_path)
        self.workspace.mkdir(parents=True, exist_ok=True)
        self._init_tools()

    def _init_tools(self):
        """Initialize all devtools"""

        # Tool 1: Git operations
        self.register_tool(MCPTool(
            name="git_operation",
            description="Execute Git operations: status, commit, push, pull, branch, log, diff",
            parameters={
                "type": "object",
                "properties": {
                    "operation": {
                        "type": "string",
                        "description": "Git operation: status, add, commit, push, pull, branch, checkout, log, diff, clone",
                        "enum": ["status", "add", "commit", "push", "pull", "branch", "checkout", "log", "diff", "clone", "remote"]
                    },
                    "repository_path": {
                        "type": "string",
                        "description": "Path to git repository (default: current workspace)"
                    },
                    "message": {
                        "type": "string",
                        "description": "Commit message (for commit operation)"
                    },
                    "branch": {
                        "type": "string",
                        "description": "Branch name (for branch/checkout operations)"
                    },
                    "files": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Files to add (for add operation)"
                    },
                    "url": {
                        "type": "string",
                        "description": "Repository URL (for clone operation)"
                    },
                    "args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Additional arguments"
                    }
                },
                "required": ["operation"]
            },
            handler=self._git_operation
        ))

        # Tool 2: Docker operations
        self.register_tool(MCPTool(
            name="docker_operation",
            description="Manage Docker containers: build, run, stop, logs, ps, images",
            parameters={
                "type": "object",
                "properties": {
                    "operation": {
                        "type": "string",
                        "description": "Docker operation: build, run, stop, start, logs, ps, images, exec, compose",
                        "enum": ["build", "run", "stop", "start", "logs", "ps", "images", "exec", "compose", "rm", "pull"]
                    },
                    "image": {
                        "type": "string",
                        "description": "Docker image name"
                    },
                    "container": {
                        "type": "string",
                        "description": "Container ID or name"
                    },
                    "dockerfile_path": {
                        "type": "string",
                        "description": "Path to Dockerfile (for build)"
                    },
                    "command": {
                        "type": "string",
                        "description": "Command to execute (for run/exec)"
                    },
                    "args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Additional Docker arguments"
                    },
                    "compose_file": {
                        "type": "string",
                        "description": "Path to docker-compose.yml"
                    }
                },
                "required": ["operation"]
            },
            handler=self._docker_operation
        ))

        # Tool 3: Deploy to platform
        self.register_tool(MCPTool(
            name="deploy",
            description="Deploy to platforms: Railway, Vercel, Netlify, Heroku",
            parameters={
                "type": "object",
                "properties": {
                    "platform": {
                        "type": "string",
                        "description": "Deployment platform",
                        "enum": ["railway", "vercel", "netlify", "heroku"]
                    },
                    "project_path": {
                        "type": "string",
                        "description": "Path to project directory"
                    },
                    "environment": {
                        "type": "string",
                        "description": "Deployment environment: production, staging, development",
                        "enum": ["production", "staging", "development"],
                        "default": "production"
                    },
                    "config": {
                        "type": "object",
                        "description": "Additional deployment configuration"
                    }
                },
                "required": ["platform"]
            },
            handler=self._deploy
        ))

        # Tool 4: Run tests
        self.register_tool(MCPTool(
            name="run_tests",
            description="Run tests: pytest, jest, mocha, unittest, coverage",
            parameters={
                "type": "object",
                "properties": {
                    "test_framework": {
                        "type": "string",
                        "description": "Test framework to use",
                        "enum": ["pytest", "jest", "mocha", "unittest", "vitest", "auto"],
                        "default": "auto"
                    },
                    "project_path": {
                        "type": "string",
                        "description": "Path to project"
                    },
                    "test_path": {
                        "type": "string",
                        "description": "Specific test file or directory"
                    },
                    "coverage": {
                        "type": "boolean",
                        "description": "Generate coverage report",
                        "default": False
                    },
                    "verbose": {
                        "type": "boolean",
                        "description": "Verbose output",
                        "default": True
                    }
                }
            },
            handler=self._run_tests
        ))

        # Tool 5: Code analysis
        self.register_tool(MCPTool(
            name="code_analysis",
            description="Analyze code: linting, security scan, complexity, dependencies",
            parameters={
                "type": "object",
                "properties": {
                    "analysis_type": {
                        "type": "string",
                        "description": "Type of analysis",
                        "enum": ["lint", "security", "complexity", "dependencies", "format", "all"],
                        "default": "all"
                    },
                    "project_path": {
                        "type": "string",
                        "description": "Path to project"
                    },
                    "language": {
                        "type": "string",
                        "description": "Programming language",
                        "enum": ["python", "javascript", "typescript", "auto"],
                        "default": "auto"
                    },
                    "fix": {
                        "type": "boolean",
                        "description": "Auto-fix issues if possible",
                        "default": False
                    }
                }
            },
            handler=self._code_analysis
        ))

        # Tool 6: Package manager operations
        self.register_tool(MCPTool(
            name="package_manager",
            description="Manage packages: npm, pip, yarn, pnpm install/update/remove",
            parameters={
                "type": "object",
                "properties": {
                    "manager": {
                        "type": "string",
                        "description": "Package manager",
                        "enum": ["npm", "pip", "yarn", "pnpm", "auto"],
                        "default": "auto"
                    },
                    "operation": {
                        "type": "string",
                        "description": "Operation: install, update, remove, list",
                        "enum": ["install", "update", "remove", "list", "outdated"]
                    },
                    "packages": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Package names"
                    },
                    "project_path": {
                        "type": "string",
                        "description": "Path to project"
                    },
                    "dev": {
                        "type": "boolean",
                        "description": "Install as dev dependency",
                        "default": False
                    }
                },
                "required": ["operation"]
            },
            handler=self._package_manager
        ))

    def _execute_command(self, command: List[str], cwd: str = None, timeout: int = 60) -> Dict[str, Any]:
        """Execute shell command safely"""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd or str(self.workspace)
            )

            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": f"Command timed out after {timeout} seconds"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def _git_operation(self, operation: str, repository_path: str = None,
                      message: str = None, branch: str = None,
                      files: List[str] = None, url: str = None,
                      args: List[str] = None) -> Dict[str, Any]:
        """Execute Git operation"""
        try:
            repo_path = repository_path or str(self.workspace)
            args = args or []

            commands = {
                "status": ["git", "status"] + args,
                "add": ["git", "add"] + (files or ["."]),
                "commit": ["git", "commit", "-m", message or "Update"] + args,
                "push": ["git", "push"] + args,
                "pull": ["git", "pull"] + args,
                "branch": ["git", "branch"] + ([branch] if branch else []) + args,
                "checkout": ["git", "checkout", branch] + args if branch else None,
                "log": ["git", "log", "--oneline", "-10"] + args,
                "diff": ["git", "diff"] + args,
                "clone": ["git", "clone", url, repo_path] if url else None,
                "remote": ["git", "remote", "-v"] + args
            }

            command = commands.get(operation)
            if not command:
                return {"error": f"Unknown Git operation: {operation}"}

            result = self._execute_command(command, cwd=repo_path, timeout=120)

            return {
                "operation": operation,
                **result
            }

        except Exception as e:
            return {"error": str(e)}

    def _docker_operation(self, operation: str, image: str = None,
                         container: str = None, dockerfile_path: str = None,
                         command: str = None, args: List[str] = None,
                         compose_file: str = None) -> Dict[str, Any]:
        """Execute Docker operation"""
        try:
            args = args or []

            commands = {
                "build": ["docker", "build", "-t", image, dockerfile_path or "."] + args if image else None,
                "run": ["docker", "run"] + args + [image] + ([command] if command else []) if image else None,
                "stop": ["docker", "stop", container] if container else None,
                "start": ["docker", "start", container] if container else None,
                "logs": ["docker", "logs"] + args + [container] if container else None,
                "ps": ["docker", "ps"] + args,
                "images": ["docker", "images"] + args,
                "exec": ["docker", "exec", container] + ([command] if command else []) if container else None,
                "compose": ["docker-compose", "-f", compose_file or "docker-compose.yml"] + args,
                "rm": ["docker", "rm", container] if container else None,
                "pull": ["docker", "pull", image] if image else None
            }

            cmd = commands.get(operation)
            if not cmd:
                return {"error": f"Unknown Docker operation: {operation}"}

            result = self._execute_command(cmd, timeout=180)

            return {
                "operation": operation,
                **result
            }

        except Exception as e:
            return {"error": str(e)}

    def _deploy(self, platform: str, project_path: str = None,
               environment: str = "production", config: Dict = None) -> Dict[str, Any]:
        """Deploy to platform"""
        try:
            proj_path = project_path or str(self.workspace)
            config = config or {}

            if platform == "railway":
                # Railway CLI deployment
                result = self._execute_command(
                    ["railway", "up", "-e", environment],
                    cwd=proj_path,
                    timeout=300
                )

            elif platform == "vercel":
                # Vercel CLI deployment
                prod_flag = ["--prod"] if environment == "production" else []
                result = self._execute_command(
                    ["vercel"] + prod_flag,
                    cwd=proj_path,
                    timeout=300
                )

            elif platform == "netlify":
                # Netlify CLI deployment
                prod_flag = ["--prod"] if environment == "production" else []
                result = self._execute_command(
                    ["netlify", "deploy"] + prod_flag,
                    cwd=proj_path,
                    timeout=300
                )

            elif platform == "heroku":
                # Heroku deployment
                app_name = config.get("app_name")
                cmd = ["git", "push", "heroku", "main"]
                result = self._execute_command(cmd, cwd=proj_path, timeout=300)

            else:
                return {"error": f"Unknown platform: {platform}"}

            return {
                "platform": platform,
                "environment": environment,
                **result
            }

        except Exception as e:
            return {"error": str(e)}

    def _run_tests(self, test_framework: str = "auto", project_path: str = None,
                  test_path: str = None, coverage: bool = False,
                  verbose: bool = True) -> Dict[str, Any]:
        """Run tests"""
        try:
            proj_path = project_path or str(self.workspace)

            # Auto-detect framework
            if test_framework == "auto":
                if (Path(proj_path) / "pytest.ini").exists() or (Path(proj_path) / "setup.py").exists():
                    test_framework = "pytest"
                elif (Path(proj_path) / "package.json").exists():
                    test_framework = "jest"
                else:
                    test_framework = "pytest"

            commands = {
                "pytest": ["pytest"] + ([test_path] if test_path else []) +
                         (["-v"] if verbose else []) + (["--cov"] if coverage else []),
                "jest": ["npm", "test"] + (["--coverage"] if coverage else []),
                "mocha": ["mocha"] + ([test_path] if test_path else []),
                "unittest": ["python", "-m", "unittest", "discover"] + ([test_path] if test_path else []),
                "vitest": ["vitest", "run"] + (["--coverage"] if coverage else [])
            }

            command = commands.get(test_framework)
            if not command:
                return {"error": f"Unknown test framework: {test_framework}"}

            result = self._execute_command(command, cwd=proj_path, timeout=180)

            return {
                "test_framework": test_framework,
                "coverage_enabled": coverage,
                **result
            }

        except Exception as e:
            return {"error": str(e)}

    def _code_analysis(self, analysis_type: str = "all", project_path: str = None,
                      language: str = "auto", fix: bool = False) -> Dict[str, Any]:
        """Analyze code"""
        try:
            proj_path = project_path or str(self.workspace)
            results = {}

            # Auto-detect language
            if language == "auto":
                if (Path(proj_path) / "package.json").exists():
                    language = "javascript"
                elif (Path(proj_path) / "requirements.txt").exists():
                    language = "python"

            if analysis_type in ["lint", "all"]:
                # Linting
                if language == "python":
                    lint_cmd = ["pylint"] + (["--fix"] if fix else []) + ["."]
                elif language in ["javascript", "typescript"]:
                    lint_cmd = ["eslint"] + (["--fix"] if fix else []) + ["."]
                else:
                    lint_cmd = None

                if lint_cmd:
                    results["lint"] = self._execute_command(lint_cmd, cwd=proj_path)

            if analysis_type in ["security", "all"]:
                # Security scan
                if language == "python":
                    results["security"] = self._execute_command(
                        ["bandit", "-r", "."],
                        cwd=proj_path
                    )
                elif language in ["javascript", "typescript"]:
                    results["security"] = self._execute_command(
                        ["npm", "audit"],
                        cwd=proj_path
                    )

            if analysis_type in ["complexity", "all"]:
                # Complexity analysis
                if language == "python":
                    results["complexity"] = self._execute_command(
                        ["radon", "cc", ".", "-a"],
                        cwd=proj_path
                    )

            if analysis_type in ["dependencies", "all"]:
                # Dependency check
                if language == "python":
                    results["dependencies"] = self._execute_command(
                        ["pip", "list", "--outdated"],
                        cwd=proj_path
                    )
                elif language in ["javascript", "typescript"]:
                    results["dependencies"] = self._execute_command(
                        ["npm", "outdated"],
                        cwd=proj_path
                    )

            return {
                "analysis_type": analysis_type,
                "language": language,
                "results": results
            }

        except Exception as e:
            return {"error": str(e)}

    def _package_manager(self, operation: str, manager: str = "auto",
                        packages: List[str] = None, project_path: str = None,
                        dev: bool = False) -> Dict[str, Any]:
        """Package manager operations"""
        try:
            proj_path = project_path or str(self.workspace)
            packages = packages or []

            # Auto-detect manager
            if manager == "auto":
                if (Path(proj_path) / "package-lock.json").exists():
                    manager = "npm"
                elif (Path(proj_path) / "yarn.lock").exists():
                    manager = "yarn"
                elif (Path(proj_path) / "pnpm-lock.yaml").exists():
                    manager = "pnpm"
                elif (Path(proj_path) / "requirements.txt").exists():
                    manager = "pip"
                else:
                    manager = "npm"

            # Build commands
            if manager == "pip":
                commands = {
                    "install": ["pip", "install"] + packages,
                    "update": ["pip", "install", "--upgrade"] + packages,
                    "remove": ["pip", "uninstall", "-y"] + packages,
                    "list": ["pip", "list"],
                    "outdated": ["pip", "list", "--outdated"]
                }
            else:  # npm/yarn/pnpm
                dev_flag = ["-D" if manager == "npm" else "--dev"] if dev else []
                commands = {
                    "install": [manager, "install"] + packages + dev_flag,
                    "update": [manager, "update"] + packages,
                    "remove": [manager, "remove"] + packages,
                    "list": [manager, "list"],
                    "outdated": [manager, "outdated"]
                }

            command = commands.get(operation)
            if not command:
                return {"error": f"Unknown operation: {operation}"}

            result = self._execute_command(command, cwd=proj_path, timeout=180)

            return {
                "manager": manager,
                "operation": operation,
                "packages": packages,
                **result
            }

        except Exception as e:
            return {"error": str(e)}

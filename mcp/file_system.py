"""
MCP File System - File and directory management
"""
from .base import MCPServer, MCPTool
from typing import Dict, Any, List
import os
import pathlib
import mimetypes
from datetime import datetime


class FileSystemMCP(MCPServer):
    """File System MCP Server - Read/write files and manage directories"""

    def __init__(self, workspace_path: str = "/tmp/vif_workspace"):
        super().__init__(
            name="file_system",
            description="File system operations: read, write, list files and directories"
        )
        self.workspace = pathlib.Path(workspace_path)
        self.workspace.mkdir(parents=True, exist_ok=True)
        self._init_tools()

    def _init_tools(self):
        """Initialize all file system tools"""

        # Tool 1: List files/directories
        self.register_tool(MCPTool(
            name="list_directory",
            description="List files and directories in a path",
            parameters={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Directory path (relative to workspace)"
                    },
                    "recursive": {
                        "type": "boolean",
                        "description": "List recursively",
                        "default": False
                    }
                },
                "required": ["path"]
            },
            handler=self._list_directory
        ))

        # Tool 2: Read file
        self.register_tool(MCPTool(
            name="read_file",
            description="Read contents of a file",
            parameters={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File path (relative to workspace)"
                    },
                    "encoding": {
                        "type": "string",
                        "description": "File encoding (default: utf-8)",
                        "default": "utf-8"
                    }
                },
                "required": ["path"]
            },
            handler=self._read_file
        ))

        # Tool 3: Write file
        self.register_tool(MCPTool(
            name="write_file",
            description="Write content to a file",
            parameters={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File path (relative to workspace)"
                    },
                    "content": {
                        "type": "string",
                        "description": "Content to write"
                    },
                    "mode": {
                        "type": "string",
                        "description": "Write mode: 'w' (overwrite) or 'a' (append)",
                        "default": "w"
                    }
                },
                "required": ["path", "content"]
            },
            handler=self._write_file
        ))

        # Tool 4: Delete file/directory
        self.register_tool(MCPTool(
            name="delete",
            description="Delete a file or directory",
            parameters={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to delete"
                    },
                    "recursive": {
                        "type": "boolean",
                        "description": "Delete directory recursively",
                        "default": False
                    }
                },
                "required": ["path"]
            },
            handler=self._delete
        ))

        # Tool 5: Get file info
        self.register_tool(MCPTool(
            name="get_file_info",
            description="Get detailed information about a file",
            parameters={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File path"
                    }
                },
                "required": ["path"]
            },
            handler=self._get_file_info
        ))

    def _resolve_path(self, path: str) -> pathlib.Path:
        """Resolve path relative to workspace"""
        full_path = (self.workspace / path).resolve()

        # Security: Ensure path is within workspace
        if not str(full_path).startswith(str(self.workspace)):
            raise PermissionError("Access denied: Path outside workspace")

        return full_path

    def _list_directory(self, path: str, recursive: bool = False) -> Dict[str, Any]:
        """List directory contents"""
        try:
            dir_path = self._resolve_path(path)

            if not dir_path.exists():
                return {"error": "Directory not found"}

            if not dir_path.is_dir():
                return {"error": "Path is not a directory"}

            items = []

            if recursive:
                for item in dir_path.rglob("*"):
                    items.append({
                        "name": str(item.relative_to(dir_path)),
                        "type": "directory" if item.is_dir() else "file",
                        "size": item.stat().st_size if item.is_file() else 0
                    })
            else:
                for item in dir_path.iterdir():
                    items.append({
                        "name": item.name,
                        "type": "directory" if item.is_dir() else "file",
                        "size": item.stat().st_size if item.is_file() else 0
                    })

            return {
                "path": path,
                "items": items,
                "count": len(items)
            }

        except Exception as e:
            return {"error": str(e)}

    def _read_file(self, path: str, encoding: str = "utf-8") -> Dict[str, Any]:
        """Read file contents"""
        try:
            file_path = self._resolve_path(path)

            if not file_path.exists():
                return {"error": "File not found"}

            if not file_path.is_file():
                return {"error": "Path is not a file"}

            content = file_path.read_text(encoding=encoding)

            return {
                "path": path,
                "content": content,
                "size": len(content),
                "lines": len(content.splitlines())
            }

        except Exception as e:
            return {"error": str(e)}

    def _write_file(self, path: str, content: str, mode: str = "w") -> Dict[str, Any]:
        """Write to file"""
        try:
            file_path = self._resolve_path(path)

            # Create parent directories if needed
            file_path.parent.mkdir(parents=True, exist_ok=True)

            if mode == "a":
                file_path.write_text(file_path.read_text() + content if file_path.exists() else content)
            else:
                file_path.write_text(content)

            return {
                "path": path,
                "bytes_written": len(content.encode('utf-8')),
                "mode": mode
            }

        except Exception as e:
            return {"error": str(e)}

    def _delete(self, path: str, recursive: bool = False) -> Dict[str, Any]:
        """Delete file or directory"""
        try:
            target_path = self._resolve_path(path)

            if not target_path.exists():
                return {"error": "Path not found"}

            if target_path.is_dir():
                if recursive:
                    import shutil
                    shutil.rmtree(target_path)
                else:
                    target_path.rmdir()  # Only works if empty
            else:
                target_path.unlink()

            return {"path": path, "deleted": True}

        except Exception as e:
            return {"error": str(e)}

    def _get_file_info(self, path: str) -> Dict[str, Any]:
        """Get file information"""
        try:
            file_path = self._resolve_path(path)

            if not file_path.exists():
                return {"error": "File not found"}

            stat = file_path.stat()
            mime_type, _ = mimetypes.guess_type(str(file_path))

            return {
                "path": path,
                "name": file_path.name,
                "type": "directory" if file_path.is_dir() else "file",
                "size": stat.st_size,
                "mime_type": mime_type,
                "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "permissions": oct(stat.st_mode)[-3:]
            }

        except Exception as e:
            return {"error": str(e)}

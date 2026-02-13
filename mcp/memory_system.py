"""
MCP Memory System - Long-term memory and context augmentation
"""
from .base import MCPServer, MCPTool
from typing import Dict, Any, List
import json
from datetime import datetime


class MemorySystemMCP(MCPServer):
    """Memory System MCP Server - Store and retrieve long-term memories"""

    def __init__(self, db_pool):
        super().__init__(
            name="memory_system",
            description="Long-term memory storage for facts, preferences, and context"
        )
        self.db_pool = db_pool
        self._init_tools()
        self._ensure_table()

    def _get_connection(self):
        """Get database connection"""
        return self.db_pool.getconn()

    def _release_connection(self, conn):
        """Release connection"""
        self.db_pool.putconn(conn)

    def _ensure_table(self):
        """Ensure memory table exists"""
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vif_memories (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(255) NOT NULL,
                    memory_type VARCHAR(50) NOT NULL,
                    key VARCHAR(255) NOT NULL,
                    value TEXT NOT NULL,
                    metadata JSONB,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(username, memory_type, key)
                )
            """)

            # Create index for faster lookups
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_memories_username
                ON vif_memories(username)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_memories_type
                ON vif_memories(memory_type)
            """)

            conn.commit()

        except Exception as e:
            print(f"Error creating memories table: {e}")

        finally:
            if conn:
                self._release_connection(conn)

    def _init_tools(self):
        """Initialize all memory tools"""

        # Tool 1: Store memory
        self.register_tool(MCPTool(
            name="store_memory",
            description="Store a fact, preference, or piece of information",
            parameters={
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "Username to associate memory with"
                    },
                    "memory_type": {
                        "type": "string",
                        "description": "Type: fact, preference, context, note",
                        "enum": ["fact", "preference", "context", "note"]
                    },
                    "key": {
                        "type": "string",
                        "description": "Memory key/identifier"
                    },
                    "value": {
                        "type": "string",
                        "description": "Memory value/content"
                    },
                    "metadata": {
                        "type": "object",
                        "description": "Optional additional metadata"
                    }
                },
                "required": ["username", "memory_type", "key", "value"]
            },
            handler=self._store_memory
        ))

        # Tool 2: Retrieve memory
        self.register_tool(MCPTool(
            name="retrieve_memory",
            description="Retrieve a specific memory by key",
            parameters={
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "Username"
                    },
                    "key": {
                        "type": "string",
                        "description": "Memory key"
                    },
                    "memory_type": {
                        "type": "string",
                        "description": "Optional: filter by type"
                    }
                },
                "required": ["username", "key"]
            },
            handler=self._retrieve_memory
        ))

        # Tool 3: List memories
        self.register_tool(MCPTool(
            name="list_memories",
            description="List all memories for a user",
            parameters={
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "Username"
                    },
                    "memory_type": {
                        "type": "string",
                        "description": "Optional: filter by type"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum results (default: 50)",
                        "default": 50
                    }
                },
                "required": ["username"]
            },
            handler=self._list_memories
        ))

        # Tool 4: Search memories
        self.register_tool(MCPTool(
            name="search_memories",
            description="Search memories by content",
            parameters={
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "Username"
                    },
                    "query": {
                        "type": "string",
                        "description": "Search query"
                    },
                    "memory_type": {
                        "type": "string",
                        "description": "Optional: filter by type"
                    }
                },
                "required": ["username", "query"]
            },
            handler=self._search_memories
        ))

        # Tool 5: Delete memory
        self.register_tool(MCPTool(
            name="delete_memory",
            description="Delete a specific memory",
            parameters={
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "Username"
                    },
                    "key": {
                        "type": "string",
                        "description": "Memory key to delete"
                    }
                },
                "required": ["username", "key"]
            },
            handler=self._delete_memory
        ))

    def _store_memory(self, username: str, memory_type: str, key: str, value: str, metadata: Dict = None) -> Dict[str, Any]:
        """Store a memory"""
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            metadata_json = json.dumps(metadata) if metadata else None

            cursor.execute("""
                INSERT INTO vif_memories (username, memory_type, key, value, metadata, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (username, memory_type, key)
                DO UPDATE SET
                    value = EXCLUDED.value,
                    metadata = EXCLUDED.metadata,
                    updated_at = EXCLUDED.updated_at
                RETURNING id
            """, (username, memory_type, key, value, metadata_json, datetime.now()))

            memory_id = cursor.fetchone()[0]
            conn.commit()

            return {
                "success": True,
                "id": memory_id,
                "username": username,
                "type": memory_type,
                "key": key
            }

        except Exception as e:
            if conn:
                conn.rollback()
            return {"error": str(e)}

        finally:
            if conn:
                self._release_connection(conn)

    def _retrieve_memory(self, username: str, key: str, memory_type: str = None) -> Dict[str, Any]:
        """Retrieve a specific memory"""
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            if memory_type:
                cursor.execute("""
                    SELECT memory_type, key, value, metadata, created_at, updated_at
                    FROM vif_memories
                    WHERE username = %s AND key = %s AND memory_type = %s
                """, (username, key, memory_type))
            else:
                cursor.execute("""
                    SELECT memory_type, key, value, metadata, created_at, updated_at
                    FROM vif_memories
                    WHERE username = %s AND key = %s
                """, (username, key))

            row = cursor.fetchone()

            if not row:
                return {"error": "Memory not found"}

            return {
                "type": row[0],
                "key": row[1],
                "value": row[2],
                "metadata": json.loads(row[3]) if row[3] else None,
                "created_at": row[4].isoformat() if row[4] else None,
                "updated_at": row[5].isoformat() if row[5] else None
            }

        except Exception as e:
            return {"error": str(e)}

        finally:
            if conn:
                self._release_connection(conn)

    def _list_memories(self, username: str, memory_type: str = None, limit: int = 50) -> Dict[str, Any]:
        """List all memories for a user"""
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            if memory_type:
                cursor.execute("""
                    SELECT memory_type, key, value, metadata, created_at, updated_at
                    FROM vif_memories
                    WHERE username = %s AND memory_type = %s
                    ORDER BY updated_at DESC
                    LIMIT %s
                """, (username, memory_type, limit))
            else:
                cursor.execute("""
                    SELECT memory_type, key, value, metadata, created_at, updated_at
                    FROM vif_memories
                    WHERE username = %s
                    ORDER BY updated_at DESC
                    LIMIT %s
                """, (username, limit))

            rows = cursor.fetchall()

            memories = []
            for row in rows:
                memories.append({
                    "type": row[0],
                    "key": row[1],
                    "value": row[2],
                    "metadata": json.loads(row[3]) if row[3] else None,
                    "created_at": row[4].isoformat() if row[4] else None,
                    "updated_at": row[5].isoformat() if row[5] else None
                })

            return {
                "username": username,
                "memories": memories,
                "count": len(memories)
            }

        except Exception as e:
            return {"error": str(e)}

        finally:
            if conn:
                self._release_connection(conn)

    def _search_memories(self, username: str, query: str, memory_type: str = None) -> Dict[str, Any]:
        """Search memories by content"""
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            if memory_type:
                cursor.execute("""
                    SELECT memory_type, key, value, metadata, created_at, updated_at
                    FROM vif_memories
                    WHERE username = %s
                        AND memory_type = %s
                        AND (key ILIKE %s OR value ILIKE %s)
                    ORDER BY updated_at DESC
                """, (username, memory_type, f'%{query}%', f'%{query}%'))
            else:
                cursor.execute("""
                    SELECT memory_type, key, value, metadata, created_at, updated_at
                    FROM vif_memories
                    WHERE username = %s
                        AND (key ILIKE %s OR value ILIKE %s)
                    ORDER BY updated_at DESC
                """, (username, f'%{query}%', f'%{query}%'))

            rows = cursor.fetchall()

            memories = []
            for row in rows:
                memories.append({
                    "type": row[0],
                    "key": row[1],
                    "value": row[2],
                    "metadata": json.loads(row[3]) if row[3] else None,
                    "created_at": row[4].isoformat() if row[4] else None,
                    "updated_at": row[5].isoformat() if row[5] else None
                })

            return {
                "query": query,
                "results": memories,
                "count": len(memories)
            }

        except Exception as e:
            return {"error": str(e)}

        finally:
            if conn:
                self._release_connection(conn)

    def _delete_memory(self, username: str, key: str) -> Dict[str, Any]:
        """Delete a memory"""
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                DELETE FROM vif_memories
                WHERE username = %s AND key = %s
                RETURNING id
            """, (username, key))

            result = cursor.fetchone()
            conn.commit()

            if not result:
                return {"error": "Memory not found"}

            return {
                "success": True,
                "username": username,
                "key": key,
                "deleted": True
            }

        except Exception as e:
            if conn:
                conn.rollback()
            return {"error": str(e)}

        finally:
            if conn:
                self._release_connection(conn)

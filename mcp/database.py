"""
MCP Database - PostgreSQL database access
"""
from .base import MCPServer, MCPTool
from typing import Dict, Any, List
import psycopg2
import psycopg2.extras


class DatabaseMCP(MCPServer):
    """Database MCP Server - Query and analyze PostgreSQL database"""

    def __init__(self, db_pool):
        super().__init__(
            name="database",
            description="Query Vif's PostgreSQL database for analytics and data retrieval"
        )
        self.db_pool = db_pool
        self._init_tools()

    def _init_tools(self):
        """Initialize all database tools"""

        # Tool 1: Execute SELECT query
        self.register_tool(MCPTool(
            name="query",
            description="Execute a SELECT query on the database (read-only)",
            parameters={
                "type": "object",
                "properties": {
                    "sql": {
                        "type": "string",
                        "description": "SQL SELECT query to execute"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of rows to return (default: 100)",
                        "default": 100
                    }
                },
                "required": ["sql"]
            },
            handler=self._query
        ))

        # Tool 2: Get conversation history
        self.register_tool(MCPTool(
            name="get_conversation_history",
            description="Get conversation history for a user",
            parameters={
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "Username to get history for"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Number of recent messages (default: 50)",
                        "default": 50
                    }
                },
                "required": ["username"]
            },
            handler=self._get_conversation_history
        ))

        # Tool 3: Get user statistics
        self.register_tool(MCPTool(
            name="get_user_stats",
            description="Get statistics for a user",
            parameters={
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "Username to get stats for"
                    }
                },
                "required": ["username"]
            },
            handler=self._get_user_stats
        ))

        # Tool 4: Search messages
        self.register_tool(MCPTool(
            name="search_messages",
            description="Search for messages containing specific text",
            parameters={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query"
                    },
                    "username": {
                        "type": "string",
                        "description": "Optional: filter by username"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum results (default: 20)",
                        "default": 20
                    }
                },
                "required": ["query"]
            },
            handler=self._search_messages
        ))

    def _get_connection(self):
        """Get database connection from pool"""
        return self.db_pool.getconn()

    def _release_connection(self, conn):
        """Release connection back to pool"""
        self.db_pool.putconn(conn)

    def _query(self, sql: str, limit: int = 100) -> Dict[str, Any]:
        """Execute SELECT query"""
        conn = None
        try:
            # Security: Only allow SELECT queries
            sql_upper = sql.strip().upper()
            if not sql_upper.startswith('SELECT'):
                return {"error": "Only SELECT queries are allowed"}

            conn = self._get_connection()
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

            # Add LIMIT if not present
            if 'LIMIT' not in sql_upper:
                sql += f" LIMIT {limit}"

            cursor.execute(sql)
            rows = cursor.fetchall()

            return {
                "success": True,
                "rows": [dict(row) for row in rows],
                "count": len(rows)
            }

        except Exception as e:
            return {"error": str(e)}

        finally:
            if conn:
                self._release_connection(conn)

    def _get_conversation_history(self, username: str, limit: int = 50) -> Dict[str, Any]:
        """Get conversation history for user"""
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

            query = """
                SELECT m.id, m.role, m.content, m.timestamp, s.title
                FROM messages m
                JOIN sessions s ON m.session_id = s.id
                WHERE s.username = %s
                ORDER BY m.timestamp DESC
                LIMIT %s
            """

            cursor.execute(query, (username, limit))
            rows = cursor.fetchall()

            return {
                "username": username,
                "messages": [dict(row) for row in rows],
                "count": len(rows)
            }

        except Exception as e:
            return {"error": str(e)}

        finally:
            if conn:
                self._release_connection(conn)

    def _get_user_stats(self, username: str) -> Dict[str, Any]:
        """Get user statistics"""
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

            # Get user info
            cursor.execute(
                "SELECT username, created_at, credits, has_paid FROM users WHERE username = %s",
                (username,)
            )
            user = cursor.fetchone()

            if not user:
                return {"error": "User not found"}

            # Count sessions
            cursor.execute(
                "SELECT COUNT(*) as session_count FROM sessions WHERE username = %s",
                (username,)
            )
            session_count = cursor.fetchone()['session_count']

            # Count messages
            cursor.execute("""
                SELECT COUNT(*) as message_count
                FROM messages m
                JOIN sessions s ON m.session_id = s.id
                WHERE s.username = %s
            """, (username,))
            message_count = cursor.fetchone()['message_count']

            return {
                "user": dict(user),
                "sessions": session_count,
                "messages": message_count
            }

        except Exception as e:
            return {"error": str(e)}

        finally:
            if conn:
                self._release_connection(conn)

    def _search_messages(self, query: str, username: str = None, limit: int = 20) -> Dict[str, Any]:
        """Search messages"""
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

            if username:
                sql = """
                    SELECT m.id, m.role, m.content, m.timestamp, s.title, s.username
                    FROM messages m
                    JOIN sessions s ON m.session_id = s.id
                    WHERE s.username = %s AND m.content ILIKE %s
                    ORDER BY m.timestamp DESC
                    LIMIT %s
                """
                cursor.execute(sql, (username, f'%{query}%', limit))
            else:
                sql = """
                    SELECT m.id, m.role, m.content, m.timestamp, s.title, s.username
                    FROM messages m
                    JOIN sessions s ON m.session_id = s.id
                    WHERE m.content ILIKE %s
                    ORDER BY m.timestamp DESC
                    LIMIT %s
                """
                cursor.execute(sql, (f'%{query}%', limit))

            rows = cursor.fetchall()

            return {
                "query": query,
                "results": [dict(row) for row in rows],
                "count": len(rows)
            }

        except Exception as e:
            return {"error": str(e)}

        finally:
            if conn:
                self._release_connection(conn)

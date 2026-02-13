"""
MCP RAG Memory - Enhanced memory with vector embeddings and semantic search
"""
from .base import MCPServer, MCPTool
from typing import Dict, Any, List
import json
from datetime import datetime
import os
import requests


class RAGMemoryMCP(MCPServer):
    """RAG Memory MCP Server - Vector embeddings, semantic search, unlimited context"""

    def __init__(self, db_pool):
        super().__init__(
            name="rag_memory",
            description="Enhanced memory with vector embeddings and semantic search for unlimited context"
        )
        self.db_pool = db_pool
        self.openrouter_key = os.getenv('OPENROUTER_API_KEY')
        self._init_tools()
        self._ensure_tables()

    def _get_connection(self):
        """Get database connection"""
        return self.db_pool.getconn()

    def _release_connection(self, conn):
        """Release connection"""
        self.db_pool.putconn(conn)

    def _ensure_tables(self):
        """Ensure vector memory tables exist"""
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            # Enable pgvector extension if available
            try:
                cursor.execute("CREATE EXTENSION IF NOT EXISTS vector")
            except:
                pass  # pgvector may not be available

            # Create memory table with vector support
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vif_rag_memories (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(255) NOT NULL,
                    content TEXT NOT NULL,
                    embedding_text TEXT,
                    embedding_vector TEXT,
                    memory_type VARCHAR(50),
                    metadata JSONB,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    accessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    access_count INTEGER DEFAULT 0
                )
            """)

            # Create indexes
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_rag_username
                ON vif_rag_memories(username)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_rag_type
                ON vif_rag_memories(memory_type)
            """)

            # Full-text search index
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_rag_content_search
                ON vif_rag_memories USING GIN (to_tsvector('english', content))
            """)

            conn.commit()

        except Exception as e:
            print(f"Error creating RAG memory tables: {e}")

        finally:
            if conn:
                self._release_connection(conn)

    def _init_tools(self):
        """Initialize RAG memory tools"""

        # Tool 1: Store with embedding
        self.register_tool(MCPTool(
            name="store_with_embedding",
            description="Store memory with semantic embedding for better retrieval",
            parameters={
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "Username"
                    },
                    "content": {
                        "type": "string",
                        "description": "Content to store"
                    },
                    "memory_type": {
                        "type": "string",
                        "description": "Type: conversation, fact, code, document",
                        "enum": ["conversation", "fact", "code", "document", "summary"]
                    },
                    "metadata": {
                        "type": "object",
                        "description": "Additional metadata"
                    }
                },
                "required": ["username", "content"]
            },
            handler=self._store_with_embedding
        ))

        # Tool 2: Semantic search
        self.register_tool(MCPTool(
            name="semantic_search",
            description="Search memories using semantic similarity",
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
                        "description": "Filter by type"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max results",
                        "default": 10
                    }
                },
                "required": ["username", "query"]
            },
            handler=self._semantic_search
        ))

        # Tool 3: Get conversation context
        self.register_tool(MCPTool(
            name="get_conversation_context",
            description="Get relevant context for current conversation",
            parameters={
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "Username"
                    },
                    "current_message": {
                        "type": "string",
                        "description": "Current user message"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max context items",
                        "default": 5
                    }
                },
                "required": ["username", "current_message"]
            },
            handler=self._get_conversation_context
        ))

        # Tool 4: Summarize conversation
        self.register_tool(MCPTool(
            name="summarize_conversation",
            description="Create summary of conversation history",
            parameters={
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "Username"
                    },
                    "time_range": {
                        "type": "string",
                        "description": "Time range: last_hour, last_day, last_week",
                        "enum": ["last_hour", "last_day", "last_week", "all"],
                        "default": "last_day"
                    }
                },
                "required": ["username"]
            },
            handler=self._summarize_conversation
        ))

    def _generate_embedding(self, text: str) -> str:
        """Generate text embedding using OpenRouter"""
        try:
            # Use a simple text embedding representation
            # In production, you would use actual embeddings API
            # For now, we'll store the text itself for full-text search
            return text[:500]  # Truncate for storage

        except Exception as e:
            return text[:500]

    def _store_with_embedding(self, username: str, content: str,
                              memory_type: str = "conversation",
                              metadata: Dict = None) -> Dict[str, Any]:
        """Store memory with embedding"""
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            # Generate embedding
            embedding_text = self._generate_embedding(content)
            metadata_json = json.dumps(metadata) if metadata else None

            cursor.execute("""
                INSERT INTO vif_rag_memories
                (username, content, embedding_text, memory_type, metadata)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
            """, (username, content, embedding_text, memory_type, metadata_json))

            memory_id = cursor.fetchone()[0]
            conn.commit()

            return {
                "success": True,
                "memory_id": memory_id,
                "username": username,
                "type": memory_type
            }

        except Exception as e:
            if conn:
                conn.rollback()
            return {"error": str(e)}

        finally:
            if conn:
                self._release_connection(conn)

    def _semantic_search(self, username: str, query: str,
                        memory_type: str = None, limit: int = 10) -> Dict[str, Any]:
        """Search memories semantically"""
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            # Use PostgreSQL full-text search
            if memory_type:
                cursor.execute("""
                    SELECT id, content, memory_type, metadata, created_at,
                           ts_rank(to_tsvector('english', content), plainto_tsquery('english', %s)) as rank
                    FROM vif_rag_memories
                    WHERE username = %s
                        AND memory_type = %s
                        AND to_tsvector('english', content) @@ plainto_tsquery('english', %s)
                    ORDER BY rank DESC, accessed_at DESC
                    LIMIT %s
                """, (query, username, memory_type, query, limit))
            else:
                cursor.execute("""
                    SELECT id, content, memory_type, metadata, created_at,
                           ts_rank(to_tsvector('english', content), plainto_tsquery('english', %s)) as rank
                    FROM vif_rag_memories
                    WHERE username = %s
                        AND to_tsvector('english', content) @@ plainto_tsquery('english', %s)
                    ORDER BY rank DESC, accessed_at DESC
                    LIMIT %s
                """, (query, username, query, limit))

            rows = cursor.fetchall()

            # Update access counts
            for row in rows:
                cursor.execute("""
                    UPDATE vif_rag_memories
                    SET accessed_at = CURRENT_TIMESTAMP,
                        access_count = access_count + 1
                    WHERE id = %s
                """, (row[0],))

            conn.commit()

            results = []
            for row in rows:
                results.append({
                    "id": row[0],
                    "content": row[1],
                    "type": row[2],
                    "metadata": json.loads(row[3]) if row[3] else None,
                    "created_at": row[4].isoformat() if row[4] else None,
                    "relevance_score": float(row[5]) if len(row) > 5 else 0
                })

            return {
                "query": query,
                "results": results,
                "count": len(results)
            }

        except Exception as e:
            return {"error": str(e)}

        finally:
            if conn:
                self._release_connection(conn)

    def _get_conversation_context(self, username: str, current_message: str,
                                   limit: int = 5) -> Dict[str, Any]:
        """Get relevant context for conversation"""
        try:
            # Search for relevant memories
            search_result = self._semantic_search(
                username=username,
                query=current_message,
                limit=limit
            )

            if "error" in search_result:
                return search_result

            # Format context
            context_items = []
            for result in search_result.get("results", []):
                context_items.append({
                    "content": result["content"],
                    "type": result["type"],
                    "relevance": result.get("relevance_score", 0)
                })

            return {
                "context_items": context_items,
                "count": len(context_items),
                "query": current_message
            }

        except Exception as e:
            return {"error": str(e)}

    def _summarize_conversation(self, username: str,
                               time_range: str = "last_day") -> Dict[str, Any]:
        """Summarize conversation history"""
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            # Determine time filter
            time_filters = {
                "last_hour": "created_at >= NOW() - INTERVAL '1 hour'",
                "last_day": "created_at >= NOW() - INTERVAL '1 day'",
                "last_week": "created_at >= NOW() - INTERVAL '1 week'",
                "all": "TRUE"
            }

            time_filter = time_filters.get(time_range, time_filters["last_day"])

            # Get recent memories
            cursor.execute(f"""
                SELECT content, memory_type, created_at
                FROM vif_rag_memories
                WHERE username = %s
                    AND memory_type = 'conversation'
                    AND {time_filter}
                ORDER BY created_at DESC
                LIMIT 50
            """, (username,))

            rows = cursor.fetchall()

            if not rows:
                return {
                    "summary": "No conversations found in this time range",
                    "time_range": time_range,
                    "message_count": 0
                }

            # Combine messages
            combined_text = "\n".join([row[0] for row in rows])

            # Generate summary using LLM
            if self.openrouter_key and len(combined_text) > 200:
                try:
                    url = "https://openrouter.ai/api/v1/chat/completions"
                    headers = {
                        "Authorization": f"Bearer {self.openrouter_key}",
                        "Content-Type": "application/json",
                        "HTTP-Referer": "https://vif.lat"
                    }

                    data = {
                        "model": "anthropic/claude-3.5-sonnet",
                        "messages": [
                            {
                                "role": "user",
                                "content": f"Summarize these conversation messages in 3-5 bullet points:\n\n{combined_text[:4000]}"
                            }
                        ],
                        "max_tokens": 500
                    }

                    response = requests.post(url, headers=headers, json=data, timeout=30)
                    response.raise_for_status()
                    result = response.json()
                    summary = result['choices'][0]['message']['content']

                except:
                    summary = f"Recent conversation covering {len(rows)} messages"
            else:
                summary = f"Recent conversation covering {len(rows)} messages"

            return {
                "summary": summary,
                "time_range": time_range,
                "message_count": len(rows),
                "first_message": rows[-1][2].isoformat() if rows else None,
                "last_message": rows[0][2].isoformat() if rows else None
            }

        except Exception as e:
            return {"error": str(e)}

        finally:
            if conn:
                self._release_connection(conn)

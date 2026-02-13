"""
MCP Cache System - Performance optimization with intelligent caching
"""
import json
import time
import hashlib
from typing import Dict, Any, Optional
from datetime import datetime, timedelta


class MCPCache:
    """Intelligent cache system for MCP tool results"""

    def __init__(self, max_size: int = 1000, default_ttl: int = 3600):
        self.cache = {}
        self.max_size = max_size
        self.default_ttl = default_ttl  # Time-to-live in seconds
        self.hits = 0
        self.misses = 0

    def _generate_key(self, server: str, tool: str, parameters: Dict) -> str:
        """Generate cache key"""
        # Create deterministic string from parameters
        param_str = json.dumps(parameters, sort_keys=True)
        key_string = f"{server}:{tool}:{param_str}"
        return hashlib.md5(key_string.encode()).hexdigest()

    def _is_cacheable(self, server: str, tool: str) -> bool:
        """Determine if tool result should be cached"""
        # Tools that should NOT be cached (non-deterministic or side effects)
        non_cacheable = {
            "code_execution": ["execute_python"],  # Code execution may have side effects
            "devtools": ["git_operation", "docker_operation", "deploy"],  # Operations with side effects
            "integration_hub": "*",  # All integrations have side effects
            "creative": ["generate_image", "text_to_speech"],  # Generation is expensive but unique
        }

        if server in non_cacheable:
            if non_cacheable[server] == "*":
                return False
            if tool in non_cacheable[server]:
                return False

        # Tools that SHOULD be cached
        cacheable = {
            "web_browser": "*",  # Web pages change slowly
            "external_apis": ["get_weather", "get_crypto_price", "get_time"],  # API results
            "database": ["query", "get_user_stats"],  # Database queries
            "data_science": ["analyze_csv"],  # Data analysis
            "vision": ["analyze_image"],  # Image analysis
            "rag_memory": ["semantic_search", "get_conversation_context"],  # Memory searches
        }

        if server in cacheable:
            if cacheable[server] == "*":
                return True
            return tool in cacheable[server]

        return False

    def get(self, server: str, tool: str, parameters: Dict) -> Optional[Dict[str, Any]]:
        """Get result from cache"""
        if not self._is_cacheable(server, tool):
            return None

        key = self._generate_key(server, tool, parameters)

        if key in self.cache:
            entry = self.cache[key]

            # Check if expired
            if time.time() < entry["expires_at"]:
                self.hits += 1
                entry["last_accessed"] = time.time()
                entry["access_count"] += 1
                return entry["result"]
            else:
                # Expired, remove
                del self.cache[key]

        self.misses += 1
        return None

    def set(self, server: str, tool: str, parameters: Dict,
            result: Dict[str, Any], ttl: Optional[int] = None) -> None:
        """Store result in cache"""
        if not self._is_cacheable(server, tool):
            return

        key = self._generate_key(server, tool, parameters)
        ttl = ttl or self.default_ttl

        # Check cache size
        if len(self.cache) >= self.max_size:
            self._evict_lru()

        self.cache[key] = {
            "result": result,
            "created_at": time.time(),
            "last_accessed": time.time(),
            "expires_at": time.time() + ttl,
            "access_count": 0,
            "server": server,
            "tool": tool
        }

    def _evict_lru(self) -> None:
        """Evict least recently used items"""
        # Remove oldest 10% of items
        items_to_remove = max(1, self.max_size // 10)

        # Sort by last_accessed
        sorted_items = sorted(
            self.cache.items(),
            key=lambda x: x[1]["last_accessed"]
        )

        for i in range(items_to_remove):
            del self.cache[sorted_items[i][0]]

    def clear(self, server: Optional[str] = None) -> int:
        """Clear cache"""
        if server is None:
            count = len(self.cache)
            self.cache.clear()
            return count

        # Clear specific server cache
        keys_to_remove = [
            k for k, v in self.cache.items()
            if v["server"] == server
        ]

        for key in keys_to_remove:
            del self.cache[key]

        return len(keys_to_remove)

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_requests = self.hits + self.misses
        hit_rate = (self.hits / total_requests * 100) if total_requests > 0 else 0

        return {
            "size": len(self.cache),
            "max_size": self.max_size,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": f"{hit_rate:.2f}%",
            "total_requests": total_requests
        }


class ParallelExecutor:
    """Execute multiple MCP tools in parallel"""

    def __init__(self, mcp_manager):
        self.mcp_manager = mcp_manager

    def execute_parallel(self, tool_calls: list) -> Dict[str, Any]:
        """Execute multiple tool calls in parallel"""
        import concurrent.futures
        import threading

        results = {}
        errors = []

        def execute_single(call):
            try:
                server = call.get("server")
                tool = call.get("tool")
                parameters = call.get("parameters", {})
                call_id = call.get("id", f"{server}_{tool}")

                result = self.mcp_manager.execute_tool(server, tool, parameters)
                return (call_id, result)

            except Exception as e:
                return (call.get("id", "unknown"), {"error": str(e)})

        # Execute in parallel with ThreadPoolExecutor
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(execute_single, call) for call in tool_calls]

            for future in concurrent.futures.as_completed(futures):
                try:
                    call_id, result = future.result()
                    results[call_id] = result
                except Exception as e:
                    errors.append(str(e))

        return {
            "results": results,
            "errors": errors,
            "count": len(results)
        }

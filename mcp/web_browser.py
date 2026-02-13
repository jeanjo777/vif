"""
MCP Web Browser - Enhanced web navigation and scraping
With retry logic, cookie support, proxy support, and improved error handling
"""
from .base import MCPServer, MCPTool
from typing import Dict, Any, Optional, List
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlencode
import time
import json
import os


class WebBrowserMCP(MCPServer):
    """Enhanced Web Browser MCP Server - Navigate and scrape web pages with advanced features"""

    def __init__(self):
        super().__init__(
            name="web_browser",
            description="Enhanced web browser for navigation, scraping, and data extraction with retry logic and proxy support"
        )
        self._init_tools()
        self.current_url = None
        self.page_content = None
        self.cookies = {}
        self.history = []

        # Setup session with retry logic
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Default headers
        self.default_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9,fr;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        self.session.headers.update(self.default_headers)

        # Proxy support
        self.proxy = os.getenv('HTTP_PROXY') or os.getenv('HTTPS_PROXY')
        if self.proxy:
            self.session.proxies = {'http': self.proxy, 'https': self.proxy}

    def _init_tools(self):
        """Initialize all web browser tools"""

        # Tool 1: Navigate to URL
        self.register_tool(MCPTool(
            name="navigate",
            description="Navigate to a URL and get page content",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "The URL to navigate to"},
                    "extract_text": {"type": "boolean", "description": "Extract clean text", "default": True},
                    "timeout": {"type": "integer", "description": "Request timeout in seconds", "default": 15},
                    "follow_redirects": {"type": "boolean", "description": "Follow redirects", "default": True}
                },
                "required": ["url"]
            },
            handler=self._navigate
        ))

        # Tool 2: Extract links
        self.register_tool(MCPTool(
            name="extract_links",
            description="Extract all links from current page",
            parameters={
                "type": "object",
                "properties": {
                    "filter_external": {"type": "boolean", "description": "Filter out external links", "default": False},
                    "filter_pattern": {"type": "string", "description": "Only return links matching this pattern"}
                }
            },
            handler=self._extract_links
        ))

        # Tool 3: Search on page
        self.register_tool(MCPTool(
            name="search_page",
            description="Search for specific text on current page",
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Text to search for"},
                    "case_sensitive": {"type": "boolean", "default": False}
                },
                "required": ["query"]
            },
            handler=self._search_page
        ))

        # Tool 4: Get page metadata
        self.register_tool(MCPTool(
            name="get_metadata",
            description="Extract metadata (title, description, etc.) from current page",
            parameters={"type": "object", "properties": {}},
            handler=self._get_metadata
        ))

        # Tool 5: POST request
        self.register_tool(MCPTool(
            name="post_request",
            description="Send a POST request with form data or JSON",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to POST to"},
                    "data": {"type": "object", "description": "Form data to send"},
                    "json_data": {"type": "object", "description": "JSON data to send"},
                    "headers": {"type": "object", "description": "Additional headers"}
                },
                "required": ["url"]
            },
            handler=self._post_request
        ))

        # Tool 6: Set custom headers
        self.register_tool(MCPTool(
            name="set_headers",
            description="Set custom headers for subsequent requests",
            parameters={
                "type": "object",
                "properties": {
                    "headers": {"type": "object", "description": "Headers to set"}
                },
                "required": ["headers"]
            },
            handler=self._set_headers
        ))

        # Tool 7: Manage cookies
        self.register_tool(MCPTool(
            name="manage_cookies",
            description="Get, set, or clear cookies",
            parameters={
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["get", "set", "clear"], "default": "get"},
                    "cookies": {"type": "object", "description": "Cookies to set (for 'set' action)"}
                }
            },
            handler=self._manage_cookies
        ))

        # Tool 8: Download file
        self.register_tool(MCPTool(
            name="download",
            description="Download a file from URL",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL of file to download"},
                    "save_path": {"type": "string", "description": "Local path to save file"}
                },
                "required": ["url", "save_path"]
            },
            handler=self._download
        ))

        # Tool 9: Extract specific elements
        self.register_tool(MCPTool(
            name="extract_elements",
            description="Extract elements using CSS selectors",
            parameters={
                "type": "object",
                "properties": {
                    "selector": {"type": "string", "description": "CSS selector"},
                    "attribute": {"type": "string", "description": "Attribute to extract (default: text)"},
                    "limit": {"type": "integer", "description": "Max elements to return", "default": 50}
                },
                "required": ["selector"]
            },
            handler=self._extract_elements
        ))

        # Tool 10: Get browsing history
        self.register_tool(MCPTool(
            name="get_history",
            description="Get browsing history for this session",
            parameters={"type": "object", "properties": {}},
            handler=self._get_history
        ))

        # Tool 11: Web search (DuckDuckGo)
        self.register_tool(MCPTool(
            name="web_search",
            description="Search the web using DuckDuckGo",
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query"},
                    "max_results": {"type": "integer", "description": "Maximum results", "default": 10}
                },
                "required": ["query"]
            },
            handler=self._web_search
        ))

        # Tool 12: Check URL status
        self.register_tool(MCPTool(
            name="check_url",
            description="Check if a URL is accessible (HEAD request)",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to check"}
                },
                "required": ["url"]
            },
            handler=self._check_url
        ))

    def _navigate(self, url: str, extract_text: bool = True, timeout: int = 15, follow_redirects: bool = True) -> Dict[str, Any]:
        """Navigate to a URL with enhanced error handling"""
        try:
            start_time = time.time()
            response = self.session.get(
                url,
                timeout=timeout,
                allow_redirects=follow_redirects
            )
            response.raise_for_status()
            elapsed = time.time() - start_time

            self.current_url = response.url  # Final URL after redirects
            self.page_content = response.text
            self.history.append({
                "url": self.current_url,
                "status": response.status_code,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            })

            soup = BeautifulSoup(response.text, 'html.parser')

            # Remove script, style, and other non-content elements
            for element in soup(["script", "style", "nav", "footer", "aside", "noscript"]):
                element.decompose()

            result = {
                "success": True,
                "url": self.current_url,
                "original_url": url,
                "status_code": response.status_code,
                "title": soup.title.string.strip() if soup.title and soup.title.string else "No title",
                "content_type": response.headers.get('Content-Type', ''),
                "response_time_ms": int(elapsed * 1000),
                "redirected": url != self.current_url
            }

            if extract_text:
                text = soup.get_text(separator='\n')
                lines = [line.strip() for line in text.splitlines() if line.strip()]
                text = '\n'.join(lines)
                result["text"] = text[:12000]  # Limit to 12k chars
                result["text_length"] = len(text)

            return result

        except requests.exceptions.Timeout:
            return {"error": f"Timeout after {timeout}s", "url": url}
        except requests.exceptions.TooManyRedirects:
            return {"error": "Too many redirects", "url": url}
        except requests.exceptions.HTTPError as e:
            return {"error": f"HTTP {e.response.status_code}: {e.response.reason}", "url": url}
        except requests.exceptions.ConnectionError:
            return {"error": "Connection failed - check URL or network", "url": url}
        except Exception as e:
            return {"error": str(e), "url": url}

    def _extract_links(self, filter_external: bool = False, filter_pattern: str = None) -> Dict[str, Any]:
        """Extract all links from current page"""
        if not self.current_url or not self.page_content:
            return {"error": "No page loaded. Use navigate first."}

        try:
            soup = BeautifulSoup(self.page_content, 'html.parser')
            current_domain = urlparse(self.current_url).netloc

            links = []
            for link in soup.find_all('a', href=True):
                href = link['href']
                absolute_url = urljoin(self.current_url, href)
                link_domain = urlparse(absolute_url).netloc

                # Filter external links
                if filter_external and link_domain != current_domain:
                    continue

                # Filter by pattern
                if filter_pattern and filter_pattern.lower() not in absolute_url.lower():
                    continue

                link_text = link.get_text().strip()
                if link_text or absolute_url:  # Only add if has text or valid URL
                    links.append({
                        "text": link_text[:100] if link_text else "[No text]",
                        "url": absolute_url,
                        "external": link_domain != current_domain
                    })

            # Remove duplicates
            seen = set()
            unique_links = []
            for link in links:
                if link['url'] not in seen:
                    seen.add(link['url'])
                    unique_links.append(link)

            return {
                "success": True,
                "links": unique_links[:200],  # Limit to 200
                "count": len(unique_links),
                "filtered": len(links) - len(unique_links)
            }

        except Exception as e:
            return {"error": str(e)}

    def _search_page(self, query: str, case_sensitive: bool = False) -> Dict[str, Any]:
        """Search for text on current page"""
        if not self.page_content:
            return {"error": "No page loaded. Use navigate first."}

        try:
            soup = BeautifulSoup(self.page_content, 'html.parser')
            text = soup.get_text()

            search_text = text if case_sensitive else text.lower()
            search_query = query if case_sensitive else query.lower()

            count = search_text.count(search_query)

            # Find context around matches
            contexts = []
            start = 0
            while len(contexts) < 5:
                pos = search_text.find(search_query, start)
                if pos == -1:
                    break

                context_start = max(0, pos - 80)
                context_end = min(len(text), pos + len(query) + 80)
                context = text[context_start:context_end].strip()
                contexts.append(f"...{context}...")

                start = pos + len(query)

            return {
                "success": True,
                "found": count > 0,
                "occurrences": count,
                "contexts": contexts,
                "query": query
            }

        except Exception as e:
            return {"error": str(e)}

    def _get_metadata(self) -> Dict[str, Any]:
        """Get page metadata"""
        if not self.page_content:
            return {"error": "No page loaded. Use navigate first."}

        try:
            soup = BeautifulSoup(self.page_content, 'html.parser')

            metadata = {
                "url": self.current_url,
                "title": soup.title.string.strip() if soup.title and soup.title.string else None,
            }

            # Extract meta tags
            for meta in soup.find_all('meta'):
                name = meta.get('name') or meta.get('property')
                content = meta.get('content')
                if name and content:
                    metadata[name] = content[:500]  # Limit content length

            # Extract canonical URL
            canonical = soup.find('link', rel='canonical')
            if canonical:
                metadata['canonical'] = canonical.get('href')

            # Extract Open Graph data
            og_data = {}
            for meta in soup.find_all('meta', property=lambda x: x and x.startswith('og:')):
                og_data[meta['property']] = meta.get('content')
            if og_data:
                metadata['open_graph'] = og_data

            return {"success": True, "metadata": metadata}

        except Exception as e:
            return {"error": str(e)}

    def _post_request(self, url: str, data: Dict = None, json_data: Dict = None, headers: Dict = None) -> Dict[str, Any]:
        """Send POST request"""
        try:
            request_headers = dict(self.session.headers)
            if headers:
                request_headers.update(headers)

            if json_data:
                response = self.session.post(url, json=json_data, headers=request_headers, timeout=15)
            else:
                response = self.session.post(url, data=data, headers=request_headers, timeout=15)

            return {
                "success": True,
                "status_code": response.status_code,
                "url": response.url,
                "content_type": response.headers.get('Content-Type', ''),
                "response": response.text[:5000]
            }

        except Exception as e:
            return {"error": str(e)}

    def _set_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Set custom headers"""
        self.session.headers.update(headers)
        return {
            "success": True,
            "current_headers": dict(self.session.headers)
        }

    def _manage_cookies(self, action: str = "get", cookies: Dict = None) -> Dict[str, Any]:
        """Manage cookies"""
        if action == "get":
            return {
                "success": True,
                "cookies": dict(self.session.cookies)
            }
        elif action == "set" and cookies:
            for name, value in cookies.items():
                self.session.cookies.set(name, value)
            return {"success": True, "message": f"Set {len(cookies)} cookies"}
        elif action == "clear":
            self.session.cookies.clear()
            return {"success": True, "message": "Cookies cleared"}
        else:
            return {"error": "Invalid action or missing cookies"}

    def _download(self, url: str, save_path: str) -> Dict[str, Any]:
        """Download file"""
        try:
            response = self.session.get(url, stream=True, timeout=60)
            response.raise_for_status()

            with open(save_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            return {
                "success": True,
                "saved_to": save_path,
                "size_bytes": os.path.getsize(save_path),
                "content_type": response.headers.get('Content-Type', '')
            }

        except Exception as e:
            return {"error": str(e)}

    def _extract_elements(self, selector: str, attribute: str = None, limit: int = 50) -> Dict[str, Any]:
        """Extract elements using CSS selector"""
        if not self.page_content:
            return {"error": "No page loaded. Use navigate first."}

        try:
            soup = BeautifulSoup(self.page_content, 'html.parser')
            elements = soup.select(selector)[:limit]

            results = []
            for el in elements:
                if attribute:
                    value = el.get(attribute)
                else:
                    value = el.get_text().strip()

                if value:
                    results.append(value[:500])

            return {
                "success": True,
                "selector": selector,
                "elements": results,
                "count": len(results)
            }

        except Exception as e:
            return {"error": str(e)}

    def _get_history(self) -> Dict[str, Any]:
        """Get browsing history"""
        return {
            "success": True,
            "history": self.history[-50:],  # Last 50 entries
            "total_pages": len(self.history)
        }

    def _web_search(self, query: str, max_results: int = 10) -> Dict[str, Any]:
        """Web search using DuckDuckGo"""
        try:
            from duckduckgo_search import DDGS

            ddgs = DDGS()
            results = list(ddgs.text(query, max_results=max_results))

            return {
                "success": True,
                "query": query,
                "results": results,
                "count": len(results)
            }

        except ImportError:
            return {"error": "duckduckgo-search not installed"}
        except Exception as e:
            return {"error": str(e)}

    def _check_url(self, url: str) -> Dict[str, Any]:
        """Check if URL is accessible"""
        try:
            response = self.session.head(url, timeout=10, allow_redirects=True)
            return {
                "success": True,
                "url": url,
                "final_url": response.url,
                "status_code": response.status_code,
                "accessible": response.status_code < 400,
                "content_type": response.headers.get('Content-Type', ''),
                "content_length": response.headers.get('Content-Length', 'unknown')
            }

        except Exception as e:
            return {"error": str(e), "accessible": False}

"""
MCP Web Browser - Interactive web navigation and scraping
"""
from .base import MCPServer, MCPTool
from typing import Dict, Any
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


class WebBrowserMCP(MCPServer):
    """Web Browser MCP Server - Navigate and scrape web pages"""

    def __init__(self):
        super().__init__(
            name="web_browser",
            description="Interactive web browser for navigation, scraping, and data extraction"
        )
        self._init_tools()
        self.current_url = None
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def _init_tools(self):
        """Initialize all web browser tools"""

        # Tool 1: Navigate to URL
        self.register_tool(MCPTool(
            name="navigate",
            description="Navigate to a URL and get page content",
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The URL to navigate to"
                    },
                    "extract_text": {
                        "type": "boolean",
                        "description": "Whether to extract clean text (default: true)",
                        "default": True
                    }
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
                    "filter_external": {
                        "type": "boolean",
                        "description": "Filter out external links",
                        "default": False
                    }
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
                    "query": {
                        "type": "string",
                        "description": "Text to search for"
                    }
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

    def _navigate(self, url: str, extract_text: bool = True) -> Dict[str, Any]:
        """Navigate to a URL"""
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()

            self.current_url = url
            soup = BeautifulSoup(response.text, 'html.parser')

            # Remove script and style elements
            for script in soup(["script", "style"]):
                script.decompose()

            result = {
                "url": url,
                "status_code": response.status_code,
                "title": soup.title.string if soup.title else "No title"
            }

            if extract_text:
                text = soup.get_text()
                lines = (line.strip() for line in text.splitlines())
                chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
                text = '\n'.join(chunk for chunk in chunks if chunk)
                result["text"] = text[:10000]  # Limit to 10k chars

            return result

        except Exception as e:
            return {"error": str(e)}

    def _extract_links(self, filter_external: bool = False) -> Dict[str, Any]:
        """Extract all links from current page"""
        if not self.current_url:
            return {"error": "No page loaded. Use navigate first."}

        try:
            response = self.session.get(self.current_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')

            links = []
            for link in soup.find_all('a', href=True):
                href = link['href']
                absolute_url = urljoin(self.current_url, href)

                if filter_external:
                    current_domain = urlparse(self.current_url).netloc
                    link_domain = urlparse(absolute_url).netloc
                    if current_domain != link_domain:
                        continue

                links.append({
                    "text": link.get_text().strip(),
                    "url": absolute_url
                })

            return {"links": links, "count": len(links)}

        except Exception as e:
            return {"error": str(e)}

    def _search_page(self, query: str) -> Dict[str, Any]:
        """Search for text on current page"""
        if not self.current_url:
            return {"error": "No page loaded. Use navigate first."}

        try:
            response = self.session.get(self.current_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            text = soup.get_text().lower()

            query_lower = query.lower()
            count = text.count(query_lower)

            # Find context around matches
            contexts = []
            start = 0
            while True:
                pos = text.find(query_lower, start)
                if pos == -1:
                    break

                context_start = max(0, pos - 100)
                context_end = min(len(text), pos + len(query) + 100)
                context = text[context_start:context_end]
                contexts.append(f"...{context}...")

                start = pos + len(query)
                if len(contexts) >= 5:  # Limit to 5 contexts
                    break

            return {
                "found": count > 0,
                "occurrences": count,
                "contexts": contexts
            }

        except Exception as e:
            return {"error": str(e)}

    def _get_metadata(self) -> Dict[str, Any]:
        """Get page metadata"""
        if not self.current_url:
            return {"error": "No page loaded. Use navigate first."}

        try:
            response = self.session.get(self.current_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')

            metadata = {
                "url": self.current_url,
                "title": soup.title.string if soup.title else None,
            }

            # Extract meta tags
            for meta in soup.find_all('meta'):
                if meta.get('name'):
                    metadata[meta['name']] = meta.get('content')
                elif meta.get('property'):
                    metadata[meta['property']] = meta.get('content')

            return metadata

        except Exception as e:
            return {"error": str(e)}

"""
MCP Scraping API - External scraping services integration
Supports ScrapingBee, Browserless.io, and ScraperAPI as fallbacks
"""
from .base import MCPServer, MCPTool
from typing import Dict, Any, Optional
import requests
import os
import json
from urllib.parse import urlencode


class ScrapingAPIMCP(MCPServer):
    """Scraping API MCP Server - Use external services for reliable web scraping"""

    def __init__(self):
        super().__init__(
            name="scraping_api",
            description="External scraping services for reliable web access (ScrapingBee, Browserless, ScraperAPI)"
        )
        self._init_tools()

        # API Keys from environment
        self.scrapingbee_key = os.getenv('SCRAPINGBEE_API_KEY')
        self.browserless_key = os.getenv('BROWSERLESS_API_KEY')
        self.scraperapi_key = os.getenv('SCRAPERAPI_KEY')

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def _init_tools(self):
        """Initialize scraping API tools"""

        # Tool 1: Smart Scrape (auto-selects best available API)
        self.register_tool(MCPTool(
            name="smart_scrape",
            description="Scrape a URL using the best available API service",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to scrape"},
                    "render_js": {"type": "boolean", "description": "Render JavaScript", "default": True},
                    "premium_proxy": {"type": "boolean", "description": "Use premium proxy for difficult sites", "default": False},
                    "wait_time": {"type": "integer", "description": "Wait time in ms for JS rendering", "default": 2000}
                },
                "required": ["url"]
            },
            handler=self._smart_scrape
        ))

        # Tool 2: ScrapingBee
        self.register_tool(MCPTool(
            name="scrapingbee",
            description="Scrape using ScrapingBee API",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to scrape"},
                    "render_js": {"type": "boolean", "default": True},
                    "extract_rules": {"type": "object", "description": "CSS selectors to extract specific data"},
                    "screenshot": {"type": "boolean", "description": "Take screenshot", "default": False},
                    "block_ads": {"type": "boolean", "default": True}
                },
                "required": ["url"]
            },
            handler=self._scrapingbee
        ))

        # Tool 3: Browserless
        self.register_tool(MCPTool(
            name="browserless",
            description="Scrape using Browserless.io headless Chrome",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to scrape"},
                    "wait_for": {"type": "string", "description": "CSS selector to wait for"},
                    "screenshot": {"type": "boolean", "default": False},
                    "pdf": {"type": "boolean", "description": "Generate PDF", "default": False}
                },
                "required": ["url"]
            },
            handler=self._browserless
        ))

        # Tool 4: ScraperAPI
        self.register_tool(MCPTool(
            name="scraperapi",
            description="Scrape using ScraperAPI",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to scrape"},
                    "render": {"type": "boolean", "description": "Enable JS rendering", "default": True},
                    "country_code": {"type": "string", "description": "Country code for geo-targeting"},
                    "keep_headers": {"type": "boolean", "default": False}
                },
                "required": ["url"]
            },
            handler=self._scraperapi
        ))

        # Tool 5: Google Search via API
        self.register_tool(MCPTool(
            name="google_search",
            description="Perform Google search via scraping API",
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query"},
                    "num_results": {"type": "integer", "description": "Number of results", "default": 10},
                    "country": {"type": "string", "description": "Country code (us, fr, etc.)", "default": "us"}
                },
                "required": ["query"]
            },
            handler=self._google_search
        ))

        # Tool 6: Extract structured data
        self.register_tool(MCPTool(
            name="extract_data",
            description="Extract structured data from a page using CSS selectors",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to scrape"},
                    "selectors": {
                        "type": "object",
                        "description": "Named CSS selectors to extract",
                        "additionalProperties": {"type": "string"}
                    }
                },
                "required": ["url", "selectors"]
            },
            handler=self._extract_data
        ))

        # Tool 7: Check API status
        self.register_tool(MCPTool(
            name="check_apis",
            description="Check which scraping APIs are configured and available",
            parameters={"type": "object", "properties": {}},
            handler=self._check_apis
        ))

    def _get_available_api(self) -> Optional[str]:
        """Get the first available API"""
        if self.scrapingbee_key:
            return "scrapingbee"
        if self.browserless_key:
            return "browserless"
        if self.scraperapi_key:
            return "scraperapi"
        return None

    def _smart_scrape(self, url: str, render_js: bool = True, premium_proxy: bool = False, wait_time: int = 2000) -> Dict[str, Any]:
        """Smart scrape using best available API"""
        api = self._get_available_api()

        if not api:
            # Fallback to simple requests
            return self._fallback_scrape(url)

        if api == "scrapingbee":
            return self._scrapingbee(url, render_js=render_js)
        elif api == "browserless":
            return self._browserless(url)
        elif api == "scraperapi":
            return self._scraperapi(url, render=render_js)

        return {"error": "No API available"}

    def _fallback_scrape(self, url: str) -> Dict[str, Any]:
        """Fallback scraping using requests + BeautifulSoup"""
        try:
            from bs4 import BeautifulSoup
            response = self.session.get(url, timeout=15)
            response.raise_for_status()

            soup = BeautifulSoup(response.text, 'html.parser')
            for script in soup(["script", "style"]):
                script.decompose()

            text = soup.get_text()
            lines = (line.strip() for line in text.splitlines())
            text = '\n'.join(line for line in lines if line)

            return {
                "success": True,
                "url": url,
                "title": soup.title.string if soup.title else None,
                "content": text[:15000],
                "method": "fallback_requests"
            }
        except Exception as e:
            return {"error": str(e), "method": "fallback_requests"}

    def _scrapingbee(self, url: str, render_js: bool = True, extract_rules: Dict = None,
                     screenshot: bool = False, block_ads: bool = True) -> Dict[str, Any]:
        """Scrape using ScrapingBee"""
        if not self.scrapingbee_key:
            return {"error": "SCRAPINGBEE_API_KEY not configured"}

        try:
            params = {
                'api_key': self.scrapingbee_key,
                'url': url,
                'render_js': str(render_js).lower(),
                'block_ads': str(block_ads).lower()
            }

            if extract_rules:
                params['extract_rules'] = json.dumps(extract_rules)

            if screenshot:
                params['screenshot'] = 'true'

            response = requests.get(
                'https://app.scrapingbee.com/api/v1/',
                params=params,
                timeout=60
            )

            if response.status_code == 200:
                return {
                    "success": True,
                    "url": url,
                    "content": response.text[:15000],
                    "method": "scrapingbee"
                }
            else:
                return {"error": f"ScrapingBee error: {response.status_code}", "details": response.text}

        except Exception as e:
            return {"error": str(e), "method": "scrapingbee"}

    def _browserless(self, url: str, wait_for: str = None, screenshot: bool = False, pdf: bool = False) -> Dict[str, Any]:
        """Scrape using Browserless.io"""
        if not self.browserless_key:
            return {"error": "BROWSERLESS_API_KEY not configured"}

        try:
            if screenshot:
                endpoint = f"https://chrome.browserless.io/screenshot?token={self.browserless_key}"
                payload = {"url": url, "options": {"fullPage": True}}
            elif pdf:
                endpoint = f"https://chrome.browserless.io/pdf?token={self.browserless_key}"
                payload = {"url": url}
            else:
                endpoint = f"https://chrome.browserless.io/content?token={self.browserless_key}"
                payload = {"url": url}
                if wait_for:
                    payload["waitForSelector"] = {"selector": wait_for}

            response = requests.post(
                endpoint,
                json=payload,
                timeout=60
            )

            if response.status_code == 200:
                if screenshot or pdf:
                    import base64
                    return {
                        "success": True,
                        "url": url,
                        "data_base64": base64.b64encode(response.content).decode(),
                        "method": "browserless"
                    }
                else:
                    return {
                        "success": True,
                        "url": url,
                        "content": response.text[:15000],
                        "method": "browserless"
                    }
            else:
                return {"error": f"Browserless error: {response.status_code}"}

        except Exception as e:
            return {"error": str(e), "method": "browserless"}

    def _scraperapi(self, url: str, render: bool = True, country_code: str = None, keep_headers: bool = False) -> Dict[str, Any]:
        """Scrape using ScraperAPI"""
        if not self.scraperapi_key:
            return {"error": "SCRAPERAPI_KEY not configured"}

        try:
            params = {
                'api_key': self.scraperapi_key,
                'url': url,
                'render': str(render).lower()
            }

            if country_code:
                params['country_code'] = country_code
            if keep_headers:
                params['keep_headers'] = 'true'

            response = requests.get(
                'http://api.scraperapi.com',
                params=params,
                timeout=60
            )

            if response.status_code == 200:
                return {
                    "success": True,
                    "url": url,
                    "content": response.text[:15000],
                    "method": "scraperapi"
                }
            else:
                return {"error": f"ScraperAPI error: {response.status_code}"}

        except Exception as e:
            return {"error": str(e), "method": "scraperapi"}

    def _google_search(self, query: str, num_results: int = 10, country: str = "us") -> Dict[str, Any]:
        """Google search via ScrapingBee"""
        if self.scrapingbee_key:
            try:
                params = {
                    'api_key': self.scrapingbee_key,
                    'search': query,
                    'nb_results': num_results,
                    'country_code': country
                }

                response = requests.get(
                    'https://app.scrapingbee.com/api/v1/',
                    params=params,
                    timeout=30
                )

                if response.status_code == 200:
                    return {
                        "success": True,
                        "query": query,
                        "results": response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text,
                        "method": "scrapingbee_search"
                    }
            except Exception as e:
                pass

        # Fallback to DuckDuckGo
        try:
            from duckduckgo_search import DDGS
            ddgs = DDGS()
            results = list(ddgs.text(query, max_results=num_results))
            return {
                "success": True,
                "query": query,
                "results": results,
                "method": "duckduckgo_fallback"
            }
        except Exception as e:
            return {"error": str(e)}

    def _extract_data(self, url: str, selectors: Dict[str, str]) -> Dict[str, Any]:
        """Extract structured data using CSS selectors"""
        if self.scrapingbee_key:
            # Use ScrapingBee's extract_rules feature
            extract_rules = {}
            for name, selector in selectors.items():
                extract_rules[name] = {"selector": selector, "type": "text"}

            return self._scrapingbee(url, extract_rules=extract_rules)

        # Fallback to BeautifulSoup
        try:
            from bs4 import BeautifulSoup
            response = self.session.get(url, timeout=15)
            soup = BeautifulSoup(response.text, 'html.parser')

            data = {}
            for name, selector in selectors.items():
                elements = soup.select(selector)
                if elements:
                    data[name] = [el.get_text().strip() for el in elements]
                else:
                    data[name] = None

            return {
                "success": True,
                "url": url,
                "data": data,
                "method": "beautifulsoup"
            }
        except Exception as e:
            return {"error": str(e)}

    def _check_apis(self) -> Dict[str, Any]:
        """Check available APIs"""
        return {
            "scrapingbee": {
                "configured": bool(self.scrapingbee_key),
                "key_preview": f"{self.scrapingbee_key[:8]}..." if self.scrapingbee_key else None
            },
            "browserless": {
                "configured": bool(self.browserless_key),
                "key_preview": f"{self.browserless_key[:8]}..." if self.browserless_key else None
            },
            "scraperapi": {
                "configured": bool(self.scraperapi_key),
                "key_preview": f"{self.scraperapi_key[:8]}..." if self.scraperapi_key else None
            },
            "fallback": "requests + BeautifulSoup (always available)"
        }

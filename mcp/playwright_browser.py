"""
MCP Playwright Browser - Advanced web automation with full JavaScript support
Works on Railway and other cloud platforms
"""
from .base import MCPServer, MCPTool
from typing import Dict, Any, Optional
import asyncio
import json

# Playwright import with fallback
try:
    from playwright.async_api import async_playwright, Browser, Page
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    async_playwright = None


class PlaywrightBrowserMCP(MCPServer):
    """Playwright Browser MCP Server - Full web automation with JS support"""

    def __init__(self):
        super().__init__(
            name="playwright_browser",
            description="Advanced web browser with JavaScript support, screenshots, and full automation"
        )
        self._init_tools()
        self.browser: Optional[Browser] = None
        self.page: Optional[Page] = None
        self.playwright = None

    def _init_tools(self):
        """Initialize all playwright browser tools"""

        # Tool 1: Navigate to URL
        self.register_tool(MCPTool(
            name="navigate",
            description="Navigate to a URL with full JavaScript rendering",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "The URL to navigate to"},
                    "wait_for": {"type": "string", "description": "Wait condition: 'load', 'domcontentloaded', 'networkidle'", "default": "domcontentloaded"},
                    "timeout": {"type": "integer", "description": "Timeout in milliseconds", "default": 30000}
                },
                "required": ["url"]
            },
            handler=self._navigate
        ))

        # Tool 2: Get page content
        self.register_tool(MCPTool(
            name="get_content",
            description="Get the full text content of the current page",
            parameters={
                "type": "object",
                "properties": {
                    "selector": {"type": "string", "description": "CSS selector to extract specific content (optional)"}
                }
            },
            handler=self._get_content
        ))

        # Tool 3: Screenshot
        self.register_tool(MCPTool(
            name="screenshot",
            description="Take a screenshot of the current page",
            parameters={
                "type": "object",
                "properties": {
                    "full_page": {"type": "boolean", "description": "Capture full page or viewport only", "default": False},
                    "selector": {"type": "string", "description": "CSS selector to screenshot specific element"}
                }
            },
            handler=self._screenshot
        ))

        # Tool 4: Click element
        self.register_tool(MCPTool(
            name="click",
            description="Click on an element",
            parameters={
                "type": "object",
                "properties": {
                    "selector": {"type": "string", "description": "CSS selector of element to click"}
                },
                "required": ["selector"]
            },
            handler=self._click
        ))

        # Tool 5: Type text
        self.register_tool(MCPTool(
            name="type_text",
            description="Type text into an input field",
            parameters={
                "type": "object",
                "properties": {
                    "selector": {"type": "string", "description": "CSS selector of input field"},
                    "text": {"type": "string", "description": "Text to type"},
                    "clear": {"type": "boolean", "description": "Clear field before typing", "default": True}
                },
                "required": ["selector", "text"]
            },
            handler=self._type_text
        ))

        # Tool 6: Execute JavaScript
        self.register_tool(MCPTool(
            name="execute_js",
            description="Execute JavaScript code on the page",
            parameters={
                "type": "object",
                "properties": {
                    "script": {"type": "string", "description": "JavaScript code to execute"}
                },
                "required": ["script"]
            },
            handler=self._execute_js
        ))

        # Tool 7: Get all links
        self.register_tool(MCPTool(
            name="get_links",
            description="Extract all links from the current page",
            parameters={
                "type": "object",
                "properties": {
                    "filter_domain": {"type": "string", "description": "Only return links from this domain"}
                }
            },
            handler=self._get_links
        ))

        # Tool 8: Wait for element
        self.register_tool(MCPTool(
            name="wait_for",
            description="Wait for an element to appear on the page",
            parameters={
                "type": "object",
                "properties": {
                    "selector": {"type": "string", "description": "CSS selector to wait for"},
                    "timeout": {"type": "integer", "description": "Timeout in milliseconds", "default": 10000}
                },
                "required": ["selector"]
            },
            handler=self._wait_for
        ))

        # Tool 9: Fill form
        self.register_tool(MCPTool(
            name="fill_form",
            description="Fill multiple form fields at once",
            parameters={
                "type": "object",
                "properties": {
                    "fields": {
                        "type": "object",
                        "description": "Object with selector:value pairs",
                        "additionalProperties": {"type": "string"}
                    },
                    "submit_selector": {"type": "string", "description": "CSS selector of submit button (optional)"}
                },
                "required": ["fields"]
            },
            handler=self._fill_form
        ))

        # Tool 10: Scroll page
        self.register_tool(MCPTool(
            name="scroll",
            description="Scroll the page",
            parameters={
                "type": "object",
                "properties": {
                    "direction": {"type": "string", "enum": ["up", "down", "top", "bottom"], "default": "down"},
                    "amount": {"type": "integer", "description": "Pixels to scroll (for up/down)", "default": 500}
                }
            },
            handler=self._scroll
        ))

    async def _ensure_browser(self) -> bool:
        """Ensure browser is initialized"""
        if not PLAYWRIGHT_AVAILABLE:
            return False

        if self.browser is None:
            try:
                self.playwright = await async_playwright().start()
                self.browser = await self.playwright.chromium.launch(
                    headless=True,
                    args=['--no-sandbox', '--disable-dev-shm-usage']
                )
                self.page = await self.browser.new_page()
                return True
            except Exception as e:
                print(f"Failed to start browser: {e}")
                return False
        return True

    def _run_async(self, coro):
        """Run async coroutine in sync context"""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro)

    def _navigate(self, url: str, wait_for: str = "domcontentloaded", timeout: int = 30000) -> Dict[str, Any]:
        """Navigate to a URL"""
        if not PLAYWRIGHT_AVAILABLE:
            return {"error": "Playwright not installed. Run: pip install playwright && playwright install chromium"}

        async def _nav():
            if not await self._ensure_browser():
                return {"error": "Failed to initialize browser"}

            try:
                response = await self.page.goto(url, wait_until=wait_for, timeout=timeout)
                title = await self.page.title()
                return {
                    "success": True,
                    "url": self.page.url,
                    "title": title,
                    "status": response.status if response else None
                }
            except Exception as e:
                return {"error": str(e)}

        return self._run_async(_nav())

    def _get_content(self, selector: str = None) -> Dict[str, Any]:
        """Get page content"""
        if not PLAYWRIGHT_AVAILABLE:
            return {"error": "Playwright not installed"}

        async def _content():
            if self.page is None:
                return {"error": "No page loaded. Use navigate first."}

            try:
                if selector:
                    element = await self.page.query_selector(selector)
                    if element:
                        text = await element.inner_text()
                    else:
                        return {"error": f"Element not found: {selector}"}
                else:
                    text = await self.page.inner_text("body")

                return {
                    "url": self.page.url,
                    "content": text[:15000]  # Limit to 15k chars
                }
            except Exception as e:
                return {"error": str(e)}

        return self._run_async(_content())

    def _screenshot(self, full_page: bool = False, selector: str = None) -> Dict[str, Any]:
        """Take screenshot"""
        if not PLAYWRIGHT_AVAILABLE:
            return {"error": "Playwright not installed"}

        async def _screen():
            if self.page is None:
                return {"error": "No page loaded. Use navigate first."}

            try:
                import base64
                if selector:
                    element = await self.page.query_selector(selector)
                    if element:
                        screenshot = await element.screenshot()
                    else:
                        return {"error": f"Element not found: {selector}"}
                else:
                    screenshot = await self.page.screenshot(full_page=full_page)

                b64 = base64.b64encode(screenshot).decode()
                return {
                    "success": True,
                    "screenshot_base64": b64,
                    "format": "png"
                }
            except Exception as e:
                return {"error": str(e)}

        return self._run_async(_screen())

    def _click(self, selector: str) -> Dict[str, Any]:
        """Click element"""
        if not PLAYWRIGHT_AVAILABLE:
            return {"error": "Playwright not installed"}

        async def _do_click():
            if self.page is None:
                return {"error": "No page loaded. Use navigate first."}

            try:
                await self.page.click(selector)
                return {"success": True, "clicked": selector}
            except Exception as e:
                return {"error": str(e)}

        return self._run_async(_do_click())

    def _type_text(self, selector: str, text: str, clear: bool = True) -> Dict[str, Any]:
        """Type text into input"""
        if not PLAYWRIGHT_AVAILABLE:
            return {"error": "Playwright not installed"}

        async def _do_type():
            if self.page is None:
                return {"error": "No page loaded. Use navigate first."}

            try:
                if clear:
                    await self.page.fill(selector, text)
                else:
                    await self.page.type(selector, text)
                return {"success": True, "typed": text, "into": selector}
            except Exception as e:
                return {"error": str(e)}

        return self._run_async(_do_type())

    def _execute_js(self, script: str) -> Dict[str, Any]:
        """Execute JavaScript"""
        if not PLAYWRIGHT_AVAILABLE:
            return {"error": "Playwright not installed"}

        async def _do_js():
            if self.page is None:
                return {"error": "No page loaded. Use navigate first."}

            try:
                result = await self.page.evaluate(script)
                return {"success": True, "result": result}
            except Exception as e:
                return {"error": str(e)}

        return self._run_async(_do_js())

    def _get_links(self, filter_domain: str = None) -> Dict[str, Any]:
        """Get all links from page"""
        if not PLAYWRIGHT_AVAILABLE:
            return {"error": "Playwright not installed"}

        async def _do_links():
            if self.page is None:
                return {"error": "No page loaded. Use navigate first."}

            try:
                links = await self.page.evaluate('''() => {
                    return Array.from(document.querySelectorAll('a[href]')).map(a => ({
                        text: a.innerText.trim(),
                        href: a.href
                    })).filter(l => l.href && l.href.startsWith('http'));
                }''')

                if filter_domain:
                    links = [l for l in links if filter_domain in l['href']]

                return {"links": links[:100], "count": len(links)}  # Limit to 100
            except Exception as e:
                return {"error": str(e)}

        return self._run_async(_do_links())

    def _wait_for(self, selector: str, timeout: int = 10000) -> Dict[str, Any]:
        """Wait for element"""
        if not PLAYWRIGHT_AVAILABLE:
            return {"error": "Playwright not installed"}

        async def _do_wait():
            if self.page is None:
                return {"error": "No page loaded. Use navigate first."}

            try:
                await self.page.wait_for_selector(selector, timeout=timeout)
                return {"success": True, "found": selector}
            except Exception as e:
                return {"error": str(e)}

        return self._run_async(_do_wait())

    def _fill_form(self, fields: Dict[str, str], submit_selector: str = None) -> Dict[str, Any]:
        """Fill form fields"""
        if not PLAYWRIGHT_AVAILABLE:
            return {"error": "Playwright not installed"}

        async def _do_fill():
            if self.page is None:
                return {"error": "No page loaded. Use navigate first."}

            try:
                filled = []
                for selector, value in fields.items():
                    await self.page.fill(selector, value)
                    filled.append(selector)

                if submit_selector:
                    await self.page.click(submit_selector)

                return {
                    "success": True,
                    "filled_fields": filled,
                    "submitted": submit_selector is not None
                }
            except Exception as e:
                return {"error": str(e)}

        return self._run_async(_do_fill())

    def _scroll(self, direction: str = "down", amount: int = 500) -> Dict[str, Any]:
        """Scroll page"""
        if not PLAYWRIGHT_AVAILABLE:
            return {"error": "Playwright not installed"}

        async def _do_scroll():
            if self.page is None:
                return {"error": "No page loaded. Use navigate first."}

            try:
                if direction == "top":
                    await self.page.evaluate("window.scrollTo(0, 0)")
                elif direction == "bottom":
                    await self.page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                elif direction == "up":
                    await self.page.evaluate(f"window.scrollBy(0, -{amount})")
                else:  # down
                    await self.page.evaluate(f"window.scrollBy(0, {amount})")

                return {"success": True, "scrolled": direction}
            except Exception as e:
                return {"error": str(e)}

        return self._run_async(_do_scroll())

    async def cleanup(self):
        """Clean up browser resources"""
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()

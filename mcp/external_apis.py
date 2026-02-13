"""
MCP External APIs - Integration with external services
"""
from .base import MCPServer, MCPTool
from typing import Dict, Any
import requests
from datetime import datetime


class ExternalAPIsMCP(MCPServer):
    """External APIs MCP Server - Access weather, news, crypto, and more"""

    def __init__(self):
        super().__init__(
            name="external_apis",
            description="Access external APIs: weather, news, crypto prices, translations"
        )
        self._init_tools()

    def _init_tools(self):
        """Initialize all external API tools"""

        # Tool 1: Get weather
        self.register_tool(MCPTool(
            name="get_weather",
            description="Get current weather for a location",
            parameters={
                "type": "object",
                "properties": {
                    "location": {
                        "type": "string",
                        "description": "City name or coordinates (lat,lon)"
                    }
                },
                "required": ["location"]
            },
            handler=self._get_weather
        ))

        # Tool 2: Get crypto price
        self.register_tool(MCPTool(
            name="get_crypto_price",
            description="Get current cryptocurrency prices",
            parameters={
                "type": "object",
                "properties": {
                    "symbol": {
                        "type": "string",
                        "description": "Crypto symbol (e.g., BTC, ETH)"
                    },
                    "currency": {
                        "type": "string",
                        "description": "Target currency (default: USD)",
                        "default": "USD"
                    }
                },
                "required": ["symbol"]
            },
            handler=self._get_crypto_price
        ))

        # Tool 3: Get news
        self.register_tool(MCPTool(
            name="get_news",
            description="Get latest news headlines",
            parameters={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query for news"
                    },
                    "country": {
                        "type": "string",
                        "description": "Country code (e.g., us, fr, gb)",
                        "default": "us"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Number of articles (default: 5)",
                        "default": 5
                    }
                }
            },
            handler=self._get_news
        ))

        # Tool 4: Translate text
        self.register_tool(MCPTool(
            name="translate",
            description="Translate text between languages",
            parameters={
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "Text to translate"
                    },
                    "target_lang": {
                        "type": "string",
                        "description": "Target language code (e.g., en, fr, es)"
                    },
                    "source_lang": {
                        "type": "string",
                        "description": "Source language (auto-detect if not specified)"
                    }
                },
                "required": ["text", "target_lang"]
            },
            handler=self._translate
        ))

        # Tool 5: Get time
        self.register_tool(MCPTool(
            name="get_time",
            description="Get current time for a timezone",
            parameters={
                "type": "object",
                "properties": {
                    "timezone": {
                        "type": "string",
                        "description": "Timezone (e.g., America/New_York, Europe/Paris)",
                        "default": "UTC"
                    }
                }
            },
            handler=self._get_time
        ))

    def _get_weather(self, location: str) -> Dict[str, Any]:
        """Get weather using wttr.in (free, no API key)"""
        try:
            # Use wttr.in API
            url = f"https://wttr.in/{location}?format=j1"
            response = requests.get(url, timeout=10)
            response.raise_for_status()

            data = response.json()
            current = data['current_condition'][0]

            return {
                "location": location,
                "temperature_c": current['temp_C'],
                "temperature_f": current['temp_F'],
                "feels_like_c": current['FeelsLikeC'],
                "feels_like_f": current['FeelsLikeF'],
                "humidity": current['humidity'],
                "description": current['weatherDesc'][0]['value'],
                "wind_kph": current['windspeedKmph'],
                "precipitation_mm": current['precipMM']
            }

        except Exception as e:
            return {"error": str(e)}

    def _get_crypto_price(self, symbol: str, currency: str = "USD") -> Dict[str, Any]:
        """Get crypto price from CoinGecko (free API)"""
        try:
            # Map common symbols to CoinGecko IDs
            symbol_map = {
                "BTC": "bitcoin",
                "ETH": "ethereum",
                "USDT": "tether",
                "BNB": "binancecoin",
                "SOL": "solana",
                "USDC": "usd-coin",
                "XRP": "ripple",
                "ADA": "cardano",
                "DOGE": "dogecoin",
                "TRX": "tron"
            }

            coin_id = symbol_map.get(symbol.upper(), symbol.lower())
            currency_lower = currency.lower()

            url = f"https://api.coingecko.com/api/v3/simple/price?ids={coin_id}&vs_currencies={currency_lower}&include_24hr_change=true"
            response = requests.get(url, timeout=10)
            response.raise_for_status()

            data = response.json()

            if coin_id not in data:
                return {"error": f"Cryptocurrency '{symbol}' not found"}

            price_data = data[coin_id]

            return {
                "symbol": symbol.upper(),
                "coin_id": coin_id,
                "price": price_data[currency_lower],
                "currency": currency.upper(),
                "change_24h": price_data.get(f'{currency_lower}_24h_change', 0)
            }

        except Exception as e:
            return {"error": str(e)}

    def _get_news(self, query: str = None, country: str = "us", limit: int = 5) -> Dict[str, Any]:
        """Get news headlines (using RSS feeds - no API key needed)"""
        try:
            # Use Google News RSS (free)
            if query:
                url = f"https://news.google.com/rss/search?q={query}&hl=en-{country.upper()}"
            else:
                url = f"https://news.google.com/rss?hl=en-{country.upper()}"

            response = requests.get(url, timeout=10)
            response.raise_for_status()

            # Parse RSS
            import xml.etree.ElementTree as ET
            root = ET.fromstring(response.content)

            articles = []
            for item in root.findall('.//item')[:limit]:
                title = item.find('title').text if item.find('title') is not None else ""
                link = item.find('link').text if item.find('link') is not None else ""
                pub_date = item.find('pubDate').text if item.find('pubDate') is not None else ""

                articles.append({
                    "title": title,
                    "url": link,
                    "published": pub_date
                })

            return {
                "query": query,
                "country": country,
                "articles": articles,
                "count": len(articles)
            }

        except Exception as e:
            return {"error": str(e)}

    def _translate(self, text: str, target_lang: str, source_lang: str = None) -> Dict[str, Any]:
        """Translate text using LibreTranslate (free)"""
        try:
            # Use LibreTranslate public instance
            url = "https://libretranslate.com/translate"

            payload = {
                "q": text,
                "target": target_lang,
                "format": "text"
            }

            if source_lang:
                payload["source"] = source_lang
            else:
                payload["source"] = "auto"

            response = requests.post(url, json=payload, timeout=15)
            response.raise_for_status()

            data = response.json()

            return {
                "original_text": text,
                "translated_text": data['translatedText'],
                "source_lang": source_lang or "auto",
                "target_lang": target_lang
            }

        except Exception as e:
            return {"error": str(e)}

    def _get_time(self, timezone: str = "UTC") -> Dict[str, Any]:
        """Get current time for timezone"""
        try:
            url = f"http://worldtimeapi.org/api/timezone/{timezone}"
            response = requests.get(url, timeout=10)
            response.raise_for_status()

            data = response.json()

            return {
                "timezone": timezone,
                "datetime": data['datetime'],
                "date": data['datetime'].split('T')[0],
                "time": data['datetime'].split('T')[1].split('.')[0],
                "utc_offset": data['utc_offset'],
                "day_of_week": data['day_of_week'],
                "day_of_year": data['day_of_year']
            }

        except Exception as e:
            return {"error": str(e)}

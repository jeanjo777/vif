"""
MCP Integration Hub - External service integrations
"""
from .base import MCPServer, MCPTool
from typing import Dict, Any
import requests
import json
import os
from datetime import datetime


class IntegrationHubMCP(MCPServer):
    """Integration Hub MCP Server - Slack, Email, Calendar, Notion, Discord"""

    def __init__(self):
        super().__init__(
            name="integration_hub",
            description="Integrations: Slack, Email, Google Calendar, Notion, Discord"
        )
        self._init_tools()

    def _init_tools(self):
        """Initialize all integration tools"""

        # Tool 1: Send Slack message
        self.register_tool(MCPTool(
            name="slack_send",
            description="Send message to Slack channel or user",
            parameters={
                "type": "object",
                "properties": {
                    "webhook_url": {
                        "type": "string",
                        "description": "Slack webhook URL"
                    },
                    "channel": {
                        "type": "string",
                        "description": "Channel name or ID"
                    },
                    "message": {
                        "type": "string",
                        "description": "Message text"
                    },
                    "username": {
                        "type": "string",
                        "description": "Bot username",
                        "default": "Vif AI"
                    },
                    "attachments": {
                        "type": "array",
                        "description": "Message attachments"
                    }
                },
                "required": ["message"]
            },
            handler=self._slack_send
        ))

        # Tool 2: Send email
        self.register_tool(MCPTool(
            name="send_email",
            description="Send email via SMTP or Gmail API",
            parameters={
                "type": "object",
                "properties": {
                    "to": {
                        "type": "string",
                        "description": "Recipient email address"
                    },
                    "subject": {
                        "type": "string",
                        "description": "Email subject"
                    },
                    "body": {
                        "type": "string",
                        "description": "Email body (HTML or plain text)"
                    },
                    "from_email": {
                        "type": "string",
                        "description": "Sender email address"
                    },
                    "cc": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "CC recipients"
                    },
                    "attachments": {
                        "type": "array",
                        "description": "File attachments"
                    }
                },
                "required": ["to", "subject", "body"]
            },
            handler=self._send_email
        ))

        # Tool 3: Create calendar event
        self.register_tool(MCPTool(
            name="calendar_event",
            description="Create Google Calendar or Outlook event",
            parameters={
                "type": "object",
                "properties": {
                    "service": {
                        "type": "string",
                        "description": "Calendar service",
                        "enum": ["google", "outlook"],
                        "default": "google"
                    },
                    "title": {
                        "type": "string",
                        "description": "Event title"
                    },
                    "start_time": {
                        "type": "string",
                        "description": "Start time (ISO 8601)"
                    },
                    "end_time": {
                        "type": "string",
                        "description": "End time (ISO 8601)"
                    },
                    "description": {
                        "type": "string",
                        "description": "Event description"
                    },
                    "location": {
                        "type": "string",
                        "description": "Event location"
                    },
                    "attendees": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Attendee email addresses"
                    }
                },
                "required": ["title", "start_time", "end_time"]
            },
            handler=self._calendar_event
        ))

        # Tool 4: Create Notion page
        self.register_tool(MCPTool(
            name="notion_create",
            description="Create page or database entry in Notion",
            parameters={
                "type": "object",
                "properties": {
                    "api_key": {
                        "type": "string",
                        "description": "Notion API key"
                    },
                    "database_id": {
                        "type": "string",
                        "description": "Target database ID"
                    },
                    "title": {
                        "type": "string",
                        "description": "Page title"
                    },
                    "content": {
                        "type": "string",
                        "description": "Page content (markdown)"
                    },
                    "properties": {
                        "type": "object",
                        "description": "Page properties"
                    }
                },
                "required": ["title"]
            },
            handler=self._notion_create
        ))

        # Tool 5: Discord webhook
        self.register_tool(MCPTool(
            name="discord_webhook",
            description="Send message via Discord webhook",
            parameters={
                "type": "object",
                "properties": {
                    "webhook_url": {
                        "type": "string",
                        "description": "Discord webhook URL"
                    },
                    "content": {
                        "type": "string",
                        "description": "Message content"
                    },
                    "username": {
                        "type": "string",
                        "description": "Bot username",
                        "default": "Vif AI"
                    },
                    "avatar_url": {
                        "type": "string",
                        "description": "Bot avatar URL"
                    },
                    "embeds": {
                        "type": "array",
                        "description": "Message embeds"
                    }
                },
                "required": ["webhook_url", "content"]
            },
            handler=self._discord_webhook
        ))

    def _slack_send(self, message: str, webhook_url: str = None,
                   channel: str = None, username: str = "Vif AI",
                   attachments: list = None) -> Dict[str, Any]:
        """Send Slack message"""
        try:
            if not webhook_url:
                webhook_url = os.getenv('SLACK_WEBHOOK_URL')

            if not webhook_url:
                return {"error": "No Slack webhook URL provided"}

            payload = {
                "text": message,
                "username": username
            }

            if channel:
                payload["channel"] = channel

            if attachments:
                payload["attachments"] = attachments

            response = requests.post(webhook_url, json=payload, timeout=10)
            response.raise_for_status()

            return {
                "success": True,
                "message": "Slack message sent",
                "channel": channel
            }

        except Exception as e:
            return {"error": str(e)}

    def _send_email(self, to: str, subject: str, body: str,
                   from_email: str = None, cc: list = None,
                   attachments: list = None) -> Dict[str, Any]:
        """Send email"""
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart

            from_email = from_email or os.getenv('SMTP_FROM_EMAIL', 'noreply@vif.lat')
            smtp_host = os.getenv('SMTP_HOST', 'smtp.gmail.com')
            smtp_port = int(os.getenv('SMTP_PORT', 587))
            smtp_user = os.getenv('SMTP_USER')
            smtp_pass = os.getenv('SMTP_PASSWORD')

            if not smtp_user or not smtp_pass:
                return {"error": "SMTP credentials not configured"}

            # Create message
            msg = MIMEMultipart()
            msg['From'] = from_email
            msg['To'] = to
            msg['Subject'] = subject

            if cc:
                msg['Cc'] = ', '.join(cc)

            # Attach body
            msg.attach(MIMEText(body, 'html' if '<html>' in body else 'plain'))

            # Send email
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.starttls()
                server.login(smtp_user, smtp_pass)
                recipients = [to] + (cc or [])
                server.sendmail(from_email, recipients, msg.as_string())

            return {
                "success": True,
                "to": to,
                "subject": subject,
                "message": "Email sent successfully"
            }

        except Exception as e:
            return {"error": str(e)}

    def _calendar_event(self, title: str, start_time: str, end_time: str,
                       service: str = "google", description: str = None,
                       location: str = None, attendees: list = None) -> Dict[str, Any]:
        """Create calendar event"""
        try:
            if service == "google":
                # Google Calendar API
                api_key = os.getenv('GOOGLE_CALENDAR_API_KEY')
                calendar_id = os.getenv('GOOGLE_CALENDAR_ID', 'primary')

                if not api_key:
                    return {"error": "Google Calendar API key not configured"}

                event = {
                    'summary': title,
                    'start': {'dateTime': start_time},
                    'end': {'dateTime': end_time}
                }

                if description:
                    event['description'] = description
                if location:
                    event['location'] = location
                if attendees:
                    event['attendees'] = [{'email': email} for email in attendees]

                url = f"https://www.googleapis.com/calendar/v3/calendars/{calendar_id}/events?key={api_key}"
                response = requests.post(url, json=event, timeout=10)
                response.raise_for_status()

                return {
                    "success": True,
                    "service": "google",
                    "event_id": response.json().get('id'),
                    "title": title
                }

            else:
                return {"error": f"Service {service} not implemented yet"}

        except Exception as e:
            return {"error": str(e)}

    def _notion_create(self, title: str, api_key: str = None,
                      database_id: str = None, content: str = None,
                      properties: Dict = None) -> Dict[str, Any]:
        """Create Notion page"""
        try:
            api_key = api_key or os.getenv('NOTION_API_KEY')
            database_id = database_id or os.getenv('NOTION_DATABASE_ID')

            if not api_key:
                return {"error": "Notion API key not configured"}

            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "Notion-Version": "2022-06-28"
            }

            page_data = {
                "parent": {"database_id": database_id} if database_id else {"page_id": ""},
                "properties": {
                    "title": {
                        "title": [{"text": {"content": title}}]
                    }
                }
            }

            if properties:
                page_data["properties"].update(properties)

            if content:
                page_data["children"] = [
                    {
                        "object": "block",
                        "type": "paragraph",
                        "paragraph": {
                            "rich_text": [{"text": {"content": content}}]
                        }
                    }
                ]

            url = "https://api.notion.com/v1/pages"
            response = requests.post(url, headers=headers, json=page_data, timeout=10)
            response.raise_for_status()

            return {
                "success": True,
                "page_id": response.json().get('id'),
                "title": title
            }

        except Exception as e:
            return {"error": str(e)}

    def _discord_webhook(self, webhook_url: str, content: str,
                        username: str = "Vif AI", avatar_url: str = None,
                        embeds: list = None) -> Dict[str, Any]:
        """Send Discord webhook message"""
        try:
            payload = {
                "content": content,
                "username": username
            }

            if avatar_url:
                payload["avatar_url"] = avatar_url

            if embeds:
                payload["embeds"] = embeds

            response = requests.post(webhook_url, json=payload, timeout=10)
            response.raise_for_status()

            return {
                "success": True,
                "message": "Discord message sent"
            }

        except Exception as e:
            return {"error": str(e)}

"""
MCP Creative - Image generation, audio synthesis, text-to-speech
"""
from .base import MCPServer, MCPTool
from typing import Dict, Any
import requests
import base64
import os
from pathlib import Path


class CreativeMCP(MCPServer):
    """Creative MCP Server - Image generation, editing, text-to-speech, speech-to-text"""

    def __init__(self):
        super().__init__(
            name="creative",
            description="Creative tools: Image generation, editing, text-to-speech, speech-to-text"
        )
        self.openrouter_key = os.getenv('OPENROUTER_API_KEY')
        self.workspace = Path("/tmp/vif_creative")
        self.workspace.mkdir(parents=True, exist_ok=True)
        self._init_tools()

    def _init_tools(self):
        """Initialize all creative tools"""

        # Tool 1: Generate image
        self.register_tool(MCPTool(
            name="generate_image",
            description="Generate image from text prompt using DALL-E or Stable Diffusion",
            parameters={
                "type": "object",
                "properties": {
                    "prompt": {
                        "type": "string",
                        "description": "Text description of image to generate"
                    },
                    "model": {
                        "type": "string",
                        "description": "Model: dall-e-3, dall-e-2, stable-diffusion",
                        "enum": ["dall-e-3", "dall-e-2", "stable-diffusion", "auto"],
                        "default": "dall-e-3"
                    },
                    "size": {
                        "type": "string",
                        "description": "Image size",
                        "enum": ["256x256", "512x512", "1024x1024", "1792x1024", "1024x1792"],
                        "default": "1024x1024"
                    },
                    "quality": {
                        "type": "string",
                        "description": "Quality: standard, hd",
                        "enum": ["standard", "hd"],
                        "default": "standard"
                    },
                    "style": {
                        "type": "string",
                        "description": "Style: vivid, natural",
                        "enum": ["vivid", "natural"],
                        "default": "vivid"
                    }
                },
                "required": ["prompt"]
            },
            handler=self._generate_image
        ))

        # Tool 2: Edit image
        self.register_tool(MCPTool(
            name="edit_image",
            description="Edit image: remove background, apply filters, resize",
            parameters={
                "type": "object",
                "properties": {
                    "image_url": {
                        "type": "string",
                        "description": "URL of image to edit"
                    },
                    "image_path": {
                        "type": "string",
                        "description": "Local path to image"
                    },
                    "operation": {
                        "type": "string",
                        "description": "Edit operation",
                        "enum": ["remove_background", "resize", "filter", "crop", "rotate", "flip"],
                        "default": "remove_background"
                    },
                    "parameters": {
                        "type": "object",
                        "description": "Operation-specific parameters"
                    }
                },
                "required": ["operation"]
            },
            handler=self._edit_image
        ))

        # Tool 3: Text-to-speech
        self.register_tool(MCPTool(
            name="text_to_speech",
            description="Convert text to natural speech audio",
            parameters={
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "Text to convert to speech"
                    },
                    "voice": {
                        "type": "string",
                        "description": "Voice: alloy, echo, fable, onyx, nova, shimmer",
                        "enum": ["alloy", "echo", "fable", "onyx", "nova", "shimmer"],
                        "default": "alloy"
                    },
                    "model": {
                        "type": "string",
                        "description": "TTS model: tts-1, tts-1-hd",
                        "enum": ["tts-1", "tts-1-hd"],
                        "default": "tts-1"
                    },
                    "speed": {
                        "type": "number",
                        "description": "Speech speed (0.25 to 4.0)",
                        "default": 1.0
                    },
                    "format": {
                        "type": "string",
                        "description": "Audio format",
                        "enum": ["mp3", "opus", "aac", "flac"],
                        "default": "mp3"
                    }
                },
                "required": ["text"]
            },
            handler=self._text_to_speech
        ))

        # Tool 4: Speech-to-text
        self.register_tool(MCPTool(
            name="speech_to_text",
            description="Transcribe audio to text using Whisper",
            parameters={
                "type": "object",
                "properties": {
                    "audio_url": {
                        "type": "string",
                        "description": "URL of audio file"
                    },
                    "audio_path": {
                        "type": "string",
                        "description": "Local path to audio file"
                    },
                    "language": {
                        "type": "string",
                        "description": "Language code (e.g., en, fr, es)"
                    },
                    "model": {
                        "type": "string",
                        "description": "Whisper model",
                        "enum": ["whisper-1"],
                        "default": "whisper-1"
                    },
                    "response_format": {
                        "type": "string",
                        "description": "Format: text, json, verbose_json, srt, vtt",
                        "enum": ["text", "json", "verbose_json", "srt", "vtt"],
                        "default": "text"
                    }
                }
            },
            handler=self._speech_to_text
        ))

    def _generate_image(self, prompt: str, model: str = "dall-e-3",
                       size: str = "1024x1024", quality: str = "standard",
                       style: str = "vivid") -> Dict[str, Any]:
        """Generate image from text"""
        try:
            # Use OpenRouter for image generation
            url = "https://openrouter.ai/api/v1/images/generations"

            headers = {
                "Authorization": f"Bearer {self.openrouter_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://vif.lat"
            }

            data = {
                "model": f"openai/{model}",
                "prompt": prompt,
                "size": size,
                "quality": quality,
                "style": style,
                "n": 1
            }

            response = requests.post(url, headers=headers, json=data, timeout=60)
            response.raise_for_status()
            result = response.json()

            image_url = result['data'][0]['url']

            # Download and save image
            img_response = requests.get(image_url, timeout=30)
            img_response.raise_for_status()

            save_path = str(self.workspace / f"generated_{hash(prompt)}.png")
            with open(save_path, 'wb') as f:
                f.write(img_response.content)

            # Encode to base64
            image_b64 = base64.b64encode(img_response.content).decode('utf-8')

            return {
                "prompt": prompt,
                "model": model,
                "size": size,
                "image_url": image_url,
                "local_path": save_path,
                "image_base64": image_b64,
                "success": True
            }

        except Exception as e:
            return {"error": str(e)}

    def _edit_image(self, image_url: str = None, image_path: str = None,
                   operation: str = "remove_background",
                   parameters: Dict = None) -> Dict[str, Any]:
        """Edit image"""
        try:
            parameters = parameters or {}

            # Load image
            if image_url:
                response = requests.get(image_url, timeout=30)
                response.raise_for_status()
                image_data = response.content
            elif image_path:
                with open(image_path, 'rb') as f:
                    image_data = f.read()
            else:
                return {"error": "No image provided"}

            # Perform operation
            if operation == "remove_background":
                # Use remove.bg API or similar
                # For now, return placeholder
                result_data = image_data
                result_message = "Background removal not implemented yet"

            elif operation == "resize":
                from PIL import Image
                import io
                img = Image.open(io.BytesIO(image_data))
                new_size = parameters.get('size', (800, 600))
                img = img.resize(new_size)
                output = io.BytesIO()
                img.save(output, format='PNG')
                result_data = output.getvalue()
                result_message = f"Resized to {new_size}"

            elif operation == "filter":
                from PIL import Image, ImageFilter
                import io
                img = Image.open(io.BytesIO(image_data))
                filter_type = parameters.get('filter', 'BLUR')
                if hasattr(ImageFilter, filter_type):
                    img = img.filter(getattr(ImageFilter, filter_type))
                output = io.BytesIO()
                img.save(output, format='PNG')
                result_data = output.getvalue()
                result_message = f"Applied {filter_type} filter"

            elif operation == "rotate":
                from PIL import Image
                import io
                img = Image.open(io.BytesIO(image_data))
                angle = parameters.get('angle', 90)
                img = img.rotate(angle)
                output = io.BytesIO()
                img.save(output, format='PNG')
                result_data = output.getvalue()
                result_message = f"Rotated {angle} degrees"

            else:
                return {"error": f"Unknown operation: {operation}"}

            # Save result
            save_path = str(self.workspace / f"edited_{operation}.png")
            with open(save_path, 'wb') as f:
                f.write(result_data)

            return {
                "operation": operation,
                "message": result_message,
                "save_path": save_path,
                "image_base64": base64.b64encode(result_data).decode('utf-8'),
                "success": True
            }

        except Exception as e:
            return {"error": str(e)}

    def _text_to_speech(self, text: str, voice: str = "alloy",
                       model: str = "tts-1", speed: float = 1.0,
                       format: str = "mp3") -> Dict[str, Any]:
        """Convert text to speech"""
        try:
            # Use OpenRouter/OpenAI TTS
            url = "https://openrouter.ai/api/v1/audio/speech"

            headers = {
                "Authorization": f"Bearer {self.openrouter_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://vif.lat"
            }

            data = {
                "model": model,
                "input": text,
                "voice": voice,
                "response_format": format,
                "speed": speed
            }

            response = requests.post(url, headers=headers, json=data, timeout=60)
            response.raise_for_status()

            audio_data = response.content

            # Save audio
            save_path = str(self.workspace / f"speech_{hash(text)}.{format}")
            with open(save_path, 'wb') as f:
                f.write(audio_data)

            return {
                "text": text[:100] + "..." if len(text) > 100 else text,
                "voice": voice,
                "model": model,
                "format": format,
                "save_path": save_path,
                "audio_base64": base64.b64encode(audio_data).decode('utf-8'),
                "success": True
            }

        except Exception as e:
            return {"error": str(e)}

    def _speech_to_text(self, audio_url: str = None, audio_path: str = None,
                       language: str = None, model: str = "whisper-1",
                       response_format: str = "text") -> Dict[str, Any]:
        """Transcribe audio to text"""
        try:
            # Load audio
            if audio_url:
                response = requests.get(audio_url, timeout=30)
                response.raise_for_status()
                audio_data = response.content
            elif audio_path:
                with open(audio_path, 'rb') as f:
                    audio_data = f.read()
            else:
                return {"error": "No audio provided"}

            # Use OpenRouter/OpenAI Whisper
            url = "https://openrouter.ai/api/v1/audio/transcriptions"

            headers = {
                "Authorization": f"Bearer {self.openrouter_key}",
                "HTTP-Referer": "https://vif.lat"
            }

            # Create multipart form data
            files = {
                'file': ('audio.mp3', audio_data, 'audio/mpeg')
            }

            data = {
                'model': model,
                'response_format': response_format
            }

            if language:
                data['language'] = language

            response = requests.post(url, headers=headers, files=files, data=data, timeout=120)
            response.raise_for_status()

            result = response.json() if response_format in ['json', 'verbose_json'] else response.text

            return {
                "model": model,
                "language": language,
                "format": response_format,
                "transcription": result,
                "success": True
            }

        except Exception as e:
            return {"error": str(e)}

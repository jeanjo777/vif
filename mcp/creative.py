"""
MCP Creative - Image generation, audio synthesis, text-to-speech
Uses Higgsfield AI API (FLUX Pro) for image generation
"""
from .base import MCPServer, MCPTool
from typing import Dict, Any
import requests
import base64
import os
import io
import time
from pathlib import Path


class CreativeMCP(MCPServer):
    """Creative MCP Server - Image generation, editing, text-to-speech, speech-to-text"""

    def __init__(self):
        super().__init__(
            name="creative",
            description="Creative tools: Image generation, editing, text-to-speech, speech-to-text"
        )
        self.openrouter_key = os.getenv('OPENROUTER_API_KEY')
        self.higgsfield_api_key = os.getenv('HIGGSFIELD_API_KEY')
        self.higgsfield_secret = os.getenv('HIGGSFIELD_SECRET')
        self.higgsfield_base_url = "https://platform.higgsfield.ai"
        self.workspace = Path("/tmp/vif_creative")
        self.workspace.mkdir(parents=True, exist_ok=True)
        self._init_tools()

    def _init_tools(self):
        """Initialize all creative tools"""

        # Tool 1: Generate image
        self.register_tool(MCPTool(
            name="generate_image",
            description="Generate image from text prompt using Higgsfield AI (FLUX Pro)",
            parameters={
                "type": "object",
                "properties": {
                    "prompt": {
                        "type": "string",
                        "description": "Text description of image to generate"
                    },
                    "aspect_ratio": {
                        "type": "string",
                        "description": "Image aspect ratio",
                        "enum": ["1:1", "16:9", "9:16", "4:3", "3:4"],
                        "default": "1:1"
                    }
                },
                "required": ["prompt"]
            },
            handler=self._generate_image
        ))

        # Tool 2: Edit image
        self.register_tool(MCPTool(
            name="edit_image",
            description="Edit image: apply filters, resize, rotate, flip",
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
                        "enum": ["resize", "filter", "crop", "rotate", "flip"],
                        "default": "resize"
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

        # Tool 3: Image-to-Image (not available with Higgsfield)
        self.register_tool(MCPTool(
            name="image_to_image",
            description="Transform an existing image using a text prompt (currently unavailable)",
            parameters={
                "type": "object",
                "properties": {
                    "prompt": {
                        "type": "string",
                        "description": "Text description of how to transform the image"
                    },
                    "image_url": {
                        "type": "string",
                        "description": "URL of the source image"
                    }
                },
                "required": ["prompt"]
            },
            handler=self._image_to_image
        ))

        # Tool 4: Text-to-speech
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

    def _generate_image(self, prompt: str, aspect_ratio: str = "1:1", **kwargs) -> Dict[str, Any]:
        """Generate image using Higgsfield AI (FLUX Pro)"""
        try:
            if not self.higgsfield_api_key or not self.higgsfield_secret:
                return {"error": "HIGGSFIELD_API_KEY/HIGGSFIELD_SECRET not configured."}

            auth = f"{self.higgsfield_api_key}:{self.higgsfield_secret}"
            headers = {
                "Authorization": f"Key {auth}",
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
            payload = {
                "prompt": prompt,
                "aspect_ratio": aspect_ratio,
                "safety_tolerance": 6
            }

            api_url = f"{self.higgsfield_base_url}/flux-pro/kontext/max/text-to-image"
            print(f"[MCP] Generating image via Higgsfield FLUX Pro: {prompt[:80]}...", flush=True)
            response = requests.post(api_url, headers=headers, json=payload, timeout=30)

            if response.status_code != 200:
                error_msg = response.text[:300]
                return {"error": f"Higgsfield API error ({response.status_code}): {error_msg}"}

            job_data = response.json()
            request_id = job_data.get("request_id")
            status_url = job_data.get("status_url")
            if not request_id or not status_url:
                return {"error": f"No request_id in response: {str(job_data)[:200]}"}

            # Poll for results (max 90s)
            for _ in range(30):
                time.sleep(3)
                poll_response = requests.get(status_url, headers=headers, timeout=15)
                if poll_response.status_code != 200:
                    continue

                poll_data = poll_response.json()
                status = poll_data.get("status", "")

                if status == "completed":
                    images = poll_data.get("images", [])
                    if not images or not images[0].get("url"):
                        return {"error": "Job completed but no image URL in results"}

                    image_url = images[0]["url"]
                    img_response = requests.get(image_url, timeout=30)
                    if img_response.status_code != 200:
                        return {"error": f"Failed to download image: {img_response.status_code}"}

                    image_data = img_response.content

                    # Compress to JPEG
                    ext = '.jpg'
                    try:
                        from PIL import Image
                        img = Image.open(io.BytesIO(image_data))
                        if img.mode == 'RGBA':
                            img = img.convert('RGB')
                        output = io.BytesIO()
                        img.save(output, format='JPEG', quality=85, optimize=True)
                        image_data = output.getvalue()
                    except ImportError:
                        ext = '.png'

                    save_path = str(self.workspace / f"generated_{abs(hash(prompt))}{ext}")
                    with open(save_path, 'wb') as f:
                        f.write(image_data)

                    image_b64 = base64.b64encode(image_data).decode('utf-8')
                    return {
                        "success": True,
                        "prompt": prompt,
                        "model": "flux-pro-kontext-max",
                        "aspect_ratio": aspect_ratio,
                        "local_path": save_path,
                        "image_base64": image_b64,
                        "file_size_kb": round(len(image_data) / 1024, 1)
                    }

                elif status == "failed":
                    return {"error": "Image generation failed on server"}

            return {"error": "Image generation timed out after 90 seconds"}

        except requests.Timeout:
            return {"error": "Image generation request timed out"}
        except Exception as e:
            return {"error": str(e)}

    def _image_to_image(self, prompt: str, image_url: str = None, **kwargs) -> Dict[str, Any]:
        """Image-to-image is not available with current API"""
        return {
            "error": "Image-to-image transformation is not available. Use generate_image instead.",
            "alternative": "Use generate_image with a detailed text prompt describing what you want."
        }

    def _edit_image(self, image_url: str = None, image_path: str = None,
                   operation: str = "resize",
                   parameters: Dict = None) -> Dict[str, Any]:
        """Edit image using Pillow"""
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
                return {"error": "No image provided (image_url or image_path required)"}

            if operation == "resize":
                from PIL import Image
                import io
                img = Image.open(io.BytesIO(image_data))
                new_size = parameters.get('size', (800, 600))
                if isinstance(new_size, str):
                    new_size = tuple(map(int, new_size.split('x')))
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
                img = img.rotate(angle, expand=True)
                output = io.BytesIO()
                img.save(output, format='PNG')
                result_data = output.getvalue()
                result_message = f"Rotated {angle} degrees"

            elif operation == "flip":
                from PIL import Image
                import io
                img = Image.open(io.BytesIO(image_data))
                direction = parameters.get('direction', 'horizontal')
                if direction == 'horizontal':
                    img = img.transpose(Image.FLIP_LEFT_RIGHT)
                else:
                    img = img.transpose(Image.FLIP_TOP_BOTTOM)
                output = io.BytesIO()
                img.save(output, format='PNG')
                result_data = output.getvalue()
                result_message = f"Flipped {direction}"

            elif operation == "crop":
                from PIL import Image
                import io
                img = Image.open(io.BytesIO(image_data))
                box = parameters.get('box')
                if box and len(box) == 4:
                    img = img.crop(tuple(box))
                else:
                    return {"error": "crop requires 'box' parameter: [left, top, right, bottom]"}
                output = io.BytesIO()
                img.save(output, format='PNG')
                result_data = output.getvalue()
                result_message = f"Cropped to {box}"

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
        """Convert text to speech using OpenRouter"""
        try:
            if not self.openrouter_key:
                return {"error": "OPENROUTER_API_KEY not configured for text-to-speech"}

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

            save_path = str(self.workspace / f"speech_{abs(hash(text))}.{format}")
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
        """Transcribe audio to text using OpenRouter"""
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

            if not self.openrouter_key:
                return {"error": "OPENROUTER_API_KEY not configured for speech-to-text"}

            url = "https://openrouter.ai/api/v1/audio/transcriptions"
            headers = {
                "Authorization": f"Bearer {self.openrouter_key}",
                "HTTP-Referer": "https://vif.lat"
            }
            files = {'file': ('audio.mp3', audio_data, 'audio/mpeg')}
            data = {'model': model, 'response_format': response_format}
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

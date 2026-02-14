"""
MCP Creative - Image generation, audio synthesis, text-to-speech
Uses HuggingFace Inference API for image generation (free)
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
        self.hf_token = os.getenv('HF_TOKEN') or os.getenv('HuggingFace_API_KEY') or os.getenv('HUGGINGFACE_TOKEN')
        self.workspace = Path("/tmp/vif_creative")
        self.workspace.mkdir(parents=True, exist_ok=True)
        self._init_tools()

    def _init_tools(self):
        """Initialize all creative tools"""

        # Tool 1: Generate image
        self.register_tool(MCPTool(
            name="generate_image",
            description="Generate image from text prompt using Stable Diffusion (HuggingFace)",
            parameters={
                "type": "object",
                "properties": {
                    "prompt": {
                        "type": "string",
                        "description": "Text description of image to generate"
                    },
                    "negative_prompt": {
                        "type": "string",
                        "description": "What to avoid in the image (e.g. 'blurry, low quality')",
                        "default": ""
                    },
                    "model": {
                        "type": "string",
                        "description": "Model: flux, sdxl, sd3",
                        "enum": ["flux", "sdxl", "sd3", "auto"],
                        "default": "flux"
                    },
                    "size": {
                        "type": "string",
                        "description": "Image size",
                        "enum": ["512x512", "768x768", "1024x1024"],
                        "default": "1024x1024"
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

        # Tool 3: Image-to-Image
        self.register_tool(MCPTool(
            name="image_to_image",
            description="Transform an existing image using a text prompt (style transfer, modifications)",
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
                    },
                    "image_path": {
                        "type": "string",
                        "description": "Local path to the source image"
                    },
                    "strength": {
                        "type": "number",
                        "description": "How much to transform (0.0 = keep original, 1.0 = full transform)",
                        "default": 0.7
                    },
                    "negative_prompt": {
                        "type": "string",
                        "description": "What to avoid",
                        "default": ""
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

    def _generate_image(self, prompt: str, negative_prompt: str = "",
                       model: str = "flux", size: str = "1024x1024") -> Dict[str, Any]:
        """Generate image using HuggingFace Inference API"""
        try:
            if not self.hf_token:
                return {"error": "HF_TOKEN not configured. Image generation requires a HuggingFace API token."}

            # Model mapping
            hf_models = {
                "flux": "black-forest-labs/FLUX.1-schnell",
                "sdxl": "stabilityai/stable-diffusion-xl-base-1.0",
                "sd3": "stabilityai/stable-diffusion-3-medium-diffusers",
                "auto": "black-forest-labs/FLUX.1-schnell",
            }

            model_id = hf_models.get(model, hf_models["flux"])

            # Parse size
            try:
                width, height = map(int, size.split('x'))
            except ValueError:
                width, height = 1024, 1024

            # Call HuggingFace Inference API
            api_url = f"https://api-inference.huggingface.co/models/{model_id}"
            headers = {
                "Authorization": f"Bearer {self.hf_token}",
                "Content-Type": "application/json"
            }

            payload = {
                "inputs": prompt,
                "parameters": {
                    "width": width,
                    "height": height,
                }
            }

            if negative_prompt:
                payload["parameters"]["negative_prompt"] = negative_prompt

            # First attempt
            response = requests.post(api_url, headers=headers, json=payload, timeout=120)

            # Handle model loading (503 = model is loading)
            if response.status_code == 503:
                estimated_time = response.json().get("estimated_time", 30)
                wait_time = min(estimated_time, 60)
                time.sleep(wait_time)
                response = requests.post(api_url, headers=headers, json=payload, timeout=120)

            if response.status_code != 200:
                error_msg = response.text[:300]
                return {"error": f"HuggingFace API error ({response.status_code}): {error_msg}"}

            # Response is raw image bytes
            image_data = response.content

            # Verify it's actually an image
            content_type = response.headers.get('content-type', '')
            if 'image' not in content_type and len(image_data) < 1000:
                return {"error": f"Unexpected response: {image_data[:200].decode('utf-8', errors='ignore')}"}

            # Compress to JPEG for faster transfer (60-80% smaller than PNG)
            try:
                from PIL import Image
                img = Image.open(io.BytesIO(image_data))
                if img.mode == 'RGBA':
                    img = img.convert('RGB')
                output = io.BytesIO()
                img.save(output, format='JPEG', quality=85, optimize=True)
                image_data = output.getvalue()
                ext = '.jpg'
            except ImportError:
                ext = '.png'

            # Save image
            save_path = str(self.workspace / f"generated_{abs(hash(prompt))}{ext}")
            with open(save_path, 'wb') as f:
                f.write(image_data)

            # Encode to base64
            image_b64 = base64.b64encode(image_data).decode('utf-8')

            return {
                "success": True,
                "prompt": prompt,
                "model": model_id,
                "size": size,
                "local_path": save_path,
                "image_base64": image_b64,
                "file_size_kb": round(len(image_data) / 1024, 1)
            }

        except requests.Timeout:
            return {"error": "Image generation timed out. The model may be loading, try again."}
        except Exception as e:
            return {"error": str(e)}

    def _image_to_image(self, prompt: str, image_url: str = None, image_path: str = None,
                       strength: float = 0.7, negative_prompt: str = "") -> Dict[str, Any]:
        """Transform image using HuggingFace img2img API"""
        try:
            if not self.hf_token:
                return {"error": "HF_TOKEN not configured. Image-to-image requires a HuggingFace API token."}

            # Load source image
            if image_url:
                img_response = requests.get(image_url, timeout=30)
                img_response.raise_for_status()
                image_data = img_response.content
            elif image_path:
                with open(image_path, 'rb') as f:
                    image_data = f.read()
            else:
                return {"error": "No source image provided (image_url or image_path required)"}

            # Use SDXL img2img via HuggingFace
            model_id = "stabilityai/stable-diffusion-xl-refiner-1.0"
            api_url = f"https://api-inference.huggingface.co/models/{model_id}"
            headers = {"Authorization": f"Bearer {self.hf_token}"}

            # Encode image to base64
            img_b64 = base64.b64encode(image_data).decode('utf-8')

            payload = {
                "inputs": {
                    "image": img_b64,
                    "prompt": prompt,
                },
                "parameters": {
                    "strength": strength,
                }
            }
            if negative_prompt:
                payload["parameters"]["negative_prompt"] = negative_prompt

            response = requests.post(api_url, headers=headers, json=payload, timeout=120)

            # Handle model loading
            if response.status_code == 503:
                estimated_time = response.json().get("estimated_time", 30)
                time.sleep(min(estimated_time, 60))
                response = requests.post(api_url, headers=headers, json=payload, timeout=120)

            if response.status_code != 200:
                return {"error": f"HuggingFace API error ({response.status_code}): {response.text[:300]}"}

            result_data = response.content
            content_type = response.headers.get('content-type', '')
            if 'image' not in content_type and len(result_data) < 1000:
                return {"error": f"Unexpected response: {result_data[:200].decode('utf-8', errors='ignore')}"}

            # Compress to JPEG for faster transfer
            try:
                from PIL import Image
                img = Image.open(io.BytesIO(result_data))
                if img.mode == 'RGBA':
                    img = img.convert('RGB')
                output = io.BytesIO()
                img.save(output, format='JPEG', quality=85, optimize=True)
                result_data = output.getvalue()
                ext = '.jpg'
            except ImportError:
                ext = '.png'

            save_path = str(self.workspace / f"img2img_{abs(hash(prompt))}{ext}")
            with open(save_path, 'wb') as f:
                f.write(result_data)

            return {
                "success": True,
                "prompt": prompt,
                "strength": strength,
                "model": model_id,
                "local_path": save_path,
                "image_base64": base64.b64encode(result_data).decode('utf-8'),
                "file_size_kb": round(len(result_data) / 1024, 1)
            }

        except requests.Timeout:
            return {"error": "Image transformation timed out. Try again."}
        except Exception as e:
            return {"error": str(e)}

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
        """Convert text to speech using HuggingFace or OpenRouter"""
        try:
            # Try HuggingFace first (free)
            if self.hf_token:
                api_url = "https://api-inference.huggingface.co/models/facebook/mms-tts-fra"
                headers = {"Authorization": f"Bearer {self.hf_token}"}
                response = requests.post(api_url, headers=headers,
                                        json={"inputs": text}, timeout=60)
                if response.status_code == 200 and 'audio' in response.headers.get('content-type', ''):
                    audio_data = response.content
                    save_path = str(self.workspace / f"speech_{abs(hash(text))}.wav")
                    with open(save_path, 'wb') as f:
                        f.write(audio_data)
                    return {
                        "text": text[:100] + "..." if len(text) > 100 else text,
                        "model": "facebook/mms-tts",
                        "save_path": save_path,
                        "audio_base64": base64.b64encode(audio_data).decode('utf-8'),
                        "success": True
                    }

            # Fallback to OpenRouter
            if not self.openrouter_key:
                return {"error": "No API key configured for text-to-speech (HF_TOKEN or OPENROUTER_API_KEY needed)"}

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
        """Transcribe audio to text using HuggingFace Whisper or OpenRouter"""
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

            # Try HuggingFace Whisper (free)
            if self.hf_token:
                api_url = "https://api-inference.huggingface.co/models/openai/whisper-large-v3"
                headers = {"Authorization": f"Bearer {self.hf_token}"}
                response = requests.post(api_url, headers=headers, data=audio_data, timeout=120)
                if response.status_code == 200:
                    result = response.json()
                    return {
                        "model": "whisper-large-v3",
                        "language": language,
                        "transcription": result.get("text", str(result)),
                        "success": True
                    }

            # Fallback to OpenRouter
            if not self.openrouter_key:
                return {"error": "No API key configured for speech-to-text (HF_TOKEN or OPENROUTER_API_KEY needed)"}

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

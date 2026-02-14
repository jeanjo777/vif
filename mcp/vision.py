"""
MCP Vision - Image analysis and multimodal capabilities
"""
from .base import MCPServer, MCPTool
from typing import Dict, Any, List
import base64
import requests
import io
import os
from pathlib import Path


class VisionMCP(MCPServer):
    """Vision MCP Server - Image analysis, OCR, object detection, diagram generation"""

    def __init__(self, openai_api_key: str = None):
        super().__init__(
            name="vision",
            description="Image analysis, OCR, object detection, diagram generation, and screenshot analysis"
        )
        self.openai_api_key = openai_api_key or os.getenv('OPENROUTER_API_KEY')
        self.workspace = Path("/tmp/vif_vision")
        self.workspace.mkdir(parents=True, exist_ok=True)
        self._init_tools()

    def _init_tools(self):
        """Initialize all vision tools"""

        # Tool 1: Analyze image
        self.register_tool(MCPTool(
            name="analyze_image",
            description="Analyze an image: OCR, object detection, description, content extraction",
            parameters={
                "type": "object",
                "properties": {
                    "image_url": {
                        "type": "string",
                        "description": "URL of the image to analyze"
                    },
                    "image_path": {
                        "type": "string",
                        "description": "Local path to image file"
                    },
                    "image_base64": {
                        "type": "string",
                        "description": "Base64 encoded image data"
                    },
                    "task": {
                        "type": "string",
                        "description": "Analysis task: describe, ocr, detect_objects, analyze_ui, extract_text",
                        "enum": ["describe", "ocr", "detect_objects", "analyze_ui", "extract_text", "detailed"]
                    },
                    "prompt": {
                        "type": "string",
                        "description": "Custom prompt for analysis"
                    }
                }
            },
            handler=self._analyze_image
        ))

        # Tool 2: Compare images
        self.register_tool(MCPTool(
            name="compare_images",
            description="Compare two images for similarity, differences, changes",
            parameters={
                "type": "object",
                "properties": {
                    "image1_url": {
                        "type": "string",
                        "description": "URL of first image"
                    },
                    "image2_url": {
                        "type": "string",
                        "description": "URL of second image"
                    },
                    "image1_path": {
                        "type": "string",
                        "description": "Local path to first image"
                    },
                    "image2_path": {
                        "type": "string",
                        "description": "Local path to second image"
                    },
                    "comparison_type": {
                        "type": "string",
                        "description": "Type: similarity, differences, changes",
                        "enum": ["similarity", "differences", "changes", "detailed"],
                        "default": "differences"
                    }
                }
            },
            handler=self._compare_images
        ))

        # Tool 3: Generate diagram
        self.register_tool(MCPTool(
            name="generate_diagram",
            description="Generate Mermaid or PlantUML diagram from description",
            parameters={
                "type": "object",
                "properties": {
                    "description": {
                        "type": "string",
                        "description": "Description of the diagram to create"
                    },
                    "diagram_type": {
                        "type": "string",
                        "description": "Type: mermaid, plantuml, flowchart, sequence, class, er",
                        "enum": ["mermaid", "plantuml", "flowchart", "sequence", "class", "er"],
                        "default": "mermaid"
                    },
                    "render": {
                        "type": "boolean",
                        "description": "Render diagram to image (default: false)",
                        "default": False
                    }
                },
                "required": ["description"]
            },
            handler=self._generate_diagram
        ))

        # Tool 4: Screenshot analysis
        self.register_tool(MCPTool(
            name="screenshot_analysis",
            description="Analyze screenshot for UI/UX issues, accessibility, layout problems",
            parameters={
                "type": "object",
                "properties": {
                    "image_url": {
                        "type": "string",
                        "description": "URL of screenshot"
                    },
                    "image_path": {
                        "type": "string",
                        "description": "Local path to screenshot"
                    },
                    "analysis_type": {
                        "type": "string",
                        "description": "Type: ui_ux, accessibility, layout, performance, design",
                        "enum": ["ui_ux", "accessibility", "layout", "performance", "design", "all"],
                        "default": "ui_ux"
                    }
                }
            },
            handler=self._screenshot_analysis
        ))

    def _get_image_content(self, image_url: str = None, image_path: str = None, image_base64: str = None) -> str:
        """Get image content as base64"""
        try:
            if image_base64:
                return image_base64

            if image_path:
                with open(image_path, 'rb') as f:
                    image_data = f.read()
                return base64.b64encode(image_data).decode('utf-8')

            if image_url:
                response = requests.get(image_url, timeout=30)
                response.raise_for_status()
                return base64.b64encode(response.content).decode('utf-8')

            raise ValueError("No image source provided")

        except Exception as e:
            raise Exception(f"Error loading image: {str(e)}")

    def _call_vision_api(self, image_base64: str, prompt: str) -> str:
        """Call OpenRouter/OpenAI vision API"""
        try:
            if not self.openai_api_key:
                return "Error: OPENROUTER_API_KEY not configured. Vision analysis requires an API key."

            url = "https://openrouter.ai/api/v1/chat/completions"

            headers = {
                "Authorization": f"Bearer {self.openai_api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://vif.lat",
                "X-Title": "Vif AI"
            }

            # Use GPT-4 Vision or similar model
            data = {
                "model": "openai/gpt-4-vision-preview",
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": prompt
                            },
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:image/jpeg;base64,{image_base64}"
                                }
                            }
                        ]
                    }
                ],
                "max_tokens": 2000
            }

            response = requests.post(url, headers=headers, json=data, timeout=60)
            response.raise_for_status()

            result = response.json()
            return result['choices'][0]['message']['content']

        except Exception as e:
            return f"Vision API error: {str(e)}"

    def _analyze_image(self, image_url: str = None, image_path: str = None,
                      image_base64: str = None, task: str = "describe",
                      prompt: str = None) -> Dict[str, Any]:
        """Analyze an image"""
        try:
            # Get image content
            img_b64 = self._get_image_content(image_url, image_path, image_base64)

            # Build prompt based on task
            if prompt:
                analysis_prompt = prompt
            else:
                prompts = {
                    "describe": "Describe this image in detail. What do you see?",
                    "ocr": "Extract all text from this image. Provide the text exactly as it appears.",
                    "detect_objects": "List all objects, people, and items visible in this image.",
                    "analyze_ui": "Analyze this UI/interface. Describe the layout, components, and design.",
                    "extract_text": "Extract all visible text, labels, and captions from this image.",
                    "detailed": "Provide a comprehensive analysis of this image including: description, text content, objects detected, colors, composition, and any notable features."
                }
                analysis_prompt = prompts.get(task, prompts["describe"])

            # Call vision API
            result = self._call_vision_api(img_b64, analysis_prompt)

            return {
                "task": task,
                "analysis": result,
                "source": "url" if image_url else "path" if image_path else "base64"
            }

        except Exception as e:
            return {"error": str(e)}

    def _compare_images(self, image1_url: str = None, image2_url: str = None,
                       image1_path: str = None, image2_path: str = None,
                       comparison_type: str = "differences") -> Dict[str, Any]:
        """Compare two images"""
        try:
            # Get both images
            img1_b64 = self._get_image_content(image1_url, image1_path)
            img2_b64 = self._get_image_content(image2_url, image2_path)

            # Build comparison prompt
            prompts = {
                "similarity": "Compare these two images and describe their similarities.",
                "differences": "Compare these two images and list all the differences you can find.",
                "changes": "These are before/after images. Describe what has changed between them.",
                "detailed": "Provide a detailed comparison of these images including similarities, differences, and any notable changes."
            }

            comparison_prompt = prompts.get(comparison_type, prompts["differences"])

            # For comparison, we need to send both images
            # Note: This requires a multi-image capable model
            url = "https://openrouter.ai/api/v1/chat/completions"

            headers = {
                "Authorization": f"Bearer {self.openai_api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://vif.lat"
            }

            data = {
                "model": "openai/gpt-4-vision-preview",
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": comparison_prompt + " (Image 1):"},
                            {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{img1_b64}"}},
                            {"type": "text", "text": "(Image 2):"},
                            {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{img2_b64}"}}
                        ]
                    }
                ],
                "max_tokens": 2000
            }

            response = requests.post(url, headers=headers, json=data, timeout=60)
            response.raise_for_status()
            result = response.json()

            return {
                "comparison_type": comparison_type,
                "comparison": result['choices'][0]['message']['content']
            }

        except Exception as e:
            return {"error": str(e)}

    def _generate_diagram(self, description: str, diagram_type: str = "mermaid",
                         render: bool = False) -> Dict[str, Any]:
        """Generate diagram code from description"""
        try:
            # Build prompt for diagram generation
            prompts = {
                "mermaid": f"Generate Mermaid diagram code for: {description}\n\nProvide only the Mermaid code, starting with ```mermaid",
                "plantuml": f"Generate PlantUML code for: {description}\n\nProvide only the PlantUML code, starting with @startuml",
                "flowchart": f"Generate a Mermaid flowchart for: {description}\n\nUse Mermaid flowchart syntax.",
                "sequence": f"Generate a Mermaid sequence diagram for: {description}\n\nUse Mermaid sequence diagram syntax.",
                "class": f"Generate a Mermaid class diagram for: {description}\n\nUse Mermaid class diagram syntax.",
                "er": f"Generate a Mermaid ER diagram for: {description}\n\nUse Mermaid ER diagram syntax."
            }

            prompt = prompts.get(diagram_type, prompts["mermaid"])

            if not self.openai_api_key:
                return {"error": "OPENROUTER_API_KEY not configured. Diagram generation requires an API key."}

            # Use OpenRouter to generate diagram code
            url = "https://openrouter.ai/api/v1/chat/completions"

            headers = {
                "Authorization": f"Bearer {self.openai_api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://vif.lat"
            }

            data = {
                "model": "anthropic/claude-3.5-sonnet",
                "messages": [
                    {"role": "user", "content": prompt}
                ],
                "max_tokens": 2000
            }

            response = requests.post(url, headers=headers, json=data, timeout=30)
            response.raise_for_status()
            result = response.json()

            diagram_code = result['choices'][0]['message']['content']

            # Extract code from markdown if present
            if "```" in diagram_code:
                lines = diagram_code.split('\n')
                code_lines = []
                in_code = False
                for line in lines:
                    if line.startswith('```'):
                        if in_code:
                            break
                        in_code = True
                        continue
                    if in_code:
                        code_lines.append(line)
                diagram_code = '\n'.join(code_lines)

            result_data = {
                "diagram_type": diagram_type,
                "code": diagram_code,
                "description": description
            }

            # Optional: Render diagram to image
            if render:
                result_data["render_url"] = f"https://mermaid.ink/img/{base64.b64encode(diagram_code.encode()).decode()}"

            return result_data

        except Exception as e:
            return {"error": str(e)}

    def _screenshot_analysis(self, image_url: str = None, image_path: str = None,
                           analysis_type: str = "ui_ux") -> Dict[str, Any]:
        """Analyze screenshot for UI/UX issues"""
        try:
            # Get image
            img_b64 = self._get_image_content(image_url, image_path)

            # Build analysis prompt
            prompts = {
                "ui_ux": """Analyze this UI/UX screenshot and provide:
1. Overall design quality
2. User experience issues
3. Visual hierarchy problems
4. Spacing and alignment issues
5. Suggestions for improvement""",

                "accessibility": """Analyze this screenshot for accessibility issues:
1. Color contrast problems
2. Text readability
3. Touch target sizes
4. Clear labeling
5. WCAG compliance suggestions""",

                "layout": """Analyze the layout of this screenshot:
1. Grid and alignment
2. Spacing consistency
3. Component organization
4. Responsive design considerations
5. Layout improvements""",

                "performance": """Analyze this UI for performance indicators:
1. Visual clutter
2. Optimization opportunities
3. Loading states
4. User feedback elements
5. Performance UX patterns""",

                "design": """Provide a design critique of this screenshot:
1. Visual design quality
2. Color scheme effectiveness
3. Typography choices
4. Branding consistency
5. Modern design patterns""",

                "all": """Provide a comprehensive UI/UX analysis covering:
1. Design quality and aesthetics
2. User experience and usability
3. Accessibility compliance
4. Layout and structure
5. Performance indicators
6. Specific improvement recommendations"""
            }

            analysis_prompt = prompts.get(analysis_type, prompts["ui_ux"])

            # Call vision API
            result = self._call_vision_api(img_b64, analysis_prompt)

            return {
                "analysis_type": analysis_type,
                "analysis": result,
                "recommendations_included": True
            }

        except Exception as e:
            return {"error": str(e)}

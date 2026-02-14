"""
MCP Video - Video generation, editing, and processing
"""
from .base import MCPServer, MCPTool
from typing import Dict, Any, List
import os
import base64
import subprocess
from pathlib import Path
import json


class VideoMCP(MCPServer):
    """Video MCP Server - Video generation, editing, frame extraction, and processing"""

    def __init__(self):
        super().__init__(
            name="video",
            description="Video generation, editing, frame extraction, and processing"
        )
        self.workspace = Path("/tmp/vif_video")
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.openrouter_key = os.getenv('OPENROUTER_API_KEY')
        self._init_tools()

    def _init_tools(self):
        """Initialize all video tools"""

        # Tool 1: Generate video from text
        self.register_tool(MCPTool(
            name="generate_video",
            description="Generate video from text description using AI (Runway, Pika, etc.)",
            parameters={
                "type": "object",
                "properties": {
                    "prompt": {
                        "type": "string",
                        "description": "Text description of video to generate"
                    },
                    "duration": {
                        "type": "integer",
                        "description": "Video duration in seconds (default: 4)",
                        "default": 4
                    },
                    "fps": {
                        "type": "integer",
                        "description": "Frames per second (default: 24)",
                        "default": 24
                    },
                    "resolution": {
                        "type": "string",
                        "description": "Video resolution",
                        "enum": ["480p", "720p", "1080p"],
                        "default": "720p"
                    },
                    "style": {
                        "type": "string",
                        "description": "Video style: cinematic, animated, realistic",
                        "enum": ["cinematic", "animated", "realistic", "anime"],
                        "default": "realistic"
                    }
                },
                "required": ["prompt"]
            },
            handler=self._generate_video
        ))

        # Tool 2: Create video from images
        self.register_tool(MCPTool(
            name="images_to_video",
            description="Create video from sequence of images",
            parameters={
                "type": "object",
                "properties": {
                    "image_paths": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of image file paths"
                    },
                    "image_urls": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of image URLs"
                    },
                    "fps": {
                        "type": "integer",
                        "description": "Frames per second (default: 30)",
                        "default": 30
                    },
                    "transition": {
                        "type": "string",
                        "description": "Transition effect between images",
                        "enum": ["none", "fade", "slide", "dissolve"],
                        "default": "fade"
                    },
                    "duration_per_image": {
                        "type": "number",
                        "description": "Seconds to show each image (default: 2)",
                        "default": 2
                    },
                    "output_format": {
                        "type": "string",
                        "description": "Output video format",
                        "enum": ["mp4", "webm", "gif"],
                        "default": "mp4"
                    }
                }
            },
            handler=self._images_to_video
        ))

        # Tool 3: Edit video
        self.register_tool(MCPTool(
            name="edit_video",
            description="Edit video: trim, concatenate, add audio, resize",
            parameters={
                "type": "object",
                "properties": {
                    "video_path": {
                        "type": "string",
                        "description": "Path to video file"
                    },
                    "video_url": {
                        "type": "string",
                        "description": "URL to video file"
                    },
                    "operation": {
                        "type": "string",
                        "description": "Edit operation",
                        "enum": ["trim", "concatenate", "resize", "add_audio", "speed", "reverse"],
                        "default": "trim"
                    },
                    "start_time": {
                        "type": "number",
                        "description": "Start time in seconds (for trim)"
                    },
                    "end_time": {
                        "type": "number",
                        "description": "End time in seconds (for trim)"
                    },
                    "videos_to_concat": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Video paths to concatenate"
                    },
                    "width": {
                        "type": "integer",
                        "description": "New width (for resize)"
                    },
                    "height": {
                        "type": "integer",
                        "description": "New height (for resize)"
                    },
                    "audio_path": {
                        "type": "string",
                        "description": "Audio file to add"
                    },
                    "speed_factor": {
                        "type": "number",
                        "description": "Speed multiplier (0.5 = half speed, 2 = double speed)"
                    }
                },
                "required": ["operation"]
            },
            handler=self._edit_video
        ))

        # Tool 4: Extract frames
        self.register_tool(MCPTool(
            name="extract_frames",
            description="Extract frames from video as images",
            parameters={
                "type": "object",
                "properties": {
                    "video_path": {
                        "type": "string",
                        "description": "Path to video file"
                    },
                    "video_url": {
                        "type": "string",
                        "description": "URL to video file"
                    },
                    "frame_rate": {
                        "type": "string",
                        "description": "Extraction rate: every_frame, every_second, specific_frames",
                        "enum": ["every_frame", "every_second", "every_5_seconds", "specific_times"],
                        "default": "every_second"
                    },
                    "specific_times": {
                        "type": "array",
                        "items": {"type": "number"},
                        "description": "Specific timestamps to extract (in seconds)"
                    },
                    "output_format": {
                        "type": "string",
                        "description": "Image format",
                        "enum": ["jpg", "png"],
                        "default": "jpg"
                    },
                    "max_frames": {
                        "type": "integer",
                        "description": "Maximum number of frames to extract",
                        "default": 10
                    }
                }
            },
            handler=self._extract_frames
        ))

        # Tool 5: Get video info
        self.register_tool(MCPTool(
            name="video_info",
            description="Get video metadata: duration, resolution, fps, codec",
            parameters={
                "type": "object",
                "properties": {
                    "video_path": {
                        "type": "string",
                        "description": "Path to video file"
                    },
                    "video_url": {
                        "type": "string",
                        "description": "URL to video file"
                    }
                }
            },
            handler=self._video_info
        ))

    def _safe_parse_fps(self, fps_str: str) -> float:
        """Safely parse FFprobe frame rate string (e.g., '30000/1001') without eval()"""
        try:
            if '/' in fps_str:
                num, den = fps_str.split('/', 1)
                num, den = float(num), float(den)
                return round(num / den, 2) if den != 0 else 0
            return float(fps_str)
        except (ValueError, ZeroDivisionError):
            return 0

    def _generate_video(self, prompt: str, duration: int = 4, fps: int = 24,
                       resolution: str = "720p", style: str = "realistic") -> Dict[str, Any]:
        """Generate video from text - not available without dedicated video API"""
        return {
            "success": False,
            "error": "Video generation is not available",
            "reason": "No video generation API is configured (Runway ML, Pika Labs, etc.)",
            "prompt": prompt,
            "alternatives": [
                "Use 'generate_image' from the creative server to create individual frames",
                "Use 'images_to_video' to combine generated images into a video"
            ]
        }

    def _images_to_video(self, image_paths: List[str] = None, image_urls: List[str] = None,
                        fps: int = 30, transition: str = "fade",
                        duration_per_image: float = 2, output_format: str = "mp4") -> Dict[str, Any]:
        """Create video from images using FFmpeg"""
        try:
            import requests
            from PIL import Image
            import io

            # Download images if URLs provided
            images = []
            if image_urls:
                for url in image_urls:
                    response = requests.get(url, timeout=30)
                    img = Image.open(io.BytesIO(response.content))
                    temp_path = self.workspace / f"img_{len(images)}.jpg"
                    img.save(temp_path)
                    images.append(str(temp_path))
            elif image_paths:
                images = image_paths
            else:
                return {"error": "No images provided"}

            if len(images) == 0:
                return {"error": "No valid images found"}

            # Create video using FFmpeg
            output_path = str(self.workspace / f"video_{hash(str(images))}.{output_format}")

            # Create concat file for FFmpeg
            concat_file = self.workspace / "concat.txt"
            with open(concat_file, 'w') as f:
                for img in images:
                    f.write(f"file '{img}'\n")
                    f.write(f"duration {duration_per_image}\n")
                # Repeat last image to ensure proper duration
                f.write(f"file '{images[-1]}'\n")

            # FFmpeg command to create video
            cmd = [
                'ffmpeg',
                '-f', 'concat',
                '-safe', '0',
                '-i', str(concat_file),
                '-vf', f'fps={fps}',
                '-pix_fmt', 'yuv420p',
                '-y',
                output_path
            ]

            # Run FFmpeg
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if result.returncode != 0:
                # Fallback: create simple video without transitions
                return {
                    "success": False,
                    "error": "FFmpeg processing failed",
                    "note": "FFmpeg may not be installed. Install with: apt-get install ffmpeg",
                    "image_count": len(images)
                }

            # Get file size
            file_size = os.path.getsize(output_path)

            return {
                "success": True,
                "video_path": output_path,
                "image_count": len(images),
                "duration": len(images) * duration_per_image,
                "fps": fps,
                "format": output_format,
                "file_size_mb": round(file_size / 1024 / 1024, 2)
            }

        except subprocess.TimeoutExpired:
            return {"error": "Video creation timed out"}
        except Exception as e:
            return {"error": str(e)}

    def _edit_video(self, video_path: str = None, video_url: str = None,
                   operation: str = "trim", **kwargs) -> Dict[str, Any]:
        """Edit video using FFmpeg"""
        try:
            import requests

            # Download video if URL provided
            if video_url:
                response = requests.get(video_url, timeout=60)
                video_path = str(self.workspace / "input_video.mp4")
                with open(video_path, 'wb') as f:
                    f.write(response.content)

            if not video_path or not os.path.exists(video_path):
                return {"error": "Video file not found"}

            output_path = str(self.workspace / f"edited_{operation}.mp4")

            # Build FFmpeg command based on operation
            if operation == "trim":
                start = kwargs.get('start_time', 0)
                end = kwargs.get('end_time')
                if not end:
                    return {"error": "end_time required for trim operation"}

                cmd = [
                    'ffmpeg',
                    '-i', video_path,
                    '-ss', str(start),
                    '-to', str(end),
                    '-c', 'copy',
                    '-y',
                    output_path
                ]

            elif operation == "resize":
                width = kwargs.get('width')
                height = kwargs.get('height')
                if not width or not height:
                    return {"error": "width and height required for resize"}

                cmd = [
                    'ffmpeg',
                    '-i', video_path,
                    '-vf', f'scale={width}:{height}',
                    '-y',
                    output_path
                ]

            elif operation == "speed":
                speed = kwargs.get('speed_factor', 1.0)
                cmd = [
                    'ffmpeg',
                    '-i', video_path,
                    '-filter:v', f'setpts={1/speed}*PTS',
                    '-y',
                    output_path
                ]

            elif operation == "reverse":
                cmd = [
                    'ffmpeg',
                    '-i', video_path,
                    '-vf', 'reverse',
                    '-af', 'areverse',
                    '-y',
                    output_path
                ]

            else:
                return {"error": f"Unknown operation: {operation}"}

            # Execute FFmpeg
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": "FFmpeg processing failed",
                    "stderr": result.stderr[:500]
                }

            return {
                "success": True,
                "operation": operation,
                "output_path": output_path,
                "file_size_mb": round(os.path.getsize(output_path) / 1024 / 1024, 2)
            }

        except Exception as e:
            return {"error": str(e)}

    def _extract_frames(self, video_path: str = None, video_url: str = None,
                       frame_rate: str = "every_second", specific_times: List[float] = None,
                       output_format: str = "jpg", max_frames: int = 10) -> Dict[str, Any]:
        """Extract frames from video"""
        try:
            import requests

            # Download video if URL
            if video_url:
                response = requests.get(video_url, timeout=60)
                video_path = str(self.workspace / "input_video.mp4")
                with open(video_path, 'wb') as f:
                    f.write(response.content)

            if not video_path or not os.path.exists(video_path):
                return {"error": "Video file not found"}

            frames_dir = self.workspace / "frames"
            frames_dir.mkdir(exist_ok=True)

            # Build FFmpeg command based on frame_rate
            if frame_rate == "every_frame":
                fps_filter = None
            elif frame_rate == "every_second":
                fps_filter = "fps=1"
            elif frame_rate == "every_5_seconds":
                fps_filter = "fps=1/5"
            elif frame_rate == "specific_times" and specific_times:
                # Extract specific frames
                extracted_frames = []
                for i, time in enumerate(specific_times[:max_frames]):
                    output = str(frames_dir / f"frame_{i:04d}.{output_format}")
                    cmd = [
                        'ffmpeg',
                        '-ss', str(time),
                        '-i', video_path,
                        '-frames:v', '1',
                        '-y',
                        output
                    ]
                    result = subprocess.run(cmd, capture_output=True, timeout=30)
                    if result.returncode == 0:
                        extracted_frames.append(output)

                return {
                    "success": True,
                    "frame_count": len(extracted_frames),
                    "frames": extracted_frames[:10],  # Return first 10 paths
                    "format": output_format
                }
            else:
                fps_filter = "fps=1"

            # Extract frames
            output_pattern = str(frames_dir / f"frame_%04d.{output_format}")
            cmd = ['ffmpeg', '-i', video_path]
            if fps_filter:
                cmd.extend(['-vf', fps_filter])
            cmd.extend(['-frames:v', str(max_frames), '-y', output_pattern])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if result.returncode != 0:
                return {"error": "Frame extraction failed", "stderr": result.stderr[:500]}

            # Get extracted frames
            frames = sorted(frames_dir.glob(f"*.{output_format}"))

            return {
                "success": True,
                "frame_count": len(frames),
                "frames": [str(f) for f in frames[:10]],  # Return first 10 paths
                "frame_rate": frame_rate,
                "format": output_format
            }

        except Exception as e:
            return {"error": str(e)}

    def _video_info(self, video_path: str = None, video_url: str = None) -> Dict[str, Any]:
        """Get video metadata using FFprobe"""
        try:
            import requests

            # Download video if URL
            if video_url:
                response = requests.get(video_url, timeout=60, stream=True)
                video_path = str(self.workspace / "temp_video.mp4")
                with open(video_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)

            if not video_path or not os.path.exists(video_path):
                return {"error": "Video file not found"}

            # Use FFprobe to get video info
            cmd = [
                'ffprobe',
                '-v', 'quiet',
                '-print_format', 'json',
                '-show_format',
                '-show_streams',
                video_path
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode != 0:
                return {"error": "FFprobe failed - may not be installed"}

            info = json.loads(result.stdout)

            # Extract relevant info
            format_info = info.get('format', {})
            video_stream = next((s for s in info.get('streams', []) if s.get('codec_type') == 'video'), {})
            audio_stream = next((s for s in info.get('streams', []) if s.get('codec_type') == 'audio'), {})

            return {
                "success": True,
                "duration": float(format_info.get('duration', 0)),
                "size_mb": round(int(format_info.get('size', 0)) / 1024 / 1024, 2),
                "format": format_info.get('format_name'),
                "video": {
                    "codec": video_stream.get('codec_name'),
                    "width": video_stream.get('width'),
                    "height": video_stream.get('height'),
                    "fps": self._safe_parse_fps(video_stream.get('r_frame_rate', '0/1')),
                    "bitrate": video_stream.get('bit_rate')
                },
                "audio": {
                    "codec": audio_stream.get('codec_name'),
                    "sample_rate": audio_stream.get('sample_rate'),
                    "channels": audio_stream.get('channels')
                } if audio_stream else None
            }

        except Exception as e:
            return {"error": str(e)}

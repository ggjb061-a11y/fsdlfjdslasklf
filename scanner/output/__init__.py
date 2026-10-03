"""Output format modules: HTML, JSON, Markdown."""
from .markdown_report import generate_markdown
from .json_report import generate_json

__all__ = ["generate_markdown", "generate_json"]

"""

Converts HTML report strings into PDF documents using WeasyPrint.
WeasyPrint renders CSS-styled HTML (including charts embedded as base64)
to pixel-perfect PDF output.

Falls back gracefully when WeasyPrint is not installed:
  - generate_pdf() returns an empty bytes object and logs a warning.
  - Callers should check ``PDFGenerator.is_available()`` before relying on PDF output.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class PDFOptions:
    """Configuration for PDF rendering."""
    page_size: str = "A4"
    margin_top: str = "20mm"
    margin_bottom: str = "20mm"
    margin_left: str = "15mm"
    margin_right: str = "15mm"
    # Optional CSS string injected before rendering
    extra_css: str = ""


class PDFGenerator:
    """
    Generates PDF documents from HTML strings using WeasyPrint.

    Usage::

        gen = PDFGenerator()
        if gen.is_available():
            pdf_bytes = gen.generate_pdf(html_content)
            with open("report.pdf", "wb") as f:
                f.write(pdf_bytes)
    """

    def __init__(self, options: Optional[PDFOptions] = None) -> None:
        self._options = options or PDFOptions()
        self._weasyprint_available = False
        try:
            import weasyprint  # noqa: F401
            self._weasyprint_available = True
        except ImportError:
            logger.warning(
                "WeasyPrint not installed — PDF generation unavailable. "
                "Install with: pip install weasyprint"
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @classmethod
    def is_available(cls) -> bool:
        """Return True if WeasyPrint is importable."""
        try:
            import weasyprint  # noqa: F401
            return True
        except ImportError:
            return False

    def generate_pdf(self, html_content: str, output_path: Optional[str] = None) -> bytes:
        """
        Convert ``html_content`` to PDF bytes.

        Args:
            html_content: Full HTML document string.
            output_path: If given, the PDF is also written to this path.

        Returns:
            PDF content as bytes, or empty bytes if WeasyPrint is unavailable.
        """
        if not self._weasyprint_available:
            logger.warning("PDF generation skipped — WeasyPrint not installed.")
            return b""

        try:
            import weasyprint

            opts = self._options
            page_css = (
                f"@page {{"
                f"  size: {opts.page_size};"
                f"  margin: {opts.margin_top} {opts.margin_right} {opts.margin_bottom} {opts.margin_left};"
                f"}}"
            )
            full_css = page_css + "\n" + opts.extra_css

            pdf = weasyprint.HTML(string=html_content).write_pdf(
                stylesheets=[weasyprint.CSS(string=full_css)]
            )

            if output_path:
                Path(output_path).write_bytes(pdf)
                logger.info("PDF written to %s (%d bytes)", output_path, len(pdf))

            return pdf
        except Exception as exc:
            logger.error("PDF generation failed: %s", exc)
            raise RuntimeError(f"PDF generation failed: {exc}") from exc

    def generate_pdf_from_file(
        self, html_path: str, output_path: Optional[str] = None
    ) -> bytes:
        """Load HTML from a file path and convert to PDF."""
        content = Path(html_path).read_text(encoding="utf-8")
        return self.generate_pdf(content, output_path=output_path)

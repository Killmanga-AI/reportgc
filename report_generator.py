"""
ReportGC - PDF Report Generator
Generates executive security reports from processed scan data.
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import HTML, CSS
from weasyprint.text.fonts import FontConfiguration

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generates professional PDF reports using Jinja2 + WeasyPrint.
    
    Design philosophy:
    - Clean, executive-friendly layout
    - Risk-based color coding
    - Minimal dependencies (no browser automation)
    """

    def __init__(
        self,
        template_dir: Path,
        static_dir: Path,
        logo_path: Optional[Path] = None
    ):
        self.template_dir = Path(template_dir)
        self.static_dir = Path(static_dir)
        self.logo_path = logo_path or (static_dir / "logo.png")
        
        # Initialize Jinja2 environment
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=select_autoescape(['html', 'xml']),
            trim_blocks=True,
            lstrip_blocks=True
        )
        
        # Add custom filters
        self.jinja_env.filters['risk_badge'] = self._risk_badge_filter
        self.jinja_env.filters['severity_color'] = self._severity_color_filter

    def generate_pdf(
        self,
        data: Dict[str, Any],
        output_path: Path,
        template_name: str = "report.html"
    ) -> Path:
        """
        Render HTML template and convert to PDF.
        
        Args:
            data: Processed scan data from SecurityExplainPlan.to_dict()
            output_path: Where to save the PDF
            template_name: Which template to use (default: report.html)
            
        Returns:
            Path to generated PDF
            
        Raises:
            RuntimeError: If PDF generation fails
        """
        try:
            # Calculate total effort hours
            plan = data.get('execution_plan', {})
            total_effort_hours = (
                plan.get('full_table_scans', {}).get('estimated_hours', 0) +
                plan.get('index_scans', {}).get('estimated_hours', 0) +
                plan.get('nested_loops', {}).get('estimated_hours', 0) +
                plan.get('low_priority', {}).get('estimated_hours', 0)
            )
            
            # Render HTML with unpacked data
            template = self.jinja_env.get_template(template_name)
            html_content = template.render(
                **data,  # Unpack all data keys for direct template access
                generated_at=data.get('generated_at', datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                logo_path=str(self.logo_path),
                grade_color=self._get_grade_color(data.get('grade', 'F')),
                grade_label=self._get_grade_label(data.get('grade', 'F')),
                total_effort_hours=total_effort_hours
            )
            
            # Configure fonts
            font_config = FontConfiguration()
            
            # Build PDF
            html = HTML(string=html_content, base_url=str(self.template_dir))
            
            # Add custom CSS if exists
            css_path = self.static_dir / "report.css"
            stylesheets = []
            if css_path.exists():
                stylesheets.append(CSS(filename=str(css_path), font_config=font_config))
            
            # Write PDF
            html.write_pdf(
                str(output_path),
                stylesheets=stylesheets,
                font_config=font_config
            )
            
            logger.info(f"PDF generated: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            raise RuntimeError(f"Failed to generate PDF: {e}") from e

    def generate_html_only(
        self,
        data: Dict[str, Any],
        template_name: str = "report.html"
    ) -> str:
        """
        Generate HTML report without PDF conversion (for debugging).
        """
        # Calculate total effort hours
        plan = data.get('execution_plan', {})
        total_effort_hours = (
            plan.get('full_table_scans', {}).get('estimated_hours', 0) +
            plan.get('index_scans', {}).get('estimated_hours', 0) +
            plan.get('nested_loops', {}).get('estimated_hours', 0) +
            plan.get('low_priority', {}).get('estimated_hours', 0)
        )
        
        template = self.jinja_env.get_template(template_name)
        return template.render(
            **data,
            generated_at=data.get('generated_at', datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            logo_path=str(self.logo_path),
            grade_color=self._get_grade_color(data.get('grade', 'F')),
            grade_label=self._get_grade_label(data.get('grade', 'F')),
            total_effort_hours=total_effort_hours
        )

    # ----------------------------------------
    # Helper Methods
    # ----------------------------------------

    @staticmethod
    def _get_grade_color(grade: str) -> str:
        """Get hex color for grade."""
        colors = {
            'A': '#28a745',  # Green
            'B': '#6c757d',  # Gray
            'C': '#ffc107',  # Yellow
            'D': '#fd7e14',  # Orange
            'F': '#dc3545'   # Red
        }
        return colors.get(grade, '#6c757d')

    @staticmethod
    def _get_grade_label(grade: str) -> str:
        """Get human-readable label for grade."""
        labels = {
            'A': 'Excellent',
            'B': 'Good',
            'C': 'Fair',
            'D': 'Poor',
            'F': 'Critical Risk'
        }
        return labels.get(grade, 'Unknown')

    # ----------------------------------------
    # Jinja2 Filters
    # ----------------------------------------

    @staticmethod
    def _risk_badge_filter(risk_level: str) -> str:
        """Convert risk level to HTML badge."""
        colors = {
            'FULL_TABLE_SCAN': '#dc3545',  # Red
            'INDEX_RANGE_SCAN': '#fd7e14',  # Orange
            'NESTED_LOOP': '#ffc107',       # Yellow
            'SEQUENTIAL_READ': '#28a745',   # Green
        }
        color = colors.get(risk_level, '#6c757d')
        return f'<span class="badge" style="background: {color};">{risk_level}</span>'

    @staticmethod
    def _severity_color_filter(severity: str) -> str:
        """Map severity to Bootstrap color class."""
        mapping = {
            'CRITICAL': 'danger',
            'HIGH': 'warning',
            'MEDIUM': 'info',
            'LOW': 'success',
            'UNKNOWN': 'secondary'
        }
        return mapping.get(severity, 'secondary')

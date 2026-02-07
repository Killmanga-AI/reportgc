from weasyprint import HTML
from jinja2 import Environment, FileSystemLoader
from pathlib import Path
import os

class ReportGenerator:
    def __init__(self, template_dir: Path, static_dir: Path):
        self.env = Environment(loader=FileSystemLoader(str(template_dir)))
        self.static_dir = static_dir
        self.template_name = "report.html"

    def _get_grade_style(self, grade: str) -> dict:
        """Returns the color coding for the board-ready report"""
        styles = {
            'A': {'color': '#28a745', 'label': 'EXCELLENT'},
            'B': {'color': '#6c757d', 'label': 'GOOD'},
            'C': {'color': '#ffc107', 'label': 'FAIR'},
            'D': {'color': '#fd7e14', 'label': 'POOR'},
            'F': {'color': '#dc3545', 'label': 'CRITICAL'}
        }
        return styles.get(grade, {'color': '#333', 'label': 'UNKNOWN'})

    def generate_pdf(self, data: dict, output_path: str):
        """Renders the HTML template and converts it to PDF"""
        template = self.env.get_template(self.template_name)
        
        # Prepare asset paths for WeasyPrint (must be absolute URIs)
        logo_path = (self.static_dir / "logo.png").absolute().as_uri()
        
        # Enrich data with styling info
        style_info = self._get_grade_style(data['grade'])
        data.update({
            'logo_url': logo_path,
            'grade_color': style_info['color'],
            'grade_label': style_info['label']
        })

        # Render HTML string
        html_out = template.render(data)

        # Generate PDF
        # We pass base_url so CSS can find local assets if needed
        HTML(string=html_out, base_url=str(self.static_dir)).write_pdf(output_path)

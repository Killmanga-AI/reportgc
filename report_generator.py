from weasyprint import HTML
from jinja2 import Environment, FileSystemLoader
from pathlib import Path
from datetime import datetime

class ReportGenerator:
    def __init__(self, template_dir: Path, static_dir: Path):
        self.env = Environment(loader=FileSystemLoader(str(template_dir)))
        self.static_dir = static_dir
        self.template_name = "report.html"

    def _get_grade_style(self) -> dict:
    """Fallback only if engine data is missing."""
    return {'color': '#333', 'label': 'UNKNOWN'}
    def _ensure_required_fields(self, data: dict) -> dict:
        """Sanitizes data to ensure template stability."""
        defaults = {
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'report_id': datetime.now().strftime('%Y%m%d-%H%M%S'),
            'summary': {'total_findings': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'cisa_kev_count': 0},
            'execution_plan': {}
        }
        
        # Merge defaults
        for key, val in defaults.items():
    if key not in data or data[key] is None:
        data[key] = val
        # Ensure execution plan structure
        for section in ['full_table_scans', 'index_scans', 'low_priority']:
    sec = data['execution_plan'].get(section)
    if not isinstance(sec, dict):
        data['execution_plan'][section] = {'count': 0, 'estimated_hours': 0, 'items': []}
        
        return data

    def generate_pdf(self, data: dict, output_path: str):
        """Renders the HTML template and converts it to PDF using WeasyPrint."""
        data = self._ensure_required_fields(data)
        template = self.env.get_template(self.template_name)
        
        # Absolute URI for assets
        logo_path = (self.static_dir / "logo.png")
        logo_url = logo_path.absolute().as_uri() if logo_path.exists() else None
        
        # Styling and calculations
        fallback = self._get_grade_style()
        # Calculate effort hours locally if not provided by engine
        data.setdefault('total_effort_hours', 0)

        data.update({
    'logo_url': logo_url,
    'grade_color': data.get('grade_color', fallback['color']),
    'grade_label': data.get('grade_label', fallback['label'])
})
        html_out = template.render(data)
        
        # Base_url allows WeasyPrint to resolve relative CSS/Image links
        HTML(string=html_out, base_url=str(self.static_dir)).write_pdf(output_path)
        print(f"PDF generated: {output_path}")

    def generate_html(self, data: dict, output_path: str):
        """Saves rendered HTML to file (debugging tool)."""
        data = self._ensure_required_fields(data)
        html_out = self.env.get_template(self.template_name).render(data)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_out)
        print(f"HTML debug file generated: {output_path}")

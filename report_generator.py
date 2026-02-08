from weasyprint import HTML
from jinja2 import Environment, FileSystemLoader
from pathlib import Path
from datetime import datetime

class ReportGenerator:
    def __init__(self, template_dir: Path, static_dir: Path):
        """
        Initialize the report generator with template and static asset directories.
        
        Args:
            template_dir: Directory containing the report.html template
            static_dir: Directory containing static assets (logos, etc.)
        """
        self.env = Environment(loader=FileSystemLoader(str(template_dir)))
        self.static_dir = static_dir
        self.template_name = "report.html"

    def _get_grade_style(self, grade: str) -> dict:
        """
        Returns the color coding for the security posture grade.
        
        Args:
            grade: Letter grade (A, B, C, D, F)
            
        Returns:
            Dictionary with color and label for the grade
        """
        styles = {
            'A': {'color': '#28a745', 'label': 'EXCELLENT'},
            'B': {'color': '#6c757d', 'label': 'GOOD'},
            'C': {'color': '#ffc107', 'label': 'FAIR'},
            'D': {'color': '#fd7e14', 'label': 'POOR'},
            'F': {'color': '#dc3545', 'label': 'CRITICAL'}
        }
        return styles.get(grade, {'color': '#333', 'label': 'UNKNOWN'})

    def _calculate_total_effort(self, execution_plan: dict) -> int:
        """
        Calculate total estimated effort hours from the execution plan.
        
        Args:
            execution_plan: Dictionary containing full_table_scans, index_scans, etc.
            
        Returns:
            Total estimated hours as integer
        """
        total = 0
        total += execution_plan.get('full_table_scans', {}).get('estimated_hours', 0)
        total += execution_plan.get('index_scans', {}).get('estimated_hours', 0)
        return total

    def _ensure_required_fields(self, data: dict) -> dict:
        """
        Ensure all required template fields are present with sensible defaults.
        
        Args:
            data: Input data dictionary
            
        Returns:
            Enhanced data dictionary with all required fields
        """
        # Set defaults for missing fields
        if 'generated_at' not in data:
            data['generated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        if 'report_id' not in data:
            data['report_id'] = datetime.now().strftime('%Y%m%d-%H%M%S')
        
        # Ensure summary exists
        if 'summary' not in data:
            data['summary'] = {}
        
        if 'total_findings' not in data['summary']:
            # Calculate from execution plan if available
            if 'execution_plan' in data:
                ep = data['execution_plan']
                total = (
                    ep.get('full_table_scans', {}).get('count', 0) +
                    ep.get('index_scans', {}).get('count', 0) +
                    ep.get('low_priority', {}).get('count', 0)
                )
                data['summary']['total_findings'] = total
            else:
                data['summary']['total_findings'] = 0
        
        # Ensure execution_plan structure exists
        if 'execution_plan' not in data:
            data['execution_plan'] = {}
        
        ep = data['execution_plan']
        
        # Ensure each section has required fields
        for section in ['full_table_scans', 'index_scans', 'low_priority']:
            if section not in ep:
                ep[section] = {}
            
            if 'count' not in ep[section]:
                ep[section]['count'] = 0
            
            if 'estimated_hours' not in ep[section]:
                ep[section]['estimated_hours'] = 0
            
            if 'items' not in ep[section]:
                ep[section]['items'] = []
        
        # Ensure each item in items has required fields
        for section in ['full_table_scans', 'index_scans', 'low_priority']:
            for item in ep[section].get('items', []):
                if 'id' not in item:
                    item['id'] = 'UNKNOWN'
                if 'title' not in item:
                    item['title'] = 'Unknown Vulnerability'
                if 'pkg_name' not in item:
                    item['pkg_name'] = 'Unknown'
                if 'installed_version' not in item:
                    item['installed_version'] = 'Unknown'
                if 'cvss_score' not in item:
                    item['cvss_score'] = 'N/A'
                if 'fixed_version' not in item:
                    item['fixed_version'] = None
                if 'description' not in item:
                    item['description'] = 'No description available.'
                if 'cisa_kev' not in item:
                    item['cisa_kev'] = False
        
        return data

    def generate_pdf(self, data: dict, output_path: str):
        """
        Renders the ReportGC.html template and converts it to PDF.
        
        Args:
            data: Dictionary containing:
                - grade: Letter grade (A-F)
                - execution_plan: Dict with full_table_scans, index_scans, low_priority
                - summary: Dict with total_findings
                - generated_at: (optional) Timestamp string
                - report_id: (optional) Report identifier
                
        Example data structure:
            {
                'grade': 'C',
                'execution_plan': {
                    'full_table_scans': {
                        'count': 3,
                        'estimated_hours': 12,
                        'items': [
                            {
                                'id': 'CVE-2024-1234',
                                'title': 'Critical Vulnerability',
                                'pkg_name': 'package-name',
                                'installed_version': '1.0.0',
                                'cvss_score': '9.8',
                                'fixed_version': '1.0.1',
                                'description': 'Vulnerability description...',
                                'cisa_kev': True
                            }
                        ]
                    },
                    'index_scans': { ... },
                    'low_priority': { ... }
                },
                'summary': {
                    'total_findings': 15
                }
            }
        """
        template = self.env.get_template(self.template_name)
        
        # Ensure all required fields are present
        data = self._ensure_required_fields(data)
        
        # Prepare asset paths for WeasyPrint (must be absolute URIs)
        logo_path = None
        if (self.static_dir / "logo.png").exists():
            logo_path = (self.static_dir / "logo.png").absolute().as_uri()
        
        # Enrich data with styling info
        style_info = self._get_grade_style(data.get('grade', 'F'))
        data.update({
            'logo_url': logo_path,
            'grade_color': style_info['color'],
            'grade_label': style_info['label'],
            'total_effort_hours': self._calculate_total_effort(data.get('execution_plan', {}))
        })

        # Render HTML string
        html_out = template.render(data)

        # Generate PDF
        # We pass base_url so CSS can find local assets if needed
        HTML(string=html_out, base_url=str(self.static_dir)).write_pdf(output_path)
        
        print(f"✓ PDF report generated successfully: {output_path}")

    def generate_html(self, data: dict, output_path: str):
        """
        Renders the ReportGC.html template and saves it as HTML (useful for debugging).
        
        Args:
            data: Same data structure as generate_pdf()
            output_path: Path where HTML file should be saved
        """
        template = self.env.get_template(self.template_name)
        
        # Ensure all required fields are present
        data = self._ensure_required_fields(data)
        
        # Prepare asset paths
        logo_path = None
        if (self.static_dir / "logo.png").exists():
            logo_path = (self.static_dir / "logo.png").absolute().as_uri()
        
        # Enrich data with styling info
        style_info = self._get_grade_style(data.get('grade', 'F'))
        data.update({
            'logo_url': logo_path,
            'grade_color': style_info['color'],
            'grade_label': style_info['label'],
            'total_effort_hours': self._calculate_total_effort(data.get('execution_plan', {}))
        })

        # Render HTML string
        html_out = template.render(data)
        
        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_out)
        
        print(f"✓ HTML report generated successfully: {output_path}")


# Example usage
if __name__ == "__main__":
    # Example data structure
    sample_data = {
        'grade': 'C',
        'execution_plan': {
            'full_table_scans': {
                'count': 2,
                'estimated_hours': 8,
                'items': [
                    {
                        'id': 'CVE-2024-1234',
                        'title': 'Remote Code Execution in OpenSSL',
                        'pkg_name': 'openssl',
                        'installed_version': '1.1.1',
                        'cvss_score': '9.8',
                        'fixed_version': '1.1.1t',
                        'description': 'A critical vulnerability allowing remote code execution through crafted certificates.',
                        'cisa_kev': True
                    },
                    {
                        'id': 'CVE-2024-5678',
                        'title': 'SQL Injection in Django ORM',
                        'pkg_name': 'django',
                        'installed_version': '3.2.0',
                        'cvss_score': '8.6',
                        'fixed_version': '3.2.19',
                        'description': 'SQL injection vulnerability in the ORM query generation affecting PostgreSQL backends.',
                        'cisa_kev': False
                    }
                ]
            },
            'index_scans': {
                'count': 5,
                'estimated_hours': 15,
                'items': [
                    {
                        'id': 'CVE-2024-9999',
                        'title': 'Cross-Site Scripting in React',
                        'pkg_name': 'react',
                        'installed_version': '17.0.0',
                        'cvss_score': '7.2',
                        'fixed_version': '17.0.2',
                        'description': 'XSS vulnerability in dangerouslySetInnerHTML when processing user-supplied SVG content.',
                        'cisa_kev': False
                    }
                ]
            },
            'low_priority': {
                'count': 8,
                'estimated_hours': 0,
                'items': []
            }
        },
        'summary': {
            'total_findings': 15
        }
    }
    
    # Initialize generator
    template_dir = Path("./templates")
    static_dir = Path("./static")
    
    generator = ReportGenerator(template_dir, static_dir)
    
    # Generate both HTML and PDF
    generator.generate_html(sample_data, "output_report.html")
    generator.generate_pdf(sample_data, "output_report.pdf")

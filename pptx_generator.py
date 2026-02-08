from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.enum.text import PP_ALIGN
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pathlib import Path
from datetime import datetime

class PPTXGenerator:
    def __init__(self, master_pptx: Path = None):
        """
        Initialize the PowerPoint generator.
        
        Args:
            master_pptx: Optional path to a master template PPTX file
        """
        # Start with your master template if provided, else a blank slate
        self.prs = Presentation(str(master_pptx)) if master_pptx and master_pptx.exists() else Presentation()
        # Widescreen 16:9 ratio
        self.prs.slide_width = Inches(13.333)
        self.prs.slide_height = Inches(7.5)

    def _get_color(self, grade: str) -> RGBColor:
        """Get the color associated with a security grade."""
        colors = {
            'A': RGBColor(40, 167, 69),    # Green - Excellent
            'B': RGBColor(108, 117, 125),  # Gray - Good
            'C': RGBColor(255, 193, 7),    # Yellow - Fair
            'D': RGBColor(253, 126, 20),   # Orange - Poor
            'F': RGBColor(220, 53, 69)     # Red - Critical
        }
        return colors.get(grade, RGBColor(0, 0, 0))

    def _get_grade_label(self, grade: str) -> str:
        """Get the text label for a security grade."""
        labels = {
            'A': 'EXCELLENT',
            'B': 'GOOD',
            'C': 'FAIR',
            'D': 'POOR',
            'F': 'CRITICAL'
        }
        return labels.get(grade, 'UNKNOWN')

    def _ensure_data_structure(self, data: dict) -> dict:
        """Ensure the data has all required fields with defaults."""
        # Set defaults
        if 'grade' not in data:
            data['grade'] = 'F'
        
        if 'generated_at' not in data:
            data['generated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        if 'summary' not in data:
            data['summary'] = {}
        
        if 'total_findings' not in data['summary']:
            data['summary']['total_findings'] = 0
        
        if 'execution_plan' not in data:
            data['execution_plan'] = {}
        
        ep = data['execution_plan']
        
        # Ensure each section exists
        for section in ['full_table_scans', 'index_scans', 'low_priority']:
            if section not in ep:
                ep[section] = {}
            
            if 'count' not in ep[section]:
                ep[section]['count'] = 0
            
            if 'estimated_hours' not in ep[section]:
                ep[section]['estimated_hours'] = 0
            
            if 'items' not in ep[section]:
                ep[section]['items'] = []
        
        return data

    def generate_pptx(self, data: dict, output_path: str):
        """
        Builds the 4-slide executive board deck.
        
        Args:
            data: Dictionary containing security assessment data with structure:
                {
                    'grade': 'A-F',
                    'execution_plan': {
                        'full_table_scans': {'count': int, 'estimated_hours': int, 'items': [...]},
                        'index_scans': {'count': int, 'estimated_hours': int, 'items': [...]},
                        'low_priority': {'count': int, 'estimated_hours': int, 'items': [...]}
                    },
                    'summary': {'total_findings': int},
                    'generated_at': 'timestamp'
                }
            output_path: Path where the PPTX should be saved
        """
        # Ensure data structure is complete
        data = self._ensure_data_structure(data)
        
        # Build the 4 slides
        self._add_title_slide(data)
        self._add_matrix_slide(data)
        self._add_critical_detail_slide(data)
        self._add_roadmap_slide(data)
        
        # Save the presentation
        self.prs.save(output_path)
        print(f"✓ PowerPoint presentation generated successfully: {output_path}")

    def _add_title_slide(self, data):
        """Create the executive title slide with the security grade."""
        slide = self.prs.slides.add_slide(self.prs.slide_layouts[6])  # Blank layout
        
        # Header
        title = slide.shapes.add_textbox(Inches(0.5), Inches(0.5), Inches(12), Inches(1.5))
        tf = title.text_frame
        tf.text = "Security Posture: Executive Brief"
        p = tf.paragraphs[0]
        p.font.size = Pt(44)
        p.font.bold = True
        p.font.color.rgb = RGBColor(44, 62, 80)
        p.alignment = PP_ALIGN.CENTER

        # Big Grade Circle/Box
        grade_color = self._get_color(data['grade'])
        grade_label = self._get_grade_label(data['grade'])
        
        # Grade letter
        grade_box = slide.shapes.add_textbox(Inches(4), Inches(2.5), Inches(5), Inches(2.5))
        tf = grade_box.text_frame
        p = tf.paragraphs[0]
        p.text = data['grade']
        p.font.size = Pt(180)
        p.font.bold = True
        p.font.color.rgb = grade_color
        p.alignment = PP_ALIGN.CENTER
        
        # Grade label below
        label_box = slide.shapes.add_textbox(Inches(4), Inches(4.8), Inches(5), Inches(0.8))
        tf = label_box.text_frame
        p = tf.paragraphs[0]
        p.text = grade_label
        p.font.size = Pt(28)
        p.font.bold = True
        p.font.color.rgb = grade_color
        p.alignment = PP_ALIGN.CENTER
        
        # Metadata footer
        footer = slide.shapes.add_textbox(Inches(0.5), Inches(6.5), Inches(12), Inches(0.8))
        tf = footer.text_frame
        p = tf.paragraphs[0]
        p.text = f"Generated: {data.get('generated_at', 'N/A')} | Total Findings: {data['summary']['total_findings']}"
        p.font.size = Pt(14)
        p.font.color.rgb = RGBColor(108, 117, 125)
        p.alignment = PP_ALIGN.CENTER

    def _add_matrix_slide(self, data):
        """Create the execution plan matrix slide."""
        slide = self.prs.slides.add_slide(self.prs.slide_layouts[6])
        
        # Title
        title_box = slide.shapes.add_textbox(Inches(0.5), Inches(0.3), Inches(12), Inches(1))
        tf = title_box.text_frame
        p = tf.paragraphs[0]
        p.text = "The 'Explain Plan': Resource Allocation Strategy"
        p.font.size = Pt(36)
        p.font.bold = True
        p.font.color.rgb = RGBColor(44, 62, 80)
        
        # Subtitle
        subtitle_box = slide.shapes.add_textbox(Inches(0.5), Inches(0.9), Inches(12), Inches(0.5))
        tf = subtitle_box.text_frame
        p = tf.paragraphs[0]
        p.text = "Prioritized by risk severity and exploitation likelihood"
        p.font.size = Pt(16)
        p.font.color.rgb = RGBColor(108, 117, 125)
        
        # Create 3 high-impact rectangles representing the plan
        plan = data['execution_plan']
        rows = [
            ("FULL TABLE SCAN (Critical)", 
             plan['full_table_scans']['count'], 
             f"FIX THIS WEEK • {plan['full_table_scans']['estimated_hours']}h effort",
             RGBColor(255, 245, 245),
             RGBColor(220, 53, 69)),
            
            ("INDEX RANGE SCAN (High)", 
             plan['index_scans']['count'], 
             f"SCHEDULE NEXT SPRINT • {plan['index_scans']['estimated_hours']}h effort",
             RGBColor(255, 253, 245),
             RGBColor(253, 126, 20)),
            
            ("SEQUENTIAL READ (Medium/Low)", 
             plan['low_priority']['count'], 
             "BATCH / ACCEPT RISK • Background task",
             RGBColor(248, 249, 250),
             RGBColor(108, 117, 125))
        ]

        for i, (label, count, action, bg_color, text_color) in enumerate(rows):
            y = 1.8 + (i * 1.7)
            
            # Background rectangle
            shape = slide.shapes.add_shape(
                MSO_SHAPE.ROUNDED_RECTANGLE,
                Inches(0.7), Inches(y), 
                Inches(11.9), Inches(1.4)
            )
            shape.fill.solid()
            shape.fill.fore_color.rgb = bg_color
            shape.line.color.rgb = text_color
            shape.line.width = Pt(2)
            
            # Label and count
            tf = shape.text_frame
            tf.clear()
            p = tf.paragraphs[0]
            p.text = f"{label}"
            p.font.size = Pt(22)
            p.font.bold = True
            p.font.color.rgb = text_color
            p.space_after = Pt(8)
            
            # Count in big text
            p = tf.add_paragraph()
            p.text = f"{count} Findings"
            p.font.size = Pt(28)
            p.font.bold = True
            p.font.color.rgb = RGBColor(44, 62, 80)
            p.space_after = Pt(8)
            
            # Action required
            p = tf.add_paragraph()
            p.text = action
            p.font.size = Pt(16)
            p.font.color.rgb = RGBColor(73, 80, 87)

    def _add_critical_detail_slide(self, data):
        """Create the critical findings detail slide."""
        slide = self.prs.slides.add_slide(self.prs.slide_layouts[6])
        
        # Title
        title_box = slide.shapes.add_textbox(Inches(0.5), Inches(0.3), Inches(12), Inches(1))
        tf = title_box.text_frame
        p = tf.paragraphs[0]
        p.text = "High-Risk Path: Critical Findings"
        p.font.size = Pt(36)
        p.font.bold = True
        p.font.color.rgb = RGBColor(220, 53, 69)
        
        critical_items = data['execution_plan']['full_table_scans']['items']
        
        if not critical_items:
            # No critical findings - show success message
            success_box = slide.shapes.add_textbox(Inches(2), Inches(2.5), Inches(9), Inches(2))
            tf = success_box.text_frame
            p = tf.paragraphs[0]
            p.text = "✓ No Critical Findings"
            p.font.size = Pt(48)
            p.font.bold = True
            p.font.color.rgb = RGBColor(40, 167, 69)
            p.alignment = PP_ALIGN.CENTER
            
            p = tf.add_paragraph()
            p.text = "Excellent security posture maintained"
            p.font.size = Pt(24)
            p.font.color.rgb = RGBColor(108, 117, 125)
            p.alignment = PP_ALIGN.CENTER
            p.space_before = Pt(20)
        else:
            # List top 3 critical findings
            y = 1.6
            items_to_show = critical_items[:3]
            
            for idx, item in enumerate(items_to_show, 1):
                # Create a styled box for each finding
                box = slide.shapes.add_shape(
                    MSO_SHAPE.ROUNDED_RECTANGLE,
                    Inches(0.7), Inches(y), 
                    Inches(11.9), Inches(1.6)
                )
                box.fill.solid()
                box.fill.fore_color.rgb = RGBColor(255, 245, 245)
                box.line.color.rgb = RGBColor(220, 53, 69)
                box.line.width = Pt(2)
                
                tf = box.text_frame
                tf.clear()
                
                # Finding ID and title
                p = tf.paragraphs[0]
                cisa_badge = " [CISA KEV]" if item.get('cisa_kev', False) else ""
                p.text = f"{idx}. {item.get('id', 'UNKNOWN')}: {item.get('title', 'Unknown Vulnerability')}{cisa_badge}"
                p.font.size = Pt(18)
                p.font.bold = True
                p.font.color.rgb = RGBColor(220, 53, 69)
                p.space_after = Pt(8)
                
                # Details
                p = tf.add_paragraph()
                details = (
                    f"Package: {item.get('pkg_name', 'Unknown')} "
                    f"| CVSS: {item.get('cvss_score', 'N/A')} "
                    f"| Fix: {item.get('fixed_version') or 'No patch available'}"
                )
                p.text = details
                p.font.size = Pt(14)
                p.font.color.rgb = RGBColor(73, 80, 87)
                
                y += 1.8
            
            # Show count if there are more
            if len(critical_items) > 3:
                remaining = len(critical_items) - 3
                footer_box = slide.shapes.add_textbox(Inches(0.7), Inches(6.5), Inches(11.9), Inches(0.8))
                tf = footer_box.text_frame
                p = tf.paragraphs[0]
                p.text = f"+ {remaining} additional critical finding{'s' if remaining > 1 else ''} require immediate attention"
                p.font.size = Pt(16)
                p.font.italic = True
                p.font.color.rgb = RGBColor(220, 53, 69)
                p.alignment = PP_ALIGN.CENTER

    def _add_roadmap_slide(self, data):
        """Create the remediation roadmap slide."""
        slide = self.prs.slides.add_slide(self.prs.slide_layouts[6])
        
        # Title
        title_box = slide.shapes.add_textbox(Inches(0.5), Inches(0.3), Inches(12), Inches(1))
        tf = title_box.text_frame
        p = tf.paragraphs[0]
        p.text = "Remediation Roadmap"
        p.font.size = Pt(36)
        p.font.bold = True
        p.font.color.rgb = RGBColor(44, 62, 80)
        
        # Subtitle
        subtitle_box = slide.shapes.add_textbox(Inches(0.5), Inches(0.9), Inches(12), Inches(0.5))
        tf = subtitle_box.text_frame
        p = tf.paragraphs[0]
        p.text = "Phased approach to systematic risk reduction"
        p.font.size = Pt(16)
        p.font.color.rgb = RGBColor(108, 117, 125)
        
        # Build timeline steps
        plan = data['execution_plan']
        steps = [
            ("Week 1", 
             f"Clear {plan['full_table_scans']['count']} Critical 'Full Table Scans'",
             f"Est. {plan['full_table_scans']['estimated_hours']} hours",
             RGBColor(220, 53, 69)),
            
            ("Week 2-3", 
             f"Address {plan['index_scans']['count']} High-Severity 'Index Range Scans'",
             f"Est. {plan['index_scans']['estimated_hours']} hours",
             RGBColor(253, 126, 20)),
            
            ("End of Month", 
             f"Review {plan['low_priority']['count']} Medium/Low findings",
             "Batch process or accept residual risk",
             RGBColor(108, 117, 125))
        ]
        
        y = 1.8
        for i, (timeframe, task, effort, color) in enumerate(steps, 1):
            # Timeline box
            box = slide.shapes.add_shape(
                MSO_SHAPE.ROUNDED_RECTANGLE,
                Inches(0.7), Inches(y), 
                Inches(11.9), Inches(1.5)
            )
            box.fill.solid()
            box.fill.fore_color.rgb = RGBColor(248, 249, 250)
            box.line.color.rgb = color
            box.line.width = Pt(3)
            
            tf = box.text_frame
            tf.clear()
            
            # Step number and timeframe
            p = tf.paragraphs[0]
            p.text = f"Step {i}: {timeframe}"
            p.font.size = Pt(22)
            p.font.bold = True
            p.font.color.rgb = color
            p.space_after = Pt(8)
            
            # Task description
            p = tf.add_paragraph()
            p.text = task
            p.font.size = Pt(18)
            p.font.color.rgb = RGBColor(44, 62, 80)
            p.space_after = Pt(6)
            
            # Effort estimate
            p = tf.add_paragraph()
            p.text = effort
            p.font.size = Pt(14)
            p.font.color.rgb = RGBColor(108, 117, 125)
            
            y += 1.7
        
        # Final note
        note_box = slide.shapes.add_textbox(Inches(0.7), Inches(6.8), Inches(11.9), Inches(0.5))
        tf = note_box.text_frame
        p = tf.paragraphs[0]
        p.text = "Note: Quarterly security reviews recommended to maintain posture"
        p.font.size = Pt(14)
        p.font.italic = True
        p.font.color.rgb = RGBColor(108, 117, 125)
        p.alignment = PP_ALIGN.CENTER


# Example usage
if __name__ == "__main__":
    # Sample data matching ReportGC structure
    sample_data = {
        'grade': 'C',
        'generated_at': '2024-02-08 14:30:00',
        'summary': {
            'total_findings': 15
        },
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
                        'cisa_kev': True
                    },
                    {
                        'id': 'CVE-2024-5678',
                        'title': 'SQL Injection in Django ORM',
                        'pkg_name': 'django',
                        'installed_version': '3.2.0',
                        'cvss_score': '8.6',
                        'fixed_version': '3.2.19',
                        'cisa_kev': False
                    }
                ]
            },
            'index_scans': {
                'count': 5,
                'estimated_hours': 15,
                'items': []
            },
            'low_priority': {
                'count': 8,
                'estimated_hours': 0,
                'items': []
            }
        }
    }
    
    # Generate presentation
    generator = PPTXGenerator()
    generator.generate_pptx(sample_data, "security_report.pptx")

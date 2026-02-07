from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.enum.text import PP_ALIGN
from pptx.dml.color import RGBColor
from pathlib import Path

class PPTXGenerator:
    def __init__(self, master_pptx: Path = None):
        # Start with your master template if provided, else a blank slate
        self.prs = Presentation(str(master_pptx)) if master_pptx and master_pptx.exists() else Presentation()
        # Widescreen 16:9 ratio
        self.prs.slide_width = Inches(13.333)
        self.prs.slide_height = Inches(7.5)

    def _get_color(self, grade: str) -> RGBColor:
        colors = {
            'A': RGBColor(40, 167, 69),   # Green
            'B': RGBColor(108, 117, 125), # Gray
            'C': RGBColor(255, 193, 7),   # Yellow
            'F': RGBColor(220, 53, 69)    # Red
        }
        return colors.get(grade, RGBColor(0, 0, 0))

    def generate_pptx(self, data: dict, output_path: str):
        """Builds the 4-slide board deck"""
        self._add_title_slide(data)
        self._add_matrix_slide(data)
        self._add_critical_detail_slide(data)
        self._add_roadmap_slide(data)
        self.prs.save(output_path)

    def _add_title_slide(self, data):
        slide = self.prs.slides.add_slide(self.prs.slide_layouts[6]) # Blank
        
        # Big Grade Circle/Text
        title = slide.shapes.add_textbox(Inches(0.5), Inches(0.5), Inches(12), Inches(1.5))
        tf = title.text_frame
        tf.text = "Security Posture: Executive Brief"
        tf.paragraphs[0].font.size = Pt(44)
        tf.paragraphs[0].font.bold = True

        grade_box = slide.shapes.add_textbox(Inches(4), Inches(2), Inches(5), Inches(3))
        tf = grade_box.text_frame
        p = tf.paragraphs[0]
        p.text = data['grade']
        p.font.size = Pt(200)
        p.font.bold = True
        p.font.color.rgb = self._get_color(data['grade'])
        p.alignment = PP_ALIGN.CENTER

    def _add_matrix_slide(self, data):
        slide = self.prs.slides.add_slide(self.prs.slide_layouts[6])
        
        title = slide.shapes.add_textbox(Inches(0.5), Inches(0.3), Inches(12), Inches(1))
        title.text = "The 'Explain Plan': Resource Allocation"
        
        # We'll create 3 high-impact rectangles representing the plan
        plan = data['execution_plan']
        rows = [
            ("FULL TABLE SCAN (Critical)", plan['full_table_scans']['count'], "FIX THIS WEEK", RGBColor(248, 215, 218)),
            ("INDEX RANGE SCAN (High)", plan['index_scans']['count'], "SCHEDULE SPRINT", RGBColor(255, 243, 205)),
            ("SEQUENTIAL READ (Low)", plan['low_priority']['count'], "BATCH / IGNORE", RGBColor(233, 236, 239))
        ]

        for i, (label, count, action, color) in enumerate(rows):
            y = 1.5 + (i * 1.8)
            shape = slide.shapes.add_shape(1, Inches(1), Inches(y), Inches(11), Inches(1.5))
            shape.fill.solid()
            shape.fill.fore_color.rgb = color
            
            tf = shape.text_frame
            tf.text = f"{label}: {count} Findings"
            tf.paragraphs[0].font.size = Pt(24)
            tf.paragraphs[0].font.bold = True
            tf.paragraphs[0].font.color.rgb = RGBColor(0,0,0)
            
            p = tf.add_paragraph()
            p.text = f"Action Required: {action}"
            p.font.size = Pt(18)
            p.font.color.rgb = RGBColor(80,80,80)

    def _add_critical_detail_slide(self, data):
        slide = self.prs.slides.add_slide(self.prs.slide_layouts[6])
        title = slide.shapes.add_textbox(Inches(0.5), Inches(0.3), Inches(12), Inches(1))
        title.text = "High-Risk Path: Full Table Scans"
        
        # List top 3 criticals
        y = 1.5
        for item in data['execution_plan']['full_table_scans']['items'][:3]:
            box = slide.shapes.add_textbox(Inches(1), Inches(y), Inches(11), Inches(1.5))
            tf = box.text_frame
            tf.text = f"• {item.id}: {item.title}"
            tf.paragraphs[0].font.size = Pt(20)
            tf.paragraphs[0].font.bold = True
            
            p = tf.add_paragraph()
            p.text = f"  Impact: {item.pkg_name} | CVSS: {item.cvss_score} | Effort: {item.fix_effort_hours}h"
            p.font.size = Pt(16)
            y += 1.5

    def _add_roadmap_slide(self, data):
        slide = self.prs.slides.add_slide(self.prs.slide_layouts[6])
        title = slide.shapes.add_textbox(Inches(0.5), Inches(0.3), Inches(12), Inches(1))
        title.text = "Remediation Roadmap"
        
        # Placeholder for a simple chevron or list
        box = slide.shapes.add_textbox(Inches(1), Inches(2), Inches(11), Inches(4))
        tf = box.text_frame
        steps = [
            ("Week 1", f"Clear {data['execution_plan']['full_table_scans']['count']} 'Full Table Scans'"),
            ("Week 2-3", f"Address {data['execution_plan']['index_scans']['count']} 'Index Range Scans'"),
            ("End of Month", "Audit remaining low-priority findings")
        ]
        for week, task in steps:
            p = tf.add_paragraph()
            p.text = f"{week}: {task}"
            p.font.size = Pt(28)
            p.space_after = Pt(20)

"""
Unit tests for report_generator.py - PDF/HTML generation.
"""

import pytest
from pathlib import Path
from report_generator import ReportGenerator


class TestReportGeneratorInitialization:
    """Test generator setup."""
    
    def test_initializes_jinja_environment(self, temp_template_dir, temp_static_dir):
        """Should create Jinja2 environment with file loader."""
        gen = ReportGenerator(temp_template_dir, temp_static_dir)
        assert gen.env is not None
        assert gen.template_dir == temp_template_dir
    
    def test_registers_truncate_filter(self, temp_template_dir, temp_static_dir):
        """Should register custom truncate filter."""
        gen = ReportGenerator(temp_template_dir, temp_static_dir)
        assert "truncate" in gen.env.filters


class TestTruncateFilter:
    """Test custom Jinja2 truncate filter."""
    
    def test_truncates_long_strings(self, temp_template_dir, temp_static_dir):
        gen = ReportGenerator(temp_template_dir, temp_static_dir)
        truncate = gen._truncate_filter
        
        result = truncate("This is a very long string", length=10)
        assert len(result) <= 13  # 10 + "..."
        assert result.endswith("...")
    
    def test_no_truncate_short_strings(self, temp_template_dir, temp_static_dir):
        gen = ReportGenerator(temp_template_dir, temp_static_dir)
        truncate = gen._truncate_filter
        
        result = truncate("Short", length=10)
        assert result == "Short"
    
    def test_handles_none(self, temp_template_dir, temp_static_dir):
        gen = ReportGenerator(temp_template_dir, temp_static_dir)
        truncate = gen._truncate_filter
        
        result = truncate(None, length=10)
        assert result == ""
    
    def test_word_boundary_aware(self, temp_template_dir, temp_static_dir):
        gen = ReportGenerator(temp_template_dir, temp_static_dir)
        truncate = gen._truncate_filter
        
        # Should not cut mid-word
        result = truncate("The quick brown fox", length=12)
        assert result == "The quick..."  # Not "The quick br..."


class TestPayloadPreparation:
    """Test data sanitization and enrichment."""
    
    def test_ensures_metadata(self, temp_template_dir, temp_static_dir):
        gen = ReportGenerator(temp_template_dir, temp_static_dir)
        data = {}
        payload = gen._prepare_payload(data)
        
        assert "generated_at" in payload
        assert "report_id" in payload
    
    def test_preserves_existing_timestamp(self, temp_template_dir, temp_static_dir):
        """Should not overwrite engine-provided timestamp."""
        gen = ReportGenerator(temp_template_dir, temp_static_dir)
        data = {
            "report_id": "20231225-000000",
            "generated_at": "2023-12-25 00:00:00"
        }
        payload = gen._prepare_payload(data)
        
        assert payload["report_id"] == "20231225-000000"
        assert payload["generated_at"] == "2023-12-25 00:00:00"
    
    def test_applies_grade_styling(self, temp_template_dir, temp_static_dir):
        gen = ReportGenerator(temp_template_dir, temp_static_dir)
        data = {"grade": "A"}
        payload = gen._prepare_payload(data)
        
        assert payload["grade_color"] == "#28a745"
        assert payload["grade_label"] == "EXCELLENT"
    
    def test_calculates_effort_hours(self, temp_template_dir, temp_static_dir):
        gen = ReportGenerator(temp_template_dir, temp_static_dir)
        data = {
            "execution_plan": {
                "full_table_scans": {"estimated_hours": 10},
                "index_scans": {"estimated_hours": 8}
            }
        }
        payload = gen._prepare_payload(data)
        
        assert payload["total_effort_hours"] == 18
    
    def test_uses_provided_effort_hours(self, temp_template_dir, temp_static_dir):
        """Should not recalculate if engine provided total."""
        gen = ReportGenerator(temp_template_dir, temp_static_dir)
        data = {
            "total_effort_hours": 100,
            "execution_plan": {
                "full_table_scans": {"estimated_hours": 10}
            }
        }
        payload = gen._prepare_payload(data)
        
        assert payload["total_effort_hours"] == 100
    
    def test_handles_missing_logo(self, temp_template_dir, temp_static_dir):
        gen = ReportGenerator(temp_template_dir, temp_static_dir)
        data = {}
        payload = gen._prepare_payload(data)
        
        assert payload["logo_url"] is None
    
    def test_resolves_logo_if_present(self, temp_template_dir, temp_static_dir):
        # Create logo file
        logo = temp_static_dir / "logo.png"
        logo.write_bytes(b"fake png data")
        
        gen = ReportGenerator(temp_template_dir, temp_static_dir)
        data = {}
        payload = gen._prepare_payload(data)
        
        assert payload["logo_url"] is not None
        assert payload["logo_url"].startswith("file://")


class TestHTMLRendering:
    """Test template rendering."""
    
    def test_renders_template_with_data(self, temp_template_dir, temp_static_dir):
        gen = ReportGenerator(temp_template_dir, temp_static_dir)
        data = {
            "grade": "B",
            "summary": {"total_findings": 42},
            "execution_plan": {
                "full_table_scans": {"count": 2}
            }
        }
        
        html = gen._render_html(gen._prepare_payload(data))
        
        assert "Grade: B" in html
        assert "Total: 42" in html
        assert "Critical: 2" in html


class TestFileGeneration:
    """Test actual file output."""
    
    def test_generates_html_file(self, temp_template_dir, temp_static_dir, tmp_path):
        gen = ReportGenerator(temp_template_dir, temp_static_dir)
        output = tmp_path / "test.html"
        
        data = {
            "grade": "A",
            "summary": {"total_findings": 0},
            "execution_plan": {
                "full_table_scans": {"count": 0, "estimated_hours": 0, "items": []},
                "index_scans": {"count": 0, "estimated_hours": 0, "items": []},
                "nested_loops": {"count": 0, "estimated_hours": 0, "items": []},
                "low_priority": {"count": 0, "estimated_hours": 0, "items": []}
            }
        }
        
        gen.generate_html(data, output)
        
        assert output.exists()
        content = output.read_text()
        assert "Grade: A" in content
    
    def test_generates_pdf_file(self, temp_template_dir, temp_static_dir, tmp_path):
        """Note: Requires WeasyPrint dependencies (Cairo, Pango)."""
        pytest.importorskip("weasyprint", reason="WeasyPrint not installed")
        
        gen = ReportGenerator(temp_template_dir, temp_static_dir)
        output = tmp_path / "test.pdf"
        
        data = {
            "grade": "B",
            "report_id": "20240101-120000",
            "generated_at": "2024-01-01 12:00:00",
            "summary": {"total_findings": 5},
            "execution_plan": {
                "full_table_scans": {"count": 1, "estimated_hours": 6, "items": []},
                "index_scans": {"count": 2, "estimated_hours": 8, "items": []},
                "nested_loops": {"count": 1, "estimated_hours": 4, "items": []},
                "low_priority": {"count": 1, "estimated_hours": 0, "items": []}
            }
        }
        
        gen.generate_pdf(data, output)
        
        assert output.exists()
        assert output.stat().st_size > 0  # PDF has content


class TestDeepCopy:
    """Test that input data is not mutated."""
    
    def test_does_not_mutate_input(self, temp_template_dir, temp_static_dir):
        gen = ReportGenerator(temp_template_dir, temp_static_dir)
        
        original = {
            "grade": "C",
            "execution_plan": {
                "full_table_scans": {"count": 5}
            }
        }
        original_ep_count = original["execution_plan"]["full_table_scans"]["count"]
        
        gen._prepare_payload(original)
        
        # Original should be unchanged
        assert original["grade"] == "C"
        assert original["execution_plan"]["full_table_scans"]["count"] == original_ep_count

"""
Unit tests for main.py - Pipeline orchestration.
"""

import pytest
import json
from pathlib import Path
from main import ReportGCPipeline, generate_reports


class TestPipelineInitialization:
    """Test ReportGCPipeline setup."""
    
    def test_creates_output_directory(self, tmp_path):
        template = tmp_path / "templates"
        static = tmp_path / "static"
        output = tmp_path / "outputs"
        
        # Directory shouldn't exist yet
        assert not output.exists()
        
        pipeline = ReportGCPipeline(template, static, output)
        
        assert output.exists()
        assert output.is_dir()
    
    def test_uses_temp_dir_if_no_output_specified(self, tmp_path, monkeypatch):
        template = tmp_path / "templates"
        static = tmp_path / "static"
        
        import tempfile
        fake_temp = tmp_path / "fake_temp"
        fake_temp.mkdir()
        monkeypatch.setattr(tempfile, "gettempdir", lambda: str(fake_temp))
        
        pipeline = ReportGCPipeline(template, static)
        assert pipeline.output_dir == fake_temp


class TestInputValidation:
    """Test scan data validation."""
    
    def test_validates_trivy_format(self, tmp_path):
        template = tmp_path / "templates"
        static = tmp_path / "static"
        pipeline = ReportGCPipeline(template, static)
        
        trivy_data = {"Results": [{"Vulnerabilities": []}]}
        assert pipeline.validate_scan_data(trivy_data) is True
    
    def test_validates_sarif_format(self, tmp_path):
        template = tmp_path / "templates"
        static = tmp_path / "static"
        pipeline = ReportGCPipeline(template, static)
        
        sarif_data = {"runs": [{"tool": {"driver": {"rules": []}}, "results": []}]}
        assert pipeline.validate_scan_data(sarif_data) is True
    
    def test_rejects_invalid_format(self, tmp_path):
        template = tmp_path / "templates"
        static = tmp_path / "static"
        pipeline = ReportGCPipeline(template, static)
        
        invalid_data = {"random": "data"}
        assert pipeline.validate_scan_data(invalid_data) is False
    
    def test_rejects_non_dict_input(self, tmp_path):
        template = tmp_path / "templates"
        static = tmp_path / "static"
        pipeline = ReportGCPipeline(template, static)
        
        assert pipeline.validate_scan_data("string") is False
        assert pipeline.validate_scan_data(None) is False
        assert pipeline.validate_scan_data([1, 2, 3]) is False


class TestProcessScan:
    """Test full pipeline execution."""
    
    def test_raises_on_invalid_data(self, tmp_path):
        template = tmp_path / "templates"
        static = tmp_path / "static"
        pipeline = ReportGCPipeline(template, static)
        
        with pytest.raises(ValueError, match="Invalid scan_data"):
            pipeline.process_scan("not a dict")
        
        with pytest.raises(ValueError, match="Invalid scan_data"):
            pipeline.process_scan({})
    
    def test_processes_valid_trivy_scan(self, tmp_path, temp_template_dir, temp_static_dir):
        pipeline = ReportGCPipeline(temp_template_dir, temp_static_dir, tmp_path)
        
        scan_data = {
            "Results": [{
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2023-1234",
                    "Title": "Test",
                    "Severity": "HIGH",
                    "CVSS": {"nvd": {"V3Score": 7.5}},
                    "FixedVersion": "1.2.3",
                    "PkgName": "test-pkg",
                    "InstalledVersion": "1.0.0",
                    "Description": "Test vulnerability"
                }]
            }]
        }
        
        result = pipeline.process_scan(scan_data)
        
        assert "pdf" in result
        assert "pptx" in result
        assert "report_id" in result
        assert "data" in result
        assert result["data"]["grade"] == "A"  # No criticals
    
    def test_uses_custom_report_id(self, tmp_path, temp_template_dir, temp_static_dir):
        pipeline = ReportGCPipeline(temp_template_dir, temp_static_dir, tmp_path)
        
        scan_data = {"Results": [{"Vulnerabilities": []}]}
        custom_id = "CUSTOM-12345"
        
        result = pipeline.process_scan(scan_data, report_id=custom_id)
        
        assert result["report_id"] == custom_id
        assert custom_id in str(result["pdf"])
        assert custom_id in str(result["pptx"])


class TestTemporaryReport:
    """Test automatic cleanup context manager."""
    
    def test_cleans_up_files_after_exit(self, tmp_path, temp_template_dir, temp_static_dir):
        pipeline = ReportGCPipeline(temp_template_dir, temp_static_dir, tmp_path)
        
        scan_data = {"Results": [{"Vulnerabilities": []}]}
        
        pdf_path = None
        pptx_path = None
        
        with pipeline.temporary_report(scan_data) as result:
            pdf_path = result["pdf"]
            pptx_path = result["pptx"]
            
            # Files should exist inside context
            assert pdf_path.exists()
            assert pptx_path.exists()
        
        # Files should be deleted after exit
        assert not pdf_path.exists()
        assert not pptx_path.exists()
    
    def test_cleans_up_on_exception(self, tmp_path, temp_template_dir, temp_static_dir):
        pipeline = ReportGCPipeline(temp_template_dir, temp_static_dir, tmp_path)
        
        scan_data = {"Results": [{"Vulnerabilities": []}]}
        
        pdf_path = None
        
        try:
            with pipeline.temporary_report(scan_data) as result:
                pdf_path = result["pdf"]
                assert pdf_path.exists()
                raise RuntimeError("Simulated error")
        except RuntimeError:
            pass
        
        # Should still cleanup on exception
        assert not pdf_path.exists()


class TestConvenienceFunction:
    """Test generate_reports() one-shot function."""
    
    def test_accepts_dict_input(self, tmp_path, temp_template_dir, temp_static_dir):
        scan_data = {"Results": [{"Vulnerabilities": []}]}
        
        result = generate_reports(
            scan_data,
            str(temp_template_dir),
            str(temp_static_dir),
            str(tmp_path)
        )
        
        assert "pdf" in result
        assert "pptx" in result
        assert "report_id" in result
    
    def test_accepts_json_string(self, tmp_path, temp_template_dir, temp_static_dir):
        scan_data = {"Results": [{"Vulnerabilities": []}]}
        json_string = json.dumps(scan_data)
        
        result = generate_reports(
            json_string,
            str(temp_template_dir),
            str(temp_static_dir),
            str(tmp_path)
        )
        
        assert "pdf" in result
        assert "pptx" in result


class TestErrorHandling:
    """Test error cases and cleanup."""
    
    def test_cleans_up_partial_output_on_failure(self, tmp_path, temp_template_dir, temp_static_dir, monkeypatch):
        pipeline = ReportGCPipeline(temp_template_dir, temp_static_dir, tmp_path)
        
        # Mock PDF generation to fail
        def mock_generate_pdf(*args, **kwargs):
            raise RuntimeError("PDF generation failed")
        
        monkeypatch.setattr(pipeline.report_gen, "generate_pdf", mock_generate_pdf)
        
        scan_data = {"Results": [{"Vulnerabilities": []}]}
        
        with pytest.raises(RuntimeError, match="Report generation failed"):
            pipeline.process_scan(scan_data)
        
        # Should not leave partial files
        assert len(list(tmp_path.glob("*.pdf"))) == 0
        assert len(list(tmp_path.glob("*.pptx"))) == 0

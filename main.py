"""
ReportGC - Main Orchestrator
Thin wrapper around engine.py for web framework integration (Flask/FastAPI)
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
import tempfile
import shutil
from contextlib import contextmanager

# Import canonical engine
from engine import SecurityExplainPlan, Finding, RiskLevel

# Import generators
from pptx_generator import PPTXGenerator
from report_generator import ReportGenerator


class ReportGCPipeline:
    """
    High-level orchestrator for the ReportGC security reporting pipeline.
    
    Responsibilities:
    - Input validation and sanitization
    - Orchestrate Engine → Generators flow
    - Temporary file management with automatic cleanup
    - Error handling and logging hooks
    """
    
    def __init__(
        self,
        template_dir: Path,
        static_dir: Path,
        output_dir: Optional[Path] = None
    ):
        self.template_dir = Path(template_dir)
        self.static_dir = Path(static_dir)
        self.output_dir = Path(output_dir) if output_dir else Path(tempfile.gettempdir())
        
        # Initialize generators
        self.report_gen = ReportGenerator(self.template_dir, self.static_dir)
        self.pptx_gen = PPTXGenerator()  # Can pass master_pptx if needed
        
        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def process_scan(
        self,
        scan_data: Dict[str, Any],
        report_id: Optional[str] = None
    ) -> Dict[str, Path]:
        """
        Process scanner output through full pipeline.
        
        Args:
            scan_data: Raw Trivy or SARIF JSON output
            report_id: Optional custom report ID (default: timestamp)
            
        Returns:
            Dict with paths to generated files: {'pdf': Path, 'pptx': Path}
            
        Raises:
            ValueError: If scan_data is invalid or empty
            RuntimeError: If report generation fails
        """
        # Input validation
        if not scan_data or not isinstance(scan_data, dict):
            raise ValueError("Invalid scan_data: must be non-empty dict")
        
        # Step 1: Engine (Security Explain Plan)
        try:
            engine = SecurityExplainPlan(scan_data)
            data = engine.to_dict()
        except Exception as e:
            raise RuntimeError(f"Engine processing failed: {e}") from e
        
        # Override report_id if provided (for consistency)
        if report_id:
            data['report_id'] = report_id
            data['generated_at'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Step 2: Generate outputs
        report_id = data['report_id']
        pdf_path = self.output_dir / f"ReportGC-{report_id}.pdf"
        pptx_path = self.output_dir / f"ReportGC-{report_id}.pptx"
        
        try:
            # PDF Report
            self.report_gen.generate_pdf(data, pdf_path)
            
            # PPTX Presentation
            self.pptx_gen.generate_pptx(data, str(pptx_path))
            
        except Exception as e:
            # Cleanup partial outputs on failure
            for path in [pdf_path, pptx_path]:
                if path.exists():
                    path.unlink()
            raise RuntimeError(f"Report generation failed: {e}") from e
        
        return {
            'pdf': pdf_path,
            'pptx': pptx_path,
            'report_id': report_id,
            'data': data  # Raw data for debugging/API response
        }

    @contextmanager
    def temporary_report(self, scan_data: Dict[str, Any]):
        """
        Context manager for temporary report generation with automatic cleanup.
        
        Usage:
            with pipeline.temporary_report(scan_data) as paths:
                # Do something with paths['pdf'], paths['pptx']
                pass
            # Files automatically deleted here
        """
        paths = None
        try:
            paths = self.process_scan(scan_data)
            yield paths
        finally:
            if paths:
                for key in ['pdf', 'pptx']:
                    path = paths.get(key)
                    if path and Path(path).exists():
                        Path(path).unlink(missing_ok=True)

    def validate_scan_data(self, scan_data: Dict[str, Any]) -> bool:
        """
        Pre-flight validation of scanner output format.
        """
        if not isinstance(scan_data, dict):
            return False
        
        # Check for Trivy format
        if "Results" in scan_data:
            return True
        
        # Check for SARIF format
        if "runs" in scan_data:
            return True
        
        return False


# Convenience function for simple usage
def generate_reports(
    scan_json: str or Dict,
    template_dir: str,
    static_dir: str,
    output_dir: Optional[str] = None
) -> Dict[str, str]:
    """
    One-shot function to generate reports from scanner JSON.
    
    Args:
        scan_json: JSON string or dict from Trivy/SARIF scanner
        template_dir: Path to report.html templates
        static_dir: Path to static assets (logo, css)
        output_dir: Where to save files (default: temp dir)
        
    Returns:
        Dict with file paths: {'pdf': str, 'pptx': str, 'report_id': str}
    """
    # Parse JSON if string provided
    if isinstance(scan_json, str):
        scan_data = json.loads(scan_json)
    else:
        scan_data = scan_json
    
    pipeline = ReportGCPipeline(
        template_dir=Path(template_dir),
        static_dir=Path(static_dir),
        output_dir=Path(output_dir) if output_dir else None
    )
    
    result = pipeline.process_scan(scan_data)
    
    return {
        'pdf': str(result['pdf']),
        'pptx': str(result['pptx']),
        'report_id': result['report_id']
    }


# Flask/FastAPI integration example
def create_api_endpoint(pipeline: ReportGCPipeline):
    """
    Example usage with Flask:
    
    from flask import Flask, request, send_file
    app = Flask(__name__)
    pipeline = ReportGCPipeline(...)
    
    @app.route('/api/report', methods=['POST'])
    def generate_report():
        scan_data = request.get_json()
        if not pipeline.validate_scan_data(scan_data):
            return {'error': 'Invalid scan format'}, 400
        
        try:
            with pipeline.temporary_report(scan_data) as result:
                # Return PDF immediately, then cleanup
                return send_file(
                    result['pdf'],
                    mimetype='application/pdf',
                    as_attachment=True,
                    download_name=f"ReportGC-{result['report_id']}.pdf"
                )
        except Exception as e:
            return {'error': str(e)}, 500
    """
    pass

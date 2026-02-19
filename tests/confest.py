"""
Shared test fixtures and utilities for ReportGC test suite.
"""

import pytest
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

# Add project root to path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from engine import SecurityExplainPlan, Finding, RiskLevel


class TestDataFactory:
    """Factory for creating test data objects."""
    
    @staticmethod
    def create_finding(
        id: str = "CVE-2023-1234",
        title: str = "Test Vulnerability",
        severity: str = "HIGH",
        cvss_score: float = 7.5,
        cisa_kev: bool = False,
        fixed_version: str = "1.2.3",
        pkg_name: str = "test-package",
        installed_version: str = "1.0.0",
        description: str = "Test description"
    ) -> Finding:
        return Finding(
            id=id,
            title=title,
            severity=severity,
            cvss_score=cvss_score,
            cisa_kev=cisa_kev,
            fixed_version=fixed_version,
            pkg_name=pkg_name,
            installed_version=installed_version,
            description=description
        )
    
    @staticmethod
    def create_trivy_vulnerability(
        vuln_id: str = "CVE-2023-1234",
        title: str = "Test Vuln",
        severity: str = "HIGH",
        cvss_score: float = 7.5,
        fixed_version: str = "1.2.3",
        pkg_name: str = "test-pkg",
        installed_version: str = "1.0.0",
        description: str = "Test desc"
    ) -> Dict[str, Any]:
        return {
            "VulnerabilityID": vuln_id,
            "Title": title,
            "Severity": severity,
            "CVSS": {"nvd": {"V3Score": cvss_score}},
            "FixedVersion": fixed_version,
            "PkgName": pkg_name,
            "InstalledVersion": installed_version,
            "Description": description,
            "CisaKnownExploited": False
        }
    
    @staticmethod
    def create_trivy_scan(results: List[Dict] = None) -> Dict[str, Any]:
        if results is None:
            results = [{"Vulnerabilities": [TestDataFactory.create_trivy_vulnerability()]}]
        return {"Results": results}
    
    @staticmethod
    def create_sarif_scan(rules: List[Dict] = None, results: List[Dict] = None) -> Dict[str, Any]:
        if rules is None:
            rules = [{
                "id": "CVE-2023-1234",
                "shortDescription": {"text": "Test Vulnerability"},
                "properties": {
                    "severity": "HIGH",
                    "cvssV3_score": 7.5,
                    "fixedVersion": "1.2.3",
                    "pkgName": "test-pkg"
                }
            }]
        if results is None:
            results = [{
                "ruleId": "CVE-2023-1234",
                "level": "error",
                "message": {"text": "Test finding"}
            }]
        return {
            "runs": [{
                "tool": {"driver": {"rules": rules}},
                "results": results
            }]
        }


@pytest.fixture
def factory():
    """Provide TestDataFactory instance."""
    return TestDataFactory()


@pytest.fixture
def sample_critical_finding(factory):
    """Create a critical severity finding."""
    return factory.create_finding(
        id="CVE-2023-9999",
        cvss_score=9.8,
        cisa_kev=True,
        severity="CRITICAL"
    )


@pytest.fixture
def sample_high_finding(factory):
    """Create a high severity finding."""
    return factory.create_finding(cvss_score=7.5, severity="HIGH")


@pytest.fixture
def sample_medium_finding(factory):
    """Create a medium severity finding."""
    return factory.create_finding(cvss_score=5.5, severity="MEDIUM")


@pytest.fixture
def sample_low_finding(factory):
    """Create a low severity finding."""
    return factory.create_finding(cvss_score=2.0, severity="LOW")


@pytest.fixture
def sample_trivy_scan(factory):
    """Create sample Trivy scan data."""
    return factory.create_trivy_scan()


@pytest.fixture
def sample_sarif_scan(factory):
    """Create sample SARIF scan data."""
    return factory.create_sarif_scan()


@pytest.fixture
def temp_output_dir(tmp_path):
    """Provide temporary output directory."""
    output_dir = tmp_path / "reports"
    output_dir.mkdir()
    return output_dir


@pytest.fixture
def temp_template_dir(tmp_path):
    """Provide temporary template directory with report.html."""
    template_dir = tmp_path / "templates"
    template_dir.mkdir()
    
    # Create minimal report.html template
    html_content = """
    <!DOCTYPE html>
    <html>
    <head><title>Test Report</title></head>
    <body>
        <h1>Grade: {{ grade }}</h1>
        <p>Total: {{ summary.total_findings }}</p>
        <p>Critical: {{ execution_plan.full_table_scans.count }}</p>
    </body>
    </html>
    """
    (template_dir / "report.html").write_text(html_content)
    return template_dir


@pytest.fixture
def temp_static_dir(tmp_path):
    """Provide temporary static directory."""
    static_dir = tmp_path / "static"
    static_dir.mkdir()
    return static_dir

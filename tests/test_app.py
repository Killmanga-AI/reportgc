import json
import os
from pathlib import Path
from fastapi.testclient import TestClient
from main import app
from engine import SecurityExplainPlan, RiskLevel

client = TestClient(app)

# --- MOCK DATA ---
MOCK_TRIVY_JSON = {
    "Results": [
        {
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-CRITICAL",
                    "Title": "Test Critical",
                    "Severity": "CRITICAL",
                    "CVSS": {"nvd": {"V3Score": 9.8}},
                    "PkgName": "test-lib",
                    "InstalledVersion": "1.0.0",
                    "FixedVersion": "1.0.1"
                },
                {
                    "VulnerabilityID": "CVE-2023-HIGH",
                    "Title": "Test High",
                    "Severity": "HIGH",
                    "CVSS": {"nvd": {"V3Score": 7.5}},
                    "PkgName": "test-lib-2"
                }
            ]
        }
    ]
}

# --- UNIT TESTS (LOGIC) ---

def test_grading_logic():
    """Test if logic correctly counts criticals and assigns grades"""
    plan = SecurityExplainPlan(MOCK_TRIVY_JSON)
    data = plan.to_dict()
    
    # We have 1 critical, so grade should be B (0=A, 1-2=B)
    assert data['grade'] == 'B'
    assert data['summary']['critical'] == 1
    assert data['summary']['high'] == 1

def test_risk_classification():
    """Test if CVSS scores map to correct 'Database' terms"""
    plan = SecurityExplainPlan(MOCK_TRIVY_JSON)
    findings = plan.findings
    
    critical = next(f for f in findings if f.id == "CVE-2023-CRITICAL")
    high = next(f for f in findings if f.id == "CVE-2023-HIGH")
    
    assert critical.risk_level == RiskLevel.CRITICAL
    assert high.risk_level == RiskLevel.HIGH

# --- INTEGRATION TESTS (API) ---

def test_home_page():
    response = client.get("/")
    assert response.status_code == 200
    assert "Security Explain Plan" in response.text

def test_analyze_endpoint():
    """Test the full upload flow"""
    # Create a temporary JSON file
    json_content = json.dumps(MOCK_TRIVY_JSON).encode('utf-8')
    
    files = {'file': ('test_scan.json', json_content, 'application/json')}
    response = client.post("/analyze", files=files)
    
    assert response.status_code == 200
    assert "Analysis Complete" in response.text
    assert "Download PDF Report" in response.text

def test_invalid_file_upload():
    """Ensure we reject non-JSON files"""
    files = {'file': ('evil.exe', b'bad data', 'application/octet-stream')}
    response = client.post("/analyze", files=files)
    
    assert response.status_code == 400
    assert "Invalid file type" in response.json()['detail']

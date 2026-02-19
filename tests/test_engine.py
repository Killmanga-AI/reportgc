"""
Unit tests for engine.py - Core security logic and data classification.
"""

import pytest
from engine import SecurityExplainPlan, Finding, RiskLevel


class TestRiskLevelClassification:
    """Test risk level assignment based on CVSS and CISA KEV."""
    
    def test_critical_cisa_kev_overrides_low_cvss(self, factory):
        """CISA KEV flag should make any vulnerability critical."""
        finding = factory.create_finding(cvss_score=2.0, cisa_kev=True)
        assert finding.risk_level == RiskLevel.FULL_TABLE_SCAN
    
    def test_critical_cvss_9_or_above(self, factory):
        """CVSS >= 9.0 should be critical regardless of CISA status."""
        finding = factory.create_finding(cvss_score=9.0, cisa_kev=False)
        assert finding.risk_level == RiskLevel.FULL_TABLE_SCAN
        
        finding = factory.create_finding(cvss_score=9.8, cisa_kev=False)
        assert finding.risk_level == RiskLevel.FULL_TABLE_SCAN
    
    def test_high_cvss_7_to_8_9(self, factory):
        """CVSS 7.0-8.9 should be high severity."""
        finding = factory.create_finding(cvss_score=7.0)
        assert finding.risk_level == RiskLevel.INDEX_RANGE_SCAN
        
        finding = factory.create_finding(cvss_score=8.9)
        assert finding.risk_level == RiskLevel.INDEX_RANGE_SCAN
    
    def test_medium_cvss_4_to_6_9(self, factory):
        """CVSS 4.0-6.9 should be medium severity."""
        finding = factory.create_finding(cvss_score=4.0)
        assert finding.risk_level == RiskLevel.NESTED_LOOP
        
        finding = factory.create_finding(cvss_score=6.9)
        assert finding.risk_level == RiskLevel.NESTED_LOOP
    
    def test_low_cvss_below_4(self, factory):
        """CVSS < 4.0 should be low severity."""
        finding = factory.create_finding(cvss_score=3.9)
        assert finding.risk_level == RiskLevel.SEQUENTIAL_READ
        
        finding = factory.create_finding(cvss_score=0.1)
        assert finding.risk_level == RiskLevel.SEQUENTIAL_READ


class TestFixEffortCalculation:
    """Test remediation effort estimation."""
    
    def test_core_package_24_hours(self, factory):
        """Kernel, glibc, openssl should be 24h regardless of CVSS."""
        for pkg in ["kernel", "glibc", "openssl", "KERNEL", "Glibc"]:
            finding = factory.create_finding(pkg_name=pkg, fixed_version=None)
            assert finding.fix_effort_hours == 24
    
    def test_no_patch_8_hours(self, factory):
        """No fixed_version should default to 8h."""
        finding = factory.create_finding(fixed_version=None, pkg_name="random-pkg")
        assert finding.fix_effort_hours == 8
    
    def test_critical_patch_6_hours(self, factory):
        """Critical with patch should be 6h."""
        finding = factory.create_finding(cvss_score=9.5, fixed_version="1.2.3")
        assert finding.fix_effort_hours == 6
    
    def test_standard_patch_4_hours(self, factory):
        """Non-critical with patch should be 4h."""
        finding = factory.create_finding(cvss_score=7.5, fixed_version="1.2.3")
        assert finding.fix_effort_hours == 4


class TestFindingSerialization:
    """Test Finding.to_dict() method."""
    
    def test_to_dict_includes_computed_fields(self, factory):
        """Serialized finding should include risk_level and fix_effort_hours."""
        finding = factory.create_finding(cvss_score=7.5)
        data = finding.to_dict()
        
        assert "risk_level" in data
        assert "fix_effort_hours" in data
        assert data["risk_level"] == "INDEX_RANGE_SCAN"
        assert data["fix_effort_hours"] == 4
    
    def test_to_dict_preserves_base_fields(self, factory):
        """All original fields should be present in output."""
        finding = factory.create_finding(id="TEST-123", title="Test Title")
        data = finding.to_dict()
        
        assert data["id"] == "TEST-123"
        assert data["title"] == "Test Title"
        assert data["cvss_score"] == 7.5


class TestSecurityExplainPlanParsing:
    """Test scan data parsing from different formats."""
    
    def test_detects_sarif_format(self, factory):
        """Should detect SARIF by 'runs' key."""
        sarif_data = factory.create_sarif_scan()
        plan = SecurityExplainPlan(sarif_data)
        assert len(plan.findings) == 1
    
    def test_detects_trivy_format(self, factory):
        """Should detect Trivy by absence of 'runs' key."""
        trivy_data = factory.create_trivy_scan()
        plan = SecurityExplainPlan(trivy_data)
        assert len(plan.findings) == 1
    
    def test_parses_multiple_vulnerabilities(self, factory):
        """Should handle multiple findings in one scan."""
        vulns = [
            factory.create_trivy_vulnerability(vuln_id="CVE-1", cvss_score=9.0),
            factory.create_trivy_vulnerability(vuln_id="CVE-2", cvss_score=7.5),
            factory.create_trivy_vulnerability(vuln_id="CVE-3", cvss_score=5.0),
        ]
        scan = factory.create_trivy_scan([{"Vulnerabilities": vulns}])
        plan = SecurityExplainPlan(scan)
        
        assert len(plan.findings) == 3
    
    def test_handles_empty_scan(self, factory):
        """Should handle scan with no findings."""
        scan = {"Results": [{"Vulnerabilities": []}]}
        plan = SecurityExplainPlan(scan)
        
        assert len(plan.findings) == 0
        assert plan.grade == "A"


class TestGradeCalculation:
    """Test security grade assignment."""
    
    def test_grade_a_no_critical(self, factory):
        """0 critical findings = Grade A."""
        scan = factory.create_trivy_scan([
            {"Vulnerabilities": [
                factory.create_trivy_vulnerability(cvss_score=7.5),
                factory.create_trivy_vulnerability(cvss_score=5.0)
            ]}
        ])
        plan = SecurityExplainPlan(scan)
        assert plan.grade == "A"
    
    def test_grade_b_one_critical(self, factory):
        """1-2 critical = Grade B."""
        scan = factory.create_trivy_scan([
            {"Vulnerabilities": [
                factory.create_trivy_vulnerability(cvss_score=9.5),
            ]}
        ])
        plan = SecurityExplainPlan(scan)
        assert plan.grade == "B"
    
    def test_grade_c_three_critical(self, factory):
        """3-5 critical = Grade C."""
        vulns = [factory.create_trivy_vulnerability(cvss_score=9.5) for _ in range(3)]
        scan = factory.create_trivy_scan([{"Vulnerabilities": vulns}])
        plan = SecurityExplainPlan(scan)
        assert plan.grade == "C"
    
    def test_grade_d_six_critical(self, factory):
        """6-10 critical = Grade D."""
        vulns = [factory.create_trivy_vulnerability(cvss_score=9.5) for _ in range(6)]
        scan = factory.create_trivy_scan([{"Vulnerabilities": vulns}])
        plan = SecurityExplainPlan(scan)
        assert plan.grade == "D"
    
    def test_grade_f_eleven_critical(self, factory):
        """11+ critical = Grade F."""
        vulns = [factory.create_trivy_vulnerability(cvss_score=9.5) for _ in range(11)]
        scan = factory.create_trivy_scan([{"Vulnerabilities": vulns}])
        plan = SecurityExplainPlan(scan)
        assert plan.grade == "F"


class TestExecutionPlanOutput:
    """Test to_dict() output structure."""
    
    def test_summary_counts_accurate(self, factory):
        """Summary should accurately count each severity tier."""
        vulns = [
            factory.create_trivy_vulnerability(vuln_id="C1", cvss_score=9.5),  # Critical
            factory.create_trivy_vulnerability(vuln_id="C2", cvss_score=9.8),  # Critical
            factory.create_trivy_vulnerability(vuln_id="H1", cvss_score=7.5),  # High
            factory.create_trivy_vulnerability(vuln_id="M1", cvss_score=5.5),  # Medium
            factory.create_trivy_vulnerability(vuln_id="L1", cvss_score=2.0),  # Low
        ]
        scan = factory.create_trivy_scan([{"Vulnerabilities": vulns}])
        plan = SecurityExplainPlan(scan)
        data = plan.to_dict()
        
        assert data["summary"]["critical"] == 2
        assert data["summary"]["high"] == 1
        assert data["summary"]["medium"] == 1
        assert data["summary"]["low"] == 1
        assert data["summary"]["total_findings"] == 5
    
    def test_execution_plan_has_all_sections(self, factory):
        """Output should have all 4 execution plan sections."""
        scan = factory.create_trivy_scan([
            {"Vulnerabilities": [factory.create_trivy_vulnerability()]}
        ])
        plan = SecurityExplainPlan(scan)
        data = plan.to_dict()
        
        assert "full_table_scans" in data["execution_plan"]
        assert "index_scans" in data["execution_plan"]
        assert "nested_loops" in data["execution_plan"]
        assert "low_priority" in data["execution_plan"]
    
    def test_items_in_correct_buckets(self, factory):
        """Findings should be sorted into correct risk buckets."""
        vulns = [
            factory.create_trivy_vulnerability(vuln_id="CRIT", cvss_score=9.5),
            factory.create_trivy_vulnerability(vuln_id="HIGH", cvss_score=7.5),
            factory.create_trivy_vulnerability(vuln_id="MED", cvss_score=5.0),
            factory.create_trivy_vulnerability(vuln_id="LOW", cvss_score=2.0),
        ]
        scan = factory.create_trivy_scan([{"Vulnerabilities": vulns}])
        plan = SecurityExplainPlan(scan)
        data = plan.to_dict()
        
        crit_ids = [f["id"] for f in data["execution_plan"]["full_table_scans"]["items"]]
        high_ids = [f["id"] for f in data["execution_plan"]["index_scans"]["items"]]
        med_ids = [f["id"] for f in data["execution_plan"]["nested_loops"]["items"]]
        low_ids = [f["id"] for f in data["execution_plan"]["low_priority"]["items"]]
        
        assert "CRIT" in crit_ids
        assert "HIGH" in high_ids
        assert "MED" in med_ids
        assert "LOW" in low_ids
    
    def test_effort_hours_summed_correctly(self, factory):
        """Total effort should sum critical + high hours."""
        vulns = [
            factory.create_trivy_vulnerability(vuln_id="C1", cvss_score=9.5, fixed_version="1.0"),  # 6h
            factory.create_trivy_vulnerability(vuln_id="C2", cvss_score=9.8, fixed_version="1.0"),  # 6h
            factory.create_trivy_vulnerability(vuln_id="H1", cvss_score=7.5, fixed_version="1.0"),  # 4h
        ]
        scan = factory.create_trivy_scan([{"Vulnerabilities": vulns}])
        plan = SecurityExplainPlan(scan)
        data = plan.to_dict()
        
        # 6 + 6 + 4 = 16 hours
        assert data["total_effort_hours"] == 16


class TestCVSSExtraction:
    """Test CVSS score extraction from various sources."""
    
    def test_extracts_nvd_first(self, factory):
        """Should prefer NVD CVSS when available."""
        vuln = {
            "VulnerabilityID": "TEST-1",
            "CVSS": {
                "nvd": {"V3Score": 8.5},
                "redhat": {"V3Score": 7.5}
            }
        }
        scan = factory.create_trivy_scan([
            {"Vulnerabilities": [vuln]}
        ])
        plan = SecurityExplainPlan(scan)
        assert plan.findings[0].cvss_score == 8.5
    
    def test_fallback_to_redhat(self, factory):
        """Should fallback to Red Hat if NVD missing."""
        vuln = {
            "VulnerabilityID": "TEST-1",
            "CVSS": {
                "redhat": {"V3Score": 7.5}
            }
        }
        scan = factory.create_trivy_scan([
            {"Vulnerabilities": [vuln]}
        ])
        plan = SecurityExplainPlan(scan)
        assert plan.findings[0].cvss_score == 7.5
    
    def test_fallback_to_severity_string(self, factory):
        """Should use severity mapping if no CVSS data."""
        vuln = {
            "VulnerabilityID": "TEST-1",
            "Severity": "HIGH",
            "CVSS": {}
        }
        scan = factory.create_trivy_scan([
            {"Vulnerabilities": [vuln]}
        ])
        plan = SecurityExplainPlan(scan)
        assert plan.findings[0].cvss_score == 7.5  # HIGH fallback


class TestCISAKEVDetection:
    """Test CISA Known Exploited Vulnerability detection."""
    
    def test_detects_explicit_flag(self, factory):
        """Should detect CisaKnownExploited=True."""
        vuln = factory.create_trivy_vulnerability()
        vuln["CisaKnownExploited"] = True
        scan = factory.create_trivy_scan([
            {"Vulnerabilities": [vuln]}
        ])
        plan = SecurityExplainPlan(scan)
        assert plan.findings[0].cisa_kev is True
    
    def test_detects_cisa_url(self, factory):
        """Should detect CISA KEV from URL references."""
        vuln = factory.create_trivy_vulnerability()
        vuln["PrimaryURL"] = "https://www.cisa.gov/known-exploited-vulnerabilities"
        scan = factory.create_trivy_scan([
            {"Vulnerabilities": [vuln]}
        ])
        plan = SecurityExplainPlan(scan)
        assert plan.findings[0].cisa_kev is True

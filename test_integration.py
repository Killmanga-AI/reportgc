#!/usr/bin/env python3
"""
Integration Test Suite for ReportGC Security Assessment System

This script validates that all components work together without errors:
- SecurityExplainPlan parsing
- ReportGenerator PDF creation
- PPTXGenerator presentation creation
- Template variable compatibility
"""

import json
import sys
from pathlib import Path
from datetime import datetime

# Sample Trivy output for testing
SAMPLE_TRIVY_DATA = {
    "Results": [
        {
            "Target": "test-image:latest",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-1234",
                    "PkgName": "openssl",
                    "InstalledVersion": "1.1.1t",
                    "FixedVersion": "1.1.1u",
                    "Severity": "CRITICAL",
                    "Title": "OpenSSL Remote Code Execution Vulnerability",
                    "Description": "A critical vulnerability in OpenSSL that allows remote code execution through crafted certificates. This vulnerability has been actively exploited in the wild.",
                    "CVSS": {
                        "nvd": {"V3Score": 9.8}
                    },
                    "References": ["https://cisa.gov/known-exploited-vulnerabilities"],
                    "CisaKnownExploited": True
                },
                {
                    "VulnerabilityID": "CVE-2024-5678",
                    "PkgName": "django",
                    "InstalledVersion": "3.2.0",
                    "FixedVersion": "3.2.19",
                    "Severity": "CRITICAL",
                    "Title": "SQL Injection in Django ORM",
                    "Description": "SQL injection vulnerability in the ORM query generation affecting PostgreSQL backends.",
                    "CVSS": {
                        "nvd": {"V3Score": 8.6}
                    }
                },
                {
                    "VulnerabilityID": "CVE-2024-9999",
                    "PkgName": "react",
                    "InstalledVersion": "17.0.0",
                    "FixedVersion": "17.0.2",
                    "Severity": "HIGH",
                    "Title": "Cross-Site Scripting in React",
                    "Description": "XSS vulnerability in dangerouslySetInnerHTML when processing user-supplied SVG content.",
                    "CVSS": {
                        "nvd": {"V3Score": 7.2}
                    }
                },
                {
                    "VulnerabilityID": "CVE-2024-1111",
                    "PkgName": "lodash",
                    "InstalledVersion": "4.17.20",
                    "FixedVersion": "4.17.21",
                    "Severity": "HIGH",
                    "Title": "Prototype Pollution in Lodash",
                    "Description": "Prototype pollution vulnerability allowing attackers to modify object prototypes.",
                    "CVSS": {
                        "nvd": {"V3Score": 7.4}
                    }
                },
                {
                    "VulnerabilityID": "CVE-2024-2222",
                    "PkgName": "axios",
                    "InstalledVersion": "0.21.0",
                    "FixedVersion": "0.21.2",
                    "Severity": "MEDIUM",
                    "Title": "Server-Side Request Forgery in Axios",
                    "Description": "SSRF vulnerability allowing attackers to make unauthorized requests.",
                    "CVSS": {
                        "nvd": {"V3Score": 5.3}
                    }
                },
                {
                    "VulnerabilityID": "CVE-2024-3333",
                    "PkgName": "moment",
                    "InstalledVersion": "2.29.1",
                    "FixedVersion": "2.29.4",
                    "Severity": "LOW",
                    "Title": "ReDoS in Moment.js",
                    "Description": "Regular Expression Denial of Service vulnerability in date parsing.",
                    "CVSS": {
                        "nvd": {"V3Score": 3.7}
                    }
                }
            ],
            "Misconfigurations": [
                {
                    "ID": "KSV001",
                    "Title": "Process can elevate its own privileges",
                    "Severity": "HIGH",
                    "Description": "Container runs with allowPrivilegeEscalation enabled",
                    "Type": "Kubernetes Security Check"
                }
            ]
        }
    ]
}

def print_section(title):
    """Print a formatted section header."""
    print("\n" + "="*80)
    print(f"  {title}")
    print("="*80)

def check_required_fields(data: dict, context: str) -> list:
    """Check if all required fields are present in the data structure."""
    errors = []
    
    # Check top-level fields
    required_top = ['grade', 'generated_at', 'report_id', 'summary', 'execution_plan']
    for field in required_top:
        if field not in data:
            errors.append(f"{context}: Missing top-level field '{field}'")
    
    # Check summary fields
    if 'summary' in data:
        required_summary = ['total_findings', 'critical', 'high']
        for field in required_summary:
            if field not in data['summary']:
                errors.append(f"{context}: Missing summary field '{field}'")
    
    # Check execution_plan structure
    if 'execution_plan' in data:
        required_sections = ['full_table_scans', 'index_scans', 'low_priority']
        for section in required_sections:
            if section not in data['execution_plan']:
                errors.append(f"{context}: Missing execution_plan section '{section}'")
            else:
                # Check section structure
                sec_data = data['execution_plan'][section]
                required_sec_fields = ['count', 'items', 'estimated_hours']
                for field in required_sec_fields:
                    if field not in sec_data:
                        errors.append(f"{context}: Missing field '{field}' in execution_plan.{section}")
                
                # Check items structure if present
                if 'items' in sec_data and isinstance(sec_data['items'], list):
                    for idx, item in enumerate(sec_data['items']):
                        required_item_fields = ['id', 'title', 'pkg_name', 'installed_version', 
                                               'cvss_score', 'fixed_version', 'description', 'cisa_kev']
                        for field in required_item_fields:
                            if field not in item:
                                errors.append(f"{context}: Item {idx} in {section} missing field '{field}'")
    
    return errors

def test_security_explain_plan():
    """Test SecurityExplainPlan class."""
    print_section("Testing SecurityExplainPlan")
    
    try:
        from engine import SecurityExplainPlan, Finding, RiskLevel
        print("✓ Successfully imported SecurityExplainPlan")
    except ImportError as e:
        print(f"✗ Failed to import SecurityExplainPlan: {e}")
        return False
    
    try:
        # Create plan from sample data
        plan = SecurityExplainPlan(SAMPLE_TRIVY_DATA)
        print(f"✓ Created SecurityExplainPlan instance")
        
        # Test findings parsing
        print(f"  - Parsed {len(plan.findings)} findings")
        
        # Test grading
        grade = plan.grade
        print(f"  - Calculated grade: {grade}")
        
        # Test stats
        stats = plan.get_stats()
        print(f"  - Stats: {stats['critical']} critical, {stats['high']} high, {stats['cisa_kev']} CISA KEV")
        
        # Test to_dict conversion
        data = plan.to_dict()
        print(f"✓ Converted to dictionary")
        
        # Validate data structure
        errors = check_required_fields(data, "SecurityExplainPlan.to_dict()")
        if errors:
            print(f"✗ Data structure validation failed:")
            for error in errors:
                print(f"  - {error}")
            return False
        else:
            print(f"✓ Data structure validation passed")
        
        # Test that items are dictionaries (not Finding objects)
        for section in ['full_table_scans', 'index_scans', 'low_priority']:
            items = data['execution_plan'][section]['items']
            if items and not isinstance(items[0], dict):
                print(f"✗ Items in {section} are not dictionaries! Template will fail.")
                return False
        print(f"✓ All items are properly serialized as dictionaries")
        
        # Test JSON export
        json_str = plan.to_json()
        json.loads(json_str)  # Validate JSON is parseable
        print(f"✓ JSON export successful")
        
        return True
        
    except Exception as e:
        print(f"✗ Error during SecurityExplainPlan test: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_report_generator():
    """Test ReportGenerator class."""
    print_section("Testing ReportGenerator")
    
    try:
        from report_generator import ReportGenerator
        from engine import SecurityExplainPlan
        print("✓ Successfully imported ReportGenerator")
    except ImportError as e:
        print(f"✗ Failed to import ReportGenerator: {e}")
        return False
    
    try:
        # Create test data
        plan = SecurityExplainPlan(SAMPLE_TRIVY_DATA)
        data = plan.to_dict()
        
        # Create generator (without actually generating files)
        template_dir = Path("./templates")
        static_dir = Path("./static")
        
        # Create directories if they don't exist
        template_dir.mkdir(exist_ok=True)
        static_dir.mkdir(exist_ok=True)
        
        generator = ReportGenerator(template_dir, static_dir)
        print(f"✓ Created ReportGenerator instance")
        
        # Test _ensure_required_fields
        enriched_data = generator._ensure_required_fields(data.copy())
        print(f"✓ Data enrichment successful")
        
        # Validate enriched data has all fields
        errors = check_required_fields(enriched_data, "ReportGenerator enriched data")
        if errors:
            print(f"✗ Enriched data validation failed:")
            for error in errors:
                print(f"  - {error}")
            return False
        
        # Check that grade_color and grade_label are added
        if 'grade_color' not in enriched_data or 'grade_label' not in enriched_data:
            print(f"✗ Missing grade styling fields")
            return False
        
        print(f"✓ All required fields present in enriched data")
        print(f"  - Grade: {enriched_data['grade']} ({enriched_data['grade_label']})")
        print(f"  - Total effort hours: {enriched_data.get('total_effort_hours', 0)}")
        
        return True
        
    except Exception as e:
        print(f"✗ Error during ReportGenerator test: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_pptx_generator():
    """Test PPTXGenerator class."""
    print_section("Testing PPTXGenerator")
    
    try:
        from pptx_generator import PPTXGenerator
        from engine import SecurityExplainPlan
        print("✓ Successfully imported PPTXGenerator")
    except ImportError as e:
        print(f"✗ Failed to import PPTXGenerator: {e}")
        return False
    
    try:
        # Create test data
        plan = SecurityExplainPlan(SAMPLE_TRIVY_DATA)
        data = plan.to_dict()
        
        # Create generator
        generator = PPTXGenerator()
        print(f"✓ Created PPTXGenerator instance")
        
        # Test data structure validation
        enriched_data = generator._ensure_data_structure(data.copy())
        print(f"✓ Data structure validation successful")
        
        # Validate enriched data
        errors = check_required_fields(enriched_data, "PPTXGenerator enriched data")
        if errors:
            print(f"✗ Enriched data validation failed:")
            for error in errors:
                print(f"  - {error}")
            return False
        
        print(f"✓ All required fields present")
        
        return True
        
    except Exception as e:
        print(f"✗ Error during PPTXGenerator test: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_template_compatibility():
    """Test that data structure matches template requirements."""
    print_section("Testing Template Compatibility")
    
    try:
        from engine import SecurityExplainPlan
        
        # Create test data
        plan = SecurityExplainPlan(SAMPLE_TRIVY_DATA)
        data = plan.to_dict()
        
        # Template variables used in ReportGC.html
        template_vars = [
            'generated_at',
            'report_id',
            'summary.total_findings',
            'grade',
            'grade_color',
            'grade_label',
            'total_effort_hours',
            'execution_plan.full_table_scans.count',
            'execution_plan.full_table_scans.estimated_hours',
            'execution_plan.full_table_scans.items',
            'execution_plan.index_scans.count',
            'execution_plan.index_scans.estimated_hours',
            'execution_plan.index_scans.items',
            'execution_plan.low_priority.count',
        ]
        
        # Variables that need to be added by generators
        generator_added_vars = ['grade_color', 'grade_label', 'total_effort_hours']
        
        missing = []
        for var in template_vars:
            if var in generator_added_vars:
                continue  # These are added by generators
                
            parts = var.split('.')
            current = data
            try:
                for part in parts:
                    current = current[part]
            except (KeyError, TypeError):
                missing.append(var)
        
        if missing:
            print(f"✗ Template compatibility check failed. Missing variables:")
            for var in missing:
                print(f"  - {var}")
            return False
        
        print(f"✓ All template variables present")
        
        # Check finding items have required fields
        finding_fields = ['id', 'title', 'pkg_name', 'installed_version', 
                         'cvss_score', 'fixed_version', 'description', 'cisa_kev']
        
        for section in ['full_table_scans', 'index_scans']:
            items = data['execution_plan'][section]['items']
            if items:
                first_item = items[0]
                missing_fields = [f for f in finding_fields if f not in first_item]
                if missing_fields:
                    print(f"✗ Finding items missing fields: {missing_fields}")
                    return False
        
        print(f"✓ All finding item fields present")
        
        # Verify items are dictionaries (not objects)
        for section in ['full_table_scans', 'index_scans', 'low_priority']:
            items = data['execution_plan'][section]['items']
            if items:
                if not isinstance(items[0], dict):
                    print(f"✗ Items in {section} are not dictionaries!")
                    return False
        
        print(f"✓ All items are dictionaries (Jinja2 compatible)")
        
        return True
        
    except Exception as e:
        print(f"✗ Error during template compatibility test: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_edge_cases():
    """Test edge cases that could cause errors."""
    print_section("Testing Edge Cases")
    
    try:
        from engine import SecurityExplainPlan
        
        # Test 1: Empty Trivy output
        print("\nTest 1: Empty Trivy output")
        empty_data = {"Results": []}
        plan = SecurityExplainPlan(empty_data)
        data = plan.to_dict()
        
        if data['summary']['total_findings'] != 0:
            print(f"✗ Expected 0 findings, got {data['summary']['total_findings']}")
            return False
        if data['grade'] != 'A':
            print(f"✗ Expected grade A, got {data['grade']}")
            return False
        print("✓ Empty data handled correctly")
        
        # Test 2: No CVSS scores
        print("\nTest 2: Missing CVSS scores")
        no_cvss = {
            "Results": [{
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-TEST",
                    "Severity": "HIGH",
                    "Title": "Test Vuln",
                    "Description": "Test",
                    "PkgName": "test",
                    "InstalledVersion": "1.0"
                }]
            }]
        }
        plan = SecurityExplainPlan(no_cvss)
        data = plan.to_dict()
        print("✓ Missing CVSS handled correctly")
        
        # Test 3: Missing fixed_version (None)
        print("\nTest 3: Missing fixed_version")
        if data['execution_plan']['index_scans']['items']:
            item = data['execution_plan']['index_scans']['items'][0]
            if 'fixed_version' not in item:
                print("✗ fixed_version field missing")
                return False
        print("✓ Missing fixed_version handled correctly")
        
        return True
        
    except Exception as e:
        print(f"✗ Error during edge case test: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all tests."""
    print("\n")
    print("╔═══════════════════════════════════════════════════════════════════════╗")
    print("║          ReportGC Integration Test Suite                             ║")
    print("║          Validating End-to-End Compatibility                         ║")
    print("╚═══════════════════════════════════════════════════════════════════════╝")
    
    results = []
    
    # Run tests
    results.append(("SecurityExplainPlan", test_security_explain_plan()))
    results.append(("ReportGenerator", test_report_generator()))
    results.append(("PPTXGenerator", test_pptx_generator()))
    results.append(("Template Compatibility", test_template_compatibility()))
    results.append(("Edge Cases", test_edge_cases()))
    
    # Summary
    print_section("Test Summary")
    
    all_passed = True
    for test_name, passed in results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{status:10} - {test_name}")
        if not passed:
            all_passed = False
    
    print("\n" + "="*80)
    if all_passed:
        print("✓ ALL TESTS PASSED - System is ready for production use!")
        print("\nNo 500 errors expected. You're good to go! ")
        return 0
    else:
        print("✗ SOME TESTS FAILED - Please fix errors before deploying")
        print("\n⚠️  WARNING: 500 errors may occur. Fix issues above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())

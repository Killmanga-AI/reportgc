import json
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict
from enum import Enum

class RiskLevel(Enum):
    CRITICAL = "FULL_TABLE_SCAN"  # Immediate attention required
    HIGH = "INDEX_RANGE_SCAN"     # High priority optimization
    MEDIUM = "NESTED_LOOP"        # Standard maintenance
    LOW = "SEQUENTIAL_READ"       # Minor overhead

@dataclass
class Finding:
    id: str
    title: str
    severity: str
    cvss_score: float
    cisa_kev: bool
    fixed_version: Optional[str]
    pkg_name: str
    installed_version: str
    description: str
    
    @property
    def risk_level(self) -> RiskLevel:
        """
        Determine risk level based on CVSS score and CISA KEV status.
        CISA KEV (Known Exploited Vulnerabilities) always get critical priority.
        """
        # CISA KEV (Known Exploited) always bumps to Critical/Full Table Scan
        if self.cisa_kev or self.cvss_score >= 9.0:
            return RiskLevel.CRITICAL
        elif self.cvss_score >= 7.0:
            return RiskLevel.HIGH
        elif self.cvss_score >= 4.0:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
    
    @property
    def fix_effort_hours(self) -> int:
        """
        Realistic estimation based on patch availability and complexity.
        Returns estimated hours required to remediate this finding.
        """
        if self.fixed_version:
            # Patch available - quick fix
            return 2 if self.cvss_score >= 7.0 else 4
        # No patch available - needs architectural workaround (2 days)
        return 16
    
    def to_dict(self) -> dict:
        """
        Convert Finding to a dictionary suitable for template rendering.
        Includes computed properties that templates need.
        """
        base_dict = asdict(self)
        base_dict['risk_level'] = self.risk_level.value
        base_dict['fix_effort_hours'] = self.fix_effort_hours
        return base_dict

class SecurityExplainPlan:
    """
    Parses Trivy security scan output and generates an execution plan
    using database query optimization metaphors.
    
    Usage:
        with open('trivy_output.json') as f:
            trivy_data = json.load(f)
        
        plan = SecurityExplainPlan(trivy_data)
        report_data = plan.to_dict()
        
        # Use with generators
        pdf_gen.generate_pdf(report_data, 'report.pdf')
        pptx_gen.generate_pptx(report_data, 'deck.pptx')
    """
    
    def __init__(self, trivy_json: dict):
        """
        Initialize the security explain plan from Trivy JSON output.
        
        Args:
            trivy_json: Dictionary containing Trivy scan results
        """
        self.raw = trivy_json
        self.findings = self._parse_findings()
        self.timestamp = datetime.now()
        
    def _parse_findings(self) -> List[Finding]:
        """Parse Trivy JSON output into Finding objects."""
        findings = []
        for result in self.raw.get("Results", []):
            # Process Vulnerabilities
            for vuln in result.get("Vulnerabilities", []):
                findings.append(self._map_to_finding(vuln))
            
            # Optionally process Misconfigurations
            for misconfig in result.get("Misconfigurations", []):
                findings.append(self._map_misconfig_to_finding(misconfig))
        
        return findings
    
    def _map_to_finding(self, v: dict) -> Finding:
        """Map a Trivy vulnerability entry to a Finding object."""
        return Finding(
            id=v.get("VulnerabilityID", "N/A"),
            title=v.get("Title", "Untitled Vulnerability"),
            severity=v.get("Severity", "UNKNOWN"),
            cvss_score=self._extract_cvss(v),
            cisa_kev=self._check_cisa_kev(v),
            fixed_version=v.get("FixedVersion"),
            pkg_name=v.get("PkgName", "system-lib"),
            installed_version=v.get("InstalledVersion", "0.0.0"),
            description=v.get("Description", "No description available.")
        )
    
    def _map_misconfig_to_finding(self, m: dict) -> Finding:
        """Map a Trivy misconfiguration entry to a Finding object."""
        # Map misconfiguration severity to CVSS-equivalent scores
        severity_map = {
            "CRITICAL": 9.5,
            "HIGH": 7.5,
            "MEDIUM": 5.0,
            "LOW": 2.5
        }
        
        return Finding(
            id=m.get("ID", "MISCONFIG"),
            title=m.get("Title", "Configuration Issue"),
            severity=m.get("Severity", "UNKNOWN"),
            cvss_score=severity_map.get(m.get("Severity", "MEDIUM"), 5.0),
            cisa_kev=False,  # Misconfigs aren't in CISA KEV
            fixed_version=None,
            pkg_name=m.get("Type", "config"),
            installed_version="N/A",
            description=m.get("Description", "No description available.")
        )

    def _check_cisa_kev(self, vuln: dict) -> bool:
        """
        Check if vulnerability is in CISA's Known Exploited Vulnerabilities catalog.
        
        Trivy may include this in various fields. This checks common locations.
        """
        # Check if explicitly marked (varies by Trivy version)
        if vuln.get("CisaKnownExploited", False):
            return True
        
        # Check references for CISA KEV mentions
        references = vuln.get("References", [])
        if isinstance(references, list):
            for ref in references:
                if "cisa.gov" in ref.lower() and "known-exploited" in ref.lower():
                    return True
        
        # Check PrimaryURL
        primary_url = vuln.get("PrimaryURL", "")
        if "cisa.gov" in primary_url.lower() and "known-exploited" in primary_url.lower():
            return True
        
        return False

    def _extract_cvss(self, vuln: dict) -> float:
        """
        Extract CVSS score from Trivy's nested structure.
        Prioritizes NVD scores, then vendor scores, with fallback.
        """
        cvss_data = vuln.get("CVSS", {})
        
        # Try to get V3 scores (preferred)
        for source in ["nvd", "redhat", "ghsa", "vendor"]:
            if source in cvss_data:
                score = cvss_data[source].get("V3Score")
                if score:
                    try:
                        return float(score)
                    except (ValueError, TypeError):
                        pass
        
        # Fallback to V2 if V3 not available
        for source in ["nvd", "redhat", "ghsa"]:
            if source in cvss_data:
                score = cvss_data[source].get("V2Score")
                if score:
                    try:
                        return float(score)
                    except (ValueError, TypeError):
                        pass
        
        # Last resort: map severity string to approximate score
        severity_map = {
            "CRITICAL": 9.0,
            "HIGH": 7.5,
            "MEDIUM": 5.0,
            "LOW": 2.5,
            "UNKNOWN": 5.0
        }
        
        return severity_map.get(vuln.get("Severity", "UNKNOWN"), 5.0)

    @property
    def grade(self) -> str:
        """
        Calculate overall security grade based on critical findings.
        
        Returns:
            Letter grade from A (excellent) to F (critical)
        """
        critical_count = len([f for f in self.findings if f.risk_level == RiskLevel.CRITICAL])
        
        if critical_count == 0:
            return "A"
        elif critical_count <= 2:
            return "B"
        elif critical_count <= 5:
            return "C"
        elif critical_count <= 10:
            return "D"
        else:
            return "F"
    
    def to_dict(self) -> dict:
        """
        Convert the security plan to a dictionary suitable for PDF and PPTX generators.
        All Finding objects are serialized to dictionaries for template compatibility.
        
        Returns:
            Dictionary with complete report data structure
        """
        criticals = [f for f in self.findings if f.risk_level == RiskLevel.CRITICAL]
        highs = [f for f in self.findings if f.risk_level == RiskLevel.HIGH]
        mediums = [f for f in self.findings if f.risk_level == RiskLevel.MEDIUM]
        lows = [f for f in self.findings if f.risk_level == RiskLevel.LOW]
        
        return {
            "grade": self.grade,
            "generated_at": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "report_id": self.timestamp.strftime("%Y%m%d-%H%M%S"),
            "summary": {
                "total_findings": len(self.findings),
                "critical": len(criticals),
                "high": len(highs),
                "medium": len(mediums),
                "low": len(lows),
                "cisa_kev_count": len([f for f in self.findings if f.cisa_kev])
            },
            "execution_plan": {
                "full_table_scans": {
                    "count": len(criticals),
                    "items": [f.to_dict() for f in criticals],  # Serialize to dict!
                    "estimated_hours": sum(f.fix_effort_hours for f in criticals)
                },
                "index_scans": {
                    "count": len(highs),
                    "items": [f.to_dict() for f in highs],  # Serialize to dict!
                    "estimated_hours": sum(f.fix_effort_hours for f in highs)
                },
                "low_priority": {
                    "count": len(mediums) + len(lows),
                    "items": [f.to_dict() for f in (mediums + lows)],  # Serialize to dict!
                    "estimated_hours": 0  # Background task
                }
            }
        }
    
    def to_json(self, filepath: str = None) -> str:
        """
        Export the security plan as JSON.
        
        Args:
            filepath: Optional path to write JSON file. If None, returns JSON string.
            
        Returns:
            JSON string representation of the plan
        """
        data = self.to_dict()
        json_str = json.dumps(data, indent=2, default=str)
        
        if filepath:
            with open(filepath, 'w') as f:
                f.write(json_str)
            print(f"✓ JSON export saved to: {filepath}")
        
        return json_str
    
    def get_stats(self) -> dict:
        """
        Get quick statistics about the security posture.
        
        Returns:
            Dictionary with key metrics
        """
        return {
            "grade": self.grade,
            "total_findings": len(self.findings),
            "critical": len([f for f in self.findings if f.risk_level == RiskLevel.CRITICAL]),
            "high": len([f for f in self.findings if f.risk_level == RiskLevel.HIGH]),
            "cisa_kev": len([f for f in self.findings if f.cisa_kev]),
            "total_effort_hours": sum(f.fix_effort_hours for f in self.findings 
                                     if f.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH])
        }


# Example usage and testing
if __name__ == "__main__":
    # Sample Trivy output structure
    sample_trivy_output = {
        "Results": [
            {
                "Target": "alpine:3.19 (alpine 3.19.0)",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-1234",
                        "PkgName": "openssl",
                        "InstalledVersion": "1.1.1t",
                        "FixedVersion": "1.1.1u",
                        "Severity": "CRITICAL",
                        "Title": "OpenSSL Remote Code Execution",
                        "Description": "A critical vulnerability in OpenSSL allowing RCE.",
                        "CVSS": {
                            "nvd": {"V3Score": 9.8}
                        },
                        "References": ["https://cisa.gov/known-exploited-vulnerabilities"]
                    },
                    {
                        "VulnerabilityID": "CVE-2024-5678",
                        "PkgName": "libcurl",
                        "InstalledVersion": "7.88.0",
                        "FixedVersion": "7.88.1",
                        "Severity": "HIGH",
                        "Title": "libcurl Buffer Overflow",
                        "Description": "Buffer overflow in libcurl URL parsing.",
                        "CVSS": {
                            "nvd": {"V3Score": 7.5}
                        }
                    }
                ],
                "Misconfigurations": [
                    {
                        "ID": "KSV001",
                        "Title": "Process can elevate its own privileges",
                        "Severity": "HIGH",
                        "Description": "Container runs with allowPrivilegeEscalation enabled"
                    }
                ]
            }
        ]
    }
    
    # Create security plan
    plan = SecurityExplainPlan(sample_trivy_output)
    
    # Print stats
    print("Security Assessment Stats:")
    print(json.dumps(plan.get_stats(), indent=2))
    
    # Export to JSON
    plan.to_json("security_plan.json")
    
    # Get data for report generators
    report_data = plan.to_dict()
    print(f"\nGrade: {report_data['grade']}")
    print(f"Total Findings: {report_data['summary']['total_findings']}")
    print(f"Critical: {report_data['summary']['critical']}")
    print(f"High: {report_data['summary']['high']}")

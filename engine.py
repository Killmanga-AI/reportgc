import json
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass
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
        """Realistic estimation based on patch availability and complexity"""
        if self.fixed_version:
            return 2 if self.cvss_score >= 7.0 else 4
        return 16  # No patch available? Needs architectural workaround (2 days)

class SecurityExplainPlan:
    def __init__(self, trivy_json: dict):
        self.raw = trivy_json
        self.findings = self._parse_findings()
        self.timestamp = datetime.now()
        
    def _parse_findings(self) -> List[Finding]:
        findings = []
        for result in self.raw.get("Results", []):
            # Process both Vulnerabilities and Misconfigurations
            for vuln in result.get("Vulnerabilities", []):
                findings.append(self._map_to_finding(vuln))
        return findings
    
    def _map_to_finding(self, v: dict) -> Finding:
        return Finding(
            id=v.get("VulnerabilityID", "N/A"),
            title=v.get("Title", "Untitled Vulnerability"),
            severity=v.get("Severity", "UNKNOWN"),
            cvss_score=self._extract_cvss(v),
            cisa_kev=v.get("Layer", {}).get("DiffID") == "known_exploited", # Simplified KEV check
            fixed_version=v.get("FixedVersion"),
            pkg_name=v.get("PkgName", "system-lib"),
            installed_version=v.get("InstalledVersion", "0.0.0"),
            description=v.get("Description", "")
        )

    def _extract_cvss(self, vuln: dict) -> float:
        """Deep-dive into Trivy's CVSS structure"""
        cvss_data = vuln.get("CVSS", {})
        # Prioritize NVD V3, then Vendor V3, then fallback
        for source in ["nvd", "redhat", "ghsa"]:
            score = cvss_data.get(source, {}).get("V3Score")
            if score: return float(score)
        return 5.0 # Default mid-point if no score found

    @property
    def grade(self) -> str:
        critical_count = len([f for f in self.findings if f.risk_level == RiskLevel.CRITICAL])
        if critical_count == 0: return "A"
        if critical_count <= 2: return "B"
        if critical_count <= 5: return "C"
        return "F"
    
    def to_dict(self) -> dict:
        """Data payload for PDF and PPTX generators"""
        criticals = [f for f in self.findings if f.risk_level == RiskLevel.CRITICAL]
        highs = [f for f in self.findings if f.risk_level == RiskLevel.HIGH]
        
        return {
            "grade": self.grade,
            "generated_at": self.timestamp.strftime("%Y-%m-%d %H:%M"),
            "summary": {
                "total_findings": len(self.findings),
                "critical": len(criticals),
                "high": len(highs),
                "cisa_kev_count": len([f for f in self.findings if f.cisa_kev])
            },
            "execution_plan": {
                "full_table_scans": {
                    "count": len(criticals),
                    "items": criticals,
                    "estimated_hours": sum(f.fix_effort_hours for f in criticals)
                },
                "index_scans": {
                    "count": len(highs),
                    "items": highs,
                    "estimated_hours": sum(f.fix_effort_hours for f in highs)
                },
                "low_priority": {
                    "count": len(self.findings) - len(criticals) - len(highs)
                }
            }
        }

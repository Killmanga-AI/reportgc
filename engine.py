import json
from datetime import datetime
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum

class RiskLevel(Enum):
    CRITICAL = "FULL_TABLE_SCAN"
    HIGH = "INDEX_RANGE_SCAN"
    MEDIUM = "NESTED_LOOP"
    LOW = "SEQUENTIAL_READ"

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
        if self.cisa_kev or self.cvss_score >= 9.0:
            return RiskLevel.CRITICAL
        elif self.cvss_score >= 7.0:
            return RiskLevel.HIGH
        elif self.cvss_score >= 4.0:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    @property
    def fix_effort_hours(self) -> int:
        if self.fixed_version:
            return 2 if self.cvss_score >= 7.0 else 4
        return 16

    def to_dict(self) -> dict:
        base_dict = asdict(self)
        base_dict['risk_level'] = self.risk_level.value
        base_dict['fix_effort_hours'] = self.fix_effort_hours
        return base_dict

class SecurityExplainPlan:
    def __init__(self, scan_data: dict):
        self.raw = scan_data
        self.timestamp = datetime.now()
        
        # Format Detection
        if "runs" in self.raw:
            self.findings = self._parse_sarif()
        else:
            self.findings = self._parse_trivy_native()

    def _parse_sarif(self) -> List[Finding]:
        findings = []
        for run in self.raw.get("runs", []):
            rules_map = {
                rule.get("id"): rule 
                for rule in run.get("tool", {}).get("driver", {}).get("rules", [])
            }
            for res in run.get("results", []):
                rule_id = res.get("ruleId")
                rule_meta = rules_map.get(rule_id, {})
                props = rule_meta.get("properties", {})
                level = res.get("level", "warning")
                severity = props.get("severity", self._map_sarif_level(level))

                findings.append(Finding(
                    id=rule_id or "N/A",
                    title=rule_meta.get("shortDescription", {}).get("text", "Security Issue"),
                    severity=severity.upper(),
                    cvss_score=float(props.get("cvssV3_score", 5.0)),
                    cisa_kev="cisa" in str(props).lower(),
                    fixed_version=props.get("fixedVersion"),
                    pkg_name=props.get("pkgName", "system"),
                    installed_version=props.get("installedVersion", "N/A"),
                    description=res.get("message", {}).get("text", "No description available.")
                ))
        return findings

    def _map_sarif_level(self, level: str) -> str:
        mapping = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW"}
        return mapping.get(level.lower(), "UNKNOWN")

    def _parse_trivy_native(self) -> List[Finding]:
        findings = []
        for result in self.raw.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                findings.append(self._map_vuln_to_finding(vuln))
            for misconfig in result.get("Misconfigurations", []):
                findings.append(self._map_misconfig_to_finding(misconfig))
        return findings

    def _map_vuln_to_finding(self, v: dict) -> Finding:
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
        severity_map = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}
        sev = m.get("Severity", "MEDIUM")
        return Finding(
            id=m.get("ID", "MISCONFIG"),
            title=m.get("Title", "Configuration Issue"),
            severity=sev,
            cvss_score=severity_map.get(sev, 5.0),
            cisa_kev=False,
            fixed_version=None,
            pkg_name=m.get("Type", "config"),
            installed_version="N/A",
            description=m.get("Description", "No description available.")
        )

    def _check_cisa_kev(self, vuln: dict) -> bool:
        if vuln.get("CisaKnownExploited", False): return True
        refs = str(vuln.get("References", "")) + vuln.get("PrimaryURL", "")
        return "cisa.gov" in refs.lower() and "known-exploited" in refs.lower()

    def _extract_cvss(self, vuln: dict) -> float:
        cvss_data = vuln.get("CVSS", {})
        for source in ["nvd", "redhat", "ghsa", "vendor"]:
            if source in cvss_data:
                score = cvss_data[source].get("V3Score") or cvss_data[source].get("V2Score")
                if score: return float(score)
        fallback = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}
        return fallback.get(vuln.get("Severity", "UNKNOWN"), 5.0)

    @property
    def grade(self) -> str:
        crit_count = len([f for f in self.findings if f.risk_level == RiskLevel.CRITICAL])
        if crit_count == 0: return "A"
        if crit_count <= 2: return "B"
        if crit_count <= 5: return "C"
        return "F"

    # --- NEW HELPER METHODS FOR report.html ---
    
    def _get_grade_color(self) -> str:
        colors = {'A': '#28a745', 'B': '#6c757d', 'C': '#ffc107', 'D': '#fd7e14', 'F': '#dc3545'}
        return colors.get(self.grade, '#000000')

    def _get_grade_label(self) -> str:
        labels = {'A': 'EXCELLENT', 'B': 'GOOD', 'C': 'FAIR', 'D': 'POOR', 'F': 'CRITICAL'}
        return labels.get(self.grade, 'UNKNOWN')

    def to_dict(self) -> dict:
        """
        Final dict structure. 
        Matches PPTXGenerator keys and report.html variables exactly.
        """
        criticals = [f for f in self.findings if f.risk_level == RiskLevel.CRITICAL]
        highs = [f for f in self.findings if f.risk_level == RiskLevel.HIGH]
        mediums = [f for f in self.findings if f.risk_level == RiskLevel.MEDIUM]
        lows = [f for f in self.findings if f.risk_level == RiskLevel.LOW]
        
        total_hours = sum(f.fix_effort_hours for f in (criticals + highs))

        return {
            "grade": self.grade,
            "grade_color": self._get_grade_color(),   # Needed for report.html
            "grade_label": self._get_grade_label(),   # Needed for report.html
            "total_effort_hours": total_hours,         # Needed for report.html
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
                    "items": [f.to_dict() for f in criticals],
                    "estimated_hours": sum(f.fix_effort_hours for f in criticals)
                },
                "index_scans": {
                    "count": len(highs),
                    "items": [f.to_dict() for f in highs],
                    "estimated_hours": sum(f.fix_effort_hours for f in highs)
                },
                "low_priority": {
                    "count": len(mediums) + len(lows),
                    "items": [f.to_dict() for f in (mediums + lows)],
                    "estimated_hours": 0 
                }
            }
        }

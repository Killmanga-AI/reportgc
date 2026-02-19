import json
from datetime import datetime
from typing import List, Dict, Optional, Any
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
        """Determine risk level based on CVSS score and CISA KEV status."""
        if self.cisa_kev or self.cvss_score >= 9.0:
            return RiskLevel.CRITICAL
        elif self.cvss_score >= 7.0:
            return RiskLevel.HIGH
        elif self.cvss_score >= 4.0:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    @property
    def fix_effort_hours(self) -> int:
        """Estimated hours required to remediate this finding."""
        if self.fixed_version:
            return 2 if self.cvss_score >= 7.0 else 4
        return 16

    def to_dict(self) -> dict:
        """Convert Finding to a dictionary for template rendering."""
        base_dict = asdict(self)
        base_dict['risk_level'] = self.risk_level.value
        base_dict['fix_effort_hours'] = self.fix_effort_hours
        return base_dict

class SecurityExplainPlan:
    """
    Parses security scan output (Trivy JSON or SARIF) and generates 
    an execution plan using database query optimization metaphors.
    """

    def __init__(self, scan_data: dict):
        self.raw = scan_data
        self.timestamp = datetime.now()
        
        # Format Detection logic
        if "runs" in self.raw:
            self.findings = self._parse_sarif()
        else:
            self.findings = self._parse_trivy_native()

    # --- SARIF PARSING LOGIC ---
    
    def _parse_sarif(self) -> List[Finding]:
        """Maps SARIF 2.1.0 (Trivy format) to Finding objects."""
        findings = []
        for run in self.raw.get("runs", []):
            # Map rules by ID for quick metadata lookup
            rules_map = {
                rule.get("id"): rule 
                for rule in run.get("tool", {}).get("driver", {}).get("rules", [])
            }

            for res in run.get("results", []):
                rule_id = res.get("ruleId")
                rule_meta = rules_map.get(rule_id, {})
                props = rule_meta.get("properties", {})
                
                # SARIF level mapping
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

    # --- TRIVY NATIVE PARSING LOGIC ---

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

    # --- OUTPUT GENERATION ---

    @property
    def grade(self) -> str:
        crit_count = len([f for f in self.findings if f.risk_level == RiskLevel.CRITICAL])
        if crit_count == 0: return "A"
        if crit_count <= 2: return "B"
        if crit_count <= 5: return "C"
        return "F"

    def to_dict(self) -> dict:
        criticals = [f for f in self.findings if f.risk_level == RiskLevel.CRITICAL]
        highs = [f for f in self.findings if f.risk_level == RiskLevel.HIGH]
        mediums = [f for f in self.findings if f.risk_level == RiskLevel.MEDIUM]
        lows = [f for f in self.findings if f.risk_level == RiskLevel.LOW]

        return {
            "grade": self.grade,
            "generated_at": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "summary": {
                "total_findings": len(self.findings),
                "critical": len(criticals),
                "high": len(highs),
                "medium": len(mediums),
                "low": len(lows),
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
                "background_tasks": {
                    "count": len(mediums) + len(lows),
                    "items": [f.to_dict() for f in (mediums + lows)]
                }
            }
        }

    def get_stats(self) -> dict:
        return {
            "grade": self.grade,
            "total_findings": len(self.findings),
            "critical": len([f for f in self.findings if f.risk_level == RiskLevel.CRITICAL]),
            "total_effort_hours": sum(f.fix_effort_hours for f in self.findings 
                                     if f.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH])
        }

# Example logic for your website route
if __name__ == "__main__":
    # This simulates how you'd use it in your web app
    try:
        with open('your_scan_file.json') as f:
            data = json.load(f)
        
        plan = SecurityExplainPlan(data)
        print(f"Plan Generated! Grade: {plan.grade}")
        print(f"Findings Found: {len(plan.findings)}")
        
    except Exception as e:
        print(f"Error parsing file: {e}")

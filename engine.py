from datetime import datetime
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum


# -------------------------------------------------
# Explain Plan Risk Levels
# -------------------------------------------------

class RiskLevel(Enum):
    FULL_TABLE_SCAN = "FULL_TABLE_SCAN"
    INDEX_RANGE_SCAN = "INDEX_RANGE_SCAN"
    NESTED_LOOP = "NESTED_LOOP"  # Restored MEDIUM tier
    SEQUENTIAL_READ = "SEQUENTIAL_READ"


# -------------------------------------------------
# Finding Model
# -------------------------------------------------

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

    # -------------------------
    # Classification
    # -------------------------

    @property
    def risk_level(self) -> RiskLevel:
        if self.cisa_kev or self.cvss_score >= 9.0:
            return RiskLevel.FULL_TABLE_SCAN
        if self.cvss_score >= 7.0:
            return RiskLevel.INDEX_RANGE_SCAN
        if self.cvss_score >= 4.0:
            return RiskLevel.NESTED_LOOP  # Restored MEDIUM tier
        return RiskLevel.SEQUENTIAL_READ

    @property
    def fix_effort_hours(self) -> int:
        """
        Very rough remediation effort heuristic.
        """
        if not self.fixed_version:
            return 8

        if self.pkg_name.lower() in {"kernel", "glibc", "openssl"}:
            return 24

        if self.cvss_score >= 9.0:
            return 6

        return 4

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["risk_level"] = self.risk_level.value
        data["fix_effort_hours"] = self.fix_effort_hours
        return data


# -------------------------------------------------
# Security Explain Plan Engine
# -------------------------------------------------

class SecurityExplainPlan:
    """
    Core classification and aggregation engine.
    This is the ONLY place where security logic exists.
    """

    def __init__(self, scan_data: Dict[str, Any]):
        self.raw = scan_data
        self.timestamp = datetime.now()
        self.findings: List[Finding] = self._parse_input()

    # -------------------------------------------------
    # Input Parsing
    # -------------------------------------------------

    def _parse_input(self) -> List[Finding]:
        if "runs" in self.raw:
            return self._parse_sarif()
        return self._parse_trivy()

    def _parse_sarif(self) -> List[Finding]:
        findings: List[Finding] = []

        for run in self.raw.get("runs", []):
            rules = {
                r.get("id"): r
                for r in run.get("tool", {})
                .get("driver", {})
                .get("rules", [])
            }

            for result in run.get("results", []):
                rule_id = result.get("ruleId", "N/A")
                rule = rules.get(rule_id, {})
                props = rule.get("properties", {})

                cvss = self._safe_float(props.get("cvssV3_score"), 5.0)

                findings.append(
                    Finding(
                        id=rule_id,
                        title=rule.get("shortDescription", {}).get("text", "Security Issue"),
                        severity=props.get("severity", "MEDIUM"),
                        cvss_score=cvss,
                        cisa_kev="cisa" in str(props).lower(),
                        fixed_version=props.get("fixedVersion"),
                        pkg_name=props.get("pkgName", "system"),
                        installed_version=props.get("installedVersion", "N/A"),
                        description=result.get("message", {}).get("text", ""),
                    )
                )

        return findings

    def _parse_trivy(self) -> List[Finding]:
        findings: List[Finding] = []

        for result in self.raw.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                findings.append(self._map_vulnerability(vuln))

            for misconfig in result.get("Misconfigurations", []):
                findings.append(self._map_misconfiguration(misconfig))

        return findings

    # -------------------------------------------------
    # Mapping Helpers
    # -------------------------------------------------

    def _map_vulnerability(self, v: Dict[str, Any]) -> Finding:
        return Finding(
            id=v.get("VulnerabilityID", "N/A"),
            title=v.get("Title", "Untitled Vulnerability"),
            severity=v.get("Severity", "UNKNOWN"),
            cvss_score=self._extract_cvss(v),
            cisa_kev=self._check_cisa_kev(v),
            fixed_version=v.get("FixedVersion"),
            pkg_name=v.get("PkgName", "system"),
            installed_version=v.get("InstalledVersion", "N/A"),
            description=v.get("Description", ""),
        )

    def _map_misconfiguration(self, m: Dict[str, Any]) -> Finding:
        severity_map = {
            "CRITICAL": 9.5,
            "HIGH": 7.5,
            "MEDIUM": 5.0,
            "LOW": 2.5,
        }

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
            description=m.get("Description", ""),
        )

    # -------------------------------------------------
    # CVSS & KEV Helpers
    # -------------------------------------------------

    def _extract_cvss(self, vuln: Dict[str, Any]) -> float:
        cvss_data = vuln.get("CVSS", {})
        for source in ("nvd", "redhat", "ghsa", "vendor"):
            entry = cvss_data.get(source)
            if entry:
                score = entry.get("V3Score") or entry.get("V2Score")
                if score:
                    return self._safe_float(score, 5.0)

        fallback = {
            "CRITICAL": 9.0,
            "HIGH": 7.5,
            "MEDIUM": 5.0,
            "LOW": 2.5,
        }

        return fallback.get(vuln.get("Severity", "MEDIUM"), 5.0)

    def _check_cisa_kev(self, vuln: Dict[str, Any]) -> bool:
        if vuln.get("CisaKnownExploited", False):
            return True

        refs = (
            str(vuln.get("References", "")) +
            str(vuln.get("PrimaryURL", ""))
        ).lower()

        return "cisa.gov" in refs and "known" in refs

    @staticmethod
    def _safe_float(value: Any, default: float) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    # -------------------------------------------------
    # Aggregation Output
    # -------------------------------------------------

    @property
    def grade(self) -> str:
        criticals = sum(
            1 for f in self.findings
            if f.risk_level == RiskLevel.FULL_TABLE_SCAN
        )

        if criticals == 0:
            return "A"
        if criticals <= 2:
            return "B"
        if criticals <= 5:
            return "C"
        if criticals <= 10:
            return "D"
        return "F"

    def _classify_findings(self) -> Dict[RiskLevel, List[Finding]]:
        """
        Single-pass classification for performance.
        Returns dict mapping RiskLevel to list of findings.
        """
        buckets = {level: [] for level in RiskLevel}
        for f in self.findings:
            buckets[f.risk_level].append(f)
        return buckets

    def to_dict(self) -> Dict[str, Any]:
        # Single-pass classification (performance fix)
        buckets = self._classify_findings()
        
        criticals = buckets[RiskLevel.FULL_TABLE_SCAN]
        highs = buckets[RiskLevel.INDEX_RANGE_SCAN]
        mediums = buckets[RiskLevel.NESTED_LOOP]
        lows = buckets[RiskLevel.SEQUENTIAL_READ]

        return {
            "grade": self.grade,
            "generated_at": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "report_id": self.timestamp.strftime("%Y%m%d-%H%M%S"),
            "summary": {
                "total_findings": len(self.findings),
                "critical": len(criticals),
                "high": len(highs),
                "medium": len(mediums),  # Now accurate!
                "low": len(lows),        # Now accurate!
                "cisa_kev_count": sum(1 for f in self.findings if f.cisa_kev),
            },
            "execution_plan": {
                "full_table_scans": {
                    "count": len(criticals),
                    "estimated_hours": sum(f.fix_effort_hours for f in criticals),
                    "items": [f.to_dict() for f in criticals],
                },
                "index_scans": {
                    "count": len(highs),
                    "estimated_hours": sum(f.fix_effort_hours for f in highs),
                    "items": [f.to_dict() for f in highs],
                },
                "nested_loops": {        # New bucket for MEDIUM
                    "count": len(mediums),
                    "estimated_hours": sum(f.fix_effort_hours for f in mediums),
                    "items": [f.to_dict() for f in mediums],
                },
                "low_priority": {
                    "count": len(lows),
                    "estimated_hours": 0,
                    "items": [f.to_dict() for f in lows],
                },
            },
        }

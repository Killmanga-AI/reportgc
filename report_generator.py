from weasyprint import HTML
from jinja2 import Environment, FileSystemLoader
from pathlib import Path
from datetime import datetime
from typing import Dict, Any


class ReportGenerator:
    """
    ReportGC – PDF/HTML rendering stage

    Responsibilities:
    - Enforce data contract for templates
    - Perform final, presentation-safe calculations
    - Render HTML → PDF using WeasyPrint
    - Never re-interpret security logic (engine owns that)
    """

    TEMPLATE_NAME = "report.html"

    GRADE_STYLES = {
        "A": {"color": "#28a745", "label": "EXCELLENT"},
        "B": {"color": "#6c757d", "label": "GOOD"},
        "C": {"color": "#ffc107", "label": "FAIR"},
        "D": {"color": "#fd7e14", "label": "POOR"},
        "F": {"color": "#dc3545", "label": "CRITICAL"},
    }

    EXECUTION_PLAN_KEYS = (
        "full_table_scans",
        "index_scans",
        "low_priority",
    )

    def __init__(self, template_dir: Path, static_dir: Path):
        self.template_dir = template_dir
        self.static_dir = static_dir

        self.env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=True
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_pdf(self, data: Dict[str, Any], output_path: Path) -> None:
        """
        Render report.html → PDF
        """
        payload = self._prepare_payload(data)
        html = self._render_html(payload)

        HTML(
            string=html,
            base_url=str(self.static_dir.resolve())
        ).write_pdf(str(output_path))

    def generate_html(self, data: Dict[str, Any], output_path: Path) -> None:
        """
        Debug-only: Render report.html → HTML
        """
        payload = self._prepare_payload(data)
        html = self._render_html(payload)

        output_path.write_text(html, encoding="utf-8")

    # ------------------------------------------------------------------
    # Internal Pipeline
    # ------------------------------------------------------------------

    def _prepare_payload(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Final sanitation & enrichment layer before rendering.
        """
        payload = dict(data)  # shallow copy for safety

        self._ensure_metadata(payload)
        self._ensure_execution_plan(payload)
        self._apply_grade_styling(payload)
        self._ensure_effort_hours(payload)
        self._resolve_assets(payload)

        return payload

    def _render_html(self, payload: Dict[str, Any]) -> str:
        template = self.env.get_template(self.TEMPLATE_NAME)
        return template.render(payload)

    # ------------------------------------------------------------------
    # Enforcement & Normalization
    # ------------------------------------------------------------------

    def _ensure_metadata(self, data: Dict[str, Any]) -> None:
        now = datetime.now()
        data.setdefault("generated_at", now.strftime("%Y-%m-%d %H:%M:%S"))
        data.setdefault("report_id", now.strftime("%Y%m%d-%H%M%S"))

        data.setdefault(
            "summary",
            {
                "total_findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "cisa_kev_count": 0,
            },
        )

    def _ensure_execution_plan(self, data: Dict[str, Any]) -> None:
        """
        Locks the execution_plan schema used by templates.
        """
        execution_plan = data.setdefault("execution_plan", {})

        for key in self.EXECUTION_PLAN_KEYS:
            execution_plan.setdefault(
                key,
                {
                    "count": 0,
                    "estimated_hours": 0,
                    "items": [],
                },
            )

    def _apply_grade_styling(self, data: Dict[str, Any]) -> None:
        """
        Single source of truth for grade visuals.
        """
        grade = data.get("grade", "F")
        style = self.GRADE_STYLES.get(grade, self.GRADE_STYLES["F"])

        data["grade"] = grade
        data["grade_color"] = style["color"]
        data["grade_label"] = style["label"]

    def _ensure_effort_hours(self, data: Dict[str, Any]) -> None:
        """
        Uses engine-provided total if present.
        Otherwise derives it safely.
        """
        if "total_effort_hours" in data:
            return

        execution_plan = data["execution_plan"]

        total = 0
        for section in execution_plan.values():
            if isinstance(section, dict):
                total += section.get("estimated_hours", 0)

        data["total_effort_hours"] = total

    def _resolve_assets(self, data: Dict[str, Any]) -> None:
        """
        Resolve static assets safely for WeasyPrint.
        """
        logo_path = self.static_dir / "logo.png"
        data["logo_url"] = (
            logo_path.resolve().as_uri()
            if logo_path.exists()
            else None
        )
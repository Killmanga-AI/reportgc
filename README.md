ReportGC

Security Reporting Pipeline

Transform raw vulnerability scans into executive-ready intelligence.

ReportGC is a sophisticated security reporting compiler that takes the messy, technical output of vulnerability scanners (Trivy, SARIF) and translates it into structured, actionable intelligence for different organizational stakeholders—from C-suite executives to engineering teams.

> ⚠️ DRAFT STATUS: This is a proof-of-concept project to validate whether security professionals and their teams will actually adopt this workflow. It's functional, well-architected, and ready for testing, but it's not (yet) a battle-tested production system. We're looking for feedback from CISOs, security engineers, DevOps leads, and compliance officers to see if this solves real problems.

---

The Problem We're Solving

Security scanners generate data vomit. A single container scan can produce thousands of lines of JSON filled with CVE IDs, CVSS scores, package versions, and obscure references. This creates three critical failures in most organizations:

1. Executives see noise: They get raw CSV dumps or PDFs with 500 pages of CVE tables. They can't make decisions from this.
2. Engineers see chaos: They get Jira tickets with "Fix CVE-2023-XXXX" and have to manually research severity, exploitability, and effort.
3. Compliance sees inconsistency: Every team reports risks differently. There's no standardized "security language."

ReportGC fixes this by acting like a compiler: it ingests messy technical data, applies business logic, and outputs stakeholder-specific artifacts with a consistent metaphor everyone understands.

---

The "Database Execution Plan" Metaphor

The core innovation of ReportGC is borrowing from database query optimization. Every developer and DBA understands that a "Full Table Scan" is an emergency that stops everything, while a "Sequential Read" is background noise.

We map security severity to this metaphor:

Risk Level	Database Analog	Business Meaning	Action Timeline	
FULL_TABLE_SCAN	Query killing the database	Critical/CISA KEV - Active exploitation likely	Fix this week	
INDEX_RANGE_SCAN	Suboptimal but manageable	High severity - Significant risk	Next sprint	
NESTED_LOOP	Inefficient join	Medium severity - Moderate concern	Sprint +1	
SEQUENTIAL_READ	Background operation	Low severity - Acceptable risk	Quarterly review	

Why this metaphor?
- Executives understand database performance analogies (everyone hates a slow query)
- Engineers immediately grasp priority without reading CVSS documentation
- Project Managers get intuitive effort estimation (table scans = expensive)
- Compliance gets standardized risk language across all reports

We rejected alternatives:
- CVSS-only: Too technical, doesn't account for CISA KEV (active exploitation)
- Critical/High/Medium/Low: Overused, meaningless without context
- Traffic lights (Red/Yellow/Green): Too simplistic, doesn't convey action urgency

---

How It Works: The Pipeline

ReportGC follows a strict linear pipeline to ensure data integrity and automatic cleanup:

```
┌─────────────┐    ┌──────────────────┐    ┌──────────────┐    ┌─────────────┐
│  Ingestion  │ →  │  Explain Plan    │ →  │   Scoring    │ →  │   Output    │
│             │    │     Engine       │    │              │    │             │
│ Trivy/SARIF │    │ RiskLevel.class  │    │ Grade A-F    │    │ PDF + PPTX  │
│   JSON      │    │ effort calc      │    │ effort hours │    │             │
└─────────────┘    └──────────────────┘    └──────────────┘    └─────────────┘
                                                                      ↓
                                                              ┌─────────────┐
                                                              │   Cleanup   │
                                                              │ Auto-delete │
                                                              │   files     │
                                                              └─────────────┘
```

1. Ingestion
Accepts raw JSON from:
- Trivy (container/image scans)
- SARIF (Static Analysis Results Interchange Format)

Auto-detects format by checking for `"runs"` key (SARIF) vs `"Results"` (Trivy).

2. The Explain Plan Engine
The core logic lives in `engine.py`. This is the single source of truth for all security decisions:
- Risk classification: CVSS score + CISA KEV status → RiskLevel
- Effort estimation: Core packages (kernel, glibc, openssl) = 24h, patchable = 2-6h, no patch = 8h
- Deduplication: Groups by risk tier for efficient processing

Key design decision: The engine never outputs raw findings. It always buckets them into the execution plan structure. This forces downstream consumers to think in terms of action plans, not vulnerability lists.

3. Scoring
Calculates:
- Security Grade (A-F): Based on critical finding count (0=A, 1-2=B, 3-5=C, 6-10=D, >10=F)
- Total Effort Hours: Sum of estimated fix time for critical + high findings
- CISA KEV Count: Known exploited vulnerabilities requiring immediate attention

Why grade instead of score?
- Executives understand school grades instantly
- Scores (0-100) require calibration ("Is 85 good?")
- Grades create emotional urgency (nobody wants an F)

4. Multi-Channel Output
Generates two artifacts simultaneously:

PDF Report (`report.html` → WeasyPrint)
- Audience: Compliance officers, security auditors, engineering leads
- Content: Complete finding details, descriptions, fix versions, evidence trail
- Length: 5-20 pages depending on finding count
- Features: Page numbers, responsive design, print-optimized CSS

PPTX Deck (`python-pptx`)
- Audience: C-suite, board members, project stakeholders
- Content: 5 slides only (Grade → Matrix → Critical Details → High Details → Roadmap)
- Design: 16:9 aspect ratio, bold typography, color-coded risk levels
- Constraint: Maximum 3 findings per detail slide (forced prioritization)

Why two formats?
We tested single-format solutions and they failed:
- PDF-only: Executives never read past page 2
- PPTX-only: Engineers lacked technical details to fix issues
- HTML-only: Compliance needs signed PDFs for auditors

5. Automatic Cleanup
The `ReportGCPipeline` (main.py) includes a `temporary_report()` context manager that auto-deletes files after use. This ensures sensitive security data doesn't persist on servers.

Why mandatory cleanup?
- Security reports contain vulnerability details that could aid attackers
- Compliance frameworks (SOC2, ISO27001) require data minimization
- Prevents "report sprawl" where outdated scans confuse decision-making

---

Architecture Decisions

Why WeasyPrint for PDFs?
- Pros: Pure Python, CSS-based styling, excellent @page support for headers/footers
- Cons: Slow (2-5s per PDF), heavy dependencies (Cairo, Pango)
- Alternative considered: ReportLab (faster but requires imperative layout code, ugly by default)
- Verdict: WeasyPrint's HTML/CSS approach lets designers modify templates without touching Python

Why python-pptx?
- Pros: Native .pptx generation, no MS Office required, template support
- Cons: Memory intensive, limited styling vs native PowerPoint
- Alternative considered: LibreOffice headless conversion (too heavy, too slow)
- Verdict: python-pptx is "good enough" for 5-slide executive decks

Why 4-Tier Risk System?
Originally we used 3 tiers (Critical/High/Low). We restored Medium (NESTED_LOOP) because:
- Security teams complained "High is too broad" (CVSS 7.0-8.9 is huge range)
- Project managers needed a "next sprint +1" bucket between "immediate" and "backlog"
- CVSS 4.0-6.9 vulnerabilities often have patches but aren't emergencies

Why Dataclasses (not Pydantic)?
- Pros: Standard library, fast, immutable-friendly
- Cons: No validation, no JSON schema
- Alternative considered: Pydantic (excellent but adds dependency, overkill for internal tool)
- Verdict: Dataclasses + manual validation in engine is sufficient for draft

Why Jinja2 (not string templating)?
- Separation of concerns: Designers edit HTML, developers edit Python
- Auto-escaping prevents XSS if reports ever render in browser
- Template inheritance allows custom branding without code changes

---

File Structure

```
reportgc/
├── engine.py              # Core security logic (RiskLevel, Finding, SecurityExplainPlan)
├── pptx_generator.py      # Executive presentation generator
├── report_generator.py    # PDF/HTML renderer (WeasyPrint + Jinja2)
├── report.html            # Jinja2 template for PDF reports
├── main.py                # Orchestrator, CLI, API integration point
└── README.md              # This file
```

Key principle: `engine.py` is the only file that interprets security data. Generators only handle presentation. If you need to change how risk is calculated, you change one file.

---

Usage

Basic Python API

```python
from main import ReportGCPipeline
import json

# Initialize pipeline
pipeline = ReportGCPipeline(
    template_dir="./templates",
    static_dir="./static",
    output_dir="./reports"
)

# Load scan data
with open("trivy-output.json") as f:
    scan_data = json.load(f)

# Generate reports
result = pipeline.process_scan(scan_data)

print(f"PDF: {result['pdf']}")
print(f"PPTX: {result['pptx']}")
print(f"Grade: {result['data']['grade']}")
```

With Automatic Cleanup

```python
# Files auto-deleted after context exits
with pipeline.temporary_report(scan_data) as result:
    # Email result['pdf'] to CISO
    # Upload result['pptx'] to board portal
    pass  # Files deleted here
```

Flask API Endpoint

```python
from flask import Flask, request, send_file
from main import ReportGCPipeline

app = Flask(__name__)
pipeline = ReportGCPipeline(...)

@app.route('/api/report', methods=['POST'])
def generate_report():
    scan_data = request.get_json()
    
    if not pipeline.validate_scan_data(scan_data):
        return {'error': 'Invalid scan format'}, 400
    
    try:
        with pipeline.temporary_report(scan_data) as result:
            return send_file(
                result['pdf'],
                mimetype='application/pdf',
                as_attachment=True
            )
    except Exception as e:
        return {'error': str(e)}, 500
```

---

Customization

Modifying Risk Thresholds

In `engine.py`, edit the `risk_level` property:

```python
@property
def risk_level(self) -> RiskLevel:
    if self.cisa_kev or self.cvss_score >= 9.0:
        return RiskLevel.FULL_TABLE_SCAN
    elif self.cvss_score >= 7.0:
        return RiskLevel.INDEX_RANGE_SCAN
    elif self.cvss_score >= 4.0:
        return RiskLevel.NESTED_LOOP
    return RiskLevel.SEQUENTIAL_READ
```

Custom Branding

Edit `report.html`:
- Replace logo.png in `static_dir`
- Modify CSS variables for colors
- Change font families in `@page` rules

Adding Output Formats

Extend `ReportGCPipeline.process_scan()`:

```python
# Add to return dict
result['json'] = self.export_json(data)
result['csv'] = self.export_csv(data)
result['slack'] = self.format_slack(data)
```

---

Known Limitations (Draft Status)

1. No authentication/authorization: Assumes external system handles access control
2. Single-threaded: Large scans (>10k findings) block the pipeline
3. No persistence: No database, no history, no trending (by design for draft)
4. Limited scanner support: Only Trivy and SARIF (no SonarQube, Snyk, etc.)
5. No email/Slack integration: Files only, distribution is manual
6. English only: No i18n support yet

What we need from you:
- Does the database metaphor resonate with your teams?
- Is the 4-tier system too granular or not enough?
- Would you use this if it had [feature X]?
- What's missing for SOC2/ISO27001 compliance in your org?

---

Future Roadmap (If There's Interest)

If professionals actually use this, we'll build:

- Async processing: Celery/RQ for large scans
- Database layer: Scan history, trending, delta reports ("What changed since last week?")
- Integrations: Jira auto-ticket creation, Slack notifications, Splunk export
- More scanners: SonarQube, Snyk, Checkmarx, custom JSON schemas
- Policy engine: "Ignore findings in dev containers" or "Auto-approve patched within 30 days"
- SaaS version: Upload scan, get reports via email (with the same auto-cleanup guarantee)

---

Installation

```bash
# Clone repository
git clone https://github.com/Killmanga-AI/reportgc.git
cd reportgc

# Install dependencies
pip install weasyprint python-pptx jinja2

# WeasyPrint requires system libraries (Ubuntu/Debian)
sudo apt-get install libffi-dev libcairo2 libpango-1.0-0

# Run test
python -c "from main import ReportGCPipeline; print('OK')"
```

---

License

MIT License - See LICENSE file

---

Contact & Feedback

This is a draft. We need to know if this is worth building into a production system.

- Security professionals: Does this reduce your report writing time?
- Executives: Would you read this instead of a 50-page PDF?
- Engineers: Is the effort estimation accurate enough for sprint planning?
- Compliance: Does this meet auditor expectations?

Open an issue with feedback or email [latification15@gmail.com].

---

ReportGC: Stop drowning in CVEs. Start executing security plans.
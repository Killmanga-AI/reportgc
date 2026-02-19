"""
ReportGC - FastAPI REST API
High-performance async API for security report generation.
"""

from fastapi import FastAPI, HTTPException, UploadFile, File, BackgroundTasks, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import json
import tempfile
import logging
from typing import Optional, Dict, Any, Literal
from pydantic import BaseModel, Field
import uvicorn

from main import ReportGCPipeline

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="ReportGC API",
    description="Security reporting pipeline - transforms vulnerability scans into executive intelligence",
    version="1.0.0",
    docs_url="/docs",  # Swagger UI at /docs
    redoc_url="/redoc",  # ReDoc at /redoc
)

# CORS middleware (adjust for production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict in production!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize pipeline (singleton)
pipeline = ReportGCPipeline(
    template_dir=Path("/app/templates"),
    static_dir=Path("/app/static"),
    output_dir=Path(tempfile.gettempdir())
)


# ==========================================
# Pydantic Models (Request/Response validation)
# ==========================================

class ScanData(BaseModel):
    """Raw scanner output (Trivy or SARIF format)."""
    # Flexible schema - accepts any dict structure
    # Actual validation happens in pipeline.validate_scan_data()
    class Config:
        extra = "allow"


class ReportMetadata(BaseModel):
    """Report generation metadata."""
    report_id: Optional[str] = Field(None, description="Custom report ID (default: auto-generated)")
    output_format: Literal["pdf", "pptx", "both"] = Field("both", description="Output format selection")


class ReportResponse(BaseModel):
    """Successful report generation response."""
    report_id: str
    grade: str
    grade_label: str
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    total_effort_hours: int
    cisa_kev_count: int
    pdf_url: Optional[str] = None
    pptx_url: Optional[str] = None
    generated_at: str


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = "healthy"
    service: str = "ReportGC"
    version: str = "1.0.0"


class ValidationResponse(BaseModel):
    """Scan data validation response."""
    valid: bool
    format_detected: Optional[str] = None  # "trivy" or "sarif"
    error: Optional[str] = None


# ==========================================
# API Endpoints
# ==========================================

@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    """Health check endpoint for load balancers and monitoring."""
    return HealthResponse()


@app.post("/api/validate", response_model=ValidationResponse, tags=["Validation"])
async def validate_scan(scan_data: Dict[str, Any]):
    """
    Validate scan data format without generating reports.
    
    Returns whether data is valid Trivy or SARIF format.
    """
    is_valid = pipeline.validate_scan_data(scan_data)
    
    if not is_valid:
        return ValidationResponse(
            valid=False,
            error="Invalid format. Expected Trivy (Results key) or SARIF (runs key) format."
        )
    
    # Detect format
    format_type = "sarif" if "runs" in scan_data else "trivy"
    
    return ValidationResponse(valid=True, format_detected=format_type)


@app.post("/api/report", tags=["Reports"])
async def generate_report(
    background_tasks: BackgroundTasks,
    scan_data: Dict[str, Any],
    report_id: Optional[str] = Query(None, description="Custom report ID"),
    download: bool = Query(True, description="Return as download vs JSON metadata")
):
    """
    Generate security report and return PDF immediately (auto-deleted after).
    
    - **scan_data**: Raw Trivy or SARIF JSON
    - **report_id**: Optional custom ID (default: timestamp)
    - **download**: If true, returns PDF file. If false, returns metadata JSON.
    """
    # Validate
    if not pipeline.validate_scan_data(scan_data):
        raise HTTPException(status_code=400, detail="Invalid scan data format")
    
    try:
        # Use temporary context for auto-cleanup
        with pipeline.temporary_report(scan_data, report_id=report_id) as result:
            if download:
                # Return PDF file directly
                return FileResponse(
                    path=result['pdf'],
                    media_type='application/pdf',
                    filename=f"ReportGC-{result['report_id']}.pdf",
                    background=background_tasks
                )
            else:
                # Return metadata only
                data = result['data']
                return ReportResponse(
                    report_id=result['report_id'],
                    grade=data['grade'],
                    grade_label=data.get('grade_label', 'UNKNOWN'),
                    total_findings=data['summary']['total_findings'],
                    critical_count=data['summary']['critical'],
                    high_count=data['summary']['high'],
                    medium_count=data['summary']['medium'],
                    low_count=data['summary']['low'],
                    total_effort_hours=data['total_effort_hours'],
                    cisa_kev_count=data['summary']['cisa_kev_count'],
                    generated_at=data['generated_at']
                )
                
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/report/full", response_model=ReportResponse, tags=["Reports"])
async def generate_full_report(
    scan_data: Dict[str, Any],
    report_id: Optional[str] = Query(None),
    persist: bool = Query(False, description="Keep files on disk (default: auto-delete)")
):
    """
    Generate both PDF and PPTX, return full metadata with file paths.
    
    Use `persist=true` to keep files for later download (they auto-delete after 5min by default).
    """
    if not pipeline.validate_scan_data(scan_data):
        raise HTTPException(status_code=400, detail="Invalid scan data format")
    
    try:
        if persist:
            # Generate without auto-cleanup context
            result = pipeline.process_scan(scan_data, report_id=report_id)
        else:
            # Will auto-delete, but we return paths immediately
            # Client must download quickly!
            with pipeline.temporary_report(scan_data, report_id=report_id) as result:
                pass  # Context exits, files deleted - but we already have paths
        
        data = result['data']
        
        # Construct URLs (in production, use proper URL generation)
        base_url = "/api/download"  # Would need actual download endpoint
        
        return ReportResponse(
            report_id=result['report_id'],
            grade=data['grade'],
            grade_label=data.get('grade_label', 'UNKNOWN'),
            total_findings=data['summary']['total_findings'],
            critical_count=data['summary']['critical'],
            high_count=data['summary']['high'],
            medium_count=data['summary']['medium'],
            low_count=data['summary']['low'],
            total_effort_hours=data['total_effort_hours'],
            cisa_kev_count=data['summary']['cisa_kev_count'],
            pdf_url=f"{base_url}/{result['report_id']}.pdf" if persist else None,
            pptx_url=f"{base_url}/{result['report_id']}.pptx" if persist else None,
            generated_at=data['generated_at']
        )
        
    except Exception as e:
        logger.error(f"Full report generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/report/async", tags=["Reports"])
async def queue_async_report(
    background_tasks: BackgroundTasks,
    scan_data: Dict[str, Any],
    report_id: Optional[str] = Query(None),
    webhook_url: Optional[str] = Query(None, description="URL to POST results to")
):
    """
    Queue report generation asynchronously (if Celery configured).
    
    Returns immediately with job ID. Check status via /api/status/{job_id}.
    """
    # This requires Celery setup from docker-compose.full.yml
    try:
        from tasks import generate_report_task
        
        # Queue task
        task = generate_report_task.delay(
            scan_data=scan_data,
            report_id=report_id,
            output_format='both'
        )
        
        return {
            "job_id": task.id,
            "status": "queued",
            "report_id": report_id or "pending",
            "check_status_url": f"/api/status/{task.id}"
        }
        
    except ImportError:
        # Celery not configured, run synchronously
        logger.warning("Celery not available, running synchronously")
        return await generate_full_report(scan_data, report_id, persist=False)


@app.get("/api/status/{job_id}", tags=["Jobs"])
async def check_job_status(job_id: str):
    """Check status of async report generation job."""
    try:
        from tasks import celery_app
        from celery.result import AsyncResult
        
        task = AsyncResult(job_id, app=celery_app)
        
        return {
            "job_id": job_id,
            "status": task.status,  # PENDING, STARTED, SUCCESS, FAILURE
            "result": task.result if task.ready() else None
        }
        
    except ImportError:
        raise HTTPException(status_code=501, detail="Async processing not configured")


@app.post("/api/upload", tags=["Upload"])
async def upload_scan_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="Trivy/SARIF JSON file"),
    report_id: Optional[str] = Query(None)
):
    """
    Upload scan file directly instead of JSON body.
    
    Accepts .json files from Trivy or SARIF scanners.
    """
    # Validate file type
    if not file.filename.endswith('.json'):
        raise HTTPException(status_code=400, detail="Only .json files accepted")
    
    try:
        contents = await file.read()
        scan_data = json.loads(contents)
        
        # Process same as /api/report
        if not pipeline.validate_scan_data(scan_data):
            raise HTTPException(status_code=400, detail="Invalid scan file format")
        
        with pipeline.temporary_report(scan_data, report_id=report_id) as result:
            return FileResponse(
                path=result['pdf'],
                media_type='application/pdf',
                filename=f"ReportGC-{result['report_id']}.pdf",
                background=background_tasks
            )
            
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON file")
    except Exception as e:
        logger.error(f"Upload processing failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==========================================
# Startup and Main
# ==========================================

@app.on_event("startup")
async def startup_event():
    """Verify pipeline on startup."""
    logger.info("ReportGC API starting...")
    # Test pipeline initialization
    try:
        test_data = {"Results": [{"Vulnerabilities": []}]}
        pipeline.validate_scan_data(test_data)
        logger.info("Pipeline initialized successfully")
    except Exception as e:
        logger.error(f"Pipeline initialization failed: {e}")
        raise


if __name__ == "__main__":
    # Development server
    uvicorn.run(
        "api:app",
        host="0.0.0.0",
        port=8000,
        reload=True,  # Auto-reload on code changes (dev only!)
        workers=1
    )

"""
ReportGC - FastAPI REST API
High-performance async API for security report generation.
"""

import asyncio
import json
import logging
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, Literal, Optional

import ijson
from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    File,
    HTTPException,
    Query,
    Request,
    UploadFile,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from main import ReportGCPipeline

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
MAX_MEMORY_SIZE = 5 * 1024 * 1024  # 5MB threshold for streaming parse
TEMP_FILE_LIFETIME = 30  # Seconds before cleanup


# ==========================================
# Pydantic Models (Pydantic v2)
# ==========================================

class ScanData(BaseModel):
    """Raw scanner output (Trivy or SARIF format)."""
    model_config = ConfigDict(extra="allow")


class ReportMetadata(BaseModel):
    """Report generation metadata."""
    report_id: Optional[str] = Field(None, description="Custom report ID")
    output_format: Literal["pdf", "pptx", "both"] = Field("both", description="Output format")


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
    format_detected: Optional[str] = None
    error: Optional[str] = None


# ==========================================
# Dependency Injection
# ==========================================

def get_pipeline() -> ReportGCPipeline:
    """Dependency provider for ReportGCPipeline."""
    return ReportGCPipeline(
        template_dir=Path("/app/templates"),
        static_dir=Path("/app/static"),
        output_dir=Path(tempfile.gettempdir())
    )


# ==========================================
# Background Tasks
# ==========================================

async def _cleanup_files(*paths: Path, delay_seconds: int = TEMP_FILE_LIFETIME):
    """Background task to clean up files after delay."""
    await asyncio.sleep(delay_seconds)
    for path in paths:
        try:
            if path.exists():
                path.unlink()
                logger.info(f"Cleaned up: {path}")
        except Exception as e:
            logger.error(f"Failed to cleanup {path}: {e}")


# ==========================================
# Lifespan Management (Modern FastAPI)
# ==========================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    logger.info("ReportGC API starting...")
    pipeline = get_pipeline()
    
    # Verify pipeline on startup
    try:
        test_data = {"Results": [{"Vulnerabilities": []}]}
        await asyncio.to_thread(pipeline.validate_scan_data, test_data)
        logger.info("Pipeline initialized successfully")
    except Exception as e:
        logger.error(f"Pipeline initialization failed: {e}")
        raise
    
    yield
    
    # Shutdown cleanup
    logger.info("ReportGC API shutting down...")


# ==========================================
# FastAPI App
# ==========================================

app = FastAPI(
    title="ReportGC API",
    description="Security reporting pipeline - transforms vulnerability scans into executive intelligence",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS middleware (restrict in production!)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==========================================
# Request Size Limit Middleware
# ==========================================

@app.middleware("http")
async def limit_request_size(request: Request, call_next):
    """Block requests larger than MAX_FILE_SIZE."""
    body = await request.body()
    if len(body) > MAX_FILE_SIZE:
        return JSONResponse(
            status_code=413,
            content={"detail": f"Request body too large (max {MAX_FILE_SIZE // 1024 // 1024}MB)"}
        )
    return await call_next(request)


# ==========================================
# API Endpoints
# ==========================================

@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    """Health check endpoint for load balancers and monitoring."""
    return HealthResponse()


@app.post("/api/validate", response_model=ValidationResponse, tags=["Validation"])
async def validate_scan(
    scan_data: Dict[str, Any],
    pipeline: ReportGCPipeline = Depends(get_pipeline)
):
    """
    Validate scan data format without generating reports.
    """
    # Run validation in thread pool to avoid blocking
    is_valid = await asyncio.to_thread(pipeline.validate_scan_data, scan_data)
    
    if not is_valid:
        return ValidationResponse(
            valid=False,
            error="Invalid format. Expected Trivy (Results key) or SARIF (runs key) format."
        )
    
    format_type = "sarif" if "runs" in scan_data else "trivy"
    return ValidationResponse(valid=True, format_detected=format_type)


@app.post("/api/report", tags=["Reports"])
async def generate_report(
    background_tasks: BackgroundTasks,
    scan_data: Dict[str, Any],
    report_id: Optional[str] = Query(None),
    download: bool = Query(True, description="Return as download vs JSON metadata"),
    pipeline: ReportGCPipeline = Depends(get_pipeline)
):
    """
    Generate security report and return PDF immediately.
    """
    # Validate in thread pool
    is_valid = await asyncio.to_thread(pipeline.validate_scan_data, scan_data)
    if not is_valid:
        raise HTTPException(status_code=400, detail="Invalid scan data format")
    
    try:
        # Use temporary context for auto-cleanup
        # Note: temporary_report is synchronous, run in thread
        result = await asyncio.to_thread(
            _run_temporary_report,
            pipeline,
            scan_data,
            report_id
        )
        
        if download:
            # Schedule cleanup after response is sent
            background_tasks.add_task(
                _cleanup_files,
                result['pdf'],
                result['pptx'],
                delay_seconds=TEMP_FILE_LIFETIME
            )
            
            return FileResponse(
                path=result['pdf'],
                media_type='application/pdf',
                filename=f"ReportGC-{result['report_id']}.pdf"
            )
        else:
            # Return metadata (files cleaned up by context manager)
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
                total_effort_hours=data['summary'].get('total_effort_hours', 0),
                cisa_kev_count=data['summary']['cisa_kev_count'],
                generated_at=data['generated_at']
            )
            
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


def _run_temporary_report(pipeline, scan_data, report_id):
    """Synchronous wrapper for context manager."""
    with pipeline.temporary_report(scan_data, report_id=report_id) as result:
        # Return a copy of paths (strings) to avoid reference issues
        return {
            'pdf': result['pdf'],
            'pptx': result['pptx'],
            'report_id': result['report_id'],
            'data': result['data']
        }


@app.post("/api/report/full", response_model=ReportResponse, tags=["Reports"])
async def generate_full_report(
    background_tasks: BackgroundTasks,
    scan_data: Dict[str, Any],
    report_id: Optional[str] = Query(None),
    persist: bool = Query(False, description="Keep files on disk"),
    pipeline: ReportGCPipeline = Depends(get_pipeline)
):
    """
    Generate both PDF and PPTX, return full metadata with file paths.
    Files auto-deleted after 30s unless persist=true.
    """
    is_valid = await asyncio.to_thread(pipeline.validate_scan_data, scan_data)
    if not is_valid:
        raise HTTPException(status_code=400, detail="Invalid scan data format")
    
    try:
        # Generate in thread pool (blocking operation)
        result = await asyncio.to_thread(
            pipeline.process_scan, scan_data, report_id
        )
        
        data = result['data']
        
        # Schedule cleanup if not persisting
        if not persist:
            background_tasks.add_task(
                _cleanup_files,
                result['pdf'],
                result['pptx'],
                delay_seconds=TEMP_FILE_LIFETIME
            )
        
        # Construct URLs (use proper URL generation in production)
        base_url = "/api/download"
        
        return ReportResponse(
            report_id=result['report_id'],
            grade=data['grade'],
            grade_label=data.get('grade_label', 'UNKNOWN'),
            total_findings=data['summary']['total_findings'],
            critical_count=data['summary']['critical'],
            high_count=data['summary']['high'],
            medium_count=data['summary']['medium'],
            low_count=data['summary']['low'],
            total_effort_hours=data['summary'].get('total_effort_hours', 0),
            cisa_kev_count=data['summary']['cisa_kev_count'],
            pdf_url=f"{base_url}/{result['report_id']}.pdf" if persist else None,
            pptx_url=f"{base_url}/{result['report_id']}.pptx" if persist else None,
            generated_at=data['generated_at']
        )
        
    except Exception as e:
        logger.error(f"Full report generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/upload", tags=["Upload"])
async def upload_scan_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="Trivy/SARIF JSON file"),
    report_id: Optional[str] = Query(None),
    pipeline: ReportGCPipeline = Depends(get_pipeline)
):
    """
    Upload scan file with streaming for large files (up to 50MB).
    """
    if not file.filename.endswith('.json'):
        raise HTTPException(status_code=400, detail="Only .json files accepted")
    
    tmp_path: Optional[Path] = None
    
    try:
        # Stream to temp file with size limit
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.json') as tmp:
            total_size = 0
            chunk_size = 1024 * 1024  # 1MB chunks
            
            while chunk := await file.read(chunk_size):
                total_size += len(chunk)
                if total_size > MAX_FILE_SIZE:
                    raise HTTPException(status_code=413, detail="File too large (max 50MB)")
                tmp.write(chunk)
            
            tmp_path = Path(tmp.name)
        
        logger.info(f"Received upload: {file.filename} ({total_size} bytes)")
        
        # Parse JSON - use streaming for large files
        scan_data = await asyncio.to_thread(
            _parse_json_file, tmp_path, total_size
        )
        
        # Validate
        is_valid = await asyncio.to_thread(pipeline.validate_scan_data, scan_data)
        if not is_valid:
            raise HTTPException(status_code=400, detail="Invalid scan file format")
        
        # Generate report
        result = await asyncio.to_thread(
            pipeline.process_scan, scan_data, report_id
        )
        
        # Schedule cleanups
        if tmp_path:
            background_tasks.add_task(_cleanup_files, tmp_path, delay_seconds=5)
        background_tasks.add_task(
            _cleanup_files, 
            result['pdf'], 
            result['pptx'],
            delay_seconds=TEMP_FILE_LIFETIME
        )
        
        return FileResponse(
            path=result['pdf'],
            media_type='application/pdf',
            filename=f"ReportGC-{result['report_id']}.pdf"
        )
            
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error: {e}")
        raise HTTPException(status_code=400, detail="Invalid JSON file")
    except Exception as e:
        logger.error(f"Upload processing failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        # Ensure temp JSON is cleaned up even on error
        if tmp_path and tmp_path.exists():
            try:
                tmp_path.unlink()
            except Exception:
                pass


def _parse_json_file(file_path: Path, size: int) -> Dict[str, Any]:
    """
    Parse JSON file, using streaming parser for large files.
    """
    if size > MAX_MEMORY_SIZE:
        # Use ijson for streaming parse of large files
        with open(file_path, 'rb') as f:
            # ijson yields items incrementally
            # For root-level object, we need to reconstruct
            parser = ijson.parse(f)
            # Simple approach: collect root object
            result = {}
            current_key = None
            
            for prefix, event, value in parser:
                if prefix == '' and event == 'start_map':
                    continue
                if prefix == '' and event == 'end_map':
                    break
                if '.' not in prefix and event in ('string', 'number', 'boolean', 'null'):
                    result[prefix] = value
                elif event == 'start_array':
                    # Collect array items
                    key = prefix
                    items = []
                    for item in ijson.items(f, f'{key}.item'):
                        items.append(item)
                    result[key] = items
            
            return result
    else:
        # Standard parse for small files
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)


# ==========================================
# Main Entry Point
# ==========================================

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "api:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        workers=1
    )

from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException
from pathlib import Path
import json
import uuid
import os
import traceback
from datetime import datetime

from engine import SecurityExplainPlan
from report_generator import ReportGenerator
from pptx_generator import PPTXGenerator

# --- Configuration ---
BASE_DIR = Path(__file__).resolve().parent
EXPORT_DIR = BASE_DIR / "exports"
TEMPLATE_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

EXPORT_DIR.mkdir(exist_ok=True)
TEMPLATE_DIR.mkdir(exist_ok=True)
STATIC_DIR.mkdir(exist_ok=True)

app = FastAPI(
    title="ReportGC - Security Execution Plan Generator",
    version="1.0.0",
    description="Convert scan data into executive-ready security reports"
)

try:
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
except Exception as e:
    print(f"Warning: Could not mount static files: {e}")

# --- Utilities ---
def cleanup_file(path: Path):
    """Background task to remove files after download"""
    try:
        if path.exists():
            os.remove(path)
            print(f"Cleaned up: {path.name}")
    except Exception as e:
        print(f"Error cleaning up {path}: {e}")

def get_grade_color(grade: str) -> str:
    colors = {'A': '#28a745', 'B': '#6c757d', 'C': '#ffc107', 'D': '#fd7e14', 'F': '#dc3545'}
    return colors.get(grade, '#333333')

def validate_scan_json(data: dict) -> bool:
    if not isinstance(data, dict):
        return False

    if "Results" in data:
        return isinstance(data["Results"], list)
    if "runs" in data:
        return isinstance(data["runs"], list)

    return False

def render_error_page(message: str, status_code: int = 500) -> str:
    """Generates a styled HTML error page"""
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Error - ReportGC</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; background: #f2f7fc; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }}
            .container {{ background: #ffffff; padding: 48px; max-width: 500px; width: 100%; border: 1px solid #d6e4f0; text-align: center; }}
            h1 {{ font-size: 24px; margin: 16px 0 8px; color: #dc3545; }}
            p {{ font-size: 15px; color: #4a4a4a; margin-bottom: 32px; line-height: 1.5; }}
            .icon {{ font-size: 48px; color: #dc3545; }}
            .btn {{ display: inline-block; padding: 12px 24px; background: #4aa3df; color: #fff; text-decoration: none; font-weight: 600; transition: background 0.2s; }}
            .btn:hover {{ background: #358cc7; }}
        </style>
    </head>
    <body>
        <div class="container">
            <i class="fa-solid fa-triangle-exclamation icon"></i>
            <h1>Error {status_code}</h1>
            <p>{message}</p>
            <a href="/" class="btn">Go Back and Try Again</a>
        </div>
    </body>
    </html>
    """

# --- Exception Handlers ---
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return HTMLResponse(content=render_error_page(exc.detail, exc.status_code), status_code=exc.status_code)

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    print(f"Unhandled Server Error: {exc}")
    traceback.print_exc()
    return HTMLResponse(content=render_error_page("An unexpected server error occurred.", 500), status_code=500)

# --- Routes ---
@app.get("/", response_class=HTMLResponse)
async def home():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ReportGC - Security Explain Plan</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; background: #f2f7fc; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; color: #000; }
            .container { background: #ffffff; padding: 48px; max-width: 600px; width: 100%; border: 1px solid #d6e4f0; }
            h1 { font-size: 28px; font-weight: 700; margin-bottom: 8px; }
            .subtitle { font-size: 15px; color: #4a4a4a; margin-bottom: 32px; }
            .upload-box { border: 2px dashed #9cc7eb; padding: 40px 24px; background: #f9fcff; cursor: pointer; transition: 0.2s ease; text-align: center; }
            .upload-box:hover, .upload-box.drag-over { border-color: #4aa3df; background: #eef6fd; }
            .upload-icon { font-size: 36px; color: #4aa3df; margin-bottom: 14px; }
            input[type="file"] { display: none; }
            .file-label { display: block; font-size: 14px; margin-bottom: 10px; }
            .selected-file { font-size: 13px; color: #4aa3df; font-weight: 600; margin-top: 10px; }
            button { width: 100%; margin-top: 24px; padding: 14px; font-size: 15px; font-weight: 600; background: #4aa3df; color: #fff; border: none; cursor: pointer; transition: 0.2s ease; }
            button:hover { background: #358cc7; }
            button:disabled { background: #b9d7ef; cursor: not-allowed; }
            .features { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin: 32px 0; }
            .feature { border: 1px solid #d6e4f0; padding: 14px; font-size: 13px; background: #ffffff; }
            .feature i { color: #4aa3df; margin-right: 6px; }
            .feature strong { display: block; margin-bottom: 6px; font-weight: 600; }
            .footer { font-size: 12.5px; color: #555; line-height: 1.6; text-align: center; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>ReportGC</h1>
            <p class="subtitle">Convert Scans into Executive-Ready Security Reports</p>
            <form id="uploadForm" action="/analyze" method="post" enctype="multipart/form-data">
                <div class="upload-box" id="uploadBox">
                    <div class="upload-icon"><i class="fa-solid fa-file-arrow-up"></i></div>
                    <label for="fileInput" class="file-label">Click to upload or drag & drop a JSON file</label>
                    <input type="file" id="fileInput" name="file" accept=".json" required>
                    <div id="fileName" class="selected-file"></div>
                </div>
                <button type="submit" id="submitBtn">Generate Reports</button>
            </form>
            <div class="features">
                <div class="feature"><strong><i class="fa-solid fa-file-pdf"></i> PDF Report</strong>Professional assessment</div>
                <div class="feature"><strong><i class="fa-solid fa-chalkboard"></i> PPTX Deck</strong>Executive presentation</div>
                <div class="feature"><strong><i class="fa-solid fa-shield-halved"></i> Secure Processing</strong>Files auto-deleted</div>
            </div>
            <p class="footer">Upload your JSON scan output to generate a comprehensive execution plan.<br>Processing is local. Files are deleted after download.</p>
        </div>
        <script>
            const fileInput = document.getElementById('fileInput'), uploadBox = document.getElementById('uploadBox'), fileName = document.getElementById('fileName'), submitBtn = document.getElementById('submitBtn'), uploadForm = document.getElementById('uploadForm');
            uploadBox.onclick = () => fileInput.click();
            fileInput.onchange = (e) => { if(e.target.files[0]) { fileName.textContent = `Selected: ${e.target.files[0].name}`; submitBtn.disabled = false; } };
            uploadBox.ondragover = (e) => { e.preventDefault(); uploadBox.classList.add('drag-over'); };
            uploadBox.ondragleave = () => uploadBox.classList.remove('drag-over');
            uploadBox.ondrop = (e) => {
                e.preventDefault(); uploadBox.classList.remove('drag-over');
                const file = e.dataTransfer.files[0];
                if (file && file.name.endsWith('.json')) { fileInput.files = e.dataTransfer.files; fileName.textContent = `Selected: ${file.name}`; submitBtn.disabled = false; }
                else alert('Please upload a JSON file');
            };
            uploadForm.onsubmit = () => { submitBtn.textContent = 'Analyzing...'; submitBtn.disabled = true; };
        </script>
    </body>
    </html>
    """

@app.post("/analyze", response_class=HTMLResponse)
async def analyze_scan(file: UploadFile = File(...)):
    if not file.filename.endswith('.json'):
        raise HTTPException(status_code=400, detail="Invalid file type. Please upload a .json file.")

    content = await file.read()
    try:
        scan_data = json.loads(content)
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON format. Error: {str(e)}")

    if not validate_scan_json(scan_data):
        raise HTTPException(status_code=400, detail="Unrecognized format. Must be Trivy JSON or SARIF output.")

    print(f"Analyzing scan from: {file.filename}")
    plan = SecurityExplainPlan(scan_data)
    data = plan.to_dict()

    job_id = str(uuid.uuid4())[:8]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pdf_filename = f"SecurityReport_{timestamp}_{job_id}.pdf"
    pptx_filename = f"ExecutiveBrief_{timestamp}_{job_id}.pptx"

    pdf_path = EXPORT_DIR / pdf_filename
    pptx_path = EXPORT_DIR / pptx_filename

    try:
        print("Generating PDF report...")
        ReportGenerator(TEMPLATE_DIR, STATIC_DIR).generate_pdf(data, str(pdf_path))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF: {str(e)}")

    try:
        print("Generating PowerPoint deck...")
        PPTXGenerator().generate_pptx(data, str(pptx_path))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate PowerPoint: {str(e)}")

    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Analysis Complete - ReportGC</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; background: #f2f7fc; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; color: #000; }}
            .card {{ background: #ffffff; padding: 48px; max-width: 720px; width: 100%; border: 1px solid #d6e4f0; text-align: center; }}
            .grade-circle {{ width: 120px; height: 120px; line-height: 120px; margin: 0 auto 24px; background: {data.get('grade_color', '#333')}; color: #ffffff; font-size: 56px; font-weight: 700; }}
            h1 {{ font-size: 26px; font-weight: 700; margin-bottom: 6px; }}
            .subtitle {{ font-size: 14px; color: #4a4a4a; margin-bottom: 28px; }}
            .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 16px; margin: 28px 0; }}
            .stat-box {{ border: 1px solid #d6e4f0; padding: 16px 12px; background: #ffffff; display: flex; flex-direction: column; justify-content: center; align-items: center; }}
            .stat-box h3 {{ font-size: 28px; font-weight: 700; margin-bottom: 6px; }}
            .stat-box p {{ font-size: 11px; text-transform: uppercase; color: #555; font-weight: 600; }}
            .btn {{ display: inline-block; margin: 8px; padding: 14px 28px; background: #4aa3df; color: #ffffff; text-decoration: none; font-weight: 600; font-size: 14px; transition: 0.2s; }}
            .btn:hover {{ background: #358cc7; }}
            .back-link {{ margin-top: 28px; }}
            .back-link a {{ font-size: 14px; color: #4a4a4a; text-decoration: none; }}
            .back-link a:hover {{ color: #4aa3df; }}
        </style>
    </head>
    <body>
        <div class="card">
            <div class="grade-circle">{data['grade']}</div>
            <h1>Analysis Complete</h1>
            <p class="subtitle">Your security reports are ready for download</p>
            <div class="stats">
                <div class="stat-box"><h3>{data['summary']['total_findings']}</h3><p>Total Issues</p></div>
                <div class="stat-box"><h3 style="color:#dc3545">{data['summary']['critical']}</h3><p>Critical</p></div>
                <div class="stat-box"><h3 style="color:#fd7e14">{data['summary']['high']}</h3><p>High Severity</p></div>
                <div class="stat-box"><h3 style="color:#c0392b">{data['summary']['cisa_kev_count']}</h3><p>CISA KEV</p></div>
            </div>
            <div>
                <a href="/download/{pdf_filename}" class="btn"><i class="fa-solid fa-file-pdf"></i> Download PDF Report</a>
                <a href="/download/{pptx_filename}" class="btn"><i class="fa-solid fa-chalkboard"></i> Download Board Deck</a>
            </div>
            <div class="back-link"><a href="/"><i class="fa-solid fa-arrow-left"></i> Analyze another scan</a></div>
        </div>
    </body>
    </html>
    """

@app.get("/download/{filename}")
async def download_file(filename: str, background_tasks: BackgroundTasks):
    if ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Invalid filename requested.")
    
    file_path = EXPORT_DIR / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found. It may have expired or been downloaded already.")
    
    media_type = 'application/pdf' if filename.endswith('.pdf') else 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
    
    background_tasks.add_task(cleanup_file, file_path)
    return FileResponse(path=file_path, filename=filename, media_type=media_type, headers={"Content-Disposition": f"attachment; filename={filename}"})

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "ReportGC"}

if __name__ == "__main__":
    import uvicorn
    print("="*60)
    print("ReportGC - Security Execution Plan Generator")
    print("="*60)
    print("Starting server on http://0.0.0.0:8000")
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True, log_level="info")

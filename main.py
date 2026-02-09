from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path
import json
import uuid
import os
import shutil
import traceback
from datetime import datetime

# Import our custom modules
from engine import SecurityExplainPlan
from report_generator import ReportGenerator
from pptx_generator import PPTXGenerator

# --- Configuration ---
BASE_DIR = Path(__file__).resolve().parent
EXPORT_DIR = BASE_DIR / "exports"
TEMPLATE_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

# Ensure directories exist
EXPORT_DIR.mkdir(exist_ok=True)
TEMPLATE_DIR.mkdir(exist_ok=True)
STATIC_DIR.mkdir(exist_ok=True)

app = FastAPI(
    title="ReportGC - Security Execution Plan Generator",
    version="1.0.0",
    description="Convert Trivy JSON scans into executive-ready security reports"
)

# Mount static files (css, images)
try:
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
except Exception as e:
    print(f"Warning: Could not mount static files: {e}")

# Setup Jinja2 templates (for any additional HTML templates beyond inline)
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))

# --- Utilities ---
def cleanup_file(path: Path):
    """Background task to remove files after download"""
    try:
        if path.exists():
            os.remove(path)
            print(f"✓ Cleaned up: {path.name}")
    except Exception as e:
        print(f"✗ Error cleaning up {path}: {e}")

def get_grade_color(grade: str) -> str:
    """Get HTML color for grade display"""
    colors = {
        'A': '#28a745',  # Green
        'B': '#6c757d',  # Gray
        'C': '#ffc107',  # Yellow
        'D': '#fd7e14',  # Orange
        'F': '#dc3545'   # Red
    }
    return colors.get(grade, '#333333')

def validate_trivy_json(data: dict) -> bool:
    """Validate that JSON is valid Trivy output"""
    if not isinstance(data, dict):
        return False
    
    # Trivy output should have a "Results" key
    if "Results" not in data:
        return False
    
    if not isinstance(data["Results"], list):
        return False
    
    return True

# --- Routes ---

@app.get("/", response_class=HTMLResponse)
async def home():
    """The upload interface"""
    return """
    <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReportGC - Security Explain Plan</title>

    <!-- Icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">

    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: #f2f7fc;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            color: #000;
        }

        .container {
            background: #ffffff;
            padding: 48px;
            max-width: 600px;
            width: 100%;
            border: 1px solid #d6e4f0;
        }

        h1 {
            font-size: 28px;
            font-weight: 700;
            margin-bottom: 8px;
            color: #000;
        }

        .subtitle {
            font-size: 15px;
            color: #4a4a4a;
            margin-bottom: 32px;
        }

        .upload-box {
            border: 2px dashed #9cc7eb;
            padding: 40px 24px;
            background: #f9fcff;
            cursor: pointer;
            transition: border-color 0.2s ease, background 0.2s ease;
            text-align: center;
        }

        .upload-box:hover,
        .upload-box.drag-over {
            border-color: #4aa3df;
            background: #eef6fd;
        }

        .upload-icon {
            font-size: 36px;
            color: #4aa3df;
            margin-bottom: 14px;
        }

        input[type="file"] {
            display: none;
        }

        .file-label {
            display: block;
            font-size: 14px;
            color: #000;
            margin-bottom: 10px;
        }

        .selected-file {
            font-size: 13px;
            color: #4aa3df;
            font-weight: 600;
            margin-top: 10px;
        }

        button {
            width: 100%;
            margin-top: 24px;
            padding: 14px;
            font-size: 15px;
            font-weight: 600;
            background: #4aa3df;
            color: #fff;
            border: none;
            cursor: pointer;
            transition: background 0.2s ease;
        }

        button:hover {
            background: #358cc7;
        }

        button:disabled {
            background: #b9d7ef;
            cursor: not-allowed;
        }

        .features {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 16px;
            margin: 32px 0;
        }

        .feature {
            border: 1px solid #d6e4f0;
            padding: 14px;
            font-size: 13px;
            background: #ffffff;
        }

        .feature i {
            color: #4aa3df;
            margin-right: 6px;
        }

        .feature strong {
            display: block;
            margin-bottom: 6px;
            font-weight: 600;
            color: #000;
        }

        .footer {
            font-size: 12.5px;
            color: #555;
            line-height: 1.6;
            text-align: center;
        }

        @media (max-width: 600px) {
            .container {
                padding: 28px 20px;
            }

            h1 {
                font-size: 22px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>ReportGC</h1>
        <p class="subtitle">Convert Trivy Scans into Executive-Ready Security Reports</p>

        <form id="uploadForm" action="/analyze" method="post" enctype="multipart/form-data">
            <div class="upload-box" id="uploadBox">
                <div class="upload-icon">
                    <i class="fa-solid fa-file-arrow-up"></i>
                </div>
                <label for="fileInput" class="file-label">
                    Click to upload or drag & drop a JSON file
                </label>
                <input type="file" id="fileInput" name="file" accept=".json" required>
                <div id="fileName" class="selected-file"></div>
            </div>

            <button type="submit" id="submitBtn">Generate Reports</button>
        </form>

        <div class="features">
            <div class="feature">
                <strong><i class="fa-solid fa-file-pdf"></i> PDF Report</strong>
                Professional security assessment document
            </div>
            <div class="feature">
                <strong><i class="fa-solid fa-chalkboard"></i> PPTX Deck</strong>
                Executive-ready presentation format
            </div>
            <div class="feature">
                <strong><i class="fa-solid fa-shield-halved"></i> Secure Processing</strong>
                Files deleted after download
            </div>
        </div>

        <p class="footer">
            Upload your Trivy JSON scan output to generate a comprehensive security execution plan.<br>
            All processing happens locally. Files are automatically deleted after download.
        </p>
    </div>

    <script>
        const fileInput = document.getElementById('fileInput');
        const uploadBox = document.getElementById('uploadBox');
        const fileName = document.getElementById('fileName');
        const submitBtn = document.getElementById('submitBtn');
        const uploadForm = document.getElementById('uploadForm');

        uploadBox.addEventListener('click', () => fileInput.click());

        fileInput.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (file) {
                fileName.textContent = `Selected: ${file.name}`;
                submitBtn.disabled = false;
            }
        });

        uploadBox.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadBox.classList.add('drag-over');
        });

        uploadBox.addEventListener('dragleave', () => {
            uploadBox.classList.remove('drag-over');
        });

        uploadBox.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadBox.classList.remove('drag-over');

            const file = e.dataTransfer.files[0];
            if (file && file.name.endsWith('.json')) {
                fileInput.files = e.dataTransfer.files;
                fileName.textContent = `Selected: ${file.name}`;
                submitBtn.disabled = false;
            } else {
                alert('Please upload a JSON file');
            }
        });

        uploadForm.addEventListener('submit', () => {
            submitBtn.textContent = 'Analyzing...';
            submitBtn.disabled = true;
        });
    </script>
</body>
</html>
    """

@app.post("/analyze", response_class=HTMLResponse)
async def analyze_scan(file: UploadFile = File(...)):
    """Process JSON, generate reports, return download links"""
    
    try:
        # 1. Validate File Type
        if not file.filename.endswith('.json'):
            raise HTTPException(
                status_code=400, 
                detail="Invalid file type. Please upload a .json file from Trivy scan output."
            )
        
        # 2. Read and Parse Content
        content = await file.read()
        try:
            trivy_data = json.loads(content)
        except json.JSONDecodeError as e:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid JSON format. Please ensure the file is valid Trivy output. Error: {str(e)}"
            )
        
        # 3. Validate Trivy Structure
        if not validate_trivy_json(trivy_data):
            raise HTTPException(
                status_code=400,
                detail="Invalid Trivy JSON structure. The file should contain a 'Results' array."
            )
        
        # 4. Run the Security Analysis
        print(f"Analyzing scan from: {file.filename}")
        plan = SecurityExplainPlan(trivy_data)
        data = plan.to_dict()
        
        # Log statistics
        stats = plan.get_stats()
        print(f"Grade: {stats['grade']}")
        print(f"Findings: {stats['total_findings']} total, {stats['critical']} critical, {stats['high']} high")
        
        # 5. Generate Unique Filenames
        job_id = str(uuid.uuid4())[:8]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pdf_filename = f"SecurityReport_{timestamp}_{job_id}.pdf"
        pptx_filename = f"ExecutiveBrief_{timestamp}_{job_id}.pptx"
        
        pdf_path = EXPORT_DIR / pdf_filename
        pptx_path = EXPORT_DIR / pptx_filename
        
        # 6. Generate PDF Report
        print("Generating PDF report...")
        try:
            report_gen = ReportGenerator(TEMPLATE_DIR, STATIC_DIR)
            report_gen.generate_pdf(data, str(pdf_path))
            print(f"✓ PDF generated: {pdf_path.name}")
        except Exception as e:
            print(f"✗ PDF generation failed: {e}")
            traceback.print_exc()
            raise HTTPException(
                status_code=500,
                detail=f"Failed to generate PDF report: {str(e)}"
            )
        
        # 7. Generate PowerPoint Deck
        print("Generating PowerPoint deck...")
        try:
            pptx_gen = PPTXGenerator()
            pptx_gen.generate_pptx(data, str(pptx_path))
            print(f"✓ PPTX generated: {pptx_path.name}")
        except Exception as e:
            print(f"✗ PPTX generation failed: {e}")
            traceback.print_exc()
            raise HTTPException(
                status_code=500,
                detail=f"Failed to generate PowerPoint deck: {str(e)}"
            )
        
        # 8. Determine grade color for UI
        grade_color = get_grade_color(data['grade'])
        
        # 9. Return Results Page
        return f"""
       <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Analysis Complete - ReportGC</title>

    <!-- Icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">

    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: #f2f7fc;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            color: #000;
        }

        .card {
            background: #ffffff;
            padding: 48px;
            max-width: 720px;
            width: 100%;
            border: 1px solid #d6e4f0;
            text-align: center;
        }

        .grade-circle {
            width: 120px;
            height: 120px;
            line-height: 120px;
            margin: 0 auto 24px;
            background: {grade_color};
            color: #ffffff;
            font-size: 56px;
            font-weight: 700;
        }

        h1 {
            font-size: 26px;
            font-weight: 700;
            margin-bottom: 6px;
        }

        .subtitle {
            font-size: 14px;
            color: #4a4a4a;
            margin-bottom: 28px;
        }

        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 16px;
            margin: 28px 0;
        }

        .stat-box {
            border: 1px solid #d6e4f0;
            padding: 16px 12px;
            background: #ffffff;
            min-height: 110px;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
        }

        .stat-box h3 {
            font-size: clamp(22px, 4vw, 28px);
            font-weight: 700;
            line-height: 1.1;
            max-width: 100%;
            word-break: break-word;
            overflow-wrap: anywhere;
            text-align: center;
            margin-bottom: 6px;
        }

        .stat-box p {
            font-size: 11px;
            letter-spacing: 0.8px;
            text-transform: uppercase;
            color: #555;
            font-weight: 600;
            text-align: center;
        }
        .downloads {
            margin: 32px 0;
        }

        .btn {
            display: inline-block;
            margin: 8px;
            padding: 14px 28px;
            background: #4aa3df;
            color: #ffffff;
            text-decoration: none;
            font-weight: 600;
            font-size: 14px;
            transition: background 0.2s ease;
        }

        .btn:hover {
            background: #358cc7;
        }

        .btn i {
            margin-right: 8px;
        }

        .back-link {
            margin-top: 28px;
        }

        .back-link a {
            font-size: 14px;
            color: #4a4a4a;
            text-decoration: none;
            transition: color 0.2s ease;
        }

        .back-link a:hover {
            color: #4aa3df;
        }

        @media (max-width: 600px) {
            .card { padding: 28px 20px; }
            .grade-circle {
                width: 90px;
                height: 90px;
                line-height: 90px;
                font-size: 42px;
            }
            h1 { font-size: 22px; }
            .btn { display: block; margin: 10px 0; }
        }
    </style>
</head>
<body>
    <div class="card">
        <div class="grade-circle">{data['grade']}</div>

        <h1>Analysis Complete</h1>
        <p class="subtitle">Your security reports are ready for download</p>

        <div class="stats">
            <div class="stat-box">
                <h3>{data['summary']['total_findings']}</h3>
                <p>Total Issues</p>
            </div>
            <div class="stat-box">
                <h3 style="color:#dc3545">{data['summary']['critical']}</h3>
                <p>Critical</p>
            </div>
            <div class="stat-box">
                <h3 style="color:#fd7e14">{data['summary']['high']}</h3>
                <p>High Severity</p>
            </div>
            <div class="stat-box">
                <h3 style="color:#c0392b">{data['summary']['cisa_kev_count']}</h3>
                <p>CISA KEV</p>
            </div>
        </div>

        <div class="downloads">
            <a href="/download/{pdf_filename}" class="btn">
                <i class="fa-solid fa-file-pdf"></i> Download PDF Report
            </a>
            <a href="/download/{pptx_filename}" class="btn">
                <i class="fa-solid fa-chalkboard"></i> Download Board Deck
            </a>
        </div>

        <div class="back-link">
            <a href="/"><i class="fa-solid fa-arrow-left"></i> Analyze another scan</a>
        </div>
    </div>
</body>
</html>
        """
    
    except HTTPException:
        # Re-raise HTTPExceptions (these are handled by FastAPI)
        raise
    
    except Exception as e:
        # Catch any unexpected errors
        print(f"✗ Unexpected error during analysis: {e}")
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"An unexpected error occurred during analysis: {str(e)}"
        )

@app.get("/download/{filename}")
async def download_file(filename: str, background_tasks: BackgroundTasks):
    """Serve file and schedule deletion"""
    file_path = EXPORT_DIR / filename
    
    # Security: Ensure filename doesn't contain path traversal
    if ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    
    if not file_path.exists():
        raise HTTPException(
            status_code=404, 
            detail="File not found. It may have expired or been already downloaded."
        )
    
    # Determine media type
    if filename.endswith('.pdf'):
        media_type = 'application/pdf'
    elif filename.endswith('.pptx'):
        media_type = 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
    else:
        media_type = 'application/octet-stream'
    
    # Schedule file deletion after response is sent
    background_tasks.add_task(cleanup_file, file_path)
    
    print(f"Serving file: {filename}")
    
    return FileResponse(
        path=file_path,
        filename=filename,
        media_type=media_type,
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        }
    )

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "ReportGC",
        "version": "1.0.0",
        "directories": {
            "exports": EXPORT_DIR.exists(),
            "templates": TEMPLATE_DIR.exists(),
            "static": STATIC_DIR.exists()
        }
    }

# Error handlers
@app.exception_handler(404)
async def not_found_handler(request, exc):
    return HTMLResponse(
        content="""
        <html>
            <body style="font-family: sans-serif; text-align: center; padding: 50px;">
                <h1>404 - Not Found</h1>
                <p>The page you're looking for doesn't exist.</p>
                <a href="/">Go Home</a>
            </body>
        </html>
        """,
        status_code=404
    )

if __name__ == "__main__":
    import uvicorn
    print("="*80)
    print("🛡️  ReportGC - Security Execution Plan Generator")
    print("="*80)
    print(f"Export Directory: {EXPORT_DIR}")
    print(f"Template Directory: {TEMPLATE_DIR}")
    print(f"Static Directory: {STATIC_DIR}")
    print("="*80)
    print("Starting server on http://0.0.0.0:8000")
    print("="*80)
    
    uvicorn.run(
        "main:app", 
        host="0.0.0.0", 
        port=8000, 
        reload=True,
        log_level="info"
    )

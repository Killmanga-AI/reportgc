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
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { 
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }
            .container { 
                background: white; 
                padding: 50px; 
                border-radius: 20px; 
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                max-width: 600px;
                width: 100%;
                text-align: center;
            }
            h1 { 
                color: #2c3e50; 
                margin-bottom: 10px;
                font-size: 32px;
                font-weight: 700;
            }
            .subtitle { 
                color: #7f8c8d; 
                margin-bottom: 40px;
                font-size: 16px;
            }
            .upload-box { 
                border: 3px dashed #cbd5e0; 
                padding: 50px 30px; 
                border-radius: 12px; 
                transition: all 0.3s ease;
                background: #f8f9fa;
                cursor: pointer;
            }
            .upload-box:hover { 
                border-color: #667eea; 
                background: #f0f4ff;
                transform: translateY(-2px);
            }
            .upload-box.drag-over {
                border-color: #667eea;
                background: #e8edff;
            }
            .upload-icon {
                font-size: 48px;
                color: #667eea;
                margin-bottom: 15px;
            }
            input[type="file"] { 
                display: none;
            }
            .file-label {
                color: #495057;
                font-weight: 500;
                margin-bottom: 15px;
                display: block;
            }
            .selected-file {
                color: #667eea;
                font-weight: 600;
                margin-top: 15px;
                font-size: 14px;
            }
            button { 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white; 
                padding: 16px 40px; 
                border: none; 
                border-radius: 8px; 
                font-size: 16px;
                font-weight: 600;
                cursor: pointer; 
                transition: all 0.2s;
                margin-top: 25px;
                box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
            }
            button:hover { 
                transform: translateY(-2px);
                box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);
            }
            button:disabled {
                background: #cbd5e0;
                cursor: not-allowed;
                box-shadow: none;
                transform: none;
            }
            .footer { 
                margin-top: 35px; 
                color: #95a5a6; 
                font-size: 13px;
                line-height: 1.6;
            }
            .features {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                gap: 20px;
                margin: 30px 0;
                text-align: left;
            }
            .feature {
                padding: 15px;
                background: #f8f9fa;
                border-radius: 8px;
                font-size: 13px;
            }
            .feature strong {
                color: #667eea;
                display: block;
                margin-bottom: 5px;
            }
            @media (max-width: 600px) {
                .container { padding: 30px 20px; }
                h1 { font-size: 24px; }
                .features { grid-template-columns: 1fr; }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ ReportGC</h1>
            <p class="subtitle">Convert Trivy Scans into Executive-Ready Security Reports</p>
            
            <form id="uploadForm" action="/analyze" method="post" enctype="multipart/form-data">
                <div class="upload-box" id="uploadBox">
                    <div class="upload-icon">📄</div>
                    <label for="fileInput" class="file-label">
                        Click to upload or drag & drop
                    </label>
                    <input type="file" id="fileInput" name="file" accept=".json" required>
                    <div id="fileName" class="selected-file"></div>
                </div>
                <button type="submit" id="submitBtn">Generate Reports</button>
            </form>
            
            <div class="features">
                <div class="feature">
                    <strong>📊 PDF Report</strong>
                    Professional security assessment document
                </div>
                <div class="feature">
                    <strong>📽️ PPTX Deck</strong>
                    Board-ready executive presentation
                </div>
                <div class="feature">
                    <strong>🔒 Secure</strong>
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

            // Click to upload
            uploadBox.addEventListener('click', () => fileInput.click());

            // File selection
            fileInput.addEventListener('change', (e) => {
                const file = e.target.files[0];
                if (file) {
                    fileName.textContent = `Selected: ${file.name}`;
                    submitBtn.disabled = false;
                }
            });

            // Drag and drop
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

            // Form submission
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
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{ 
                    font-family: -apple-system, sans-serif; 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                }}
                .card {{ 
                    background: white; 
                    padding: 50px; 
                    border-radius: 20px; 
                    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                    max-width: 700px;
                    width: 100%;
                    text-align: center;
                }}
                .grade-circle {{ 
                    width: 140px; 
                    height: 140px; 
                    line-height: 140px; 
                    border-radius: 50%; 
                    background: {grade_color}; 
                    color: white; 
                    font-size: 72px; 
                    font-weight: bold; 
                    margin: 0 auto 30px;
                    box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                }}
                h1 {{ 
                    color: #2c3e50; 
                    margin-bottom: 10px;
                    font-size: 32px;
                }}
                .subtitle {{
                    color: #7f8c8d;
                    margin-bottom: 30px;
                    font-size: 14px;
                }}
                .stats {{ 
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
                    gap: 20px;
                    margin: 30px 0;
                    padding: 30px;
                    background: #f8f9fa;
                    border-radius: 12px;
                }}
                .stat-box h3 {{ 
                    margin: 0; 
                    font-size: 36px; 
                    color: #2c3e50;
                    font-weight: 700;
                }}
                .stat-box p {{ 
                    margin: 8px 0 0; 
                    color: #7f8c8d; 
                    font-size: 12px; 
                    text-transform: uppercase;
                    letter-spacing: 1px;
                    font-weight: 600;
                }}
                .downloads {{
                    margin: 35px 0;
                }}
                .btn {{ 
                    display: inline-block; 
                    margin: 10px; 
                    padding: 16px 32px; 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white; 
                    text-decoration: none; 
                    border-radius: 8px; 
                    font-weight: 600;
                    transition: all 0.2s;
                    box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
                }}
                .btn:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);
                }}
                .btn-ppt {{ 
                    background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
                    box-shadow: 0 4px 15px rgba(245, 87, 108, 0.4);
                }}
                .btn-ppt:hover {{
                    box-shadow: 0 6px 20px rgba(245, 87, 108, 0.6);
                }}
                .back-link {{
                    margin-top: 30px;
                    display: block;
                }}
                .back-link a {{
                    color: #7f8c8d;
                    text-decoration: none;
                    font-size: 14px;
                    transition: color 0.2s;
                }}
                .back-link a:hover {{
                    color: #667eea;
                }}
                .icon {{
                    margin-right: 8px;
                }}
                @media (max-width: 600px) {{
                    .card {{ padding: 30px 20px; }}
                    .grade-circle {{ width: 100px; height: 100px; line-height: 100px; font-size: 48px; }}
                    h1 {{ font-size: 24px; }}
                    .btn {{ display: block; margin: 10px 0; }}
                }}
            </style>
        </head>
        <body>
            <div class="card">
                <div class="grade-circle">{data['grade']}</div>
                <h1>✓ Analysis Complete</h1>
                <p class="subtitle">Your security reports are ready for download</p>
                
                <div class="stats">
                    <div class="stat-box">
                        <h3>{data['summary']['total_findings']}</h3>
                        <p>Total Issues</p>
                    </div>
                    <div class="stat-box">
                        <h3 style="color: #dc3545">{data['summary']['critical']}</h3>
                        <p>Critical</p>
                    </div>
                    <div class="stat-box">
                        <h3 style="color: #fd7e14">{data['summary']['high']}</h3>
                        <p>High Severity</p>
                    </div>
                    <div class="stat-box">
                        <h3 style="color: #e74c3c">{data['summary']['cisa_kev_count']}</h3>
                        <p>CISA KEV</p>
                    </div>
                </div>

                <div class="downloads">
                    <a href="/download/{pdf_filename}" class="btn">
                        <span class="icon">📄</span>Download PDF Report
                    </a>
                    <a href="/download/{pptx_filename}" class="btn btn-ppt">
                        <span class="icon">📽️</span>Download Board Deck
                    </a>
                </div>
                
                <div class="back-link">
                    <a href="/">← Analyze another scan</a>
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

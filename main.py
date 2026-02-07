from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path
import json
import uuid
import os
import shutil

# Import our custom modules
from engine import SecurityExplainPlan
from report_generator import ReportGenerator
from pptx_generator import PPTXGenerator

# --- Configuration ---
BASE_DIR = Path(__file__).resolve().parent
EXPORT_DIR = BASE_DIR / "exports"
TEMPLATE_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

# Ensure export directory exists
EXPORT_DIR.mkdir(exist_ok=True)

app = FastAPI(title="ReportGC", version="1.0.0")

# Mount static files (css, images)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Setup Jinja2 templates
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))

# --- Utilities ---
def cleanup_file(path: Path):
    """Background task to remove files after download"""
    try:
        if path.exists():
            os.remove(path)
    except Exception as e:
        print(f"Error cleaning up {path}: {e}")

# --- Routes ---

@app.get("/", response_class=HTMLResponse)
async def home():
    """The upload interface"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Explain Plan</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; background: #f4f6f9; }
            .container { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); text-align: center; }
            h1 { color: #2c3e50; margin-bottom: 10px; }
            .subtitle { color: #7f8c8d; margin-bottom: 40px; }
            .upload-box { border: 2px dashed #bdc3c7; padding: 40px; border-radius: 8px; transition: all 0.3s; background: #fafafa; }
            .upload-box:hover { border-color: #3498db; background: #f0f8ff; }
            button { background: #3498db; color: white; padding: 14px 28px; border: none; border-radius: 6px; font-size: 16px; cursor: pointer; transition: background 0.2s; margin-top: 20px; }
            button:hover { background: #2980b9; }
            input[type="file"] { margin-bottom: 10px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Security Explain Plan</h1>
            <p class="subtitle">Convert Trivy JSON into a Board-Ready Strategy</p>
            
            <form action="/analyze" method="post" enctype="multipart/form-data" class="upload-box">
                <input type="file" name="file" accept=".json" required>
                <br>
                <button type="submit">Generate Execution Plan</button>
            </form>
            
            <p style="margin-top: 30px; color: #95a5a6; font-size: 12px;">
                Processing happens locally. Files are deleted after download.
            </p>
        </div>
    </body>
    </html>
    """

@app.post("/analyze", response_class=HTMLResponse)
async def analyze_scan(file: UploadFile = File(...)):
    """Process JSON, generate reports, return download links"""
    
    # 1. Validate File
    if not file.filename.endswith('.json'):
        raise HTTPException(400, "Invalid file type. Please upload a Trivy JSON file.")
    
    # 2. Parse Content
    content = await file.read()
    try:
        trivy_data = json.loads(content)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON format.")
    
    # 3. Run the Logic Engine
    plan = SecurityExplainPlan(trivy_data)
    data = plan.to_dict()
    
    # 4. Generate Unique Filenames
    job_id = str(uuid.uuid4())[:8]
    pdf_filename = f"Security_Plan_{job_id}.pdf"
    pptx_filename = f"Board_Deck_{job_id}.pptx"
    
    pdf_path = EXPORT_DIR / pdf_filename
    pptx_path = EXPORT_DIR / pptx_filename
    
    # 5. Generate Outputs
    # Initialize generators with paths
    report_gen = ReportGenerator(TEMPLATE_DIR, STATIC_DIR)
    pptx_gen = PPTXGenerator() # Add master template path here if you have one
    
    report_gen.generate_pdf(data, str(pdf_path))
    pptx_gen.generate_pptx(data, str(pptx_path))
    
    # 6. Return Result Page
    # Determine grade color for UI
    grade_color = "#2ecc71" if data['grade'] == 'A' else "#e74c3c" if data['grade'] == 'F' else "#f1c40f"
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Analysis Complete</title>
        <style>
            body {{ font-family: -apple-system, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; background: #f4f6f9; }}
            .card {{ background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); text-align: center; }}
            .grade-circle {{ width: 120px; height: 120px; line-height: 120px; border-radius: 50%; background: {grade_color}; color: white; font-size: 64px; font-weight: bold; margin: 0 auto 30px; }}
            .btn {{ display: inline-block; margin: 10px; padding: 15px 30px; background: #3498db; color: white; text-decoration: none; border-radius: 6px; font-weight: 600; }}
            .btn-ppt {{ background: #e67e22; }}
            .stats {{ display: flex; justify-content: center; gap: 40px; margin: 30px 0; }}
            .stat-box h3 {{ margin: 0; font-size: 32px; color: #2c3e50; }}
            .stat-box p {{ margin: 5px 0 0; color: #7f8c8d; font-size: 14px; text-transform: uppercase; }}
        </style>
    </head>
    <body>
        <div class="card">
            <div class="grade-circle">{data['grade']}</div>
            <h1>Analysis Complete</h1>
            
            <div class="stats">
                <div class="stat-box">
                    <h3>{data['summary']['total_findings']}</h3>
                    <p>Total Issues</p>
                </div>
                <div class="stat-box">
                    <h3 style="color: #e74c3c">{data['summary']['critical']}</h3>
                    <p>Critical</p>
                </div>
                <div class="stat-box">
                    <h3>{data['summary']['cisa_kev_count']}</h3>
                    <p>CISA KEV</p>
                </div>
            </div>

            <div style="margin-top: 30px;">
                <a href="/download/{pdf_filename}" class="btn">Download PDF Report</a>
                <a href="/download/{pptx_filename}" class="btn btn-ppt">Download Board Deck</a>
            </div>
            
            <p style="margin-top: 30px;"><a href="/" style="color: #95a5a6;">Analyze another file</a></p>
        </div>
    </body>
    </html>
    """

@app.get("/download/{filename}")
async def download_file(filename: str, background_tasks: BackgroundTasks):
    """Serve file and schedule deletion"""
    file_path = EXPORT_DIR / filename
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found or expired")
    
    # Schedule file deletion after response is sent
    background_tasks.add_task(cleanup_file, file_path)
    
    return FileResponse(
        path=file_path,
        filename=filename,
        media_type='application/octet-stream'
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

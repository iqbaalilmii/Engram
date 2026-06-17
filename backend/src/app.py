import uvicorn
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import os
import sys
import uuid
import subprocess
import json
import re
from datetime import datetime
from pydantic import BaseModel
from typing import List, Optional

# In-memory storage - Global
cases = {}
jobs = {}

# Membuat instance FastAPI
app = FastAPI(title="Engram Forensics API - Volatility 3 Integrated")

# Menambahkan middleware untuk CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class CaseCreate(BaseModel):
    case_name: str
    dump_path: str
    analyst_name: str
    description: Optional[str] = None

# Path logic for frontend
if getattr(sys, 'frozen', False):
    base_path = sys._MEIPASS
    frontend_dir = os.path.join(base_path, "frontend", "dist")
else:
    base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    frontend_dir = os.path.join(base_path, "..", "frontend", "dist")

index_html_path = os.path.join(frontend_dir, "index.html")

# --- Helpers ---

def convert_windows_to_wsl_path(windows_path: str) -> str:
    """Konversi path Windows (C:\\...) ke format WSL (/mnt/c/...)"""
    match = re.match(r'^([a-zA-Z]):\\(.*)', windows_path)
    if match:
        drive = match.group(1).lower()
        rest = match.group(2).replace('\\', '/')
        return f"/mnt/{drive}/{rest}"
    return windows_path.replace('\\', '/')

def run_volatility(dump_path_wsl: str, plugin: str) -> Optional[List[dict]]:
    """Eksekusi vol3 via WSL menggunakan full path vol.py"""
    # Menggunakan full path skrip vol.py sesuai instruksi user
    cmd = ["wsl", "python3", "/mnt/d/tools/volatility3/vol.py", "--offline", "-f", dump_path_wsl, "-r", "json", plugin]
    
    print(f"[DEBUG] Menjalankan: {' '.join(cmd)}")
    
    try:
        # Timeout 15 menit untuk dump yang besar
        process = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=900)
        
        if process.returncode != 0:
            print(f"[!] ERROR pada WSL/Volatility (Plugin: {plugin}):")
            print(f"--- STDERR ---\n{process.stderr}\n--------------")
            return None
        
        try:
            results = json.loads(process.stdout)
            print(f"[+] Selesai memproses {plugin}, jumlah data: {len(results)}")
            return results
        except json.JSONDecodeError:
            print(f"[!] Gagal decode JSON dari output vol3 {plugin}.")
            print(f"--- STDOUT PREVIEW (first 500 chars) ---\n{process.stdout[:500]}\n----------------------")
            return None
            
    except subprocess.TimeoutExpired:
        print(f"[!] TIMEOUT: Eksekusi plugin {plugin} melampaui batas waktu 15 menit.")
        return None
    except Exception as e:
        print(f"[!] EXCEPTION saat menjalankan vol3: {e}")
        return None

def calculate_process_score(proc: dict, all_procs: List[dict]) -> tuple:
    """Heuristik deteksi malware sederhana"""
    score = 0
    reasons = []
    
    name = proc.get("ImageFileName", "").lower()
    pid = proc.get("PID")
    ppid = proc.get("PPID")
    
    if name == "svchost.exe":
        parent = next((p for p in all_procs if p.get("PID") == ppid), None)
        parent_name = parent.get("ImageFileName", "").lower() if parent else "unknown"
        if parent_name != "services.exe":
            score += 45
            reasons.append("unusual_parent")
            
    if not proc.get("FileName"):
        score += 30
        reasons.append("no_disk_path")

    suspicious_keywords = ["malware", "beacon", "meterpreter", "exploit", "nc.exe"]
    if any(k in name for k in suspicious_keywords):
        score += 60
        reasons.append("suspicious_name")

    severity = "clean"
    if score >= 85: severity = "critical"
    elif score >= 70: severity = "high"
    elif score >= 50: severity = "medium"
    elif score > 0: severity = "low"
    
    return min(score, 100), reasons, severity

async def background_analysis(case_id: str):
    """Pipeline analisis utama yang berjalan di background"""
    global cases, jobs
    if case_id not in cases: return
    
    case = cases[case_id]
    job = jobs[case_id]
    
    if not os.path.exists(case["dump_path"]):
        print(f"[!] File tidak ditemukan: {case['dump_path']}")
        job["status"] = "failed"
        case["status"] = "failed"
        return

    dump_wsl = convert_windows_to_wsl_path(case["dump_path"])
    job["status"] = "running"
    
    # Plugin list sesuai bantuan help user
    pipeline = [
        ("windows.pslist", 33),
        ("windows.netscan", 66),
        ("windows.malware.malfind", 100)
    ]
    
    for plugin, percent in pipeline:
        job["progress"]["current_plugin"] = plugin
        results = run_volatility(dump_wsl, plugin)
        
        if results is None:
            job["status"] = "failed"
            case["status"] = "failed"
            return

        cases[case_id]["raw_results"][plugin] = results
        job["progress"]["completed_plugins"] += 1
        job["progress"]["percent"] = percent

    job["status"] = "completed"
    case["status"] = "completed"
    case["completed_at"] = datetime.now().isoformat() + "Z"
    
    pslist = cases[case_id]["raw_results"].get("windows.pslist", [])
    malfind = cases[case_id]["raw_results"].get("windows.malware.malfind", [])
    netscan = cases[case_id]["raw_results"].get("windows.netscan", [])
    
    case["summary"] = {
        "total_processes": len(pslist),
        "suspicious_processes": len([p for p in pslist if calculate_process_score(p, pslist)[0] > 40]),
        "critical_alerts": len(malfind),
        "ioc_found": len(netscan),
        "yara_hits": 0
    }
    print(f"[***] Analisis Case {case_id} SELESAI.")

# --- API Endpoints ---

@app.post("/api/cases")
async def create_case(case_data: CaseCreate):
    global cases
    case_id = f"case_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:4]}"
    new_case = {
        "case_id": case_id,
        "case_name": case_data.case_name,
        "dump_path": case_data.dump_path,
        "analyst_name": case_data.analyst_name,
        "description": case_data.description,
        "status": "ready",
        "created_at": datetime.now().isoformat() + "Z",
        "summary": None,
        "raw_results": {"windows.pslist": [], "windows.netscan": [], "windows.malware.malfind": []}
    }
    cases[case_id] = new_case
    return {"success": True, "data": new_case, "error": None}

@app.get("/api/cases")
async def list_cases():
    return {"success": True, "data": list(cases.values()), "error": None}

@app.get("/api/cases/{case_id}")
async def get_case(case_id: str):
    if case_id not in cases:
        raise HTTPException(status_code=404, detail="Case not found")
    return {"success": True, "data": cases[case_id], "error": None}

@app.post("/api/cases/{case_id}/analyze")
async def analyze_case(case_id: str, background_tasks: BackgroundTasks):
    if case_id not in cases:
        raise HTTPException(status_code=404, detail="Case not found")
    
    jobs[case_id] = {
        "job_id": f"job_{uuid.uuid4().hex[:8]}",
        "case_id": case_id,
        "status": "queued",
        "progress": {"total_plugins": 3, "completed_plugins": 0, "current_plugin": "init", "percent": 0}
    }
    
    cases[case_id]["status"] = "running"
    background_tasks.add_task(background_analysis, case_id)
    return {"success": True, "data": {"job_id": jobs[case_id]["job_id"], "status": "queued"}}

@app.get("/api/cases/{case_id}/status")
async def get_case_status(case_id: str):
    if case_id not in cases:
        raise HTTPException(status_code=404, detail="Case not found")
    job = jobs.get(case_id)
    if not job:
        return {"success": True, "data": {"status": cases[case_id]["status"], "progress": {"percent": 0}}}
    return {"success": True, "data": job}

@app.get("/api/cases/{case_id}/processes")
async def get_processes(case_id: str):
    if case_id not in cases: raise HTTPException(status_code=404)
    raw_ps = cases[case_id].get("raw_results", {}).get("windows.pslist", [])
    processes = []
    for p in raw_ps:
        score, reasons, severity = calculate_process_score(p, raw_ps)
        processes.append({
            "pid": p.get("PID"),
            "ppid": p.get("PPID"),
            "name": p.get("ImageFileName"),
            "path": p.get("FileName") or "N/A",
            "score": score,
            "severity": severity
        })
    return {"success": True, "data": {"processes": processes}}

@app.get("/api/cases/{case_id}/network")
async def get_network(case_id: str):
    if case_id not in cases: raise HTTPException(status_code=404)
    raw_net = cases[case_id].get("raw_results", {}).get("windows.netscan", [])
    raw_ps = cases[case_id].get("raw_results", {}).get("windows.pslist", [])
    pid_map = {p.get("PID"): p.get("ImageFileName") for p in raw_ps}
    connections = []
    for n in raw_net:
        pid = n.get("PID")
        connections.append({
            "pid": pid,
            "process": pid_map.get(pid) or "Unknown",
            "local": f"{n.get('LocalAddr')}:{n.get('LocalPort')}",
            "foreign": f"{n.get('ForeignAddr')}:{n.get('ForeignPort')}",
            "state": n.get("State")
        })
    return {"success": True, "data": {"connections": connections}}

@app.get("/api/cases/{case_id}/malfind")
async def get_malfind(case_id: str):
    if case_id not in cases: raise HTTPException(status_code=404)
    raw_mal = cases[case_id].get("raw_results", {}).get("windows.malware.malfind", [])
    findings = []
    for m in raw_mal:
        offset = m.get("StartVPN")
        findings.append({
            "pid": m.get("PID"),
            "process": m.get("Process") or "Unknown",
            "address": f"0x{offset:x}" if isinstance(offset, int) else str(offset),
            "protection": m.get("Protection"),
            "severity": "critical"
        })
    return {"success": True, "data": {"findings": findings}}

if os.path.exists(frontend_dir):
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="static")

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)

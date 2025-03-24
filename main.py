from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
import os
import sys
import threading
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any

# Add parent directory to path so we can import modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import tool modules
from modules.url_fuzzer import URLFuzzer
from modules.subdomain_finder import SubdomainFinder
from modules.port_scanner import PortScanner

app = FastAPI(
    title="Security Toolkit API",
    description="API for URL fuzzing, subdomain finding, and port scanning tools",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins in development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Store running tasks and results
running_tasks = {}
task_results = {}

# Create results directory
os.makedirs('results', exist_ok=True)

# Models
class TaskParams(BaseModel):
    domain: str
    threads: Optional[int] = 50
    timeout: Optional[float] = 2.0
    
class FuzzerParams(TaskParams):
    extensions: Optional[str] = None
    override_extensions: Optional[bool] = False
    use_ip: Optional[bool] = False

class SubdomainParams(TaskParams):
    advanced_discovery: Optional[bool] = True
    skip_wordlist: Optional[bool] = False

class PortScanParams(TaskParams):
    ports: Optional[str] = "1-1000"

class TaskRequest(BaseModel):
    tool_type: str
    params: Dict[str, Any]

class TaskResponse(BaseModel):
    task_id: str

class TaskStatus(BaseModel):
    status: str
    type: str
    params: Dict[str, Any]
    started_at: str
    completed_at: Optional[str] = None
    error: Optional[str] = None

class ResultItem(BaseModel):
    path: str
    url: str
    status: int
    reason: str
    size: float
    type: str

# Task runner
def run_tool_in_thread(task_id: str, tool_type: str, params: dict):
    """Run a tool in a background thread"""
    output_file = f"results/results_{task_id}.txt"
    
    # Initialize real-time results tracking
    if task_id not in task_results:
        task_results[task_id] = []
    
    # Define a callback for this specific task
    def callback_wrapper(result):
        task_results[task_id].append(result)
    
    try:
        if tool_type == "subdomain":
            domain = params['domain']
            threads = int(params.get('threads', 50))
            advanced = params.get('advanced_discovery', True)
            skip_wordlist = params.get('skip_wordlist', False)
            
            finder = SubdomainFinder(
                domain=domain,
                wordlist="wordlists/subdomains.txt",
                threads=threads,
                output=output_file,
                use_advanced=advanced,
                skip_wordlist=skip_wordlist,
                realtime_callback=callback_wrapper
            )
            finder.run()
            
        elif tool_type == "fuzzer":
            domain = params['domain']
            threads = int(params.get('threads', 50))
            use_ip = params.get('use_ip', False)
            
            # Default optimal extensions for pentesting unless overridden
            if params.get('override_extensions', False) and params.get('extensions'):
                extensions = params.get('extensions').split(',')
            else:
                # Use an optimal set of extensions for pentesting by default
                extensions = ["php", "html", "js", "txt", "asp", "aspx", "jsp", "cgi", "bak", "old", 
                             "backup", "xml", "json", "sql", "config", "log", "env", "git", "svn"]
            
            # Add http:// prefix if not present
            if not domain.startswith(('http://', 'https://')):
                domain = 'https://' + domain
            
            fuzzer = URLFuzzer(
                target=domain,
                wordlist="wordlists/common.txt",
                extensions=extensions,
                threads=threads,
                output=output_file,
                timeout=params.get('timeout', 2.0),
                use_ip=use_ip,
                follow_redirects=True,
                realtime_callback=callback_wrapper
            )
            fuzzer.run()
            
        elif tool_type == "portscan":
            domain = params['domain']
            threads = int(params.get('threads', 50))
            ports = params.get('ports', "1-1000")
            
            scanner = PortScanner(
                target=domain,
                ports=ports,
                threads=threads,
                output=output_file,
                timeout=params.get('timeout', 1.0),
                realtime_callback=callback_wrapper
            )
            scanner.run()
            
        # Update task status to completed
        running_tasks[task_id]['status'] = 'completed'
        running_tasks[task_id]['completed_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
    except Exception as e:
        # Handle errors
        running_tasks[task_id]['status'] = 'error'
        running_tasks[task_id]['error'] = str(e)
        running_tasks[task_id]['completed_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Write error to output file
        with open(output_file, "w") as f:
            f.write(f"Error running {tool_type} on {params['domain']}:\n\n{str(e)}")

@app.get("/")
async def root():
    return {
        "name": "Security Toolkit API",
        "version": "1.0.0",
        "description": "API for URL fuzzing, subdomain finding, and port scanning tools",
        "endpoints": [
            "/start_task - Start a new tool task",
            "/task_status/{task_id} - Get task status",
            "/results/{task_id} - Get task results",
            "/live_results/{task_id} - Get real-time results",
            "/download/{task_id} - Download results file",
            "/tasks - List all tasks",
            "/health - Health check endpoint for monitoring"
        ]
    }

@app.get("/health")
async def health_check():
    """Health check endpoint for Railway monitoring"""
    return {"status": "ok", "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

@app.post("/start_task", response_model=TaskResponse)
async def start_task(task_request: TaskRequest, background_tasks: BackgroundTasks):
    """Start a new tool task"""
    tool_type = task_request.tool_type
    params = task_request.params
    
    # Validate input
    if not tool_type or not params.get('domain'):
        raise HTTPException(status_code=400, detail="Missing required parameters")
    
    # Generate task ID
    task_id = f"{tool_type}_{str(uuid.uuid4())[:8]}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
    
    # Initialize task
    running_tasks[task_id] = {
        'status': 'running',
        'type': tool_type,
        'params': params,
        'started_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    # Start task in background
    background_tasks.add_task(run_tool_in_thread, task_id, tool_type, params)
    
    return {"task_id": task_id}

@app.get("/task_status/{task_id}", response_model=TaskStatus)
async def task_status(task_id: str):
    """Get the status of a running task"""
    if task_id not in running_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    
    return running_tasks[task_id]

@app.get("/results/{task_id}")
async def get_results(task_id: str):
    """Get the results of a completed task"""
    if task_id not in running_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    
    task = running_tasks[task_id]
    if task['status'] != 'completed':
        raise HTTPException(status_code=400, detail=f"Task is {task['status']}")
    
    output_file = f"results/results_{task_id}.txt"
    if os.path.exists(output_file):
        with open(output_file, 'r') as f:
            content = f.read()
        return {"content": content}
    
    raise HTTPException(status_code=404, detail="Results not available")

@app.get("/live_results/{task_id}")
async def live_results(task_id: str):
    """Get the real-time results of a running task"""
    if task_id not in running_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    
    # Return the most recent results
    if task_id in task_results:
        return {"results": task_results[task_id]}
    else:
        return {"results": []}

@app.get("/download/{task_id}")
async def download_results(task_id: str):
    """Download the results file of a completed task"""
    if task_id not in running_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    
    task = running_tasks[task_id]
    if task['status'] != 'completed':
        raise HTTPException(status_code=404, detail="Results not available")
    
    output_file = f"results/results_{task_id}.txt"
    if not os.path.exists(output_file):
        raise HTTPException(status_code=404, detail="Results file not found")
    
    # Create a meaningful filename for downloaded file
    domain = task['params'].get('domain', 'unknown')
    if '://' in domain:
        domain = domain.split('://', 1)[1]
    if '/' in domain:
        domain = domain.split('/', 1)[0]
        
    filename = f"{task['type']}_{domain}_{datetime.now().strftime('%Y%m%d')}.txt"
    
    return FileResponse(
        path=output_file,
        filename=filename,
        media_type="text/plain"
    )

@app.get("/tasks")
async def list_tasks():
    """List all tasks"""
    return running_tasks

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8000"))) 
#!/usr/bin/env python3
import os
import sys
import json
import subprocess
import threading
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_from_directory

# Add parent directory to path so we can import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import tool modules
from modules.url_fuzzer import URLFuzzer
from modules.subdomain_finder import SubdomainFinder
from modules.port_scanner import PortScanner

app = Flask(__name__)

# Store running tasks
running_tasks = {}
# Store real-time results for tasks
task_results = {}

def result_callback(task_id, result):
    """Callback function to handle real-time results from tools"""
    if task_id not in task_results:
        task_results[task_id] = []
    task_results[task_id].append(result)

def run_tool_in_thread(task_id, tool_type, params):
    """Run a tool in a background thread"""
    output_file = f"ui/static/results/results_{task_id}.txt"
    
    try:
        if tool_type == "subdomain":
            domain = params['domain']
            threads = int(params.get('threads', 50))
            advanced = params.get('advancedDiscovery', True)
            skip_wordlist = params.get('skipWordlist', False)
            
            finder = SubdomainFinder(
                domain=domain,
                wordlist="wordlists/subdomains.txt",
                threads=threads,
                output=output_file,
                use_advanced=advanced,
                skip_wordlist=skip_wordlist
            )
            finder.run()
            
        elif tool_type == "fuzzer":
            domain = params['domain']
            threads = int(params.get('threads', 50))
            use_ip = params.get('use_ip', False)
            
            # Default optimal extensions for pentesting unless overridden
            if params.get('override_extensions', False):
                extensions = params.get('extensions', "php,html,js,txt").split(',')
            else:
                # Use an optimal set of extensions for pentesting by default
                extensions = ["php", "html", "js", "txt", "asp", "aspx", "jsp", "cgi", "bak", "old", 
                             "backup", "xml", "json", "sql", "config", "log", "env", "git", "svn"]
            
            # Add http:// prefix if not present
            if not domain.startswith(('http://', 'https://')):
                domain = 'https://' + domain
                
            # Print more information about the target
            print(f"Starting fuzzer on target: {domain}")
            
            # Define a callback for this specific task
            def callback_wrapper(result):
                result_callback(task_id, result)
            
            fuzzer = URLFuzzer(
                target=domain,
                wordlist="wordlists/common.txt",
                extensions=extensions,
                threads=threads,
                output=output_file,
                timeout=2,
                use_ip=use_ip,
                follow_redirects=True,  # Follow redirects to get the final target
                realtime_callback=callback_wrapper  # Add the callback
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
                timeout=1.0
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
        print(f"Error in task {task_id}: {str(e)}")
        
        # Write error to output file
        with open(output_file, "w") as f:
            f.write(f"Error running {tool_type} on {params['domain']}:\n\n{str(e)}")

@app.route('/')
def index():
    """Render main UI page"""
    return render_template('index.html')

@app.route('/start_task', methods=['POST'])
def start_task():
    """Start a new tool task"""
    data = request.json
    tool_type = data.get('tool_type')
    params = data.get('params', {})
    
    # Validate input
    if not tool_type or not params.get('domain'):
        return jsonify({'error': 'Missing required parameters'}), 400
    
    # Generate task ID
    task_id = f"{tool_type}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
    
    # Initialize task
    running_tasks[task_id] = {
        'status': 'running',
        'type': tool_type,
        'params': params,
        'started_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    # Start task in background thread
    thread = threading.Thread(
        target=run_tool_in_thread, 
        args=(task_id, tool_type, params)
    )
    thread.daemon = True
    thread.start()
    
    return jsonify({'task_id': task_id})

@app.route('/task_status/<task_id>')
def task_status(task_id):
    """Get the status of a running task"""
    if task_id not in running_tasks:
        return jsonify({'error': 'Task not found'}), 404
    
    return jsonify(running_tasks[task_id])

@app.route('/results/<task_id>')
def get_results(task_id):
    """Get the results of a completed task"""
    if task_id not in running_tasks:
        return jsonify({'error': 'Task not found'}), 404
    
    task = running_tasks[task_id]
    if task['status'] != 'completed':
        return jsonify({'error': f"Task is {task['status']}"}), 400
    
    output_file = f"ui/static/results/results_{task_id}.txt"
    if os.path.exists(output_file):
        with open(output_file, 'r') as f:
            content = f.read()
        return jsonify({'content': content})
    
    return jsonify({'error': 'Results not available'}), 404

@app.route('/download/<task_id>')
def download_results(task_id):
    """Download the results file of a completed task"""
    if task_id not in running_tasks:
        return jsonify({'error': 'Task not found'}), 404
    
    task = running_tasks[task_id]
    if task['status'] != 'completed':
        return jsonify({'error': 'Results not available'}), 404
    
    output_file = f"results_{task_id}.txt"
    return send_from_directory(
        'static/results',
        output_file,
        as_attachment=True,
        download_name=f"{task['type']}_{task['params']['domain']}_{datetime.now().strftime('%Y%m%d')}.txt"
    )

@app.route('/tasks')
def list_tasks():
    """List all tasks"""
    return jsonify(running_tasks)

@app.route('/live_results/<task_id>')
def live_results(task_id):
    """Get the real-time results of a running task"""
    if task_id not in running_tasks:
        return jsonify({'error': 'Task not found'}), 404
    
    # Return the most recent results
    if task_id in task_results:
        return jsonify({
            'results': task_results[task_id],
            'status': running_tasks[task_id]['status']
        })
    else:
        return jsonify({
            'results': [],
            'status': running_tasks[task_id]['status']
        })

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors"""
    return render_template('index.html'), 404

# Ensure results directory exists
os.makedirs('ui/static/results', exist_ok=True)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000) 
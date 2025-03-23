// Security Toolkit UI - Client-side JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // DOM Elements
    const toolForm = document.getElementById('toolForm');
    const toolTypeSelect = document.getElementById('toolType');
    const startButton = document.getElementById('startButton');
    const downloadButton = document.getElementById('downloadButton');
    const resultPanel = document.getElementById('resultPanel');
    const progressPanel = document.getElementById('progressPanel');
    const taskList = document.getElementById('taskList');
    
    // Tool-specific option elements
    const subdomainOptions = document.getElementById('subdomainOptions');
    const fuzzerOptions = document.getElementById('fuzzerOptions');
    const portscanOptions = document.getElementById('portscanOptions');
    
    // Add a real-time results container
    const liveResultsContainer = document.createElement('div');
    liveResultsContainer.id = 'liveResultsContainer';
    liveResultsContainer.innerHTML = `
        <h3>Results</h3>
        <div class="table-responsive">
            <table class="table table-striped table-hover">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>HTTP Code</th>
                        <th>HTTP Reason</th>
                        <th>Page Size (KB)</th>
                        <th></th>
                    </tr>
                </thead>
                <tbody id="liveResultsTable">
                    <!-- Results will be inserted here -->
                </tbody>
            </table>
        </div>
    `;
    progressPanel.appendChild(liveResultsContainer);
    
    // Current active task
    let activeTaskId = null;
    let taskStatusCheckInterval = null;
    let liveResultsInterval = null;
    
    // Load initial task list
    loadTaskList();
    
    // Event Listeners
    toolTypeSelect.addEventListener('change', handleToolSelection);
    toolForm.addEventListener('submit', startTask);
    downloadButton.addEventListener('click', downloadResults);
    
    // Tool selection
    document.getElementById('tool').addEventListener('change', function() {
        updateToolOptions();
    });
    
    // Override extensions checkbox
    document.getElementById('overrideExtensions').addEventListener('change', function() {
        document.getElementById('extensionsContainer').style.display = this.checked ? 'block' : 'none';
    });
    
    // Function to update tool options visibility
    function updateToolOptions() {
        const tool = document.getElementById('tool').value;
        
        // Hide all option groups first
        document.querySelectorAll('.tool-option-group').forEach(el => {
            el.style.display = 'none';
        });
        
        // Show the selected tool's options
        if (tool === 'subdomain') {
            document.getElementById('subdomainOptions').style.display = 'block';
        } else if (tool === 'fuzz') {
            document.getElementById('fuzzerOptions').style.display = 'block';
        } else if (tool === 'portscan') {
            document.getElementById('portscanOptions').style.display = 'block';
        }
    }
    
    // Initial setup - show options for preselected tool
    updateToolOptions();
    
    /**
     * Show/hide tool-specific options based on selection
     */
    function handleToolSelection() {
        const selectedTool = toolTypeSelect.value;
        
        // Hide all options first
        subdomainOptions.style.display = 'none';
        fuzzerOptions.style.display = 'none';
        portscanOptions.style.display = 'none';
        
        // Show options for selected tool
        if (selectedTool === 'subdomain') {
            subdomainOptions.style.display = 'block';
        } else if (selectedTool === 'fuzzer') {
            fuzzerOptions.style.display = 'block';
        } else if (selectedTool === 'portscan') {
            portscanOptions.style.display = 'block';
        }
    }
    
    /**
     * Start a new task
     */
    async function startTask(event) {
        event.preventDefault();
        
        const toolType = toolTypeSelect.value;
        const domain = document.getElementById('domain').value;
        
        if (!toolType || !domain) {
            showError('Please select a tool and enter a target domain');
            return;
        }
        
        // Collect common parameters
        const params = {
            domain: domain,
            threads: document.getElementById('threads').value,
            timeout: document.getElementById('timeout').value
        };
        
        // Add tool-specific parameters
        if (toolType === 'subdomain') {
            params.advanced = document.getElementById('advancedDiscovery').checked;
            params.skip_wordlist = document.getElementById('skipWordlist').checked;
        } else if (toolType === 'fuzzer') {
            // Only include extensions if override is checked
            if (document.getElementById('overrideExtensions').checked) {
                params.extensions = document.getElementById('extensions').value;
                params.override_extensions = true;
            }
            params.use_ip = document.getElementById('useIp').checked;
        } else if (toolType === 'portscan') {
            params.ports = document.getElementById('ports').value;
        }
        
        // Show progress UI
        resultPanel.style.display = 'none';
        progressPanel.style.display = 'block';
        startButton.disabled = true;
        downloadButton.disabled = true;
        
        try {
            // Send request to start task
            const response = await fetch('/start_task', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    tool_type: toolType,
                    params: params
                })
            });
            
            const data = await response.json();
            
            if (data.error) {
                showError(data.error);
                return;
            }
            
            activeTaskId = data.task_id;
            
            // Start polling for task status
            startTaskStatusPolling(activeTaskId);
            
            // Refresh task list
            setTimeout(loadTaskList, 1000);
            
        } catch (error) {
            showError('Error starting task: ' + error.message);
            resetUI();
        }
    }
    
    /**
     * Poll for task status updates
     */
    function startTaskStatusPolling(taskId) {
        // Clear any existing interval
        if (taskStatusCheckInterval) {
            clearInterval(taskStatusCheckInterval);
        }
        
        // Clear any existing live results interval
        if (liveResultsInterval) {
            clearInterval(liveResultsInterval);
        }
        
        // Set up new interval for task status
        taskStatusCheckInterval = setInterval(async () => {
            try {
                const response = await fetch(`/task_status/${taskId}`);
                const data = await response.json();
                
                if (data.error) {
                    showError(data.error);
                    clearInterval(taskStatusCheckInterval);
                    clearInterval(liveResultsInterval);
                    resetUI();
                    return;
                }
                
                // If task is completed or errored, show results and stop polling
                if (data.status === 'completed' || data.status === 'error') {
                    clearInterval(taskStatusCheckInterval);
                    clearInterval(liveResultsInterval);
                    await loadResults(taskId);
                    loadTaskList();
                    resetUI();
                    
                    if (data.status === 'error' && data.error) {
                        showError(data.error);
                    }
                }
                
            } catch (error) {
                showError('Error checking task status: ' + error.message);
                clearInterval(taskStatusCheckInterval);
                clearInterval(liveResultsInterval);
                resetUI();
            }
        }, 2000); // Check every 2 seconds
        
        // Start polling for live results
        startLiveResultsPolling(taskId);
    }
    
    /**
     * Poll for live results
     */
    function startLiveResultsPolling(taskId) {
        // Set up interval for live results
        liveResultsInterval = setInterval(async () => {
            try {
                const response = await fetch(`/live_results/${taskId}`);
                const data = await response.json();
                
                if (data.error) {
                    // Don't show error here, as it might not have results yet
                    return;
                }
                
                // Update UI with live results
                updateLiveResults(data.results);
                
            } catch (error) {
                console.error('Error fetching live results:', error);
            }
        }, 1000); // Check every second
    }
    
    /**
     * Update the UI with live results
     */
    function updateLiveResults(results) {
        if (!results || results.length === 0) {
            return;
        }
        
        const tableBody = document.getElementById('liveResultsTable');
        
        // Clear existing rows if we're showing all results again
        // (alternatively, you could append only new results)
        tableBody.innerHTML = '';
        
        // Add results to table
        results.forEach(result => {
            const row = document.createElement('tr');
            
            // Style row based on status code
            if (result.status >= 400) {
                row.className = 'table-warning';
            } else if (result.status >= 300) {
                row.className = 'table-info';
            } else {
                row.className = 'table-success';
            }
            
            row.innerHTML = `
                <td>${result.path}</td>
                <td>${result.status}</td>
                <td>${result.reason}</td>
                <td>${result.size.toFixed(3)}</td>
                <td>
                    <button class="btn btn-sm btn-outline-secondary">
                        <i class="bi bi-three-dots-vertical"></i>
                    </button>
                </td>
            `;
            
            tableBody.appendChild(row);
        });
        
        // Show the container
        liveResultsContainer.style.display = 'block';
    }
    
    /**
     * Load and display task results
     */
    async function loadResults(taskId) {
        try {
            const response = await fetch(`/results/${taskId}`);
            const data = await response.json();
            
            if (data.error) {
                showError(data.error);
                return;
            }
            
            // Display results
            resultPanel.innerHTML = `<pre>${data.content}</pre>`;
            resultPanel.style.display = 'block';
            progressPanel.style.display = 'none';
            downloadButton.disabled = false;
            
            // Update active task
            activeTaskId = taskId;
            highlightActiveTask();
            
        } catch (error) {
            showError('Error loading results: ' + error.message);
        }
    }
    
    /**
     * Download results file
     */
    function downloadResults() {
        if (activeTaskId) {
            window.location.href = `/download/${activeTaskId}`;
        }
    }
    
    /**
     * Load and display the list of tasks
     */
    async function loadTaskList() {
        try {
            const response = await fetch('/tasks');
            const tasks = await response.json();
            
            // Clear current list
            taskList.innerHTML = '';
            
            // If no tasks, show message
            if (Object.keys(tasks).length === 0) {
                taskList.innerHTML = '<li class="list-group-item">No tasks yet</li>';
                return;
            }
            
            // Convert to array and sort by time (newest first)
            const taskArray = Object.entries(tasks).map(([id, task]) => {
                return {
                    id: id,
                    ...task
                };
            }).sort((a, b) => {
                const aTime = a.started_at || a.completed_at || '';
                const bTime = b.started_at || b.completed_at || '';
                return bTime.localeCompare(aTime);
            });
            
            // Create task list items
            taskArray.forEach(task => {
                const listItem = document.createElement('li');
                listItem.className = 'list-group-item task-item d-flex justify-content-between align-items-center';
                if (task.id === activeTaskId) {
                    listItem.classList.add('active');
                }
                
                const statusClass = `status-${task.status}`;
                
                listItem.innerHTML = `
                    <div>
                        <div><strong>${formatTaskType(task.type)}</strong> - ${task.params?.domain || ''}</div>
                        <small>${task.started_at || task.completed_at || ''}</small>
                    </div>
                    <span class="task-status ${statusClass}">${task.status}</span>
                `;
                
                listItem.addEventListener('click', () => {
                    if (task.status === 'completed') {
                        loadResults(task.id);
                    }
                });
                
                taskList.appendChild(listItem);
            });
            
        } catch (error) {
            console.error('Error loading task list:', error);
        }
    }
    
    /**
     * Highlight the active task in the task list
     */
    function highlightActiveTask() {
        // Remove active class from all items
        document.querySelectorAll('.task-item').forEach(item => {
            item.classList.remove('active');
        });
        
        // Add active class to current task
        if (activeTaskId) {
            const activeItem = Array.from(document.querySelectorAll('.task-item')).find(
                item => item.textContent.includes(activeTaskId)
            );
            if (activeItem) {
                activeItem.classList.add('active');
            }
        }
    }
    
    /**
     * Show error message
     */
    function showError(message) {
        resultPanel.innerHTML = `<div class="alert alert-danger">${message}</div>`;
        resultPanel.style.display = 'block';
        progressPanel.style.display = 'none';
    }
    
    /**
     * Reset UI elements to their default state
     */
    function resetUI() {
        startButton.disabled = false;
        progressPanel.style.display = 'none';
        resultPanel.style.display = 'block';
        document.getElementById('liveResultsTable').innerHTML = '';
    }
    
    /**
     * Format task type for display
     */
    function formatTaskType(type) {
        if (type === 'subdomain') return 'Subdomain Finder';
        if (type === 'fuzzer') return 'URL Fuzzer';
        if (type === 'portscan') return 'Port Scanner';
        return type;
    }
}); 
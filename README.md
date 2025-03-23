# Security Toolkit API

A FastAPI-based RESTful API for security testing tools, including URL fuzzing, subdomain finding, and port scanning.

## Features

- **URL Fuzzer**: Discover hidden endpoints and files on web servers
- **Subdomain Finder**: Enumerate subdomains of a target domain
- **Port Scanner**: Scan for open ports on target hosts
- **Asynchronous Task Processing**: Run long-running scans in the background
- **Real-time Results**: Get results as they are found
- **Comprehensive API**: REST API with JSON responses

## API Endpoints

- **GET /**: API information and available endpoints
- **POST /start_task**: Start a new tool task
- **GET /task_status/{task_id}**: Get the status of a running task
- **GET /results/{task_id}**: Get the results of a completed task
- **GET /live_results/{task_id}**: Get real-time results of a running task
- **GET /download/{task_id}**: Download the results file
- **GET /tasks**: List all tasks

## Getting Started

### Prerequisites

- Python 3.8+
- FastAPI
- Hypercorn

### Running Locally

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Run the API:
   ```
   hypercorn main:app --bind 0.0.0.0:8000
   ```

3. Access the API at http://localhost:8000

### Deploying to Railway

This API is configured for easy deployment on Railway:

1. Push to GitHub
2. Connect your repo to Railway
3. Deploy!

## API Usage Examples

### Start a URL Fuzzing Task

```bash
curl -X POST "http://localhost:8000/start_task" \
  -H "Content-Type: application/json" \
  -d '{
    "tool_type": "fuzzer",
    "params": {
      "domain": "example.com",
      "threads": 50,
      "timeout": 2.0,
      "extensions": "php,html,js",
      "override_extensions": false
    }
  }'
```

### Get Task Status

```bash
curl -X GET "http://localhost:8000/task_status/fuzzer_12345678_20230515123456"
```

### Get Results

```bash
curl -X GET "http://localhost:8000/results/fuzzer_12345678_20230515123456"
```

## Tool Options

### URL Fuzzer

- **domain**: Target domain or URL
- **threads**: Number of threads (default: 50)
- **timeout**: Request timeout in seconds (default: 2.0)
- **extensions**: File extensions to check (comma separated)
- **override_extensions**: Whether to override default extensions (default: false)
- **use_ip**: Use IP address instead of hostname (default: false)

### Subdomain Finder

- **domain**: Target domain
- **threads**: Number of threads (default: 50)
- **advanced_discovery**: Use advanced discovery methods (default: true)
- **skip_wordlist**: Skip wordlist-based enumeration (default: false)

### Port Scanner

- **domain**: Target domain or IP
- **threads**: Number of threads (default: 50)
- **timeout**: Connection timeout in seconds (default: 1.0)
- **ports**: Port range (e.g., "1-1000" or "80,443,8080")

## Disclaimer

This tool is provided for educational and legitimate security testing purposes only. Always ensure you have proper authorization before testing any systems you don't own. Unauthorized scanning or testing of systems is illegal and unethical.

## License

MIT 
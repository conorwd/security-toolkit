# Security Toolkit UI

A web-based user interface for the Security Toolkit penetration testing tools.

## Features

- Run all tools from a clean web interface
- View and download scan results
- Track running and completed tasks
- Configure all tool parameters from the UI

## Tools Available

- **Subdomain Finder**: Discover subdomains of a target domain
- **URL Fuzzer**: Fuzz URLs to find hidden endpoints
- **Port Scanner**: Scan for open ports on a target

## Getting Started

### Prerequisites

- Python 3.x
- Flask
- The Security Toolkit package

### Installation

1. Install the required packages:
   ```
   pip install flask
   ```

2. Navigate to the project directory and run the app:
   ```
   python ui/app.py
   ```

3. Open your browser and navigate to:
   ```
   http://localhost:5000
   ```

## Using the UI

1. **Select a Tool**: Choose from Subdomain Finder, URL Fuzzer, or Port Scanner
2. **Enter Target Domain**: Enter the target domain (e.g., example.com)
3. **Configure Options**: Set tool-specific options
4. **Start Scan**: Click "Start Scan" to begin
5. **View Results**: Results will be displayed in the right panel
6. **Download Results**: Click "Download Results" to save the scan output

## Tool Options

### Subdomain Finder
- **Advanced Discovery**: Use methods like Certificate Transparency logs
- **Skip Wordlist**: Use only advanced methods (no wordlist-based enumeration)

### URL Fuzzer

The URL Fuzzer tool finds hidden files and directories on the target website.

**Options:**
- **Override default extensions**: By default, the fuzzer uses an optimal set of extensions for pentesting. Check this box to manually specify extensions.
- **File Extensions**: Only visible when "Override default extensions" is checked. Allows specifying custom extensions as a comma-separated list.
- **Use IP address instead of hostname**: Performs requests using the resolved IP instead of the domain name.

**Key Features:**
- **Default extensions for pentesting** include:
  - Common web files: php, html, js, txt
  - Server-side code: asp, aspx, jsp, cgi
  - Config & data files: xml, json, sql, config, log
  - Backup files: bak, old, backup
  - Version control: git, svn
- **Automatic redirect following**: Detects when a target redirects (e.g., from http to https or adding www) and uses the final URL as the base for testing.
- **Plain path testing**: Tests paths without extensions (like "/about" or "/terms-and-conditions"), with additional format variations (hyphenated, underscored).

### Port Scanner
- **Ports**: Port range (e.g., 1-1000 or 80,443,8080)

## Common Options
- **Threads**: Number of threads to use
- **Timeout**: Request timeout in seconds 
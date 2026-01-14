# Cariddi - Advanced Endpoint & Secrets Scanner for Burp Suite

## Overview

Cariddi is a powerful Burp Suite extension that automates the discovery of API endpoints, secrets, credentials, and sensitive information from web applications. It combines advanced crawling and pattern matching to identify security issues during the reconnaissance phase of penetration testing.

**Developed for:** Security professionals, penetration testers, bug bounty hunters, and security researchers.

## Features

### 1. **API Endpoint Discovery**
- Automatic crawling of URLs
- Discovery of REST, GraphQL, and SOAP endpoints
- Tests common API paths: `/api`, `/v1`, `/admin`, `/swagger`, `/graphql`, etc.
- Identifies hidden endpoints and internal APIs
- Intensive mode for subdomain scanning (*.target.com)

### 2. **Secrets & Credentials Detection**
- AWS Access Keys and Secrets
- JWT Tokens
- API Keys and Bearer Tokens
- Slack, Discord, and GitHub Tokens
- Stripe Payment API Keys
- Database Connection Strings (MongoDB, MySQL, PostgreSQL)
- Private Keys (.pem, .key, .pfx files)
- OAuth tokens and credentials

### 3. **Error & Exception Disclosure**
- Java stack traces and exceptions
- Python tracebacks
- JavaScript errors and console logs
- SQL injection error messages
- Generic error disclosures

### 4. **Information Gathering**
- Email address extraction
- IP address identification
- Server version information
- HTTP headers analysis
- Technology fingerprinting

### 5. **File Extension Hunting**
- 7-level granularity system
- Discovers sensitive configuration files
- Finds backup and archived files
- Identifies development files

### 6. **Advanced Capabilities**
- Multi-threaded concurrent scanning
- Configurable crawl depth (1-10 levels)
- Custom HTTP headers support
- User-Agent customization
- Adjustable timeout settings
- Real-time progress monitoring
- Resizable and adjustable UI components

### 7. **Export & Reporting**
- **JSON**: For programmatic processing and integration
- **CSV**: For spreadsheet analysis in Excel/Google Sheets
- **XML**: For enterprise tools and SIEM integration
- **TXT**: For readable reports and documentation

## Installation

### Requirements
- Burp Suite Professional or Community Edition
- Java 8 or higher
- BurpSuite Community API JAR

### Setup Steps

1. **Build the Extension:**
   ```powershell
   cd c:\Users\navee\OneDrive\Documents\New-projects\cariddi
   javac -cp burpsuite_community_api.jar *.java
   jar cvfm cariddi.jar MANIFEST.MF burp/*.class
   ```

2. **Load in Burp Suite:**
   - Open Burp Suite
   - Go to `Extender` → `Extensions`
   - Click `Add`
   - Select `Extension type: Java`
   - Choose `cariddi.jar` file
   - Click `Next`

3. **Verify Installation:**
   - A new `Cariddi` tab should appear in Burp Suite
   - Check the output console for: "[*] Cariddi extension loaded successfully!"

## Usage Guide

### Step 1: Add Target URLs
1. Navigate to the **Scanner** tab
2. Enter target URLs in the "Target URLs" section
3. One URL per line
4. Examples:
   ```
   https://example.com
   https://api.example.com
   https://app.example.com/api
   ```

### Step 2: Configure Scanning Options
Go to the **Settings** tab:

**Scan Options:**
- ✅ **Hunt for Endpoints** - Find API paths (default: ON)
- ✅ **Hunt for Secrets** - Find exposed credentials (default: ON)
- ☐ **Hunt for Errors** - Find error disclosures (default: OFF)
- ☐ **Hunt for Info** - Find information leaks (default: OFF)
- ☐ **Intensive Mode** - Scan subdomains matching *.domain.com (default: OFF)

**Performance Settings:**
- **Concurrency Level** (default: 20, range: 1-200)
  - Higher values = faster scanning but more server load
  - Use 20-50 for public targets, 10-20 for private networks
  
- **Timeout** (default: 10 seconds, range: 1-60)
  - Time to wait for each request
  - Increase for slow or remote servers
  
- **Max Crawl Depth** (default: 3, range: 1-10)
  - How deep to follow links from the initial URL
  - Higher values = more comprehensive but slower
  
- **File Extension Level** (default: 2, range: 1-7)
  1. Most juicy: .key, .pem, .env, .config, .secret
  2. Very juicy: .json, .xml, .yaml, .sql, .db
  3. Juicy: .txt, .csv, .xlsx, .zip
  4. Medium: .js, .py, .php, .java
  5. Low-medium: .html, .css, .ts
  6. Low: Fonts and assets
  7. Not juicy: Images

**Custom Settings:**
- **Custom Headers** (format: `Cookie: value;; Authorization: Bearer token`)
  - Add authentication headers if needed
  - Use `;;` to separate multiple headers
  
- **User Agent**: Customize to avoid detection or mimic specific browsers

### Step 3: Start Scanning
1. Return to the **Scanner** tab
2. Click **Start Scan** button
3. Monitor progress with the progress bar
4. Status updates appear in real-time
5. Click **Stop Scan** to halt the scan

### Step 4: Review Results
1. Go to the **Results** tab
2. Browse discovered findings
3. Results are color-coded for quick identification:
   - 🔴 **Red (Secrets)**: High priority - exposed credentials
   - 🔵 **Blue (Endpoints)**: API paths found
   - 🟡 **Yellow (Errors)**: Error disclosures
   - 🟢 **Green (Info)**: Information leaks
4. Click individual rows to view details

### Step 5: Export Results
1. In the **Results** tab, select the rows to export (or select all)
2. Choose export format:
   - **Export as JSON**: For automation and integration
   - **Export as CSV**: For spreadsheet analysis
   - **Export as XML**: For enterprise tools
   - **Export as TXT**: For reports
3. **Copy Selected**: Copy selected rows to clipboard
4. Select file location and save

## Test Cases & Examples

### Example 1: Basic API Scanning
**Target:** `https://api.example.com`

**Configuration:**
- Hunt for Endpoints: ON
- Hunt for Secrets: ON
- Concurrency: 50
- Timeout: 10s

**Expected Findings:**
- `/api/users`
- `/api/auth/login`
- `/api/v1/products`
- `/graphql`
- `/swagger.json`

### Example 2: Secrets Discovery
**Target:** `https://github.com/someorg/somerepo`

**Configuration:**
- Hunt for Secrets: ON
- Hunt for Info: ON
- Custom Headers: Add GitHub authentication if needed

**Expected Findings:**
- AWS keys in source code
- Database connection strings
- OAuth tokens
- Email addresses

### Example 3: Error Disclosure Testing
**Target:** `https://vulnerable.example.com`

**Configuration:**
- Hunt for Errors: ON
- Hunt for Info: ON
- Max Crawl Depth: 5

**Expected Findings:**
- Stack traces revealing technology
- Database error messages
- Server configuration leaks

### Example 4: Comprehensive Reconnaissance
**Target:** `https://example.com`

**Configuration:**
- Hunt for Endpoints: ON
- Hunt for Secrets: ON
- Hunt for Errors: ON
- Hunt for Info: ON
- Intensive Mode: ON
- Concurrency: 100

**Expected Findings:**
- All APIs and endpoints
- Any exposed secrets
- Configuration disclosures
- Information about all subdomains

## Tips for Best Results

1. **Start Conservative**: Begin with default settings, increase concurrency if needed
2. **Use Authentication**: Add custom headers with authentication tokens for private APIs
3. **Adjust Timeout**: Increase timeout for slow or geographically distant servers
4. **Multiple Passes**: Run scans with different settings to find all issues
5. **Combine Tools**: Use results with other security tools (Burp Scanner, OWASP ZAP, etc.)
6. **Review False Positives**: Not all findings are necessarily vulnerabilities
7. **Scope Carefully**: Ensure you have permission to scan the target
8. **Check Proxy**: Verify Burp proxy settings if scans aren't detecting results

## Understanding Results

### Result Types

| Type | Meaning | Examples |
|------|---------|----------|
| **Endpoint** | API or web endpoint discovered | `/api/users`, `/admin/panel`, `/graphql` |
| **Secret** | Exposed credential or token | API keys, AWS credentials, JWT tokens |
| **Error** | Error message disclosing info | Stack traces, SQL errors, version info |
| **Info** | Non-critical information leaked | Email addresses, IP addresses |

### Severity Levels

- **High**: Exposed credentials, secrets, or critical endpoints
- **Medium**: Error disclosures, sensitive information leaks
- **Low**: Non-sensitive endpoints, general information

## Keyboard Shortcuts

- **Start Scan**: Click "Start Scan" button (or Enter if URL field is focused)
- **Stop Scan**: Click "Stop Scan" button
- **Clear URLs**: Click "Clear URLs" button
- **Export**: Select rows + click export button

## Performance Tuning

### For Large Targets
- Increase **Concurrency Level** to 100-150
- Reduce **Timeout** to 5-8 seconds
- Set **Max Crawl Depth** to 2-3
- Disable non-essential hunting modes

### For Slow Networks
- Reduce **Concurrency Level** to 5-10
- Increase **Timeout** to 30-60 seconds
- Set **Max Crawl Depth** to 1-2

### For Maximum Coverage
- Set **Concurrency Level** to 50-100
- Increase **Max Crawl Depth** to 5-10
- Enable **Intensive Mode**
- Enable all hunting modes

## Troubleshooting

### Issue: No results found
**Solution:** 
- Check that target is reachable
- Verify Burp proxy settings
- Try with custom User-Agent
- Increase timeout value

### Issue: Extension loads but tab doesn't appear
**Solution:**
- Check Burp console for error messages
- Verify Java version (requires Java 8+)
- Try reloading the extension

### Issue: Slow scanning
**Solution:**
- Reduce concurrency level
- Increase timeout
- Reduce max crawl depth
- Disable non-essential modes

### Issue: Too many false positives
**Solution:**
- Adjust regex patterns if source available
- Filter results before export
- Review and manually validate findings

## Security Considerations

- **Authorization**: Only scan systems you have permission to test
- **Rate Limiting**: Be respectful of target server resources
- **Authentication**: Use authentication headers to scan private APIs
- **Credentials**: Never commit API keys or credentials to version control
- **Data Protection**: Exported results may contain sensitive information - handle carefully

## Version History

- **v1.0.0** (2026-01-14): Initial release
  - Full endpoint discovery
  - Secrets and credentials detection
  - Error and information disclosure hunting
  - Multi-format export (JSON, CSV, XML, TXT)
  - Comprehensive help and documentation

## License

This extension is provided as-is for authorized security testing purposes only. Ensure you have proper authorization before scanning any systems.

## Support & Contributing

- Report issues through the Burp Suite console
- Review the Help tab within the extension for detailed guidance
- Check test cases for common scenarios

## Related Tools

- **Burp Suite Professional**: https://portswigger.net/burp
- **Cariddi (Original CLI)**: https://github.com/edoardottt/cariddi
- **OWASP ZAP**: https://www.zaproxy.org/
- **Nuclei**: https://github.com/projectdiscovery/nuclei
- **Gitleaks**: https://github.com/gitleaks/gitleaks

---

**Developed for:** Penetration Testing, Bug Bounty, Security Research, OSINT

**Platform:** Burp Suite (Community & Professional)

**Language:** Java

**Status:** Active Development

# BurpXcelerator - Advanced Penetration Testing Automation

A production-ready Burp Suite extension that automates and accelerates penetration testing workflows.

## Overview

BurpXcelerator is a comprehensive Burp Suite extension designed to reduce penetration testing time by automating reconnaissance, prioritization, access control testing, and professional reporting. Built with Java and the Burp Extender API, it provides a modular architecture with six powerful modules.

## Key Features

### 1. Core Engine
- **Real-time HTTP Traffic Capture**: Monitors all proxy traffic automatically
- **Data Normalization**: Standardizes request/response data for analysis
- **Thread-Safe Storage**: Uses ConcurrentHashMap for concurrent access
- **Risk Scoring (0-10)**: Assigns relevance scores to all captured traffic

### 2. URL Relevance Engine
- **Intelligent Filtering**: Automatically ignores static resources (.css, .js, .png, etc.)
- **Smart Scoring**: Scores URLs based on HTTP method, keywords, and parameters
- **Attackable URLs Filter**: Toggle to show only high-risk targets (score >= 5)
- **URL Export**: Export discovered URLs for external scanning tools

### 3. Smart Parameter Analyzer
- **Automatic Extraction**: Extracts all request parameters (GET, POST, headers, cookies)
- **Type Classification**: 
  - Numeric ID, String ID, User Reference
  - Authentication tokens, Boolean parameters
- **Risk Scoring**: Assigns risk scores based on parameter type
- **Sortable Table UI**: Professional Swing interface with export functionality
- **CSV Export**: Export parameters for further analysis

### 4. Broken Access Control Tester
- **Right-Click Context Menu**: "Test Access Control" on any request
- **Multiple Test Strategies**:
  - Remove all cookies
  - Remove Authorization headers
  - Modify numeric ID parameters
- **Anomaly Detection**:
  - Status code differences
  - Response length variations
  - Content comparison
- **Severity Classification**: Low, Medium, High, Critical
- **CSV Export**: Export findings with detailed analysis

### 5. External Tool Integrations
- **Nuclei Integration**:
  - Export URLs to file format
  - Parse Nuclei JSON results
  - Integration with template-based vulnerability scanning
  
- **Semgrep Integration**:
  - Scan JavaScript and API responses
  - Parse code vulnerability findings
  - Requires Semgrep CLI installation

- **OWASP Top 10 Mapping**:
  - Automatic categorization of findings
  - All 10 OWASP 2021 categories mapped
  - Comprehensive vulnerability classification

### 6. Auto PoC Report Generator
- **Professional Markdown Reports** including:
  - Vulnerability title and severity
  - OWASP Top 10 mapping
  - Detailed summary
  - Step-by-step reproduction guide
  - HTTP request and response
  - Impact analysis
  - Remediation recommendations
  - Risk assessment
- **Custom Report Builder**: Create reports with custom details
- **Markdown Export**: Export to professional documentation format

## Architecture

```
BurpXcelerator/
├── burp/
│   ├── BurpExtender.java          # Extension entry point
│   ├── core/
│   │   ├── CoreEngine.java         # Traffic capture & scoring
│   │   └── package-info.java
│   ├── relevance/
│   │   ├── URLRelevanceEngine.java # URL filtering logic
│   │   ├── URLRelevanceUI.java     # URL table UI
│   │   └── package-info.java
│   ├── parameters/
│   │   ├── Parameter.java          # Parameter data class
│   │   ├── ParameterAnalyzerUI.java # Parameter table UI
│   │   └── package-info.java
│   ├── accesstrol/
│   │   ├── AccessControlTester.java # AC testing logic
│   │   ├── AccessControlUI.java    # Results UI
│   │   ├── AccessControlIssue.java # Finding data class
│   │   └── package-info.java
│   ├── integrations/
│   │   ├── NucleiIntegration.java  # Nuclei integration
│   │   ├── SemgrepIntegration.java # Semgrep integration
│   │   ├── OwaspMapping.java       # OWASP categorization
│   │   ├── IntegrationsUI.java     # Integration UI
│   │   └── package-info.java
│   ├── reporting/
│   │   ├── ReportGenerator.java    # Report generation
│   │   ├── ReportingUI.java        # Report UI
│   │   └── package-info.java
│   └── ui/
│       ├── MainUI.java             # Main tabbed interface
│       └── package-info.java
```

## Compilation Instructions

### Prerequisites
- **Java 8 or later** (Java 11+ recommended)
- **Burp Suite API JAR**: `burp-extender-api.jar`

### Step 1: Obtain Burp Suite API
```bash
# The Burp Suite API is included with Burp Suite Pro
# Location: <BurpSuitePath>/burp-extender-api.jar
# Or download from: https://portswigger.net/burp/releases
```

### Step 2: Compile the Source Code

**On Linux/macOS:**
```bash
cd BurpXcelerator1

# Create build directory
mkdir -p build

# Compile with Burp API in classpath
javac -cp burp-extender-api.jar -d build -encoding UTF-8 $(find src -name "*.java")

# Create JAR
cd build
jar -cvfe ../BurpXcelerator.jar burp.BurpExtender burp/
cd ..
```

**On Windows (PowerShell):**
```powershell
cd BurpXcelerator1

# Create build directory
mkdir build -Force

# Compile (use backtick for line continuation)
javac -cp burp-extender-api.jar -d build -encoding UTF-8 `
    $(Get-ChildItem -Path src -Include "*.java" -Recurse | ForEach-Object {$_.FullName})

# Create JAR
cd build
jar -cvfe ..\BurpXcelerator.jar burp.BurpExtender burp/
cd ..
```

**On Windows (cmd.exe):**
```cmd
cd BurpXcelerator1
mkdir build
javac -cp burp-extender-api.jar -d build -encoding UTF-8 src\burp\*.java src\burp\core\*.java src\burp\relevance\*.java src\burp\parameters\*.java src\burp\accesstrol\*.java src\burp\integrations\*.java src\burp\reporting\*.java src\burp\ui\*.java
cd build
jar -cvfe ..\BurpXcelerator.jar burp.BurpExtender burp/
cd ..
```

### Step 3: Verify the JAR
```bash
jar -tf BurpXcelerator.jar | head -20
# Should show manifest and class files
```

## Loading into Burp Suite

### Method 1: Burp Suite UI (Recommended)
1. Open **Burp Suite Pro**
2. Navigate to **Extensions → Installed** tab
3. Click **Add**
4. Select **Extension type**: Java
5. Click **Select file** and choose `BurpXcelerator.jar`
6. Click **Next**
7. Check the **Output** tab for initialization messages
8. The **BurpXcelerator** tab will appear in Burp Suite

### Method 2: From Extender API
```java
// If extending programmatically
callbacks.loadExtension(new File("BurpXcelerator.jar"));
```

## Usage Guide

### URL Relevance Engine
1. Navigate the web application in Burp Suite Proxy
2. Switch to the **URL Relevance** tab
3. View captured URLs with relevance scores (0-10)
4. Check **"Show only attackable URLs"** to filter high-risk targets
5. **Export URLs** button to save for external scanners

### Parameter Analyzer
1. Navigate to the **Parameter Analyzer** tab
2. View all parameters with classifications and risk scores
3. **Show High Risk Only** to focus on critical parameters
4. **Export Parameters (CSV)** for analysis in spreadsheets
5. Parameters are categorized by type:
   - Numeric ID (Risk: 8)
   - String ID (Risk: 8)
   - User Reference (Risk: 7)
   - Authentication tokens (Risk: 9)
   - Boolean parameters (Risk: 4)

### Access Control Tester
1. In Burp Proxy or any message area, right-click a request
2. Select **"Test Access Control"**
3. Results appear in the **Access Control** tab
4. The tester automatically:
   - Removes cookies and replays
   - Removes Authorization header and replays
   - Modifies numeric ID parameters
5. **Export Findings** as CSV with detailed results
6. Findings colored by severity: Low, Medium, High, Critical

### Integrations
**Nuclei Integration:**
1. Switch to **Integrations** tab
2. Click **"Export URLs for Nuclei"**
3. Copy the displayed command
4. Run: `nuclei -l urls_for_nuclei.txt -o results.json`
5. Click **"Load Nuclei Results"** to parse findings

**Semgrep Integration:**
1. Install Semgrep: `pip install semgrep`
2. Click **"Scan with Semgrep"** for instructions
3. Run Semgrep on captured responses
4. Results are analyzed against OWASP Top 10

**OWASP Mapping:**
1. Click **"View OWASP Categories"**
2. All findings automatically mapped to OWASP 2021 Top 10

### Reporting
1. Navigate to the **Reporting** tab
2. **Generate Sample Report**: Creates a SQL Injection example
3. **Custom Report Generator**: Fill in details for custom reports
4. **Export Report to Markdown**: Save professional PDF-ready reports

## Error Handling

The extension includes comprehensive error handling:
- All exceptions are logged to Burp Suite's **Output** tab
- Thread-safe concurrent operations
- Graceful degradation if optional features unavailable
- Input validation on all user inputs
- Resource cleanup on shutdown

## Thread Safety

- **ConcurrentHashMap** for URL and transaction storage
- **ExecutorService** with fixed thread pool (10 threads)
- **SwingUtilities.invokeLater()** for UI updates
- Atomic operations on shared state

## Performance Considerations

- **Efficient Filtering**: Static resource detection prevents UI bloat
- **Lazy Loading**: UI updates only for relevant traffic
- **Batch Processing**: Parameters grouped by URL
- **Memory Management**: Configurable maximum stored requests

## Troubleshooting

### Extension doesn't appear in Burp
- Check **Extensions → Installed** tab for error messages
- Verify JAR compilation with correct Java version
- Ensure `burp-extender-api.jar` is in compilation classpath

### No traffic captured
- Verify requests are going through **Burp Proxy**
- Check that extension loaded successfully
- Enable **Proxy → Intercept is on** temporarily
- Check **Output** tab for errors

### Parameters not appearing
- Ensure requests have parameters (GET, POST, headers)
- Check URL doesn't match static resource pattern
- Clear parameters and navigate to a new URL

### Access Control tests fail
- Ensure target request has modifiable parameters
- Verify HTTP service is accessible
- Check Burp Suite has network connectivity

## Limitations & Future Enhancements

### Current Limitations
- Semgrep integration requires CLI installation
- Nuclei JSON parsing is regex-based (not full JSON parsing)
- Maximum URL storage limited by system RAM

### Future Enhancements
- GraphQL introspection and testing
- WebSocket traffic analysis
- Machine learning-based parameter classification
- Database fingerprinting
- Custom payload templates
- Advanced request diffing

## Security Considerations

- Extension runs with same privileges as Burp Suite
- No data is sent externally unless explicitly exported
- All local file operations are to user-selected directories
- Sensitive headers properly handled in Access Control tests

## License & Credits

Built for security professionals by security professionals.

## Support & Feedback

For issues, feature requests, or feedback:
1. Check this README for troubleshooting
2. Review error messages in Burp Suite **Output** tab
3. Verify Java version compatibility (8+)
4. Test with a fresh Burp project

---

**Version**: 1.0.0  
**Last Updated**: January 2026  
**Compatibility**: Burp Suite Pro 2021.2+, Java 8+
2.  Go to the "Extender" tab.
3.  Click on the "Add" button in the "Burp Extensions" section.
4.  In the "Add extension" dialog, select "Java" as the "Extension type".
5.  Click on the "Select file..." button and choose the `BurpXcelerator.jar` file.
6.  Click "Next". The extension should be loaded and a new tab named "BurpXcelerator" will appear in the main tabbed pane.

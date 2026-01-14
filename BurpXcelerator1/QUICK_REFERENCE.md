# BurpXcelerator - Quick Reference

## Modules Overview

| Module | Purpose | UI | Key Features |
|--------|---------|-----|--------------|
| **Core Engine** | HTTP traffic capture and normalization | Background | Real-time capture, scoring (0-10), thread-safe storage |
| **URL Relevance** | Identify attackable URLs | Table + Filter | Smart scoring, static resource filtering, export |
| **Parameters** | Extract and analyze parameters | Sortable Table | Classification, risk scoring (3-9), CSV export |
| **Access Control** | Test AC vulnerabilities | Results Table | 3 test strategies, anomaly detection, severity levels |
| **Integrations** | External tool integration | Tabbed Panel | Nuclei, Semgrep, OWASP mapping |
| **Reporting** | Generate PoC reports | Text + Form | Markdown export, custom reports, professional format |

## Scoring Systems

### URL Relevance Score (0-10)
- HTTP Method: POST/PUT (+3), DELETE (+4), GET (+1)
- Keywords: api, admin, user, etc. (+2 each)
- Parameters: Present (+1-3)
- Response Status: 4xx/5xx (+1)
- Path Depth: >3 slashes (+1)

### Parameter Risk Score (0-10)
- Numeric ID: 8
- String ID: 8
- User Reference: 7
- Authentication: 9
- Numeric: 5
- Boolean: 4
- String: 3

### AC Test Severity
- **Critical** - Direct access bypass (200 → 200 same content)
- **High** - Status code changes revealing access control
- **Medium** - Significant response length differences
- **Low** - Minor differences or inconclusive

## Static Resources (Auto-Filtered)
`.css`, `.js`, `.png`, `.jpg`, `.jpeg`, `.gif`, `.svg`, `.woff`, `.woff2`, `.ttf`, `.eot`, `.ico`, `.xml`, `.json`, `.pdf`, `.mp4`, `.webm`, `.webp`

## OWASP Top 10 2021 Categories

| Code | Category | Examples |
|------|----------|----------|
| A01 | Broken Access Control | IDOR, privilege escalation |
| A02 | Cryptographic Failures | Weak encryption, exposed secrets |
| A03 | Injection | SQL injection, XSS, command injection |
| A04 | Insecure Design | Logic flaws, business logic abuse |
| A05 | Security Misconfiguration | Default creds, debug enabled, XXE |
| A06 | Vulnerable Components | Outdated libraries |
| A07 | Authentication Failures | Broken auth, session fixation |
| A08 | Data Integrity Failures | Insecure deserialization |
| A09 | Logging Failures | Missing logs, monitoring gaps |
| A10 | SSRF | Server-side request forgery |

## Compilation Commands

### Linux/macOS One-Liner
```bash
cd BurpXcelerator1 && mkdir -p build && javac -cp burp-extender-api.jar -d build -encoding UTF-8 $(find src -name "*.java") && cd build && jar -cvfe ../BurpXcelerator.jar burp.BurpExtender burp/ && cd ..
```

### Windows PowerShell One-Liner
```powershell
cd BurpXcelerator1; mkdir build -Force; javac -cp burp-extender-api.jar -d build -encoding UTF-8 $(Get-ChildItem -Path src -Include "*.java" -Recurse | ForEach-Object {$_.FullName}); cd build; jar -cvfe ..\BurpXcelerator.jar burp.BurpExtender burp/; cd ..
```

## File Count Summary

| Component | Files |
|-----------|-------|
| Core Engine | 2 |
| URL Relevance | 3 |
| Parameters | 3 |
| Access Control | 4 |
| Integrations | 5 |
| Reporting | 3 |
| UI | 2 |
| Entry Point | 1 |
| **Total Java Files** | **23** |
| Documentation | README.md, IMPLEMENTATION_SUMMARY.md |

## Key Classes

### Core
- `CoreEngine` - IHttpListener, thread-safe capture, scoring
- `HttpTransaction` - Immutable transaction data
- `RequestMetadata` - Metadata with timestamp

### URL Relevance
- `URLRelevanceEngine` - Scoring logic, filtering
- `URLRelevanceUI` - JTable, export, filter toggle

### Parameters
- `Parameter` - Data class (name, value, type, risk)
- `ParameterAnalyzerUI` - Table, CSV export, high-risk filter

### Access Control
- `AccessControlTester` - IContextMenuFactory, 3 test strategies
- `AccessControlUI` - Results table, CSV export
- `AccessControlIssue` - Severity enum, finding data

### Integrations
- `NucleiIntegration` - Export/parse Nuclei results
- `SemgrepIntegration` - Semgrep CLI integration
- `OwaspMapping` - 50+ keyword mappings
- `IntegrationsUI` - Integration panels, buttons

### Reporting
- `ReportGenerator` - Markdown generation
- `ReportingUI` - Custom report builder, export

### UI
- `BurpExtender` - IBurpExtender, initialization
- `MainUI` - ITab, 5-tab container

## Data Flow

```
HTTP Traffic (Proxy)
        ↓
CoreEngine (IHttpListener)
        ↓
    ├── URL Scoring
    ├── Parameter Extraction
    └── Storage (ConcurrentHashMap)
        ↓
    ├── URLRelevanceUI (table)
    ├── ParameterAnalyzerUI (table)
    ├── AccessControlTester (context menu)
    ├── IntegrationsUI (Nuclei, Semgrep, OWASP)
    └── ReportingUI (report generation)
        ↓
    Export (CSV, Markdown, TXT)
```

## Common Usage Patterns

### Discover Attackable URLs
1. Navigate target application in Burp
2. Check URL Relevance tab
3. Enable "Show only attackable URLs" (score >= 5)
4. Export URLs for Nuclei scanning

### Find Sensitive Parameters
1. Monitor traffic in URL Relevance tab
2. Check Parameter Analyzer tab
3. Sort by Risk Score (High to Low)
4. Review Authentication tokens, User References

### Test Access Control
1. Right-click request in Proxy or history
2. Select "Test Access Control"
3. Check results in AC tab
4. Focus on HIGH/CRITICAL severity findings
5. Export findings for report

### Generate PoC Report
1. Go to Reporting tab
2. Fill custom report form with vulnerability details
3. Click "Generate Custom Report"
4. Review Markdown preview
5. Click "Export Report to Markdown"
6. Save PDF from Markdown or use online converter

## Configuration Notes

- **Thread Pool**: 10 threads (configurable in CoreEngine)
- **Response Length Threshold**: 15% difference (AccessControlTester)
- **Score Threshold**: >= 5 for "attackable" URLs
- **Risk Filter**: >= 7 for "high risk" parameters
- **Static Resources**: Hardcoded in CoreEngine (extensible)

## Troubleshooting

| Issue | Solution |
|-------|----------|
| No traffic captured | Verify Burp Proxy enabled, check Output tab |
| Parameters not showing | Ensure requests have GET/POST params or headers |
| AC tests failing | Right-click request with modifiable params, check connectivity |
| Nuclei results not parsing | Verify JSON format, check file path |
| Export fails | Check write permissions on selected directory |

## Extension Lifecycle

1. **Load** → BurpExtender.registerExtenderCallbacks()
2. **Initialize** → Create CoreEngine, MainUI, register listeners
3. **Run** → CoreEngine captures traffic via IHttpListener
4. **Analyze** → URL scoring, parameter extraction
5. **Display** → UI tabs updated via SwingUtilities.invokeLater()
6. **Export** → User clicks export buttons for CSV/Markdown
7. **Unload** → ExecutorService shutdown (auto-handled)

## Version History

| Version | Date | Status |
|---------|------|--------|
| 1.0.0 | January 2026 | Complete, Production Ready |

## Contact & Support

- Check README.md for detailed usage
- Review IMPLEMENTATION_SUMMARY.md for technical details
- Check Burp Suite Output tab for error logs
- All exceptions logged to stderr with stack traces

---

**Extension Name**: BurpXcelerator  
**Version**: 1.0.0  
**Compatibility**: Burp Suite Pro 2021.2+, Java 8+  
**Status**: Production Ready ✅

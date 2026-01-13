# Security Headers Analyzer - Burp Suite Extension
## Production-Ready Implementation

### Overview
A comprehensive Jython-based Burp Suite extension for analyzing HTTP security headers with intelligent URL filtering, policy-driven scoring, and context-aware risk assessment.

### Key Features Implemented

#### 1. **Burp APIs Integration**
- ✅ IBurpExtender - Main extension interface
- ✅ ITab - Custom tab in Burp UI ("Security Headers Analyzer")
- ✅ IHttpListener - HTTP traffic monitoring
- ✅ IContextMenuFactory - Right-click menu integration

#### 2. **Security Headers Analysis**
Detects and analyzes:
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options (Clickjacking protection)
- X-Content-Type-Options (MIME-sniffing protection)
- Referrer-Policy
- Permissions-Policy
- Cache-Control
- Set-Cookie flags (Secure, HttpOnly, SameSite)

#### 3. **URL Relevance Engine**
- Ignores static resources (.css, .js, images, fonts)
- Content-Type based filtering
- HTTP status code validation
- Keyword detection (login, session, admin, token, etc.)
- Cookie presence analysis
- Relevance scoring (0-100) with 40-point threshold
- Debug view for excluded URLs

#### 4. **Intelligent Scoring System**
- **Per-URL Scoring**: Weighted analysis based on header strength
- **Policy-Driven**: Adjusts weights based on application profile
- **Context-Aware**: Multipliers for:
  - Exposure level (Internal/External)
  - Authentication type (SSO/Public/NA)
  - Application profile (SPA, REST API, Traditional Web, Admin Portal)
- **Overall Score**: Weighted average calculation
  - High risk URLs weighted 1.5x
  - Medium risk URLs weighted 1.0x
  - Low risk URLs weighted 0.5x

#### 5. **Risk Classification**
- **Low Risk**: Score ≥ 80
- **Medium Risk**: Score 60-79
- **High Risk**: Score < 60

#### 6. **User Interface**
**Controls Panel:**
- Application profile dropdown (SPA, REST API, Traditional Web, Admin Portal)
- Exposure selector (Internal/External)
- Authentication type selector (SSO, Public, NA)
- Auto-detect meaningful URLs checkbox
- Show excluded URLs (debug) checkbox
- Evaluate, Export, Clear buttons

**Summary Panel:**
- Overall application score (0-100)
- Overall risk level with color coding
- Real-time updates after evaluation

**Results Table:**
- URL column
- Individual header status columns (S=Strong, M=Medium, W=Weak, P=Present, X=Missing)
- Per-URL score
- Per-URL risk classification
- Right-click context menu (Copy URL, Copy as JSON)

#### 7. **Export Functionality**
**CSV Export:**
- Overall score and risk summary
- Per-header analysis for each URL
- All results in tabular format

**JSON Export:**
- Metadata (generation time, exposure, auth, profile)
- Application summary (overall score/risk)
- Detailed per-URL results with header breakdown

#### 8. **Code Architecture**
- **SecurityHeaderAnalyzer**: Header detection and strength analysis
- **ScoringEngine**: Score calculation with policy support
- **ResultsTableModel**: Data model for results table
- **TableMouseListener**: Right-click menu handling
- **ExportUtilities**: CSV/JSON export functionality
- **BurpExtender**: Main extension class

### File Details
- **Location**: security-header-scan/BurpExtender.py
- **Language**: Jython (Python 2.7 compatible)
- **Size**: ~520 lines
- **Production Ready**: Full error handling, logging, and optimization

### How to Load in Burp Suite
1. Open Burp Suite
2. Go to Extender → Extensions → Add
3. Select "Python" as extension type
4. Browse to BurpExtender.py
5. Click "Next" and allow the extension to load

### Workflow
1. Browse target application to populate HTTP history
2. Configure application context (Profile, Exposure, Auth)
3. Click "Evaluate" to analyze captured URLs
4. Review results in the table and summary panel
5. Right-click results for context menu options
6. Export findings to CSV or JSON

### API Compliance
✅ All mandatory Burp APIs implemented
✅ Single-file architecture as requested
✅ Modular, well-commented functions
✅ Full error handling
✅ Production-ready code quality

### Additional Notes
- Automatic filtering reduces noise by excluding static resources
- Policy-driven scoring adapts to your application's characteristics
- Color-coded risk indicators (Green=Low, Orange=Medium, Red=High)
- Extensible design allows easy addition of new headers or profiles

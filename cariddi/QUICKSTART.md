# Cariddi Extension - Quick Start Guide

## 🚀 Build & Installation - 30 Seconds

### 1. **Already Built!**
The extension is pre-compiled and ready to use:
```
📁 Location: c:\Users\navee\OneDrive\Documents\New-projects\cariddi\cariddi.jar
📦 Size: ~30KB
✅ Status: Ready for Burp Suite
```

### 2. **Load into Burp Suite**
1. Open **Burp Suite Professional/Community**
2. Navigate to: **Extender** → **Extensions** → **Add**
3. Choose:
   - **Extension type**: Java
   - **Extension file**: `cariddi.jar`
4. Click **Next** and **Close**
5. A new **Cariddi** tab should appear

### 3. **Verify Installation**
Check the **Output console** (Extender → Output) for:
```
[*] Cariddi extension loaded successfully!
```

## 🎯 Quick Scan - 2 Minutes

### Step 1: Input URLs
1. Click the **Cariddi** tab
2. Go to **Scanner** sub-tab
3. Paste URLs:
   ```
   https://example.com
   https://api.example.com
   ```

### Step 2: Start Scan
1. Click **Start Scan**
2. Watch the progress bar
3. Results appear in real-time

### Step 3: View Results
1. Click **Results** tab
2. Findings are color-coded:
   - 🔴 **Red**: Secrets (high priority!)
   - 🔵 **Blue**: Endpoints
   - 🟡 **Yellow**: Errors
   - 🟢 **Green**: Info

### Step 4: Export
1. Select rows (or all)
2. Click **Export as JSON/CSV/XML/TXT**
3. Save file

## ⚙️ Configuration Tips

### For Public Targets
```
Concurrency: 50-100
Timeout: 10s
Max Depth: 3
Hunt: Endpoints + Secrets (ON)
```

### For Private APIs (with auth)
```
Concurrency: 20-30
Timeout: 15-20s
Max Depth: 3
Custom Headers: Cookie: session=...
```

### For Maximum Coverage
```
Concurrency: 100
Timeout: 10s
Max Depth: 5-10
Intensive Mode: ON
Hunt Everything: ON
```

## 📊 Understanding Results

| Type | Example | Action |
|------|---------|--------|
| Endpoint | `/api/users` | Test for vulnerabilities |
| Secret | `aws_access_key_id=...` | Immediate security issue! |
| Error | `SQLException: ...` | Database info leaked |
| Info | `admin@company.com` | OSINT data |

## 🔧 Source Files Structure

```
cariddi/
├── CariddiExtender.java      (Main extension class)
├── CariddiUI.java            (Main UI container)
├── CariddiScanner.java       (Scanning engine)
├── CariddiScanTab.java       (Scanner tab UI)
├── CariddiHelpTab.java       (Help documentation)
├── CariddiExporter.java      (Export functionality)
├── MANIFEST.MF               (JAR manifest)
├── README.md                 (Full documentation)
├── cariddi.jar               (⭐ FINAL DELIVERABLE)
└── burpsuite_community_api.jar (Burp API dependency)
```

## ✨ Key Features

✅ **Endpoint Discovery** - Finds hidden APIs  
✅ **Secrets Detection** - AWS keys, JWT tokens, API keys  
✅ **Error Hunting** - Stack traces, DB errors  
✅ **Info Gathering** - Emails, IPs, metadata  
✅ **Multi-format Export** - JSON, CSV, XML, TXT  
✅ **Advanced UI** - Resizable grids, real-time updates  
✅ **Help Documentation** - Built-in guides & examples  

## 🎓 Learn More

- **Help Tab**: Built-in comprehensive guide
- **README.md**: Full documentation
- **Test Cases**: Example scenarios in Help tab
- **Original Tool**: https://github.com/edoardottt/cariddi

## 💡 Pro Tips

1. **Start Conservative** - Use default settings first
2. **Add Auth Headers** - For private APIs
3. **Increase Timeout** - For slow servers
4. **Multiple Runs** - Different settings = better coverage
5. **Combine Tools** - Use with Burp Scanner for complete testing
6. **Check Scope** - Ensure you have permission to scan

## ⚠️ Important

- ✅ **Authorized Testing Only**: Get permission before scanning
- ✅ **Handle Results Carefully**: May contain sensitive data
- ✅ **Respect Rate Limits**: Don't overload servers
- ✅ **Review False Positives**: Not all findings = vulnerabilities

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| No results found | Increase timeout, check target reachability |
| Slow scanning | Reduce concurrency, reduce depth |
| Extension won't load | Check Java version, verify cariddi.jar exists |
| Too many false positives | Review results carefully, adjust settings |

## 📋 File Breakdown

### **cariddi.jar** (THE DELIVERABLE)
- 30KB compiled JAR
- Contains all 13 compiled classes
- Ready to load into Burp Suite
- Includes manifest with all metadata

### **Source Files** (for reference)
- 6 main Java classes (~1500 lines of code)
- 2 supporting classes
- 1 interface
- Full feature-complete implementation

## 🚀 What You Can Do Now

✅ Discover hidden API endpoints  
✅ Find exposed AWS keys, JWT tokens, credentials  
✅ Locate configuration files and backups  
✅ Identify error disclosures  
✅ Extract information for OSINT  
✅ Export results for reports  
✅ Automate reconnaissance phase  

## 📞 Support

For detailed help:
1. Open Cariddi tab
2. Click **Help** sub-tab
3. Read:
   - **Overview**: What is Cariddi?
   - **Features**: Detailed feature list
   - **Usage Guide**: Step-by-step instructions
   - **Test Cases**: Real-world examples
   - **Settings**: Configuration reference

---

**Version:** 1.0.0  
**Status:** ✅ Production Ready  
**Deliverable:** `cariddi.jar` (30KB)  
**Location:** `c:\Users\navee\OneDrive\Documents\New-projects\cariddi\`

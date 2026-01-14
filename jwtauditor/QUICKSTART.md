# JWT Auditor - Quick Start Guide

## 📋 Prerequisites

- **Java JDK 8+** installed (`java -version` to verify)
- **Burp Suite Pro** with Extender support
- All 11 Java files in the `jwtauditor` folder

## 🚀 Compile in 3 Easy Steps

### Option 1: Using Windows Command Prompt (Fastest)

```batch
cd c:\Users\navee\OneDrive\Documents\New-projects\jwtauditor
javac *.java
jar cf JWTAuditor.jar *.class
```

**Done!** Your extension is ready: `JWTAuditor.jar`

### Option 2: Using PowerShell

```powershell
cd "c:\Users\navee\OneDrive\Documents\New-projects\jwtauditor"
javac *.java
jar cf JWTAuditor.jar *.class
```

### Option 3: Using VS Code Integrated Terminal

1. Open VS Code
2. Terminal → New Terminal
3. Paste the commands above
4. Press Enter

---

## 📦 Load into Burp Suite (5 Steps)

### Step 1: Open Burp Suite Pro
Launch Burp Suite and go to **Extender** tab

### Step 2: Add Extension
Click **Extensions** → **Add** → **Select File**

### Step 3: Navigate to JAR
```
c:\Users\navee\OneDrive\Documents\New-projects\jwtauditor\JWTAuditor.jar
```

### Step 4: Confirm Load
- Output shows: "JWT Auditor extension loaded successfully"
- New **JWT Auditor** tab appears in main window

### Step 5: Test It
- Paste a JWT token in the **Decoder** tab
- Click **Decode**
- See token parsed!

---

## 🧪 Test Your Installation

### Step 1: Get a Test JWT
Paste this sample JWT in the Decoder tab:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

### Step 2: Decode It
1. Click **Decode** button
2. See header, payload, signature extracted
3. Review token info

### Step 3: Analyze It
1. Go to **Analyzer** tab
2. Click **Analyze Current Token**
3. See security findings

### Step 4: Try an Attack
1. Go to **Attacks** tab
2. Click **None Algorithm Bypass**
3. See modified token generated

---

## 🔧 Troubleshooting

### Issue: "Cannot find javac"
**Solution**: Install Java JDK (not JRE)
```
java -version   # Verify installation
javac -version  # Should work now
```

### Issue: "JWTAuditor.jar not found after compilation"
**Solution**: Make sure you're in the right folder
```
cd c:\Users\navee\OneDrive\Documents\New-projects\jwtauditor
dir *.java      # Should show 11 files
javac *.java    # Compile
dir *.class     # Should show 11+ class files
```

### Issue: Burp Extension fails to load
**Solution**: Check output console
- Verify Java version (8+)
- Check file path is correct
- Restart Burp Suite

### Issue: "Unsupported major.minor version"
**Solution**: Your Java version is too old
```
# Update to Java 11+
java -version
# Should show version 11 or higher
```

---

## 📂 File Organization

```
jwtauditor/
├── JWTAuditorExtender.java        ← Main entry point
├── JWTAuditorUI.java
├── JWTEditorTab.java
├── JWTEditorTabFactory.java
├── JWTContextMenuFactory.java
├── JWTUtils.java
├── JWTHeader.java
├── JWTToken.java
├── SecurityAnalyzer.java
├── SecretBruteforcer.java
├── AdvancedAttackPlatform.java
├── *.class                        ← Generated after compile
├── JWTAuditor.jar                 ← Load this into Burp
└── Documentation files
```

---

## ✅ Success Checklist

After loading into Burp:
- [ ] Burp shows "JWT Auditor" tab in main window
- [ ] Output console shows load message
- [ ] Can paste JWT in Decoder tab
- [ ] Decode button works
- [ ] Can run security analysis
- [ ] Can generate attacks
- [ ] Can run bruteforcer

---

## 🎯 Next Steps After Loading

1. **Test with Real Tokens**
   - Proxy intercept a request with JWT
   - Right-click → "Send to JWT Auditor"
   - Analyze immediately

2. **Run Security Analysis**
   - Each finding shows severity
   - Detailed explanation provided
   - Actionable recommendations

3. **Generate Test Payloads**
   - Try different attack modules
   - Test against your application
   - Document vulnerabilities

4. **Brute Force Secrets**
   - Start with 100+ default secrets
   - Add custom wordlist if needed
   - Document cracked secrets

---

## 💡 Tips & Tricks

### Tip 1: Keep Extension Loaded
Once loaded, it stays in Burp even after restart.

### Tip 2: Monitor Output Console
Burp Extender → Output shows debug info and errors.

### Tip 3: Use Context Menu
Right-click any text with JWT → "Send to JWT Auditor"

### Tip 4: Copy & Test
Copy generated attacks to clipboard, paste into Repeater tab.

### Tip 5: Export Findings
Document findings in Burp's Reports feature.

---

## 📞 Quick Commands Reference

### Compile Extension
```bash
cd jwtauditor
javac *.java
jar cf JWTAuditor.jar *.class
```

### Verify JARs Built
```bash
dir *.jar        # Should show JWTAuditor.jar
```

### Clean Up (Remove compiled files)
```bash
del *.class
del JWTAuditor.jar
```

### View Extension Source
```bash
dir *.java       # List all source files
type JWTAuditorExtender.java  # View file
```

---

## 🚀 You're Ready!

Everything is set up for production use. Follow these 3 steps:

1. **Compile**: Run `javac *.java && jar cf JWTAuditor.jar *.class`
2. **Load**: Add JWTAuditor.jar to Burp Extender
3. **Test**: Paste JWT token and analyze

**Happy hunting! 🎯**

For detailed feature documentation, see **README.md** and **FEATURES.md**.

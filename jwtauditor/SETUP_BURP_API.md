# Setting Up Burp Suite API for Compilation

## Problem
The extension requires the Burp Suite API (`burpsuite.jar`) to compile. Without it, you'll see "cannot find symbol" errors for classes like `IBurpExtender`, `ITab`, etc.

## Solution: Get the Burp Suite JAR

### Option 1: Burp Suite Community Edition (Free) ⭐ RECOMMENDED

1. **Download**
   - Visit: https://portswigger.net/burp/communitydownload
   - Download `burpsuite_community_*.jar`

2. **Place in lib folder**
   ```batch
   cd c:\Users\navee\OneDrive\Documents\New-projects\jwtauditor
   mkdir lib
   # Copy downloaded JAR to lib\ folder as burpsuite.jar
   ```

3. **Verify**
   ```batch
   dir lib\burpsuite.jar
   # Should show file exists
   ```

### Option 2: Burp Suite Pro (Professional)

If you have Burp Suite Pro installed:

1. **Locate Installation**
   - Usually at: `C:\Program Files\BurpSuitePro\`
   - Look for: `burpsuite_pro.jar` or similar

2. **Copy to lib folder**
   ```batch
   copy "C:\Program Files\BurpSuitePro\burpsuite_pro.jar" ^
        "c:\Users\navee\OneDrive\Documents\New-projects\jwtauditor\lib\burpsuite.jar"
   ```

### Option 3: From Burp Installation Directory

If you have Burp Suite installed:

1. **Locate JAR file**
   - Go to Burp Suite installation folder
   - Find the main JAR file (varies by version)
   - Common names:
     - `burpsuite_pro.jar`
     - `burpsuite_community.jar`
     - `burpsuite_*.jar`

2. **Copy to lib folder**
   ```batch
   copy "C:\Program Files\Burp Suite Pro\burpsuite_pro.jar" ^
        "c:\Users\navee\OneDrive\Documents\New-projects\jwtauditor\lib\burpsuite.jar"
   ```

---

## Step-by-Step Setup

### Step 1: Create lib Directory
```batch
cd c:\Users\navee\OneDrive\Documents\New-projects\jwtauditor
mkdir lib
```

### Step 2: Obtain Burp JAR
Choose one method above to get `burpsuite.jar` or similar named file.

### Step 3: Copy to lib Folder
```batch
# Example (adjust path to your actual JAR location):
copy "C:\Downloads\burpsuite_community_2025.1.1.jar" lib\burpsuite.jar
```

### Step 4: Verify File Exists
```batch
dir lib\burpsuite.jar
# Should output file info, not "file not found"
```

### Step 5: Try Compilation
```batch
cd c:\Users\navee\OneDrive\Documents\New-projects\jwtauditor
javac -cp lib\burpsuite.jar *.java
```

If successful: `0 errors`

---

## Quick Verification Checklist

✓ Check Java installed:
```batch
java -version
javac -version
```

✓ Check Burp JAR location:
```batch
dir lib\burpsuite.jar
```

✓ Test compilation command:
```batch
javac -cp lib\burpsuite.jar *.java
```

✓ Check for .class files:
```batch
dir *.class
# Should show 11+ files
```

---

## Automated Compilation Script

We've provided `compile.bat` which:
1. Checks for Java installation
2. Looks for Burp Suite in common locations
3. Attempts automatic detection
4. Shows helpful error messages
5. Creates JAR file if successful

**Usage:**
```batch
cd c:\Users\navee\OneDrive\Documents\New-projects\jwtauditor
compile.bat
```

---

## Common Issues & Solutions

### Issue: "Cannot find javac"
```
Error: 'javac' is not recognized as an internal or external command
```

**Solution:**
- Install Java JDK (not JRE)
- Add Java to system PATH
- Verify with: `javac -version`

### Issue: "Cannot find symbol: class IBurpExtender"
```
JWTAuditorExtender.java:18: error: cannot find symbol
```

**Solution:**
- Burp JAR not in classpath
- Run: `javac -cp lib\burpsuite.jar *.java`
- Verify JAR file exists: `dir lib\burpsuite.jar`

### Issue: "Unsupported major.minor version"
```
UnsupportedClassVersionError
```

**Solution:**
- Java version mismatch
- Update Java to 8+
- Check: `java -version`

### Issue: JAR file in lib\ but still not found
```
Cannot find symbol
```

**Solution:**
- Ensure JAR name is exactly `burpsuite.jar` (case matters)
- Try explicit path:
  ```batch
  javac -cp lib\burpsuite.jar;. *.java
  ```

---

## Compiling Manually (Without Script)

If `compile.bat` doesn't work, try manually:

```batch
@REM 1. Navigate to jwtauditor folder
cd c:\Users\navee\OneDrive\Documents\New-projects\jwtauditor

@REM 2. Compile with Burp API
javac -cp lib\burpsuite.jar *.java

@REM 3. Create JAR (if compilation succeeded)
jar cf JWTAuditor.jar *.class

@REM 4. Verify JAR created
dir JWTAuditor.jar
```

---

## Testing Compilation Success

After compilation, you should see:

✓ No error messages
✓ Command prompt returns without error
✓ Multiple `.class` files created:
```
JWTAuditorExtender.class
JWTAuditorUI.class
JWTEditorTab.class
... (11 total)
```

✓ `JWTAuditor.jar` file created

---

## Next Steps After Successful Compilation

1. **Load into Burp Suite**
   ```
   Extender → Extensions → Add → Select JWTAuditor.jar
   ```

2. **Verify Loading**
   - Look for "JWT Auditor" tab in main window
   - Check Extender → Output tab for messages

3. **Test the Extension**
   - Paste JWT in Decoder tab
   - Click Decode
   - Verify it parses correctly

---

## Download Links

- **Burp Suite Community** (Free):
  https://portswigger.net/burp/communitydownload

- **Burp Suite Professional** (30-day trial):
  https://portswigger.net/burp/pro

- **PortSwigger Docs**:
  https://portswigger.net/burp/extender

---

## Still Having Issues?

1. Check that you're in the right directory:
   ```batch
   cd c:\Users\navee\OneDrive\Documents\New-projects\jwtauditor
   dir *.java
   # Should show 11 files
   ```

2. Verify Java installation:
   ```batch
   javac -version
   # Should show version (8+)
   ```

3. Confirm Burp JAR location:
   ```batch
   dir lib\burpsuite.jar
   # Should show file
   ```

4. Try compilation with verbose output:
   ```batch
   javac -cp lib\burpsuite.jar -d . *.java
   ```

---

**Once you have the Burp Suite JAR in place, compilation becomes a one-line command and takes ~5 seconds!**

---

*Last Updated: January 2026*

# Build Instructions

## Prerequisites

- Java Development Kit (JDK) 8 or higher
- Burp Suite Pro (with extension capability)

## Compilation Steps

### 1. Compile All Java Files

```bash
# Windows
javac JWTAuditorExtender.java
javac JWTUtils.java
javac JWTHeader.java
javac JWTToken.java
javac SecurityAnalyzer.java
javac SecretBruteforcer.java
javac AdvancedAttackPlatform.java
javac JWTAuditorUI.java
javac JWTEditorTab.java
javac JWTEditorTabFactory.java
javac JWTContextMenuFactory.java
```

### 2. Create JAR File

```bash
jar cf JWTAuditor.jar *.class
```

### 3. Load into Burp Suite

1. Open Burp Suite
2. Go to **Extender** → **Extensions**
3. Click **Add**
4. Select **Extension type**: Java
5. Choose the compiled `JWTAuditor.jar` file
6. Click **Next**
7. Wait for compilation and loading

### 4. Verify Installation

Check the **Output** tab in Extender window. You should see:
```
[JWT Auditor] Extension loaded successfully
[JWT Auditor] Features: Decoder, Analyzer, Bruteforcer, Attack Platform, Editor
```

A new **JWT Auditor** tab will appear in the main Burp window.

## Automated Build Script

### Windows (build.bat)

```batch
@echo off
echo Compiling JWT Auditor Extension...

REM Compile all Java files
javac JWTAuditorExtender.java JWTUtils.java JWTHeader.java JWTToken.java ^
       SecurityAnalyzer.java SecretBruteforcer.java AdvancedAttackPlatform.java ^
       JWTAuditorUI.java JWTEditorTab.java JWTEditorTabFactory.java JWTContextMenuFactory.java

if %ERRORLEVEL% NEQ 0 (
    echo Compilation failed!
    exit /b 1
)

echo Creating JAR file...
jar cf JWTAuditor.jar *.class

echo Build successful! JWTAuditor.jar is ready.
echo Load this JAR file into Burp Suite via Extender → Extensions → Add
```

### Linux/macOS (build.sh)

```bash
#!/bin/bash

echo "Compiling JWT Auditor Extension..."

javac JWTAuditorExtender.java JWTUtils.java JWTHeader.java JWTToken.java \
      SecurityAnalyzer.java SecretBruteforcer.java AdvancedAttackPlatform.java \
      JWTAuditorUI.java JWTEditorTab.java JWTEditorTabFactory.java JWTContextMenuFactory.java

if [ $? -ne 0 ]; then
    echo "Compilation failed!"
    exit 1
fi

echo "Creating JAR file..."
jar cf JWTAuditor.jar *.class

echo "Build successful! JWTAuditor.jar is ready."
echo "Load this JAR file into Burp Suite via Extender → Extensions → Add"
```

Make executable:
```bash
chmod +x build.sh
./build.sh
```

## Package Organization

For production, organize files in proper package structure:

```
src/
├── burp/
│   └── jwt/
│       ├── JWTAuditorExtender.java
│       ├── JWTAuditorUI.java
│       ├── JWTEditorTab.java
│       ├── JWTEditorTabFactory.java
│       ├── JWTContextMenuFactory.java
│       ├── core/
│       │   ├── JWTUtils.java
│       │   ├── JWTHeader.java
│       │   └── JWTToken.java
│       ├── analyzer/
│       │   └── SecurityAnalyzer.java
│       ├── bruteforce/
│       │   └── SecretBruteforcer.java
│       └── attacks/
│           └── AdvancedAttackPlatform.java
```

### Compile with Package Structure

```bash
javac src/burp/jwt/*.java
javac src/burp/jwt/*/*.java
jar cf JWTAuditor.jar -C src .
```

## Troubleshooting Compilation

### Error: "cannot find symbol"
- Check all imports are correct
- Verify file names match class names
- Ensure you're in the correct directory

### Error: "incompatible types"
- Check Java version (use Java 8+ compatible syntax)
- Verify all generics are properly specified
- Check type conversions

### JAR not loading in Burp
- Verify it's a proper JAR file: `jar tf JWTAuditor.jar`
- Check file is not corrupted
- Ensure Burp has read permissions
- Check Burp console for error messages

## IDE Configuration

### IntelliJ IDEA

1. Create New Project
2. File → Project Structure → Libraries
3. Add Burp Suite JAR (burpsuite_pro.jar)
4. Set Output directory for compilation
5. Build → Build Project

### Eclipse

1. New Java Project
2. Project → Properties → Java Build Path
3. Add External JAR (burpsuite_pro.jar)
4. Project → Build All

### Visual Studio Code

Create `.vscode/settings.json`:
```json
{
    "java.project.sourcePath": ".",
    "java.project.outputPath": ".",
    "java.project.referencedLibraries": [
        "${workspaceFolder}/burpsuite_pro.jar"
    ]
}
```

## Testing the Extension

1. Start Burp Suite
2. Go to Burp → Extender → Extensions
3. Load JWTAuditor.jar
4. Test with sample JWT:
   ```
   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
   ```
5. Paste in Decoder tab
6. Click "Decode"
7. See header and payload displayed

## Release Package

Create distribution:

```bash
# Compile
javac *.java

# Create JAR
jar cf JWTAuditor.jar *.class

# Create release package
mkdir JWTAuditor-1.0
cp JWTAuditor.jar JWTAuditor-1.0/
cp README.md JWTAuditor-1.0/
cp BUILD.md JWTAuditor-1.0/

# Zip for distribution
zip -r JWTAuditor-1.0.zip JWTAuditor-1.0/
```

## Version History

### Version 1.0
- Initial release
- 7 attack modules
- 15+ security checks
- 1000+ wordlist bruteforcer
- Full JWT analysis capabilities

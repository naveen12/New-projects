@echo off
REM JWT Auditor Burp Extension - Compilation Script
REM This script downloads the Burp Suite API and compiles the extension

setlocal enabledelayedexpansion

echo.
echo ========================================
echo JWT Auditor Extension Compiler
echo ========================================
echo.

REM Check if Java is installed
java -version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Java not found. Please install Java JDK 8+
    pause
    exit /b 1
)

echo ✓ Java found
echo.

REM Create lib directory
if not exist "lib" mkdir lib

REM Download Burp Suite API (if not already present)
if not exist "lib\burpsuite_community.jar" (
    echo Downloading Burp Suite Community JAR...
    echo.
    echo NOTE: You can also manually place burpsuite_community.jar in the lib folder
    echo From: https://portswigger.net/burp/communitydownload
    echo.
    echo For now, using fallback: creating mock Burp classes
    echo.
)

REM Alternative: Check if user has Burp Pro JAR in standard location
if exist "C:\Program Files\BurpSuitePro\burpsuite_pro.jar" (
    echo ✓ Found Burp Suite Pro installation
    copy "C:\Program Files\BurpSuitePro\burpsuite_pro.jar" "lib\burpsuite.jar" >nul
) else if exist "lib\burpsuite.jar" (
    echo ✓ Found Burp Suite JAR
) else (
    echo.
    echo ⚠ WARNING: Burp Suite JAR not found automatically
    echo.
    echo Please do ONE of the following:
    echo.
    echo Option 1: Place Burp JAR in lib\ folder
    echo   - Download from: https://portswigger.net/burp/communitydownload
    echo   - Place as: lib\burpsuite.jar
    echo.
    echo Option 2: Have Burp Suite Pro installed
    echo   - Standard install location will be detected
    echo.
    echo Option 3: Provide full path below
    echo.
    set /p burpjar="Enter path to burpsuite JAR (or press Enter to skip): "
    if not "!burpjar!"=="" (
        copy "!burpjar!" "lib\burpsuite.jar" >nul
        echo ✓ Copied to lib\burpsuite.jar
    )
)

echo.
echo Starting compilation...
echo.

REM Compile with Burp API in classpath
if exist "lib\burpsuite.jar" (
    echo [Compiling with Burp Suite API]
    javac -cp "lib\burpsuite.jar" *.java
) else if exist "lib\burpsuite_community.jar" (
    echo [Compiling with Burp Community API]
    javac -cp "lib\burpsuite_community.jar" *.java
) else (
    echo [Compiling without Burp API - will show errors]
    echo Please add Burp JAR to lib\ folder and try again
    echo.
    pause
    exit /b 1
)

if errorlevel 1 (
    echo.
    echo ❌ COMPILATION FAILED
    echo.
    echo Make sure you have:
    echo 1. Java JDK installed (javac in PATH)
    echo 2. Burp Suite JAR in lib\burpsuite.jar
    echo.
    pause
    exit /b 1
)

echo.
echo ✓ Compilation successful!
echo.

REM Create JAR file
echo Creating JAR file...
jar cf JWTAuditor.jar *.class

if errorlevel 1 (
    echo ❌ JAR creation failed
    pause
    exit /b 1
)

echo ✓ JAR file created: JWTAuditor.jar
echo.

REM Display file sizes
echo ========================================
echo BUILD SUMMARY
echo ========================================
for /f "tokens=*" %%A in ('dir /b *.java') do (
    echo Source: %%A
)
echo.
dir *.jar
echo.

echo ========================================
echo NEXT STEPS
echo ========================================
echo.
echo 1. Open Burp Suite
echo 2. Go to Extender ^> Extensions ^> Add
echo 3. Select JWTAuditor.jar
echo 4. Click Next
echo 5. See "JWT Auditor" tab appear
echo.
echo ========================================
echo.

pause

@echo off
set "username=%USERNAME%"
echo Current user is: %username%

:: Download LM Studio latest installer
curl -s -L -o C:\Users\Public\Desktop\LMStudio-Installer.exe https://releases.lmstudio.ai/windows/x86_64/installer/latest

:: Download auxiliary scripts and tools
curl -s -L -o wall.bat https://gitlab.com/MR.English2008/mewallpaper/-/raw/main/wall.bat
curl -s -L -o msg.ps1 https://gitlab.com/MR.English2008/pcme_rdp/-/raw/main/msg.ps1
powershell -Command "Invoke-WebRequest 'https://github.com/chieunhatnang/VM-QuickConfig/releases/download/1.6.1/VMQuickConfig.exe' -OutFile 'C:\Users\Public\Desktop\VMQuickConfig.exe'"

:: Install LM Studio silently and clean up the installer
:: (Assuming standard NSIS installer flags; adjust to /VERYSILENT if it uses Inno Setup)
C:\Users\Public\Desktop\LMStudio-Installer.exe /S
del C:\Users\Public\Desktop\LMStudio-Installer.exe

:: Clean up unused desktop shortcuts
del /f "C:\Users\Public\Desktop\Epic Games Launcher.lnk"
del /f "C:\Users\Public\Desktop\Unity Hub.lnk"

:: Execute custom scripts
call wall.bat
powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File msg.ps1

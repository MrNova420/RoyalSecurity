@echo off
setlocal
echo ============================================
echo  RoyalSecurity Installer Builder
echo ============================================
echo.

REM Check for Inno Setup compiler
where ISCC.exe >nul 2>&1
if %errorlevel% equ 0 (
    set "ISCC_PATH=ISCC.exe"
    goto :found_iscc
)

REM Check common install locations
if exist "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" (
    set "ISCC_PATH=C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
    goto :found_iscc
)
if exist "C:\Program Files\Inno Setup 6\ISCC.exe" (
    set "ISCC_PATH=C:\Program Files\Inno Setup 6\ISCC.exe"
    goto :found_iscc
)
if exist "C:\Program Files (x86)\Inno Setup 5\ISCC.exe" (
    set "ISCC_PATH=C:\Program Files (x86)\Inno Setup 5\ISCC.exe"
    goto :found_iscc
)

echo ERROR: Inno Setup compiler (ISCC.exe) not found!
echo Please install Inno Setup 6 from https://jrsoftware.org/isinfo.php
exit /b 1

:found_iscc
echo Found Inno Setup: %ISCC_PATH%
echo.

REM Build release binary
echo [1/2] Building release binary...
cd /d "%~dp0.."
cargo build --release -p royalsecurity
if %errorlevel% neq 0 (
    echo ERROR: Build failed!
    exit /b 1
)
echo Build successful!
echo.

REM Build installer
echo [2/2] Building installer...
"%ISCC_PATH%" "%~dp0royalsecurity.iss"
if %errorlevel% neq 0 (
    echo ERROR: Installer build failed!
    exit /b 1
)
echo.
echo ============================================
echo  Installer built successfully!
echo  Output: %~dp0output\
echo ============================================
endlocal

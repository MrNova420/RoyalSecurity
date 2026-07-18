@echo off
echo Building RoyalSecurity Release...
cd /d "%~dp0.."
cargo build --release -p royalsecurity
if %errorlevel% neq 0 (
    echo Build failed!
    exit /b 1
)
echo Building frontend...
cd royalsecurity-ui
npm run build
cd ..
echo Packaging installer...
"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" "installer\royalsecurity.iss"
echo Done!

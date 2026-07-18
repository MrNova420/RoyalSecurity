@echo off
title RoyalSecurity
echo ===================================
echo   RoyalSecurity Agent v0.1.0
echo   Military-Grade Security Platform
echo ===================================
echo.
echo Starting RoyalSecurity...
echo.
cd /d "%~dp0"
start "" "target\release\royalsecurity.exe"

@echo off
echo Building EDR Test Tool
echo =====================

REM Check if CSC is available
where csc >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Error: C# compiler (csc) not found.
    echo Please ensure .NET SDK is installed and in your PATH.
    exit /b 1
)

echo Compiling ContextInjection_EDR_Test.cs...
csc /unsafe /out:ContextInjection_EDR_Test.exe ContextInjection_EDR_Test.cs

if %ERRORLEVEL% NEQ 0 (
    echo Error: Build failed.
    exit /b %ERRORLEVEL%
)

echo Build successful!
echo.
echo IMPORTANT: This tool is for EDR testing purposes only.
echo Run with administrator privileges to test EDR detection capabilities.
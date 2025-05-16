@echo off
echo Building Context-Only Attack Surface Techniques (Go version)...
echo ===========================================================
echo This will compile the Go implementation for EDR detection testing.

REM Check for Go compiler
WHERE go.exe >nul 2>nul
IF %ERRORLEVEL% NEQ 0 (
    echo ERROR: Go compiler not found.
    echo Please install Go from https://golang.org/dl/
    goto :exit
)

REM Build the Go program
echo Building context_techniques.go...
go build -o ContextTechniques.exe context_techniques.go

IF %ERRORLEVEL% NEQ 0 (
    echo ERROR: Build failed.
    goto :exit
)

echo.
echo Build successful.
echo.
echo IMPORTANT NOTICE:
echo =================
echo This tool is intended for security research and EDR testing ONLY.
echo Use this tool only on systems you own or have explicit permission to test.
echo This tool helps EDR teams understand and improve detection capabilities.
echo.
echo Run with: ContextTechniques.exe
echo Or for specific techniques:
echo - ContextTechniques.exe -technique 1  (Pointer-Only LoadLibrary)
echo - ContextTechniques.exe -technique 2  (Advanced ThreadContext)

:exit
echo.
pause
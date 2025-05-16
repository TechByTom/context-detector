@echo off
echo Compiling Context-Only Attack Surface Techniques...
echo ==================================================
echo This will compile the test utility for EDR detection testing.

REM Check for Visual Studio compiler
WHERE cl.exe >nul 2>nul
IF %ERRORLEVEL% NEQ 0 (
    echo ERROR: Microsoft Visual C++ compiler not found.
    echo Please run this from a Visual Studio Developer Command Prompt.
    echo For example: "x64 Native Tools Command Prompt for VS 2019"
    goto :exit
)

REM Compile the application
echo Compiling ContextOnlyTechniques.cpp...
cl.exe /EHsc /W4 /Fe:ContextOnlyTechniques.exe ContextOnlyTechniques.cpp /link advapi32.lib

IF %ERRORLEVEL% NEQ 0 (
    echo ERROR: Compilation failed.
    goto :exit
)

echo.
echo Compilation successful.
echo.
echo IMPORTANT NOTICE:
echo =================
echo This tool is intended for security research and EDR testing ONLY.
echo Use this tool only on systems you own or have explicit permission to test.
echo This tool helps EDR teams understand and improve detection capabilities.

:exit
echo.
pause
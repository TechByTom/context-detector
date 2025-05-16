#!/bin/bash
# Script to build all implementations using Windows executables from WSL
# Run this script from Windows CMD or PowerShell with: bash build_all.sh

echo "Building Context-Only Attack Surface Detection tools..."
echo "======================================================"
echo

cd "$(dirname "$0")"
WIN_PATH=$(wslpath -w "$(pwd)")

echo "Building Go implementation..."
if command -v go.exe &> /dev/null; then
    go.exe build -o ContextTechniques.exe context_techniques.go
    echo "Go build complete."
else
    echo "Go not found. Please install Go for Windows and add it to your PATH."
    echo "Download from: https://golang.org/dl/"
fi

echo
echo "Building C++ implementation..."
if command -v cl.exe &> /dev/null; then
    # Visual Studio compiler
    cl.exe /EHsc /W4 /Fe:ContextOnlyTechniques.exe ContextOnlyTechniques.cpp /link advapi32.lib dbghelp.lib psapi.lib
    echo "C++ build complete."
else
    echo "Microsoft Visual C++ compiler not found."
    echo "Please open a Visual Studio Developer Command Prompt and run compile.bat"
fi

echo
echo "Building C# implementation..."
if command -v csc.exe &> /dev/null; then
    # C# compiler
    csc.exe /unsafe /out:ContextInjection_EDR_Test.exe ContextInjection_EDR_Test.cs
    echo "C# build complete."
else
    echo "C# compiler not found."
    echo "Please install .NET SDK and run edr_test_build.bat"
fi

echo
echo "Build process completed."
echo "For any components that couldn't be built automatically,"
echo "please use the provided .bat files in Windows Command Prompt."
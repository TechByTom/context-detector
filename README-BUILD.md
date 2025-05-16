# Building the Context-Only Attack Surface Detection Tools

These tools are designed for Windows systems and require Windows-specific APIs. Here are instructions for building each component:

## Prerequisites

- **Windows Environment**: All tools require Windows to build and run
- **Go**: For the Go implementation (version 1.18+)
- **Visual Studio**: For the C++ implementation (Visual Studio 2019+ recommended)
- **.NET SDK**: For the C# implementation (.NET Framework or .NET Core)

## Build Options

### Option 1: Using batch files (Recommended)

Run each batch file from a Command Prompt or PowerShell window:

1. **Go implementation**:
   ```
   build_go.bat
   ```

2. **C++ implementation**:
   ```
   compile.bat
   ```
   *Note: Run this from a Visual Studio Developer Command Prompt*

3. **C# implementation**:
   ```
   edr_test_build.bat
   ```

### Option 2: Using the combined script

If you have WSL (Windows Subsystem for Linux), you can use the combined script:

```
bash build_all.sh
```

This script attempts to use Windows compilers from WSL to build all implementations.

### Option 3: Manual build commands

#### Go implementation
```
go build -o ContextTechniques.exe context_techniques.go
```

#### C++ implementation
From a Visual Studio Developer Command Prompt:
```
cl.exe /EHsc /W4 /Fe:ContextOnlyTechniques.exe ContextOnlyTechniques.cpp /link advapi32.lib dbghelp.lib psapi.lib
```

#### C# implementation
```
csc.exe /unsafe /out:ContextInjection_EDR_Test.exe ContextInjection_EDR_Test.cs
```

## Running the Tools

All tools require Administrator privileges to access process memory and thread contexts.

1. **Go implementation**:
   ```
   ContextTechniques.exe
   ```

2. **C++ implementation**:
   ```
   ContextOnlyTechniques.exe
   ```

3. **C# implementation**:
   ```
   ContextInjection_EDR_Test.exe
   ```

## Troubleshooting

- **Missing Headers**: Ensure you have the proper SDK installed
- **Link Errors**: Make sure you're using the correct Visual Studio Command Prompt
- **Permission Errors**: Run as Administrator
- **Execution Policy**: You may need to adjust PowerShell execution policy to run batch files
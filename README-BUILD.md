# Building the Context-Only Attack Surface Detection Tools

These tools are designed for Windows systems and require Windows-specific APIs. Here are instructions for building each component:

## Prerequisites

- **Windows Environment**: All tools require Windows to build and run
- **Go**: For the Go implementation (version 1.18+)
- **Visual Studio**: For the C++ implementation (Visual Studio 2019+ recommended)
- **.NET SDK**: For the C# implementation (.NET Framework or .NET Core)

## Build Instructions

### Go implementation
Run from Command Prompt or PowerShell:
```
build_go.bat
```

Or manually:
```
go build -o ContextTechniques.exe context_techniques.go
```

### C++ implementation
Run from a Visual Studio Developer Command Prompt:
```
compile.bat
```

Or manually:
```
cl.exe /EHsc /W4 /Fe:ContextOnlyTechniques.exe ContextOnlyTechniques.cpp /link advapi32.lib dbghelp.lib psapi.lib
```

### C# implementation
Run from Command Prompt or PowerShell:
```
edr_test_build.bat
```

Or manually:
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
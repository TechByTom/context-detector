# Context-Only Attack Surface EDR Testing Utility

This tool implements the specific techniques described in the "[The Context-Only Attack Surface](https://blog.fndsec.net/2025/05/16/the-context-only-attack-surface/)" research to help blue teams test their EDR/XDR detection capabilities.

## Overview

This utility demonstrates two advanced process injection techniques that focus on execution primitives rather than traditional memory allocation patterns:

1. **Pointer-Only LoadLibrary Injection**
   - Uses existing in-memory strings instead of allocating new memory
   - Exploits Windows DLL search order
   - Manipulates thread context to point to existing LoadLibrary functions
   
2. **CreateRemoteThread + SetThreadContext (Advanced)**
   - Thread stack borrowing technique
   - ROP (Return-Oriented Programming) gadget approach
   - Thread initialization process manipulation

## Build Instructions

### Prerequisites
- Visual Studio 2019 or newer with C++ development tools
- Windows SDK
- Admin privileges to run

### Building
1. Open a "Developer Command Prompt for VS" or "x64 Native Tools Command Prompt for VS"
2. Navigate to the directory containing these files
3. Run `compile.bat`

## Usage

Run the compiled executable with Administrator privileges. The tool will:

1. Find or launch a target process (notepad.exe by default)
2. Provide a menu to select which technique to demonstrate
3. Execute the selected technique
4. Display detailed information about what it's doing

```
ContextOnlyTechniques.exe
```

## EDR Testing Methodology

1. **Prepare Environment**
   - Ensure your EDR/XDR solution is properly deployed
   - Configure logging for maximum visibility
   - Create a baseline of normal activity

2. **Run Tests**
   - Execute each technique individually
   - Document alerts/events generated in EDR console
   - Note any techniques that do not trigger alerts

3. **Analyze Results**
   - Review which aspects of each technique are detected
   - Identify detection gaps
   - Determine what telemetry is missing

4. **Improve Detection**
   - Develop custom rules for undetected techniques
   - Focus on the context manipulation patterns
   - Implement stack manipulation detection

## Specific EDR Detection Points

For proper detection of these techniques, your EDR should monitor:

### Pointer-Only LoadLibrary Technique
- Thread context manipulation (especially RIP changes)
- Thread suspension followed by context changes
- LoadLibrary calls without corresponding memory allocations
- Cross-process operations targeting thread contexts

### CreateRemoteThread + SetThreadContext
- Thread creation in suspended state
- Thread context manipulation before resuming
- Stack pointer (RSP) modifications
- Suspicious RIP values pointing to system DLLs
- Patterns indicating ROP chain setup

## Legal Disclaimer

This tool is for **legitimate security research and blue team training only**. Use only on systems you own or have explicit permission to test. This code is designed to facilitate the development of better security controls against advanced attacks.
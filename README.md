# Context-Only Attack Surface Detector

A Go-based security research tool for detecting and analyzing context-only process injection techniques as described in the research article: [The Context-Only Attack Surface](https://blog.fndsec.net/2025/05/16/the-context-only-attack-surface/).

## Overview

This tool is designed for **security research and blue team detection development** to help understand and detect advanced process injection techniques that focus exclusively on execution primitives rather than traditional memory allocation/writing patterns.

The detector monitors:
- Thread context manipulation
- Suspicious DLL loading
- Thread execution redirection

## Security Notice

This tool is intended for **legitimate security research only**. Use only on systems you own or have explicit permission to test. The tool is designed to facilitate detection engineering rather than offensive security purposes.

## Features

- Real-time monitoring of thread contexts for suspicious manipulation
- Detection of DLL loading via non-standard methods
- Thread enumeration and tracking
- Detailed alerting with JSON output
- Configurable monitoring duration

## Requirements

- Go 1.18 or higher
- Windows OS (primary target)
- Requires admin privileges to monitor processes

## Installation

```bash
# Clone the repository
git clone https://github.com/your-org/context-detector.git
cd context-detector

# Build the tool
go build -o detector.exe .
```

## Usage

```bash
# Basic usage
./detector.exe -pid=1234 -duration=5m -output=alerts.json

# Command line options
./detector.exe -h
```

### Command Line Options

- `-pid`: Target process ID to monitor (required)
- `-duration`: Monitoring duration (default: 1m)
- `-output`: Output file for alerts in JSON format (optional)
- `-verbose`: Enable verbose logging (optional)

## Detection Capabilities

### 1. Thread Context Monitoring

Detects suspicious manipulation of thread contexts, including:
- Instruction pointer (RIP) redirection
- Stack pointer (RSP) manipulation
- Register value changes that may indicate function parameter setup

### 2. DLL Loading Monitoring

Identifies unusual DLL loading patterns:
- DLLs loaded from unexpected locations
- Modules loaded without proper initialization
- Unusual LoadLibrary call stacks

### 3. Thread Execution Redirection

Tracks when thread execution is redirected to:
- System DLLs that weren't previously executing
- Memory regions that don't contain executable code
- Known API functions like LoadLibrary

## Output Format

When using the `-output` flag, alerts are written in JSON format:

```json
{
  "type": "SUSPICIOUS_CONTEXT_CHANGE",
  "process_id": 1234,
  "thread_id": 5678,
  "description": "Suspicious RIP change from 0x7FF123456789 to 0x7FF987654321",
  "timestamp": "2025-05-16T14:25:36Z",
  "details": {
    "before_rip": "0x7FF123456789",
    "after_rip": "0x7FF987654321"
  }
}
```

## Example Usage Scenarios

### 1. Monitor a Specific Process

```bash
./detector.exe -pid=1234 -duration=10m -output=process_1234_alerts.json
```

### 2. Use as a Research Tool

The code demonstrates different approaches to detection:

```go
// Create components individually for more control
threadEnum := NewThreadEnumerator(pid)
dllMonitor := NewDLLMonitor(pid)
threadDetector := NewThreadContextDetector(pid)

// Initialize and use specific detectors
threads, _ := threadEnum.EnumerateThreads()
dllMonitor.StartMonitoring()
```

## Building Detection Rules

This tool is designed to help security teams develop and test detection rules for advanced process injection techniques. The JSON output can be used to:

1. Analyze patterns of suspicious behavior
2. Develop SIEM/EDR detection rules
3. Test detection effectiveness against known techniques

## License

This project is licensed for security research purposes only. See LICENSE file for details.

## References

- [The Context-Only Attack Surface](https://blog.fndsec.net/2025/05/16/the-context-only-attack-surface/)
- [Microsoft Windows Internals](https://www.microsoftpressstore.com/store/windows-internals-part-1-system-architecture-processes-9780735684188)
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

// ThreadContext is kept for compatibility
type ThreadContext struct {
	ContextFlags      uint32
	Rax               uintptr
	Rbx               uintptr
	Rcx               uintptr
	Rdx               uintptr
	Rsp               uintptr
	Rbp               uintptr
	Rsi               uintptr
	Rdi               uintptr
	R8                uintptr
	R9                uintptr
	R10               uintptr
	R11               uintptr
	R12               uintptr
	R13               uintptr
	R14               uintptr
	R15               uintptr
	Rip               uintptr
}

func main() {
	fmt.Println("Context-Only Attack Surface Detector")
	fmt.Println("For security research and detection development only")
	fmt.Println("Based on research from: https://blog.fndsec.net/2025/05/16/the-context-only-attack-surface/")
	
	// Parse command line flags
	pidFlag := flag.Int("pid", 0, "Target process ID to monitor")
	durationFlag := flag.String("duration", "1m", "Monitoring duration (e.g. 30s, 5m)")
	outputFlag := flag.String("output", "", "Output file for alerts (JSON format)")
	verboseFlag := flag.Bool("verbose", false, "Enable verbose logging")
	flag.Parse()
	
	// Validate PID
	if *pidFlag == 0 {
		fmt.Println("Usage: ./detector -pid=<target_pid> [-duration=1m] [-output=alerts.json] [-verbose]")
		fmt.Println("\nExample: ./detector -pid=1234 -duration=5m -output=alerts.json")
		os.Exit(1)
	}
	
	targetPID := uint32(*pidFlag)
	
	// Parse duration
	duration, err := time.ParseDuration(*durationFlag)
	if err != nil {
		log.Fatalf("Invalid duration format: %v", err)
	}
	
	// Create detector
	detector := NewContextDetector(targetPID, *outputFlag)
	
	// Enable verbose logging if requested
	if *verboseFlag {
		fmt.Println("Verbose logging enabled")
	}
	
	// Initialize detector
	err = detector.Initialize()
	if err != nil {
		log.Fatalf("Failed to initialize detector: %v", err)
	}
	
	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	
	// Start monitoring in a goroutine
	done := make(chan struct{})
	go func() {
		detector.Monitor(duration)
		close(done)
	}()
	
	// Wait for either completion or interrupt
	select {
	case <-done:
		fmt.Println("Monitoring completed")
	case sig := <-sigChan:
		fmt.Printf("Received signal %v, shutting down...\n", sig)
	}
	
	// Generate final report
	report := detector.GenerateReport()
	fmt.Println(report)
	
	if *outputFlag != "" {
		fmt.Printf("Full alert details written to %s\n", *outputFlag)
	}
}

// Example functions to show how to use the detector
func monitorExistingProcess() {
	// Get PID from user
	fmt.Print("Enter process ID to monitor: ")
	var pidStr string
	fmt.Scanln(&pidStr)
	
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		log.Fatalf("Invalid PID: %v", err)
	}
	
	// Create and initialize detector
	detector := NewContextDetector(uint32(pid), "alerts.json")
	err = detector.Initialize()
	if err != nil {
		log.Fatalf("Failed to initialize detector: %v", err)
	}
	
	// Monitor for 5 minutes
	detector.Monitor(5 * time.Minute)
	
	// Generate report
	report := detector.GenerateReport()
	fmt.Println(report)
}

func monitorWithSpecificChecks() {
	// Example of how to set up targeted monitoring
	pid := uint32(1234) // Replace with actual PID
	
	// Create components individually for more control
	threadEnum := NewThreadEnumerator(pid)
	dllMonitor := NewDLLMonitor(pid)
	threadDetector := NewThreadContextDetector(pid)
	
	// Initialize components
	threads, _ := threadEnum.EnumerateThreads()
	fmt.Printf("Found %d threads in process %d\n", len(threads), pid)
	
	dllMonitor.StartMonitoring()
	threadDetector.StartMonitoring()
	
	// Monitor for specific events
	for i := 0; i < 10; i++ {
		dllMonitor.DetectNewModules()
		threadDetector.DetectContextChanges()
		time.Sleep(1 * time.Second)
	}
}
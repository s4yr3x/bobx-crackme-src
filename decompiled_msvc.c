#include <intrin.h> 
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>

 // =============================================================================
 // Type Definitions and Forward Declarations
 // =============================================================================

 // Standard NT API types
typedef LONG NTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define ERROR_INVALID_HANDLE 6L

// Function pointer for NtQueryInformationProcess
typedef NTSTATUS(WINAPI* PFN_NT_QUERY_INFORMATION_PROCESS)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

// Function pointer for NtSetInformationThread
typedef NTSTATUS(WINAPI* PFN_NT_SET_INFORMATION_THREAD)(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
    );

typedef NTSTATUS(WINAPI* PFN_NT_SET_INFORMATION_THREAD)(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
    );

// manually define enum values not in public headers
#ifndef ThreadHideFromDebugger
#define ThreadHideFromDebugger ((THREADINFOCLASS)17)
#endif

// forward declarations
BOOL perform_security_checks();
void WINAPI security_monitor_thread(LPVOID lpThreadParameter);
void generate_correct_password(char* destination_buffer);
BOOL validate_password(const char* input_password);

// =============================================================================
// Global Variables (from .data and .bss sections)
// =============================================================================

uint64_t g_stack_canary = 0; // Original: qword_140008140

// =============================================================================
// Anti-Debugging & Anti-VM Functions
// =============================================================================

LONG WINAPI vectored_exception_handler(struct _EXCEPTION_POINTERS* ExceptionInfo) {
    if (ExceptionInfo && ExceptionInfo->ExceptionRecord &&
        ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
        // move past the `int 3` instruction (__debugbreak)
        ExceptionInfo->ContextRecord->Rip++;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL check_hardware_breakpoints() {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    HANDLE hThread = GetCurrentThread();
    if (GetThreadContext(hThread, &ctx)) {
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOL check_execution_timing() {
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    volatile int counter = 0;
    for (int i = 0; i < 1000; ++i) {
        counter++;
    }

    QueryPerformanceCounter(&end);

    double elapsed_seconds = (double)(end.QuadPart - start.QuadPart) / (double)freq.QuadPart;

    const double timing_threshold = 0.0001; // from address 0x140005498
    return elapsed_seconds > timing_threshold;
}

BOOL check_debugger_via_process_info() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    PFN_NT_QUERY_INFORMATION_PROCESS pfnNtQueryInformationProcess =
        (PFN_NT_QUERY_INFORMATION_PROCESS)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!pfnNtQueryInformationProcess) return FALSE;

    DWORD_PTR is_debugged = 0;
    NTSTATUS status = pfnNtQueryInformationProcess(
        GetCurrentProcess(),
        ProcessDebugPort, // ProcessInformationClass 7
        &is_debugged,
        sizeof(is_debugged),
        NULL
    );

    return (status == STATUS_SUCCESS && is_debugged != 0);
}

int hide_thread_from_debugger() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return 0;

    PFN_NT_SET_INFORMATION_THREAD pfnNtSetInformationThread =
        (PFN_NT_SET_INFORMATION_THREAD)GetProcAddress(hNtdll, "NtSetInformationThread");
    if (pfnNtSetInformationThread) {
        pfnNtSetInformationThread(
            GetCurrentThread(),
            ThreadHideFromDebugger, // ThreadInformationClass 17
            NULL,
            0
        );
    }
    return 0;
}

BOOL check_debugger_process_name() {
    const char* debugger_names[] = {
        "x64dbg", "windbg", "ollydbg", "ida", "x32dbg", "ghidra", "cheat", "process", NULL
    };

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            char lower_process_name[MAX_PATH] = { 0 };
            wcstombs(lower_process_name, pe32.szExeFile, MAX_PATH - 1);
            for (int i = 0; lower_process_name[i]; i++) {
                lower_process_name[i] = tolower(lower_process_name[i]);
            }

            for (int i = 0; debugger_names[i] != NULL; ++i) {
                if (strstr(lower_process_name, debugger_names[i])) {
                    CloseHandle(hSnapshot);
                    return TRUE;
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return FALSE;
}

BOOL check_vm_artifacts() {
    if (GetFileAttributesA("C:\\Windows\\System32\\drivers\\vmmouse.sys") != INVALID_FILE_ATTRIBUTES) {
        return TRUE;
    }
    if (GetFileAttributesA("C:\\Windows\\System32\\drivers\\vmhgfs.sys") != INVALID_FILE_ATTRIBUTES) {
        return TRUE;
    }
    return FALSE;
}

BOOL perform_security_checks() {
    uint64_t canary_check = g_stack_canary;
    int detection_score = 0;

    // 1. Hide thread from debugger
    hide_thread_from_debugger();

    // 2. IsDebuggerPresent API call
    if (IsDebuggerPresent()) detection_score++;

    // 3. NtQueryInformationProcess for debug port
    if (check_debugger_via_process_info()) detection_score++;

    // 4. Vectored Exception Handler for __debugbreak
    PVOID hVeh = AddVectoredExceptionHandler(1, vectored_exception_handler);
    if (hVeh) {
        volatile BOOL caught = FALSE;
        __try {
            __debugbreak();
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            caught = TRUE; //  i think it should not be reached if VEH works
        }

        detection_score++; // a debugger might interfere with this one
        RemoveVectoredExceptionHandler(hVeh);
    }

    // 5. Hardware breakpoints
    if (check_hardware_breakpoints()) detection_score++;

    // 6. CloseHandle with an invalid handle
    SetLastError(0);
    CloseHandle((HANDLE)(uintptr_t)0xDEADBEEF);
    if (GetLastError() != ERROR_INVALID_HANDLE) detection_score++;

    // 7. Check for debugger process names
    if (check_debugger_process_name()) detection_score++;

    // 8. OutputDebugStringA timing/error check
    SetLastError(0);
    OutputDebugStringA("SecurityCheck");
    if (GetLastError() == 0) detection_score++;

    // 9. PEB BeingDebugged flag
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    if (pPeb->BeingDebugged) detection_score++;

    // 10. CheckRemoteDebuggerPresent API call
    BOOL is_remote_debugger_present = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &is_remote_debugger_present);
    if (is_remote_debugger_present) detection_score++;

    // 11. VM artifacts check
    if (check_vm_artifacts()) detection_score++;

    // 12. System information checks (low core count, low memory)
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    if (sys_info.dwNumberOfProcessors <= 1) detection_score++;

    MEMORYSTATUSEX mem_status;
    mem_status.dwLength = sizeof(mem_status);
    GlobalMemoryStatusEx(&mem_status);
    if (mem_status.ullTotalPhys < (2ULL * 1024 * 1024 * 1024)) detection_score++; // Less than 2GB RAM

    // 13. Timing check
    if (check_execution_timing()) detection_score++;

    // stack canary
    if (canary_check != g_stack_canary) {
        // original binary func at 0x140002560
        puts("*** stack smashing detected ***: terminated\n");
        TerminateProcess(GetCurrentProcess(), 0xC0000409);
    }

    return detection_score > 1;
}

void WINAPI security_monitor_thread(LPVOID lpThreadParameter) {
    while (TRUE) {
        if (perform_security_checks()) {
            ExitProcess(0xDEAD);
        }
        Sleep(100); // 100 ms
    }
}

// =============================================================================
// Password Generation and Validation
// =============================================================================

void generate_correct_password(char* destination_buffer) {
    uint64_t canary_check = g_stack_canary;

    // The password buffer is initialized with these hardcoded 64-bit integers.
    uint64_t initial_data[] = {
        0x8783445371865073, // Bytes: 73 50 86 71 53 44 83 87
        0x484C8677454D4C85, // Bytes: 85 4C 4D 45 77 86 4C 48
        0x8280825F4C745086, // Bytes: 86 50 74 4C 5F 82 80 82
        0x0021818600000000  // Bytes: 86 81 21 00 ... (partially set)
    };
    memcpy(destination_buffer, initial_data, 27);
    destination_buffer[27] = '\0';

    // The dynamic key is based on runtime values.
    BYTE xor_key = (BYTE)GetTickCount() ^ (BYTE)GetCurrentProcessId();

    // --- OBFUSCATED XOR LOOPS ---
    // The original decompiled code shows two complex, sequential loops here.
    // They appear to perform a chained XOR over the buffer. Due to their
    // structure, it is highly probable they are designed to cancel each other out.
    // To preserve semantics, we replicate this behavior: encrypt, then decrypt.
    // This is a common anti-reversing trick.

    // First obfuscated loop (simulated)
    for (size_t i = 0; destination_buffer[i] != '\0'; ++i) {
        destination_buffer[i] ^= xor_key;
    }

    // Second obfuscated loop (simulated) - cancels the first one
    for (size_t i = 0; destination_buffer[i] != '\0'; ++i) {
        destination_buffer[i] ^= xor_key;
    }
    // --- END OF OBFUSCATED LOGIC ---

    if (canary_check != g_stack_canary) {
        puts("*** stack smashing detected ***: terminated\n");
        TerminateProcess(GetCurrentProcess(), 0xC0000409);
    }
}

BOOL validate_password(const char* input_password) {
    uint64_t canary_check = g_stack_canary;
    char correct_password[64];

    generate_correct_password(correct_password);

    size_t input_len = strlen(input_password);
    size_t correct_len = strlen(correct_password);

    if (input_len != correct_len) {
        return FALSE;
    }

    // Constant-time comparison is not used; a simple memcmp/strcmp is sufficient
    // to replicate the original binary's behavior.
    BOOL result = (strncmp(input_password, correct_password, correct_len) == 0);

    if (canary_check != g_stack_canary) {
        puts("*** stack smashing detected ***: terminated\n");
        TerminateProcess(GetCurrentProcess(), 0xC0000409);
    }

    return result;
}

// =============================================================================
// Main Application Logic
// =============================================================================

void initialize_stack_canary() {
    if (g_stack_canary == 0) {
        // The original uses rand_s, which is not standard.
        // We use srand/rand to achieve a similar non-deterministic result.
        srand((unsigned int)time(NULL) ^ GetCurrentProcessId());
        uint32_t part1 = rand();
        uint32_t part2 = rand();
        g_stack_canary = ((uint64_t)part1 << 32) | part2;
        if (g_stack_canary == 0) g_stack_canary = 0xDEADBEEFDEADBEEF;
    }
}

int main_logic() {
    uint64_t canary_check = g_stack_canary;
    char user_input[256];

    const char* hints[] = {
        "Respect, Bobx!",
        "Shoutout to Bobx!"
    };

    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)security_monitor_thread, NULL, 0, NULL);

    SetConsoleTitleA("Secure Authentication System v3.0 ULTRA");
    puts("\n===============================================");
    puts("    SECURE CRACKME CHALLENGE - ULTRA HARD");
    puts("    BY BOBX");
    puts("===============================================");
    puts("");

    char* bobx_env = getenv("BOBX");
    if (bobx_env && *bobx_env) {
        printf(
            "\n%s\n",
            "BBBB   OOO   BBBB   XX  XX\n"
            "B   B O   O  B   B   XXXX \n"
            "BBBB  O   O  BBBB     XX  \n"
            "B   B O   O  B   B   XXXX \n"
            "BBBB   OOO   BBBB   XX  XX\n"
        );
        printf("[egg] %s\n\n", hints[rand() % 2]);
    }
    else if ((rand() % 3) == 0) { // simplified from original calculation
        printf("\n[hint] %s (set BOBX=1 for full ASCII art)\n\n", hints[rand() % 2]);
    }

    for (int i = 0; i < 5; ++i) {
        if (perform_security_checks()) {
            puts("[!] Security violation detected!");
            puts("[!] Terminating...");
            Sleep(1000);
            ExitProcess(1);
        }
        Sleep(50);
    }

    puts("[*] Security checks passed.");
    puts("[*] System integrity verified.");
    puts("");
    printf("[*] Enter password (or type 'about'): ");

    // my changes of this decompiled code 
    // start here
    char correct_password[64];
    generate_correct_password(correct_password);
    printf("\n\n[!!!] CORRECT PASSWORD: %s\n\n", correct_password);
    // end here

    if (!fgets(user_input, sizeof(user_input), stdin)) {
        puts("[!] Input error.");
        return 1;
    }

    user_input[strcspn(user_input, "\n")] = 0;

    if (strcmp(user_input, "about") == 0) {
        puts("\n[about] Build: ultra-secure demo. Credits: Bobx.");
        puts("[about] Tip: set BOBX=1 before launch.\n");
    }

    if (perform_security_checks()) {
        puts("[!] Tampering detected!");
        ExitProcess(1);
    }

    if (validate_password(user_input)) {
        puts("\n===============================================");
        puts("    [SUCCESS] Access Granted!");
        puts("    Flag: FLAG{U_CR4CK3D_TH3_ULT1M4TE_CH4LL3NG3}");
        puts("    Congratulations, elite hacker!");
        puts("===============================================");
    }
    else {
        puts("\n[!] Invalid password. Access denied.");
        puts("[!] Nice try, keep going!");
    }

    puts("\nPress ENTER to exit...");
    getchar();

    if (canary_check != g_stack_canary) {
        puts("*** stack smashing detected ***: terminated\n");
        TerminateProcess(GetCurrentProcess(), 0xC0000409);
    }

    return 0;
}

int main() {
    initialize_stack_canary();
    return main_logic();
}
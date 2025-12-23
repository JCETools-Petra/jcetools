#define NOMINMAX // [FIX] Mencegah konflik macro min/max Windows dengan std::numeric_limits
#pragma warning(disable:4996)
#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <thread>
#include <string>
#include <stdexcept>
#include <chrono>
#include <sstream>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <ctime>
#include <atomic>
#include <iomanip>
#include <vector>
#include <array>
#include <memory>
#include <shlwapi.h>
#include <locale>
#include <codecvt>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <mutex>
#include <errhandlingapi.h>
#include <algorithm>
#include <limits> 

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "libcurl.lib")
#pragma comment(lib, "wldap32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "normaliz.lib")
#pragma comment(lib, "ntdll.lib")

// =================================================================================
// NT API DECLARATIONS FOR ANTI-DEBUG
// =================================================================================
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID ProcessInformation,
    DWORD ProcessInformationLength,
    PDWORD ReturnLength
);

typedef NTSTATUS(NTAPI* pNtSetInformationThread)(
    HANDLE ThreadHandle,
    DWORD ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
);

#define ProcessDebugPort 7
#define ProcessDebugObjectHandle 30
#define ProcessDebugFlags 31
#define ThreadHideFromDebugger 17

// =================================================================================
// GLOBALS & ENUMS
// =================================================================================
enum AuthMode {
    AUTH_NONE = 0,
    AUTH_HWID = 1,
    AUTH_USERPASS = 2
};

AuthMode g_authMode = AUTH_NONE;
std::string g_sessionToken = "";
std::string g_challengeCode = "";
std::atomic<bool> g_isRunning(true);
std::atomic<bool> g_gameProcessLaunched(false);
HANDLE g_hJobObject = NULL; // Job object untuk automatic child process termination
HANDLE g_hGameProcess = NULL; // Game process handle untuk efficient monitoring

enum ConsoleColor {
    COLOR_DEFAULT = 7,
    COLOR_SUCCESS = 10,  // Hijau
    COLOR_ERROR = 12,    // Merah
    COLOR_INFO = 11,     // Cyan
    COLOR_WARN = 14,     // Kuning
    COLOR_DEBUG = 13     // Ungu (Untuk Debugging)
};

// Forward declarations (implementations after GeneralLogger)
void SetColor(int color);
void LogDebug(const std::wstring& msg);
void DrawBanner();
void PrintStatus(const std::wstring& stepName, const std::wstring& status, int color);

// =================================================================================
// String Obfuscation
// =================================================================================
#define _OBFUSCATE_KEY 0x5A
template <typename CharT, size_t N>
class XORString {
private:
    std::array<CharT, N> encrypted_data;
    std::basic_string<CharT> decrypt() const {
        std::basic_string<CharT> decrypted;
        decrypted.reserve(N);
        for (size_t i = 0; i < N - 1; ++i) decrypted += encrypted_data[i] ^ _OBFUSCATE_KEY;
        return decrypted;
    }
public:
    constexpr XORString(const CharT(&str)[N]) : encrypted_data{} {
        for (size_t i = 0; i < N; ++i) encrypted_data[i] = str[i] ^ _OBFUSCATE_KEY;
    }
    std::basic_string<CharT> get() const { return decrypt(); }
};
#define OBFUSCATE(str) (XORString<std::decay_t<decltype(*str)>, sizeof(str) / sizeof(decltype(*str))>(str).get())

// =================================================================================
// CONFIGURATION
// =================================================================================
struct Config {
    static const std::string CURRENT_VERSION;
    static const std::string VERSION_URL;
    static const std::string UPDATE_URL;
    static const std::string API_URL;
    static const std::string SESSION_KEY_URL;
    static const std::string LOGIN_API_URL;
    static const std::string SESSION_CHECK_API_URL;
    static const std::string PAYLOAD_SECRET_KEY;
    static const std::wstring TARGET_PROCESS;
    static const std::wstring LAUNCH_ARGS;
    static const std::wstring TARGET_DLL;
    static const std::wstring TARGET_WINDOW_TITLE;

    static constexpr long CONNECT_TIMEOUT = 30L;
    static constexpr long REQUEST_TIMEOUT = 45L;
    static constexpr long BACKGROUND_CHECK_TIMEOUT = 60L;
    static constexpr int MAX_RETRY_ATTEMPTS = 3;
    static constexpr int RETRY_DELAY_MS = 2000;
    static constexpr int BACKGROUND_CHECK_MINUTES = 5;
    static constexpr int MAX_FAILED_CHECKS = 5;
    static constexpr int BACKGROUND_RETRY_ATTEMPTS = 3;
};

const std::string Config::CURRENT_VERSION = "1.5";
const std::string Config::VERSION_URL = OBFUSCATE("https://jcetools.my.id/api/version.txt");
const std::string Config::UPDATE_URL = OBFUSCATE("https://jcetools.my.id/api/JCE_Launcher_v1.6.exe");
const std::string Config::API_URL = OBFUSCATE("https://jcetools.my.id/api/1.php");
const std::string Config::SESSION_KEY_URL = OBFUSCATE("https://jcetools.my.id/api/auth/get-session-key.php");
const std::string Config::LOGIN_API_URL = OBFUSCATE("https://jcetools.my.id/api/session_login.php");
const std::string Config::SESSION_CHECK_API_URL = OBFUSCATE("https://jcetools.my.id/api/session_check.php");
const std::string Config::PAYLOAD_SECRET_KEY = OBFUSCATE("JCE-5981938591067384910264058215");
const std::wstring Config::TARGET_PROCESS = OBFUSCATE(L"Audition.exe");
const std::wstring Config::TARGET_DLL = OBFUSCATE(L"jcetools.dll");
const std::wstring Config::TARGET_WINDOW_TITLE = OBFUSCATE(L"Audition");
const std::wstring Config::LAUNCH_ARGS = OBFUSCATE(L"/t3enter 19007B2D55244A7710564371116B1D6E4F28636B4010781E7D IN");


class HandleWrapper {
private:
    HANDLE m_handle;
public:
    HandleWrapper(HANDLE handle = NULL) : m_handle(handle) {}
    ~HandleWrapper() {
        if (m_handle && m_handle != INVALID_HANDLE_VALUE) CloseHandle(m_handle);
    }
    HandleWrapper(const HandleWrapper&) = delete;
    HandleWrapper& operator=(const HandleWrapper&) = delete;
    HandleWrapper(HandleWrapper&& other) noexcept : m_handle(other.m_handle) { other.m_handle = NULL; }
    HandleWrapper& operator=(HandleWrapper&& other) noexcept {
        if (this != &other) {
            if (m_handle && m_handle != INVALID_HANDLE_VALUE) CloseHandle(m_handle);
            m_handle = other.m_handle;
            other.m_handle = NULL;
        }
        return *this;
    }
    operator HANDLE() const { return m_handle; }
    HANDLE get() const { return m_handle; }
};

// =================================================================================
// HELPER FORWARD DECLARATIONS
// =================================================================================
void ShowFriendlyError(const std::wstring& detailedMessage, int errorCode, bool terminate);
void TerminateProcessByName(const std::wstring& processName);
std::string base64UrlDecode(const std::string& input);
void hexToBytes(const std::string& hex, unsigned char* bytes, size_t maxLen);
bool IsDebuggerAttached();
void HandleDebuggerDetection();

// =================================================================================
// STRING CONVERSION (NEEDED BY LOGGER)
// =================================================================================
std::wstring string_to_wstring(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

std::string GetCertPath() {
    wchar_t buffer[MAX_PATH];
    GetModuleFileNameW(NULL, buffer, MAX_PATH);
    PathRemoveFileSpecW(buffer);
    std::wstring certPath = std::wstring(buffer) + L"\\cacert.pem";

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, certPath.c_str(), -1, NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, certPath.c_str(), -1, &strTo[0], size_needed, NULL, NULL);
    if (!strTo.empty()) strTo.pop_back();

    return strTo;
}

// =================================================================================
// LOGGER CLASS
// =================================================================================
class GeneralLogger {
public:
    GeneralLogger() {
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(nullptr, path, MAX_PATH);
        std::wstring p(path);
        log_path_ = p.substr(0, p.find_last_of(L"\\/")) + L"\\log.jce";

        // Clear previous log and write header
        std::wofstream f(log_path_, std::ios::trunc);
        if (f.is_open()) {
            f << L"=================================================================\n";
            f << L"    JCE LAUNCHER - DEBUG LOG\n";
            f << L"    Session Start: ";

            // Add timestamp
            auto now = std::time(nullptr);
            std::tm tm;
            localtime_s(&tm, &now);
            wchar_t timeStr[100];
            wcsftime(timeStr, 100, L"%Y-%m-%d %H:%M:%S", &tm);
            f << timeStr << L"\n";
            f << L"=================================================================\n\n";

            // Log that constructor completed
            f << L"[INIT] GeneralLogger constructor completed\n";
            f << L"[INIT] Log file path: " << log_path_ << L"\n";
            f << L"[INIT] Waiting for main() to be called...\n";
            f << L"\n";
            f.flush(); // Immediate flush
        }
    }

    void log(const std::wstring& message) {
        std::lock_guard<std::mutex> lk(mu_);
        std::wofstream f(log_path_, std::ios::app);
        if (f.is_open()) {
            // Add timestamp to each log entry
            auto now = std::time(nullptr);
            std::tm tm;
            localtime_s(&tm, &now);
            wchar_t timeStr[20];
            wcsftime(timeStr, 20, L"[%H:%M:%S] ", &tm);

            f << timeStr << message << L"\n";
            f.flush(); // CRITICAL: Flush immediately to ensure log is written even if crash
        }
    }

    void separator() {
        log(L"-----------------------------------------------------------------");
    }

private:
    std::wstring log_path_;
    std::mutex mu_;
};
GeneralLogger g_generalLogger;

// =================================================================================
// ANTI-DEBUG PROTECTION (Must be after g_generalLogger declaration)
// =================================================================================
bool IsDebuggerAttached() {
    // Technique 1: IsDebuggerPresent (Basic check)
    if (IsDebuggerPresent()) {
        g_generalLogger.log(L"[ANTI-DEBUG] Technique #1 triggered: IsDebuggerPresent");
        return true;
    }

    // Technique 2: CheckRemoteDebuggerPresent
    BOOL isDebuggerPresent = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent) && isDebuggerPresent) {
        g_generalLogger.log(L"[ANTI-DEBUG] Technique #2 triggered: CheckRemoteDebuggerPresent");
        return true;
    }

    // Technique 3: NtQueryInformationProcess - ProcessDebugPort
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (NtQIP) {
            DWORD debugPort = 0;
            NTSTATUS status = NtQIP(GetCurrentProcess(), ProcessDebugPort, &debugPort, sizeof(debugPort), NULL);
            if (status == 0 && debugPort != 0) {
                g_generalLogger.log(L"[ANTI-DEBUG] Technique #3 triggered: ProcessDebugPort = " + std::to_wstring(debugPort));
                return true;
            }

            // Technique 4: ProcessDebugObjectHandle
            HANDLE debugObject = NULL;
            status = NtQIP(GetCurrentProcess(), ProcessDebugObjectHandle, &debugObject, sizeof(debugObject), NULL);
            if (status == 0 && debugObject != NULL) {
                g_generalLogger.log(L"[ANTI-DEBUG] Technique #4 triggered: ProcessDebugObjectHandle");
                CloseHandle(debugObject);
                return true;
            }

            // Technique 5: ProcessDebugFlags (NoDebugInherit)
            DWORD debugFlags = 0;
            status = NtQIP(GetCurrentProcess(), ProcessDebugFlags, &debugFlags, sizeof(debugFlags), NULL);
            if (status == 0 && debugFlags == 0) {
                g_generalLogger.log(L"[ANTI-DEBUG] Technique #5 triggered: ProcessDebugFlags = 0");
                return true;
            }
        }
    }

    // Technique 6: Hardware Breakpoint Detection (Check DR registers)
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
            g_generalLogger.log(L"[ANTI-DEBUG] Technique #6 triggered: Hardware Breakpoints detected");
            return true;
        }
    }

    // Technique 7: Timing Check (RDTSC - Detect single-stepping)
    // DISABLED: Too prone to false positives due to CPU power management and context switching
    /*
    ULONGLONG startTick = __rdtsc();
    volatile int dummy = 0;
    for (int i = 0; i < 10; i++) dummy++;
    ULONGLONG endTick = __rdtsc();
    // Increased threshold to 500000 to prevent false positives
    if ((endTick - startTick) > 500000) {
        g_generalLogger.log(L"[ANTI-DEBUG] Technique #7 triggered: Timing anomaly (cycles: " + std::to_wstring(endTick - startTick) + L")");
        return true;
    }
    */

    // Technique 8: Parent Process Check (check if launched by debugger)
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
        DWORD currentPID = GetCurrentProcessId();
        DWORD parentPID = 0;

        if (Process32FirstW(hSnapshot, &pe)) {
            do {
                if (pe.th32ProcessID == currentPID) {
                    parentPID = pe.th32ParentProcessID;
                    break;
                }
            } while (Process32NextW(hSnapshot, &pe));
        }

        // Get parent process name
        if (parentPID != 0 && Process32FirstW(hSnapshot, &pe)) {
            do {
                if (pe.th32ProcessID == parentPID) {
                    std::wstring parentName = pe.szExeFile;
                    std::transform(parentName.begin(), parentName.end(), parentName.begin(), ::tolower);

                    // Common debugger process names
                    if (parentName.find(L"x64dbg") != std::wstring::npos ||
                        parentName.find(L"x32dbg") != std::wstring::npos ||
                        parentName.find(L"ollydbg") != std::wstring::npos ||
                        parentName.find(L"windbg") != std::wstring::npos ||
                        parentName.find(L"ida") != std::wstring::npos ||
                        parentName.find(L"ghidra") != std::wstring::npos ||
                        parentName.find(L"cheatengine") != std::wstring::npos ||
                        parentName.find(L"processhacker") != std::wstring::npos) {
                        g_generalLogger.log(L"[ANTI-DEBUG] Technique #8 triggered: Debugger parent process: " + parentName);
                        CloseHandle(hSnapshot);
                        return true;
                    }
                    break;
                }
            } while (Process32NextW(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }

    // Technique 9: Check for common debugger windows
    if (FindWindowA("OLLYDBG", NULL) != NULL) {
        g_generalLogger.log(L"[ANTI-DEBUG] Technique #9 triggered: OllyDbg window detected");
        return true;
    }
    if (FindWindowA("WinDbgFrameClass", NULL) != NULL) {
        g_generalLogger.log(L"[ANTI-DEBUG] Technique #9 triggered: WinDbg window detected");
        return true;
    }
    if (FindWindowA("Qt5QWindowIcon", NULL) != NULL) {
        g_generalLogger.log(L"[ANTI-DEBUG] Technique #9 triggered: x64dbg window detected");
        return true;
    }
    if (FindWindowA("ID", NULL) != NULL) {
        g_generalLogger.log(L"[ANTI-DEBUG] Technique #9 triggered: IDA Pro window detected");
        return true;
    }
    if (FindWindowA("ProcessHacker", NULL) != NULL) {
        g_generalLogger.log(L"[ANTI-DEBUG] Technique #9 triggered: Process Hacker window detected");
        return true;
    }

    // Technique 10: SeDebugPrivilege check
    // DISABLED: Too many false positives when running as Administrator
    /*
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        LUID luid;
        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
            PRIVILEGE_SET ps;
            ps.PrivilegeCount = 1;
            ps.Control = PRIVILEGE_SET_ALL_NECESSARY;
            ps.Privilege[0].Luid = luid;
            ps.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

            BOOL result = FALSE;
            if (PrivilegeCheck(hToken, &ps, &result) && result) {
                g_generalLogger.log(L"[ANTI-DEBUG] Technique #10 triggered: SeDebugPrivilege detected");
                CloseHandle(hToken);
                return true;
            }
        }
        CloseHandle(hToken);
    }
    */

    return false;
}

void HandleDebuggerDetection() {
    g_generalLogger.log(L"[SECURITY] Debugger detected - Terminating");

    // Terminate game if launched
    if (g_gameProcessLaunched) {
        TerminateProcessByName(Config::TARGET_PROCESS);
    }

    g_isRunning = false;

    // Don't show obvious error message to debugger
    ShowFriendlyError(L"Terjadi kesalahan sistem. Kode: 0x80070057", 999, true);
}

// =================================================================================
// VM / SANDBOX DETECTION (TIER A - Security Enhancement)
// =================================================================================
bool IsRunningInVM() {
    g_generalLogger.log(L"[VM-CHECK] Starting VM/Sandbox detection...");

    // Check 1: VMware detection via registry
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware Tools", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        g_generalLogger.log(L"[VM-CHECK] DETECTED: VMware (Registry key found)");
        return true;
    }

    // Check 2: VirtualBox detection
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Oracle\\VirtualBox Guest Additions", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        g_generalLogger.log(L"[VM-CHECK] DETECTED: VirtualBox (Registry key found)");
        return true;
    }

    // Check 3: Check for VM processes
    const wchar_t* vmProcesses[] = {
        L"vmtoolsd.exe", L"vmwaretray.exe", L"vmwareuser.exe",
        L"vboxservice.exe", L"vboxtray.exe",
        L"xenservice.exe", L"qemu-ga.exe"
    };

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
        if (Process32FirstW(hSnap, &pe)) {
            do {
                std::wstring procName = pe.szExeFile;
                std::transform(procName.begin(), procName.end(), procName.begin(), ::tolower);

                for (const auto& vmProc : vmProcesses) {
                    std::wstring vmProcLower = vmProc;
                    std::transform(vmProcLower.begin(), vmProcLower.end(), vmProcLower.begin(), ::tolower);

                    if (procName == vmProcLower) {
                        g_generalLogger.log(L"[VM-CHECK] DETECTED: VM process found: " + procName);
                        CloseHandle(hSnap);
                        return true;
                    }
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }

    // Check 4: Check for Sandboxie
    if (GetModuleHandleA("SbieDll.dll") != NULL) {
        g_generalLogger.log(L"[VM-CHECK] DETECTED: Sandboxie (SbieDll.dll loaded)");
        return true;
    }

    // Check 5: Check MAC address (VMware uses 00:05:69, 00:0C:29, 00:50:56)
    // This is more complex, skipping for now

    g_generalLogger.log(L"[VM-CHECK] No VM/Sandbox detected - Running on real hardware");
    return false;
}

// =================================================================================
// JOB OBJECT - AUTOMATIC CHILD PROCESS TERMINATION
// =================================================================================
bool CreateJobObjectForAutoKill() {
    g_generalLogger.log(L"[JOB] Creating job object for automatic child termination...");

    // Create a job object
    g_hJobObject = CreateJobObject(NULL, NULL);
    if (g_hJobObject == NULL) {
        g_generalLogger.log(L"[JOB] ERROR: Failed to create job object. Error code: " + std::to_wstring(GetLastError()));
        return false;
    }

    // Configure job to kill all processes when job handle is closed
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = { 0 };
    jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

    if (!SetInformationJobObject(g_hJobObject, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli))) {
        g_generalLogger.log(L"[JOB] ERROR: Failed to set job information. Error code: " + std::to_wstring(GetLastError()));
        CloseHandle(g_hJobObject);
        g_hJobObject = NULL;
        return false;
    }

    // Add current process (launcher) to job
    if (!AssignProcessToJobObject(g_hJobObject, GetCurrentProcess())) {
        g_generalLogger.log(L"[JOB] ERROR: Failed to assign launcher to job. Error code: " + std::to_wstring(GetLastError()));
        CloseHandle(g_hJobObject);
        g_hJobObject = NULL;
        return false;
    }

    g_generalLogger.log(L"[JOB] Job object created successfully");
    g_generalLogger.log(L"[JOB] Launcher process assigned to job - All child processes will auto-terminate with launcher");
    return true;
}

bool AddProcessToJob(HANDLE hProcess) {
    if (g_hJobObject == NULL) {
        g_generalLogger.log(L"[JOB] ERROR: Job object is NULL, cannot add process");
        return false;
    }

    if (!AssignProcessToJobObject(g_hJobObject, hProcess)) {
        DWORD error = GetLastError();
        g_generalLogger.log(L"[JOB] ERROR: Failed to add process to job. Error code: " + std::to_wstring(error));
        return false;
    }

    g_generalLogger.log(L"[JOB] Process successfully added to job object");
    return true;
}

// =================================================================================
// ANIMATED LOADING (TIER A - UX Enhancement)
// =================================================================================
class LoadingAnimation {
private:
    const wchar_t* frames[10] = {
        L"⠋", L"⠙", L"⠹", L"⠸", L"⠼", L"⠴", L"⠦", L"⠧", L"⠇", L"⠏"
    };
    int currentFrame = 0;
    std::wstring message;
    bool isRunning = false;
    std::thread animThread;

    void animate() {
        while (isRunning) {
            SetColor(COLOR_INFO);
            std::wcout << L"\r  [" << frames[currentFrame] << L"] " << message << L"          ";
            std::wcout.flush();
            currentFrame = (currentFrame + 1) % 10;
            Sleep(80); // 80ms per frame = smooth animation
        }
    }

public:
    void start(const std::wstring& msg) {
        message = msg;
        currentFrame = 0;
        isRunning = true;
        animThread = std::thread(&LoadingAnimation::animate, this);
    }

    void update(const std::wstring& msg) {
        message = msg;
    }

    void stop(const std::wstring& finalMsg, bool success = true) {
        isRunning = false;
        if (animThread.joinable()) animThread.join();

        SetColor(success ? COLOR_SUCCESS : COLOR_ERROR);
        std::wcout << L"\r  [" << (success ? L"✓" : L"✗") << L"] " << finalMsg;
        // Pad with spaces to clear previous text
        std::wcout << L"                                        \n";
        SetColor(COLOR_DEFAULT);
    }
};

// Progress bar animation
void ShowProgressBar(const std::wstring& label, int percent) {
    int barWidth = 30;
    int filled = (barWidth * percent) / 100;

    SetColor(COLOR_INFO);
    std::wcout << L"\r  " << label << L" [";

    for (int i = 0; i < barWidth; i++) {
        if (i < filled) {
            SetColor(COLOR_SUCCESS);
            std::wcout << L"█";
        } else {
            SetColor(COLOR_DEFAULT);
            std::wcout << L"░";
        }
    }

    SetColor(COLOR_INFO);
    std::wcout << L"] " << percent << L"%   ";
    std::wcout.flush();
    SetColor(COLOR_DEFAULT);
}

// =================================================================================
// UI HELPER FUNCTIONS
// =================================================================================
void SetColor(int color) {
    try {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
    } catch (...) {
        g_generalLogger.log(L"ERROR: SetColor() failed");
    }
}

void LogDebug(const std::wstring& msg) {
    // Only write to log file, not to console (user-friendly)
    g_generalLogger.log(L"[DEBUG] " + msg);
}

// Animated ASCII Art Banner
class AnimatedBanner {
private:
    std::atomic<bool> isRunning{false};
    std::thread animThread;
    int colorOffset = 0;

    const std::wstring asciiArt[9] = {
        L"  ╔═══════════════════════════════════════════════════════════════╗",
        L"  ║    ██╗ ██████╗███████╗    ████████╗ ██████╗  ██████╗ ██╗     ║",
        L"  ║    ██║██╔════╝██╔════╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ║",
        L"  ║    ██║██║     █████╗  █████╗██║   ██║   ██║██║   ██║██║     ║",
        L"  ║    ██║██║     ██╔══╝  ╚════╝██║   ██║   ██║██║   ██║██║     ║",
        L"  ║    ██║╚██████╗███████╗      ██║   ╚██████╔╝╚██████╔╝███████╗║",
        L"  ║    ╚═╝ ╚═════╝╚══════╝      ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝║",
        L"  ║              🎮  Secure Launcher v1.7  🎮                    ║",
        L"  ╚═══════════════════════════════════════════════════════════════╝"
    };

    void animate() {
        int rainbowColors[] = {12, 14, 10, 11, 9, 13}; // Red, Yellow, Green, Cyan, Blue, Magenta
        int numColors = 6;

        while (isRunning) {
            // Clear previous
            COORD coord = {0, 0};
            SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), coord);

            // Draw with rainbow wave effect
            for (int i = 0; i < 9; i++) {
                int colorIndex = (i + colorOffset) % numColors;
                SetColor(rainbowColors[colorIndex]);
                std::wcout << asciiArt[i] << L"\n";
            }

            // Loading text
            SetColor(COLOR_INFO);
            std::wcout << L"\n";

            // Animated dots
            int dotCount = (colorOffset / 3) % 4;
            std::wcout << L"                    🚀 Initializing";
            for (int i = 0; i < dotCount; i++) std::wcout << L".";
            for (int i = dotCount; i < 3; i++) std::wcout << L" ";
            std::wcout << L"                    \n";

            SetColor(COLOR_DEFAULT);

            colorOffset++;
            if (colorOffset >= numColors * 100) colorOffset = 0;

            Sleep(150); // Animation speed
        }
    }

public:
    void start() {
        // Clear screen first
        system("cls");

        isRunning = true;
        animThread = std::thread(&AnimatedBanner::animate, this);
        g_generalLogger.log(L"Animated banner started");
    }

    void stop() {
        isRunning = false;
        if (animThread.joinable()) {
            animThread.join();
        }

        // Clear screen and show final banner
        system("cls");

        // Draw final static banner
        SetColor(COLOR_SUCCESS);
        for (int i = 0; i < 9; i++) {
            std::wcout << asciiArt[i] << L"\n";
        }

        SetColor(COLOR_SUCCESS);
        std::wcout << L"\n                ✅ Initialization Complete!\n\n";
        SetColor(COLOR_DEFAULT);

        g_generalLogger.log(L"Animated banner stopped");
    }
};

AnimatedBanner g_banner;

void DrawBanner() {
    g_generalLogger.log(L"DrawBanner() - START");
    try {
        g_banner.start();
        g_generalLogger.log(L"DrawBanner() - SUCCESS");
    } catch (const std::exception& e) {
        g_generalLogger.log(L"ERROR: DrawBanner() exception: " + string_to_wstring(std::string(e.what())));
    } catch (...) {
        g_generalLogger.log(L"ERROR: DrawBanner() unknown exception");
    }
}

void PrintStatus(const std::wstring& stepName, const std::wstring& status, int color) {
    g_generalLogger.log(L"PrintStatus: " + stepName + L" = " + status);
    try {
        SetColor(COLOR_DEFAULT);
        std::wcout << L"  ["; SetColor(COLOR_INFO); std::wcout << L"*"; SetColor(COLOR_DEFAULT);
        std::wcout << L"] " << std::left << std::setw(35) << stepName << L" : ";
        SetColor(color); std::wcout << status << std::endl;
        SetColor(COLOR_DEFAULT);
        Sleep(100);
    } catch (...) {
        g_generalLogger.log(L"ERROR: PrintStatus() console output failed");
    }
}

// =================================================================================
// CRYPTO & STRING UTILS
// =================================================================================
std::string base64UrlDecode(const std::string& input) {
    std::string base64 = input;
    for (char& c : base64) {
        if (c == '-') c = '+';
        if (c == '_') c = '/';
    }
    while (base64.length() % 4 != 0) base64 += '=';
    static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string decoded;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[base64_chars[i]] = i;
    int val = 0, valb = -8;
    for (unsigned char c : base64) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            decoded.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return decoded;
}

void hexToBytes(const std::string& hex, unsigned char* bytes, size_t maxLen) {
    for (size_t i = 0; i < hex.length() && i < maxLen * 2; i += 2) {
        std::string byteString = hex.substr(i, 2);
        bytes[i / 2] = (unsigned char)strtol(byteString.c_str(), nullptr, 16);
    }
}

size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* output) {
    size_t totalSize = size * nmemb;
    output->append(static_cast<char*>(contents), totalSize);
    return totalSize;
}

std::string encrypt_payload(const std::string& plaintext, const std::string& keyStr) {
    unsigned char key[32];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, keyStr.c_str(), keyStr.length());
    SHA256_Final(key, &sha256);

    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, AES_BLOCK_SIZE);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    int len = 0, ciphertext_len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char*)plaintext.c_str(), (int)plaintext.size());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(ciphertext_len);

    std::stringstream ss;
    for (int i = 0; i < AES_BLOCK_SIZE; i++) ss << std::hex << std::setw(2) << std::setfill('0') << (int)iv[i];
    ss << "::";
    for (unsigned char c : ciphertext) ss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    return ss.str();
}

std::string decrypt_payload(const std::string& encrypted_str, const std::string& keyStr) {
    size_t delimiterPos = encrypted_str.find("::");
    if (delimiterPos == std::string::npos) return "";

    std::string ivHex = encrypted_str.substr(0, delimiterPos);
    std::string cipherHex = encrypted_str.substr(delimiterPos + 2);

    unsigned char key[32];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, keyStr.c_str(), keyStr.length());
    SHA256_Final(key, &sha256);

    unsigned char iv[16];
    hexToBytes(ivHex, iv, 16);

    std::vector<unsigned char> ciphertext(cipherHex.length() / 2);
    for (size_t i = 0; i < cipherHex.length(); i += 2) {
        std::string byteString = cipherHex.substr(i, 2);
        ciphertext[i / 2] = (unsigned char)strtol(byteString.c_str(), nullptr, 16);
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> plaintext(ciphertext.size() + AES_BLOCK_SIZE);
    int len = 0, plaintext_len = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), (int)ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx); return "";
    }
    plaintext_len = len;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx); return "";
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(plaintext_len);

    return std::string(plaintext.begin(), plaintext.end());
}

// =================================================================================
// NETWORK FUNCTIONS
// =================================================================================
void SetupCurl(CURL* curl, const std::string& url, const std::string& postData, std::string* response) {
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36");
    if (!postData.empty()) {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
    }
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, Config::REQUEST_TIMEOUT);

    static std::string certPath = GetCertPath();
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_CAINFO, certPath.c_str());
}

bool IsInternetAvailable() {
    g_generalLogger.log(L"IsInternetAvailable() - Checking internet connection...");
    try {
        CURL* curl = curl_easy_init();
        if (!curl) {
            g_generalLogger.log(L"IsInternetAvailable() - FAILED: curl_easy_init() returned NULL");
            return false;
        }
        std::string response;
        SetupCurl(curl, "https://www.google.com", "", &response);
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        CURLcode res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);

        if (res == CURLE_OK) {
            g_generalLogger.log(L"IsInternetAvailable() - SUCCESS");
            return true;
        } else {
            g_generalLogger.log(L"IsInternetAvailable() - FAILED: curl error code " + std::to_wstring(res));
            return false;
        }
    } catch (const std::exception& e) {
        g_generalLogger.log(L"IsInternetAvailable() - EXCEPTION: " + string_to_wstring(std::string(e.what())));
        return false;
    } catch (...) {
        g_generalLogger.log(L"IsInternetAvailable() - UNKNOWN EXCEPTION");
        return false;
    }
}

size_t WriteToFileCallback(void* ptr, size_t size, size_t nmemb, FILE* stream) {
    return fwrite(ptr, size, nmemb, stream);
}

bool DownloadToFile(const std::string& url, const std::wstring& filepath) {
    CURL* curl = curl_easy_init();
    if (!curl) return false;
    FILE* fp = _wfopen(filepath.c_str(), L"wb");
    if (!fp) { curl_easy_cleanup(curl); return false; }

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteToFileCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 300L);

    static std::string certPath = GetCertPath();
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_CAINFO, certPath.c_str());

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    fclose(fp);
    return res == CURLE_OK;
}

std::string DownloadToString(const std::string& url) {
    CURL* curl = curl_easy_init();
    if (!curl) return "";
    std::string content;
    SetupCurl(curl, url, "", &content);
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (res != CURLE_OK) return "";
    return content;
}

void CheckForUpdates() {
    g_generalLogger.log(L"CheckForUpdates() - START");
    try {
        PrintStatus(L"Memeriksa Pembaruan", L"Checking...", COLOR_WARN);
        g_generalLogger.log(L"CheckForUpdates() - Downloading version info from: " + string_to_wstring(Config::VERSION_URL));

        std::string latestVersion = DownloadToString(Config::VERSION_URL);
        g_generalLogger.log(L"CheckForUpdates() - Downloaded version: " + string_to_wstring(latestVersion));

        if (!latestVersion.empty()) {
            latestVersion.erase(latestVersion.find_last_not_of(" \n\r\t") + 1);
        }

        if (latestVersion.empty() || latestVersion == Config::CURRENT_VERSION) {
            g_generalLogger.log(L"CheckForUpdates() - Version is up to date: " + string_to_wstring(Config::CURRENT_VERSION));
            PrintStatus(L"Versi Launcher", L"Terbaru (v" + string_to_wstring(Config::CURRENT_VERSION) + L")", COLOR_SUCCESS);
            return;
        }

        g_generalLogger.log(L"CheckForUpdates() - Update available: " + string_to_wstring(latestVersion));
    } catch (const std::exception& e) {
        g_generalLogger.log(L"CheckForUpdates() - EXCEPTION: " + string_to_wstring(std::string(e.what())));
        return;
    } catch (...) {
        g_generalLogger.log(L"CheckForUpdates() - UNKNOWN EXCEPTION");
        return;
    }

    PrintStatus(L"Pembaruan Ditemukan", L"Mengunduh...", COLOR_WARN);
    wchar_t currentExePath[MAX_PATH];
    GetModuleFileNameW(NULL, currentExePath, MAX_PATH);
    std::wstring currentExeName = PathFindFileNameW(currentExePath);
    std::wstring newExePath = std::wstring(currentExePath) + L".new";
    std::wstring batPath = std::wstring(currentExePath) + L".bat";

    if (!DownloadToFile(Config::UPDATE_URL, newExePath)) {
        ShowFriendlyError(L"Gagal mengunduh pembaruan.", 801, true);
        return;
    }

    PrintStatus(L"Unduhan Selesai", L"Restarting...", COLOR_SUCCESS);
    Sleep(2000);

    std::wofstream batFile(batPath);
    if (batFile.is_open()) {
        batFile << L"@echo off\n" << L"timeout /t 2 /nobreak > nul\n"
            << L"del \"" << currentExeName << L"\"\n"
            << L"rename \"" << newExePath << L"\" \"" << currentExeName << L"\"\n"
            << L"start \"\" \"" << currentExeName << L"\"\n"
            << L"del \"" << batPath << L"\"\n";
        batFile.close();
    }
    ShellExecuteW(NULL, L"open", batPath.c_str(), NULL, NULL, SW_HIDE);
    exit(0);
}

// --- API REQUEST FUNCTIONS ---
std::string SendLoginRequest(const std::string& username, const std::string& password) {
    CURL* curl = curl_easy_init();
    if (!curl) return "";

    nlohmann::json json_payload;
    json_payload["username"] = username;
    json_payload["password"] = password;

    std::string encrypted_payload = encrypt_payload(json_payload.dump(), Config::PAYLOAD_SECRET_KEY);
    if (encrypted_payload.empty()) { curl_easy_cleanup(curl); return ""; }

    std::string response_data;
    SetupCurl(curl, Config::LOGIN_API_URL, encrypted_payload, &response_data);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) return "";
    return decrypt_payload(response_data, Config::PAYLOAD_SECRET_KEY);
}

std::string SendTokenCheckRequest(const std::string& token, const std::string& challenge_response) {
    CURL* curl = curl_easy_init();
    if (!curl) return "";

    nlohmann::json json_payload;
    json_payload["session_token"] = token;
    json_payload["response"] = challenge_response;

    std::string encrypted_payload = encrypt_payload(json_payload.dump(), Config::PAYLOAD_SECRET_KEY);
    if (encrypted_payload.empty()) { curl_easy_cleanup(curl); return ""; }

    std::string response_data;
    SetupCurl(curl, Config::SESSION_CHECK_API_URL, encrypted_payload, &response_data);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) return "";
    return decrypt_payload(response_data, Config::PAYLOAD_SECRET_KEY);
}

std::string RequestSessionKeyHWID() {
    CURL* curl = curl_easy_init();
    if (!curl) return "";
    std::string response;
    SetupCurl(curl, Config::SESSION_KEY_URL, "", &response);
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (res != CURLE_OK) return "";
    try {
        auto json = nlohmann::json::parse(response);
        if (json.value("status", "") == "success") return json.value("session_token", "");
    }
    catch (...) {}
    return "";
}

std::string SendHWIDRequest(const std::string& encryptedHwid, const std::string& sessionToken) {
    CURL* curl = curl_easy_init();
    if (!curl) return "";
    std::string response;
    std::string jsonData = "{\"hwid\":\"" + encryptedHwid + "\"}";

    curl_easy_setopt(curl, CURLOPT_URL, Config::API_URL.c_str());
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36");
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonData.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, Config::REQUEST_TIMEOUT);

    static std::string certPath = GetCertPath();
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_CAINFO, certPath.c_str());

    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    std::string authHeader = "Authorization: Bearer " + sessionToken;
    headers = curl_slist_append(headers, authHeader.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);

    if (res == CURLE_OK) return response;
    return "";
}

// =================================================================================
// UTILS
// =================================================================================
void ShowFriendlyError(const std::wstring& detailedMessage, int errorCode, bool terminate) {
    g_generalLogger.log(L"ERROR Code " + std::to_wstring(errorCode));
    SetColor(COLOR_ERROR);
    std::wcout << L"\n  [!] ERROR (" << errorCode << L"): " << detailedMessage << L"\n";
    SetColor(COLOR_DEFAULT);
    // [DEBUG] Changed exit to pause so we can see the error
    if (terminate) {
        std::wcout << L"\n  [DEBUG] Fatal Error. Press Enter to exit...\n";
        system("pause");
        exit(1);
    }
}

DWORD GetVolumeSerialNumberFromCurrentDrive() {
    char modulePath[MAX_PATH]; if (GetModuleFileNameA(NULL, modulePath, MAX_PATH) == 0) return 0;
    std::string drivePath = std::string(1, modulePath[0]) + ":\\";
    DWORD serialNumber = 0; GetVolumeInformationA(drivePath.c_str(), NULL, 0, &serialNumber, NULL, NULL, NULL, 0);
    return serialNumber;
}
std::string ConvertToString(DWORD value) { std::ostringstream oss; oss << value; return oss.str(); }

struct SessionKeyData { std::string session_id, key, iv; bool valid = false; };
SessionKeyData ParseJWTToken(const std::string& token) {
    SessionKeyData data; data.valid = false;
    size_t firstDot = token.find('.'); size_t secondDot = token.find('.', firstDot + 1);
    if (firstDot == std::string::npos || secondDot == std::string::npos) return data;
    std::string payloadEncoded = token.substr(firstDot + 1, secondDot - firstDot - 1);
    std::string payloadJson = base64UrlDecode(payloadEncoded);
    try {
        auto payload = nlohmann::json::parse(payloadJson);
        data.session_id = payload.value("session_id", "");
        data.key = payload.value("key", "");
        data.iv = payload.value("iv", "");
        if (!data.session_id.empty()) data.valid = true;
    }
    catch (...) {}
    return data;
}

bool encrypt_standard(const std::string& plaintext, const unsigned char* key, const unsigned char* iv, std::vector<unsigned char>& ciphertext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    ciphertext.resize(plaintext.size() + AES_BLOCK_SIZE);
    int len = 0, clen = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char*)plaintext.c_str(), (int)plaintext.size());
    clen = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    clen += len;
    ciphertext.resize(clen);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}
std::string ciphertextToHex(const std::vector<unsigned char>& ct) {
    std::ostringstream oss; for (unsigned char c : ct) oss << std::hex << std::setw(2) << std::setfill('0') << (int)c; return oss.str();
}

// =================================================================================
// CORE LOGIC 1: VERIFY HWID
// =================================================================================
int VerifyLicenseHWID(bool isInitialCheck) {
    LoadingAnimation loader;

    if (isInitialCheck) {
        std::wcout << L"\n";
        loader.start(L"Menghubungi server lisensi...");
        Sleep(500);
    }

    std::string sessionToken = RequestSessionKeyHWID();
    if (sessionToken.empty()) {
        if (isInitialCheck) {
            loader.stop(L"Gagal menghubungi server", false);
        } else {
            g_generalLogger.log(L"Pemeriksaan: Koneksi ke server gagal, mencoba ulang...");
        }
        return 2;
    }

    if (isInitialCheck) {
        loader.update(L"Menerima kunci enkripsi...");
        Sleep(300);
    }

    SessionKeyData sessionData = ParseJWTToken(sessionToken);
    if (!sessionData.valid) {
        if (isInitialCheck) {
            loader.stop(L"Respon server tidak valid", false);
        } else {
            g_generalLogger.log(L"Pemeriksaan: Respon server tidak valid");
        }
        return 2;
    }

    if (isInitialCheck) {
        loader.update(L"Mengenkripsi ID perangkat Anda...");
        Sleep(400);
    }

    DWORD hwid_val = GetVolumeSerialNumberFromCurrentDrive();
    std::string plaintext = ConvertToString(hwid_val);

    unsigned char key[32] = { 0 }; unsigned char iv[AES_BLOCK_SIZE] = { 0 };
    hexToBytes(sessionData.key, key, 32); hexToBytes(sessionData.iv, iv, AES_BLOCK_SIZE);

    std::vector<unsigned char> ciphertext;
    encrypt_standard(plaintext, key, iv, ciphertext);
    std::string encryptedString = ciphertextToHex(ciphertext);

    if (isInitialCheck) {
        loader.update(L"Memverifikasi HWID dengan database...");
        Sleep(300);
    }

    std::string response = SendHWIDRequest(encryptedString, sessionToken);
    if (response.empty()) {
        if (isInitialCheck) {
            loader.stop(L"Server tidak merespon", false);
        } else {
            g_generalLogger.log(L"Pemeriksaan: Server tidak merespon, mencoba ulang...");
        }
        return 2;
    }

    if (isInitialCheck) {
        loader.update(L"Memeriksa status lisensi...");
        Sleep(400);
    }

    try {
        auto jsonResponse = nlohmann::json::parse(response);
        std::string status = jsonResponse.value("status", "error");

        if (status == "success") {
            if (isInitialCheck) {
                std::string user = jsonResponse.value("user", "User");
                loader.stop(L"Login berhasil! Selamat datang, " + string_to_wstring(user), true);

                std::wcout << L"\n";
                SetColor(COLOR_SUCCESS);
                std::wcout << L"  ╔════════════════════════════════════════════╗\n";
                std::wcout << L"  ║         AUTENTIKASI BERHASIL               ║\n";
                std::wcout << L"  ╚════════════════════════════════════════════╝\n";
                SetColor(COLOR_INFO);
                std::wcout << L"  [+] Login sebagai    : " << string_to_wstring(user) << L"\n";
                std::wcout << L"  [+] Metode Akses     : HWID (Automatic)\n";
                std::wcout << L"  [+] Status           : Terdaftar & Aktif\n";
                SetColor(COLOR_DEFAULT);
            } else {
                // Background check success
                g_generalLogger.log(L"Pemeriksaan lisensi berhasil");
            }
            return 1; // Success
        }
        else {
            std::string msg = jsonResponse.value("message", "");
            if (msg.find("not found") != std::string::npos || jsonResponse.value("code", "") == "NOT_FOUND") {
                if (isInitialCheck) {
                    loader.stop(L"HWID tidak terdaftar", false);
                }
                return 0; // Trigger Login Manual
            }
            if (!isInitialCheck) g_generalLogger.log(L"Pemeriksaan: Verifikasi ditolak oleh server");
            if (isInitialCheck) {
                loader.stop(L"Verifikasi ditolak: " + string_to_wstring(msg), false);
                ShowFriendlyError(string_to_wstring(msg), 302, true);
            }
            return 2;
        }
    }
    catch (...) {
        if (isInitialCheck) {
            loader.stop(L"Terjadi kesalahan saat parsing respon", false);
        } else {
            g_generalLogger.log(L"Pemeriksaan: Terjadi kesalahan, mencoba ulang...");
        }
        return 2;
    }
}

// =================================================================================
// CORE LOGIC 2: VERIFY SESSION
// =================================================================================
bool VerifyLicenseSession(bool isInitialCheck) {
    if (g_sessionToken.empty()) {
        if (!isInitialCheck) g_generalLogger.log(L"Pemeriksaan: Sesi tidak ditemukan");
        return false;
    }
    std::string response_to_challenge = g_challengeCode;
    std::reverse(response_to_challenge.begin(), response_to_challenge.end());

    std::string response = SendTokenCheckRequest(g_sessionToken, response_to_challenge);
    if (response.empty()) {
        if (!isInitialCheck) g_generalLogger.log(L"Pemeriksaan: Koneksi ke server gagal, mencoba ulang...");
        return false;
    }

    try {
        auto json = nlohmann::json::parse(response);
        if (json.value("status", "error") == "success") {
            if (!isInitialCheck) {
                g_generalLogger.log(L"Pemeriksaan lisensi berhasil");
            }
            return true;
        }
        else {
            std::string msg = json.value("message", "Session expired");
            if (!isInitialCheck) {
                g_generalLogger.log(L"Pemeriksaan: Sesi login telah berakhir");
                g_isRunning = false;
                TerminateProcessByName(Config::TARGET_PROCESS);
                ShowFriendlyError(L"Sesi ID/Password telah berakhir.", 305, false);
            }
            return false;
        }
    }
    catch (...) {
        if (!isInitialCheck) g_generalLogger.log(L"Pemeriksaan: Terjadi kesalahan, mencoba ulang...");
        return false;
    }
}

// =================================================================================
// MAIN CHECK FLOW
// =================================================================================
void PerformLoginUI() {
    PrintStatus(L"Status Lisensi", L"HWID Tidak Terdaftar", COLOR_WARN);
    std::wcout << L"\n  [!] Perangkat ini belum terdaftar.\n";
    std::wcout << L"  [!] Silakan login menggunakan ID & Password Anda.\n\n";

    std::string username, password;
    SetColor(COLOR_INFO); std::cout << "  Username: "; SetColor(COLOR_DEFAULT); std::cin >> username;
    SetColor(COLOR_INFO); std::cout << "  Password: "; SetColor(COLOR_DEFAULT);

    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE); DWORD mode = 0;
    GetConsoleMode(hStdin, &mode); SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));

    std::cin >> password;

    SetConsoleMode(hStdin, mode);
    std::cout << "\n\n";

    // === PERBAIKAN UTAMA DISINI ===
    // [FIX] Menggunakan (std::numeric_limits...) untuk menghindari konflik macro max
    std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');
    LogDebug(L"Input buffer cleared.");

    PrintStatus(L"Otentikasi Akun", L"Verifying...", COLOR_WARN);
    std::string response = SendLoginRequest(username, password);

    if (response.empty()) { ShowFriendlyError(L"Gagal terhubung ke server login.", 201, true); return; }

    LogDebug(L"Server Response Received.");

    try {
        auto json = nlohmann::json::parse(response);
        if (json.value("status", "error") == "success") {
            g_sessionToken = json.value("session_token", "");
            g_challengeCode = json.value("challenge", "");
            if (g_challengeCode.empty()) g_challengeCode = "DUMMY";
            g_authMode = AUTH_USERPASS;

            PrintStatus(L"Otentikasi Akun", L"Berhasil [OK]", COLOR_SUCCESS);
            std::wcout << L"\n"; SetColor(COLOR_INFO);
            std::wcout << L"  [+] Login sebagai    : " << string_to_wstring(username) << L"\n";
            std::wcout << L"  [+] Metode Akses     : ID & Password\n"; SetColor(COLOR_DEFAULT);
            LogDebug(L"Auth successful, continuing to launch...");
        }
        else {
            std::string msg = json.value("message", "Invalid credentials");
            ShowFriendlyError(L"Login Gagal: " + string_to_wstring(msg), 301, true);
        }
    }
    catch (const nlohmann::json::parse_error&) { ShowFriendlyError(L"Respon server login rusak.", 202, true); }
}

void InitialCheck() {
    g_generalLogger.log(L"InitialCheck() - START");
    g_generalLogger.separator();

    try {
        g_generalLogger.log(L"InitialCheck() - Checking internet connection...");
        PrintStatus(L"Cek Koneksi Internet", L"Checking...", COLOR_WARN);

        if (!IsInternetAvailable()) {
            g_generalLogger.log(L"InitialCheck() - FAILED: No internet connection");
            ShowFriendlyError(L"Tidak ada koneksi internet.", 200, true);
            return;
        }
        PrintStatus(L"Cek Koneksi Internet", L"Online [OK]", COLOR_SUCCESS);
        g_generalLogger.log(L"InitialCheck() - Internet connection OK");

        g_generalLogger.log(L"InitialCheck() - Verifying HWID license...");
        int hwidResult = VerifyLicenseHWID(true);
        g_generalLogger.log(L"InitialCheck() - HWID verification result: " + std::to_wstring(hwidResult));

        if (hwidResult == 1) {
            g_authMode = AUTH_HWID;
            g_generalLogger.log(L"InitialCheck() - Auth Mode set to HWID");
            LogDebug(L"Auth Mode set to HWID");
        }
        else if (hwidResult == 0) {
            g_generalLogger.log(L"InitialCheck() - HWID not registered, entering manual login");
            LogDebug(L"HWID failed, entering PerformLoginUI");
            PerformLoginUI();
        }
        else {
            g_generalLogger.log(L"InitialCheck() - HWID verification failed with error");
            ShowFriendlyError(L"Gagal memverifikasi HWID (Connection Error).", 205, true);
        }

        g_generalLogger.log(L"InitialCheck() - END");
        g_generalLogger.separator();
    } catch (const std::exception& e) {
        g_generalLogger.log(L"InitialCheck() - EXCEPTION: " + string_to_wstring(std::string(e.what())));
        throw;
    } catch (...) {
        g_generalLogger.log(L"InitialCheck() - UNKNOWN EXCEPTION");
        throw;
    }
}

void TerminateProcessByName(const std::wstring& processName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (wcscmp(pe.szExeFile, processName.c_str()) == 0) {
                HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (hProc) { TerminateProcess(hProc, 0); CloseHandle(hProc); }
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
}

// =================================================================================
// CLEANUP & EXIT HANDLERS
// =================================================================================
void CleanupAndExit() {
    static bool alreadyCalled = false;
    if (alreadyCalled) return; // Prevent multiple calls
    alreadyCalled = true;

    g_isRunning = false;

    // Only terminate game if it was actually launched
    if (g_gameProcessLaunched) {
        g_generalLogger.log(L"Menutup program dan game...");
        TerminateProcessByName(Config::TARGET_PROCESS);
        Sleep(500);
        g_generalLogger.log(L"Cleanup selesai");
    } else {
        g_generalLogger.log(L"Program ditutup (game belum dijalankan)");
    }

    // Close game process handle if we have it
    if (g_hGameProcess != NULL) {
        CloseHandle(g_hGameProcess);
        g_hGameProcess = NULL;
    }

    // Close job object handle if we have it
    if (g_hJobObject != NULL) {
        CloseHandle(g_hJobObject);
        g_hJobObject = NULL;
    }
}

BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType) {
    switch (dwCtrlType) {
        case CTRL_C_EVENT:          // Ctrl+C
            g_generalLogger.log(L"Pengguna menekan Ctrl+C");
            break;
        case CTRL_BREAK_EVENT:      // Ctrl+Break
            g_generalLogger.log(L"Pengguna menekan Ctrl+Break");
            break;
        case CTRL_CLOSE_EVENT:      // Console window closed
            g_generalLogger.log(L"Jendela program ditutup");
            break;
        case CTRL_LOGOFF_EVENT:     // User logoff
            g_generalLogger.log(L"Pengguna logout dari Windows");
            break;
        case CTRL_SHUTDOWN_EVENT:   // System shutdown
            g_generalLogger.log(L"Sistem sedang shutdown");
            break;
        default:
            return FALSE;
    }
    CleanupAndExit();
    return TRUE;
}

// =================================================================================
// BACKGROUND CHECK WITH RETRY MECHANISM
// =================================================================================
bool VerifyWithRetry(AuthMode mode, int maxRetries) {
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        bool isValid = false;

        // Perform verification based on auth mode
        if (mode == AUTH_HWID) {
            int res = VerifyLicenseHWID(false);
            isValid = (res == 1);
        }
        else if (mode == AUTH_USERPASS) {
            isValid = VerifyLicenseSession(false);
        }

        // If valid, return success immediately
        if (isValid) {
            if (attempt > 1) {
                g_generalLogger.log(L"Koneksi pulih, verifikasi berhasil");
            }
            return true;
        }

        // If failed and not the last attempt, wait before retry with exponential backoff
        if (attempt < maxRetries) {
            int delaySec = (Config::RETRY_DELAY_MS * attempt) / 1000; // Convert to seconds
            g_generalLogger.log(L"Menunggu " + std::to_wstring(delaySec) + L" detik sebelum mencoba lagi...");
            Sleep(Config::RETRY_DELAY_MS * attempt);
        }
    }

    // All retries failed
    g_generalLogger.log(L"Pemeriksaan gagal setelah beberapa percobaan");
    return false;
}

void AntiDebugThread() {
    g_generalLogger.log(L"[SECURITY] Anti-debug monitoring thread started");

    while (g_isRunning) {
        // Check every 2 seconds for debugger
        std::this_thread::sleep_for(std::chrono::seconds(2));
        if (!g_isRunning) break;

        if (IsDebuggerAttached()) {
            g_generalLogger.log(L"[SECURITY] Debugger detected during runtime - Terminating");
            HandleDebuggerDetection();
            break;
        }
    }

    g_generalLogger.log(L"[SECURITY] Anti-debug monitoring thread stopped");
}

void BackgroundThread() {
    int fails = 0;
    while (g_isRunning) {
        // Interruptible sleep: sleep in 1-second chunks instead of 5 minutes straight
        // This allows the thread to exit quickly when g_isRunning becomes false
        int sleepSeconds = Config::BACKGROUND_CHECK_MINUTES * 60; // Convert minutes to seconds
        for (int i = 0; i < sleepSeconds && g_isRunning; i++) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (!g_isRunning) break;

        // Log background check start with timestamp
        auto now = std::time(nullptr);
        std::tm tm;
        localtime_s(&tm, &now);
        wchar_t timeStr[100];
        wcsftime(timeStr, 100, L"%H:%M:%S", &tm);
        g_generalLogger.log(L"--- Pemeriksaan otomatis [" + std::wstring(timeStr) + L"] ---");

        // Use retry mechanism for background check
        bool isValid = VerifyWithRetry(g_authMode, Config::BACKGROUND_RETRY_ATTEMPTS);

        if (!isValid) {
            fails++;
            g_generalLogger.log(L"Status: Gagal (percobaan ke-" + std::to_wstring(fails) + L" dari maksimal " + std::to_wstring(Config::MAX_FAILED_CHECKS) + L")");

            if (fails >= Config::MAX_FAILED_CHECKS) {
                g_generalLogger.log(L"Koneksi terputus karena terlalu banyak kegagalan verifikasi");
                g_isRunning = false;
                TerminateProcessByName(Config::TARGET_PROCESS);
                ShowFriendlyError(L"Sesi validasi berakhir setelah " + std::to_wstring(Config::MAX_FAILED_CHECKS) + L" kali gagal.", 305, false);
            }
        }
        else {
            if (fails > 0) {
                g_generalLogger.log(L"Status: Berhasil (koneksi kembali normal)");
            } else {
                g_generalLogger.log(L"Status: Berhasil");
            }
            fails = 0;
        }
    }
    g_generalLogger.log(L"Program dihentikan");
}
void HideConsole() {
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    g_generalLogger.log(L"Console window hidden");
}

void ShowConsole() {
    ShowWindow(GetConsoleWindow(), SW_SHOW);
    g_generalLogger.log(L"Console window shown");
}

bool InjectDLL(DWORD processID, const std::wstring& dllPath) {
    LogDebug(L"Attempting Injection into PID: " + std::to_wstring(processID));
    HandleWrapper hProcess(OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID));
    if (!hProcess) {
        ShowFriendlyError(L"Injeksi DLL gagal: Tidak dapat membuka proses target.", 501, true);
        return false;
    }

    SIZE_T dllPathSize = (dllPath.length() + 1) * sizeof(wchar_t);
    LPVOID pDllPathRemote = VirtualAllocEx(hProcess, NULL, dllPathSize, MEM_COMMIT, PAGE_READWRITE);

    if (!pDllPathRemote) {
        ShowFriendlyError(L"Injeksi DLL gagal: Alokasi memori gagal.", 502, true);
        return false;
    }

    if (!WriteProcessMemory(hProcess, pDllPathRemote, dllPath.c_str(), dllPathSize, NULL)) {
        ShowFriendlyError(L"Injeksi DLL gagal: Tidak dapat menulis ke memori proses.", 503, true);
        VirtualFreeEx(hProcess, pDllPathRemote, 0, MEM_RELEASE);
        return false;
    }

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) {
        ShowFriendlyError(L"Injeksi DLL gagal: Tidak dapat memuat kernel32.dll.", 505, true);
        VirtualFreeEx(hProcess, pDllPathRemote, 0, MEM_RELEASE);
        return false;
    }

    FARPROC pLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");
    if (!pLoadLibraryW) {
        ShowFriendlyError(L"Injeksi DLL gagal: Tidak dapat menemukan LoadLibraryW.", 506, true);
        VirtualFreeEx(hProcess, pDllPathRemote, 0, MEM_RELEASE);
        return false;
    }

    HandleWrapper hRemoteThread(CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibraryW, pDllPathRemote, 0, NULL));

    if (!hRemoteThread) {
        ShowFriendlyError(L"Injeksi DLL gagal: Tidak dapat membuat remote thread.", 504, true);
        VirtualFreeEx(hProcess, pDllPathRemote, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(hRemoteThread, INFINITE);
    VirtualFreeEx(hProcess, pDllPathRemote, 0, MEM_RELEASE);
    return true;
}

std::wstring GetExecutablePath(const std::wstring& executableName) {
    wchar_t buffer[MAX_PATH];
    GetModuleFileNameW(NULL, buffer, MAX_PATH);
    PathRemoveFileSpecW(buffer);
    return std::wstring(buffer) + L"\\" + executableName;
}

void LaunchAndInject() {
    g_generalLogger.log(L"LaunchAndInject() - START");
    g_generalLogger.separator();

    std::wstring auditionExePath; // Declare outside try block

    try {
        auditionExePath = GetExecutablePath(Config::TARGET_PROCESS);
        g_generalLogger.log(L"LaunchAndInject() - Game path: " + auditionExePath);
        LogDebug(L"Path Game yang dicari: " + auditionExePath);

        if (!PathFileExistsW(auditionExePath.c_str())) {
            g_generalLogger.log(L"LaunchAndInject() - FAILED: Game executable not found");
            ShowFriendlyError(L"Audition.exe tidak ditemukan.\nPath: " + auditionExePath, 401, true);
            return;
        }
        g_generalLogger.log(L"LaunchAndInject() - Game executable found");
    } catch (const std::exception& e) {
        g_generalLogger.log(L"LaunchAndInject() - EXCEPTION in file check: " + string_to_wstring(std::string(e.what())));
        throw;
    } catch (...) {
        g_generalLogger.log(L"LaunchAndInject() - UNKNOWN EXCEPTION in file check");
        throw;
    }

    g_generalLogger.log(L"LaunchAndInject() - Cleaning old processes...");
    TerminateProcessByName(Config::TARGET_PROCESS);
    Sleep(1000);

    g_generalLogger.log(L"LaunchAndInject() - Preparing process creation...");
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);

    wchar_t fullCommand[1024];
    swprintf_s(fullCommand, _countof(fullCommand), L"\"%s\" %s", auditionExePath.c_str(), Config::LAUNCH_ARGS.c_str());
    g_generalLogger.log(L"LaunchAndInject() - Command: " + std::wstring(fullCommand));
    g_generalLogger.log(L"LaunchAndInject() - Calling CreateProcessW...");

    if (!CreateProcessW(NULL, fullCommand, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        DWORD error = GetLastError();
        g_generalLogger.log(L"LaunchAndInject() - FAILED: CreateProcessW error code " + std::to_wstring(error));
        ShowFriendlyError(L"Gagal memulai Audition.exe. Coba jalankan sebagai Administrator.", 402, true);
        return;
    }
    g_generalLogger.log(L"LaunchAndInject() - CreateProcessW SUCCESS, PID: " + std::to_wstring(pi.dwProcessId));

    // Add Audition.exe to job object for automatic termination
    if (g_hJobObject != NULL) {
        if (AddProcessToJob(pi.hProcess)) {
            g_generalLogger.log(L"[JOB] Audition.exe (PID: " + std::to_wstring(pi.dwProcessId) + L") added to job");
            g_generalLogger.log(L"[JOB] Game will auto-terminate if launcher is killed");
        } else {
            g_generalLogger.log(L"[JOB] WARNING: Failed to add Audition.exe to job - using manual cleanup");
        }
    }

    g_generalLogger.log(L"LaunchAndInject() - Waiting for game window...");
    HWND hAuditionWindow = NULL;

    int waitCount = 0;
    for (int i = 0; i < 120; ++i) {
        hAuditionWindow = FindWindowW(NULL, Config::TARGET_WINDOW_TITLE.c_str());
        if (hAuditionWindow != NULL) break;
        Sleep(500);
        waitCount++;
        if (waitCount % 10 == 0) {
            LogDebug(L"Waiting for window... " + std::to_wstring(waitCount));
            g_generalLogger.log(L"LaunchAndInject() - Still waiting for window... (attempt " + std::to_wstring(waitCount) + L")");
        }
    }

    if (hAuditionWindow == NULL) {
        g_generalLogger.log(L"LaunchAndInject() - FAILED: Game window not found (timeout)");
        ShowFriendlyError(L"Gagal menemukan jendela game (Timeout).", 403, true);
        if (pi.hProcess) {
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess);
        }
        if (pi.hThread) CloseHandle(pi.hThread);
        return;
    }
    g_generalLogger.log(L"LaunchAndInject() - Game window found!");

    std::wstring fullDllPath = GetExecutablePath(Config::TARGET_DLL);
    g_generalLogger.log(L"LaunchAndInject() - DLL path: " + fullDllPath);
    LogDebug(L"Path DLL yang dicari: " + fullDllPath);

    if (!PathFileExistsW(fullDllPath.c_str())) {
        g_generalLogger.log(L"LaunchAndInject() - FAILED: DLL file not found");
        ShowFriendlyError(L"File pendukung (DLL) tidak ditemukan.", 404, true);
        if (pi.hProcess) {
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess);
        }
        if (pi.hThread) CloseHandle(pi.hThread);
        return;
    }
    g_generalLogger.log(L"LaunchAndInject() - DLL file found");
    g_generalLogger.log(L"LaunchAndInject() - Starting DLL injection...");

    if (InjectDLL(pi.dwProcessId, fullDllPath)) {
        // Stop the animated banner - show final success screen
        g_banner.stop();

        PrintStatus(L"Status Injeksi", L"Berhasil [OK]", COLOR_SUCCESS);
        g_gameProcessLaunched = true; // Mark game as launched
        g_generalLogger.log(L"LaunchAndInject() - DLL injection SUCCESS");
        g_generalLogger.log(L"LaunchAndInject() - Game successfully launched and injected");
        g_generalLogger.separator();

        SetColor(COLOR_SUCCESS);
        std::wcout << L"\n  ╔════════════════════════════════════════════╗\n";
        std::wcout << L"  ║     🎉  SEMUA SIAP! SELAMAT BERMAIN  🎉    ║\n";
        std::wcout << L"  ╚════════════════════════════════════════════╝\n\n";
        SetColor(COLOR_DEFAULT);

        Sleep(2000);
        HideConsole();
    }
    else {
        g_generalLogger.log(L"LaunchAndInject() - FAILED: DLL injection failed");
        if (pi.hProcess) {
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess);
        }
        if (pi.hThread) CloseHandle(pi.hThread);
        exit(1);
    }

    // DON'T close pi.hProcess yet - we need it for efficient monitoring!
    // Store it globally
    g_hGameProcess = pi.hProcess;

    if (pi.hThread) CloseHandle(pi.hThread);

    g_generalLogger.log(L"LaunchAndInject() - END");
}

// =================================================================================
// ENTRY POINT
// =================================================================================
int main() {
    // ========== CRITICAL: ANTI-DEBUG CHECK FIRST ==========
    // Must be first thing to prevent debugging
    if (IsDebuggerAttached()) {
        HandleDebuggerDetection();
        return 1;
    }

    // ULTRA-EARLY LOGGING - First thing in main()
    g_generalLogger.log(L"");
    g_generalLogger.log(L"!!! ENTERED main() FUNCTION !!!");
    g_generalLogger.log(L"!!! THIS IS PROOF THAT main() WAS CALLED !!!");
    g_generalLogger.log(L"[SECURITY] Initial anti-debug check: PASSED");
    g_generalLogger.separator();

    // Log executable path and working directory
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    g_generalLogger.log(L"Executable full path: " + std::wstring(exePath));

    wchar_t workDir[MAX_PATH];
    GetCurrentDirectoryW(MAX_PATH, workDir);
    g_generalLogger.log(L"Current working directory: " + std::wstring(workDir));

    wchar_t exeDir[MAX_PATH];
    wcscpy_s(exeDir, exePath);
    PathRemoveFileSpecW(exeDir);
    g_generalLogger.log(L"Executable directory: " + std::wstring(exeDir));

    // Check if cacert.pem exists
    std::wstring certCheck = std::wstring(exeDir) + L"\\cacert.pem";
    DWORD certAttr = GetFileAttributesW(certCheck.c_str());
    g_generalLogger.log(L"Checking cacert.pem at: " + certCheck);
    g_generalLogger.log(L"cacert.pem exists: " + std::wstring(certAttr != INVALID_FILE_ATTRIBUTES ? L"YES" : L"NO"));

    // List all DLLs in executable directory
    g_generalLogger.log(L"Listing DLL files in executable directory:");
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW((std::wstring(exeDir) + L"\\*.dll").c_str(), &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            g_generalLogger.log(L"  - Found DLL: " + std::wstring(findData.cFileName));
        } while (FindNextFileW(hFind, &findData));
        FindClose(hFind);
    } else {
        g_generalLogger.log(L"  - No DLL files found or error listing");
    }
    g_generalLogger.separator();

    // Show MessageBox as visual confirmation (REMOVE THIS AFTER DEBUGGING)
    // MessageBoxW(NULL, L"main() has been called!\nCheck log.jce for details.", L"DEBUG: main() Called", MB_OK | MB_ICONINFORMATION);

    try {
        g_generalLogger.log(L"Calling SetConsoleTitle...");
        SetConsoleTitle(L"JCE Tools Launcher");
        g_generalLogger.log(L"SetConsoleTitle OK");

        g_generalLogger.log(L"=== Program Started ===");

        // Create Job Object for automatic child process termination
        g_generalLogger.log(L"Step 0: Creating job object...");
        if (!CreateJobObjectForAutoKill()) {
            g_generalLogger.log(L"WARNING: Failed to create job object. Manual cleanup will be used.");
            // Continue anyway - we still have manual cleanup as fallback
        }

        g_generalLogger.log(L"Step 1: Drawing banner...");
        DrawBanner();

        g_generalLogger.log(L"Step 2: Registering cleanup handlers...");
        // Register cleanup handlers
        SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);
        std::atexit(CleanupAndExit);
        g_generalLogger.log(L"Step 3: Cleanup handlers registered successfully");

        g_generalLogger.log(L"Step 4: Checking certificate...");
        // Pastikan cacert.pem ada
        std::wstring certW = string_to_wstring(GetCertPath());
        g_generalLogger.log(L"Certificate path: " + certW);

        if (GetFileAttributesW(certW.c_str()) == INVALID_FILE_ATTRIBUTES) {
            g_generalLogger.log(L"ERROR: cacert.pem NOT FOUND!");
            SetColor(COLOR_ERROR);
            std::wcout << L"\n  [!] ERROR: cacert.pem tidak ditemukan!\n";
            std::wcout << L"  [!] Path: " << certW << L"\n\n";
            std::wcout << L"  [!] Pastikan file berikut ada di folder yang sama dengan executable:\n";
            std::wcout << L"      - cacert.pem\n";
            std::wcout << L"      - libcurl.dll\n";
            std::wcout << L"      - libcrypto-3.dll\n";
            std::wcout << L"      - zlib1.dll\n\n";
            std::wcout << L"  [!] Copy semua file dari folder Release!\n";
            SetColor(COLOR_DEFAULT);

            MessageBoxW(NULL,
                L"ERROR: cacert.pem tidak ditemukan!\n\n"
                L"Pastikan file berikut ada di folder yang sama dengan executable:\n"
                L"- cacert.pem\n"
                L"- libcurl.dll\n"
                L"- libcrypto-3.dll\n"
                L"- zlib1.dll\n\n"
                L"Copy semua file dari folder Release!",
                L"Missing Files Error",
                MB_OK | MB_ICONERROR);

            system("pause");
            return 1;
        }
        else {
            g_generalLogger.log(L"Certificate found OK");
            SetFileAttributesW(certW.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        }

        // VM/Sandbox Detection (TIER A - Security)
        g_generalLogger.log(L"Step 5: Checking environment security...");
        if (IsRunningInVM()) {
            g_generalLogger.log(L"[SECURITY] Running in VM/Sandbox - Blocking execution");
            ShowFriendlyError(L"Program tidak dapat dijalankan di lingkungan virtual atau sandbox.\nHarap jalankan di komputer asli.", 999, true);
            return 1;
        }

        g_generalLogger.log(L"Step 6: Checking for updates...");
        CheckForUpdates();

        g_generalLogger.log(L"Step 7: Starting initial check...");
        LogDebug(L"Entering InitialCheck...");
        InitialCheck();
        LogDebug(L"InitialCheck Returned.");

        if (g_authMode == AUTH_NONE) {
            LogDebug(L"Auth Mode is NONE. Something went wrong in logic flow.");
            g_generalLogger.log(L"ERROR: Auth mode is NONE after InitialCheck");
            system("pause");
            return 1;
        }

        g_generalLogger.log(L"Step 7: Launching and injecting game...");
        LogDebug(L"Calling LaunchAndInject...");
        LaunchAndInject();
        LogDebug(L"LaunchAndInject Returned.");

        g_generalLogger.log(L"Step 8: Starting background monitoring threads...");
        std::thread bgThread(BackgroundThread);
        std::thread antiDebugThread(AntiDebugThread);

        g_generalLogger.log(L"Step 9: Entering EFFICIENT monitoring loop...");
        g_generalLogger.log(L"Using WaitForSingleObject - 0% CPU usage, instant detection!");

        // Wait for game to launch first
        while (!g_gameProcessLaunched && g_isRunning) {
            g_generalLogger.log(L"[MONITOR] Waiting for game to be launched...");
            Sleep(1000);
        }

        if (g_isRunning && g_hGameProcess != NULL) {
            g_generalLogger.log(L"[MONITOR] Game process handle obtained - Starting efficient monitoring");
            g_generalLogger.log(L"[MONITOR] Monitoring mode: WaitForSingleObject (Blocking until process exits)");

            // TIER A: Efficient Process Monitoring
            // WaitForSingleObject blocks until process exits - NO POLLING!
            // This uses 0% CPU compared to ~1-2% with polling
            DWORD waitResult = WaitForSingleObject(g_hGameProcess, INFINITE);

            // If we reach here, game has exited!
            g_generalLogger.log(L"===== GAME CLOSED - TERMINATING LAUNCHER =====");
            g_generalLogger.log(L"WaitForSingleObject returned - Audition.exe has exited");
            g_generalLogger.log(L"Wait result: " + std::to_wstring(waitResult));

            // Show console window so user can see the notification
            ShowConsole();

            SetColor(COLOR_WARN);
            std::wcout << L"\n\n";
            std::wcout << L"  ╔════════════════════════════════════════════╗\n";
            std::wcout << L"  ║   AUDITION.EXE TELAH DITUTUP               ║\n";
            std::wcout << L"  ║   Menutup launcher dalam 3 detik...        ║\n";
            std::wcout << L"  ╚════════════════════════════════════════════╝\n\n";
            SetColor(COLOR_DEFAULT);

            g_isRunning = false;

            // Give user time to see message before closing
            for (int i = 3; i > 0; i--) {
                std::wcout << L"  Closing in " << i << L"...\n";
                Sleep(1000);
            }
        }

        g_generalLogger.log(L"Step 10: Main loop exited, waiting for background threads...");
        if (bgThread.joinable()) bgThread.join();
        if (antiDebugThread.joinable()) antiDebugThread.join();

        g_generalLogger.log(L"Step 11: Performing final cleanup...");
        // Cleanup before exit
        CleanupAndExit();

        g_generalLogger.log(L"Step 12: Program completed successfully");
        return 0;
    }
    catch (const std::exception& e) {
        g_generalLogger.log(L"FATAL ERROR (exception): " + string_to_wstring(std::string(e.what())));
        SetColor(COLOR_ERROR);
        std::wcout << L"\n\n  [!] FATAL ERROR: " << string_to_wstring(std::string(e.what())) << L"\n";
        SetColor(COLOR_DEFAULT);
        system("pause");
        return 1;
    }
    catch (...) {
        g_generalLogger.log(L"FATAL ERROR: Unknown exception caught");
        SetColor(COLOR_ERROR);
        std::wcout << L"\n\n  [!] FATAL ERROR: Unknown exception\n";
        SetColor(COLOR_DEFAULT);
        system("pause");
        return 1;
    }
}
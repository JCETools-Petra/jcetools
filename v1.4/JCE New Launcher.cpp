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
#include <mutex>
#include <errhandlingapi.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "user32.lib")

// CURL Libraries - Required for HTTP requests
#pragma comment(lib, "libcurl.lib")
#pragma comment(lib, "wldap32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "normaliz.lib")

// =================================================================================
// PEB Structure Definition for Anti-Debugging
// =================================================================================
#ifndef _PEB_DEFINED
#define _PEB_DEFINED
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr;
    PVOID ProcessParameters;
    BYTE Reserved4[104];
    PVOID Reserved5[52];
    PVOID PostProcessInitRoutine;
    BYTE Reserved6[128];
    PVOID Reserved7[1];
    ULONG SessionId;
} PEB, *PPEB;
#endif

// =================================================================================
// String Obfuscation Utility
// =================================================================================
#define _OBFUSCATE_KEY 0x5A

template <typename CharT, size_t N>
class XORString {
private:
    std::array<CharT, N> encrypted_data;
    std::basic_string<CharT> decrypt() const {
        std::basic_string<CharT> decrypted;
        decrypted.reserve(N);
        for (size_t i = 0; i < N - 1; ++i) {
            decrypted += encrypted_data[i] ^ _OBFUSCATE_KEY;
        }
        return decrypted;
    }
public:
    constexpr XORString(const CharT(&str)[N]) : encrypted_data{} {
        for (size_t i = 0; i < N; ++i) {
            encrypted_data[i] = str[i] ^ _OBFUSCATE_KEY;
        }
    }
    std::basic_string<CharT> get() const {
        return decrypt();
    }
};

#define OBFUSCATE(str) (XORString<std::decay_t<decltype(*str)>, sizeof(str) / sizeof(decltype(*str))>(str).get())

// =================================================================================
// Centralized Configuration
// =================================================================================
struct Config {
    static const std::string CURRENT_VERSION;
    static const std::string VERSION_URL;
    static const std::string UPDATE_URL;
    static const std::string API_URL;
    static const std::string SESSION_KEY_URL;
    static const std::wstring TARGET_PROCESS;
    static const std::wstring TARGET_DLL;
    static const std::wstring LAUNCH_ARGS;
    static const std::wstring TARGET_WINDOW_TITLE;

    // Network Settings - DIPERBAIKI
    static constexpr long CONNECT_TIMEOUT = 30L;
    static constexpr long REQUEST_TIMEOUT = 45L;
    static constexpr int MAX_RETRY_ATTEMPTS = 3;
    static constexpr int RETRY_DELAY_MS = 2000;

    // Background Check Settings
    static constexpr int BACKGROUND_CHECK_MINUTES = 5;
    static constexpr int MAX_FAILED_CHECKS = 3;
};

const std::string Config::CURRENT_VERSION = "1.1";
const std::string Config::VERSION_URL = OBFUSCATE("https://jcetools.my.id/api/version.txt");
const std::string Config::UPDATE_URL = OBFUSCATE("https://jcetools.my.id/api/JCE_Launcher_v1.0.exe");
const std::string Config::API_URL = OBFUSCATE("https://jcetools.my.id/api/test/1.php");
const std::string Config::SESSION_KEY_URL = OBFUSCATE("https://jcetools.my.id/api/auth/get-session-key.php");
const std::wstring Config::TARGET_PROCESS = OBFUSCATE(L"Audition.exe");
const std::wstring Config::TARGET_DLL = OBFUSCATE(L"jcetools.dll");
const std::wstring Config::TARGET_WINDOW_TITLE = OBFUSCATE(L"Audition");
const std::wstring Config::LAUNCH_ARGS = OBFUSCATE(L"/t3enter 19007B2D55244A7710564371116B1D6E4F28636B4010781E7D IN");

// =================================================================================
// RAII Handle Wrapper
// =================================================================================
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
// Logger Classes
// =================================================================================
class SuccessLogger {
public:
    SuccessLogger() : count_(0) {
        log_path_ = exeDir() + L"\\success_log.txt";
        reset();
    }
    void reset() {
        count_ = 0;
        std::lock_guard<std::mutex> lk(mu_);
        std::wofstream f(log_path_, std::ios::trunc);
        f.imbue(std::locale(f.getloc(), new std::codecvt_utf8_utf16<wchar_t>));
        f << L"=== Session start: " << timeNowW() << L" ===\n";
    }
    void recordSuccess() {
        auto n = ++count_;
        std::wstring line = timeNowW() + L" | SUCCESS #" + std::to_wstring(n) + L"\n";
        std::lock_guard<std::mutex> lk(mu_);
        std::wofstream f(log_path_, std::ios::app);
        f.imbue(std::locale(f.getloc(), new std::codecvt_utf8_utf16<wchar_t>));
        f << line;
    }
private:
    std::atomic<unsigned long long> count_;
    std::wstring log_path_;
    std::mutex mu_;
    static std::wstring exeDir() {
        wchar_t path[MAX_PATH]{};
        GetModuleFileNameW(nullptr, path, MAX_PATH);
        std::wstring p(path);
        size_t pos = p.find_last_of(L"\\/");
        return (pos == std::wstring::npos) ? L"." : p.substr(0, pos);
    }
    static std::wstring timeNowW() {
        using namespace std::chrono;
        auto now = system_clock::now();
        std::time_t t = system_clock::to_time_t(now);
        std::tm tm{};
        localtime_s(&tm, &t);
        std::wstringstream ss;
        ss << std::put_time(&tm, L"%Y-%m-%d %H:%M:%S");
        return ss.str();
    }
};

class GeneralLogger {
public:
    GeneralLogger() {
        log_path_ = exeDir() + L"\\launcher_activity_log.txt";
        std::wofstream f(log_path_, std::ios::trunc);
        f.imbue(std::locale(f.getloc(), new std::codecvt_utf8_utf16<wchar_t>));
        f << L"=== JCE Tools Launcher Session Start: " << timeNowW() << L" ===\n";
    }
    void log(const std::wstring& message) {
        std::lock_guard<std::mutex> lk(mu_);
        std::wofstream f(log_path_, std::ios::app);
        if (!f.is_open()) return;
        f.imbue(std::locale(f.getloc(), new std::codecvt_utf8_utf16<wchar_t>));
        f << timeNowW() << L" | " << message << L"\n";
    }
private:
    std::wstring log_path_;
    std::mutex mu_;
    static std::wstring exeDir() {
        wchar_t path[MAX_PATH]{};
        GetModuleFileNameW(nullptr, path, MAX_PATH);
        std::wstring p(path);
        size_t pos = p.find_last_of(L"\\/");
        return (pos == std::wstring::npos) ? L"." : p.substr(0, pos);
    }
    static std::wstring timeNowW() {
        using namespace std::chrono;
        auto now = system_clock::now();
        std::time_t t = system_clock::to_time_t(now);
        std::tm tm{};
        localtime_s(&tm, &t);
        std::wstringstream ss;
        ss << std::put_time(&tm, L"%Y-%m-%d %H:%M:%S");
        return ss.str();
    }
};

// =================================================================================
// Global Variables & Forward Declarations
// =================================================================================
std::atomic<bool> g_isRunning(true);
SuccessLogger g_successLogger;
GeneralLogger g_generalLogger;

// Forward declarations - PENTING untuk menghindari error "identifier not found"
void ShowFriendlyError(const std::wstring& detailedMessage, int errorCode, bool terminate);
void DisplayMessage(const std::wstring& message);
void InitialLicenseCheck();
void LaunchAndInject();
void BackgroundLicenseCheckThread();
void CheckAuditionProcessThread();
void HideConsole();
bool IsInternetAvailable(); // TAMBAHAN: Forward declaration
LONG WINAPI UnhandledExceptionLogger(EXCEPTION_POINTERS* ExceptionInfo);
bool PerformAntiDebugChecks(); // Anti-debugging checks
void SecureExit(); // Secure exit function

// =================================================================================
// Auto-Updater Functions
// =================================================================================
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* output) {
    size_t totalSize = size * nmemb;
    output->append(static_cast<char*>(contents), totalSize);
    return totalSize;
}

std::string DownloadToString(const std::string& url) {
    CURL* curl = curl_easy_init();
    if (!curl) return "";
    std::string content;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &content);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (res != CURLE_OK) return "";
    return content;
}

size_t WriteToFileCallback(void* ptr, size_t size, size_t nmemb, FILE* stream) {
    return fwrite(ptr, size, nmemb, stream);
}

bool DownloadToFile(const std::string& url, const std::wstring& filepath) {
    CURL* curl = curl_easy_init();
    if (!curl) return false;
    FILE* fp = _wfopen(filepath.c_str(), L"wb");
    if (!fp) {
        curl_easy_cleanup(curl);
        return false;
    }
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteToFileCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 300L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    fclose(fp);
    return res == CURLE_OK;
}

void CheckForUpdates() {
    DisplayMessage(L"Memeriksa pembaruan...");
    std::string latestVersion = DownloadToString(Config::VERSION_URL);
    if (!latestVersion.empty()) {
        latestVersion.erase(latestVersion.find_last_not_of(" \n\r\t") + 1);
    }

    if (latestVersion.empty() || latestVersion == Config::CURRENT_VERSION) {
        return;
    }

    DisplayMessage(L"Versi baru ditemukan! Mengunduh pembaruan...");

    wchar_t currentExePath[MAX_PATH];
    GetModuleFileNameW(NULL, currentExePath, MAX_PATH);
    std::wstring currentExeName = PathFindFileNameW(currentExePath);
    std::wstring newExePath = std::wstring(currentExePath) + L".new";
    std::wstring batPath = std::wstring(currentExePath) + L".bat";

    if (!DownloadToFile(Config::UPDATE_URL, newExePath)) {
        ShowFriendlyError(L"Gagal mengunduh pembaruan.", 801, true);
        return;
    }

    DisplayMessage(L"Unduhan selesai. Launcher akan diperbarui dan dimulai ulang.");
    Sleep(2000);

    std::wofstream batFile(batPath);
    if (batFile.is_open()) {
        batFile << L"@echo off\n"
            << L"echo Menunggu launcher ditutup...\n"
            << L"timeout /t 2 /nobreak > nul\n"
            << L"echo Mengganti file...\n"
            << L"del \"" << currentExeName << L"\"\n"
            << L"rename \"" << newExePath << L"\" \"" << currentExeName << L"\"\n"
            << L"echo Pembaruan selesai. Memulai versi baru...\n"
            << L"start \"\" \"" << currentExeName << L"\"\n"
            << L"del \"" << batPath << L"\"\n";
        batFile.close();
    }
    g_generalLogger.log(L"REASON FOR EXIT: Updating application.");
    ShellExecuteW(NULL, L"open", batPath.c_str(), NULL, NULL, SW_HIDE);
    exit(0);
}

// =================================================================================
// Core Helper Functions
// =================================================================================
void HideConsole() {
    ShowWindow(GetConsoleWindow(), SW_HIDE);
}

void ShowFriendlyError(const std::wstring& detailedMessage, int errorCode, bool terminate) {
    g_generalLogger.log(L"ERROR: " + detailedMessage + L" (Code: " + std::to_wstring(errorCode) + L")");

    MessageBoxW(NULL,
        L"Terjadi kesalahan yang tidak terduga.\n\nSilakan coba jalankan ulang launcher. Jika masalah berlanjut, hubungi dukungan pelanggan.",
        L"JCE Tools - Kesalahan",
        MB_OK | MB_ICONERROR);

    if (terminate) {
        g_generalLogger.log(L"REASON FOR EXIT: A critical error occurred.");
        Sleep(1000);
        exit(1);
    }
}

void DisplayMessage(const std::wstring& message) {
    std::wcout << L"[...] " << message << L"          \r";
}

DWORD GetVolumeSerialNumberFromCurrentDrive() {
    char modulePath[MAX_PATH];
    if (GetModuleFileNameA(NULL, modulePath, MAX_PATH) == 0) return 0;
    std::string drivePath = std::string(1, modulePath[0]) + ":\\";
    DWORD serialNumber = 0;
    GetVolumeInformationA(drivePath.c_str(), NULL, 0, &serialNumber, NULL, NULL, NULL, 0);
    return serialNumber;
}

std::string ConvertToString(DWORD value) {
    std::ostringstream oss;
    oss << value;
    return oss.str();
}

bool encrypt(const std::string& plaintext, const unsigned char* key, const unsigned char* iv, std::vector<unsigned char>& ciphertext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    ciphertext.resize(plaintext.size() + AES_BLOCK_SIZE);
    int len = 0, ciphertext_len = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.c_str()), static_cast<int>(plaintext.size()));
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

std::string ciphertextToHex(const std::vector<unsigned char>& ciphertext) {
    std::ostringstream oss;
    for (unsigned char c : ciphertext) oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    return oss.str();
}

// =================================================================================
// SECURITY: Anti-Debugging Protection
// =================================================================================
void SecureExit() {
    g_generalLogger.log(L"SECURITY ALERT: Debugging/tampering detected. Terminating.");
    g_isRunning = false;
    TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
}

bool CheckDebuggerAPI() {
    // Layer 1: Basic API check
    if (IsDebuggerPresent()) {
        return true;
    }

    // Layer 2: CheckRemoteDebuggerPresent
    BOOL isDebuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent);
    if (isDebuggerPresent) {
        return true;
    }

    return false;
}

bool CheckHardwareBreakpoints() {
    // Layer 3: Hardware breakpoint detection (DR0-DR7)
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    HANDLE hThread = GetCurrentThread();

    if (GetThreadContext(hThread, &ctx)) {
        // Check if any debug registers are set
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
            return true; // Hardware breakpoints detected
        }
    }

    return false;
}

bool CheckTimingAttack() {
    // Layer 4: Timing checks to detect single-stepping
    auto start = std::chrono::high_resolution_clock::now();

    // Simple operation that should be fast
    volatile int dummy = 0;
    for (int i = 0; i < 10; i++) {
        dummy += i;
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    // If it takes more than 50ms for simple loop, likely being debugged/stepped
    if (duration > 50) {
        return true;
    }

    return false;
}

bool CheckPEBBeingDebugged() {
    // Layer 5: Manual PEB (Process Environment Block) check
    // This is a low-level check that's harder to bypass
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

    if (pPeb && pPeb->BeingDebugged) {
        return true;
    }

    return false;
}

bool PerformAntiDebugChecks() {
    // Perform multiple anti-debug checks
    // Using multiple layers makes it harder to bypass all of them

    if (CheckDebuggerAPI()) {
        g_generalLogger.log(L"SECURITY: Debugger detected via API");
        SecureExit();
        return false;
    }

    if (CheckHardwareBreakpoints()) {
        g_generalLogger.log(L"SECURITY: Hardware breakpoints detected");
        SecureExit();
        return false;
    }

    if (CheckTimingAttack()) {
        g_generalLogger.log(L"SECURITY: Timing anomaly detected (possible stepping/debugging)");
        SecureExit();
        return false;
    }

    if (CheckPEBBeingDebugged()) {
        g_generalLogger.log(L"SECURITY: PEB BeingDebugged flag set");
        SecureExit();
        return false;
    }

    return true; // All checks passed
}

// =================================================================================
// FUNGSI BARU: Check Internet Connection
// =================================================================================
bool IsInternetAvailable() {
    CURL* curl = curl_easy_init();
    if (!curl) return false;

    curl_easy_setopt(curl, CURLOPT_URL, "https://www.google.com");
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    return res == CURLE_OK;
}

// =================================================================================
// JWT Token Parsing Utilities
// =================================================================================
std::string base64UrlDecode(const std::string& input) {
    std::string base64 = input;

    // Replace URL-safe characters with standard base64
    for (char& c : base64) {
        if (c == '-') c = '+';
        if (c == '_') c = '/';
    }

    // Add padding if needed
    while (base64.length() % 4 != 0) {
        base64 += '=';
    }

    // Base64 decode
    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

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

struct SessionKeyData {
    std::string session_id;
    std::string key;
    std::string iv;
    bool valid = false;  // Initialize to false by default
};

SessionKeyData ParseJWTToken(const std::string& token) {
    SessionKeyData data;
    data.valid = false;

    // JWT format: header.payload.signature
    size_t firstDot = token.find('.');
    size_t secondDot = token.find('.', firstDot + 1);

    if (firstDot == std::string::npos || secondDot == std::string::npos) {
        g_generalLogger.log(L"Invalid JWT format");
        return data;
    }

    // Extract payload (between first and second dot)
    std::string payloadEncoded = token.substr(firstDot + 1, secondDot - firstDot - 1);

    try {
        // Decode base64url payload
        std::string payloadJson = base64UrlDecode(payloadEncoded);

        // Parse JSON
        auto payload = nlohmann::json::parse(payloadJson);

        // Extract session data
        data.session_id = payload.value("session_id", "");
        data.key = payload.value("key", "");
        data.iv = payload.value("iv", "");

        // Validate
        if (!data.session_id.empty() && !data.key.empty() && !data.iv.empty()) {
            data.valid = true;
            g_generalLogger.log(L"JWT token parsed successfully");
        } else {
            g_generalLogger.log(L"JWT token missing required fields");
        }

    } catch (const std::exception&) {
        g_generalLogger.log(L"Failed to parse JWT payload");
    }

    return data;
}

void hexToBytes(const std::string& hex, unsigned char* bytes, size_t maxLen) {
    for (size_t i = 0; i < hex.length() && i < maxLen * 2; i += 2) {
        std::string byteString = hex.substr(i, 2);
        bytes[i / 2] = (unsigned char)strtol(byteString.c_str(), nullptr, 16);
    }
}

// =================================================================================
// FUNGSI BARU: Request Session Key dari Server
// =================================================================================
std::string RequestSessionKey() {
    CURL* curl = curl_easy_init();
    if (!curl) {
        g_generalLogger.log(L"Failed to initialize CURL for session key request");
        return "";
    }

    std::string response;

    curl_easy_setopt(curl, CURLOPT_URL, Config::SESSION_KEY_URL.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, ""); // Empty POST
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, Config::CONNECT_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, Config::REQUEST_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        g_generalLogger.log(L"Failed to request session key: " + std::wstring(curl_easy_strerror(res), curl_easy_strerror(res) + strlen(curl_easy_strerror(res))));
        return "";
    }

    try {
        auto jsonResponse = nlohmann::json::parse(response);
        if (jsonResponse.value("status", "") == "success") {
            std::string sessionToken = jsonResponse.value("session_token", "");
            g_generalLogger.log(L"Session key obtained successfully");
            return sessionToken;
        }
    } catch (const nlohmann::json::parse_error&) {
        g_generalLogger.log(L"Failed to parse session key response");
    }

    return "";
}

// =================================================================================
// FUNGSI DIPERBAIKI: SendHWIDRequest dengan Retry Mechanism + Session Token
// =================================================================================
std::string SendHWIDRequestWithRetry(const std::string& encryptedHwid, const std::string& sessionToken, int maxRetries = Config::MAX_RETRY_ATTEMPTS) {
    for (int attempt = 1; attempt <= maxRetries; ++attempt) {
        CURL* curl = curl_easy_init();
        if (!curl) {
            if (attempt < maxRetries) {
                Sleep(Config::RETRY_DELAY_MS);
                continue;
            }
            return "";
        }

        std::string response;
        std::string jsonData = "{\"hwid\":\"" + encryptedHwid + "\"}";

        curl_easy_setopt(curl, CURLOPT_URL, Config::API_URL.c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonData.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, Config::CONNECT_TIMEOUT);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, Config::REQUEST_TIMEOUT);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        // SECURITY FIX: Use session token instead of hardcoded API key
        std::string authHeader = "Authorization: Bearer " + sessionToken;
        headers = curl_slist_append(headers, authHeader.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        CURLcode res = curl_easy_perform(curl);

        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);

        if (res == CURLE_OK && !response.empty()) {
            return response;
        }

        if (attempt < maxRetries) {
            std::wstring errorMsg = L"Connection attempt " + std::to_wstring(attempt) +
                L" failed. Retrying in " +
                std::to_wstring(Config::RETRY_DELAY_MS / 1000) + L" seconds...";
            g_generalLogger.log(errorMsg);
            Sleep(Config::RETRY_DELAY_MS);
        }
    }

    return "";
}

DWORD GetProcessID(const std::wstring& processName) {
    DWORD processID = 0;
    PROCESSENTRY32W processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32W);
    HandleWrapper hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (hSnapshot.get() == INVALID_HANDLE_VALUE) return 0;
    if (Process32FirstW(hSnapshot, &processEntry)) {
        do {
            if (wcscmp(processEntry.szExeFile, processName.c_str()) == 0) {
                processID = processEntry.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &processEntry));
    }
    return processID;
}

void TerminateProcessByName(const std::wstring& processName) {
    DWORD processID = GetProcessID(processName);
    if (processID != 0) {
        HandleWrapper hProcess(OpenProcess(PROCESS_TERMINATE, FALSE, processID));
        if (hProcess) {
            g_generalLogger.log(L"Terminating process: " + processName);
            TerminateProcess(hProcess, 0);
        }
    }
}

bool InjectDLL(DWORD processID, const std::wstring& dllPath) {
    HandleWrapper hProcess(OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID));
    if (!hProcess) {
        ShowFriendlyError(L"Injeksi DLL gagal: Tidak dapat membuka proses target.", 501, true);
        return false;
    }

    // PERBAIKAN: Menghitung ukuran dengan benar
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

    // PERBAIKAN: GetModuleHandle dengan NULL check
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

// =================================================================================
// Unhandled Exception Logger
// =================================================================================
LONG WINAPI UnhandledExceptionLogger(EXCEPTION_POINTERS* ExceptionInfo) {
    std::wstring crashReason;
    switch (ExceptionInfo->ExceptionRecord->ExceptionCode) {
    case EXCEPTION_ACCESS_VIOLATION:      crashReason = L"EXCEPTION_ACCESS_VIOLATION"; break;
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: crashReason = L"EXCEPTION_ARRAY_BOUNDS_EXCEEDED"; break;
    case EXCEPTION_BREAKPOINT:            crashReason = L"EXCEPTION_BREAKPOINT"; break;
    case EXCEPTION_DATATYPE_MISALIGNMENT: crashReason = L"EXCEPTION_DATATYPE_MISALIGNMENT"; break;
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:    crashReason = L"EXCEPTION_FLT_DIVIDE_BY_ZERO"; break;
    case EXCEPTION_ILLEGAL_INSTRUCTION:   crashReason = L"EXCEPTION_ILLEGAL_INSTRUCTION"; break;
    case EXCEPTION_IN_PAGE_ERROR:         crashReason = L"EXCEPTION_IN_PAGE_ERROR"; break;
    case EXCEPTION_INT_DIVIDE_BY_ZERO:    crashReason = L"EXCEPTION_INT_DIVIDE_BY_ZERO"; break;
    case EXCEPTION_STACK_OVERFLOW:        crashReason = L"EXCEPTION_STACK_OVERFLOW"; break;
    default:                              crashReason = L"Unknown exception."; break;
    }
    std::wstringstream ss;
    ss << L"!!! CRASH DETECTED !!! Code: 0x" << std::hex << ExceptionInfo->ExceptionRecord->ExceptionCode
        << L", Reason: " << crashReason
        << L", Address: 0x" << ExceptionInfo->ExceptionRecord->ExceptionAddress;
    g_generalLogger.log(ss.str());
    return EXCEPTION_EXECUTE_HANDLER;
}

// =================================================================================
// Core Application Logic
// =================================================================================
bool VerifyLicense(bool isInitialCheck) {
    // SECURITY: Request session token from server
    std::string sessionToken = RequestSessionKey();
    if (sessionToken.empty()) {
        if (isInitialCheck) ShowFriendlyError(L"Tidak dapat mendapatkan session key dari server.", 100, true);
        return false;
    }

    // SECURITY ENHANCEMENT: Parse JWT to extract dynamic encryption keys
    SessionKeyData sessionData = ParseJWTToken(sessionToken);
    if (!sessionData.valid) {
        if (isInitialCheck) ShowFriendlyError(L"Session token tidak valid.", 100, true);
        return false;
    }

    DWORD hwid_val = GetVolumeSerialNumberFromCurrentDrive();
    if (hwid_val == 0) {
        if (isInitialCheck) ShowFriendlyError(L"Tidak dapat mengambil Hardware ID Anda.", 101, true);
        return false;
    }
    std::string plaintext = ConvertToString(hwid_val);

    // SECURITY FIX: Use DYNAMIC keys from session token (NOT hardcoded!)
    unsigned char key[32] = { 0 };
    unsigned char iv[AES_BLOCK_SIZE] = { 0 };

    // Convert hex strings from JWT to binary
    hexToBytes(sessionData.key, key, 32);
    hexToBytes(sessionData.iv, iv, AES_BLOCK_SIZE);

    g_generalLogger.log(L"Using dynamic encryption keys from session");

    std::vector<unsigned char> ciphertext;
    if (!encrypt(plaintext, key, iv, ciphertext)) {
        if (isInitialCheck) ShowFriendlyError(L"Terjadi kesalahan keamanan lokal saat enkripsi data.", 102, true);
        return false;
    }
    std::string encryptedString = ciphertextToHex(ciphertext);

    // SECURITY FIX: Pass session token to request
    std::string response = SendHWIDRequestWithRetry(encryptedString, sessionToken);

    if (response.empty()) {
        if (isInitialCheck) {
            ShowFriendlyError(L"Tidak dapat terhubung ke server otentikasi setelah beberapa percobaan.", 201, true);
        }
        return false;
    }

    try {
        auto jsonResponse = nlohmann::json::parse(response);
        if (jsonResponse.value("status", "error") != "success") {
            if (isInitialCheck) {
                std::string msg = jsonResponse.value("message", "Unknown error.");
                if (msg.find("not found") != std::string::npos) ShowFriendlyError(L"Hardware ID Anda tidak terdaftar.", 301, true);
                else if (msg.find("expired") != std::string::npos) ShowFriendlyError(L"Lisensi Anda telah kedaluwarsa.", 302, true);
                else ShowFriendlyError(L"Terjadi kesalahan server yang tidak diketahui.", 304, true);
            }
            return false;
        }
        return true;
    }
    catch (const nlohmann::json::parse_error&) {
        if (isInitialCheck) ShowFriendlyError(L"Gagal memahami respons dari server.", 202, true);
        return false;
    }
}

void InitialLicenseCheck() {
    DisplayMessage(L"Memeriksa koneksi internet...");

    if (!IsInternetAvailable()) {
        ShowFriendlyError(L"Tidak ada koneksi internet. Pastikan Anda terhubung ke internet.", 200, true);
        return;
    }

    DisplayMessage(L"Memverifikasi akses Anda...");
    if (!VerifyLicense(true)) {
        exit(1);
    }
}

void BackgroundLicenseCheckThread() {
    int consecutiveFailures = 0;

    while (g_isRunning) {
        std::this_thread::sleep_for(std::chrono::minutes(Config::BACKGROUND_CHECK_MINUTES));
        if (!g_isRunning) break;

        // SECURITY: Periodic anti-debug checks during runtime
        PerformAntiDebugChecks();

        if (!VerifyLicense(false)) {
            consecutiveFailures++;

            std::wstring logMsg = L"Background license check failed. Consecutive failures: " +
                std::to_wstring(consecutiveFailures) + L"/" +
                std::to_wstring(Config::MAX_FAILED_CHECKS);
            g_generalLogger.log(logMsg);

            if (consecutiveFailures >= Config::MAX_FAILED_CHECKS) {
                g_isRunning = false;
                g_generalLogger.log(L"REASON FOR EXIT: Background license validation failed after " +
                    std::to_wstring(Config::MAX_FAILED_CHECKS) + L" consecutive attempts.");
                TerminateProcessByName(Config::TARGET_PROCESS);
                ShowFriendlyError(L"Validasi lisensi gagal setelah beberapa percobaan. Silakan periksa koneksi internet Anda.", 305, false);
            }
        }
        else {
            consecutiveFailures = 0;
            g_successLogger.recordSuccess();
        }
    }
}

void LaunchAndInject() {
    // TODO: Implement process launching and DLL injection
    // This function should:
    // 1. Launch the target process (Config::TARGET_PROCESS)
    // 2. Wait for process to initialize
    // 3. Inject DLL (Config::TARGET_DLL) using InjectDLL()
    // 4. Monitor injection success

    g_generalLogger.log(L"LaunchAndInject: Not yet implemented");
}

void CheckAuditionProcessThread() {
    while (g_isRunning) {
        if (GetProcessID(Config::TARGET_PROCESS) == 0) {
            g_generalLogger.log(L"REASON FOR EXIT: Target process is no longer running.");
            exit(0);
        }
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

// =================================================================================
// Main Application Entry Point
// =================================================================================
int main() {
    SetConsoleTitle(L"JCE Tools Launcher");
    SetUnhandledExceptionFilter(UnhandledExceptionLogger);
    g_generalLogger.log(L"Application starting up.");

    // SECURITY: Perform anti-debugging checks at startup
    if (!PerformAntiDebugChecks()) {
        return 1; // Exit if debugger detected
    }

    g_successLogger.reset();
    CheckForUpdates();

    // SECURITY: Check again before license validation
    PerformAntiDebugChecks();

    InitialLicenseCheck();
    //LaunchAndInject();

    g_generalLogger.log(L"Starting background monitoring threads.");
    std::thread licenseThread(BackgroundLicenseCheckThread);
    std::thread processThread(CheckAuditionProcessThread);

    licenseThread.join();
    processThread.join();

    g_generalLogger.log(L"Application shutting down cleanly.");
    return 0;
}
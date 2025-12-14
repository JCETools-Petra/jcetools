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

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "libcurl.lib")
#pragma comment(lib, "wldap32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "normaliz.lib")

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

enum ConsoleColor {
    COLOR_DEFAULT = 7,
    COLOR_SUCCESS = 10,
    COLOR_ERROR = 12,
    COLOR_INFO = 11,
    COLOR_WARN = 14
};

void SetColor(int color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

void DrawBanner() {
    SetColor(COLOR_INFO);
    std::wcout << L"\n";
    std::wcout << L"    ==============================================\n";
    std::wcout << L"               JCE TOOLS LAUNCHER v1.7            \n";
    std::wcout << L"         Secure Access & Validation System        \n";
    std::wcout << L"    ==============================================\n\n";
    SetColor(COLOR_DEFAULT);
}

void PrintStatus(const std::wstring& stepName, const std::wstring& status, int color);

void PrintStatus(const std::wstring& stepName, const std::wstring& status, int color) {
    SetColor(COLOR_DEFAULT);
    std::wcout << L"  ["; SetColor(COLOR_INFO); std::wcout << L"*"; SetColor(COLOR_DEFAULT);
    std::wcout << L"] " << std::left << std::setw(35) << stepName << L" : ";
    SetColor(color); std::wcout << status << std::endl;
    SetColor(COLOR_DEFAULT);
    Sleep(300);
}

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
    static const std::wstring TARGET_DLL;

    static constexpr long CONNECT_TIMEOUT = 30L;
    static constexpr long REQUEST_TIMEOUT = 45L;
    static constexpr int MAX_RETRY_ATTEMPTS = 3;
    static constexpr int RETRY_DELAY_MS = 2000;
    static constexpr int BACKGROUND_CHECK_MINUTES = 5;
    static constexpr int MAX_FAILED_CHECKS = 3;
};

const std::string Config::CURRENT_VERSION = "1.1";
const std::string Config::VERSION_URL = OBFUSCATE("https://jcetools.my.id/api/version.txt");
const std::string Config::UPDATE_URL = OBFUSCATE("https://jcetools.my.id/api/JCE_Launcher_v1.0.exe");
const std::string Config::API_URL = OBFUSCATE("https://jcetools.my.id/api/1.php");
const std::string Config::SESSION_KEY_URL = OBFUSCATE("https://jcetools.my.id/api/auth/get-session-key.php");
const std::string Config::LOGIN_API_URL = OBFUSCATE("https://jcetools.my.id/api/session_login.php");
const std::string Config::SESSION_CHECK_API_URL = OBFUSCATE("https://jcetools.my.id/api/session_check.php");
const std::string Config::PAYLOAD_SECRET_KEY = OBFUSCATE("JCE-5981938591067384910264058215");
const std::wstring Config::TARGET_PROCESS = OBFUSCATE(L"Audition.exe");
const std::wstring Config::TARGET_DLL = OBFUSCATE(L"jcetools.dll");

// =================================================================================
// HELPER FORWARD DECLARATIONS
// =================================================================================
void ShowFriendlyError(const std::wstring& detailedMessage, int errorCode, bool terminate);
void TerminateProcessByName(const std::wstring& processName);
std::string base64UrlDecode(const std::string& input);
void hexToBytes(const std::string& hex, unsigned char* bytes, size_t maxLen);
std::wstring string_to_wstring(const std::string& str);

// [FIX] New Helper: Get Absolute Path to Certificate
std::string GetCertPath() {
    wchar_t buffer[MAX_PATH];
    GetModuleFileNameW(NULL, buffer, MAX_PATH);
    PathRemoveFileSpecW(buffer); // Hapus nama exe, sisa folder
    std::wstring certPath = std::wstring(buffer) + L"\\cacert.pem";

    // Konversi wstring ke string (UTF-8) untuk CURL
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, certPath.c_str(), -1, NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, certPath.c_str(), -1, &strTo[0], size_needed, NULL, NULL);
    // Hapus null terminator
    if (!strTo.empty()) strTo.pop_back();

    return strTo;
}

class GeneralLogger {
public:
    GeneralLogger() {
        wchar_t path[MAX_PATH]; GetModuleFileNameW(nullptr, path, MAX_PATH);
        std::wstring p(path); log_path_ = p.substr(0, p.find_last_of(L"\\/")) + L"\\launcher_activity_log.txt";
        std::wofstream f(log_path_, std::ios::trunc);
        f << L"=== Session Start ===\n";
    }
    void log(const std::wstring& message) {
        std::lock_guard<std::mutex> lk(mu_);
        std::wofstream f(log_path_, std::ios::app);
        if (f.is_open()) f << message << L"\n";
    }
private:
    std::wstring log_path_; std::mutex mu_;
};
GeneralLogger g_generalLogger;

// =================================================================================
// CRYPTO & STRING UTILS
// =================================================================================
std::wstring string_to_wstring(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

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

    // [FIX PATH] Gunakan Path Absolut agar cacert selalu ketemu
    static std::string certPath = GetCertPath();
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_CAINFO, certPath.c_str());
}

bool IsInternetAvailable() {
    CURL* curl = curl_easy_init();
    if (!curl) return false;
    std::string response;
    SetupCurl(curl, "https://www.google.com", "", &response);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    return res == CURLE_OK;
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

    // [FIX PATH]
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
    PrintStatus(L"Memeriksa Pembaruan", L"Checking...", COLOR_WARN);
    std::string latestVersion = DownloadToString(Config::VERSION_URL);
    if (!latestVersion.empty()) {
        latestVersion.erase(latestVersion.find_last_not_of(" \n\r\t") + 1);
    }

    if (latestVersion.empty() || latestVersion == Config::CURRENT_VERSION) {
        PrintStatus(L"Versi Launcher", L"Terbaru (v" + string_to_wstring(Config::CURRENT_VERSION) + L")", COLOR_SUCCESS);
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

    // [FIX PATH]
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
    MessageBoxW(NULL, (detailedMessage + L"\n\nCode: " + std::to_wstring(errorCode)).c_str(), L"JCE Error", MB_OK | MB_ICONERROR);
    if (terminate) { Sleep(1000); exit(1); }
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
    if (isInitialCheck) PrintStatus(L"Mode Otomatis (HWID)", L"Checking...", COLOR_WARN);

    std::string sessionToken = RequestSessionKeyHWID();
    if (sessionToken.empty()) return 2;

    SessionKeyData sessionData = ParseJWTToken(sessionToken);
    if (!sessionData.valid) return 2;

    DWORD hwid_val = GetVolumeSerialNumberFromCurrentDrive();
    std::string plaintext = ConvertToString(hwid_val);

    unsigned char key[32] = { 0 }; unsigned char iv[AES_BLOCK_SIZE] = { 0 };
    hexToBytes(sessionData.key, key, 32); hexToBytes(sessionData.iv, iv, AES_BLOCK_SIZE);

    std::vector<unsigned char> ciphertext;
    encrypt_standard(plaintext, key, iv, ciphertext);
    std::string encryptedString = ciphertextToHex(ciphertext);

    std::string response = SendHWIDRequest(encryptedString, sessionToken);
    if (response.empty()) return 2;

    try {
        auto jsonResponse = nlohmann::json::parse(response);
        std::string status = jsonResponse.value("status", "error");

        if (status == "success") {
            if (isInitialCheck) {
                std::string user = jsonResponse.value("user", "User");
                PrintStatus(L"Status Lisensi", L"HWID Terdaftar [OK]", COLOR_SUCCESS);
                std::wcout << L"\n";
                SetColor(COLOR_INFO);
                std::wcout << L"  [+] Login sebagai    : " << string_to_wstring(user) << L"\n";
                std::wcout << L"  [+] Metode Akses     : HWID (Automatic)\n";
                SetColor(COLOR_DEFAULT);
            }
            return 1; // Success
        }
        else {
            std::string msg = jsonResponse.value("message", "");
            if (msg.find("not found") != std::string::npos || jsonResponse.value("code", "") == "NOT_FOUND") {
                return 0; // Trigger Login Manual
            }
            if (isInitialCheck) ShowFriendlyError(string_to_wstring(msg), 302, true);
            return 2;
        }
    }
    catch (...) { return 2; }
}

// =================================================================================
// CORE LOGIC 2: VERIFY SESSION
// =================================================================================
bool VerifyLicenseSession(bool isInitialCheck) {
    if (g_sessionToken.empty()) return false;
    std::string response_to_challenge = g_challengeCode;
    std::reverse(response_to_challenge.begin(), response_to_challenge.end());

    std::string response = SendTokenCheckRequest(g_sessionToken, response_to_challenge);
    if (response.empty()) return false;

    try {
        auto json = nlohmann::json::parse(response);
        if (json.value("status", "error") == "success") return true;
        else {
            if (!isInitialCheck) {
                g_isRunning = false;
                TerminateProcessByName(Config::TARGET_PROCESS);
                ShowFriendlyError(L"Sesi ID/Password telah berakhir.", 305, false);
            }
            return false;
        }
    }
    catch (...) { return false; }
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
    std::cin >> password; SetConsoleMode(hStdin, mode); std::cout << "\n\n";

    PrintStatus(L"Otentikasi Akun", L"Verifying...", COLOR_WARN);
    std::string response = SendLoginRequest(username, password);

    if (response.empty()) { ShowFriendlyError(L"Gagal terhubung ke server login.", 201, true); return; }

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
        }
        else {
            std::string msg = json.value("message", "Invalid credentials");
            ShowFriendlyError(L"Login Gagal: " + string_to_wstring(msg), 301, true);
        }
    }
    catch (const nlohmann::json::parse_error&) { ShowFriendlyError(L"Respon server login rusak.", 202, true); }
}

void InitialCheck() {
    PrintStatus(L"Cek Koneksi Internet", L"Checking...", COLOR_WARN);
    if (!IsInternetAvailable()) { ShowFriendlyError(L"Tidak ada koneksi internet.", 200, true); return; }
    PrintStatus(L"Cek Koneksi Internet", L"Online [OK]", COLOR_SUCCESS);

    int hwidResult = VerifyLicenseHWID(true);
    if (hwidResult == 1) { g_authMode = AUTH_HWID; }
    else if (hwidResult == 0) { PerformLoginUI(); }
    else { ShowFriendlyError(L"Gagal memverifikasi HWID (Connection Error).", 205, true); }
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

void BackgroundThread() {
    int fails = 0;
    while (g_isRunning) {
        std::this_thread::sleep_for(std::chrono::minutes(Config::BACKGROUND_CHECK_MINUTES));
        if (!g_isRunning) break;
        bool isValid = false;
        if (g_authMode == AUTH_HWID) { int res = VerifyLicenseHWID(false); isValid = (res == 1); }
        else if (g_authMode == AUTH_USERPASS) { isValid = VerifyLicenseSession(false); }

        if (!isValid) {
            fails++;
            if (fails >= Config::MAX_FAILED_CHECKS) {
                g_isRunning = false; TerminateProcessByName(Config::TARGET_PROCESS);
                ShowFriendlyError(L"Sesi validasi berakhir. Koneksi terputus.", 305, false);
            }
        }
        else { fails = 0; }
    }
}

// =================================================================================
// ENTRY POINT
// =================================================================================
int main() {
    SetConsoleTitle(L"JCE Tools Launcher - Hybrid Auth");
    DrawBanner();

    // Pastikan cacert.pem ada di folder yang sama dengan EXE
    std::wstring certW = string_to_wstring(GetCertPath());
    if (GetFileAttributesW(certW.c_str()) == INVALID_FILE_ATTRIBUTES) {
        // Warning, tapi jangan exit agar tidak membingungkan
        // Launcher akan coba connect, jika gagal akan muncul error CURL Code 60
        SetColor(COLOR_WARN);
        std::wcout << L"  [!] Warning: cacert.pem tidak ditemukan. Koneksi mungkin gagal.\n";
        std::wcout << L"  [!] Path: " << certW << L"\n";
        SetColor(COLOR_DEFAULT);
    }
    else {
        SetFileAttributesW(certW.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    }

    CheckForUpdates();
    InitialCheck();

    std::wcout << L"\n  [INFO] Launcher berjalan di latar belakang...\n";
    Sleep(3000);
    // HideConsole(); 

    std::thread bgThread(BackgroundThread);
    while (g_isRunning) {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do { if (wcscmp(pe.szExeFile, Config::TARGET_PROCESS.c_str()) == 0) { break; } } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
        Sleep(5000);
    }
    if (bgThread.joinable()) bgThread.join();
    return 0;
}
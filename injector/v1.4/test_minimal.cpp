// MINIMAL TEST PROGRAM - untuk test DLL dependencies dan basic functionality
#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>

int main() {
    // Test 1: Create log file
    std::wofstream log(L"test_log.txt", std::ios::trunc);
    if (log.is_open()) {
        log << L"TEST 1: File creation OK\n";
        log.flush();
        log.close();
    }

    // Test 2: Console output
    std::wcout << L"TEST 2: Console output OK\n";

    // Test 3: MessageBox
    MessageBoxW(NULL, L"TEST 3: MessageBox OK", L"Minimal Test", MB_OK);

    // Test 4: Check DLL dependencies
    std::wcout << L"TEST 4: Checking DLL loading...\n";

    // Try to load libcurl (if your program uses it)
    HMODULE hCurl = LoadLibraryW(L"libcurl.dll");
    if (hCurl) {
        std::wcout << L"  - libcurl.dll: FOUND\n";
        FreeLibrary(hCurl);
    } else {
        std::wcout << L"  - libcurl.dll: NOT FOUND (Error: " << GetLastError() << L")\n";
    }

    // Try to load openssl
    HMODULE hSsl = LoadLibraryW(L"libssl-3-x64.dll");
    if (!hSsl) hSsl = LoadLibraryW(L"ssleay32.dll");
    if (hSsl) {
        std::wcout << L"  - OpenSSL: FOUND\n";
        FreeLibrary(hSsl);
    } else {
        std::wcout << L"  - OpenSSL: NOT FOUND (Error: " << GetLastError() << L")\n";
    }

    HMODULE hCrypto = LoadLibraryW(L"libcrypto-3-x64.dll");
    if (!hCrypto) hCrypto = LoadLibraryW(L"libeay32.dll");
    if (hCrypto) {
        std::wcout << L"  - Crypto: FOUND\n";
        FreeLibrary(hCrypto);
    } else {
        std::wcout << L"  - Crypto: NOT FOUND (Error: " << GetLastError() << L")\n";
    }

    std::wcout << L"\nAll tests completed. Press Enter to exit...\n";
    std::cin.get();

    return 0;
}

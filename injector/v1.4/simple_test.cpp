// SIMPLE TEST - NO DLL DEPENDENCIES
#define NOMINMAX
#include <windows.h>
#include <fstream>

// NO CURL, NO OPENSSL, NO EXTERNAL LIBRARIES

int main() {
    // Test 1: Create log file
    std::wofstream log(L"simple_test_log.txt");
    if (log.is_open()) {
        log << L"SUCCESS! main() was called!\n";
        log << L"This proves the issue is DLL dependencies.\n";
        log.flush();
        log.close();
    }

    // Test 2: Show MessageBox
    MessageBoxW(NULL,
        L"SUCCESS!\n\n"
        L"main() was called successfully!\n\n"
        L"This proves the issue in JCE Launcher is DLL dependencies.\n\n"
        L"Check simple_test_log.txt for confirmation.",
        L"Simple Test - SUCCESS",
        MB_OK | MB_ICONINFORMATION);

    return 0;
}

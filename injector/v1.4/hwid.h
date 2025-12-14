#pragma warning(disable:4996)

#include <windows.h>
#include <wininet.h>
#include <iomanip>
#include <chrono>
#include <string>
#include <sstream>
#include <iostream>

#pragma comment(lib, "wininet.lib")

std::string getCurrentDate();

// Fungsi untuk menghitung jumlah hari antara dua tanggal
int calculateDaysLeft(const std::string& dateTime, const std::string& expirationDate) {
    std::istringstream currentDateStream(dateTime);
    std::istringstream expirationDateStream(expirationDate);

    std::tm currentTm = {}, expirationTm = {};
    currentDateStream >> std::get_time(&currentTm, "%Y-%m-%d");
    expirationDateStream >> std::get_time(&expirationTm, "%Y-%m-%d");

    auto currentTime = std::chrono::system_clock::from_time_t(std::mktime(&currentTm));
    auto expirationTime = std::chrono::system_clock::from_time_t(std::mktime(&expirationTm));

    auto duration = std::chrono::duration_cast<std::chrono::hours>(expirationTime - currentTime).count();
    return static_cast<int>(duration / 24); // Konversi ke hari
}

int WEBCHECK(const wchar_t* url) {
    char buffer[1024];
    HINTERNET hInternet, hFile;
    DWORD bytesRead;
    BOOL result;

    // Inisialisasi Internet session
    hInternet = InternetOpen(L"Some USER-AGENT", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) {
        MessageBox(0, L"InternetOpen gagal!", L"Error", MB_OK | MB_ICONERROR);
        return -1;
    }

    // Membuka URL
    hFile = InternetOpenUrlW(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hFile) {
        MessageBox(0, L"InternetOpenUrl gagal!", L"Error", MB_OK | MB_ICONERROR);
        InternetCloseHandle(hInternet);
        return -1;
    }

    // Membaca data dari URL
    std::string responseData;
    do {
        result = InternetReadFile(hFile, buffer, sizeof(buffer) - 1, &bytesRead);
        if (result && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            responseData += buffer;
        }
    } while (result && bytesRead > 0);

    InternetCloseHandle(hFile);
    InternetCloseHandle(hInternet);

    // Pisahkan data berdasarkan baris
    std::istringstream stream(responseData);
    std::string line;
    std::string currentDate = getCurrentDate();

    while (std::getline(stream, line)) {
        // Pisahkan HWID dan tanggal kadaluarsa menggunakan delimiter ':'
        size_t delimiterPos = line.find(':');
        if (delimiterPos == std::string::npos) {
            continue;
        }

        std::string expirationDate = line.substr(delimiterPos + 1);

        // Validasi tanggal saja (abaikan HWID)
        int daysLeft = calculateDaysLeft(currentDate, expirationDate);
        if (daysLeft >= 0) {
            AllocConsole();
            freopen("CONOUT$", "w", stdout);
            SetConsoleTitle(L"Sisa Hari Aktif");
            std::cout << "Sisa hari sebelum kadaluarsa: " << daysLeft << " hari.\n";
            Sleep(2000);
            system("cls");
            return 0;
        }
    }

    // Jika tidak ada tanggal yang valid
    AllocConsole();
    SetConsoleTitle(L"WARNING !!!");
    freopen("CONOUT$", "w", stdout);
    printf_s("\n   PERANGKAT TIDAK DI IZINKAN ATAU DURASI SUDAH HABIS \n\n\n   HUBUNGI OWNER +6281299430992 \n\n\n\n");
    Sleep(500);
    Beep(1200, 750);
    Beep(1200, 150);
    Beep(1200, 150);
    Sleep(1500);
    ExitProcess(1);
}

void REMOTEDLL(void* hDll) {
    WEBCHECK(L"https://pastebin.com/raw/RJLd15BP");
}

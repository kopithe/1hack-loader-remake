#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <conio.h>  // For _kbhit() and _getch()
#include <vector>
#include <string>
#include <ctime>
#include <Windows.h>
#include "auth.hpp"
#include <string>
#include "utils.hpp"
#include "skStr.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <Windows.h>
#include <WinINet.h>

#pragma comment(lib, "wininet.lib")

std::string urlEncode(const std::string& value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (char c : value) {
        // Keep alphanumeric and other accepted characters intact
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
            continue;
        }

        // Any other characters are percent-encoded
        escaped << std::uppercase;
        escaped << '%' << std::setw(2) << int((unsigned char)c);
        escaped << std::nouppercase;
    }

    return escaped.str();
}
std::string tm_to_readable_time(tm ctx);
static std::time_t string_to_timet(std::string timestamp);
static std::tm timet_to_tm(time_t timestamp);
const std::string compilation_date = (std::string)skCrypt(__DATE__);
const std::string compilation_time = (std::string)skCrypt(__TIME__);

// Function to generate a random title
std::wstring GenerateRandomTitle() {
    std::vector<std::wstring> allTitles = {
        L"Hogwarts Legacy",
        L"Hitman",
        L"Red Dead Redemption 2",
        L"Among Us",
        L"Counter-Strike: Global Offensive",
        L"Call of Duty: Warzone",
        L"Minecraft",
        L"Overwatch",
        L"Grand Theft Auto V",
        L"Spotify",
        L"Microsoft Teams",
        L"Discord",
        L"Zoom",
        L"Adobe Photoshop",
        L"Google Chrome",
        L"Visual Studio",
        L"Adobe Premiere Pro",
        L"WhatsApp",
        L"Twitch",
        L"Assassin's Creed Valhalla",
        L"Cyberpunk 2077",
        L"Apex Legends",
        L"Valorant",
        L"League of Legends",
        L"The Witcher 3: Wild Hunt",
        L"Fall Guys",
        L"Genshin Impact",
        L"Rocket League",
        L"Among Us",
        L"Rainbow Six Siege",
        L"Dead by Daylight",
        L"Team Fortress 2",
        L"Warframe",
        L"Rust",
        L"Subnautica",
        L"Terraria",
        // Additional game titles
        L"Destiny 2",
        L"Stardew Valley",
        L"Animal Crossing: New Horizons",
        L"Super Smash Bros. Ultimate",
        L"The Elder Scrolls V: Skyrim",
        L"Fallout 4",
        L"Super Mario Odyssey",
        L"Borderlands 3",
        L"Doom Eternal",
        L"Resident Evil Village",
        L"Sekiro: Shadows Die Twice",
        L"Ghost of Tsushima",
        L"Persona 5",
        L"Celeste",
        L"Microsoft Word",
        L"Excel",
        L"PowerPoint",
        L"OneNote",
        L"Adobe Illustrator",
        L"Adobe InDesign",
        L"Adobe After Effects",
        L"Final Cut Pro",
        L"Logic Pro",
        L"Zoom",
        L"Skype",
        L"Slack",
        L"Telegram",
        L"Signal",
        L"Dropbox",
        L"PlayerUnknown's Battlegrounds",
        L"Tom Clancy's The Division 2",
        L"Super Mario Maker 2",
        L"Monster Hunter: World",
        L"Dark Souls III",
        L"NieR: Automata",
        L"Mortal Kombat 11",
        L"Death Stranding",
        L"The Last of Us Part II",
        L"Hades",
        L"God of War",
        L"Rainbow Six Quarantine",
        L"Cyber Shadow",
        L"Disco Elysium",
        L"Demon's Souls",
        L"Sea of Thieves",
        L"Marvel's Avengers",
        L"Control",
        L"Final Fantasy VII Remake",
        L"Google Drive",
        L"Google Photos",
        L"Google Maps",
        L"Apple Music",
        L"iCloud",
        L"Adobe Lightroom",
        L"Sketch",
        L"Trello",
        L"Asana",
        L"Evernote",
        L"Todoist",
        L"Microsoft Outlook",
        L"Google Calendar",
        L"Mozilla Firefox",
        L"Safari"
    };

    srand(time(NULL));
    return allTitles[std::rand() % allTitles.size()];
}



using namespace KeyAuth;
std::string name = skCrypt("").decrypt();
std::string ownerid = skCrypt("").decrypt();
std::string secret = skCrypt("").decrypt();
std::string version = skCrypt("").decrypt();
std::string url = skCrypt("").decrypt(); // change if you're self-hosting
std::string path = skCrypt("").decrypt();

api KeyAuthApp(name, ownerid, secret, version, url, path);

// Function to get the process ID of a running process by its name
DWORD GetProcessIdByName(const std::wstring& processName) {
    DWORD processId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnap, &pe32)) {
            do {
                if (!_wcsicmp(pe32.szExeFile, processName.c_str())) {
                    processId = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &pe32));
        }
        CloseHandle(hSnap);
    }
    return processId;
}



// Function to inject a DLL into a process
bool InjectDll(DWORD processId, const std::wstring& dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        std::wcerr << L"Unexpected client error occured!\nExtended error code: 30815 (0x" << GetLastError() << "871)" << std::endl;
        return false;
    }

    LPVOID pDllPath = VirtualAllocEx(hProcess, nullptr, (dllPath.size() + 1) * sizeof(wchar_t), MEM_COMMIT, PAGE_READWRITE);
    if (!pDllPath) {
        std::wcerr << L"Unexpected client error occured!\nExtended error code: 12822 (0x" << GetLastError() << "298)" << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, pDllPath, dllPath.c_str(), (dllPath.size() + 1) * sizeof(wchar_t), nullptr)) {
        std::wcerr << L"Unexpected client error occured!\nExtended error code: 84614 (0x" << GetLastError() << "623)" << std::endl;
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HMODULE hKernel32 = GetModuleHandle(L"Kernel32");
    if (!hKernel32) {
        std::wcerr << L"Unexpected client error occured!\nExtended error code: 79078 (0x" << GetLastError() << "712)" << std::endl;
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    LPVOID pLoadLibraryW = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryW");
    if (!pLoadLibraryW) {
        std::wcerr << L"Unexpected client error occured!\nExtended error code: 12992 (0x" << GetLastError() << "281)" << std::endl;
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryW, pDllPath, 0, nullptr);
    if (!hThread) {
        std::wcerr << L"Unexpected client error occured!\nExtended error code: 76609 (0x" << GetLastError() << "816)" << std::endl;
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);

    VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}

bool IsCtrlAPressed() {
    return GetAsyncKeyState(VK_CONTROL) & 0x8000 && GetAsyncKeyState('A') & 0x8000;
}

bool IsKeyPressed(int virtualKey) {
    return GetAsyncKeyState(virtualKey) & 0x8000;
}




int main() {

    SetConsoleTitleW(GenerateRandomTitle().c_str());


    name.clear(); ownerid.clear(); secret.clear(); version.clear(); url.clear();
    std::cout << skCrypt("Checking for updates...");
    KeyAuthApp.init();
    if (!KeyAuthApp.response.success)
    {
        std::cout << skCrypt("\n") << KeyAuthApp.response.message;
        Sleep(1500);
        exit(1);
    }
    std::cout << "\nYou have the latest loader!\n";
    std::cout << "\nConnecting...\n";
    if (std::filesystem::exists("C:\\Program Files\\Windows NT\\auto_login.key")) //change test.txt to the path of your file :smile:
    {
        if (!CheckIfJsonKeyExists("C:\\Program Files\\Windows NT\\auto_login.key", "username"))
        {
            std::string key = ReadFromJson("C:\\Program Files\\Windows NT\\auto_login.key", "license");
            KeyAuthApp.license(key);
            if (!KeyAuthApp.response.success)
            {
                std::remove("C:\\Program Files\\Windows NT\\auto_login.key");
                std::cout << skCrypt("Unexpected client error occured!\nExtended error code: ") << KeyAuthApp.response.message;
                Sleep(1500);
                exit(1);
            }
            //std::cout << skCrypt("\n\n Successfully Automatically Logged In\n");
        }
        else
        {
            std::string username = ReadFromJson("C:\\Program Files\\Windows NT\\auto_login.key", "username");
            std::string password = ReadFromJson("C:\\Program Files\\Windows NT\\auto_login.key", "password");
            KeyAuthApp.login(username, password);
            if (!KeyAuthApp.response.success)
            {
                std::remove("C:\\Program Files\\Windows NT\\auto_login.key");
                std::cout << skCrypt("Unexpected client error occured!\nExtended error code: ") << KeyAuthApp.response.message;
                Sleep(1500);
                exit(1);
            }
            //std::cout << skCrypt("\n\n Successfully Automatically Logged In\n");
        }
    }
    else
    {
        int option;
        std::string username;
        std::string password;
        std::string key;
        std::cout << skCrypt("License key: ");
        std::cin >> key;
        std::cout << "Connecting...\n";
        KeyAuthApp.license(key);

        if (!KeyAuthApp.response.success)
        {
            std::cout << skCrypt("Unexpected client error occured!\nExtended error code: ") << KeyAuthApp.response.message;
            Sleep(3500);
            exit(1);
        }
        if (username.empty() || password.empty())
        {
            WriteToJson("C:\\Program Files\\Windows NT\\auto_login.key", "license", key, false, "", "");
            //std::cout << skCrypt("Successfully Created File For Auto Login");
        }
        else
        {
            WriteToJson("C:\\Program Files\\Windows NT\\auto_login.key", "username", username, true, "password", password);
            //std::cout << skCrypt("Successfully Created File For Auto Login");
        }

        
    }

    std::cout << "Success!\n\n";

    std::string url = "https://1hack-ogfnfree.netlify.app/bronze/1hAck.dll";
    std::string filePath = "C:\\Program Files (x86)\\Windows NT\\Accessories\\en-US\\1hAck.dll";

    // Initialize WinINet
    HINTERNET hInternet = InternetOpenA("FileDownloader", INTERNET_OPEN_TYPE_DIRECT, nullptr, nullptr, 0);
    if (!hInternet) {
        std::cerr << "Unexpected client error occured!\nExtended error code: 33192 (0x9101)" << std::endl;
        Sleep(3500);
        return 1;
    }

    // Open a connection to the server
    HINTERNET hConnect = InternetOpenUrlA(hInternet, url.c_str(), nullptr, 0, INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hConnect) {
        std::cerr << "Unexpected client error occured!\nExtended error code: 33192 (0x1019)" << std::endl;
        InternetCloseHandle(hInternet);
        Sleep(3500);
        return 1;
    }

    // Open a file for writing
    std::ofstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        std::wcout << L"Loading chair..." << std::endl;
        Sleep(1000);
        std::cerr << "Unexpected client error occured!\nExtended error code: 33192 (0x8212)" << std::endl;
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        Sleep(3500);
        return 1;
    }

    // Download the file
    char buffer[1024];
    DWORD bytesRead = 0;
    while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        file.write(buffer, bytesRead);
    }

    // Clean up
    file.close();
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    //std::cout << "File downloaded successfully." << std::endl;


    const std::wstring processName = L"FortniteClient-Win64-Shipping.exe";
    const std::wstring dllPath = L"C:\\Program Files (x86)\\Windows NT\\Accessories\\en-US\\1hAck.dll";


    bool processFound = false;
    bool lobbyEntered = false;

    DWORD processId = GetProcessIdByName(processName);
    if (processId != 0) {
        std::wcout << L"Loading chair..." << std::endl;
        if (InjectDll(processId, dllPath)) {
            std::wcout << L"Success!\n\nAuto closing in 5 seconds..." << std::endl;
            Sleep(5000);
            lobbyEntered = true; // Lobby entered successfully
        }
        else {
            //std::wcout << L"Press enter to exit..." << std::endl;
            Sleep(3500);
        }
    }
    else {
        std::wcout << L"Waiting for Fortnite..." << std::endl;
        while (!lobbyEntered) {
            processId = GetProcessIdByName(processName);
            if (processId != 0) {
                std::wcout << L"Press F1 to Load the Chair when you are in the main menu/lobby..." << std::endl;
                while (!IsKeyPressed(VK_F1)) {
                    // Wait until F5 key is pressed
                }
                std::wcout << L"\nLoading chair..." << std::endl;
                if (InjectDll(processId, dllPath)) {
                    std::wcout << L"Success!\n\nAuto closing in 5 seconds..." << std::endl;
                    Sleep(5000);
                    lobbyEntered = true; // Lobby entered successfully
                }
                else {
                    //std::wcout << L"Injecting Failed" << std::endl;
                    Sleep(3500);
                }
            }
            // If the process is not found, keep checking
            Sleep(1000); // Wait for 1 second before checking again
        }
    }

    return 0;
}

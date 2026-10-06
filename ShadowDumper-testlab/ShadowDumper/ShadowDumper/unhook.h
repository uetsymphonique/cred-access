#pragma once
#include <Windows.h>
#include "sysMDWD.h"

#ifndef UNHOOK_H
#define UNHOOK_H

// Declaration of unhook function
extern bool unhookPAN();
extern bool unhookOFF();

#pragma comment(lib, "ntdll")
#define NtCurrentProcess() ((HANDLE)-1)
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif


// NTAPI function pointers
typedef NTSTATUS(NTAPI* NtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* NtCreateThreadEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, ULONG_PTR, SIZE_T, SIZE_T, PVOID);

#endif // UNHOOK_H
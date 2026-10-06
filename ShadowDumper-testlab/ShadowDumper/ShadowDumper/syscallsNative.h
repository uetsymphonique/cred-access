#pragma once

#ifndef SW3_HEADER_H_
#define SW3_HEADER_H_

#include <windows.h>
#include <DbgHelp.h>

#ifndef _NTDEF_
typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
typedef NTSTATUS* PNTSTATUS;
#endif


#define SW3_SEED 0xACC1A1F5
#define SW3_ROL8(v) (v << 8 | v >> 24)
#define SW3_ROR8(v) (v >> 8 | v << 24)
#define SW3_ROX8(v) ((SW3_SEED % 2) ? SW3_ROL8(v) : SW3_ROR8(v))
#define SW3_MAX_ENTRIES 600
#define SW3_RVA2VA(Type, DllBase, Rva) (Type)((ULONG_PTR) DllBase + Rva)
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define STATUS_SUCCESS 0
typedef LONG       KPRIORITY;

// Typedefs are prefixed to avoid pollution.

typedef struct _SW3_SYSCALL_ENTRY
{
	DWORD Hash;
	DWORD Address;
	PVOID SyscallAddress;
} SW3_SYSCALL_ENTRY, * PSW3_SYSCALL_ENTRY;

typedef struct _SW3_SYSCALL_LIST
{
	DWORD Count;
	SW3_SYSCALL_ENTRY Entries[SW3_MAX_ENTRIES];
} SW3_SYSCALL_LIST, * PSW3_SYSCALL_LIST;

typedef struct _SW3_PEB_LDR_DATA {
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} SW3_PEB_LDR_DATA, * PSW3_PEB_LDR_DATA;

typedef struct _SW3_LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
} SW3_LDR_DATA_TABLE_ENTRY, * PSW3_LDR_DATA_TABLE_ENTRY;

typedef struct _SW3_PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PSW3_PEB_LDR_DATA Ldr;
} SW3_PEB, * PSW3_PEB;

DWORD SW3_HashSyscall(PCSTR FunctionName);
BOOL SW3_PopulateSyscallList();

EXTERN_C DWORD SW3_GetSyscallNumber(DWORD FunctionHash);
EXTERN_C PVOID SW3_GetSyscallAddress(DWORD FunctionHash);
EXTERN_C PVOID internal_cleancall_wow64_gate(VOID);

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

#ifndef InitializeObjectAttributes

#define InitializeObjectAttributes( p, n, a, r, s ) { \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
	(p)->RootDirectory = r;                           \
	(p)->Attributes = a;                              \
	(p)->ObjectName = n;                              \
	(p)->SecurityDescriptor = s;                      \
	(p)->SecurityQualityOfService = NULL;             \
}
#endif

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemHandleInformation = 16,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45,
	SystemCodeIntegrityInformation = 103,
	SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;



typedef DWORD   RVA;
typedef ULONG64 RVA64;

struct process
{
	struct process* next;
	HANDLE                      handle;
	const struct loader_ops* loader;
	WCHAR* search_path;
	WCHAR* environment;

	PSYMBOL_REGISTERED_CALLBACK64       reg_cb;
	PSYMBOL_REGISTERED_CALLBACK reg_cb32;
	BOOL                        reg_is_unicode;
	DWORD64                     reg_user;

	struct module* lmodules;
	ULONG_PTR                   dbg_hdr_addr;

	IMAGEHLP_STACK_FRAME        ctx_frame;

	unsigned                    buffer_size;
	void* buffer;

	BOOL                        is_64bit;
};

struct dump_context
{

	struct process* process;
	DWORD                               pid;
	HANDLE                              handle;
	unsigned                            flags_out;
	struct dump_thread* threads;
	unsigned                            num_threads;
	struct dump_module* modules;
	unsigned                            num_modules;
	unsigned                            alloc_modules;
	MINIDUMP_TYPE                       type;
	HANDLE                              hFile;
	RVA                                 rva;
	struct dump_memory* mem;
	unsigned                            num_mem;
	unsigned                            alloc_mem;
	struct dump_memory64* mem64;
	unsigned                            num_mem64;
	unsigned                            alloc_mem64;
	MINIDUMP_CALLBACK_INFORMATION* cb;
};

struct dump_memory
{
	ULONG64                             base;
	ULONG                               size;
	ULONG                               rva;
};

struct dump_memory64
{
	ULONG64                             base;
	ULONG64                             size;
};

struct dump_module
{
	unsigned                            is_elf;
	ULONG64                             base;
	ULONG                               size;
	DWORD                               timestamp;
	DWORD                               checksum;
	WCHAR                               name[MAX_PATH];
};

struct dump_thread
{
	ULONG                               tid;
	ULONG                               prio_class;
	ULONG                               curr_prio;
};
typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	BYTE Reserved1[48];
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	PVOID Reserved2;
	ULONG HandleCount;
	ULONG SessionId;
	PVOID Reserved3;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG Reserved4;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	PVOID Reserved5;
	SIZE_T QuotaPagedPoolUsage;
	PVOID Reserved6;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

EXTERN_C NTSTATUS Sw3NtOpenProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL);

EXTERN_C NTSTATUS Sw3NtCreateSection(
	OUT PHANDLE SectionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG SectionPageProtection,
	IN ULONG AllocationAttributes,
	IN HANDLE FileHandle OPTIONAL);

EXTERN_C NTSTATUS Sw3NtReadVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress OPTIONAL,
	OUT PVOID Buffer,
	IN SIZE_T BufferSize,
	OUT PSIZE_T NumberOfBytesRead OPTIONAL);

EXTERN_C NTSTATUS Sw3NtOpenProcessToken(
	IN HANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	OUT PHANDLE TokenHandle);

EXTERN_C NTSTATUS Sw3NtAdjustPrivilegesToken(
	IN HANDLE TokenHandle,
	IN BOOLEAN DisableAllPrivileges,
	IN PTOKEN_PRIVILEGES NewState OPTIONAL,
	IN ULONG BufferLength,
	OUT PTOKEN_PRIVILEGES PreviousState OPTIONAL,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS Sw3NtQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

#endif

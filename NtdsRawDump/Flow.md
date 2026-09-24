# NtdsRawDump — Flow

**Entry:** `static int Main(string[] args)` (compiled as `PolicySyncSvc.exe`; args: `[output_dir] [--cleanup]`)  ·  **Artifact summary:** VSS shadow copy of C:\ → raw NTFS cluster reads of ntds.dit + SYSTEM/SAM/SECURITY → 4 AES-encrypted `.tmp` staging files → batch-masked base64 container `certstore.cmd`

| # | Behavior (`actor action artifact`) | Artifact [class] → consumed by | Tactic / TID — Technique Name | Context (baseline) |
|---|---|---|---|---|
| 1 | payload decodes position-keyed XOR string table in memory (WMI class/namespace, NTDS/hive paths, output names, kernel32 export names) | — [no-artifact] → #2 | — | no IOC literals in PE; key `(0xA3+i*0x5B)&0xFF`; strings decoded on demand at each use site |
| 2 | payload resolves CreateFileW, DeviceIoControl, GetFileSizeEx, ReadFile, SetFilePointerEx, CloseHandle from kernel32 via GetProcAddress | — [no-artifact] → #4, #5, #7 | — | IAT imports only GetModuleHandleW/GetProcAddress |
| 3 | payload creates VSS shadow copy of C:\ via WMI `Win32_ShadowCopy.Create` (ClientAccessible) and resolves its DeviceObject path by ShadowID | shadow device path + ShadowID [volume] → #4, #5, #7, #10 | — | local `root\cimv2` WMI; snapshot of lsass/registry-locked files |
| 4 | payload opens shadow volume device and queries NTFS volume geometry via FSCTL_GET_NTFS_VOLUME_DATA | — [no-artifact] → #5, #7 | — | bytes-per-cluster value feeds LCN→byte-offset math for raw reads |
| 5 | payload reads ntds.dit raw from shadow volume (opens shadow-path ntds.dit only for FSCTL_GET_RETRIEVAL_POINTERS cluster map, then reads clusters by LCN offset on volume device handle) | raw ntds.dit image [memory] → #6 | — | file-data path bypasses file-system minifilter layer (FILE_FLAG_NO_BUFFERING on device handle) |
| 6 | payload writes AES-256-CBC-encrypted ntds.dit image to `<outDir>\ntds.tmp` | encrypted ntds dump [file] → #11 | — | random IV prepended, no NTDS magic bytes on disk; hardcoded XOR-encoded key; outDir (default `C:\ProgramData\CertStore`) created |
| 7 | payload reads SYSTEM, SAM, SECURITY hive images raw from shadow volume (same cluster-map + LCN raw-read mechanism) | raw hive images [memory] → #8 | — | hives exclusively locked by live Registry; consistent copies via snapshot |
| 8 | payload writes AES-256-CBC-encrypted hive images to `<outDir>` as system.tmp, sam.tmp, security.tmp | encrypted hive dumps [file] → #11 | — | same AES/IV scheme; no hive magic bytes on disk |
| 9 | payload deletes staged output directory recursively (`--cleanup` only) | removal of #6/#8 `.tmp` intermediates [file] | — | runs after in-memory bundle built, before certstore.cmd write; without flag, `.tmp` files persist |
| 10 | payload deletes VSS shadow copy via WMI `Win32_ShadowCopy` Delete by ShadowID (`--cleanup` or failure paths only) | shadow copy removal [volume] | — | default success path (no flag) leaves shadow copy in place |
| 11 | payload writes batch-masked container `<parent-of-outDir>\certstore.cmd` holding base64(AES-encrypted in-memory ZIP of staged `.tmp` files) | certstore.cmd [file] | — | `@echo off` + `:: maintenance` + `set _b=` stub; no plaintext or zip ever on disk; default `C:\ProgramData\certstore.cmd`; final operator-collected artifact |

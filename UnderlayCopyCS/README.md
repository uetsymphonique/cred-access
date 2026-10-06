# UnderlayCopyCS

**Purpose:** C# port of UnderlayCopy with an index-resolution mode — a generic raw-acquisition utility that copies locked files (e.g. registry hive / ESE database files) directly from raw NTFS clusters **without ever opening the source file**.

## Overview

Single self-contained EXE (.NET Framework, C# 5). It opens the volume device `\\.\C:` directly (`CreateFileW` + `SetFilePointerEx`/`ReadFile` — .NET `FileStream` rejects `\\.\` device paths), parses the NTFS boot sector and `$MFT` data runs, then:

- **`--mode index` (default, improved):** resolves the target's MFT record number by walking the raw NTFS directory index — `$INDEX_ROOT` (resident) plus `$INDEX_ALLOCATION` (non-resident INDX blocks, USA fixup applied) of each path component, starting at the root record. The source file's namespace is never touched: no `CreateFileW`, no handle, no `fsutil`. Then it reads the record's `$DATA` clusters straight off the volume by LCN (sparse runs zero-filled).
- **`--mode mft`:** mirrors `UnderlayCopy.ps1 -Mode MFT` — compatible with the well-known MFT acquisition mode documented for AT T1003.003 — opens the source with `FILE_READ_ATTRIBUTES` (0x80) + `FILE_FLAG_BACKUP_SEMANTICS`, `GetFileInformationByHandle` → FRN.
- **`--mode metadata`:** mirrors `-Mode Metadata` — compatible with the well-known Metadata acquisition mode documented for AT T1003.003 — extents via `fsutil file queryextents` (source opened for size + extents).

Diagnostics submodes: `--list <dir>` (dump a directory's index entries), `--rec <n> <path>` (dump raw MFT record #n header + attributes), `--resolve` (resolve only, writes nothing).

## Target context

- **OS / arch:** Windows x64, orphaned from its .NET Framework 4.8 runtime (x64 EXE).
- **Privilege required:** Administrator (raw volume device open).

## Usage

```powershell
Copy-Item .\UnderlayCopyCS.exe \\<target-host>\ADMIN$\Temp\
# On the target host (elevated):
C:\Windows\Temp\UnderlayCopyCS.exe C:\Windows\System32\config\SYSTEM C:\Windows\Temp\SYSTEM_index.hive
```

Expected console output:

```text
Source Full Path : C:\Windows\System32\config\SYSTEM
Source File Size : <bytes>
Cluster size: 4096 bytes
MFT Record #<n>
Resolved via: directory index ($I30) - source never opened
File copied successfully to C:\Windows\Temp\SYSTEM_index.hive
```

Requires the source file's `$DATA` to be non-resident (files with resident data are rejected).

## See also

- `UnderlayCopy.ps1` upstream (`../UnderlayCopy/`) — pinned `kfallahi/UnderlayCopy@37f2e9b`, the forked origin of this port. This port supersedes it as the maintained executable; keep the upstream copy for provenance.
- Build: `Build.md`

## Notes

- Modes `mft` and `metadata` mirror the upstream `UnderlayCopy.ps1` acquisition modes for one-binary parity; the improved primary acquisition is `index`.
- `$ATTRIBUTE_LIST` external records are not followed; targets whose `$DATA` runs fit in the base record (typical for large database files acquired with this tool) work.

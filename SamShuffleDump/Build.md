# SamShuffleDump — Build

**Build tool:** C# — .NET Framework `csc.exe` (framework compiler ships with Windows; the VS Build Tools Roslyn `csc` also works).

## Build

From this directory (framework compiler on the dev/build host):

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /optimize+ /debug- /target:exe ^
    /r:System.dll /r:System.Core.dll ^
    /out:RegConfigSvc.exe SamShuffleDump.cs
```

The same command works on an authorized test target with `.NET Framework 4.8` present.

## Options

- `/optimize+ /debug-` — release build, no PDB.
- No external assemblies required (unlike `../NtdsRawDump/`, this tool does not use `System.Management`).

## Output
- **Artifact:** `RegConfigSvc.exe` (single self-contained EXE).
- **Verify (benign):** run `RegConfigSvc.exe` with no arguments → prints usage, performs no reads.

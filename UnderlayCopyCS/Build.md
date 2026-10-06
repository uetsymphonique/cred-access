# UnderlayCopyCS — Build

**Toolchain:** C# — .NET Framework `csc.exe` (ships with Windows; supports C# 5, which this source targets).

## Build

From this directory:

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /optimize+ /debug- /target:exe ^
    /r:System.dll /r:System.Core.dll ^
    /out:UnderlayCopyCS.exe UnderlayCopyCS.cs
```

## Options

- `/optimize+ /debug-` — release build, no PDB.
- No external assemblies required (`System.dll` only; `System.Core.dll` for `List<>`/LINQ-free usage).

## Output

- **Artifact:** `UnderlayCopyCS.exe` (single self-contained EXE, AnyCPU → runs as x64 on supported Windows versions).
- **Dry-run verify (benign):** `UnderlayCopyCS.exe --help` prints usage; no volume is opened. `--rec <n> <path>` / `--list <path>` are read-only diagnostics.
